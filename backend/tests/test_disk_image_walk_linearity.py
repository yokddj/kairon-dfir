"""Tests for the disk-image filesystem walker's live-tree guarantees.

Profiling a real ext4 image (Webserver.E01 / VulnOS) found the walker
spending ~99.8% of materialization runtime inside directory traversal and
producing an output where 97% of the files lived at paths that do not
exist in the filesystem. The cause was a pair of missing rules in
_iter_directory, both covered here:

  * deleted (TSK_FS_NAME_FLAG_UNALLOC) directory entries were followed.
    A deleted name whose inode has since been recycled points at whatever
    lives at that inode *now* -- on that image, ~770 dpkg residue entries
    in a single directory, some resolving to ancestor directories.
  * nothing detected that the directory being entered was already on the
    current ancestor chain, so entering one re-walked (and re-extracted)
    the whole tree beneath a phantom path, bounded only by max_depth.

The fake filesystem below resolves paths the way TSK does -- component by
component, from the root, every time -- so a recycled-inode entry produces
a genuinely unbounded tree rather than a pre-canned one. A regression in
either rule makes these tests hang or explode rather than quietly pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import pytsk3

from app.disk_images.service import (
    WalkStats,
    _is_allocated_entry,
    _iter_directory,
    _materialize_volume_installation,
)

ROOT_INODE = 2
ALLOC = int(pytsk3.TSK_FS_NAME_FLAG_ALLOC)
UNALLOC = int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
SYSLOG_BYTES = b"authoritative syslog bytes"


def _entry(name: str, inode: int | None, *, directory: bool = False, flags: int = ALLOC, meta: bool = True, size: int = 0):
    meta_obj = None
    if meta:
        meta_obj = SimpleNamespace(
            addr=inode,
            type=pytsk3.TSK_FS_META_TYPE_DIR if directory else pytsk3.TSK_FS_META_TYPE_REG,
            size=size,
        )
    return SimpleNamespace(info=SimpleNamespace(name=SimpleNamespace(name=name.encode(), flags=flags), meta=meta_obj))


class _FakeDirectory:
    def __init__(self, inode: int, entries: list):
        self.info = SimpleNamespace(fs_file=SimpleNamespace(meta=SimpleNamespace(addr=inode)))
        self._entries = entries

    def __iter__(self):
        return iter(self._entries)


class _FakeFsInfo:
    """A pytsk3.FS_Info stand-in backed by an inode -> entries mapping.

    open_dir(path=...) resolves the path from the root one component at a
    time, exactly like the real thing, so an entry pointing back at an
    ancestor inode yields an infinitely deep namespace -- the real failure
    mode -- instead of a finite fixture that could pass by accident.
    """

    def __init__(self, dirs: dict[int, list], file_contents: dict[int, bytes] | None = None):
        self.dirs = dirs
        self.file_contents = file_contents or {}
        self.open_dir_calls: list[str] = []

    def _resolve(self, path: str) -> int:
        inode = ROOT_INODE
        for part in [component for component in path.strip("/").split("/") if component]:
            entries = self.dirs.get(inode)
            if entries is None:
                raise OSError("not a directory")
            match = next((entry for entry in entries if entry.info.name.name.decode() == part), None)
            if match is None or match.info.meta is None:
                raise OSError("no such file or directory")
            inode = match.info.meta.addr
        return inode

    def open_dir(self, path: str):
        self.open_dir_calls.append(path)
        inode = self._resolve(path)
        if inode not in self.dirs:
            raise OSError("not a directory")
        return _FakeDirectory(inode, self.dirs[inode])

    def open(self, path: str):
        inode = self._resolve(path)
        content = self.file_contents.get(inode, b"")
        return SimpleNamespace(read_random=lambda offset, size: content[offset : offset + size])


def _walk(fs_info: _FakeFsInfo, *, max_depth: int = 16, stats: WalkStats | None = None) -> tuple[list, WalkStats]:
    stats = stats or WalkStats()
    return list(_iter_directory(fs_info, "/", depth=0, max_depth=max_depth, stats=stats)), stats


def _paths(results) -> list[str]:
    return [path for path, _entry, _is_dir in results]


def test_allocated_regular_entry_is_materialized():
    fs_info = _FakeFsInfo({ROOT_INODE: [_entry("passwd", 100)]})

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/passwd"]
    assert results[0][2] is False
    assert stats.allocated_entries_followed == 1
    assert stats.unallocated_entries_skipped == 0


def test_allocated_directory_is_traversed():
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("etc", 10, directory=True)],
            10: [_entry("passwd", 100), _entry("hostname", 101)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/etc", "/etc/passwd", "/etc/hostname"]
    assert "/etc" in fs_info.open_dir_calls
    assert stats.directories_opened == 2


def test_unallocated_regular_entry_is_skipped():
    fs_info = _FakeFsInfo({ROOT_INODE: [_entry("passwd", 100), _entry("passwd.dpkg-new", 101, flags=UNALLOC)]})

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/passwd"]
    assert stats.unallocated_entries_skipped == 1


def test_unallocated_directory_entry_is_skipped_before_open_dir():
    """The skip must happen before the entry is opened as a directory --
    otherwise a deleted name still costs a full directory read, which is
    most of what made the real walk slow."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("gconv", 10, directory=True, flags=UNALLOC)],
            10: [_entry("passwd", 100)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == []
    assert "/gconv" not in fs_info.open_dir_calls
    assert stats.unallocated_entries_skipped == 1


def test_deleted_name_pointing_at_recycled_live_inode_is_skipped():
    """The exact shape of the production failure: a deleted dpkg residue
    name in /usr/lib/i386-linux-gnu/gconv whose inode was recycled and is
    now the root directory. Following it reproduced the entire tree under
    a phantom path."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("gconv", 10, directory=True), _entry("syslog", 100)],
            10: [_entry("ISO-8859-1.so.dpkg-new", ROOT_INODE, directory=True, flags=UNALLOC)],
        },
        file_contents={100: b"real syslog"},
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/gconv", "/syslog"]
    assert stats.unallocated_entries_skipped == 1
    assert stats.cycles_prevented == 0  # never reached the guard: skipped earlier
    assert not any(path.count("/gconv") > 1 for path in _paths(results))


def test_direct_self_cycle_is_prevented():
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("var", 10, directory=True)],
            10: [_entry("self", 10, directory=True), _entry("syslog", 100)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/var", "/var/self", "/var/syslog"]
    assert stats.cycles_prevented == 1
    assert "/var/self" not in fs_info.open_dir_calls


def test_ancestor_cycle_a_to_b_to_a_is_prevented():
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("a", 10, directory=True)],
            10: [_entry("b", 11, directory=True)],
            11: [_entry("back-to-a", 10, directory=True), _entry("syslog", 100)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/a", "/a/b", "/a/b/back-to-a", "/a/b/syslog"]
    assert stats.cycles_prevented == 1
    assert "/a/b/back-to-a" not in fs_info.open_dir_calls


def test_allocated_cycle_terminates_without_phantom_paths():
    """An *allocated* entry pointing at an ancestor is the case the
    unallocated filter alone cannot catch. Without the ancestor guard this
    walk does not terminate at any sane depth -- it produces a tree of size
    O(branching ** max_depth) full of paths that do not exist."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("usr", 10, directory=True), _entry("syslog", 100)],
            10: [_entry("loop", ROOT_INODE, directory=True)],
        }
    )

    results, stats = _walk(fs_info, max_depth=16)

    assert _paths(results) == ["/usr", "/usr/loop", "/syslog"]
    assert stats.cycles_prevented == 1
    assert stats.max_depth_truncations == 0  # terminated by the guard, not by the bound


def test_max_depth_remains_functional_independently():
    """max_depth stays an independent safety bound: a legitimately deep,
    acyclic tree is still truncated by it, and the cycle guard does not
    interfere."""
    depth = 20
    dirs = {ROOT_INODE: [_entry("d0", 1000, directory=True)]}
    for level in range(depth):
        child_inode = 1000 + level + 1
        dirs[1000 + level] = [_entry(f"d{level + 1}", child_inode, directory=True)]
    dirs[1000 + depth] = [_entry("syslog", 5000)]

    results, stats = _walk(fs_info := _FakeFsInfo(dirs), max_depth=5)

    assert stats.max_depth_truncations > 0
    assert stats.cycles_prevented == 0
    assert max(path.count("/") for path in _paths(results)) <= 6
    assert not any(path.endswith("syslog") for path in _paths(results))
    assert fs_info.open_dir_calls  # the shallow part was still walked


def test_recursion_stack_identity_is_removed_on_unwind():
    """The guard is an ancestor chain, not a global visited set: once a
    branch is unwound its inodes must be walkable again in a sibling
    branch, or every second occurrence of a shared directory would vanish."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("branch-a", 10, directory=True), _entry("branch-b", 11, directory=True)],
            10: [_entry("shared", 20, directory=True)],
            11: [_entry("shared", 20, directory=True)],
            20: [_entry("syslog", 100)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == [
        "/branch-a",
        "/branch-a/shared",
        "/branch-a/shared/syslog",
        "/branch-b",
        "/branch-b/shared",
        "/branch-b/shared/syslog",
    ]
    assert stats.cycles_prevented == 0


def test_repeated_inode_in_non_ancestor_branch_is_walked_in_both():
    """Hard-link semantics: the same inode reached from two unrelated
    branches is a real path in each, and both are extracted."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("one", 10, directory=True), _entry("two", 11, directory=True)],
            10: [_entry("passwd", 500)],
            11: [_entry("passwd", 500)],
        }
    )

    results, stats = _walk(fs_info)

    assert _paths(results) == ["/one", "/one/passwd", "/two", "/two/passwd"]
    assert stats.cycles_prevented == 0


def test_malformed_or_missing_metadata_does_not_crash_the_walk():
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [
                _entry("no-meta", None, meta=False),
                _entry("bad-inode", "not-an-int"),
                SimpleNamespace(info=SimpleNamespace(name=None, meta=None)),
                _entry("weird-flags", 101),
                _entry("passwd", 100),
            ],
        }
    )
    fs_info.dirs[ROOT_INODE][3].info.name.flags = object()

    results, stats = _walk(fs_info)

    # Entries whose flags cannot be read are kept, never silently dropped:
    # losing a live forensic path is worse than keeping an ambiguous one.
    assert "/passwd" in _paths(results)
    assert "/weird-flags" in _paths(results)
    assert "/no-meta" in _paths(results)
    assert stats.entries_inspected >= 4


def test_is_allocated_entry_predicate_is_conservative():
    assert _is_allocated_entry(_entry("live", 1)) is True
    assert _is_allocated_entry(_entry("deleted", 1, flags=UNALLOC)) is False
    assert _is_allocated_entry(_entry("no-meta", None, meta=False)) is True
    assert _is_allocated_entry(SimpleNamespace(info=SimpleNamespace(name=None, meta=None))) is True
    assert _is_allocated_entry(SimpleNamespace(info=None)) is True


def _materialize(fs_info, tmp_path):
    install = SimpleNamespace(id="install-1", platform="linux", root_path="/")
    volume = SimpleNamespace(id="volume-1", partition_index=1)
    disk_image = SimpleNamespace(id="image-1")
    return _materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path,
    )


def test_cycle_and_deletion_diagnostics_stay_bounded(tmp_path):
    """Thousands of corrupt entries must produce counters, not thousands of
    warnings -- the real image has ~770 deleted entries in one directory
    alone."""
    deleted = [_entry(f"residue-{index}.dpkg-new", 900 + index, flags=UNALLOC) for index in range(2000)]
    cycles = [_entry(f"loop-{index}", ROOT_INODE, directory=True) for index in range(50)]
    fs_info = _FakeFsInfo(
        {ROOT_INODE: [*deleted, *cycles, _entry("syslog", 100, size=len(SYSLOG_BYTES))]},
        file_contents={100: SYSLOG_BYTES},
    )

    extracted_files, manifest_entries, _source_map, warnings = _materialize(fs_info, tmp_path)

    assert len(warnings) == 2
    assert "skipped_deleted_directory_entries:2000" in warnings
    assert "prevented_directory_cycles:50" in warnings
    assert [entry["path"] for entry in manifest_entries] == extracted_files
    assert len(extracted_files) == 1


def test_materialization_writes_only_live_paths(tmp_path):
    """End-to-end shape of the production bug: the deleted entry resolving
    to the root inode must leave no phantom copy of the tree on disk, and
    the one real file must be written exactly once."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("var", 10, directory=True), _entry("gconv", 11, directory=True)],
            10: [_entry("syslog", 100, size=len(SYSLOG_BYTES))],
            11: [_entry("ISO-8859-1.so.dpkg-new", ROOT_INODE, directory=True, flags=UNALLOC)],
        },
        file_contents={100: SYSLOG_BYTES},
    )

    extracted_files, _manifest, _source_map, _warnings = _materialize(fs_info, tmp_path)

    written = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file())
    assert written == ["volume-1/linux/var/syslog"]
    assert len(extracted_files) == 1
    assert (tmp_path / "volume-1/linux/var/syslog").read_bytes() == SYSLOG_BYTES


@pytest.mark.parametrize("max_depth", [4, 8, 16])
def test_walk_is_linear_in_live_tree_size_regardless_of_max_depth(max_depth):
    """The decisive regression test: with a cycle present, the amount of
    work must depend on the live tree, not on max_depth. Before the fix the
    entry count grew with max_depth (exponentially); it must now be
    identical at every bound."""
    fs_info = _FakeFsInfo(
        {
            ROOT_INODE: [_entry("usr", 10, directory=True), _entry("etc", 12, directory=True)],
            10: [_entry("lib", 11, directory=True)],
            11: [_entry("recycled", ROOT_INODE, directory=True), _entry("passwd", 100)],
            12: [_entry("hostname", 101)],
        }
    )

    results, stats = _walk(fs_info, max_depth=max_depth)

    assert _paths(results) == [
        "/usr",
        "/usr/lib",
        "/usr/lib/recycled",
        "/usr/lib/passwd",
        "/etc",
        "/etc/hostname",
    ]
    assert stats.directories_opened == 4
    assert stats.cycles_prevented == 1
