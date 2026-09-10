"""Some evidence has an entire prior installation copied into an
arbitrarily-named top-level folder rather than under a drive-letter folder
or the volume's true root -- found on the same real CyberDefenders
"SpottedInTheWild" image already covered by
test_disk_image_ntfs_boot_sector_repair.py and
test_disk_image_ntfs_metadata_capture.py: a folder named "VSS1" sitting
alongside "/C" at the volume's true root, containing its own complete
Windows/Users/ProgramData tree and its own $MFT -- almost certainly a
Volume Shadow Copy that was mounted and copied out before imaging, rather
than genuine block-level VSS data (this environment's pytsk3 build has no
libvshadow support at all, so it cannot be the latter).
"""

from __future__ import annotations

import pytsk3

from app.disk_images.service import (
    _detect_installations,
    _looks_like_drive_letter_root,
    _root_secondary_installation_prefixes,
)


class _FakeMeta:
    def __init__(self, is_dir: bool):
        self.type = pytsk3.TSK_FS_META_TYPE_DIR if is_dir else pytsk3.TSK_FS_META_TYPE_REG


class _FakeNameInfo:
    def __init__(self, name: bytes):
        self.name = name


class _FakeEntryInfo:
    def __init__(self, name: bytes, is_dir: bool):
        self.name = _FakeNameInfo(name)
        self.meta = _FakeMeta(is_dir)


class _FakeEntry:
    def __init__(self, name: bytes, is_dir: bool = True):
        self.info = _FakeEntryInfo(name, is_dir)


class _FakeFsInfo:
    def __init__(self, root_entries: list[_FakeEntry], existing_paths: set[str]):
        self._root_entries = root_entries
        self._existing = existing_paths

    def open_dir(self, path: str):
        if path == "/":
            return list(self._root_entries)
        raise RuntimeError(f"unsupported path in fake: {path}")

    def open(self, path: str):
        if path in self._existing:
            return object()
        raise FileNotFoundError(path)


def test_root_secondary_installation_prefixes_finds_arbitrarily_named_folders():
    fake = _FakeFsInfo(
        root_entries=[
            _FakeEntry(b".", is_dir=True),
            _FakeEntry(b"..", is_dir=True),
            _FakeEntry(b"$MFT", is_dir=False),
            _FakeEntry(b"$Extend", is_dir=True),
            _FakeEntry(b"C", is_dir=True),
            _FakeEntry(b"VSS1", is_dir=True),
            _FakeEntry(b"$RECYCLE.BIN", is_dir=True),
            _FakeEntry(b"System Volume Information", is_dir=True),
            _FakeEntry(b"leftover.tmp", is_dir=False),
        ],
        existing_paths=set(),
    )
    assert _root_secondary_installation_prefixes(fake) == ["/VSS1"]


def test_root_secondary_installation_prefixes_empty_when_root_cannot_be_opened():
    class Broken:
        def open_dir(self, path):
            raise RuntimeError("boom")

    assert _root_secondary_installation_prefixes(Broken()) == []


def test_looks_like_drive_letter_root():
    assert _looks_like_drive_letter_root("/C")
    assert _looks_like_drive_letter_root("C")
    assert not _looks_like_drive_letter_root("/")
    assert not _looks_like_drive_letter_root("/VSS1")
    assert not _looks_like_drive_letter_root("/Two")


def test_detect_installations_finds_both_the_live_system_and_a_secondary_root():
    fake = _FakeFsInfo(
        root_entries=[
            _FakeEntry(b".", is_dir=True),
            _FakeEntry(b"..", is_dir=True),
            _FakeEntry(b"$MFT", is_dir=False),
            _FakeEntry(b"C", is_dir=True),
            _FakeEntry(b"VSS1", is_dir=True),
        ],
        existing_paths={
            "/C/Windows/System32",
            "/C/Windows/System32/config/SYSTEM",
            "/C/Windows/System32/config/SOFTWARE",
            "/C/Users",
            "/C/ProgramData",
            "/VSS1/Windows/System32",
            "/VSS1/Windows/System32/config/SYSTEM",
            "/VSS1/Windows/System32/config/SOFTWARE",
            "/VSS1/Users",
            "/VSS1/ProgramData",
        },
    )

    installs = _detect_installations(fake, "volume-1")

    by_root = {install["root_path"]: install for install in installs}
    assert set(by_root) == {"/C", "/VSS1"}
    assert "metadata" not in by_root["/C"]
    assert by_root["/VSS1"]["metadata"]["installation_root_kind"] == "secondary_top_level_folder"
    assert by_root["/VSS1"]["metadata"]["secondary_root_folder"] == "VSS1"


def test_detect_installations_does_not_false_positive_on_ordinary_root_siblings():
    """Every top-level directory becomes a candidate, but the existing
    marker-based check must still reject the ones that aren't actually a
    nested installation -- a live system's own top-level folders (Windows,
    Users, ...) must not each be reported as their own secondary install."""
    fake = _FakeFsInfo(
        root_entries=[
            _FakeEntry(b"Windows", is_dir=True),
            _FakeEntry(b"Users", is_dir=True),
            _FakeEntry(b"ProgramData", is_dir=True),
        ],
        existing_paths={
            "/Windows/System32",
            "/Windows/System32/config/SYSTEM",
            "/Windows/System32/config/SOFTWARE",
            "/Users",
            "/ProgramData",
        },
    )

    installs = _detect_installations(fake, "volume-1")

    assert len(installs) == 1
    assert installs[0]["root_path"] == "/"
