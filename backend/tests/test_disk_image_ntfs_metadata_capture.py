"""NTFS's own metadata files ($MFT and siblings) were never materialized from
a disk image at all -- _should_materialize's whitelist had no entry for them.
Found while investigating why a real disk image (CyberDefenders
"SpottedInTheWild") produced zero $MFT artifact despite mounting and
extracting cleanly: even once that's fixed, an installation whose root_path
is a drive-letter subfolder (e.g. "/C", see the drive-letter-detection work
in test_disk_image_ntfs_boot_sector_repair.py) still never visits the
volume's true root at all, where these files actually live -- so they need a
small, separate, non-recursive top-level scan of the true root.
"""

from __future__ import annotations

from pathlib import Path

import pytsk3

from app.disk_images.service import (
    _NTFS_METADATA_FILENAMES,
    _materialize_volume_installation,
    _should_materialize,
)
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation


def test_should_materialize_recognizes_ntfs_metadata_filenames():
    for name in _NTFS_METADATA_FILENAMES:
        assert _should_materialize(f"/{name}")
        assert _should_materialize(f"/C/{name}")


def test_should_materialize_still_rejects_unrelated_root_files():
    assert not _should_materialize("/random_installer_leftover.tmp")
    assert not _should_materialize("/$RECYCLE.BIN/some_file")


class _FakeFlags:
    pass


class _FakeNameInfo:
    def __init__(self, name: bytes):
        self.name = name


class _FakeMeta:
    def __init__(self, *, is_reg: bool, size: int, data: bytes):
        self.type = pytsk3.TSK_FS_META_TYPE_REG if is_reg else pytsk3.TSK_FS_META_TYPE_DIR
        self.size = size
        self._data = data


class _FakeEntryInfo:
    def __init__(self, name: bytes, meta: _FakeMeta | None):
        self.name = _FakeNameInfo(name)
        self.meta = meta


class _FakeEntry:
    def __init__(self, name: bytes, meta: _FakeMeta | None):
        self.info = _FakeEntryInfo(name, meta)


class _FakeFileObj:
    def __init__(self, data: bytes):
        self._data = data

    def read_random(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


class _FakeFsInfo:
    """Only implements what _materialize_volume_installation's true-root
    metadata scan and the main _iter_directory walk actually call: open_dir
    on a fixed set of paths (raising for anything else, which _iter_directory
    already tolerates), and open() for reading a regular file's content."""

    def __init__(self, root_entries: list[_FakeEntry], files: dict[str, bytes]):
        self._root_entries = root_entries
        self._files = files

    def open_dir(self, path: str):
        if path == "/":
            return list(self._root_entries)
        raise RuntimeError(f"no such fake directory: {path}")

    def open(self, path: str):
        return _FakeFileObj(self._files[path])


def _root_fixture() -> tuple[_FakeFsInfo, dict]:
    mft_data = b"FILE" + b"\x00" * 1020
    entries = [
        _FakeEntry(b".", _FakeMeta(is_reg=False, size=0, data=b"")),
        _FakeEntry(b"..", _FakeMeta(is_reg=False, size=0, data=b"")),
        _FakeEntry(b"$MFT", _FakeMeta(is_reg=True, size=len(mft_data), data=mft_data)),
        _FakeEntry(b"$LogFile", _FakeMeta(is_reg=True, size=4, data=b"log!")),
        _FakeEntry(b"C", _FakeMeta(is_reg=False, size=0, data=b"")),
        _FakeEntry(b"$RECYCLE.BIN", _FakeMeta(is_reg=False, size=0, data=b"")),
        _FakeEntry(b"System Volume Information", _FakeMeta(is_reg=False, size=0, data=b"")),
    ]
    fs_info = _FakeFsInfo(entries, {"/$MFT": mft_data, "/$LogFile": b"log!"})
    return fs_info, {"mft_data": mft_data}


def test_materialization_captures_ntfs_metadata_at_true_root_for_drive_letter_layout(tmp_path):
    fs_info, fixture = _root_fixture()
    install = OSInstallation(platform="windows", root_path="/C")
    disk_image = DiskImage(evidence_id="ev-1", original_filename="test.vhd", format="raw")
    volume = DiskVolume(partition_index=3, offset_bytes=32256, length_bytes=10_000_000)

    extracted_files, manifest_entries, source_map, warnings = _materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path,
    )

    mft_relative = next(p for p in extracted_files if p.endswith("$MFT"))
    assert (tmp_path / mft_relative).read_bytes() == fixture["mft_data"]
    assert source_map[mft_relative]["original_source_path"] == "/$MFT"

    log_relative = next(p for p in extracted_files if p.endswith("$LogFile"))
    assert source_map[log_relative]["original_source_path"] == "/$LogFile"


def test_materialization_does_not_capture_unrelated_root_siblings(tmp_path):
    fs_info, _ = _root_fixture()
    install = OSInstallation(platform="windows", root_path="/C")
    disk_image = DiskImage(evidence_id="ev-1", original_filename="test.vhd", format="raw")
    volume = DiskVolume(partition_index=3, offset_bytes=32256, length_bytes=10_000_000)

    extracted_files, _, _, _ = _materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path,
    )

    assert not any("RECYCLE" in p for p in extracted_files)
    assert not any("System Volume Information" in p for p in extracted_files)
    assert not any(p.rstrip("/").endswith("/C") for p in extracted_files)


def test_materialization_captures_ntfs_metadata_via_the_normal_walk_when_root_is_the_volume_root(tmp_path):
    """When install.root_path is already "/" (no drive-letter subfolder), the
    ordinary recursive walk visits the true root directly -- the
    _should_materialize fix alone is enough there, and the true-root
    addendum must not run a second time and produce duplicates."""
    fs_info, fixture = _root_fixture()
    install = OSInstallation(platform="windows", root_path="/")
    disk_image = DiskImage(evidence_id="ev-1", original_filename="test.vhd", format="raw")
    volume = DiskVolume(partition_index=1, offset_bytes=0, length_bytes=10_000_000)

    extracted_files, _, source_map, _ = _materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path,
    )

    mft_matches = [p for p in extracted_files if p.endswith("$MFT")]
    assert len(mft_matches) == 1
    assert (tmp_path / mft_matches[0]).read_bytes() == fixture["mft_data"]
    assert source_map[mft_matches[0]]["original_source_path"] == "/$MFT"
    assert not any("RECYCLE" in p for p in extracted_files)
