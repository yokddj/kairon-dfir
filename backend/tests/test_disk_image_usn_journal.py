"""$UsnJrnl's actual journal records live entirely in its named "$J"
Alternate Data Stream -- the file's own default/unnamed attribute is always
empty, and a plain directory listing never exposes ADS as separate entries
at all (verified against the real "SpottedInTheWild" evidence: 0 of 1501
walked entries had a colon in their name). Sleuthkit only exposes named
streams by iterating a File's attributes and re-reading with an explicit
(type, id) pair. This generalizes the same read mechanism to any evidence
with a real USN journal -- this specific evidence doesn't have one (its
$Extend has no $UsnJrnl at all), so this is verified with a real pytsk3
attribute-selection call against a different, always-present named NTFS
stream ($Secure's $SDS) plus unit tests with fakes for the $J-specific path.
"""

from __future__ import annotations

from pathlib import Path

import pytsk3

from app.disk_images.service import (
    _NTFS_METADATA_FILENAMES,
    _materialize_volume_installation,
    _read_usn_journal_j_stream,
    _should_materialize,
)
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation


class _FakeAttrInfo:
    def __init__(self, name: bytes | None, attr_type: int, attr_id: int, size: int):
        self.name = name
        self.type = attr_type
        self.id = attr_id
        self.size = size


class _FakeAttr:
    def __init__(self, info: _FakeAttrInfo):
        self.info = info


class _FakeUsnJrnlFile:
    """Mirrors the real shape: iterating a pytsk3.File yields its
    attributes, and read_random only returns the $J stream's real content
    when explicitly asked for that (type, id) pair -- exactly like the
    default/unnamed attribute being empty on a real $UsnJrnl."""

    def __init__(self, j_data: bytes, j_id: int = 6):
        self._j_data = j_data
        self._j_id = j_id
        self.info = type("Info", (), {"meta": type("Meta", (), {"size": 0})()})()

    def __iter__(self):
        return iter(
            [
                _FakeAttr(_FakeAttrInfo(None, pytsk3.TSK_FS_ATTR_TYPE_DEFAULT, 0, 0)),
                _FakeAttr(_FakeAttrInfo(b"$J", pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA, self._j_id, len(self._j_data))),
            ]
        )

    def read_random(self, offset: int, size: int, attr_type=None, attr_id=None, flags=0):
        if attr_type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr_id == self._j_id:
            return self._j_data[offset : offset + size]
        return b""


def test_should_materialize_recognizes_usn_journal():
    assert "$UsnJrnl" in _NTFS_METADATA_FILENAMES
    assert _should_materialize("/$Extend/$UsnJrnl")


def test_read_usn_journal_j_stream_returns_the_named_stream_content():
    fake = _FakeUsnJrnlFile(b"USN-RECORD-BYTES" * 100)
    assert _read_usn_journal_j_stream(fake) == b"USN-RECORD-BYTES" * 100


def test_read_usn_journal_j_stream_returns_none_when_no_j_attribute_exists():
    class _NoJFile:
        def __iter__(self):
            return iter([_FakeAttr(_FakeAttrInfo(None, pytsk3.TSK_FS_ATTR_TYPE_DEFAULT, 0, 0))])

        def read_random(self, *args, **kwargs):
            raise AssertionError("should never be called when no $J attribute exists")

    assert _read_usn_journal_j_stream(_NoJFile()) is None


def test_read_usn_journal_j_stream_returns_none_when_j_attribute_is_empty():
    fake = _FakeUsnJrnlFile(b"")
    assert _read_usn_journal_j_stream(fake) is None


def test_read_usn_journal_j_stream_caps_at_the_configured_maximum(monkeypatch):
    import app.disk_images.service as service

    monkeypatch.setattr(service, "_USN_JOURNAL_MAX_BYTES", 10)
    fake = _FakeUsnJrnlFile(b"0123456789" * 5)
    assert _read_usn_journal_j_stream(fake) == b"0123456789"


class _FakeNameInfo:
    def __init__(self, name: bytes):
        self.name = name


class _FakeMeta:
    def __init__(self, *, is_reg: bool):
        self.type = pytsk3.TSK_FS_META_TYPE_REG if is_reg else pytsk3.TSK_FS_META_TYPE_DIR
        self.size = 0


class _FakeEntryInfo:
    def __init__(self, name: bytes, meta: _FakeMeta | None):
        self.name = _FakeNameInfo(name)
        self.meta = meta


class _FakeEntry:
    def __init__(self, name: bytes, meta: _FakeMeta | None):
        self.info = _FakeEntryInfo(name, meta)


class _FakeFsInfoWithUsnJrnl:
    """A drive-letter-layout volume ("/C" + true root) whose true root has
    a real $Extend/$UsnJrnl -- exercises the true-root addendum's separate
    directory scan for it, not just the top-level metadata scan."""

    def __init__(self, j_data: bytes):
        self._j_data = j_data
        self._usn_file = _FakeUsnJrnlFile(j_data)

    def open_dir(self, path: str):
        if path == "/":
            return [
                _FakeEntry(b"C", _FakeMeta(is_reg=False)),
                _FakeEntry(b"$Extend", _FakeMeta(is_reg=False)),
            ]
        if path == "/$Extend":
            return [_FakeEntry(b"$UsnJrnl", _FakeMeta(is_reg=True))]
        raise RuntimeError(f"unsupported fake path: {path}")

    def open(self, path: str):
        if path == "/$Extend/$UsnJrnl":
            return self._usn_file
        raise FileNotFoundError(path)


def test_materialization_extracts_the_usn_journal_for_a_drive_letter_layout(tmp_path):
    fs_info = _FakeFsInfoWithUsnJrnl(b"USN-JOURNAL-RECORD-DATA" * 50)
    install = OSInstallation(platform="windows", root_path="/C")
    disk_image = DiskImage(evidence_id="ev-1", original_filename="test.vhd", format="raw")
    volume = DiskVolume(partition_index=1, offset_bytes=32256, length_bytes=10_000_000)

    extracted_files, _, source_map, _ = _materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path,
    )

    usn_relative = next(p for p in extracted_files if p.endswith("$UsnJrnl"))
    assert (tmp_path / usn_relative).read_bytes() == b"USN-JOURNAL-RECORD-DATA" * 50
    assert source_map[usn_relative]["original_source_path"] == "/$Extend/$UsnJrnl"
