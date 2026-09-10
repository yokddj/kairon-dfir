"""NTFS boot sector repair.

Found on the CyberDefenders "SpottedInTheWild" CTF image: a VHD whose NTFS
partition's boot sector (and its backup copy at the end of the volume) had
the jump instruction and the mandatory 0x55AA signature zeroed, while the BPB
fields that actually carry filesystem geometry were untouched. TSK's own
mmls/fsstat reproduced the same "Cannot determine file system type" failure
independently of Kairon, confirming this is a real boot-sector integrity gap
in the source image, not a parsing bug -- but the underlying data is still
there, so Kairon should recover it rather than reporting zero files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import pytsk3

from app.disk_images.service import (
    _BootSectorPatchedReader,
    _looks_like_repairable_ntfs_boot_sector,
    _repair_ntfs_boot_sector,
    _try_repair_ntfs_boot_sector,
)


def _require_mkntfs() -> None:
    if subprocess.run(["bash", "-lc", "command -v mkntfs >/dev/null 2>&1"], check=False).returncode != 0:
        pytest.skip("mkntfs not available")


def _make_ntfs_volume(path: Path, size_mb: int = 20) -> None:
    _require_mkntfs()
    path.write_bytes(b"\x00" * (size_mb * 1024 * 1024))
    subprocess.run(
        ["mkntfs", "-F", "-Q", "-L", "TESTVOL", str(path)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _sanitize_boot_sector(path: Path) -> bytes:
    """Reproduces the exact corruption observed on the real CTF image: the
    jump instruction and everything from offset 0x50 onward (including the
    mandatory 0x55AA signature) zeroed, while the OEM ID and BPB geometry
    fields before it are left untouched. Returns the original 512 bytes."""
    data = bytearray(path.read_bytes())
    original = bytes(data[:512])
    data[0:3] = b"\x00\x00\x00"
    data[0x50:512] = b"\x00" * (512 - 0x50)
    path.write_bytes(bytes(data))
    return original


class _FakeInnerReader:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]

    def get_size(self) -> int:
        return len(self._data)

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------
# Pure byte-level logic: no external tools, no pytsk3 filesystem semantics.
# --------------------------------------------------------------------------


def test_looks_like_repairable_boot_sector_flags_zeroed_jump_and_signature():
    blob = bytearray(512)
    blob[3:11] = b"NTFS    "
    assert _looks_like_repairable_ntfs_boot_sector(bytes(blob))


def test_looks_like_repairable_boot_sector_ignores_non_ntfs_oem_id():
    blob = bytearray(512)
    blob[3:11] = b"MSDOS5.0"
    assert not _looks_like_repairable_ntfs_boot_sector(bytes(blob))


def test_looks_like_repairable_boot_sector_ignores_an_already_valid_sector():
    blob = bytearray(512)
    blob[0:3] = b"\xeb\x52\x90"
    blob[3:11] = b"NTFS    "
    blob[510:512] = b"\x55\xaa"
    assert not _looks_like_repairable_ntfs_boot_sector(bytes(blob))


def test_looks_like_repairable_boot_sector_rejects_short_blobs():
    assert not _looks_like_repairable_ntfs_boot_sector(b"NTFS    ")


def test_repair_only_touches_the_two_validated_fields():
    blob = bytearray(512)
    blob[3:11] = b"NTFS    "
    blob[11:13] = b"\x00\x02"  # bytes-per-sector BPB field, arbitrary non-zero marker
    repaired = _repair_ntfs_boot_sector(bytes(blob))
    assert repaired[0:3] == b"\xeb\x52\x90"
    assert repaired[510:512] == b"\x55\xaa"
    assert repaired[3:11] == b"NTFS    "
    assert repaired[11:13] == b"\x00\x02"


def test_boot_sector_patched_reader_splices_only_the_patched_range():
    inner = _FakeInnerReader(b"A" * 4096)
    reader = _BootSectorPatchedReader(inner, boot_sector_offset=512, patched_boot_sector=b"B" * 512)
    whole = reader.read(0, 4096)
    assert whole[:512] == b"A" * 512
    assert whole[512:1024] == b"B" * 512
    assert whole[1024:] == b"A" * (4096 - 1024)


def test_boot_sector_patched_reader_handles_a_read_starting_inside_the_patch():
    inner = _FakeInnerReader(b"A" * 4096)
    reader = _BootSectorPatchedReader(inner, boot_sector_offset=512, patched_boot_sector=b"B" * 512)
    assert reader.read(700, 100) == b"B" * 100


def test_boot_sector_patched_reader_passes_through_reads_outside_the_patch():
    inner = _FakeInnerReader(b"A" * 4096)
    reader = _BootSectorPatchedReader(inner, boot_sector_offset=512, patched_boot_sector=b"B" * 512)
    assert reader.read(0, 100) == b"A" * 100
    assert reader.read(2000, 100) == b"A" * 100


# --------------------------------------------------------------------------
# End-to-end: a real NTFS volume, corrupted the same way, actually recovered.
# --------------------------------------------------------------------------


def test_repair_recovers_a_real_ntfs_volume_with_a_sanitized_boot_sector(tmp_path):
    image_path = tmp_path / "volume.raw"
    _make_ntfs_volume(image_path)
    _sanitize_boot_sector(image_path)

    # Confirm the corruption actually reproduces the real-world failure --
    # otherwise this test would prove nothing about the repair.
    with pytest.raises(Exception):
        pytsk3.FS_Info(pytsk3.Img_Info(str(image_path)))

    blob = image_path.read_bytes()[:512]
    assert _looks_like_repairable_ntfs_boot_sector(blob)

    fs_info = _try_repair_ntfs_boot_sector(pytsk3.Img_Info(str(image_path)), 0, blob)

    assert fs_info is not None
    root_entries = {entry.info.name.name.decode("utf-8", "replace") for entry in fs_info.open_dir(path="/") if entry.info.name}
    assert {"$MFT", "$Boot", "$Bitmap"} <= root_entries


def test_repair_is_not_attempted_for_an_unrelated_failure(tmp_path):
    image_path = tmp_path / "garbage.raw"
    image_path.write_bytes(b"\x00" * (1024 * 1024))
    blob = image_path.read_bytes()[:512]
    assert _try_repair_ntfs_boot_sector(pytsk3.Img_Info(str(image_path)), 0, blob) is None
