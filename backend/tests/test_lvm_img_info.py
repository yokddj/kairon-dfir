"""Tests for app.disk_images.lvm.img_info.LogicalVolumeImgInfo (PR2, Layer 2).

Kept deliberately separate from test_lvm_reader.py: this is the one test
file in the LVM suite allowed to import pytsk3 (directly, and indirectly by
importing app.disk_images.lvm.img_info). test_lvm_reader.py's whole point
is proving Layer 1 needs none of that.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from app.disk_images.lvm.img_info import LogicalVolumeImgInfo
from app.disk_images.lvm.models import LinearSegment, LogicalVolume, MetadataArea, PhysicalVolume, VolumeGroup
from app.disk_images.lvm.reader import LogicalVolumeReader

EXTENT_SIZE = 4096
PE_START = 0


def _single_segment_reader(buffer: bytes) -> LogicalVolumeReader:
    pv = PhysicalVolume(
        name="pv0",
        id="pv0-uuid",
        device_size_bytes=len(buffer),
        extent_size_bytes=EXTENT_SIZE,
        pe_start_bytes=PE_START,
        extent_count=len(buffer) // EXTENT_SIZE,
    )
    vg = VolumeGroup(
        name="vg0",
        id="vg0-uuid",
        extent_size_bytes=EXTENT_SIZE,
        physical_volumes=(pv,),
        logical_volumes=(),
        metadata_area=MetadataArea(
            header_offset_bytes=0,
            area_size_bytes=EXTENT_SIZE,
            metadata_text_offset_bytes=0,
            metadata_text_size_bytes=0,
        ),
    )
    segment = LinearSegment(
        start_extent=0,
        extent_count=len(buffer) // EXTENT_SIZE,
        physical_volume_name="pv0",
        start_physical_extent=0,
    )
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(segment,))
    return LogicalVolumeReader(lv, vg, lambda offset, size: buffer[offset : offset + size])


def test_read_forwards_to_reader():
    buffer = bytes(i % 256 for i in range(EXTENT_SIZE * 4))
    reader = _single_segment_reader(buffer)
    img_info = LogicalVolumeImgInfo(reader)

    assert img_info.read(100, 50) == reader.read(100, 50)
    assert img_info.read(0, EXTENT_SIZE) == reader.read(0, EXTENT_SIZE)


def test_get_size_forwards_to_reader_size_bytes():
    buffer = bytes(EXTENT_SIZE * 3)
    reader = _single_segment_reader(buffer)
    img_info = LogicalVolumeImgInfo(reader)

    assert img_info.get_size() == reader.size_bytes == len(buffer)


def test_close_is_a_safe_noop_and_reader_remains_usable():
    buffer = bytes(i % 256 for i in range(EXTENT_SIZE * 2))
    reader = _single_segment_reader(buffer)
    img_info = LogicalVolumeImgInfo(reader)

    img_info.close()  # must not raise

    # LogicalVolumeReader owns no closable resource of its own -- closing
    # the adapter must not disturb it (see img_info.py's close() docstring).
    assert img_info.read(0, 10) == buffer[0:10]


def _require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


def test_real_fs_info_reads_a_file_through_the_adapter(tmp_path):
    """End-to-end proof that a real pytsk3.FS_Info can be built directly on
    top of LogicalVolumeImgInfo -- the same way app.disk_images.service
    already builds one on top of _PytskFileReader for a plain file -- by
    pointing it at a real FAT filesystem's bytes served through a synthetic,
    single-segment Logical Volume instead of a real LVM disk."""
    _require_tools("mkfs.vfat", "mcopy")

    fs_image = tmp_path / "fs.img"
    subprocess.run(["mkfs.vfat", "-C", str(fs_image), "1024"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    marker_file = tmp_path / "marker.txt"
    marker_file.write_text("lvm reader layer 2 smoke test\n")
    subprocess.run(["mcopy", "-i", str(fs_image), str(marker_file), "::marker.txt"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    buffer = fs_image.read_bytes()
    padded_len = ((len(buffer) + EXTENT_SIZE - 1) // EXTENT_SIZE) * EXTENT_SIZE
    buffer = buffer.ljust(padded_len, b"\x00")
    reader = _single_segment_reader(buffer)
    img_info = LogicalVolumeImgInfo(reader)

    import pytsk3

    fs = pytsk3.FS_Info(img_info)
    entries = [entry.info.name.name.decode() for entry in fs.open_dir("/") if entry.info.name is not None]
    assert "MARKER.TXT" in entries or "marker.txt" in entries
