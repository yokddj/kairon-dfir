"""Opening a disk image and one of its volumes as a pytsk3 filesystem.

Kept apart from app.disk_images.service on purpose: it imports nothing but
pytsk3 and the image/LVM readers, so the file explorer's sandboxed helper
(app.disk_images.file_browser_cli) can load it in a fresh process quickly.
The service re-exports every name here, so older imports keep working."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytsk3

from app.disk_images.ewf_img_info import EwfImgInfo
from app.disk_images.lvm import LogicalVolumeReader, parse_physical_volume_metadata
from app.disk_images.lvm.img_info import LogicalVolumeImgInfo


class _PytskFileReader(pytsk3.Img_Info):
    def __init__(self, image_path: Path):
        self._file = image_path.open("rb")
        self._size = image_path.stat().st_size
        super().__init__(url=str(image_path))

    def close(self) -> None:
        try:
            self._file.close()
        except Exception:
            pass

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def get_size(self) -> int:
        return self._size


def _open_disk_image_reader(context: dict[str, Any]) -> "_PytskFileReader | EwfImgInfo":
    """Build the pytsk3.Img_Info every downstream reader (volume/LVM
    discovery, installation detection, materialization) will read every
    byte through, based on what adapter.expose_readonly() returned.

    EWF's own adapter (see app.disk_images.ewf.EwfImageAdapter) never
    writes a temporary RAW file -- context["access_strategy"] ==
    "pyewf_streaming_readonly" is how it signals that bytes should come
    directly from EwfImgInfo (pyewf) instead. Every other format
    (raw, vmdk, vhd/vhdx, qcow/qcow2, vdi) is unchanged: it already wrote
    a real file (or, for raw, never needed to), so _PytskFileReader over
    that path is exactly what ran before this sprint.
    """
    if context.get("access_strategy") == "pyewf_streaming_readonly":
        segments = [Path(item) for item in context.get("segments") or []]
        return EwfImgInfo(segments)
    raw_path = Path(str(context.get("exported_raw_path") or context.get("image_path") or ""))
    return _PytskFileReader(raw_path)


def _safe_reader_read(img: "_PytskFileReader | EwfImgInfo", offset: int, length: int = 4096) -> bytes:
    """Best-effort signature-detection read (encryption/LVM magic bytes)
    against a volume pytsk3 already failed to open as a filesystem --
    never raises, since an unreadable range here just means no signature
    can be identified, not a reason to abort discovery of the rest of
    the image."""
    try:
        return img.read(max(offset, 0), length)
    except Exception:
        return b""


_NTFS_OEM_ID = b"NTFS    "
_NTFS_JUMP_INSTRUCTION = b"\xeb\x52\x90"
_NTFS_BOOT_SIGNATURE = b"\x55\xaa"


def _looks_like_repairable_ntfs_boot_sector(blob: bytes) -> bool:
    """A boot sector whose OEM ID says NTFS but whose jump instruction and/or
    trailing 0x55AA signature are zeroed -- seen on images whose boot sector was
    sanitized/redacted before being shared (e.g. to keep it from booting), while
    the BPB fields that actually carry filesystem geometry (cluster size, MFT
    location, offsets 0x0B-0x53) are left intact. TSK refuses to open these as a
    filesystem at all because the signature it validates on open is missing --
    not because the filesystem itself is unreadable. Both the primary boot
    sector and NTFS's backup copy (last sector of the volume) are checked the
    same way, since a sanitizer that zeroes one typically zeroes both."""
    if len(blob) < 512:
        return False
    if blob[3:11] != _NTFS_OEM_ID:
        return False
    return blob[0:3] != _NTFS_JUMP_INSTRUCTION or blob[510:512] != _NTFS_BOOT_SIGNATURE


def _repair_ntfs_boot_sector(blob: bytes) -> bytes:
    """Restores only the two fields TSK's open-time validation checks --
    changes nothing in the BPB, so the filesystem is read exactly as it always
    was, just past a validation gate that isn't about the data itself."""
    patched = bytearray(blob[:512])
    patched[0:3] = _NTFS_JUMP_INSTRUCTION
    patched[510:512] = _NTFS_BOOT_SIGNATURE
    return bytes(patched)


class _BootSectorPatchedReader(pytsk3.Img_Info):
    """Wraps another Img_Info, substituting a repaired boot sector for the
    original bytes at `boot_sector_offset` -- every other byte, including the
    rest of the same sector, passes through unchanged. Used only as a
    last-resort retry after the unpatched image already failed
    pytsk3.FS_Info, to recover a filesystem whose boot sector was
    sanitized/corrupted but whose actual metadata is intact."""

    def __init__(self, inner: "_PytskFileReader | EwfImgInfo", *, boot_sector_offset: int, patched_boot_sector: bytes):
        self._inner = inner
        self._boot_sector_offset = boot_sector_offset
        self._patched_boot_sector = patched_boot_sector
        # Empty url, not a real path: every byte is served by read()/get_size()
        # below. Same pattern EwfImgInfo already uses for a non-file-backed
        # custom image source -- a stat-able but wrongly-sized path (e.g.
        # /dev/null) would make TSK trust that path's own size over get_size().
        super().__init__(url="")

    def close(self) -> None:
        try:
            self._inner.close()
        except Exception:
            pass

    def get_size(self) -> int:
        return self._inner.get_size()

    def read(self, offset: int, size: int) -> bytes:
        data = bytearray(self._inner.read(offset, size))
        patch_start = self._boot_sector_offset
        patch_end = patch_start + len(self._patched_boot_sector)
        overlap_start = max(offset, patch_start)
        overlap_end = min(offset + size, patch_end, offset + len(data))
        if overlap_start < overlap_end:
            data[overlap_start - offset : overlap_end - offset] = self._patched_boot_sector[overlap_start - patch_start : overlap_end - patch_start]
        return bytes(data)


def _try_repair_ntfs_boot_sector(img: "_PytskFileReader | EwfImgInfo", offset_bytes: int, blob: bytes) -> pytsk3.FS_Info | None:
    if not _looks_like_repairable_ntfs_boot_sector(blob):
        return None
    patched_reader = _BootSectorPatchedReader(img, boot_sector_offset=offset_bytes, patched_boot_sector=_repair_ntfs_boot_sector(blob))
    try:
        return pytsk3.FS_Info(patched_reader, offset=offset_bytes)
    except Exception:
        return None


def _open_logical_volume_fs_info(read_physical, logical_volume_name: str) -> pytsk3.FS_Info:
    """Parse a Physical Volume's metadata (via read_physical, an
    offset-0-relative ByteRangeReader already bound to that PV's own start)
    and build a pytsk3.FS_Info for the one logical volume named
    logical_volume_name. Used only by _open_persisted_volume_fs_info (see
    below), for materialize_disk_image_sources's second, independent open --
    that call site only has a persisted DiskVolume's metadata_json to
    reconstruct from, not the original in-memory PhysicalVolumeMetadata/
    VolumeGroup objects _discover_logical_volumes built the first time.
    _discover_logical_volumes itself does not call this: it already has the
    parsed VolumeGroup in hand and constructs each logical volume's reader
    directly, without a second parse."""
    pv_metadata = parse_physical_volume_metadata(read_physical)
    logical_volume = next((lv for lv in pv_metadata.volume_group.logical_volumes if lv.name == logical_volume_name), None)
    if logical_volume is None:
        raise ValueError(f"logical volume {logical_volume_name!r} not found while reparsing volume group {pv_metadata.volume_group.name!r}")
    reader = LogicalVolumeReader(logical_volume, pv_metadata.volume_group, read_physical)
    return pytsk3.FS_Info(LogicalVolumeImgInfo(reader))


def _volume_byte_reader(image_reader: "_PytskFileReader | EwfImgInfo", volume: Any):
    """read(offset, size) over the volume's own bytes (offset 0 = start of the
    filesystem), for the readers that need raw blocks TSK does not expose,
    such as the ext3/ext4 journal parser. Plain partitions and logical volumes
    only; the NTFS boot-sector repair does not matter for raw block reads."""
    lvm_marker = (volume.metadata_json or {}).get("lvm")
    if lvm_marker:
        container_offset_bytes = int(lvm_marker["container_offset_bytes"])

        def read_physical(offset: int, size: int) -> bytes:
            return image_reader.read(container_offset_bytes + offset, size)

        pv_metadata = parse_physical_volume_metadata(read_physical)
        logical_volume = next(lv for lv in pv_metadata.volume_group.logical_volumes if lv.name == str(lvm_marker["logical_volume"]))
        img = LogicalVolumeImgInfo(LogicalVolumeReader(logical_volume, pv_metadata.volume_group, read_physical))
        return img.read
    offset_bytes = int(volume.offset_bytes)
    return lambda offset, size: image_reader.read(offset_bytes + offset, size)


def _open_persisted_volume_fs_info(image_reader: "_PytskFileReader | EwfImgInfo", volume: Any) -> pytsk3.FS_Info:
    """Reopen a pytsk3.FS_Info for an already-persisted DiskVolume, for
    materialization. A plain partition is reopened exactly as before (a flat
    byte offset into the raw image); a logical volume -- identified by the
    "lvm" marker _discover_logical_volumes left in metadata_json -- is not a
    single contiguous byte range in the raw image in general, so its owning
    Physical Volume's metadata is reparsed (cheap: a few KB of text) and the
    same LogicalVolumeReader/LogicalVolumeImgInfo chain is rebuilt instead.
    Callers already treat any exception from this the same way regardless of
    which path was taken (skip materializing this volume this run)."""
    lvm_marker = (volume.metadata_json or {}).get("lvm")
    if lvm_marker:
        container_offset_bytes = int(lvm_marker["container_offset_bytes"])
        logical_volume_name = str(lvm_marker["logical_volume"])

        def read_physical(offset: int, size: int) -> bytes:
            return image_reader.read(container_offset_bytes + offset, size)

        return _open_logical_volume_fs_info(read_physical, logical_volume_name)
    offset_bytes = int(volume.offset_bytes)
    try:
        if volume.partition_index != 0 or offset_bytes:
            return pytsk3.FS_Info(image_reader, offset=offset_bytes)
        return pytsk3.FS_Info(image_reader)
    except Exception:
        # Discovery may have opened this exact volume through the boot-sector
        # repair path (see _discover_raw_volumes) -- that isn't persisted
        # anywhere, so a volume recovered that way needs the same repair
        # retried here, or materialization would silently skip it even though
        # discovery already proved its data is readable.
        if "ntfs_boot_sector_repaired" not in (volume.warnings_json or []):
            raise
        blob = _safe_reader_read(image_reader, offset_bytes)
        repaired = _try_repair_ntfs_boot_sector(image_reader, offset_bytes, blob)
        if repaired is None:
            raise
        return repaired
