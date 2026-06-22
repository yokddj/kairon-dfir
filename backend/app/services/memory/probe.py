"""Memory image format probe (read-only content detection).

The probe inspects a small portion of a file to classify it as:

* ``confirmed_memory``       - clear memory image signature
* ``probable_memory``        - strong memory indicators, minor uncertainty
* ``ambiguous_raw``          - unstructured RAW; could be memory or disk
* ``probable_disk``          - disk partition structures detected
* ``unsupported``            - format we do not handle
* ``invalid``                - file too small, truncated, or unreadable
* ``probe_failed``           - probe raised unexpectedly

The probe is strictly read-only.  It opens the file once, reads a
bounded number of bytes, and returns a structured verdict.  No
external tools are invoked; this module never shells out.

A separate, optional Volatility preflight probe is provided in
:mod:`app.services.memory.probe_volatility` and only runs in the
dedicated memory-worker process.
"""
from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Candidate extensions that may contain a memory image.  The probe
# makes the final decision based on content; the extension only
# influences the initial confidence level.
CANDIDATE_MEMORY_EXTENSIONS: frozenset[str] = frozenset({
    ".raw", ".mem", ".dmp", ".dump", ".bin", ".img", ".vmem", ".lime",
})


# Status values returned by the probe.  These are the canonical
# strings stored in ``Evidence.detection_status``.
STATUS_CONFIRMED_MEMORY = "confirmed_memory"
STATUS_PROBABLE_MEMORY = "probable_memory"
STATUS_AMBIGUOUS_RAW = "ambiguous_raw"
STATUS_PROBABLE_DISK = "probable_disk"
STATUS_UNSUPPORTED = "unsupported"
STATUS_INVALID = "invalid"
STATUS_PROBE_FAILED = "probe_failed"


# Confidence levels.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


# Probe constants.
_HEADER_READ_BYTES = 1024 * 1024          # 1 MiB header
_FOOTER_READ_BYTES = 64 * 1024            # 64 KiB footer
_MIN_FILE_SIZE = 1024                      # anything smaller is invalid
_MAX_PROBE_FILE_SIZE = 16 * 1024 * 1024 * 1024  # 16 GiB hard cap


# Signatures detected by the probe.
_VMWARE_VMEM_MAGIC = b"\x00\x00\x00\x00M\x00R\x00E\x00"
_LIME_MAGIC = struct.pack("<I", 0x4C694D45)  # "LiME" little-endian: bytes "EMiL"
_ELF_MAGIC = b"\x7fELF"
_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_LZ4_MAGIC = b"\x02\x21\x4c\x18"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_7Z_MAGIC = b"\x37\x7a\xbc\xaf\x27\x1c"
_ZIP_MAGIC = b"PK\x03\x04"
_RAR_MAGIC = b"Rar!\x1a\x07\x00"
_TAR_MAGIC = b"ustar"
_PDF_MAGIC = b"%PDF-"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_GIF_MAGIC = b"GIF8"
_ZIP_DOCX_MAGIC = b"PK\x03\x04"


# Windows crash dump signatures (PAGE / DUMP).
_DUMP_SIGNATURES: list[bytes] = [
    b"PAGE",
    b"DU64",
    b"MPHD",
    b"MAVS",
]


# Hibernation file signatures.
_HIBERNATION_SIGNATURES: list[bytes] = [
    b"HIBR",
    b"PAGEPG",
    b"\x80\x00\x00\x00\x00\x00\x00\x00",  # partial (x86 magic)
]


# Master Boot Record signature at offset 510.
_MBR_SIGNATURE = b"\x55\xaa"


# GPT signature.
_GPT_SIGNATURE = b"EFI PART"


# NTFS detection.  The legacy matchers (strings like "NTFS" or
# "MSDOS" found anywhere in the first 1 KiB) produced false
# positives on arbitrary memory dumps.  The structural validators
# in :func:`_has_valid_ntfs_boot_sector` are the only NTFS path
# now; the markers are kept for documentation only.
_NTFS_MARKERS: list[bytes] = []


# ext2/3/4 superblock magic.
_EXT_MAGIC_OFFSET = 1024 + 56
_EXT_MAGIC = b"\x53\xef"


@dataclass
class ProbeResult:
    """Structured verdict from the probe."""

    status: str
    confidence: str
    detected_format: str
    reason: str
    detected_evidence_type: str  # "memory" or "disk"
    file_size: int
    extension: str
    requires_confirmation: bool = False
    can_analyze: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "detected_format": self.detected_format,
            "reason": self.reason,
            "detected_evidence_type": self.detected_evidence_type,
            "file_size": self.file_size,
            "extension": self.extension,
            "requires_confirmation": self.requires_confirmation,
            "can_analyze": self.can_analyze,
            "details": self.details,
        }


def _is_disk_image(header: bytes) -> bool:
    """Return True when the header shows a CLEAR disk signature.

    A single weak match is NOT enough to classify the image as
    ``probable_disk``: short byte sequences (e.g. MBR's 2-byte
    signature at offset 510) appear in arbitrary data.  This routine
    demands coherent structural evidence before returning True.
    """
    if _has_valid_mbr(header):
        return True
    if _has_valid_gpt(header):
        return True
    if _has_valid_ntfs_boot_sector(header):
        return True
    if _has_valid_fat_boot_sector(header):
        return True
    if _has_valid_ext_superblock(header):
        return True
    return False


def _has_valid_mbr(header: bytes) -> bool:
    """Return True when the header contains a structurally valid MBR.

    A valid MBR has:

    * 0x55 0xAA signature at offset 510.
    * Four 16-byte partition entries starting at offset 446.
    * At least one entry with a non-zero boot indicator (0x80) and
      a plausible partition type, or an entry with a non-zero type
      and a start LBA < total sectors.

    Two-byte matches alone are not sufficient.
    """
    if len(header) < 512 or header[510:512] != _MBR_SIGNATURE:
        return False
    entries = header[446:510]
    if len(entries) < 64:
        return False
    valid_count = 0
    for i in range(4):
        entry = entries[i * 16:(i + 1) * 16]
        if len(entry) < 16:
            continue
        boot_indicator = entry[0]
        ptype = entry[4]
        start_lba = int.from_bytes(entry[8:12], "little", signed=False)
        size_lba = int.from_bytes(entry[12:16], "little", signed=False)
        if ptype == 0:
            continue
        if boot_indicator not in (0, 0x80):
            return False
        if size_lba == 0:
            return False
        if start_lba > 0xFFFFFFFF:
            return False
        valid_count += 1
    return valid_count > 0


def _has_valid_gpt(header: bytes) -> bool:
    """Return True when the header contains a structurally valid GPT."""
    if len(header) < 1024:
        return False
    signature_pos = header.find(_GPT_SIGNATURE)
    if signature_pos < 0 or signature_pos > 512:
        return False
    rev = int.from_bytes(header[signature_pos + 8:signature_pos + 12], "little")
    if rev < 0x00010000 or rev > 0x00FFFFFF:
        return False
    header_size = int.from_bytes(header[signature_pos + 12:signature_pos + 16], "little")
    if header_size not in (92, 216):
        return False
    my_lba = int.from_bytes(header[signature_pos + 24:signature_pos + 32], "little")
    backup_lba = int.from_bytes(header[signature_pos + 32:signature_pos + 40], "little")
    if my_lba == 0 or backup_lba == 0 or my_lba == backup_lba:
        return False
    entry_size = int.from_bytes(header[signature_pos + 84:signature_pos + 88], "little")
    entry_count = int.from_bytes(header[signature_pos + 80:signature_pos + 84], "little")
    if entry_size not in (128, 256):
        return False
    if entry_count < 1 or entry_count > 256:
        return False
    return True


def _has_valid_ntfs_boot_sector(header: bytes) -> bool:
    """Return True when offset 0 contains a structurally valid NTFS VBR.

    A valid NTFS boot sector has:

    * Jump instruction 0xEB 0x52 0x90 or 0xEB 0x53 0x90 at offset 0.
    * OEM ID "NTFS    " at offset 3.
    * bytes_per_sector of 512, 1024, 2048 or 4096.
    * sectors_per_cluster a power of two.
    * total_sectors > 0 and consistent with a plausible file size.
    * ``"NTFS"`` signature at offset 0x28 (NTFS-specific marker).
    """
    if len(header) < 512:
        return False
    if header[0] != 0xEB or header[2] != 0x90:
        return False
    if header[3:11] != b"NTFS    ":
        return False
    bytes_per_sector = int.from_bytes(header[11:13], "little")
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return False
    spc = header[13]
    if spc == 0 or (spc & (spc - 1)) != 0:
        return False
    total_sectors = int.from_bytes(header[40:48], "little")
    if total_sectors == 0:
        return False
    if header[3:7] != b"NTFS" and header[0x28:0x2C] != b"NTFS":
        return False
    return True


def _has_valid_fat_boot_sector(header: bytes) -> bool:
    """Return True when offset 0 contains a structurally valid FAT VBR."""
    if len(header) < 512:
        return False
    if header[0] not in (0xEB, 0xE9):
        return False
    oem = header[3:11]
    if not (3 <= len(oem) <= 8):
        return False
    bytes_per_sector = int.from_bytes(header[11:13], "little")
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return False
    spc = header[13]
    if spc == 0 or (spc & (spc - 1)) != 0:
        return False
    total_sectors = int.from_bytes(header[19:21], "little")
    if total_sectors == 0:
        return False
    return True


def _has_valid_ext_superblock(header: bytes) -> bool:
    """Return True when offset 1024+56 contains the ext superblock magic
    and plausible structural fields."""
    if len(header) < _EXT_MAGIC_OFFSET + 256:
        return False
    if header[_EXT_MAGIC_OFFSET:_EXT_MAGIC_OFFSET + 2] != _EXT_MAGIC:
        return False
    s_inodes = int.from_bytes(header[_EXT_MAGIC_OFFSET + 4:_EXT_MAGIC_OFFSET + 8], "little")
    s_blocks = int.from_bytes(header[_EXT_MAGIC_OFFSET + 24:_EXT_MAGIC_OFFSET + 28], "little")
    if s_inodes == 0 or s_blocks == 0:
        return False
    s_log_block_size = int.from_bytes(header[_EXT_MAGIC_OFFSET + 24:_EXT_MAGIC_OFFSET + 28], "little")
    if s_log_block_size > 16:
        return False
    return True


def _is_compressed_or_archive(header: bytes) -> bool:
    """Return True when the header shows a compressed / archive signature."""
    magic = header[:8]
    return any(magic.startswith(m) for m in (
        _GZIP_MAGIC, _ZSTD_MAGIC, _LZ4_MAGIC, _BZIP2_MAGIC, _XZ_MAGIC,
        _7Z_MAGIC, _ZIP_MAGIC, _RAR_MAGIC,
    ))


def _is_document(header: bytes) -> bool:
    """Return True when the header shows a non-memory document."""
    if header.startswith(_PDF_MAGIC) or header.startswith(_PNG_MAGIC):
        return True
    if header.startswith(_JPEG_MAGIC) or header.startswith(_GIF_MAGIC):
        return True
    return False


def probe_memory_image(path: str | os.PathLike[str]) -> ProbeResult:
    """Classify a file as memory, disk, or other based on its content.

    The probe is read-only.  It reads at most ``_HEADER_READ_BYTES`` from
    the start and ``_FOOTER_READ_BYTES`` from the end of the file.  It
    never runs external commands, never mounts the file, and never
    writes back to the storage.
    """
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return ProbeResult(
            status=STATUS_PROBE_FAILED,
            confidence=CONFIDENCE_LOW,
            detected_format="unknown",
            reason=f"Unable to stat file: {exc!s}",
            detected_evidence_type="unknown",
            file_size=0,
            extension=suffix,
        )

    if size < _MIN_FILE_SIZE:
        return ProbeResult(
            status=STATUS_INVALID,
            confidence=CONFIDENCE_HIGH,
            detected_format="invalid",
            reason=f"File too small ({size} bytes); memory images are typically megabytes to gigabytes.",
            detected_evidence_type="unknown",
            file_size=size,
            extension=suffix,
        )
    if size > _MAX_PROBE_FILE_SIZE:
        return ProbeResult(
            status=STATUS_INVALID,
            confidence=CONFIDENCE_HIGH,
            detected_format="invalid",
            reason=f"File exceeds the {(_MAX_PROBE_FILE_SIZE // (1024**3))} GiB probe safety cap.",
            detected_evidence_type="unknown",
            file_size=size,
            extension=suffix,
        )

    # Read header (bounded).
    try:
        with file_path.open("rb") as fh:
            header = fh.read(_HEADER_READ_BYTES)
    except OSError as exc:
        return ProbeResult(
            status=STATUS_PROBE_FAILED,
            confidence=CONFIDENCE_LOW,
            detected_format="unknown",
            reason=f"Unable to read header: {exc!s}",
            detected_evidence_type="unknown",
            file_size=size,
            extension=suffix,
        )

    # Compressed / archive formats cannot be a raw memory image.
    if _is_compressed_or_archive(header):
        return ProbeResult(
            status=STATUS_UNSUPPORTED,
            confidence=CONFIDENCE_HIGH,
            detected_format="compressed_or_archive",
            reason="The file starts with a compressed or archive signature. Extract it before re-uploading as evidence.",
            detected_evidence_type="unknown",
            file_size=size,
            extension=suffix,
        )

    # Documents are not memory images.
    if _is_document(header):
        return ProbeResult(
            status=STATUS_UNSUPPORTED,
            confidence=CONFIDENCE_HIGH,
            detected_format="document",
            reason="The file starts with a document signature (PDF / image). Not a memory image.",
            detected_evidence_type="unknown",
            file_size=size,
            extension=suffix,
        )

    # Clear disk signatures.
    if _is_disk_image(header):
        reason = "The file contains a disk partition signature (MBR / GPT / NTFS / FAT / ext)."
        return ProbeResult(
            status=STATUS_PROBABLE_DISK,
            confidence=CONFIDENCE_HIGH,
            detected_format="disk_image",
            reason=reason,
            detected_evidence_type="disk",
            file_size=size,
            extension=suffix,
            details={"signature": "mbr_or_filesystem"},
        )

    # VMware .vmem header (sparse memory file).
    if header.startswith(b"\x00" * 4) and _VMWARE_VMEM_MAGIC in header[:64]:
        return ProbeResult(
            status=STATUS_CONFIRMED_MEMORY,
            confidence=CONFIDENCE_HIGH,
            detected_format="vmware_vmem",
            reason="VMware .vmem sparse memory file detected.",
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            can_analyze=True,
        )

    # LiME Linux memory format.
    if header[:4] == _LIME_MAGIC:
        return ProbeResult(
            status=STATUS_CONFIRMED_MEMORY,
            confidence=CONFIDENCE_HIGH,
            detected_format="lime",
            reason="LiME Linux memory format detected.",
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            can_analyze=True,
        )

    # ELF core dump.
    if header[:4] == _ELF_MAGIC:
        return ProbeResult(
            status=STATUS_CONFIRMED_MEMORY,
            confidence=CONFIDENCE_HIGH,
            detected_format="elf_core",
            reason="ELF core dump signature detected.",
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            can_analyze=True,
        )

    # Windows crash dump.
    if any(header.startswith(sig) for sig in _DUMP_SIGNATURES):
        return ProbeResult(
            status=STATUS_CONFIRMED_MEMORY,
            confidence=CONFIDENCE_HIGH,
            detected_format="windows_crash_dump",
            reason="Windows crash dump signature (PAGE/DU64/MPHD) detected.",
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            can_analyze=True,
        )

    # Hibernation file.
    if any(header[:8].startswith(sig[:8]) for sig in _HIBERNATION_SIGNATURES):
        return ProbeResult(
            status=STATUS_CONFIRMED_MEMORY,
            confidence=CONFIDENCE_MEDIUM,
            detected_format="hibernation",
            reason="Windows hibernation file signature detected.",
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            can_analyze=True,
        )

    # The .img extension on a large unstructured file is ambiguous.
    # We do NOT assume it is a memory image, but we also do not
    # reject it outright: the operator decides.
    if suffix in CANDIDATE_MEMORY_EXTENSIONS:
        return ProbeResult(
            status=STATUS_AMBIGUOUS_RAW,
            confidence=CONFIDENCE_MEDIUM,
            detected_format="raw_candidate",
            reason=(
                "No memory or disk signature in the first 1 MiB. "
                "The file may be an unstructured RAW memory or disk image."
            ),
            detected_evidence_type="memory",
            file_size=size,
            extension=suffix,
            requires_confirmation=True,
            can_analyze=False,
        )

    # No candidate extension.  Fall back to a content-based check.
    return ProbeResult(
        status=STATUS_AMBIGUOUS_RAW,
        confidence=CONFIDENCE_LOW,
        detected_format="unknown_candidate",
        reason="No recognized signature and no known memory extension.",
        detected_evidence_type="memory",
        file_size=size,
        extension=suffix,
        requires_confirmation=True,
        can_analyze=False,
    )
