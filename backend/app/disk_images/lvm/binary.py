"""Parsing for the fixed, binary on-disk structures LVM2 writes at the
start of a Physical Volume: the label header, the (variable-length) PV
header it points to, and the metadata area header(s) the PV header points
to in turn.

Every function here takes plain bytes and returns a small, private,
non-public result object (not part of app.disk_images.lvm.models' public
API -- these are intermediate representations consumed by parser.py while
it builds the public dataclasses). Nothing in this module touches a file,
a disk image, or pytsk3 -- callers are responsible for supplying the exact
bytes each function needs.

Byte layouts and the "weak" CRC-32 checksum algorithm below are taken from
LVM2's own on-disk format (independently cross-checked against a
third-party reverse-engineering reference during implementation, not
merely recalled from memory) -- see the architecture RFC
(docs/architecture/lvm-support.md, moved out of the repository per the
user's own request but still the design this implements) for the
higher-level rationale.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from app.disk_images.lvm.exceptions import (
    InvalidLabelError,
    MalformedMetadataTextError,
    UnsupportedMetadataLayoutError,
    UnsupportedMetadataVersionError,
)

SECTOR_SIZE = 512

_LABEL_SIGNATURE = b"LABELONE"
_LABEL_TYPE = b"LVM2 001"
_LABEL_STRUCT = struct.Struct("<8sQII8s")  # id, sector_xl, crc_xl, offset_xl, type
LABEL_SCAN_SECTORS = 4  # LVM2 itself only ever checks the first 4 sectors

_DISK_LOCN_STRUCT = struct.Struct("<QQ")  # offset, size
_DISK_LOCN_SIZE = _DISK_LOCN_STRUCT.size

MDA_HEADER_SIZE = 512
_MDA_MAGIC = b" LVM2 x[5A%r0N*>"
_MDA_HEADER_FIXED_STRUCT = struct.Struct("<I16sIQQ")  # checksum_xl, magic, version, start, size
_MDA_SUPPORTED_VERSION = 1
_RAW_LOCN_STRUCT = struct.Struct("<QQII")  # offset, size, checksum, flags
_RAW_LOCN_SIZE = _RAW_LOCN_STRUCT.size
_RAW_LOCN_IGNORED = 0x00000001

# LVM2's "weak" CRC-32: the standard reflected CRC-32 (polynomial
# 0xEDB88320, the same table zlib.crc32 uses internally) but seeded with
# 0xf597a6cf instead of the usual 0xFFFFFFFF, and *without* the final
# complement (XOR 0xFFFFFFFF) the public/standard CRC-32 applies.
#
# zlib.crc32(data, value) is defined so that it can resume a previous
# CRC-32 computation: internally it un-complements `value`, runs the
# table algorithm, then re-complements the result -- i.e.
#   zlib.crc32(data, value) == raw_algorithm(data, value ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
# To get raw_algorithm(data, 0xf597a6cf) (LVM2's variant, no XOR at
# either end) from zlib's own primitive, solve for the `value` that makes
# the un-complement land on 0xf597a6cf: value = 0xf597a6cf ^ 0xFFFFFFFF.
# This was verified during implementation against an independent,
# from-scratch bit-level CRC-32 implementation before being used here.
_LVM_CRC_SEED = 0xF597A6CF ^ 0xFFFFFFFF


def lvm_weak_crc32(data: bytes) -> int:
    """LVM2's own checksum algorithm -- see the derivation above."""
    return zlib.crc32(data, _LVM_CRC_SEED) ^ 0xFFFFFFFF


def format_lvm_uuid(raw: bytes) -> str:
    """Format a 32-character raw (no-dashes) on-disk UUID the same way
    LVM2's own tools display it: dash-grouped in 6-4-4-4-4-4-6 characters.
    Used only to compare a Physical Volume's binary-header UUID against
    the same UUID as recorded (already dashed) in its Volume Group's
    metadata text -- see exceptions.InconsistentMetadataError."""
    text = raw.decode("ascii", errors="strict")
    if len(text) != 32:
        raise InvalidLabelError(f"Physical volume UUID must be exactly 32 characters, got {len(text)}.")
    groups = (text[0:6], text[6:10], text[10:14], text[14:18], text[18:22], text[22:26], text[26:32])
    return "-".join(groups)


@dataclass(frozen=True)
class _DiskLocation:
    offset_bytes: int
    size_bytes: int


@dataclass(frozen=True)
class _LabelHeader:
    label_sector: int
    pv_header_offset: int
    """Byte offset of the PV header, relative to the start of the sector
    the label itself was found in (i.e. absolute offset = label sector's
    own byte offset + this value)."""


@dataclass(frozen=True)
class _PhysicalVolumeHeader:
    pv_uuid: str
    """Already formatted with dashes -- see format_lvm_uuid."""

    device_size_bytes: int
    data_areas: tuple[_DiskLocation, ...]
    metadata_areas: tuple[_DiskLocation, ...]


@dataclass(frozen=True)
class _RawLocation:
    offset_bytes: int
    """Relative to the metadata area's own start (== the mda_header's own
    `start` field)."""

    size_bytes: int
    checksum: int
    ignored: bool


@dataclass(frozen=True)
class _MetadataAreaHeader:
    area_start_bytes: int
    """Absolute byte offset of the metadata area (as the mda_header itself
    records it -- cross-checked by the caller against the PV header's own
    descriptor for the same area)."""

    area_size_bytes: int
    locations: tuple[_RawLocation, ...]


def parse_label_header(sector_bytes: bytes, *, sector_number: int) -> _LabelHeader:
    """Parse one candidate label-header sector. Raises InvalidLabelError if
    this sector is not a valid LVM2 label (callers scan multiple candidate
    sectors -- see parse_label -- so a single non-matching sector here is
    an expected, ordinary occurrence, not necessarily corruption)."""
    if len(sector_bytes) < _LABEL_STRUCT.size:
        raise InvalidLabelError(f"Sector {sector_number} is too short to contain a label header.")
    signature, recorded_sector, _crc, pv_header_offset, label_type = _LABEL_STRUCT.unpack(sector_bytes[: _LABEL_STRUCT.size])
    if signature != _LABEL_SIGNATURE:
        raise InvalidLabelError(f"Sector {sector_number} does not start with the LVM2 label signature.")
    if label_type != _LABEL_TYPE:
        raise InvalidLabelError(f"Sector {sector_number} has an unrecognized label type: {label_type!r}.")
    if recorded_sector != sector_number:
        raise InvalidLabelError(f"Label at sector {sector_number} records its own sector number as {recorded_sector}, a mismatch that indicates a corrupted or relocated label.")
    return _LabelHeader(label_sector=sector_number, pv_header_offset=pv_header_offset)


def parse_label(first_sectors: bytes) -> _LabelHeader:
    """Scan the first LABEL_SCAN_SECTORS sectors (the same set LVM2 itself
    checks) for a valid label header. `first_sectors` must contain at
    least LABEL_SCAN_SECTORS * SECTOR_SIZE bytes, starting at the
    beginning of the physical volume."""
    last_error: InvalidLabelError | None = None
    for sector_number in range(LABEL_SCAN_SECTORS):
        start = sector_number * SECTOR_SIZE
        candidate = first_sectors[start : start + SECTOR_SIZE]
        if len(candidate) < SECTOR_SIZE:
            break
        try:
            return parse_label_header(candidate, sector_number=sector_number)
        except InvalidLabelError as exc:
            last_error = exc
            continue
    raise last_error or InvalidLabelError("No LVM2 label header found in the first sectors of this physical volume.")


def _parse_disk_locations(data: bytes) -> tuple[tuple[_DiskLocation, ...], int]:
    """Parse a NULL-terminated (offset == 0) list of 16-byte disk_locn
    entries starting at the beginning of `data`. Returns (entries,
    bytes_consumed_including_terminator). Raises InvalidLabelError if the
    terminator is never found within `data` -- silently returning a
    partial list would be indistinguishable from genuinely corrupt input
    that happens to run out of zero bytes to terminate on."""
    locations: list[_DiskLocation] = []
    offset = 0
    while offset + _DISK_LOCN_SIZE <= len(data):
        entry_offset, entry_size = _DISK_LOCN_STRUCT.unpack(data[offset : offset + _DISK_LOCN_SIZE])
        offset += _DISK_LOCN_SIZE
        if entry_offset == 0:
            return tuple(locations), offset
        locations.append(_DiskLocation(offset_bytes=entry_offset, size_bytes=entry_size))
    raise InvalidLabelError("Physical volume header's descriptor list never reaches its NULL terminator within the bytes available -- the header is truncated or corrupt.")


def parse_pv_header(header_bytes: bytes) -> _PhysicalVolumeHeader:
    """Parse the PV header: a fixed 40-byte prefix (UUID + device size)
    followed by two NULL-terminated lists of disk_locn entries (data
    areas, then metadata areas). `header_bytes` must contain the full
    header plus both lists and their terminators; a generously-sized
    buffer read from the caller (this parser does not know in advance how
    long the header is) is expected."""
    prefix_size = 32 + 8
    if len(header_bytes) < prefix_size + _DISK_LOCN_SIZE:
        raise InvalidLabelError("Physical volume header is too short to contain a UUID, device size, and at least one descriptor list terminator.")
    raw_uuid = header_bytes[:32]
    (device_size,) = struct.unpack("<Q", header_bytes[32:prefix_size])
    pv_uuid = format_lvm_uuid(raw_uuid)

    remainder = header_bytes[prefix_size:]
    data_areas, data_areas_consumed = _parse_disk_locations(remainder)
    metadata_areas, _metadata_areas_consumed = _parse_disk_locations(remainder[data_areas_consumed:])

    if not metadata_areas:
        raise MalformedMetadataTextError("Physical volume header declares no metadata areas -- there is no Volume Group metadata to read for this physical volume.")

    return _PhysicalVolumeHeader(pv_uuid=pv_uuid, device_size_bytes=device_size, data_areas=data_areas, metadata_areas=metadata_areas)


def parse_mda_header(mda_bytes: bytes) -> _MetadataAreaHeader:
    """Parse a metadata area header (a fixed 512-byte structure at the
    start of a metadata area). `mda_bytes` must contain at least the full
    512 bytes."""
    if len(mda_bytes) < MDA_HEADER_SIZE:
        raise MalformedMetadataTextError(f"Metadata area header is truncated: expected {MDA_HEADER_SIZE} bytes, got {len(mda_bytes)}.")

    checksum, magic, version, area_start, area_size = _MDA_HEADER_FIXED_STRUCT.unpack(mda_bytes[: _MDA_HEADER_FIXED_STRUCT.size])
    if magic != _MDA_MAGIC:
        raise UnsupportedMetadataVersionError("Metadata area header signature does not match the LVM2 text-format magic -- this is not metadata this parser recognizes at all.")
    if version != _MDA_SUPPORTED_VERSION:
        raise UnsupportedMetadataVersionError(f"Metadata area header declares format version {version}; only version {_MDA_SUPPORTED_VERSION} is supported.")

    expected_checksum = lvm_weak_crc32(mda_bytes[4:MDA_HEADER_SIZE])
    if checksum != expected_checksum:
        raise MalformedMetadataTextError("Metadata area header checksum does not match its recorded value -- the header is corrupted.")

    locations: list[_RawLocation] = []
    offset = _MDA_HEADER_FIXED_STRUCT.size
    while offset + _RAW_LOCN_SIZE <= min(len(mda_bytes), MDA_HEADER_SIZE):
        entry_offset, entry_size, entry_checksum, entry_flags = _RAW_LOCN_STRUCT.unpack(mda_bytes[offset : offset + _RAW_LOCN_SIZE])
        offset += _RAW_LOCN_SIZE
        if entry_offset == 0:
            break
        locations.append(_RawLocation(offset_bytes=entry_offset, size_bytes=entry_size, checksum=entry_checksum, ignored=bool(entry_flags & _RAW_LOCN_IGNORED)))

    if not locations:
        raise MalformedMetadataTextError("Metadata area header has no active metadata location recorded.")

    return _MetadataAreaHeader(area_start_bytes=area_start, area_size_bytes=area_size, locations=tuple(locations))


def select_active_location(mda_header: _MetadataAreaHeader) -> _RawLocation:
    """Pick the first metadata location that is not flagged as superseded
    ("ignored") -- LVM2 can carry more than one location during a
    transition, but exactly one is authoritative at rest."""
    for location in mda_header.locations:
        if not location.ignored:
            if location.offset_bytes + location.size_bytes > mda_header.area_size_bytes:
                raise UnsupportedMetadataLayoutError(
                    "The active metadata text wraps around the end of the metadata area back to its start. "
                    "This parser (V1) supports only the common, non-wrapped layout."
                )
            return location
    raise MalformedMetadataTextError("Every recorded metadata location is flagged as superseded ('ignored') -- there is no active metadata to read.")


def verify_metadata_text_checksum(text_bytes: bytes, *, expected_checksum: int) -> None:
    actual = lvm_weak_crc32(text_bytes)
    if actual != expected_checksum:
        raise MalformedMetadataTextError("Metadata text checksum does not match its recorded value -- the metadata is corrupted.")
