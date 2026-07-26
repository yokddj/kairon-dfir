"""Public entry point for parsing an LVM2 Physical Volume's metadata.

This module is the only one in app.disk_images.lvm meant to be imported by
callers outside this package (re-exported via __init__.py). It never
imports pytsk3 and is not referenced anywhere in Kairon's production
disk-image pipeline yet -- this package exists, is fully tested, and is
otherwise unused, exactly as specified for this PR.

parse_physical_volume_metadata() is the main entry point: given a small
"read a byte range" callable (so this parser never needs to hold an
entire, possibly multi-gigabyte, physical volume in memory, and never
needs to know anything about pytsk3.Img_Info, offset translation into a
larger disk image, or how the caller actually obtained those bytes), it
returns a fully validated, strongly-typed PhysicalVolumeMetadata.

The lower-level functions in this module (and in binary.py/text_format.py)
are also usable directly by tests and future callers that already have
specific byte ranges in hand and do not need the read-callable
orchestration.
"""

from __future__ import annotations

from typing import Protocol

from app.disk_images.lvm import binary, text_format
from app.disk_images.lvm.exceptions import (
    InconsistentMetadataError,
    MalformedMetadataTextError,
    MissingRequiredFieldError,
    UnsupportedSegmentTypeError,
)
from app.disk_images.lvm.models import (
    LinearSegment,
    LogicalVolume,
    MetadataArea,
    PhysicalVolume,
    PhysicalVolumeMetadata,
    VolumeGroup,
)

SECTOR_SIZE = binary.SECTOR_SIZE

# Generous but bounded: the common case (one or two data areas, one
# metadata area) fits comfortably within this; parse_pv_header raises a
# clear error (rather than silently truncating) if it does not find both
# descriptor-list terminators within the bytes it is given.
_PV_HEADER_READ_SIZE = 1024


class ByteRangeReader(Protocol):
    """The only thing this parser needs from its caller: read exactly
    `size` bytes starting at `offset` (absolute, from the start of the
    physical volume being parsed). Anything satisfying this -- a plain
    bytes buffer wrapped in a lambda, a file object, or (in a future PR)
    an adapter over pytsk3's own reader -- can be passed to
    parse_physical_volume_metadata without this package ever importing or
    knowing about pytsk3."""

    def __call__(self, offset: int, size: int) -> bytes: ...


def _require(section: dict, key: str, expected_type: type, *, context: str):
    if key not in section:
        raise MissingRequiredFieldError(f"{context} is missing required field {key!r}.")
    value = section[key]
    if not isinstance(value, expected_type):
        raise MissingRequiredFieldError(f"{context} field {key!r} has the wrong type: expected {expected_type.__name__}, got {type(value).__name__}.")
    return value


def _find_volume_group_section(document: dict) -> tuple[str, dict]:
    candidates = [(name, value) for name, value in document.items() if isinstance(value, dict)]
    if not candidates:
        raise MissingRequiredFieldError("Metadata text has no Volume Group section (no top-level entry is a nested section).")
    if len(candidates) > 1:
        names = [name for name, _ in candidates]
        raise MalformedMetadataTextError(f"Metadata text declares more than one top-level section ({names!r}); exactly one Volume Group per metadata text is supported.")
    return candidates[0]


def _build_physical_volumes(vg_body: dict, *, vg_name: str, extent_size_bytes: int) -> tuple[PhysicalVolume, ...]:
    pv_section = _require(vg_body, "physical_volumes", dict, context=f"volume group {vg_name!r}")
    physical_volumes: list[PhysicalVolume] = []
    for pv_name, pv_body in pv_section.items():
        if not isinstance(pv_body, dict):
            raise MalformedMetadataTextError(f"volume group {vg_name!r} physical_volumes entry {pv_name!r} is not a section.")
        context = f"physical volume {pv_name!r} (in volume group {vg_name!r})"
        pv_id = _require(pv_body, "id", str, context=context)
        dev_size = _require(pv_body, "dev_size", int, context=context)
        pe_start = _require(pv_body, "pe_start", int, context=context)
        pe_count = _require(pv_body, "pe_count", int, context=context)
        if dev_size <= 0 or pe_count <= 0 or pe_start < 0:
            raise InconsistentMetadataError(f"{context} has a non-positive dev_size/pe_count or a negative pe_start.")
        physical_volumes.append(
            PhysicalVolume(
                name=pv_name,
                id=pv_id,
                device_size_bytes=dev_size * SECTOR_SIZE,
                extent_size_bytes=extent_size_bytes,
                pe_start_bytes=pe_start * SECTOR_SIZE,
                extent_count=pe_count,
            )
        )
    if not physical_volumes:
        raise MissingRequiredFieldError(f"Volume group {vg_name!r} declares an empty physical_volumes section.")
    return tuple(physical_volumes)


def _build_linear_segment(segment_key: str, segment_body: dict, *, lv_name: str, known_pv_names: frozenset[str]) -> LinearSegment:
    context = f"logical volume {lv_name!r} {segment_key}"
    start_extent = _require(segment_body, "start_extent", int, context=context)
    extent_count = _require(segment_body, "extent_count", int, context=context)
    segment_type = _require(segment_body, "type", str, context=context)
    stripe_count = _require(segment_body, "stripe_count", int, context=context)
    stripes = segment_body.get("stripes")

    if segment_type != "striped":
        raise UnsupportedSegmentTypeError(f"{context} uses segment type {segment_type!r}; only a 'striped' segment with stripe_count == 1 (LVM2's on-disk representation of a linear segment) is supported.")
    if stripe_count != 1:
        raise UnsupportedSegmentTypeError(f"{context} has stripe_count={stripe_count}; only stripe_count == 1 (linear) is supported -- real striping across multiple physical volumes is out of scope for V1.")
    if stripes is None:
        raise MissingRequiredFieldError(f"{context} is missing required field 'stripes'.")
    if not isinstance(stripes, list) or len(stripes) != 2 or not isinstance(stripes[0], str) or not isinstance(stripes[1], int):
        raise InconsistentMetadataError(f"{context} declares stripe_count=1 but its 'stripes' value is not exactly one (physical_volume_name, start_extent) pair: {stripes!r}.")

    pv_name, start_pe = stripes
    if pv_name not in known_pv_names:
        raise InconsistentMetadataError(f"{context} references physical volume {pv_name!r}, which this volume group does not declare in its physical_volumes section.")
    if extent_count <= 0:
        raise InconsistentMetadataError(f"{context} has a non-positive extent_count ({extent_count}).")
    if start_extent < 0 or start_pe < 0:
        raise InconsistentMetadataError(f"{context} has a negative start_extent or physical extent offset.")

    return LinearSegment(start_extent=start_extent, extent_count=extent_count, physical_volume_name=pv_name, start_physical_extent=start_pe)


def _build_logical_volume(lv_name: str, lv_body: dict, *, known_pv_names: frozenset[str]) -> LogicalVolume:
    context = f"logical volume {lv_name!r}"
    lv_id = _require(lv_body, "id", str, context=context)
    segment_count = _require(lv_body, "segment_count", int, context=context)
    if segment_count <= 0:
        raise MissingRequiredFieldError(f"{context} declares segment_count={segment_count}; at least one segment is required.")

    segments: list[LinearSegment] = []
    for index in range(1, segment_count + 1):
        segment_key = f"segment{index}"
        segment_body = lv_body.get(segment_key)
        if not isinstance(segment_body, dict):
            raise MissingRequiredFieldError(f"{context} declares segment_count={segment_count} but is missing section {segment_key!r}.")
        segments.append(_build_linear_segment(segment_key, segment_body, lv_name=lv_name, known_pv_names=known_pv_names))

    segments.sort(key=lambda segment: segment.start_extent)
    expected_start = 0
    for segment in segments:
        if segment.start_extent != expected_start:
            raise InconsistentMetadataError(f"{context} has a gap or overlap between segments: expected the next segment to start at extent {expected_start}, but found one starting at {segment.start_extent}.")
        expected_start += segment.extent_count

    return LogicalVolume(name=lv_name, id=lv_id, segments=tuple(segments))


def _build_logical_volumes(vg_body: dict, *, vg_name: str, known_pv_names: frozenset[str]) -> tuple[LogicalVolume, ...]:
    lv_section = _require(vg_body, "logical_volumes", dict, context=f"volume group {vg_name!r}")
    logical_volumes: list[LogicalVolume] = []
    for lv_name, lv_body in lv_section.items():
        if not isinstance(lv_body, dict):
            raise MalformedMetadataTextError(f"volume group {vg_name!r} logical_volumes entry {lv_name!r} is not a section.")
        logical_volumes.append(_build_logical_volume(lv_name, lv_body, known_pv_names=known_pv_names))
    if not logical_volumes:
        raise MissingRequiredFieldError(f"Volume group {vg_name!r} declares an empty logical_volumes section.")
    return tuple(logical_volumes)


def build_volume_group(document: dict, *, metadata_area: MetadataArea) -> VolumeGroup:
    """Build a validated VolumeGroup from the private dict-tree produced
    by text_format.parse_config_text. Exposed (not prefixed) because it is
    useful on its own to tests and to any future caller that already has a
    parsed document, without needing the full read-callable
    orchestration."""
    vg_name, vg_body = _find_volume_group_section(document)
    vg_id = _require(vg_body, "id", str, context=f"volume group {vg_name!r}")
    extent_size_sectors = _require(vg_body, "extent_size", int, context=f"volume group {vg_name!r}")
    if extent_size_sectors <= 0:
        raise InconsistentMetadataError(f"Volume group {vg_name!r} has a non-positive extent_size ({extent_size_sectors}).")
    extent_size_bytes = extent_size_sectors * SECTOR_SIZE

    physical_volumes = _build_physical_volumes(vg_body, vg_name=vg_name, extent_size_bytes=extent_size_bytes)
    known_pv_names = frozenset(pv.name for pv in physical_volumes)
    logical_volumes = _build_logical_volumes(vg_body, vg_name=vg_name, known_pv_names=known_pv_names)

    return VolumeGroup(
        name=vg_name,
        id=vg_id,
        extent_size_bytes=extent_size_bytes,
        physical_volumes=physical_volumes,
        logical_volumes=logical_volumes,
        metadata_area=metadata_area,
    )


def parse_physical_volume_metadata(read: ByteRangeReader) -> PhysicalVolumeMetadata:
    """Parse one Physical Volume's LVM2 metadata, calling `read(offset,
    size)` only as many times as needed (label scan, PV header, metadata
    area header, then the metadata text itself -- never the whole
    physical volume). Raises a subclass of LVMMetadataError (see
    exceptions.py) on any structural problem; never returns a partial or
    best-effort result."""
    first_sectors = read(0, SECTOR_SIZE * binary.LABEL_SCAN_SECTORS)
    label = binary.parse_label(first_sectors)
    label_absolute_offset = label.label_sector * SECTOR_SIZE
    pv_header_absolute_offset = label_absolute_offset + label.pv_header_offset

    pv_header_bytes = read(pv_header_absolute_offset, _PV_HEADER_READ_SIZE)
    pv_header = binary.parse_pv_header(pv_header_bytes)

    # V1 reads only the first declared metadata area -- LVM2 can carry a
    # second, redundant copy, but a single, current, non-wrapped copy is
    # sufficient to reconstruct the Volume Group.
    metadata_area_descriptor = pv_header.metadata_areas[0]
    mda_header_bytes = read(metadata_area_descriptor.offset_bytes, binary.MDA_HEADER_SIZE)
    mda_header = binary.parse_mda_header(mda_header_bytes)

    if mda_header.area_start_bytes != metadata_area_descriptor.offset_bytes:
        raise InconsistentMetadataError(
            f"Metadata area header records its own offset as {mda_header.area_start_bytes}, "
            f"but the physical volume header points to it at offset {metadata_area_descriptor.offset_bytes}."
        )
    if mda_header.area_size_bytes != metadata_area_descriptor.size_bytes:
        raise InconsistentMetadataError(
            f"Metadata area header records its own size as {mda_header.area_size_bytes} bytes, "
            f"but the physical volume header declares it as {metadata_area_descriptor.size_bytes} bytes."
        )

    active_location = binary.select_active_location(mda_header)
    metadata_text_absolute_offset = mda_header.area_start_bytes + active_location.offset_bytes
    metadata_text_bytes = read(metadata_text_absolute_offset, active_location.size_bytes)
    binary.verify_metadata_text_checksum(metadata_text_bytes, expected_checksum=active_location.checksum)

    metadata_text = metadata_text_bytes.decode("utf-8", errors="strict").rstrip("\x00")
    document = text_format.parse_config_text(metadata_text)

    metadata_area = MetadataArea(
        header_offset_bytes=metadata_area_descriptor.offset_bytes,
        area_size_bytes=mda_header.area_size_bytes,
        metadata_text_offset_bytes=metadata_text_absolute_offset,
        metadata_text_size_bytes=active_location.size_bytes,
    )
    volume_group = build_volume_group(document, metadata_area=metadata_area)

    matching_pv = next((pv for pv in volume_group.physical_volumes if pv.id == pv_header.pv_uuid), None)
    if matching_pv is None:
        raise InconsistentMetadataError(
            f"This physical volume's own header UUID ({pv_header.pv_uuid}) does not match any physical "
            f"volume declared in its own Volume Group's metadata."
        )

    return PhysicalVolumeMetadata(physical_volume=matching_pv, volume_group=volume_group)
