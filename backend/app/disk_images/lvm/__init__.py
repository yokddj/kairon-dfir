"""Pure-Python, read-only LVM2 metadata parser.

Public API:

    parse_physical_volume_metadata(read) -> PhysicalVolumeMetadata
    build_volume_group(document, metadata_area=...) -> VolumeGroup
    ByteRangeReader                                   (Protocol)

    PhysicalVolumeMetadata, VolumeGroup, PhysicalVolume, LogicalVolume,
    LinearSegment, MetadataArea                        (typed dataclasses)

    LVMMetadataError and its subclasses                (exceptions)

This package is deliberately independent of pytsk3 and is not referenced
anywhere in Kairon's disk-image pipeline yet. It implements only the PR1
scope of the LVM support architecture RFC: parsing (label, physical
volume header, metadata area, and metadata text) into a validated typed
model of a single Volume Group's linear logical volumes. It does not
translate logical-volume offsets into physical byte offsets, and it does
not implement anything resembling pytsk3.Img_Info -- see the RFC's
Section 5 (Reader Architecture) for where those belong in a later PR.
"""

from __future__ import annotations

from app.disk_images.lvm.exceptions import (
    InconsistentMetadataError,
    InvalidLabelError,
    LVMMetadataError,
    MalformedMetadataTextError,
    MissingRequiredFieldError,
    UnsupportedMetadataLayoutError,
    UnsupportedMetadataVersionError,
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
from app.disk_images.lvm.parser import ByteRangeReader, build_volume_group, parse_physical_volume_metadata

__all__ = [
    "ByteRangeReader",
    "build_volume_group",
    "parse_physical_volume_metadata",
    "PhysicalVolumeMetadata",
    "VolumeGroup",
    "PhysicalVolume",
    "LogicalVolume",
    "LinearSegment",
    "MetadataArea",
    "LVMMetadataError",
    "InvalidLabelError",
    "UnsupportedMetadataVersionError",
    "UnsupportedMetadataLayoutError",
    "MalformedMetadataTextError",
    "MissingRequiredFieldError",
    "UnsupportedSegmentTypeError",
    "InconsistentMetadataError",
]
