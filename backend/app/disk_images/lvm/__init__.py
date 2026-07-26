"""Pure-Python, read-only LVM2 support: metadata parsing (PR1) and the
logical-volume read engine built on top of it (PR2).

Public API:

    parse_physical_volume_metadata(read) -> PhysicalVolumeMetadata   (parser.py)
    build_volume_group(document, metadata_area=...) -> VolumeGroup    (parser.py)
    ByteRangeReader                                   (Protocol, parser.py)

    LogicalVolumeReader(logical_volume, volume_group, read_physical)  (reader.py)

    PhysicalVolumeMetadata, VolumeGroup, PhysicalVolume, LogicalVolume,
    LinearSegment, MetadataArea                        (typed dataclasses)

    LVMMetadataError and its subclasses                 (metadata-parsing errors)
    LogicalVolumeReadError and its subclasses           (read-layer errors)

LogicalVolumeImgInfo (Layer 2, img_info.py) is deliberately NOT re-exported
here. Python always runs a package's __init__.py before any of its
submodules, so if this file imported img_info.py at module level, even
`import app.disk_images.lvm.reader` alone would transitively import
pytsk3 -- silently defeating the "independently testable without
importing pytsk3" property reader.py's own docstring promises. Import it
explicitly instead: `from app.disk_images.lvm.img_info import
LogicalVolumeImgInfo`.

This package is not referenced anywhere in Kairon's disk-image pipeline
yet. reader.py (Layer 1: offset translation) never imports pytsk3 and is
independently testable with nothing more than a plain callable over an
in-memory bytes buffer; img_info.py (Layer 2) is the only module here
that imports pytsk3, and contains no offset-translation logic of its own
-- see reader.py's and img_info.py's module docstrings. Nothing in this
package is wired into _discover_raw_volumes(), installation detection,
materialization, or preflight yet -- that is PR3.
"""

from __future__ import annotations

from app.disk_images.lvm.exceptions import (
    ExtentMapGapError,
    InconsistentMetadataError,
    InvalidLabelError,
    InvalidReadRequestError,
    LogicalVolumeReadError,
    LVMMetadataError,
    MalformedMetadataTextError,
    MissingRequiredFieldError,
    UnderlyingReadError,
    UnresolvedPhysicalVolumeError,
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
from app.disk_images.lvm.reader import LogicalVolumeReader

__all__ = [
    "ByteRangeReader",
    "build_volume_group",
    "parse_physical_volume_metadata",
    "LogicalVolumeReader",
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
    "LogicalVolumeReadError",
    "InvalidReadRequestError",
    "ExtentMapGapError",
    "UnresolvedPhysicalVolumeError",
    "UnderlyingReadError",
]
