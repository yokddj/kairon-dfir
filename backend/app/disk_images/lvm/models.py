"""Typed object model for parsed LVM2 metadata.

Every type here is a frozen dataclass -- the parser's entire public output
shape. No dictionaries are exposed as part of this model; anywhere a
dict-like structure would be tempting (e.g. "segments keyed by name"), a
tuple of typed objects is used instead so callers get attribute access and
static type checking, not string-keyed lookups into an untyped blob.

These types describe exactly the V1 scope: a single Volume Group, backed
by one or more Physical Volumes, containing Logical Volumes made of purely
Linear Segments. Nothing here can represent striping (stripe_count > 1),
mirrors, thin provisioning, snapshots, or RAID -- the parser rejects
metadata describing any of those (see exceptions.UnsupportedSegmentTypeError)
rather than silently misrepresenting them with this model.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MetadataArea:
    """Where a Volume Group's metadata was physically found.

    All offsets are absolute byte offsets from the start of the physical
    volume that was parsed (not relative to any partition table entry
    above it -- the caller is responsible for whatever offset the PV
    itself starts at within a larger disk image).
    """

    header_offset_bytes: int
    """Absolute byte offset of the metadata area's own header (mda_header)."""

    area_size_bytes: int
    """Total size, in bytes, of the metadata area (the circular region the
    header describes -- not just the currently-active text within it)."""

    metadata_text_offset_bytes: int
    """Absolute byte offset of the currently active metadata text."""

    metadata_text_size_bytes: int
    """Size, in bytes, of the currently active metadata text."""


@dataclass(frozen=True)
class LinearSegment:
    """One contiguous run of a Logical Volume's address space, mapped onto
    a contiguous run of a single Physical Volume's address space.

    This is the only segment shape V1 supports -- see
    exceptions.UnsupportedSegmentTypeError for what is rejected instead of
    being represented here.
    """

    start_extent: int
    """First Logical Extent (0-based, within the owning Logical Volume) this
    segment covers."""

    extent_count: int
    """Number of extents this segment covers."""

    physical_volume_name: str
    """The name (e.g. "pv0") of the Physical Volume this segment is
    allocated on, as declared in the Volume Group's own
    physical_volumes section -- see VolumeGroup.physical_volumes."""

    start_physical_extent: int
    """First Physical Extent (0-based, on the named Physical Volume) this
    segment's data begins at."""


@dataclass(frozen=True)
class LogicalVolume:
    """One Logical Volume within a Volume Group, made of one or more
    Linear Segments in V1's supported case."""

    name: str
    id: str
    """LVM UUID, as recorded in the metadata text (with dashes, as-is --
    this parser does not reformat or reinterpret it)."""

    segments: tuple[LinearSegment, ...]
    """Ordered by start_extent. Guaranteed (by the parser's own validation,
    not merely assumed) to be contiguous, non-overlapping, and starting at
    extent 0 -- see exceptions.InconsistentMetadataError."""

    @property
    def extent_count(self) -> int:
        """Total size of this Logical Volume, in extents (the sum of every
        segment's extent_count -- valid because segments are already
        guaranteed contiguous and non-overlapping)."""
        return sum(segment.extent_count for segment in self.segments)


@dataclass(frozen=True)
class PhysicalVolume:
    """One Physical Volume as declared within a Volume Group's metadata --
    corresponds to one `physical_volumes { <name> { ... } }` block in the
    on-disk text metadata.

    For V1 (a single physical volume being inspected), exactly one of
    these will always describe the same physical volume whose label and
    header bytes were parsed to reach this metadata in the first place;
    the parser cross-checks that this entry's id matches the id recorded
    in that volume's own binary header (see
    exceptions.InconsistentMetadataError) rather than assuming they agree.
    """

    name: str
    """The identifier Logical Volume segments reference (e.g. "pv0")."""

    id: str
    """LVM UUID, as recorded in the metadata text."""

    device_size_bytes: int
    extent_size_bytes: int
    """This Volume Group's fixed allocation unit, for convenience computing
    byte offsets from this PV's own pe_start/pe_count without needing the
    owning VolumeGroup in hand."""

    pe_start_bytes: int
    """Absolute byte offset (from the start of this physical volume) where
    its extents begin -- i.e. where Physical Extent 0 starts."""

    extent_count: int
    """Total number of Physical Extents this Physical Volume provides to
    the Volume Group (its usable, allocatable capacity in extents)."""


@dataclass(frozen=True)
class VolumeGroup:
    """A single Volume Group, parsed from one Physical Volume's metadata
    area. V1 supports exactly one Volume Group per parse -- LVM2's on-disk
    format allows a metadata area to describe only one VG at a time in the
    text format Kairon supports, so this is a direct, not a simplifying,
    match to what is actually on disk.
    """

    name: str
    id: str
    """LVM UUID, as recorded in the metadata text."""

    extent_size_bytes: int
    """This Volume Group's fixed allocation unit -- the on-disk metadata
    records this in 512-byte sectors; this field is already converted to
    bytes so callers never need to know the sector-to-byte convention."""

    physical_volumes: tuple[PhysicalVolume, ...]
    """Every Physical Volume this Volume Group's metadata declares. V1's
    parser does not restrict this to exactly one entry -- a Volume Group
    spanning multiple Physical Volumes is parsed faithfully even though
    V1's segment validation (UnsupportedSegmentTypeError) still rejects
    any segment that is not a single-PV linear allocation. Whether a
    multi-PV Volume Group whose every segment still happens to be linear
    is in scope for integration is an open question the architecture RFC
    leaves unresolved -- this parser takes no position on it; it only
    represents what is actually declared on disk."""

    logical_volumes: tuple[LogicalVolume, ...]

    metadata_area: MetadataArea
    """Where this Volume Group's metadata was itself found -- retained for
    diagnostics/provenance, not needed to interpret the model above it."""


@dataclass(frozen=True)
class PhysicalVolumeMetadata:
    """The complete result of parsing one Physical Volume's LVM2 metadata:
    the Physical Volume itself (as declared within its own Volume Group's
    metadata -- see PhysicalVolume's docstring for why there is exactly
    one canonical entry for the volume being read) and the single Volume
    Group it belongs to.

    This is the return type of parser.parse_physical_volume_metadata --
    the one public entry point most callers need.
    """

    physical_volume: PhysicalVolume
    volume_group: VolumeGroup
