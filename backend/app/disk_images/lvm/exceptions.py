"""Typed exception hierarchy for the LVM2 metadata parser.

Every error this package can raise is a subclass of LVMMetadataError, so a
caller that only cares about "could this be parsed at all" can catch that
one type. Each subclass exists because it maps to a distinct, real failure
mode a caller (or, later, an analyst-facing diagnostic) needs to tell apart
-- see app/services/evidence_preflight.py's _translate_volume_diagnostic for
the existing precedent of translating internal detection detail into
analyst-facing language without ever surfacing a raw exception string.

None of these carry a raw Python traceback or a raw pytsk3/library
exception -- they are constructed with a plain, specific message describing
what was actually wrong (see docstrings below for what belongs in each).
"""

from __future__ import annotations


class LVMMetadataError(Exception):
    """Base class for every error raised while parsing LVM2 metadata."""


class InvalidLabelError(LVMMetadataError):
    """The LVM2 label header was not found, or was structurally invalid.

    Raised when: the "LABELONE" signature is absent from every sector
    scanned, the label's type indicator is not "LVM2 001", the label's
    recorded checksum does not match the checksum computed over the
    labelled region, or the label's own byte layout is too short/truncated
    to contain the fields this parser requires.
    """


class UnsupportedMetadataVersionError(LVMMetadataError):
    """The metadata area declares a format/version this parser does not
    implement.

    Raised when: the metadata area header's magic signature does not match
    the expected LVM2 text-format signature, or its version field is not
    the single version (1) this parser supports.
    """


class UnsupportedMetadataLayoutError(LVMMetadataError):
    """The metadata area is laid out in a way V1 does not implement.

    Raised when: the active metadata location wraps around the end of the
    metadata area back to its start (LVM2's metadata area is used as a
    circular log; V1 deliberately supports only the common, non-wrapped
    case -- see the architecture RFC's open question on this). This is
    distinct from UnsupportedMetadataVersionError: the format/version is
    recognized, only this specific physical layout is not yet handled.
    """


class MalformedMetadataTextError(LVMMetadataError):
    """The metadata text itself could not be parsed, or failed integrity
    verification.

    Raised when: the recorded checksum for the metadata text region does
    not match the checksum computed over the actual bytes read, or the
    text does not conform to LVM2's config-file grammar (unbalanced
    braces/brackets, an unterminated string, a value where a section was
    expected, etc.).
    """


class MissingRequiredFieldError(LVMMetadataError):
    """Otherwise well-formed metadata text is missing a field this parser
    requires to build a complete object model.

    Raised when: a Volume Group is missing its extent_size, a physical
    volume entry is missing its id/dev_size/pe_start/pe_count, a logical
    volume declares a segment_count that does not match the number of
    segmentN blocks actually present, or a segment is missing start_extent
    /extent_count/type/stripe_count/stripes.
    """


class UnsupportedSegmentTypeError(LVMMetadataError):
    """A logical volume segment uses a type or configuration outside V1's
    scope.

    Raised when: a segment's type is anything other than "striped", or a
    "striped" segment has stripe_count != 1 (real striping across
    multiple physical volumes) or does not have exactly one (pv_name,
    start_pe) pair in its stripes list. V1 only supports the plain linear
    case -- a single-PV "striped" segment with stripe_count == 1 is how
    LVM2 itself represents a linear allocation on disk; see the
    architecture RFC (Section 3) for why this is the only segment shape
    V1 implements.
    """


class InconsistentMetadataError(LVMMetadataError):
    """The metadata parses as well-formed but is internally inconsistent.

    Raised when: a segment references a physical volume name not declared
    in the Volume Group's own physical_volumes section, a logical
    volume's segments do not form a contiguous, non-overlapping,
    zero-based extent range covering its whole declared size, or the
    physical volume's UUID recorded in its own header does not match the
    UUID the Volume Group's metadata declares for it.
    """


# ---------------------------------------------------------------------------
# Reader-layer errors (see reader.py) -- a distinct hierarchy from
# LVMMetadataError above. These are raised while *reading* an already
# (successfully) parsed Logical Volume's bytes, not while parsing its
# metadata; a LogicalVolumeReader is deliberately not required to have
# been built from a validated parser.py output (see reader.py's module
# docstring), so it re-checks the invariants it depends on rather than
# assuming PR1's own validation always ran.
# ---------------------------------------------------------------------------


class LogicalVolumeReadError(Exception):
    """Base class for every error LogicalVolumeReader (and the pytsk3
    Img_Info adapter built on it) can raise."""


class InvalidReadRequestError(LogicalVolumeReadError):
    """The requested read is not a request this reader can ever satisfy,
    regardless of the extent map's contents.

    Raised when: offset is negative, size is negative, or the requested
    range [offset, offset + size) extends beyond the logical volume's
    declared size (the sum of every segment's extent_count).
    """


class ExtentMapGapError(LogicalVolumeReadError):
    """The Logical Volume's segments do not form a contiguous, zero-based,
    non-overlapping range covering the whole declared size.

    Raised at LogicalVolumeReader construction time (not lazily, only when
    a read happens to touch the gap) -- a reader built over a
    discontiguous extent map is not usable at all, not merely partially
    usable. app.disk_images.lvm.parser already enforces this same
    invariant when building a LogicalVolume from real metadata text; this
    is a defensive, independent re-check for this layer, which does not
    assume its input necessarily came from that validated path.
    """


class UnresolvedPhysicalVolumeError(LogicalVolumeReadError):
    """A segment references a physical volume name that was not provided
    to this reader.

    Raised at construction time, for the same "fail fast, not partway
    through a read" reason as ExtentMapGapError.
    """


class UnderlyingReadError(LogicalVolumeReadError):
    """The underlying physical byte-range reader returned fewer bytes than
    requested, without raising its own exception.

    This is distinct from the underlying reader raising an exception
    itself -- that case is never caught here and propagates completely
    unchanged (see reader.py's read() docstring). This error exists only
    for the case where the underlying reader returns *some* bytes, just
    not as many as it was asked for, silently -- treated as a hard error
    rather than a short/partial result, since fabricating or truncating
    evidence bytes is never acceptable.
    """
