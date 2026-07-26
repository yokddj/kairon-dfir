"""Layer 1: LogicalVolumeReader -- a pure-Python, read-only byte-stream
view of a single Logical Volume, built from PR1's parsed models
(LogicalVolume, VolumeGroup) and a caller-supplied physical byte reader.

This module never imports pytsk3. It is independently testable with
nothing more than an in-memory bytes buffer wrapped in a plain callable
-- see app.disk_images.lvm.img_info (Layer 2) for the thin pytsk3
Img_Info adapter built on top of this, which contains no offset-
translation logic of its own.

Invariants this reader maintains
---------------------------------
- Never writes. The only I/O this class performs is calling the
  caller-supplied `read_physical` callable; nothing here ever opens a
  file for writing or mutates the bytes it reads.
- Never caches mutable state across calls. The only state built at
  construction time is a fixed, derived index (segment boundaries) used
  for lookup -- read() never mutates `self` and repeated/overlapping
  reads always recompute their result from that same fixed index plus
  whatever the underlying reader returns *this* time.
- Never fabricates or zero-fills bytes. A read is only ever satisfied by
  concatenating exactly the bytes the underlying reader actually
  returned for each physical sub-range; if the underlying reader can't
  produce them, this class raises rather than padding the gap.
- Never silently truncates. A request that cannot be fully satisfied
  (out of range, a gap in the extent map, an underlying short read) is
  always an exception, never a shorter-than-requested return value.

Does NOT re-implement app.disk_images.lvm.parser's own metadata
validation -- but does not assume it always ran either. A
LogicalVolume's segment list is expected to already be contiguous,
zero-based, and non-overlapping (parser.py enforces this when building
one from real metadata text), and this class defensively re-checks that
invariant at construction time (see ExtentMapGapError) rather than
silently trusting it, since nothing stops a caller from constructing a
LogicalVolume by hand (as this module's own tests deliberately do, to
exercise the gap-detection path).
"""

from __future__ import annotations

import bisect
from typing import Protocol, Sequence

from app.disk_images.lvm.exceptions import (
    ExtentMapGapError,
    InvalidReadRequestError,
    UnderlyingReadError,
    UnresolvedPhysicalVolumeError,
)
from app.disk_images.lvm.models import LogicalVolume, PhysicalVolume, VolumeGroup


class ByteRangeReader(Protocol):
    """Identical in shape to app.disk_images.lvm.parser.ByteRangeReader --
    redeclared here (rather than imported) so this module has no
    dependency on parser.py at all, keeping the metadata-parsing layer
    and the read layer independent of each other; both happen to need
    the same tiny shape because both ultimately read bytes from a
    physical volume, not because one depends on the other."""

    def __call__(self, offset: int, size: int) -> bytes: ...


class LogicalVolumeReader:
    """Exposes one Logical Volume as a contiguous, read-only byte stream.

    Construction is where all of this class's validation happens (see
    the module docstring's "fail fast" rationale) -- once constructed
    successfully, every read() call is a pure function of (offset, size)
    and whatever read_physical(...) returns for the physical sub-ranges
    it delegates to; nothing about a LogicalVolumeReader itself changes
    between calls.
    """

    def __init__(self, logical_volume: LogicalVolume, volume_group: VolumeGroup, read_physical: ByteRangeReader) -> None:
        self._logical_volume = logical_volume
        self._extent_size_bytes = volume_group.extent_size_bytes
        self._read_physical = read_physical
        self._physical_volumes_by_name: dict[str, PhysicalVolume] = {pv.name: pv for pv in volume_group.physical_volumes}

        segments = sorted(logical_volume.segments, key=lambda segment: segment.start_extent)
        self._segments = tuple(segments)

        # Precompute each segment's LV-relative starting *byte* offset, in
        # the same order as self._segments, so a read's offset can be
        # located via a single bisect (O(log S)) instead of scanning every
        # segment on every call -- see the module-level complexity note in
        # this PR's report for why this is the right amount of
        # optimization here (S is always small: a handful of segments per
        # Logical Volume in every real case this parser supports).
        segment_start_bytes: list[int] = []
        expected_next_extent = 0
        for segment in self._segments:
            if segment.start_extent != expected_next_extent:
                raise ExtentMapGapError(
                    f"Logical volume {logical_volume.name!r} has a gap or overlap in its extent map: "
                    f"expected a segment starting at extent {expected_next_extent}, found one starting at {segment.start_extent}."
                )
            if segment.physical_volume_name not in self._physical_volumes_by_name:
                raise UnresolvedPhysicalVolumeError(
                    f"Logical volume {logical_volume.name!r} has a segment referencing physical volume "
                    f"{segment.physical_volume_name!r}, which was not provided to this reader."
                )
            segment_start_bytes.append(expected_next_extent * self._extent_size_bytes)
            expected_next_extent += segment.extent_count

        self._segment_start_bytes = segment_start_bytes
        self._size_bytes = expected_next_extent * self._extent_size_bytes

    @property
    def size_bytes(self) -> int:
        """Total size of this Logical Volume, in bytes -- the sum of every
        segment's extent_count, already validated (at construction) to be
        contiguous from extent 0."""
        return self._size_bytes

    def read(self, offset: int, size: int) -> bytes:
        """Read exactly `size` bytes starting at LV-relative `offset`.

        Offset translation: locates which segment(s) [offset, offset +
        size) falls within via bisect over the precomputed segment-start
        table (O(log S) to find the first segment, then O(k) for the k
        segments an unusually large read happens to span -- k is 1 for
        the overwhelming majority of real reads). For each segment
        touched, the LV-relative sub-range is translated to an absolute
        physical byte offset as:

            physical_offset = pv.pe_start_bytes
                             + segment.start_physical_extent * extent_size_bytes
                             + (position_within_lv - segment_start_bytes)

        and delegated to read_physical(). Results are concatenated in
        order. A read spanning multiple segments therefore costs one
        read_physical() call per segment touched, not one per byte.

        Error propagation: an exception raised *by* read_physical() is
        never caught here -- it propagates completely unchanged, exactly
        as raised, with no wrapping. Only a read_physical() call that
        returns *fewer bytes than requested without raising* is treated
        as this reader's own error (UnderlyingReadError) -- a silent
        short read is exactly the kind of thing "never silently
        truncate" (see the module docstring) forbids passing through.
        """
        if offset < 0:
            raise InvalidReadRequestError(f"Read offset must not be negative, got {offset}.")
        if size < 0:
            raise InvalidReadRequestError(f"Read size must not be negative, got {size}.")
        end = offset + size
        if end > self._size_bytes:
            raise InvalidReadRequestError(f"Read [{offset}, {end}) extends beyond this logical volume's size ({self._size_bytes} bytes).")
        if size == 0:
            return b""

        chunks: list[bytes] = []
        position = offset
        while position < end:
            segment_index = bisect.bisect_right(self._segment_start_bytes, position) - 1
            segment = self._segments[segment_index]
            segment_start = self._segment_start_bytes[segment_index]
            segment_size = segment.extent_count * self._extent_size_bytes
            segment_end = segment_start + segment_size

            chunk_end = min(end, segment_end)
            chunk_size = chunk_end - position
            offset_within_segment = position - segment_start

            pv = self._physical_volumes_by_name[segment.physical_volume_name]  # already validated to exist at construction
            physical_offset = pv.pe_start_bytes + segment.start_physical_extent * self._extent_size_bytes + offset_within_segment

            chunk = self._read_physical(physical_offset, chunk_size)
            if len(chunk) != chunk_size:
                raise UnderlyingReadError(
                    f"Underlying reader returned {len(chunk)} bytes for a {chunk_size}-byte request at physical offset {physical_offset} "
                    f"(logical volume {self._logical_volume.name!r}, offset {position})."
                )
            chunks.append(chunk)
            position = chunk_end

        return b"".join(chunks)
