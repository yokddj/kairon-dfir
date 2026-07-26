"""Tests for app.disk_images.lvm.reader.LogicalVolumeReader (PR2, Layer 1).

Deliberately does not import pytsk3 anywhere in this file -- LogicalVolume,
VolumeGroup, PhysicalVolume etc. are constructed directly from PR1's
dataclasses, and the "physical device" each test reads from is a plain
in-memory bytes buffer wrapped in _FakePhysicalReader below. This mirrors
the synthetic-fixture approach test_lvm_parser.py already established for
PR1, applied to the read layer instead of the metadata layer.

See app/disk_images/lvm/img_info.py's own small test file for the
(separate, pytsk3-importing) Layer 2 coverage.
"""

from __future__ import annotations

import pytest

from app.disk_images.lvm.exceptions import (
    ExtentMapGapError,
    InvalidReadRequestError,
    UnderlyingReadError,
    UnresolvedPhysicalVolumeError,
)
from app.disk_images.lvm.models import LinearSegment, LogicalVolume, MetadataArea, PhysicalVolume, VolumeGroup
from app.disk_images.lvm.reader import LogicalVolumeReader

EXTENT_SIZE = 4096
PE_START = 8192
BUFFER_SIZE = PE_START + 10 * EXTENT_SIZE


class _FakePhysicalReader:
    """A ByteRangeReader over an in-memory buffer, with optional failure
    injection, and a call log so tests can assert exactly how many
    read_physical() calls a given LogicalVolumeReader.read() made (and at
    what physical offsets) -- not just what bytes came back."""

    def __init__(self, buffer: bytes, *, raise_with: Exception | None = None, short_by: int = 0) -> None:
        self._buffer = buffer
        self._raise_with = raise_with
        self._short_by = short_by
        self.calls: list[tuple[int, int]] = []

    def __call__(self, offset: int, size: int) -> bytes:
        self.calls.append((offset, size))
        if self._raise_with is not None:
            raise self._raise_with
        chunk = self._buffer[offset : offset + size]
        if self._short_by:
            chunk = chunk[: -self._short_by] if self._short_by < len(chunk) else b""
        return chunk


def _pattern_buffer(size: int = BUFFER_SIZE) -> bytes:
    return bytes(i % 256 for i in range(size))


def _pv(name: str = "pv0", *, extent_count: int = 10, pe_start: int = PE_START) -> PhysicalVolume:
    return PhysicalVolume(
        name=name,
        id=f"{name}-uuid",
        device_size_bytes=pe_start + extent_count * EXTENT_SIZE,
        extent_size_bytes=EXTENT_SIZE,
        pe_start_bytes=pe_start,
        extent_count=extent_count,
    )


def _vg(physical_volumes: tuple[PhysicalVolume, ...]) -> VolumeGroup:
    return VolumeGroup(
        name="vg0",
        id="vg0-uuid",
        extent_size_bytes=EXTENT_SIZE,
        physical_volumes=physical_volumes,
        logical_volumes=(),
        metadata_area=MetadataArea(
            header_offset_bytes=4096,
            area_size_bytes=1_048_576,
            metadata_text_offset_bytes=4608,
            metadata_text_size_bytes=512,
        ),
    )


# Two segments on the same PV, deliberately laid out non-contiguously on the
# *physical* side (start_physical_extent 0 then 5, with a physical gap at
# extents 2-4) to prove the translation formula doesn't assume LV-contiguous
# implies PV-contiguous:
#
#   segment0: LV extents [0, 2)  -> PV extents [0, 2)  -> LV bytes [0, 8192)
#   segment1: LV extents [2, 5)  -> PV extents [5, 8)  -> LV bytes [8192, 20480)
_SEGMENT_0 = LinearSegment(start_extent=0, extent_count=2, physical_volume_name="pv0", start_physical_extent=0)
_SEGMENT_1 = LinearSegment(start_extent=2, extent_count=3, physical_volume_name="pv0", start_physical_extent=5)
_LV_SIZE_BYTES = 5 * EXTENT_SIZE  # 20480


def _two_segment_reader(buffer: bytes | None = None, **fake_kwargs) -> tuple[LogicalVolumeReader, _FakePhysicalReader]:
    buffer = _pattern_buffer() if buffer is None else buffer
    fake = _FakePhysicalReader(buffer, **fake_kwargs)
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(_SEGMENT_0, _SEGMENT_1))
    vg = _vg((_pv(),))
    reader = LogicalVolumeReader(lv, vg, fake)
    return reader, fake


def _expected_physical_offset(lv_offset: int) -> int:
    """Hand-derived (independently of reader.py's own formula) expected
    physical offset for a given LV-relative byte offset, for the two-segment
    fixture above -- used to assert against, not reused from the
    implementation under test."""
    if lv_offset < 8192:
        return PE_START + lv_offset
    return PE_START + 5 * EXTENT_SIZE + (lv_offset - 8192)


def test_size_bytes_is_sum_of_segment_extents():
    reader, _ = _two_segment_reader()
    assert reader.size_bytes == _LV_SIZE_BYTES


def test_single_segment_read():
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(_SEGMENT_0,))
    vg = _vg((_pv(),))
    buffer = _pattern_buffer()
    fake = _FakePhysicalReader(buffer)
    reader = LogicalVolumeReader(lv, vg, fake)

    result = reader.read(100, 50)

    assert result == buffer[PE_START + 100 : PE_START + 150]
    assert fake.calls == [(PE_START + 100, 50)]


def test_multiple_segments_full_volume_read():
    reader, fake = _two_segment_reader()

    result = reader.read(0, _LV_SIZE_BYTES)

    buffer = _pattern_buffer()
    expected = buffer[PE_START : PE_START + 8192] + buffer[PE_START + 5 * EXTENT_SIZE : PE_START + 5 * EXTENT_SIZE + 3 * EXTENT_SIZE]
    assert result == expected
    # One read_physical() call per segment touched, not one per byte.
    assert fake.calls == [(_expected_physical_offset(0), 8192), (_expected_physical_offset(8192), 3 * EXTENT_SIZE)]


def test_boundary_crossing_read():
    reader, fake = _two_segment_reader()
    offset, size = 8000, 400  # starts in segment0 (ends at 8192), ends in segment1

    result = reader.read(offset, size)

    buffer = _pattern_buffer()
    part0 = buffer[_expected_physical_offset(offset) : _expected_physical_offset(offset) + (8192 - offset)]
    part1 = buffer[_expected_physical_offset(8192) : _expected_physical_offset(8192) + (offset + size - 8192)]
    assert result == part0 + part1
    assert len(fake.calls) == 2


def test_first_byte():
    reader, fake = _two_segment_reader()
    result = reader.read(0, 1)
    assert result == _pattern_buffer()[PE_START : PE_START + 1]


def test_last_byte():
    reader, fake = _two_segment_reader()
    result = reader.read(_LV_SIZE_BYTES - 1, 1)
    expected_offset = _expected_physical_offset(_LV_SIZE_BYTES - 1)
    assert result == _pattern_buffer()[expected_offset : expected_offset + 1]


def test_zero_size_read_never_touches_underlying_reader():
    reader, fake = _two_segment_reader()
    result = reader.read(1234, 0)
    assert result == b""
    assert fake.calls == []


def test_non_aligned_read():
    reader, fake = _two_segment_reader()
    offset, size = 3000, 777  # neither aligned to EXTENT_SIZE, stays within segment0

    result = reader.read(offset, size)

    expected_offset = _expected_physical_offset(offset)
    assert result == _pattern_buffer()[expected_offset : expected_offset + size]
    assert fake.calls == [(expected_offset, size)]


def test_three_segments_single_read_spans_all_of_them():
    seg_a = LinearSegment(start_extent=0, extent_count=1, physical_volume_name="pv0", start_physical_extent=0)
    seg_b = LinearSegment(start_extent=1, extent_count=1, physical_volume_name="pv0", start_physical_extent=3)
    seg_c = LinearSegment(start_extent=2, extent_count=1, physical_volume_name="pv0", start_physical_extent=6)
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(seg_a, seg_b, seg_c))
    vg = _vg((_pv(),))
    buffer = _pattern_buffer()
    fake = _FakePhysicalReader(buffer)
    reader = LogicalVolumeReader(lv, vg, fake)

    result = reader.read(0, 3 * EXTENT_SIZE)

    expected = (
        buffer[PE_START + 0 * EXTENT_SIZE : PE_START + 1 * EXTENT_SIZE]
        + buffer[PE_START + 3 * EXTENT_SIZE : PE_START + 4 * EXTENT_SIZE]
        + buffer[PE_START + 6 * EXTENT_SIZE : PE_START + 7 * EXTENT_SIZE]
    )
    assert result == expected
    assert len(fake.calls) == 3


def test_segments_out_of_order_are_sorted_at_construction():
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(_SEGMENT_1, _SEGMENT_0))  # reversed
    vg = _vg((_pv(),))
    buffer = _pattern_buffer()
    fake = _FakePhysicalReader(buffer)
    reader = LogicalVolumeReader(lv, vg, fake)

    assert reader.size_bytes == _LV_SIZE_BYTES
    result = reader.read(0, _LV_SIZE_BYTES)
    assert len(result) == _LV_SIZE_BYTES


def test_repeated_reads_are_consistent_and_reader_is_stateless_across_calls():
    reader, fake = _two_segment_reader()

    first = reader.read(100, 50)
    second = reader.read(100, 50)
    assert first == second

    # A differently-shaped read afterwards still works correctly -- proves
    # no mutable state leaked from the previous calls.
    third = reader.read(8100, 200)
    expected_offset = _expected_physical_offset(8100)
    part0 = _pattern_buffer()[expected_offset : expected_offset + (8192 - 8100)]
    part1_offset = _expected_physical_offset(8192)
    part1 = _pattern_buffer()[part1_offset : part1_offset + (8100 + 200 - 8192)]
    assert third == part0 + part1


def test_negative_offset_is_rejected():
    reader, _ = _two_segment_reader()
    with pytest.raises(InvalidReadRequestError):
        reader.read(-1, 10)


def test_negative_size_is_rejected():
    reader, _ = _two_segment_reader()
    with pytest.raises(InvalidReadRequestError):
        reader.read(0, -1)


def test_read_extending_past_end_is_rejected():
    reader, _ = _two_segment_reader()
    with pytest.raises(InvalidReadRequestError):
        reader.read(_LV_SIZE_BYTES - 1, 2)


def test_read_starting_at_exact_end_with_zero_size_is_allowed():
    reader, fake = _two_segment_reader()
    result = reader.read(_LV_SIZE_BYTES, 0)
    assert result == b""
    assert fake.calls == []


def test_read_starting_past_end_is_rejected():
    reader, _ = _two_segment_reader()
    with pytest.raises(InvalidReadRequestError):
        reader.read(_LV_SIZE_BYTES + 1, 0)


def test_gap_in_extent_map_is_rejected_at_construction():
    seg0 = LinearSegment(start_extent=0, extent_count=2, physical_volume_name="pv0", start_physical_extent=0)
    seg1 = LinearSegment(start_extent=3, extent_count=2, physical_volume_name="pv0", start_physical_extent=5)  # gap: skips extent 2
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(seg0, seg1))
    vg = _vg((_pv(),))

    with pytest.raises(ExtentMapGapError):
        LogicalVolumeReader(lv, vg, _FakePhysicalReader(_pattern_buffer()))


def test_overlapping_segments_are_rejected_at_construction():
    seg0 = LinearSegment(start_extent=0, extent_count=3, physical_volume_name="pv0", start_physical_extent=0)
    seg1 = LinearSegment(start_extent=2, extent_count=2, physical_volume_name="pv0", start_physical_extent=5)  # overlaps extent 2
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(seg0, seg1))
    vg = _vg((_pv(),))

    with pytest.raises(ExtentMapGapError):
        LogicalVolumeReader(lv, vg, _FakePhysicalReader(_pattern_buffer()))


def test_unresolved_physical_volume_is_rejected_at_construction():
    seg = LinearSegment(start_extent=0, extent_count=1, physical_volume_name="pv-does-not-exist", start_physical_extent=0)
    lv = LogicalVolume(name="lv0", id="lv0-uuid", segments=(seg,))
    vg = _vg((_pv(name="pv0"),))  # declares only "pv0", not "pv-does-not-exist"

    with pytest.raises(UnresolvedPhysicalVolumeError):
        LogicalVolumeReader(lv, vg, _FakePhysicalReader(_pattern_buffer()))


def test_underlying_short_read_raises_underlying_read_error():
    reader, _ = _two_segment_reader(short_by=1)
    with pytest.raises(UnderlyingReadError):
        reader.read(0, 100)


def test_underlying_reader_exception_propagates_unchanged():
    boom = OSError("simulated device failure")
    reader, _ = _two_segment_reader(raise_with=boom)
    with pytest.raises(OSError) as excinfo:
        reader.read(0, 100)
    assert excinfo.value is boom
