"""Tests for app.disk_images.lvm -- the pure-Python, read-only LVM2
metadata parser (PR1 of the LVM support architecture RFC).

Every fixture here is constructed byte-by-byte in Python, matching the
same "hand-craft the bytes, no external tools" technique already
established in test_evidence_preflight.py's synthetic MBR disk-image
tests -- no lvm2 userspace tools, no loop devices, no privileged access,
no real disk image of any kind.
"""

from __future__ import annotations

import struct

import pytest

from app.disk_images.lvm import binary, text_format
from app.disk_images.lvm.exceptions import (
    InconsistentMetadataError,
    InvalidLabelError,
    MalformedMetadataTextError,
    MissingRequiredFieldError,
    UnsupportedMetadataLayoutError,
    UnsupportedMetadataVersionError,
    UnsupportedSegmentTypeError,
)
from app.disk_images.lvm.parser import build_volume_group, parse_physical_volume_metadata

SECTOR = 512
DEFAULT_PV_UUID_RAW = b"aaaaaaaaaabbbbbbbbbbccccccccccdd"  # 32 chars, no dashes
DEFAULT_PV_UUID_FORMATTED = "aaaaaa-aaaa-bbbb-bbbb-bbcc-cccc-ccccdd"


# ---------------------------------------------------------------------------
# Byte-level fixture construction
# ---------------------------------------------------------------------------


def _label_header_bytes(*, sector_number: int, pv_header_offset: int, signature: bytes = b"LABELONE", label_type: bytes = b"LVM2 001") -> bytes:
    # crc_xl is never validated by this parser (a documented, deliberate
    # limitation -- see the exact checksummed byte range's ambiguity noted
    # in the architecture work), so tests never need to compute a real one.
    return struct.pack("<8sQII8s", signature, sector_number, 0, pv_header_offset, label_type)


def _disk_locations_bytes(entries: list[tuple[int, int]]) -> bytes:
    parts = [struct.pack("<QQ", offset, size) for offset, size in entries]
    parts.append(struct.pack("<QQ", 0, 0))  # terminator
    return b"".join(parts)


def _pv_header_bytes(*, pv_uuid_raw: bytes, device_size_bytes: int, data_areas: list[tuple[int, int]], metadata_areas: list[tuple[int, int]]) -> bytes:
    assert len(pv_uuid_raw) == 32
    return pv_uuid_raw + struct.pack("<Q", device_size_bytes) + _disk_locations_bytes(data_areas) + _disk_locations_bytes(metadata_areas)


def _mda_header_bytes(*, area_start: int, area_size: int, raw_locns: list[tuple[int, int, int, int]], magic: bytes = b" LVM2 x[5A%r0N*>", version: int = 1, corrupt_checksum: bool = False) -> bytes:
    fixed = magic + struct.pack("<I", version) + struct.pack("<QQ", area_start, area_size)
    raw_locn_bytes = b"".join(struct.pack("<QQII", *entry) for entry in raw_locns)
    body = (fixed + raw_locn_bytes).ljust(binary.MDA_HEADER_SIZE - 4, b"\x00")
    checksum = binary.lvm_weak_crc32(body)
    if corrupt_checksum:
        checksum ^= 0xFFFFFFFF
    return struct.pack("<I", checksum) + body


def build_synthetic_pv(
    *,
    metadata_text: str,
    pv_uuid_raw: bytes = DEFAULT_PV_UUID_RAW,
    label_sector: int = 1,
    device_size_sectors: int = 204800,
    pe_start_sectors: int = 2048,
    mda_offset: int = SECTOR * 8,
    mda_size: int = SECTOR * 64,
    corrupt_metadata_checksum: bool = False,
    corrupt_mda_header_checksum: bool = False,
    mda_version: int = 1,
    wrap_metadata: bool = False,
    ignore_active_location: bool = False,
) -> bytes:
    """Build a complete, byte-accurate synthetic LVM2 physical volume
    prefix: label header + PV header (both in the label's own sector) +
    a metadata area (mda_header + the metadata text itself) -- everything
    parse_physical_volume_metadata needs, with correct checksums unless a
    `corrupt_*`/other deliberately-wrong option says otherwise."""
    metadata_bytes = metadata_text.encode("utf-8")
    metadata_checksum = binary.lvm_weak_crc32(metadata_bytes)
    if corrupt_metadata_checksum:
        metadata_checksum ^= 0xFFFFFFFF

    raw_locn_offset = SECTOR  # first sector of the metadata area is reserved for mda_header
    if wrap_metadata:
        # Declare a size that would run past the end of the metadata area --
        # exercises the deliberately-unsupported wraparound path.
        raw_locn_size = mda_size  # offset (SECTOR) + size (mda_size) always exceeds mda_size
    else:
        raw_locn_size = len(metadata_bytes)

    flags = binary._RAW_LOCN_IGNORED if ignore_active_location else 0
    raw_locns = [(raw_locn_offset, raw_locn_size, metadata_checksum, flags)]

    mda_header = _mda_header_bytes(area_start=mda_offset, area_size=mda_size, raw_locns=raw_locns, version=mda_version, corrupt_checksum=corrupt_mda_header_checksum)

    pv_header_offset_in_sector = 32  # immediately after the 32-byte label header
    label = _label_header_bytes(sector_number=label_sector, pv_header_offset=pv_header_offset_in_sector)
    pv_header = _pv_header_bytes(
        pv_uuid_raw=pv_uuid_raw,
        device_size_bytes=device_size_sectors * SECTOR,
        data_areas=[(pe_start_sectors * SECTOR, (device_size_sectors - pe_start_sectors) * SECTOR)],
        metadata_areas=[(mda_offset, mda_size)],
    )

    total_size = max(mda_offset + mda_size, mda_offset + raw_locn_offset + len(metadata_bytes)) + SECTOR
    buffer = bytearray(total_size)
    label_sector_start = label_sector * SECTOR
    buffer[label_sector_start : label_sector_start + len(label)] = label
    buffer[label_sector_start + pv_header_offset_in_sector : label_sector_start + pv_header_offset_in_sector + len(pv_header)] = pv_header
    buffer[mda_offset : mda_offset + len(mda_header)] = mda_header
    buffer[mda_offset + raw_locn_offset : mda_offset + raw_locn_offset + len(metadata_bytes)] = metadata_bytes
    return bytes(buffer)


def _reader_for(data: bytes):
    def read(offset: int, size: int) -> bytes:
        return data[offset : offset + size]

    return read


# ---------------------------------------------------------------------------
# Metadata text builder (renders structured Python data into LVM2's config
# grammar) -- used for the "happy path" and structural-variation tests;
# malformed/missing-field cases below use short hand-written literal text
# instead, for precise control over exactly what is wrong.
# ---------------------------------------------------------------------------


def _render_segment(index: int, segment: dict) -> str:
    stripes = ", ".join(f'"{s}"' if isinstance(s, str) else str(s) for s in segment["stripes"])
    return f"""
            segment{index} {{
                start_extent = {segment['start_extent']}
                extent_count = {segment['extent_count']}
                type = "{segment['type']}"
                stripe_count = {segment['stripe_count']}
                stripes = [{stripes}]
            }}"""


def _render_lv(name: str, lv: dict) -> str:
    segments = "".join(_render_segment(i, seg) for i, seg in enumerate(lv["segments"], start=1))
    return f"""
        {name} {{
            id = "{lv['id']}"
            segment_count = {len(lv['segments'])}{segments}
        }}"""


def _render_pv(name: str, pv: dict) -> str:
    return f"""
        {name} {{
            id = "{pv['id']}"
            dev_size = {pv['dev_size']}
            pe_start = {pv['pe_start']}
            pe_count = {pv['pe_count']}
        }}"""


def render_metadata_text(*, vg_name="test-vg", vg_id="AAAAAA-BBBB-CCCC-DDDD-EEEE-FFFF-000001", extent_size=8192, physical_volumes: list[dict], logical_volumes: list[dict]) -> str:
    pvs = "".join(_render_pv(pv["name"], pv) for pv in physical_volumes)
    lvs = "".join(_render_lv(lv["name"], lv) for lv in logical_volumes)
    return f"""# Generated for tests
contents = "Text Format Volume Group"
version = 1

{vg_name} {{
    id = "{vg_id}"
    seqno = 1
    format = "lvm2"
    extent_size = {extent_size}
    max_lv = 0
    max_pv = 0

    physical_volumes {{{pvs}
    }}

    logical_volumes {{{lvs}
    }}
}}
"""


def _single_linear_lv_metadata(*, pv_id: str = DEFAULT_PV_UUID_FORMATTED, extent_count: int = 100) -> str:
    return render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": pv_id, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000001",
                "segments": [{"start_extent": 0, "extent_count": extent_count, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]}],
            }
        ],
    )


# ---------------------------------------------------------------------------
# Text-format grammar (tokenizer/parser) -- low-level, direct tests
# ---------------------------------------------------------------------------


def test_text_format_parses_comments_sections_arrays_and_negative_numbers():
    text = """
    # a leading comment
    top = 1
    kali-vg {
        status = ["RESIZEABLE", "READ"]  # inline comment
        offset = -5
        nested {
            deep = "value"
        }
    }
    """
    document = text_format.parse_config_text(text)
    assert document["top"] == 1
    assert document["kali-vg"]["status"] == ["RESIZEABLE", "READ"]
    assert document["kali-vg"]["offset"] == -5
    assert document["kali-vg"]["nested"]["deep"] == "value"


def test_text_format_rejects_unterminated_string():
    with pytest.raises(MalformedMetadataTextError, match="Unterminated string"):
        text_format.parse_config_text('name = "unterminated')


def test_text_format_rejects_unbalanced_braces():
    with pytest.raises(MalformedMetadataTextError):
        text_format.parse_config_text("vg { id = \"x\"")


def test_text_format_rejects_value_where_section_or_assignment_expected():
    with pytest.raises(MalformedMetadataTextError):
        text_format.parse_config_text('vg "not an assignment or section"')


def test_text_format_empty_array_parses_to_empty_list():
    document = text_format.parse_config_text("flags = []")
    assert document["flags"] == []


# ---------------------------------------------------------------------------
# Full round-trip: valid metadata
# ---------------------------------------------------------------------------


def test_parses_valid_single_pv_single_lv_metadata():
    text = _single_linear_lv_metadata(extent_count=100)
    data = build_synthetic_pv(metadata_text=text)

    result = parse_physical_volume_metadata(_reader_for(data))

    assert result.physical_volume.name == "pv0"
    assert result.physical_volume.id == DEFAULT_PV_UUID_FORMATTED
    assert result.physical_volume.device_size_bytes == 204800 * SECTOR
    assert result.physical_volume.pe_start_bytes == 2048 * SECTOR
    assert result.physical_volume.extent_count == 200
    assert result.physical_volume.extent_size_bytes == 8192 * SECTOR

    vg = result.volume_group
    assert vg.name == "test-vg"
    assert vg.extent_size_bytes == 8192 * SECTOR
    assert len(vg.physical_volumes) == 1
    assert len(vg.logical_volumes) == 1

    lv = vg.logical_volumes[0]
    assert lv.name == "root"
    assert lv.extent_count == 100
    assert len(lv.segments) == 1
    segment = lv.segments[0]
    assert segment.start_extent == 0
    assert segment.extent_count == 100
    assert segment.physical_volume_name == "pv0"
    assert segment.start_physical_extent == 0


def test_parses_multiple_logical_volumes():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {"name": "root", "id": "LLLLLL-0000-0000-0000-0000-0000-000001", "segments": [{"start_extent": 0, "extent_count": 80, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]}]},
            {"name": "swap", "id": "LLLLLL-0000-0000-0000-0000-0000-000002", "segments": [{"start_extent": 0, "extent_count": 20, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 80]}]},
        ],
    )
    data = build_synthetic_pv(metadata_text=text)

    result = parse_physical_volume_metadata(_reader_for(data))

    names = {lv.name: lv.extent_count for lv in result.volume_group.logical_volumes}
    assert names == {"root": 80, "swap": 20}


def test_parses_multiple_linear_segments_in_one_logical_volume():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [
                    {"start_extent": 0, "extent_count": 40, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]},
                    {"start_extent": 40, "extent_count": 60, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 100]},
                ],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)

    result = parse_physical_volume_metadata(_reader_for(data))

    lv = result.volume_group.logical_volumes[0]
    assert lv.extent_count == 100
    assert [(s.start_extent, s.extent_count, s.start_physical_extent) for s in lv.segments] == [(0, 40, 0), (40, 60, 100)]


def test_segments_out_of_order_in_source_are_sorted_by_start_extent():
    # Deliberately declare segment2 (the later extent range) before
    # segment1 in the source text -- LVM2 metadata does not guarantee
    # segmentN blocks appear in extent order, only that the N suffix does.
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [
                    {"start_extent": 40, "extent_count": 60, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 100]},
                    {"start_extent": 0, "extent_count": 40, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]},
                ],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    result = parse_physical_volume_metadata(_reader_for(data))
    lv = result.volume_group.logical_volumes[0]
    assert [s.start_extent for s in lv.segments] == [0, 40]


# ---------------------------------------------------------------------------
# Invalid label / header-level failures
# ---------------------------------------------------------------------------


def test_invalid_label_signature_is_rejected():
    data = bytearray(build_synthetic_pv(metadata_text=_single_linear_lv_metadata()))
    label_start = 1 * SECTOR
    data[label_start : label_start + 8] = b"NOTALVM!"
    with pytest.raises(InvalidLabelError):
        parse_physical_volume_metadata(_reader_for(bytes(data)))


def test_missing_label_entirely_is_rejected():
    data = b"\x00" * (SECTOR * 16)
    with pytest.raises(InvalidLabelError):
        parse_physical_volume_metadata(_reader_for(data))


def test_truncated_pv_header_without_terminator_is_rejected():
    # A pv_header whose descriptor lists never reach their NULL terminator
    # within the bytes made available -- distinguishing "corrupt/truncated"
    # from "well-formed but empty" is exactly what this must catch. The
    # non-zero filler must span the parser's *entire* PV-header read
    # window (parser._PV_HEADER_READ_SIZE), or the read would run past it
    # into real zero-padding and accidentally "find" a valid terminator.
    from app.disk_images.lvm.parser import _PV_HEADER_READ_SIZE

    pv_uuid = DEFAULT_PV_UUID_RAW
    prefix = pv_uuid + struct.pack("<Q", 1000)
    filler = b"\x01" * (_PV_HEADER_READ_SIZE)  # every 16-byte chunk has a non-zero offset
    garbage = prefix + filler
    label = _label_header_bytes(sector_number=1, pv_header_offset=32)
    buf = bytearray(SECTOR + 32 + len(garbage))
    buf[SECTOR : SECTOR + len(label)] = label
    buf[SECTOR + 32 : SECTOR + 32 + len(garbage)] = garbage
    with pytest.raises(InvalidLabelError):
        parse_physical_volume_metadata(_reader_for(bytes(buf)))


# ---------------------------------------------------------------------------
# Metadata-area/version-level failures
# ---------------------------------------------------------------------------


def test_unsupported_metadata_version_is_rejected():
    text = _single_linear_lv_metadata()
    data = build_synthetic_pv(metadata_text=text, mda_version=2)
    with pytest.raises(UnsupportedMetadataVersionError):
        parse_physical_volume_metadata(_reader_for(data))


def test_corrupted_mda_header_checksum_is_rejected():
    text = _single_linear_lv_metadata()
    data = build_synthetic_pv(metadata_text=text, corrupt_mda_header_checksum=True)
    with pytest.raises(MalformedMetadataTextError):
        parse_physical_volume_metadata(_reader_for(data))


def test_corrupted_metadata_text_checksum_is_rejected():
    text = _single_linear_lv_metadata()
    data = build_synthetic_pv(metadata_text=text, corrupt_metadata_checksum=True)
    with pytest.raises(MalformedMetadataTextError):
        parse_physical_volume_metadata(_reader_for(data))


def test_wrapped_metadata_area_is_unsupported():
    text = _single_linear_lv_metadata()
    data = build_synthetic_pv(metadata_text=text, wrap_metadata=True)
    with pytest.raises(UnsupportedMetadataLayoutError):
        parse_physical_volume_metadata(_reader_for(data))


def test_every_metadata_location_ignored_is_rejected():
    text = _single_linear_lv_metadata()
    data = build_synthetic_pv(metadata_text=text, ignore_active_location=True)
    with pytest.raises(MalformedMetadataTextError, match="superseded"):
        parse_physical_volume_metadata(_reader_for(data))


# ---------------------------------------------------------------------------
# Malformed metadata text (grammar-level, via the full pipeline)
# ---------------------------------------------------------------------------


def test_malformed_metadata_text_grammar_is_rejected():
    data = build_synthetic_pv(metadata_text="vg { id = \"unterminated")
    with pytest.raises(MalformedMetadataTextError):
        parse_physical_volume_metadata(_reader_for(data))


def test_metadata_text_with_no_top_level_section_is_rejected():
    data = build_synthetic_pv(metadata_text='contents = "Text Format Volume Group"\nversion = 1\n')
    with pytest.raises(MissingRequiredFieldError):
        parse_physical_volume_metadata(_reader_for(data))


def test_metadata_text_with_two_top_level_sections_is_rejected():
    text = 'vg-one {\n    id = "x"\n}\nvg-two {\n    id = "y"\n}\n'
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MalformedMetadataTextError, match="more than one"):
        parse_physical_volume_metadata(_reader_for(data))


# ---------------------------------------------------------------------------
# Missing required fields
# ---------------------------------------------------------------------------


def test_volume_group_missing_extent_size_is_rejected():
    text = 'test-vg {\n    id = "AAAAAA-BBBB-CCCC-DDDD-EEEE-FFFF-000001"\n    physical_volumes { }\n    logical_volumes { }\n}\n'
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="extent_size"):
        parse_physical_volume_metadata(_reader_for(data))


def test_physical_volume_missing_dev_size_is_rejected():
    text = """test-vg {
    id = "AAAAAA-BBBB-CCCC-DDDD-EEEE-FFFF-000001"
    extent_size = 8192
    physical_volumes {
        pv0 {
            id = "aaaaaa-aaaa-bbbb-bbbb-bbcc-cccc-ccccdd"
            pe_start = 2048
            pe_count = 200
        }
    }
    logical_volumes {
        root {
            id = "LLLLLL-0000-0000-0000-0000-0000-000001"
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 100
                type = "striped"
                stripe_count = 1
                stripes = ["pv0", 0]
            }
        }
    }
}
"""
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="dev_size"):
        parse_physical_volume_metadata(_reader_for(data))


def test_logical_volume_missing_segment_count_is_rejected():
    text = _single_linear_lv_metadata().replace("segment_count = 1\n", "")
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="segment_count"):
        parse_physical_volume_metadata(_reader_for(data))


def test_segment_missing_start_extent_is_rejected():
    text = _single_linear_lv_metadata().replace("                start_extent = 0\n", "")
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="start_extent"):
        parse_physical_volume_metadata(_reader_for(data))


def test_segment_count_mismatch_with_actual_segment_blocks_is_rejected():
    text = _single_linear_lv_metadata().replace("segment_count = 1", "segment_count = 2")
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="segment2"):
        parse_physical_volume_metadata(_reader_for(data))


def test_volume_group_with_empty_physical_volumes_is_rejected():
    text = _single_linear_lv_metadata()
    # Blank out the one physical_volumes entry, leaving an empty section.
    text = text.replace(
        _render_pv("pv0", {"id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}),
        "",
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(MissingRequiredFieldError, match="physical_volumes"):
        parse_physical_volume_metadata(_reader_for(data))


# ---------------------------------------------------------------------------
# Unsupported segment types (out of V1 scope)
# ---------------------------------------------------------------------------


def test_mirror_segment_type_is_rejected():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [{"start_extent": 0, "extent_count": 100, "type": "mirror", "stripe_count": 1, "stripes": ["pv0", 0]}],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(UnsupportedSegmentTypeError, match="mirror"):
        parse_physical_volume_metadata(_reader_for(data))


def test_real_striping_stripe_count_greater_than_one_is_rejected():
    text = render_metadata_text(
        physical_volumes=[
            {"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200},
        ],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [{"start_extent": 0, "extent_count": 100, "type": "striped", "stripe_count": 2, "stripes": ["pv0", 0, "pv0", 50]}],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(UnsupportedSegmentTypeError, match="stripe_count=2"):
        parse_physical_volume_metadata(_reader_for(data))


def test_stripes_list_inconsistent_with_stripe_count_one_is_rejected():
    # stripe_count claims linear (1), but stripes has more than one pair --
    # an internally inconsistent segment, not merely a different type.
    text = _single_linear_lv_metadata().replace('stripes = ["pv0", 0]', 'stripes = ["pv0", 0, "pv0", 50]')
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError):
        parse_physical_volume_metadata(_reader_for(data))


# ---------------------------------------------------------------------------
# Inconsistent metadata
# ---------------------------------------------------------------------------


def test_segment_referencing_undeclared_physical_volume_is_rejected():
    text = _single_linear_lv_metadata().replace('stripes = ["pv0", 0]', 'stripes = ["pv-does-not-exist", 0]')
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="pv-does-not-exist"):
        parse_physical_volume_metadata(_reader_for(data))


def test_segments_with_a_gap_are_rejected():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [
                    {"start_extent": 0, "extent_count": 40, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]},
                    {"start_extent": 50, "extent_count": 50, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 100]},  # gap: 40..50 uncovered
                ],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="gap or overlap"):
        parse_physical_volume_metadata(_reader_for(data))


def test_segments_with_overlap_are_rejected():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [
                    {"start_extent": 0, "extent_count": 40, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]},
                    {"start_extent": 30, "extent_count": 50, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 100]},  # overlaps 30..40
                ],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="gap or overlap"):
        parse_physical_volume_metadata(_reader_for(data))


def test_logical_volume_not_starting_at_extent_zero_is_rejected():
    text = render_metadata_text(
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": 2048, "pe_count": 200}],
        logical_volumes=[
            {
                "name": "root",
                "id": "LLLLLL-0000-0000-0000-0000-0000-000001",
                "segments": [{"start_extent": 5, "extent_count": 40, "type": "striped", "stripe_count": 1, "stripes": ["pv0", 0]}],
            },
        ],
    )
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="gap or overlap"):
        parse_physical_volume_metadata(_reader_for(data))


def test_physical_volume_uuid_mismatch_between_header_and_metadata_text_is_rejected():
    # The metadata text declares a *different* PV UUID than the one
    # actually recorded in this physical volume's own binary header.
    text = _single_linear_lv_metadata(pv_id="zzzzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzzzz")
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="does not match"):
        parse_physical_volume_metadata(_reader_for(data))


def test_negative_dev_size_is_rejected():
    text = _single_linear_lv_metadata().replace("dev_size = 204800", "dev_size = 0")
    data = build_synthetic_pv(metadata_text=text)
    with pytest.raises(InconsistentMetadataError, match="non-positive"):
        parse_physical_volume_metadata(_reader_for(data))


# ---------------------------------------------------------------------------
# build_volume_group() directly (no byte-level fixture needed)
# ---------------------------------------------------------------------------


def test_build_volume_group_accepts_a_pre_parsed_document():
    from app.disk_images.lvm.models import MetadataArea

    text = _single_linear_lv_metadata()
    document = text_format.parse_config_text(text)
    metadata_area = MetadataArea(header_offset_bytes=0, area_size_bytes=1024, metadata_text_offset_bytes=512, metadata_text_size_bytes=len(text))

    vg = build_volume_group(document, metadata_area=metadata_area)

    assert vg.name == "test-vg"
    assert vg.metadata_area is metadata_area

