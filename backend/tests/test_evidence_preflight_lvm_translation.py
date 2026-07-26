"""Coverage for the LVM-aware volume-diagnostic translation added to align
Disk Image Preflight with LVM V1 (see app.services.evidence_preflight's
_translate_volume_diagnostics / _translate_volume_diagnostic /
_collect_display_filesystems / _is_raw_numeric_identifier).

Uses hand-built "volume" dicts matching exactly the shape
app.disk_images.service._discover_raw_volumes / _discover_logical_volumes
produce -- no real disk image or LVM fixture needed to exercise this
purely presentational translation layer.
"""

from __future__ import annotations

from app.services.evidence_preflight import (
    _collect_display_filesystems,
    _is_raw_numeric_identifier,
    _translate_volume_diagnostics,
)


def _partition(partition_index: int, **overrides) -> dict:
    base = {
        "partition_index": partition_index,
        "offset_bytes": 1048576,
        "length_bytes": 8 * 1024 * 1024,
        "partition_type": "Linux (0x83)",
        "filesystem_type": "ext4",
        "label": None,
        "uuid": None,
        "encrypted": False,
        "readable": True,
        "status": "readable",
        "warnings": [],
        "error": {},
        "metadata": {},
    }
    base.update(overrides)
    return base


def _lvm_container(partition_index: int) -> dict:
    return _partition(
        partition_index,
        partition_type="Linux Logical Volume Manager (0x8e)",
        filesystem_type=None,
        readable=False,
        status="unreadable_volume",
        error={"code": "unsupported_filesystem", "message": "internal detail, never surfaced"},
        metadata={"container_signature": "lvm2_physical_volume"},
    )


def _logical_volume(index: int, *, container_partition_index: int, name: str, readable: bool, filesystem_type: str | None = "ext4") -> dict:
    return _partition(
        index,
        partition_type="lvm2_logical_volume",
        filesystem_type=filesystem_type if readable else None,
        readable=readable,
        status="readable" if readable else "unreadable_volume",
        error={} if readable else {"code": "unsupported_filesystem", "message": "no recognizable filesystem"},
        metadata={"lvm": {"container_partition_index": container_partition_index, "container_offset_bytes": 1048576, "volume_group": "test-vg", "logical_volume": name}},
    )


def test_is_raw_numeric_identifier():
    assert _is_raw_numeric_identifier("128") is True
    assert _is_raw_numeric_identifier("8192") is True
    assert _is_raw_numeric_identifier("ext4") is False
    assert _is_raw_numeric_identifier(None) is False
    assert _is_raw_numeric_identifier("") is False


def test_collect_display_filesystems_excludes_raw_numeric_codes():
    volumes = [_partition(1, filesystem_type="ntfs"), _partition(2, filesystem_type="128"), _partition(3, filesystem_type="ntfs")]
    assert _collect_display_filesystems(volumes) == ["ntfs"]


def test_container_with_one_fully_readable_logical_volume_is_a_success_not_a_warning():
    volumes = [_lvm_container(7), _logical_volume(10700001, container_partition_index=7, name="root", readable=True)]

    diagnostics = _translate_volume_diagnostics(volumes)

    container_diag, lv_diag = diagnostics
    assert container_diag.kind == "partition"
    assert container_diag.status == "container"
    assert container_diag.ok is True  # not a warning
    assert "parsed successfully" in container_diag.explanation
    assert "does not currently parse" not in container_diag.explanation
    assert "does not yet discover" not in container_diag.explanation

    assert lv_diag.kind == "logical_volume"
    assert lv_diag.name == "root"
    assert lv_diag.container_volume_id == 7
    assert lv_diag.ok is True
    assert lv_diag.status == "readable"


def test_container_with_partial_logical_volume_success_shows_partial_not_total_failure():
    volumes = [
        _lvm_container(7),
        _logical_volume(10700001, container_partition_index=7, name="root", readable=True),
        _logical_volume(10700002, container_partition_index=7, name="swap_1", readable=False),
    ]

    diagnostics = _translate_volume_diagnostics(volumes)

    container_diag = diagnostics[0]
    assert container_diag.ok is True
    assert "1 of 2" in container_diag.explanation
    assert "were read as supported filesystems" in container_diag.explanation

    root_diag, swap_diag = diagnostics[1], diagnostics[2]
    assert root_diag.ok is True
    assert swap_diag.ok is False
    assert swap_diag.kind == "logical_volume"
    assert swap_diag.name == "swap_1"


def test_container_with_no_readable_logical_volumes_does_not_claim_success_but_stays_specific():
    volumes = [
        _lvm_container(7),
        _logical_volume(10700001, container_partition_index=7, name="root", readable=False),
    ]

    diagnostics = _translate_volume_diagnostics(volumes)

    container_diag = diagnostics[0]
    assert container_diag.ok is False
    assert "parsed successfully" in container_diag.explanation  # the container itself did parse
    assert "none could be read" in container_diag.explanation


def test_container_with_no_children_keeps_the_original_unsupported_container_diagnostic():
    # Parsing failed (or a multi-PV Volume Group was out of scope) --
    # _discover_logical_volumes added nothing. Must be identical to the
    # pre-PR3 diagnostic (regression coverage for
    # test_volume_diagnostics_detect_lvm_signature_without_parsing_lvm's
    # real-world case).
    volumes = [_lvm_container(7)]

    diagnostics = _translate_volume_diagnostics(volumes)

    diag = diagnostics[0]
    assert diag.kind == "partition"
    assert diag.status == "unreadable"
    assert diag.ok is False
    assert diag.detected_signature == "LVM2 physical volume"
    assert "does not currently parse this container format" in diag.explanation


def test_plain_partition_is_completely_unaffected():
    volumes = [_partition(1, filesystem_type="ntfs")]

    diagnostics = _translate_volume_diagnostics(volumes)

    diag = diagnostics[0]
    assert diag.kind == "partition"
    assert diag.status == "readable"
    assert diag.ok is True
    assert diag.name is None
    assert diag.container_volume_id is None


def test_logical_volume_filesystem_raw_numeric_code_is_suppressed():
    volumes = [_lvm_container(7), _logical_volume(10700001, container_partition_index=7, name="root", readable=True, filesystem_type="8192")]

    diagnostics = _translate_volume_diagnostics(volumes)

    lv_diag = diagnostics[1]
    assert lv_diag.filesystem is None
    assert lv_diag.ok is True
