"""Tests for the disk-image ingest progress/phase-timing fix.

Covers the three defects found investigating the "Processing / 5% / Core
ingest" stall-that-wasn't-a-stall: a falsely-precise percentage floor when
total_files is unknown, a hardcoded generic phase label instead of the real
current_action, and unbounded phase_timings growth from heartbeat ticks.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, utc_now
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.usable_ingest import USABLE_INGEST_MODE, ingest_mode_metadata
from app.workers.tasks import (
    DISK_IMAGE_PROGRESS_ACTIONS,
    _compute_extraction_progress,
    _finish_metadata_phase_timing,
    _transition_metadata_phase_timing,
    _update_progress,
)

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _case() -> Case:
    return Case(id=CASE_ID, name="Case", status="open")


def _evidence() -> Evidence:
    metadata = {**ingest_mode_metadata(USABLE_INGEST_MODE)}
    return Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="disk.E01",
        stored_path="/tmp/disk.E01",
        original_path="/tmp/disk.E01",
        evidence_type=EvidenceType.disk_image,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="abc",
        size_bytes=128,
        file_count=0,
        ingest_status=IngestStatus.processing,
        metadata_json=metadata,
        path_validation={},
        ingest_source={},
        error_log={},
    )


# ---------------------------------------------------------------------------
# _compute_extraction_progress: percentage / phase-label / indeterminate flag
# ---------------------------------------------------------------------------


def test_disk_image_with_unknown_total_files_is_indeterminate() -> None:
    pct, phase_name, indeterminate = _compute_extraction_progress(
        is_selected_velociraptor=False,
        streaming_materialization_enabled=True,
        current_action="materializing_disk_image_files",
        total_files=0,
        processed_files=0,
    )
    assert indeterminate is True
    assert phase_name == "materializing_disk_image_files"
    assert pct == 5


def test_disk_image_with_known_total_files_is_not_indeterminate() -> None:
    pct, phase_name, indeterminate = _compute_extraction_progress(
        is_selected_velociraptor=False,
        streaming_materialization_enabled=True,
        current_action="materializing_disk_image_files",
        total_files=1000,
        processed_files=500,
    )
    assert indeterminate is False
    assert phase_name == "materializing_disk_image_files"
    assert 5 <= pct <= 18


def test_disk_image_current_action_becomes_phase_name_not_generic_label() -> None:
    for action in DISK_IMAGE_PROGRESS_ACTIONS:
        _, phase_name, _ = _compute_extraction_progress(
            is_selected_velociraptor=False,
            streaming_materialization_enabled=True,
            current_action=action,
            total_files=0,
            processed_files=0,
        )
        assert phase_name == action


def test_regular_archive_extraction_is_never_indeterminate() -> None:
    """Archive/velociraptor extraction always knows total_files up front
    (from the archive manifest) and must keep getting a real percentage --
    this fix must not change that path's behaviour."""
    pct, phase_name, indeterminate = _compute_extraction_progress(
        is_selected_velociraptor=False,
        streaming_materialization_enabled=False,
        current_action="",
        total_files=100,
        processed_files=50,
    )
    assert indeterminate is False
    assert phase_name == "extracting"
    assert 5 <= pct <= 18


def test_velociraptor_selected_extraction_is_never_indeterminate() -> None:
    pct, phase_name, indeterminate = _compute_extraction_progress(
        is_selected_velociraptor=True,
        streaming_materialization_enabled=True,
        current_action="",
        total_files=100,
        processed_files=50,
    )
    assert indeterminate is False
    assert phase_name == "materializing_and_parsing"
    assert 30 <= pct <= 45


def test_unknown_action_falls_back_to_generic_extracting_phase() -> None:
    pct, phase_name, indeterminate = _compute_extraction_progress(
        is_selected_velociraptor=False,
        streaming_materialization_enabled=False,
        current_action="some_future_unmapped_action",
        total_files=0,
        processed_files=0,
    )
    assert phase_name == "extracting"
    assert indeterminate is False
    assert pct == 5


# ---------------------------------------------------------------------------
# _transition_metadata_phase_timing / _finish_metadata_phase_timing:
# bounded, deduplicated phase_timings
# ---------------------------------------------------------------------------


def test_repeated_heartbeat_in_same_phase_updates_in_place_no_growth() -> None:
    metadata: dict = {}
    _transition_metadata_phase_timing(metadata, "materializing_disk_image_files")
    assert len(metadata["phase_timings"]) == 1

    for _ in range(50):
        _transition_metadata_phase_timing(metadata, "materializing_disk_image_files")

    assert len(metadata["phase_timings"]) == 1
    assert metadata["phase_timings"][0]["phase"] == "materializing_disk_image_files"
    assert metadata["phase_timings"][0]["finished_at"] is None
    assert metadata["current_phase_timing"]["finished_at"] is None


def test_phase_transition_closes_previous_entry_exactly_once() -> None:
    metadata: dict = {}
    _transition_metadata_phase_timing(metadata, "detecting_format")
    _transition_metadata_phase_timing(metadata, "detecting_format")
    _transition_metadata_phase_timing(metadata, "hashing")

    phases = [item["phase"] for item in metadata["phase_timings"]]
    assert phases == ["detecting_format", "hashing"]
    assert metadata["phase_timings"][0]["finished_at"] is not None
    assert metadata["phase_timings"][1]["finished_at"] is None
    assert metadata["current_phase_timing"]["phase"] == "hashing"


def test_exactly_one_unfinished_entry_invariant_across_many_transitions() -> None:
    metadata: dict = {}
    action_sequence = [
        "detecting_format",
        "hashing",
        "inspecting_image",
        "discovering_volumes",
        "materializing_disk_image_files",
    ]
    for action in action_sequence:
        for _ in range(10):
            _transition_metadata_phase_timing(metadata, action)

    unfinished = [item for item in metadata["phase_timings"] if item.get("finished_at") is None]
    assert len(unfinished) == 1
    assert unfinished[0]["phase"] == "materializing_disk_image_files"
    assert len(metadata["phase_timings"]) == len(action_sequence)


def test_long_running_heartbeat_simulation_stays_bounded() -> None:
    """Simulates the real disk-image materialization heartbeat firing every
    ~5 seconds for a long walk (the mechanism that turned this from a
    latent bug into unbounded growth): hundreds of same-phase calls must
    never add more than one entry."""
    metadata: dict = {}
    for _ in range(500):
        _transition_metadata_phase_timing(metadata, "materializing_disk_image_files")

    assert len(metadata["phase_timings"]) == 1
    assert metadata["phase_timings"][0]["finished_at"] is None


def test_finish_metadata_phase_timing_closes_exactly_one_entry_and_stays_bounded() -> None:
    metadata: dict = {}
    for _ in range(20):
        _transition_metadata_phase_timing(metadata, "materializing_disk_image_files")

    _finish_metadata_phase_timing(metadata, phase="materializing_disk_image_files")

    assert metadata["current_phase_timing"] is None
    assert len(metadata["phase_timings"]) == 1
    assert metadata["phase_timings"][0]["finished_at"] is not None


def test_self_heals_preexisting_duplicate_unfinished_entries_without_migration() -> None:
    """Simulates DB rows corrupted by the old buggy snapshot-persistence
    pattern (many stray open entries for one phase, already committed to
    metadata_json before this fix existed). No migration should be needed
    -- the very next transition/finish call must clean it up."""
    corrupted_metadata = {
        "current_phase_timing": {
            "phase": "materializing_disk_image_files",
            "started_at": utc_now().isoformat(),
            "finished_at": None,
            "duration_seconds": 900.0,
        },
        "phase_timings": [
            {
                "phase": "materializing_disk_image_files",
                "started_at": utc_now().isoformat(),
                "finished_at": None,
                "duration_seconds": float(i),
            }
            for i in range(342)
        ],
    }

    _transition_metadata_phase_timing(corrupted_metadata, "discovering_volumes")

    assert len(corrupted_metadata["phase_timings"]) == 2
    assert corrupted_metadata["phase_timings"][0]["phase"] == "materializing_disk_image_files"
    assert corrupted_metadata["phase_timings"][0]["finished_at"] is not None
    assert corrupted_metadata["phase_timings"][1]["phase"] == "discovering_volumes"
    assert corrupted_metadata["phase_timings"][1]["finished_at"] is None


def test_self_heals_preexisting_corruption_via_finish_too() -> None:
    corrupted_metadata = {
        "current_phase_timing": {
            "phase": "materializing_disk_image_files",
            "started_at": utc_now().isoformat(),
            "finished_at": None,
            "duration_seconds": 900.0,
        },
        "phase_timings": [
            {
                "phase": "materializing_disk_image_files",
                "started_at": utc_now().isoformat(),
                "finished_at": None,
                "duration_seconds": float(i),
            }
            for i in range(342)
        ],
    }

    _finish_metadata_phase_timing(corrupted_metadata, phase="materializing_disk_image_files")

    assert len(corrupted_metadata["phase_timings"]) == 1
    assert corrupted_metadata["phase_timings"][0]["finished_at"] is not None
    assert corrupted_metadata["current_phase_timing"] is None


def test_completed_entries_are_never_mutated_by_later_transitions() -> None:
    metadata: dict = {}
    _transition_metadata_phase_timing(metadata, "detecting_format")
    _transition_metadata_phase_timing(metadata, "hashing")
    first_completed_snapshot = dict(metadata["phase_timings"][0])

    _transition_metadata_phase_timing(metadata, "inspecting_image")
    _transition_metadata_phase_timing(metadata, "discovering_volumes")

    assert metadata["phase_timings"][0] == first_completed_snapshot


# ---------------------------------------------------------------------------
# _update_progress integration: progress_indeterminate flows through, and
# existing non-disk-image behaviour (real percentages, phase_timings) is
# unaffected by this fix.
# ---------------------------------------------------------------------------


def test_update_progress_persists_progress_indeterminate_flag() -> None:
    db = _session()
    db.add(_case())
    evidence = _evidence()
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    _update_progress(
        db,
        evidence,
        phase="materializing_disk_image_files",
        progress_pct=5,
        extra={"progress_indeterminate": True, "current_action": "materializing_disk_image_files"},
    )
    db.refresh(evidence)

    assert evidence.metadata_json["progress_indeterminate"] is True
    assert evidence.metadata_json["current_phase"] == "materializing_disk_image_files"


def test_update_progress_heartbeats_do_not_grow_phase_timings() -> None:
    db = _session()
    db.add(_case())
    evidence = _evidence()
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    for _ in range(30):
        _update_progress(
            db,
            evidence,
            phase="materializing_disk_image_files",
            progress_pct=5,
            extra={"progress_indeterminate": True, "heartbeat_at": utc_now().isoformat()},
        )
        db.refresh(evidence)

    assert len(evidence.metadata_json["phase_timings"]) == 1
    assert evidence.metadata_json["phase_timings"][0]["finished_at"] is None


def test_existing_non_disk_image_progress_still_gets_real_percentage() -> None:
    """Regression guard: archive/velociraptor ingest must still see real,
    moving percentages and phase_timings behaviour untouched by this fix."""
    db = _session()
    db.add(_case())
    evidence = _evidence()
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    _update_progress(db, evidence, phase="extracting", progress_pct=12, phases=["extracting", "parsing"])
    db.refresh(evidence)
    assert evidence.metadata_json["current_phase"] == "extracting"
    assert evidence.metadata_json["progress_pct"] == 12
    assert evidence.metadata_json.get("progress_indeterminate") is None

    _update_progress(db, evidence, phase="parsing", progress_pct=60, phases=["extracting", "parsing"])
    db.refresh(evidence)
    phases_seen = [item["phase"] for item in evidence.metadata_json["phase_timings"]]
    assert phases_seen == ["extracting", "parsing"]
