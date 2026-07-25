from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case, CaseStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.evidence_runs import start_ingest_run, upsert_ingest_run
from app.services.job_watchdog import (
    STALE_INGEST_HEARTBEAT_SECONDS,
    maybe_reconcile_stale_ingest,
    reconcile_stale_ingests,
    release_stale_ingest_lock,
)


def _make_db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _make_stuck_evidence(db, *, heartbeat_age_seconds: int, events_indexed: int = 0) -> Evidence:
    case = Case(id="11111111-1111-4111-a111-111111111111", name="Stuck ingest", status=CaseStatus.open)
    heartbeat_ts = (datetime.now(UTC) - timedelta(seconds=heartbeat_age_seconds)).replace(microsecond=0).isoformat()
    evidence = Evidence(
        id="22222222-2222-4222-a222-222222222222",
        case_id=case.id,
        original_filename="stuck.vmdk",
        stored_path="/tmp/stuck.vmdk",
        original_path="/tmp/stuck.vmdk",
        evidence_type=EvidenceType.disk_image,
        sha256="abc",
        size_bytes=123,
        file_count=2,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run({}, run_id="ingest-stuck-1", run_type="ingest", mode="full_rediscovery", status="running")
    metadata = upsert_ingest_run(
        metadata,
        "ingest-stuck-1",
        {"status": "processing", "phase": "parsing", "heartbeat_at": heartbeat_ts},
    )
    metadata["current_ingest_run_id"] = "ingest-stuck-1"
    metadata["heartbeat_at"] = heartbeat_ts
    metadata["current_phase"] = "parsing"
    metadata["progress_pct"] = 35
    metadata["events_indexed"] = events_indexed
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.commit()
    return evidence


def test_release_stale_ingest_lock_marks_failed_when_no_events_indexed(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=STALE_INGEST_HEARTBEAT_SECONDS + 60, events_indexed=0)

    release_stale_ingest_lock(evidence, reason="test reason")
    db.commit()
    db.refresh(evidence)

    assert evidence.ingest_status == IngestStatus.failed
    assert evidence.metadata_json.get("current_ingest_run_id") is None
    assert evidence.metadata_json.get("stale_recovery", {}).get("reason") == "test reason"


def test_release_stale_ingest_lock_marks_completed_with_errors_when_events_indexed(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=STALE_INGEST_HEARTBEAT_SECONDS + 60, events_indexed=70119)

    release_stale_ingest_lock(evidence, reason="test reason")
    db.commit()
    db.refresh(evidence)

    assert evidence.ingest_status == IngestStatus.completed_with_errors
    assert evidence.metadata_json.get("current_ingest_run_id") is None


def test_maybe_reconcile_stale_ingest_releases_when_heartbeat_stale_and_no_live_job(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=STALE_INGEST_HEARTBEAT_SECONDS + 60)
    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})

    reconciled = maybe_reconcile_stale_ingest(db, evidence)

    assert reconciled is True
    assert evidence.ingest_status == IngestStatus.failed


def test_maybe_reconcile_stale_ingest_leaves_fresh_heartbeat_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=5)
    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})

    reconciled = maybe_reconcile_stale_ingest(db, evidence)

    assert reconciled is False
    assert evidence.ingest_status == IngestStatus.processing


def test_maybe_reconcile_stale_ingest_leaves_alive_job_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=STALE_INGEST_HEARTBEAT_SECONDS + 60)
    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": True, "status": "started", "job_id": "job-1"})

    reconciled = maybe_reconcile_stale_ingest(db, evidence)

    assert reconciled is False
    assert evidence.ingest_status == IngestStatus.processing


def test_reconcile_stale_ingests_sweeps_multiple_evidences(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    stuck = _make_stuck_evidence(db, heartbeat_age_seconds=STALE_INGEST_HEARTBEAT_SECONDS + 60)
    fresh = Evidence(
        id="33333333-3333-4333-a333-333333333333",
        case_id=stuck.case_id,
        original_filename="fresh.vmdk",
        stored_path="/tmp/fresh.vmdk",
        original_path="/tmp/fresh.vmdk",
        evidence_type=EvidenceType.disk_image,
        sha256="def",
        size_bytes=1,
        file_count=1,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={"heartbeat_at": datetime.now(UTC).replace(microsecond=0).isoformat()},
        error_log={},
    )
    db.add(fresh)
    db.commit()
    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})

    stats = reconcile_stale_ingests(db)

    assert stats == {"inspected": 1, "reconciled": 1}
    db.refresh(stuck)
    db.refresh(fresh)
    assert stuck.ingest_status == IngestStatus.failed
    assert fresh.ingest_status == IngestStatus.processing
