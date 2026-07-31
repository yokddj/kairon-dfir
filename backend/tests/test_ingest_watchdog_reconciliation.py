from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_evidence import pause_evidence_indexing
from app.core.database import Base
from app.models.case import Case, CaseStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.evidence_runs import start_ingest_run, upsert_ingest_run
from app.services.job_watchdog import (
    STALE_INGEST_HEARTBEAT_SECONDS,
    maybe_reconcile_stale_ingest,
    maybe_reconcile_stale_indexing_plan,
    reconcile_stale_indexing_plans,
    reconcile_stale_ingests,
    release_stale_ingest_lock,
)
from app.services.indexing_profiles import evidence_has_active_indexing


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


def test_pause_stops_a_live_job_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=2)  # fresh heartbeat: genuinely running
    stop_calls: list[str] = []
    monkeypatch.setattr(
        "app.api.routes_evidence._find_ingest_job",
        lambda _evidence_id: {"exists": True, "status": "started", "job_id": "job-live-1"},
    )
    monkeypatch.setattr(
        "app.api.routes_evidence.send_stop_job_command",
        lambda _conn, job_id: stop_calls.append(job_id),
    )

    result = pause_evidence_indexing(evidence.id, payload=None, db=db)

    assert stop_calls == ["job-live-1"]
    assert result["stopped_live_job"] is True
    assert result["retry_allowed"] is True
    db.refresh(evidence)
    assert evidence.ingest_status == IngestStatus.failed
    assert evidence.metadata_json.get("current_phase") == "paused"
    assert evidence.metadata_json.get("current_ingest_run_id") is None


def test_pause_cancels_a_queued_job(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=2)
    cancelled: list[str] = []

    class _FakeJob:
        def cancel(self) -> None:
            cancelled.append("cancelled")

    monkeypatch.setattr(
        "app.api.routes_evidence._find_ingest_job",
        lambda _evidence_id: {"exists": True, "status": "queued", "job_id": "job-queued-1"},
    )
    monkeypatch.setattr("app.api.routes_evidence.Job.fetch", lambda *_args, **_kwargs: _FakeJob())

    result = pause_evidence_indexing(evidence.id, payload=None, db=db)

    assert cancelled == ["cancelled"]
    assert result["stopped_live_job"] is False
    db.refresh(evidence)
    assert evidence.metadata_json.get("current_phase") == "paused"


def test_pause_rejects_evidence_that_is_not_actively_indexing() -> None:
    db = _make_db()
    evidence = _make_stuck_evidence(db, heartbeat_age_seconds=2)
    evidence.ingest_status = IngestStatus.completed
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        pause_evidence_indexing(evidence.id, payload=None, db=db)

    assert exc_info.value.status_code == 409


class _FakeRQJob:
    def __init__(self, status: str):
        self._status = status

    def get_status(self, refresh: bool = False):  # noqa: ARG002
        return self._status


def _make_completed_evidence_with_stuck_plan(db, *, plan_job_run_id: str = "rq-job-1", step_id: str = "mft_full") -> Evidence:
    """A core ingest that finished successfully (Evidence.ingest_status ==
    completed, processed_at set -- the "COMPLETED" tile EvidenceDetail
    renders), but whose on-demand indexing-plan run is still marked queued.
    This is the exact shape of the reported bug: 100% progress (implied by
    ingest_status == completed), a completed_at date, and -- because
    evidence_has_active_indexing() checks indexing_plan_run before
    ingest_status -- a badge that still reads "Processing".
    """
    case = Case(id="44444444-4444-4444-a444-444444444444", name="Stuck plan", status=CaseStatus.open)
    completed_at = datetime.now(UTC).replace(microsecond=0, tzinfo=None)
    evidence = Evidence(
        id="55555555-5555-4555-a555-555555555555",
        case_id=case.id,
        original_filename="finished.E01",
        stored_path="/tmp/finished.E01",
        original_path="/tmp/finished.E01",
        evidence_type=EvidenceType.disk_image,
        sha256="fed",
        size_bytes=456,
        file_count=1,
        ingest_status=IngestStatus.completed,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={
            "progress_pct": 100,
            "indexing_plan_run": {
                "run_id": "plan-1",
                "status": "queued",
                "queued_jobs": [{"step_id": step_id, "run_id": plan_job_run_id, "status": "queued"}],
            },
        },
        error_log={},
    )
    evidence.processed_at = completed_at
    db.add(case)
    db.add(evidence)
    db.commit()
    return evidence


def test_maybe_reconcile_stale_indexing_plan_closes_a_job_that_actually_finished(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_completed_evidence_with_stuck_plan(db)
    monkeypatch.setattr("app.services.job_watchdog.ingest_queue.fetch_job", lambda job_id: _FakeRQJob("finished") if job_id == "rq-job-1" else None)

    reconciled = maybe_reconcile_stale_indexing_plan(db, evidence)

    assert reconciled is True
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "completed"
    assert plan_run["queued_jobs"][0]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_maybe_reconcile_stale_indexing_plan_leaves_a_genuinely_running_job_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_completed_evidence_with_stuck_plan(db)
    monkeypatch.setattr("app.services.job_watchdog.ingest_queue.fetch_job", lambda job_id: _FakeRQJob("started") if job_id == "rq-job-1" else None)

    reconciled = maybe_reconcile_stale_indexing_plan(db, evidence)

    assert reconciled is False
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "queued"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is True  # correctly still active -- this is not the bug


def test_maybe_reconcile_stale_indexing_plan_treats_an_expired_rq_job_as_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    evidence = _make_completed_evidence_with_stuck_plan(db)
    monkeypatch.setattr("app.services.job_watchdog.ingest_queue.fetch_job", lambda job_id: None)

    reconciled = maybe_reconcile_stale_indexing_plan(db, evidence)

    assert reconciled is True
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "completed_with_errors"
    assert plan_run["queued_jobs"][0]["status"] == "failed"


def test_reconcile_stale_indexing_plans_sweeps_multiple_evidences(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db()
    stuck = _make_completed_evidence_with_stuck_plan(db)
    fresh_id = "66666666-6666-4666-a666-666666666666"
    fresh = Evidence(
        id=fresh_id,
        case_id=stuck.case_id,
        original_filename="healthy.E01",
        stored_path="/tmp/healthy.E01",
        original_path="/tmp/healthy.E01",
        evidence_type=EvidenceType.disk_image,
        sha256="aaa",
        size_bytes=1,
        file_count=1,
        ingest_status=IngestStatus.completed,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={"indexing_plan_run": {"run_id": "plan-2", "status": "completed", "queued_jobs": []}},
        error_log={},
    )
    db.add(fresh)
    db.commit()
    monkeypatch.setattr("app.services.job_watchdog.ingest_queue.fetch_job", lambda job_id: _FakeRQJob("finished") if job_id == "rq-job-1" else None)

    stats = reconcile_stale_indexing_plans(db)

    assert stats == {"inspected": 1, "reconciled": 1}
    db.refresh(stuck)
    db.refresh(fresh)
    assert stuck.metadata_json["indexing_plan_run"]["status"] == "completed"
    assert fresh.metadata_json["indexing_plan_run"]["status"] == "completed"  # untouched, already terminal


def test_regression_100_percent_completed_at_processing_badge_with_no_active_job(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exact reported repro: progress 100%, completed_at set, core
    ingest_status already completed, but the Evidence Detail "Processing"
    badge (driven by evidence_has_active_indexing) stays active forever
    because an on-demand indexing-plan job never closed. Reconciliation
    must converge it to the correct terminal, non-active state without
    touching completed_at/ingest_status (both already correct) or fabricating
    a new status value.
    """
    db = _make_db()
    evidence = _make_completed_evidence_with_stuck_plan(db)

    # Before reconciliation: reproduces the bug exactly as reported.
    assert evidence.ingest_status == IngestStatus.completed
    assert evidence.processed_at is not None
    assert evidence.metadata_json.get("progress_pct") == 100
    active_before, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active_before is True

    monkeypatch.setattr("app.services.job_watchdog.ingest_queue.fetch_job", lambda job_id: _FakeRQJob("finished") if job_id == "rq-job-1" else None)
    reconciled = maybe_reconcile_stale_indexing_plan(db, evidence)

    assert reconciled is True
    # Terminal fields the badge/date tile already relied on are untouched.
    assert evidence.ingest_status == IngestStatus.completed
    assert evidence.processed_at is not None
    assert evidence.metadata_json.get("progress_pct") == 100
    # The one thing that was actually broken is now coherent.
    active_after, job_after = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active_after is False
    assert job_after is None
