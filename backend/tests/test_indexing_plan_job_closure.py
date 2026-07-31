"""Tests for the on-demand indexing-plan job closure fix.

Covers the "stuck Processing" bug: Evidence Detail could show a PROCESSING
badge, 100% progress and a completed_at date at the same time as a live
"Pause indexing" button, because an on-demand step (Full MFT, MFT summary,
User Activity, Defender) never closed its own entry in
metadata_json["indexing_plan_run"] when it finished -- so
evidence_has_active_indexing() (which checks indexing_plan_run before it
ever looks at Evidence.ingest_status) reported "active" forever.

These tests call the real _update_*_metadata helpers from app.workers.tasks
directly, the same functions each on-demand task calls at its own
success/failure sites, to verify the fix at the exact place it was applied.
Each helper opens its own isolated SessionLocal() (by design, so it can run
detached from any caller's session/transaction inside an RQ worker) --
SessionLocal is monkeypatched to the test's in-memory engine so that
isolated session sees the same data.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case, CaseStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.indexing_profiles import evidence_has_active_indexing
from app.workers.tasks import (
    _update_defender_evtx_metadata,
    _update_mft_full_metadata,
    _update_mft_summary_metadata,
    _update_recmd_user_activity_metadata,
)

CASE_ID = "77777777-7777-4777-a777-777777777777"
EVIDENCE_ID = "88888888-8888-4888-a888-888888888888"


@pytest.fixture
def db_session(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    TestSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    # _update_*_metadata each open their own SessionLocal() rather than
    # taking a db param (by design -- they run detached inside an RQ
    # worker), so the module-level name in app.workers.tasks has to be
    # redirected to this test engine for their writes to be visible here.
    monkeypatch.setattr("app.workers.tasks.SessionLocal", TestSessionLocal)
    session = TestSessionLocal()
    yield session
    session.close()


def _make_evidence_with_queued_step(db, *, step_id: str) -> Evidence:
    case = Case(id=CASE_ID, name="On-demand step", status=CaseStatus.open)
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="disk.E01",
        stored_path="/tmp/disk.E01",
        original_path="/tmp/disk.E01",
        evidence_type=EvidenceType.disk_image,
        sha256="abc",
        size_bytes=1,
        file_count=1,
        ingest_status=IngestStatus.completed,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={
            "indexing_plan_run": {
                "run_id": "plan-1",
                "status": "queued",
                "queued_jobs": [{"step_id": step_id, "run_id": "rq-job-1", "status": "queued"}],
            }
        },
        error_log={},
    )
    db.add(case)
    db.add(evidence)
    db.commit()
    return evidence


def test_mft_full_success_closes_the_indexing_plan_job(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="mft_full")

    _update_mft_full_metadata(EVIDENCE_ID, {"run_id": "internal-run-1", "status": "completed", "records_total": 10, "records_indexed": 10})

    db_session.refresh(evidence)
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "completed"
    assert plan_run["queued_jobs"][0]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_mft_full_failure_closes_the_job_but_does_not_report_completed(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="mft_full")

    _update_mft_full_metadata(EVIDENCE_ID, {"run_id": "internal-run-1", "status": "failed", "error": "backend unavailable"})

    db_session.refresh(evidence)
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "completed_with_errors"
    assert plan_run["queued_jobs"][0]["status"] == "failed"
    # Failed must not look like an active job either -- it's terminal, just unhappy.
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_mft_full_running_write_does_not_prematurely_close_the_job(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="mft_full")

    _update_mft_full_metadata(EVIDENCE_ID, {"run_id": "internal-run-1", "status": "running"})

    db_session.refresh(evidence)
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "queued"
    assert plan_run["queued_jobs"][0]["status"] == "queued"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is True


def test_mft_summary_success_closes_the_indexing_plan_job(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="mft_summary")

    _update_mft_summary_metadata(EVIDENCE_ID, {"run_id": "internal-run-2", "status": "completed", "records_total": 5, "records_indexed": 5, "coverage_status": "partial_summary"})

    db_session.refresh(evidence)
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "completed"


def test_mft_summary_with_warnings_still_closes_as_completed_not_active(db_session):
    # A partial-coverage warning is not a terminal failure -- it must not
    # keep the plan (and therefore the badge) looking "Processing".
    evidence = _make_evidence_with_queued_step(db_session, step_id="mft_summary")

    _update_mft_summary_metadata(EVIDENCE_ID, {"run_id": "internal-run-2", "status": "completed", "records_total": 5, "records_indexed": 3, "coverage_status": "partial_summary"})

    db_session.refresh(evidence)
    assert evidence.metadata_json.get("display_status") == "completed_with_warnings"
    plan_run = evidence.metadata_json["indexing_plan_run"]
    assert plan_run["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_recmd_user_activity_success_closes_the_indexing_plan_job(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="user_activity")

    _update_recmd_user_activity_metadata(EVIDENCE_ID, {"run_id": "internal-run-3", "status": "completed", "records_indexed": 4})

    db_session.refresh(evidence)
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_recmd_user_activity_zero_records_indexed_still_completes_not_active(db_session):
    # "skipped empty" (no matching RECmd artifacts) is a legitimate
    # completion, not a stuck run.
    evidence = _make_evidence_with_queued_step(db_session, step_id="user_activity")

    _update_recmd_user_activity_metadata(EVIDENCE_ID, {"run_id": "internal-run-3", "status": "completed", "records_indexed": 0})

    db_session.refresh(evidence)
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_defender_evtx_success_closes_the_indexing_plan_job(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="defender")

    _update_defender_evtx_metadata(EVIDENCE_ID, {"run_id": "internal-run-4", "status": "completed", "docs_indexed": 2})

    db_session.refresh(evidence)
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False


def test_defender_evtx_no_data_still_completes_not_active(db_session):
    evidence = _make_evidence_with_queued_step(db_session, step_id="defender")

    _update_defender_evtx_metadata(EVIDENCE_ID, {"run_id": "internal-run-4", "status": "completed", "docs_indexed": 0, "no_data": True})

    db_session.refresh(evidence)
    assert evidence.metadata_json["indexing_plan_run"]["status"] == "completed"
    active, _job = evidence_has_active_indexing(evidence.metadata_json, evidence.ingest_status)
    assert active is False
