"""AI drafts and suggestions run as background jobs: one active job per
target, the latest result kept, failures and stalled jobs reported."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.finding import Finding
from app.services.ai import jobs
from app.services.ai.providers import ProviderError

CASE = "6f1d2c3e-0000-4000-8000-000000000001"


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Case(id=CASE, name="Sample"))
    session.commit()
    monkeypatch.setattr(jobs, "ai_draft_status", lambda _db: {"enabled": True})
    queued = []
    monkeypatch.setattr("app.workers.tasks.enqueue_ai_job", lambda job_id, _timeout: queued.append(job_id) or f"rq-{job_id}")
    session.queued = queued
    yield session
    session.close()


def test_one_active_job_per_target_and_the_worker_stores_the_result(db, monkeypatch) -> None:
    first = jobs.start_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)
    again = jobs.start_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)
    draft = jobs.start_ai_job(db, CASE, jobs.REPORT_DRAFT, report_id="report-1")
    assert again.id == first.id and draft.id != first.id and len(db.queued) == 2
    assert first.job_id == f"rq-{first.id}"
    result = {"suggestions": [{"title": "Tool run"}, {"title": "Other"}], "dropped": 0}
    monkeypatch.setattr("app.services.ai.finding_suggestions.suggest_findings", lambda _db, _case: result)
    jobs.run_ai_job(db, first.id)
    db.add(Finding(case_id=CASE, title="Tool run", source="ai_suggestion"))
    db.commit()
    latest = jobs.latest_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)
    assert latest["status"] == "completed" and latest["finished_at"]
    # A suggestion already accepted says so after a reload.
    created = [item.get("created_finding_id") for item in latest["result"]["suggestions"]]
    assert created[0] and created[1] is None
    # Drafts are kept per report.
    assert jobs.latest_ai_job(db, CASE, jobs.REPORT_DRAFT, report_id="report-1")["status"] == "queued"
    assert jobs.latest_ai_job(db, CASE, jobs.REPORT_DRAFT, report_id="report-2") is None


def test_provider_errors_and_stalled_jobs_are_reported(db, monkeypatch) -> None:
    job = jobs.start_ai_job(db, CASE, jobs.REPORT_DRAFT, report_id="report-1")

    def fail(*_args):
        raise ProviderError("Provider returned HTTP 502. <html><body>Bad gateway</body></html>")

    monkeypatch.setattr("app.services.ai.report_draft.draft_report_narrative", fail)
    jobs.run_ai_job(db, job.id)
    latest = jobs.latest_ai_job(db, CASE, jobs.REPORT_DRAFT, report_id="report-1")
    assert latest["status"] == "failed" and "Bad gateway" in latest["error"] and "<" not in latest["error"]

    stalled = jobs.start_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)
    row = db.get(CaseAnalysisJob, stalled.id)
    row.status = CaseAnalysisJobStatus.running
    row.started_at = jobs._now() - timedelta(seconds=jobs.JOB_TIMEOUT_SECONDS + 120)
    db.commit()
    assert jobs.latest_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)["status"] == "failed"
    # A stalled job does not block a new one.
    assert jobs.start_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS).id != stalled.id


def test_no_job_is_queued_when_ai_is_off(db, monkeypatch) -> None:
    monkeypatch.setattr(jobs, "ai_draft_status", lambda _db: {"enabled": False})
    with pytest.raises(jobs.ReportDraftUnavailable):
        jobs.start_ai_job(db, CASE, jobs.FINDING_SUGGESTIONS)
    assert db.queued == []


def test_aware_timestamps_from_postgres_are_compared_in_utc() -> None:
    from datetime import UTC, datetime, timedelta, timezone

    job = CaseAnalysisJob(case_id=CASE, analysis_type=jobs.FINDING_SUGGESTIONS, status=CaseAnalysisJobStatus.running)
    job.started_at = datetime.now(timezone(timedelta(hours=2))) - timedelta(minutes=5)
    job.created_at = datetime.now(UTC)
    assert jobs._stalled(job) is False
    job.started_at = datetime.now(UTC) - timedelta(seconds=jobs.JOB_TIMEOUT_SECONDS + 120)
    assert jobs._stalled(job) is True
    assert jobs._iso(datetime(2026, 1, 10, 11, 0, tzinfo=timezone(timedelta(hours=2)))) == "2026-01-10T09:00:00+00:00"
