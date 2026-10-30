"""AI report drafts and finding suggestions as background jobs.

A local model can take minutes. Run inside the HTTP request, the work was lost
when the page closed or a proxy cut the connection, and had to start again.
Each request now becomes a CaseAnalysisJob run by the analysis worker; the page
polls its state, and the last result of each kind stays available (per case
for suggestions, per report for drafts) until the next run replaces it.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.finding import Finding
from app.services.ai.report_draft import ReportDraftUnavailable, ai_draft_status, provider_error_text

logger = logging.getLogger(__name__)

FINDING_SUGGESTIONS = "ai_finding_suggestions"
REPORT_DRAFT = "ai_report_draft"
JOB_TIMEOUT_SECONDS = 1800
_ACTIVE = (CaseAnalysisJobStatus.queued, CaseAnalysisJobStatus.running)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _jobs(db: Session, case_id: str, kind: str, report_id: str | None):
    jobs = (
        db.query(CaseAnalysisJob)
        .filter(CaseAnalysisJob.case_id == case_id, CaseAnalysisJob.analysis_type == kind)
        .order_by(CaseAnalysisJob.created_at.desc())
        .limit(50)
        .all()
    )
    return [job for job in jobs if report_id is None or (job.parameters_json or {}).get("report_id") == report_id]


def _stalled(job: CaseAnalysisJob) -> bool:
    """A job the worker never finished (restart, sleep): past its timeout."""
    reference = job.started_at or job.created_at
    return job.status in _ACTIVE and reference is not None and _now() - reference > timedelta(seconds=JOB_TIMEOUT_SECONDS + 60)


def start_ai_job(db: Session, case_id: str, kind: str, *, report_id: str | None = None) -> CaseAnalysisJob:
    """Queue a job, or return the one already queued or running for the same target."""
    if not ai_draft_status(db).get("enabled"):
        raise ReportDraftUnavailable("The AI assistant is not enabled. Configure a provider in AI settings first.")
    for job in _jobs(db, case_id, kind, report_id)[:1]:
        if job.status in _ACTIVE and not _stalled(job):
            return job
    job = CaseAnalysisJob(
        case_id=case_id,
        analysis_type=kind,
        status=CaseAnalysisJobStatus.queued,
        parameters_json={"report_id": report_id} if report_id else {},
        phases=[],
        metrics_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    from app.workers.tasks import enqueue_ai_job

    try:
        job.job_id = enqueue_ai_job(job.id, JOB_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 -- Redis down: say so instead of a job that never runs
        job.status = CaseAnalysisJobStatus.failed
        job.error_message = f"The job could not be queued: {exc}"
        job.finished_at = _now()
    db.commit()
    return job


def latest_ai_job(db: Session, case_id: str, kind: str, *, report_id: str | None = None) -> dict[str, Any] | None:
    jobs = _jobs(db, case_id, kind, report_id)
    return serialize_job(db, jobs[0]) if jobs else None


def serialize_job(db: Session, job: CaseAnalysisJob) -> dict[str, Any]:
    status = job.status.value if hasattr(job.status, "value") else str(job.status)
    error = job.error_message
    if _stalled(job):
        status, error = "failed", "The job did not finish (the worker stopped or the computer slept). Start it again."
    result = job.result_json
    if result and job.analysis_type == FINDING_SUGGESTIONS:
        result = _mark_created(db, job.case_id, result)
    return {
        "id": job.id,
        "kind": job.analysis_type,
        "status": status,
        "created_at": _iso(job.created_at),
        "started_at": _iso(job.started_at),
        "finished_at": _iso(job.finished_at),
        "error": error,
        "result": result,
    }


def _iso(value: datetime | None) -> str | None:
    return value.replace(tzinfo=UTC).isoformat() if value else None


def _mark_created(db: Session, case_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Suggestions already turned into findings say so, so a reload does not offer them twice."""
    created = {
        str(finding.title): finding.id
        for finding in db.query(Finding).filter(Finding.case_id == case_id, Finding.source == "ai_suggestion").all()
    }
    return {
        **result,
        "suggestions": [
            {**item, "created_finding_id": created.get(str(item.get("title")))}
            for item in result.get("suggestions") or []
        ],
    }


def run_ai_job(db: Session, job_id: str) -> None:
    """Worker side: run the job and store its result or error."""
    from app.services.ai.finding_suggestions import suggest_findings
    from app.services.ai.providers import ProviderError
    from app.services.ai.report_draft import draft_report_narrative

    job = db.get(CaseAnalysisJob, job_id)
    if job is None:
        return
    job.status = CaseAnalysisJobStatus.running
    job.started_at = _now()
    db.commit()
    try:
        if job.analysis_type == FINDING_SUGGESTIONS:
            result = suggest_findings(db, job.case_id)
        elif job.analysis_type == REPORT_DRAFT:
            result = draft_report_narrative(db, job.case_id, str((job.parameters_json or {}).get("report_id") or ""))
        else:
            raise ReportDraftUnavailable(f"Unknown AI job type {job.analysis_type}.")
    except (ReportDraftUnavailable, ProviderError) as exc:
        db.rollback()
        job = db.get(CaseAnalysisJob, job_id)
        job.status = CaseAnalysisJobStatus.failed
        job.error_message = provider_error_text(exc) if isinstance(exc, ProviderError) else str(exc)
    except Exception as exc:  # noqa: BLE001 -- the page must see a failure, not a job running forever
        logger.exception("AI job %s failed", job_id)
        db.rollback()
        job = db.get(CaseAnalysisJob, job_id)
        job.status = CaseAnalysisJobStatus.failed
        job.error_message = getattr(exc, "detail", None) or f"The job failed: {exc}"
    else:
        job.status = CaseAnalysisJobStatus.completed
        job.result_json = result
        job.progress_pct = 100
    job.finished_at = _now()
    db.commit()
