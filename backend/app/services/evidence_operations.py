from __future__ import annotations

import logging
import shutil
from datetime import timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now
from app.models.evidence_operation import EvidenceOperation, EvidenceOperationJob
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus

logger = logging.getLogger(__name__)


TERMINAL_UPLOAD_STATUSES = {"cancelled", "expired", "promoted", "failed"}
TERMINAL_OPERATION_STATUSES = {"completed", "failed", "cancelled", "expired"}
ACTIVE_JOB_STATUSES = {"queued", "running"}

ALLOWED_OPERATION_TRANSITIONS: dict[str, set[str]] = {
    "created": {"waiting_upload", "uploading", "cancelled", "failed"},
    "waiting_upload": {"uploading", "paused", "cancelled", "expired", "failed"},
    "uploading": {"paused", "finalizing", "cancelled", "expired", "failed"},
    "paused": {"uploading", "finalizing", "cancelled", "expired", "failed"},
    "finalizing": {"verifying", "preflight", "ready_for_promotion", "failed"},
    "verifying": {"preflight", "ready_for_promotion", "failed"},
    "preflight": {"ready_for_promotion", "waiting_user", "failed"},
    "ready_for_promotion": {"waiting_user", "promoting", "cancelled", "failed"},
    "waiting_user": {"promoting", "cancelled", "failed"},
    "promoting": {"queued", "running", "completed", "failed"},
    "queued": {"running", "completed", "failed", "cancelled"},
    "running": {"completed", "failed", "cancelled"},
    "failed": {"queued", "running", "finalizing", "preflight", "promoting", "cancelled"},
    "cancelled": set(),
    "expired": set(),
    "completed": set(),
}


def _operation_status(session_status: str) -> str:
    if session_status == "created":
        return "waiting_upload"
    if session_status == "uploading":
        return "uploading"
    if session_status == "preflight_running":
        return "preflight"
    if session_status == "staged":
        return "waiting_user"
    if session_status == "promoted":
        return "completed"
    if session_status in {"cancelled", "expired"}:
        return session_status
    if session_status in {"failed"}:
        return "failed"
    if session_status == "interrupted":
        return "paused"
    return "running"


def transition_operation(operation: EvidenceOperation, status: str, *, stage: str | None = None, owner: str | None = None, error: str | None = None, force: bool = False) -> None:
    current = operation.status or "created"
    if current == status:
        pass
    elif not force and status not in ALLOWED_OPERATION_TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid evidence operation transition: {current} -> {status}")
    operation.status = status
    if stage is not None:
        operation.stage = stage
    if owner is not None:
        operation.owner = owner
    operation.last_error = error
    if status in TERMINAL_OPERATION_STATUSES and operation.completed_at is None:
        operation.completed_at = utc_now()
    if status not in TERMINAL_OPERATION_STATUSES:
        operation.completed_at = None


def _operation_stage(session: EvidenceUploadSession) -> str:
    return str((session.metadata_json or {}).get("current_stage") or session.status)


def _operation_progress(session: EvidenceUploadSession) -> int | None:
    expected = int(session.expected_size_bytes or session.size_bytes or 0)
    received = int(session.bytes_received or session.size_bytes or 0)
    if expected > 0:
        return max(0, min(100, round((received / expected) * 100)))
    if session.status in {"staged", "promoted"}:
        return 100
    return None


def _metadata(session: EvidenceUploadSession) -> dict[str, Any]:
    return {
        "upload_session_id": session.id,
        "label": session.original_filename,
        "category": (session.metadata_json or {}).get("category"),
        "sha256": session.sha256,
        "promoted_evidence_id": session.promoted_evidence_id,
        "failure_message": session.failure_message,
        "is_server_path": session.is_server_path,
        "is_folder": session.is_folder,
        "original_filename": session.original_filename,
        "declared_platform": session.declared_platform,
        "backend": (session.metadata_json or {}).get("backend") or "legacy",
        "unified_status": (session.metadata_json or {}).get("unified_status"),
    }


def _uuid_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        UUID(str(value))
    except ValueError:
        return None
    return str(value)


def _is_before_now(value: Any, now: Any) -> bool:
    if value is None:
        return False
    try:
        return value < now
    except TypeError:
        # Naive/aware mix -- SQLite (tests) hands back naive datetimes for
        # DateTime(timezone=True) columns even though the values it stored
        # were UTC-aware (Postgres, production, preserves tzinfo and never
        # reaches this branch). Treat a naive value as UTC, matching this
        # codebase's own utc_now_naive() convention -- NOT as local time,
        # which .timestamp() on a naive datetime would otherwise assume,
        # silently corrupting the comparison by the local UTC offset.
        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)
        if getattr(now, "tzinfo", None) is None:
            now = now.replace(tzinfo=timezone.utc)
        return value < now


def sync_upload_operation(db: Session, session: EvidenceUploadSession, *, commit: bool = True) -> EvidenceOperation:
    operation = (
        db.query(EvidenceOperation)
        .filter(EvidenceOperation.upload_session_id == session.id, EvidenceOperation.kind == "upload")
        .one_or_none()
    )
    now = utc_now()
    if operation is None:
        operation = EvidenceOperation(
            case_id=session.case_id,
            upload_session_id=session.id,
            kind="upload",
            started_at=session.created_at or now,
        )
    operation.case_id = session.case_id
    promoted_evidence_id = _uuid_or_none(session.promoted_evidence_id)
    if promoted_evidence_id is not None and db.get(Evidence, promoted_evidence_id) is None:
        # The promoted Evidence row can be deleted after promotion (operator
        # cleanup, re-upload, etc.); evidence_operations.evidence_id has an FK
        # to evidences, so writing a dangling id here would abort every future
        # reconciliation pass and any request that reads this operation.
        promoted_evidence_id = None
    operation.evidence_id = promoted_evidence_id
    next_status = _operation_status(session.status)
    next_owner = "browser" if session.status in {"created", "uploading", "interrupted"} else "backend" if session.status in {"preflight_running", "staged"} else "database"
    transition_operation(operation, next_status, stage=_operation_stage(session), owner=next_owner, error=session.failure_message, force=True)
    operation.progress = _operation_progress(session)
    operation.bytes_received = int(session.bytes_received or session.size_bytes or 0)
    operation.expected_size_bytes = int(session.expected_size_bytes or session.size_bytes or 0) or None
    operation.metadata_json = _metadata(session)
    db.add(operation)
    if commit:
        db.commit()
        db.refresh(operation)
    return operation


def get_upload_operation(db: Session, session: EvidenceUploadSession) -> EvidenceOperation:
    return sync_upload_operation(db, session, commit=False)


def upsert_operation_job(
    db: Session,
    operation: EvidenceOperation,
    *,
    job_type: str,
    dedupe_key: str | None = None,
    status: str = "queued",
    owner: str = "worker",
    rq_job_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    commit: bool = True,
) -> EvidenceOperationJob:
    key = dedupe_key or job_type
    job = (
        db.query(EvidenceOperationJob)
        .filter(
            EvidenceOperationJob.operation_id == operation.id,
            EvidenceOperationJob.job_type == job_type,
            EvidenceOperationJob.dedupe_key == key,
        )
        .one_or_none()
    )
    if job is None:
        job = EvidenceOperationJob(
            operation_id=operation.id,
            case_id=operation.case_id,
            evidence_id=operation.evidence_id,
            upload_session_id=operation.upload_session_id,
            job_type=job_type,
            dedupe_key=key,
        )
    job.status = status
    job.owner = owner
    if rq_job_id:
        job.rq_job_id = rq_job_id
    job.metadata_json = {**(job.metadata_json or {}), **(metadata or {})}
    db.add(job)
    if commit:
        db.commit()
        db.refresh(job)
    return job


def mark_operation_job_running(db: Session, job: EvidenceOperationJob) -> EvidenceOperationJob:
    job.status = "running"
    job.started_at = job.started_at or utc_now()
    job.finished_at = None
    job.last_error = None
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def mark_operation_job_finished(db: Session, job: EvidenceOperationJob, *, status: str, error: str | None = None, progress: int | None = None) -> EvidenceOperationJob:
    job.status = status
    job.finished_at = utc_now()
    job.last_error = error
    if progress is not None:
        job.progress = progress
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def active_job_for_operation(db: Session, operation: EvidenceOperation, job_type: str) -> EvidenceOperationJob | None:
    return (
        db.query(EvidenceOperationJob)
        .filter(
            EvidenceOperationJob.operation_id == operation.id,
            EvidenceOperationJob.job_type == job_type,
            EvidenceOperationJob.status.in_(ACTIVE_JOB_STATUSES),
        )
        .order_by(EvidenceOperationJob.created_at.desc())
        .first()
    )


def reconcile_evidence_operations(db: Session, *, retention_seconds: int = 7 * 24 * 3600) -> dict[str, int]:
    now = utc_now()
    stats = {"sessions_without_operations": 0, "operations_without_sessions": 0, "operations_synced_from_evidence": 0, "expired_uploads": 0, "orphan_upload_dirs": 0, "removed_empty_dirs": 0}
    sessions = db.query(EvidenceUploadSession).limit(500).all()
    session_ids = {session.id for session in sessions}
    for session in sessions:
        before = db.query(EvidenceOperation).filter(EvidenceOperation.upload_session_id == session.id).one_or_none()
        if before is None:
            stats["sessions_without_operations"] += 1
        if (
            (session.metadata_json or {}).get("backend") != "unified"
            and session.status in {EvidenceUploadSessionStatus.created.value, EvidenceUploadSessionStatus.uploading.value, EvidenceUploadSessionStatus.interrupted.value, EvidenceUploadSessionStatus.staged.value}
            and _is_before_now(session.expires_at, now)
        ):
            # This is the ONLY expiry-driven cleanup path for legacy
            # (non-unified) EvidenceUploadSession rows -- covers every
            # non-terminal status (created/uploading/interrupted/staged),
            # not just `staged`. Without this call, abandoned sessions'
            # staged bytes would never be deleted (observed on production:
            # several GB of staging directories for sessions with no live
            # DB-tracked reason to keep them). Deferred import to avoid a
            # circular import with app.services.evidence_upload_session,
            # which already imports sync_upload_operation from this module.
            from app.services.evidence_upload_session import _cleanup_storage

            _cleanup_storage(session)
            session.status = EvidenceUploadSessionStatus.expired.value
            session.failure_message = "Upload session expired during reconciliation."
            stats["expired_uploads"] += 1
        sync_upload_operation(db, session, commit=False)
    for operation in db.query(EvidenceOperation).filter(EvidenceOperation.upload_session_id.isnot(None)).limit(500).all():
        if operation.upload_session_id not in session_ids and operation.status not in TERMINAL_OPERATION_STATUSES:
            transition_operation(operation, "failed", stage="session_missing", owner="reconciler", error="Upload session is missing for active operation.", force=True)
            db.add(operation)
            stats["operations_without_sessions"] += 1
    for operation in db.query(EvidenceOperation).filter(EvidenceOperation.evidence_id.isnot(None), EvidenceOperation.status.in_(["queued", "running"])).limit(500).all():
        evidence = db.get(Evidence, operation.evidence_id)
        if evidence is None:
            continue
        ingest_status = str(getattr(evidence.ingest_status, "value", evidence.ingest_status) or "")
        if ingest_status in {"completed", "completed_with_warnings"}:
            transition_operation(operation, "completed", stage="processing_complete", owner="database", force=True)
            db.add(operation)
            stats["operations_synced_from_evidence"] += 1
        elif ingest_status == "failed":
            transition_operation(operation, "failed", stage="processing_failed", owner="database", error="Evidence processing failed.", force=True)
            db.add(operation)
            stats["operations_synced_from_evidence"] += 1
    root = get_settings().backend_temp_dir / "evidence-upload-sessions"
    if root.exists():
        for child in root.iterdir():
            if not child.is_dir() or child.name in session_ids:
                continue
            stats["orphan_upload_dirs"] += 1
            try:
                age = now.timestamp() - child.stat().st_mtime
                if age > retention_seconds and not any(child.iterdir()):
                    shutil.rmtree(child, ignore_errors=True)
                    stats["removed_empty_dirs"] += 1
                else:
                    logger.warning("orphan evidence upload directory retained path=%s age_seconds=%s", child, round(age))
            except OSError as exc:
                logger.warning("orphan evidence upload directory scan failed path=%s error=%s", child, exc)
    db.commit()
    logger.info("evidence operation reconciliation: %s", stats)
    return stats
