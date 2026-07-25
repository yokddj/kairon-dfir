"""Preflight Inspection + Temporary Upload Session endpoints for the
Unified Evidence Ingestion wizard.

Two concerns live here, both DB-write-free until the analyst explicitly
confirms:

- Server Health Check (Step 0): a read-only readiness probe.
- Upload sessions: stage a file/folder/server-path ONCE, run Preflight
  Inspection against the staged copy (possibly more than once), and only
  promote it into a real Evidence when the analyst confirms Start
  Processing - see app.services.evidence_upload_session for how promotion
  reuses the already-staged bytes without a second network transfer.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.timing import timed_phase
from app.models.evidence_operation import EvidenceOperation, EvidenceOperationJob
from app.models.evidence_upload_session import EvidenceUploadSession
from app.models.user import User
from app.schemas.evidence import EvidenceRead
from app.services.auth_dependencies import get_optional_user, require_case_access
from app.schemas.evidence_preflight import PreflightReport
from app.schemas.evidence_upload_session import (
    ActivityCenterResponse,
    EvidenceUploadSessionCreateResponse,
    EvidenceUploadSessionAppendResponse,
    EvidenceUploadSessionFinalizeResponse,
    EvidenceUploadSessionInitRequest,
    EvidenceUploadSessionStageResponse,
    EvidenceUploadSessionRead,
    PreflightRerunRequest,
    PromoteUploadSessionRequest,
    ResumableUploadSessionRead,
    ResumableUploadSessionsResponse,
    UnifiedResumeDetails,
    UnifiedUploadInfo,
)
from app.services.evidence_upload_session import (
    UploadSessionError,
    append_resumable_upload_chunk_stream,
    cancel_upload_session,
    create_resumable_upload_session,
    create_streamed_upload_session,
    create_upload_session,
    get_active_session,
    get_upload_session,
    finalize_resumable_upload_session,
    list_resumable_upload_sessions,
    promote_upload_session,
    rerun_preflight,
)
from app.services.evidence_operations import PREFLIGHT_SUBSTAGES, derive_operation_stage, get_operation_for_session, get_operation_stage, reconcile_evidence_operations, sync_upload_operation, transition_operation
from app.services.evidence_unified_upload import (
    UNIFIED_UPLOAD_KINDS,
    cancel_unified_session,
    create_unified_upload_session,
    is_unified_session,
    sync_unified_session,
    unified_resume_info,
    unified_upload_info,
)
from app.services.processing_queue import list_case_processing
from app.services.ingestion_health import check_ingestion_readiness
from app.services.memory.upload_sessions import MemoryUploadSessionError

router = APIRouter(prefix="/api/cases", tags=["evidence-preflight"])
logger = logging.getLogger(__name__)


def _sync_session(db: Session, session: EvidenceUploadSession, *, commit: bool = True) -> EvidenceUploadSession:
    """Refresh session state, routing to the unified projection when needed.

    Every route that previously called sync_upload_operation(db, session)
    directly now goes through here so a unified session's status/progress
    always comes from its backing MemoryUpload, never from stale
    EvidenceUploadSession columns that nothing else writes for it.
    """
    if is_unified_session(session):
        return sync_unified_session(db, session)
    sync_upload_operation(db, session, commit=commit)
    return session


def _session_to_read(db: Session, session: EvidenceUploadSession) -> EvidenceUploadSessionRead:
    # Legacy sessions: current_stage is derived read-only from the
    # associated EvidenceOperation.stage (the canonical persisted source --
    # see app.services.evidence_operations), never stored a second time on
    # the session itself. Unified sessions are untouched by this sprint --
    # they still read their own pre-existing metadata_json.current_stage,
    # populated by app.services.evidence_unified_upload, a separate code
    # path this change does not touch.
    current_stage = (session.metadata_json or {}).get("current_stage") if is_unified_session(session) else get_operation_stage(db, session)
    return EvidenceUploadSessionRead(
        id=session.id,
        case_id=session.case_id,
        status=session.status,
        original_filename=session.original_filename,
        is_folder=session.is_folder,
        is_server_path=session.is_server_path,
        size_bytes=session.size_bytes,
        sha256=session.sha256,
        client_sha256=session.client_sha256,
        client_sha256_mismatch=bool((session.metadata_json or {}).get("client_sha256_mismatch")),
        declared_platform=session.declared_platform,
        expires_at=session.expires_at,
        created_at=session.created_at,
        updated_at=session.updated_at,
        expected_size_bytes=session.expected_size_bytes,
        bytes_received=session.bytes_received,
        last_activity_at=session.last_activity_at,
        failure_message=session.failure_message,
        promoted_evidence_id=session.promoted_evidence_id,
        category=(session.metadata_json or {}).get("category"),
        backend=(session.metadata_json or {}).get("backend") or "legacy",
        current_stage=current_stage,
    )


def _http_from_upload_error(exc: UploadSessionError) -> HTTPException:
    status_code = 404 if exc.code in {"case_not_found", "session_not_found"} else 409 if exc.code in {"offset_mismatch", "session_not_uploading", "session_busy", "session_lock_unavailable"} else 400
    return HTTPException(status_code=status_code, detail=exc.details or {"error_code": exc.code, "code": exc.code, "message": exc.message})


@router.get("/{case_id}/ingestion-readiness")
def ingestion_readiness(case_id: str, db: Session = Depends(get_db)) -> dict:
    return check_ingestion_readiness(db)


@router.get("/{case_id}/activity", response_model=ActivityCenterResponse)
def case_activity_center(case_id: str, db: Session = Depends(get_db)) -> ActivityCenterResponse:
    from collections import Counter
    from datetime import datetime, timezone

    operations: list[dict] = []
    now = datetime.now(timezone.utc)
    reconcile_evidence_operations(db)
    sessions = db.query(EvidenceUploadSession).filter(EvidenceUploadSession.case_id == case_id).order_by(EvidenceUploadSession.updated_at.desc()).limit(50).all()
    for session in sessions:
        if is_unified_session(session):
            sync_unified_session(db, session)
        else:
            sync_upload_operation(db, session, commit=False)
    db.commit()
    persisted = db.query(EvidenceOperation).filter(EvidenceOperation.case_id == case_id).order_by(EvidenceOperation.updated_at.desc()).limit(50).all()
    for operation in persisted:
        details = dict(operation.metadata_json or {})
        jobs = db.query(EvidenceOperationJob).filter(EvidenceOperationJob.operation_id == operation.id).order_by(EvidenceOperationJob.updated_at.desc()).all()
        details["operation_id"] = operation.id
        details["evidence_id"] = operation.evidence_id
        details["jobs"] = [
            {
                "id": job.id,
                "job_type": job.job_type,
                "status": job.status,
                "progress": job.progress,
                "owner": job.owner,
                "rq_job_id": job.rq_job_id,
                "started_at": job.started_at,
                "updated_at": job.updated_at,
                "finished_at": job.finished_at,
                "last_error": job.last_error,
                "retry_count": job.retry_count,
            }
            for job in jobs
        ]
        category = "Uploads"
        if operation.status == "paused":
            category = "Paused uploads"
        elif operation.status == "completed":
            category = "Completed"
        elif operation.status in {"failed", "cancelled", "expired"}:
            category = "Failed"
        elif operation.stage in {"preflight_running", "preflight_complete", "staged", *PREFLIGHT_SUBSTAGES}:
            # PREFLIGHT_SUBSTAGES covers the fine-grained checkpoints finalize
            # now writes directly onto operation.stage (verifying_integrity,
            # classifying, inspecting_evidence, preparing_evidence) -- without
            # this, an operation mid-finalize would fall through to the
            # default "Uploads" bucket the moment its stage moved past the
            # old coarse "preflight_running" label.
            category = "Processing"
        started = operation.started_at or operation.created_at
        elapsed = (now - started).total_seconds() if started and getattr(started, "tzinfo", None) else None
        operations.append({
            "id": operation.id,
            "case_id": case_id,
            "kind": operation.kind,
            "category": category,
            "status": operation.status,
            "stage": operation.stage,
            "label": str(details.get("label") or details.get("original_filename") or operation.id),
            "progress": operation.progress,
            "bytes_received": operation.bytes_received,
            "expected_size_bytes": operation.expected_size_bytes,
            "current_owner": operation.owner,
            "created_at": operation.created_at,
            "updated_at": operation.updated_at,
            "last_activity_at": operation.updated_at,
            "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
            "details": details,
        })
    processing = list_case_processing(db, case_id)
    for item in processing.get("items", []):
        status = str(item.get("processing_status") or "unknown")
        operations.append({
            "id": str(item.get("evidence_id")),
            "case_id": case_id,
            "kind": "processing",
            "category": "Completed" if status.startswith("completed") else "Failed" if status == "failed" else "Processing" if status in {"queued", "running", "pending"} else "Indexing",
            "status": status,
            "stage": str(item.get("last_run_status") or status),
            "label": str(item.get("filename") or item.get("evidence_id")),
            "progress": 100 if status.startswith("completed") else None,
            "bytes_received": None,
            "expected_size_bytes": None,
            "current_owner": "worker" if status in {"queued", "running", "pending"} else "database",
            "created_at": item.get("uploaded_at"),
            "updated_at": item.get("last_run_finished_at") or item.get("last_run_started_at") or item.get("uploaded_at"),
            "last_activity_at": item.get("last_run_finished_at") or item.get("last_run_started_at") or item.get("uploaded_at"),
            "elapsed_seconds": item.get("duration"),
            "details": {"host": item.get("host"), "artifact_count": item.get("artifact_count"), "links": item.get("links")},
        })
    counts = Counter(str(item["category"]) for item in operations)
    return ActivityCenterResponse(case_id=case_id, summary=dict(counts), operations=operations)


@router.post("/{case_id}/evidence-operations/{operation_id}/retry")
def retry_evidence_operation(case_id: str, operation_id: str, db: Session = Depends(get_db)) -> dict:
    from app.services.evidence_operations import transition_operation, upsert_operation_job
    from app.workers.tasks import enqueue_evidence_upload_preflight

    operation = db.get(EvidenceOperation, operation_id)
    if operation is None or operation.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence operation not found")
    if operation.upload_session_id and operation.stage in {"queued_preflight", "finalizing_upload", "preflight_failed", "upload", "uploading"}:
        transition_operation(operation, "finalizing", stage="queued_preflight", owner="worker", force=True)
        job = upsert_operation_job(db, operation, job_type="preflight", dedupe_key=operation.upload_session_id, status="queued", commit=False)
        job.retry_count += 1
        db.add(operation)
        db.add(job)
        db.commit()
        job.rq_job_id = enqueue_evidence_upload_preflight(operation.upload_session_id)
        db.add(job)
        db.commit()
        return {"status": "queued", "operation_id": operation.id, "job_type": "preflight", "job_id": job.rq_job_id}
    raise HTTPException(status_code=409, detail="This operation cannot be retried automatically yet.")


@router.post("/{case_id}/evidence-operations/{operation_id}/dismiss")
def dismiss_evidence_operation(case_id: str, operation_id: str, db: Session = Depends(get_db)) -> dict:
    operation = db.get(EvidenceOperation, operation_id)
    if operation is None or operation.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence operation not found")
    if operation.status not in {"completed", "cancelled", "expired"}:
        raise HTTPException(status_code=409, detail="Only completed terminal operations can be dismissed.")
    operation.metadata_json = {**(operation.metadata_json or {}), "dismissed": True}
    db.add(operation)
    db.commit()
    return {"status": "dismissed", "operation_id": operation.id}


def _resumable_entry(session: EvidenceUploadSession, db: Session) -> ResumableUploadSessionRead:
    metadata = session.metadata_json or {}
    unified = is_unified_session(session)
    # See _session_to_read: legacy sessions derive current_stage from
    # EvidenceOperation.stage read-only; unified sessions are untouched.
    current_stage = metadata.get("current_stage") if unified else get_operation_stage(db, session)
    expected = session.expected_size_bytes or 0
    progress_percent = round((session.bytes_received / expected) * 100, 2) if expected else None
    resumable = session.status in {"created", "uploading", "interrupted"} or (session.status == "failed" and unified)
    cancellable = session.status not in {"cancelled", "expired", "promoted", "failed"}

    unified_details: UnifiedResumeDetails | None = None
    if unified:
        info = unified_resume_info(session, db)
        if info is not None:
            unified_details = UnifiedResumeDetails(
                memory_upload_id=info.memory_upload_id,
                chunk_size_bytes=info.chunk_size_bytes,
                total_chunks=info.total_chunks,
                received_chunks=info.received_chunks,
                missing_chunks=info.missing_chunks,
                default_concurrency=info.default_concurrency,
                max_concurrency=info.max_concurrency,
                expected_sha256=info.expected_sha256,
                verification_chunk_index=info.verification_chunk_index,
                verification_chunk_size=info.verification_chunk_size,
                verification_chunk_sha256=info.verification_chunk_sha256,
            )

    return ResumableUploadSessionRead(
        id=session.id,
        case_id=session.case_id,
        backend="unified" if unified else "legacy",
        category=metadata.get("category"),
        original_filename=session.original_filename,
        expected_size_bytes=session.expected_size_bytes,
        bytes_received=session.bytes_received,
        progress_percent=progress_percent,
        status=session.status,
        current_stage=current_stage,
        created_at=session.created_at,
        updated_at=session.updated_at,
        expires_at=session.expires_at,
        resumable=resumable,
        cancellable=cancellable,
        promoted_evidence_id=session.promoted_evidence_id,
        failure_message=session.failure_message,
        unified=unified_details,
    )


@router.get("/{case_id}/evidence-uploads", response_model=ResumableUploadSessionsResponse)
def list_resumable_evidence_uploads(
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> ResumableUploadSessionsResponse:
    """Case-scoped discovery of upload sessions worth surfacing for resume.

    This is the entry point that lets a browser close/reload without the
    upload becoming invisible: the Wizard and the case Evidence page both
    call this on open instead of requiring a resume_session URL parameter.
    """
    require_case_access(case_id)(request, db)
    sessions = list_resumable_upload_sessions(db, case_id=case_id)
    return ResumableUploadSessionsResponse(case_id=case_id, sessions=[_resumable_entry(session, db) for session in sessions])


@router.post("/{case_id}/evidence-uploads/resumable", response_model=EvidenceUploadSessionStageResponse)
def init_resumable_evidence_upload(
    case_id: str,
    payload: EvidenceUploadSessionInitRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
) -> EvidenceUploadSessionStageResponse:
    declared = payload.declared_platform if payload.declared_platform and payload.declared_platform != "auto" else None
    kind_config = UNIFIED_UPLOAD_KINDS.get(payload.intake_category or "")
    if kind_config is not None and kind_config.is_enabled(get_settings()):
        try:
            session, info = create_unified_upload_session(
                db,
                case_id,
                kind=payload.intake_category,
                workflow=kind_config.workflow,
                evidence_type=kind_config.evidence_type,
                filename=payload.filename,
                expected_size_bytes=payload.expected_size_bytes,
                declared_platform=declared,
                client_sha256=payload.client_sha256,
                host_id=payload.host_id,
                provided_host=payload.provided_host,
                authorization_acknowledged=payload.memory_authorization_acknowledged,
                notes=payload.notes,
                current_user=current_user,
                evidence_intent=payload.evidence_intent,
                ingest_mode=payload.ingest_mode,
                evtx_profile=payload.evtx_profile,
            )
        except UploadSessionError as exc:
            raise _http_from_upload_error(exc) from exc
        except MemoryUploadSessionError as exc:
            detail = {"error_code": exc.code, "code": exc.code, "message": exc.message, **(exc.detail or {})}
            status_code = 409 if exc.code in {"MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS", "MEMORY_UPLOAD_CASE_QUOTA_EXCEEDED"} else 413 if exc.code == "MEMORY_UPLOAD_TOO_LARGE" else 400
            raise HTTPException(status_code=status_code, detail=detail) from exc
        return EvidenceUploadSessionStageResponse(session=_session_to_read(db, session), health=check_ingestion_readiness(db), unified=UnifiedUploadInfo(**vars(info)))
    try:
        session = create_resumable_upload_session(db, case_id, filename=payload.filename, expected_size_bytes=payload.expected_size_bytes, declared_platform=declared, client_sha256=payload.client_sha256)
    except UploadSessionError as exc:
        raise _http_from_upload_error(exc) from exc
    return EvidenceUploadSessionStageResponse(session=_session_to_read(db, session), health=check_ingestion_readiness(db))


@router.get("/{case_id}/evidence-uploads/{session_id}", response_model=EvidenceUploadSessionStageResponse)
def get_evidence_upload(case_id: str, session_id: str, db: Session = Depends(get_db)) -> EvidenceUploadSessionStageResponse:
    try:
        session = get_upload_session(db, case_id, session_id)
    except UploadSessionError as exc:
        raise _http_from_upload_error(exc) from exc
    session = _sync_session(db, session)
    info = unified_upload_info(session, db) if is_unified_session(session) else None
    return EvidenceUploadSessionStageResponse(session=_session_to_read(db, session), health=None, unified=UnifiedUploadInfo(**vars(info)) if info else None)


@router.put("/{case_id}/evidence-uploads/{session_id}/bytes", response_model=EvidenceUploadSessionAppendResponse)
async def append_resumable_evidence_upload(case_id: str, session_id: str, request: Request, offset: int = Query(..., ge=0), db: Session = Depends(get_db)) -> EvidenceUploadSessionAppendResponse:
    try:
        session = get_upload_session(db, case_id, session_id)
        session = await append_resumable_upload_chunk_stream(db, session, offset=offset, chunks=request.stream())
        if session.expected_size_bytes is not None and int(session.bytes_received or 0) >= int(session.expected_size_bytes):
            from app.services.evidence_operations import get_upload_operation, transition_operation, upsert_operation_job
            from app.workers.tasks import enqueue_evidence_upload_preflight

            operation = get_upload_operation(db, session)
            transition_operation(operation, "finalizing", stage="queued_preflight", owner="worker", force=True)
            job = upsert_operation_job(db, operation, job_type="preflight", dedupe_key=session.id, status="queued", commit=False)
            db.add(operation)
            db.commit()
            job_id = enqueue_evidence_upload_preflight(session.id)
            job.rq_job_id = job_id
            db.add(job)
            db.commit()
    except UploadSessionError as exc:
        raise _http_from_upload_error(exc) from exc
    return EvidenceUploadSessionAppendResponse(session=_session_to_read(db, session), offset=int(session.bytes_received or 0))


@router.post("/{case_id}/evidence-uploads/{session_id}/finalize", response_model=EvidenceUploadSessionFinalizeResponse)
def finalize_resumable_evidence_upload(case_id: str, session_id: str, db: Session = Depends(get_db)) -> EvidenceUploadSessionFinalizeResponse:
    with timed_phase("finalize.http_request", case_id=case_id, session_id=session_id):
        try:
            with timed_phase("finalize.get_upload_session", session_id=session_id):
                session = get_upload_session(db, case_id, session_id)
            session, report = finalize_resumable_upload_session(db, session)
        except UploadSessionError as exc:
            raise _http_from_upload_error(exc) from exc
        except Exception as exc:
            # Mirrors the background retry worker's own failure handling
            # (app.workers.tasks.run_evidence_upload_preflight): the
            # operation -- not session.status, deliberately left untouched
            # here to match that existing convention -- transitions to
            # "failed", so nothing can keep presenting this as an active
            # operation (UI activeness is governed by status, never by the
            # stage string alone). Unlike the worker's own hardcoded
            # "preflight_failed" label, this preserves whatever real
            # checkpoint (verifying_integrity/classifying/inspecting_evidence/
            # preparing_evidence) was last reached, via the same
            # derive_operation_stage derivation sync_upload_operation already
            # uses -- useful forensic detail on *where* it broke, not just
            # that it broke. Progress checkpoints are observational only
            # and must never make finalize's actual result partially
            # successful; only this outcome commit does.
            operation = get_operation_for_session(db, session)
            if operation is not None:
                transition_operation(operation, "failed", stage=derive_operation_stage(session, operation.stage), owner="backend", error=f"{exc.__class__.__name__}: {exc}", force=True)
                db.add(operation)
                db.commit()
            raise
        with timed_phase("finalize.build_response", session_id=session_id):
            response = EvidenceUploadSessionFinalizeResponse(session=_session_to_read(db, session), preflight=report, health=check_ingestion_readiness(db))
    return response


@router.post("/{case_id}/evidence-uploads", response_model=EvidenceUploadSessionCreateResponse)
def create_evidence_upload(
    case_id: str,
    files: list[UploadFile] | None = File(None),
    folder_upload: bool = Form(False),
    server_path: str | None = Form(None),
    declared_platform: str | None = Form(None),
    client_sha256: str | None = Form(None),
    db: Session = Depends(get_db),
) -> EvidenceUploadSessionCreateResponse:
    declared = declared_platform if declared_platform and declared_platform != "auto" else None
    try:
        session, report = create_upload_session(
            db,
            case_id,
            files=files,
            is_folder=folder_upload,
            server_path=server_path,
            declared_platform=declared,
            client_sha256=client_sha256,
        )
    except UploadSessionError as exc:
        status_code = 404 if exc.code == "case_not_found" else 400
        raise HTTPException(status_code=status_code, detail=exc.details or {"error_code": exc.code, "code": exc.code, "message": exc.message}) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Preflight inspection failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Preflight inspection failed: {exc.__class__.__name__}") from exc

    return EvidenceUploadSessionCreateResponse(session=_session_to_read(db, session), preflight=report, health=check_ingestion_readiness(db))


@router.post("/{case_id}/evidence-uploads/stream", response_model=EvidenceUploadSessionStageResponse)
async def create_evidence_upload_stream(
    case_id: str,
    request: Request,
    filename: str = Query(..., min_length=1),
    declared_platform: str | None = Query(None),
    client_sha256: str | None = Query(None),
    x_kairon_file_size: int | None = Header(None, alias="X-Kairon-File-Size"),
    db: Session = Depends(get_db),
) -> EvidenceUploadSessionStageResponse:
    declared = declared_platform if declared_platform and declared_platform != "auto" else None
    content_length = request.headers.get("content-length")
    expected_bytes = x_kairon_file_size
    if expected_bytes is None and content_length and content_length.isdigit():
        expected_bytes = int(content_length)
    try:
        session = await create_streamed_upload_session(
            db,
            case_id,
            request=request,
            filename=filename,
            expected_bytes=expected_bytes,
            declared_platform=declared,
            client_sha256=client_sha256,
        )
    except UploadSessionError as exc:
        status_code = 404 if exc.code == "case_not_found" else 413 if exc.code in {"upload_size_limit", "insufficient_storage"} else 408 if exc.code == "upload_idle_timeout" else 499 if exc.code == "client_disconnected" else 400
        raise HTTPException(status_code=status_code, detail=exc.details or {"error_code": exc.code, "code": exc.code, "message": exc.message}) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Streaming evidence upload failed for case %s", case_id)
        raise HTTPException(status_code=500, detail={"error_code": "staging_failed", "code": "staging_failed", "message": f"Upload staging failed: {exc.__class__.__name__}"}) from exc

    return EvidenceUploadSessionStageResponse(session=_session_to_read(db, session), health=check_ingestion_readiness(db))


@router.post("/{case_id}/evidence-uploads/{session_id}/preflight", response_model=PreflightReport)
def rerun_evidence_upload_preflight(
    case_id: str,
    session_id: str,
    payload: PreflightRerunRequest,
    db: Session = Depends(get_db),
) -> PreflightReport:
    try:
        session = get_active_session(db, case_id, session_id)
    except UploadSessionError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    declared = payload.declared_platform if payload.declared_platform and payload.declared_platform != "auto" else None
    report = rerun_preflight(session, declared_platform=declared)
    session.metadata_json = {**(session.metadata_json or {}), "category": report.classification.category}
    db.add(session)
    db.commit()
    sync_upload_operation(db, session)
    return report


@router.post("/{case_id}/evidence-uploads/{session_id}/promote", response_model=EvidenceRead)
def promote_evidence_upload(
    case_id: str,
    session_id: str,
    payload: PromoteUploadSessionRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    try:
        session = get_active_session(db, case_id, session_id)
    except UploadSessionError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc

    declared = payload.provided_platform if payload.provided_platform and payload.provided_platform != "auto" else None
    try:
        from app.services.evidence_operations import get_upload_operation, mark_operation_job_finished, mark_operation_job_running, transition_operation, upsert_operation_job

        operation = get_upload_operation(db, session)
        transition_operation(operation, "promoting", stage="promoting", owner="backend", force=True)
        promotion_job = upsert_operation_job(db, operation, job_type="promotion", dedupe_key=session.id, status="queued", commit=False)
        db.add(operation)
        db.commit()
        mark_operation_job_running(db, promotion_job)
        evidence = promote_upload_session(
            db,
            session,
            provided_platform=declared,
            host_id=payload.host_id,
            provided_host=payload.provided_host,
            evtx_profile=payload.evtx_profile,
            memory_authorization_acknowledged=payload.memory_authorization_acknowledged,
            folder_name=payload.folder_name,
            labels=payload.labels,
            notes=payload.notes,
            current_user=current_user,
            evidence_intent=payload.evidence_intent,
            ingest_mode=payload.ingest_mode,
        )
        operation = get_upload_operation(db, session)
        transition_operation(operation, "queued", stage="processing_queued", owner="worker", force=True)
        upsert_operation_job(db, operation, job_type="promotion", dedupe_key=session.id, status="completed", metadata={"evidence_id": evidence.id}, commit=False)
        db.add(operation)
        db.commit()
        mark_operation_job_finished(db, promotion_job, status="completed", progress=100)
    except HTTPException:
        raise
    except MemoryUploadSessionError as exc:
        if exc.code in {"MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS", "MEMORY_EVIDENCE_DUPLICATE"}:
            status_code = 409
        elif exc.code == "MEMORY_UPLOAD_TOO_LARGE":
            status_code = 413
        else:
            status_code = 400
        detail = {"error_code": exc.code, "code": exc.code, "message": exc.message, **(exc.detail or {})}
        raise HTTPException(status_code=status_code, detail=detail) from exc
    except UploadSessionError as exc:
        if 'promotion_job' in locals():
            mark_operation_job_finished(db, promotion_job, status="failed", error=exc.message)
        detail = {"error_code": exc.code, "code": exc.code, "message": exc.message}
        raise HTTPException(status_code=400, detail=detail) from exc
    except Exception as exc:  # noqa: BLE001
        if 'promotion_job' in locals():
            mark_operation_job_finished(db, promotion_job, status="failed", error=str(exc))
        logger.exception("Promoting upload session %s failed for case %s", session_id, case_id)
        raise HTTPException(status_code=500, detail=f"Could not start processing: {exc.__class__.__name__}") from exc
    return evidence


@router.delete("/{case_id}/evidence-uploads/{session_id}")
def cancel_evidence_upload(case_id: str, session_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        session = get_upload_session(db, case_id, session_id)
    except UploadSessionError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    if is_unified_session(session):
        cancel_unified_session(db, session)
    else:
        cancel_upload_session(db, session)
    return {"status": "cancelled", "session_id": session_id}
