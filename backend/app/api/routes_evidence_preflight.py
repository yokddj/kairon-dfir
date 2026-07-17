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

from app.core.database import get_db
from app.models.evidence_upload_session import EvidenceUploadSession
from app.models.user import User
from app.schemas.evidence import EvidenceRead
from app.services.auth_dependencies import get_optional_user
from app.schemas.evidence_preflight import PreflightReport
from app.schemas.evidence_upload_session import (
    EvidenceUploadSessionCreateResponse,
    EvidenceUploadSessionStageResponse,
    EvidenceUploadSessionRead,
    PreflightRerunRequest,
    PromoteUploadSessionRequest,
)
from app.services.evidence_upload_session import (
    UploadSessionError,
    cancel_upload_session,
    create_streamed_upload_session,
    create_upload_session,
    get_active_session,
    promote_upload_session,
    rerun_preflight,
)
from app.services.ingestion_health import check_ingestion_readiness
from app.services.memory.upload_sessions import MemoryUploadSessionError

router = APIRouter(prefix="/api/cases", tags=["evidence-preflight"])
logger = logging.getLogger(__name__)


def _session_to_read(session: EvidenceUploadSession) -> EvidenceUploadSessionRead:
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
    )


@router.get("/{case_id}/ingestion-readiness")
def ingestion_readiness(case_id: str, db: Session = Depends(get_db)) -> dict:
    return check_ingestion_readiness(db)


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

    return EvidenceUploadSessionCreateResponse(session=_session_to_read(session), preflight=report, health=check_ingestion_readiness(db))


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

    return EvidenceUploadSessionStageResponse(session=_session_to_read(session), health=check_ingestion_readiness(db))


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
        )
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
    except Exception as exc:  # noqa: BLE001
        logger.exception("Promoting upload session %s failed for case %s", session_id, case_id)
        raise HTTPException(status_code=500, detail=f"Could not start processing: {exc.__class__.__name__}") from exc
    return evidence


@router.delete("/{case_id}/evidence-uploads/{session_id}")
def cancel_evidence_upload(case_id: str, session_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        session = get_active_session(db, case_id, session_id)
    except UploadSessionError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    cancel_upload_session(db, session)
    return {"status": "cancelled", "session_id": session_id}
