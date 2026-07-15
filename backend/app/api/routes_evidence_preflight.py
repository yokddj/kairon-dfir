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

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.evidence_upload_session import EvidenceUploadSession
from app.models.user import User
from app.schemas.evidence import EvidenceRead
from app.services.auth_dependencies import get_optional_user
from app.schemas.evidence_preflight import PreflightReport
from app.schemas.evidence_upload_session import (
    EvidenceUploadSessionCreateResponse,
    EvidenceUploadSessionRead,
    PreflightRerunRequest,
    PromoteUploadSessionRequest,
)
from app.services.evidence_upload_session import (
    UploadSessionError,
    cancel_upload_session,
    create_upload_session,
    get_active_session,
    promote_upload_session,
    rerun_preflight,
)
from app.services.ingestion_health import check_ingestion_readiness

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
        raise HTTPException(status_code=status_code, detail=exc.message) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Preflight inspection failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Preflight inspection failed: {exc.__class__.__name__}") from exc

    return EvidenceUploadSessionCreateResponse(session=_session_to_read(session), preflight=report, health=check_ingestion_readiness(db))


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
    return rerun_preflight(session, declared_platform=declared)


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
