"""Evidence-scoped API for VMware companion files (.vmsn / .vmss).

See ``app.services.memory.companion_files`` for the materialization logic
and ``app.models.evidence.EvidenceCompanionFile`` for the data model and
the rationale behind "at most one active companion per evidence."
"""
from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.storage import evidence_staging_dir, safe_remove
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceCompanionFile, EvidenceType
from app.schemas.evidence import EvidenceCompanionRead
from app.services.auth_dependencies import require_case_access
from app.services.memory.companion_files import (
    EvidenceCompanionError,
    StagedCompanionUpload,
    attach_vmware_companion,
    delete_evidence_companion,
    list_evidence_companions,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["evidence-companions"])
settings = get_settings()

_COMPANION_ERROR_STATUS: dict[str, int] = {
    "EVIDENCE_NOT_MEMORY_DUMP": 400,
    "PRIMARY_NOT_VMEM": 400,
    "UNSUPPORTED_COMPANION_TYPE": 400,
    "COMPANION_MATCHES_PRIMARY": 400,
    "COMPANION_UPLOAD_REJECTED": 400,
    "COMPANION_UPLOAD_TOO_LARGE": 413,
    "COMPANION_UPLOAD_NOT_FOUND": 400,
    "INSUFFICIENT_STORAGE": 507,
    "REFUSED_PRIMARY_OVERWRITE": 400,
    "COMPANION_PERMISSION_FAILED": 500,
    "COMPANION_NOT_FOUND": 404,
    "UNSAFE_COMPANION_PATH": 400,
    "REFUSED_PRIMARY_DELETE": 400,
    "COMPANION_DELETE_FAILED": 500,
    "EVIDENCE_FILE_NOT_FOUND": 409,
    "UNSAFE_EVIDENCE_PATH": 409,
    "UNSAFE_EVIDENCE_FILE": 409,
    "EVIDENCE_PATH_MISSING": 409,
}


def _require_case(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _require_memory_evidence(db: Session, case_id: str, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id or evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=404, detail="Memory evidence was not found for this case.")
    return evidence


def _raise_companion_error(exc: EvidenceCompanionError) -> None:
    status_code = _COMPANION_ERROR_STATUS.get(exc.code, 400)
    raise HTTPException(status_code=status_code, detail={"error_code": exc.code, "message": exc.message}) from exc


@router.get(
    "/cases/{case_id}/evidences/{evidence_id}/companions",
    response_model=list[EvidenceCompanionRead],
)
def list_companions(
    case_id: str,
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> list[EvidenceCompanionFile]:
    require_case_access(case_id)(request, db)
    _require_case(db, case_id)
    _require_memory_evidence(db, case_id, evidence_id)
    return list_evidence_companions(db, evidence_id)


@router.post(
    "/cases/{case_id}/evidences/{evidence_id}/companions/vmware",
    response_model=EvidenceCompanionRead,
    status_code=status.HTTP_201_CREATED,
)
def upload_vmware_companion(
    case_id: str,
    evidence_id: str,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> EvidenceCompanionFile:
    user = require_case_access(case_id)(request, db)
    _require_case(db, case_id)
    evidence = _require_memory_evidence(db, case_id, evidence_id)

    original_filename = file.filename or "companion"
    if Path(original_filename).suffix.lower() not in (".vmsn", ".vmss"):
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "UNSUPPORTED_COMPANION_TYPE",
                "message": "Only .vmsn and .vmss files are accepted as VMware companions.",
            },
        )

    staging_dir = evidence_staging_dir(case_id, evidence_id)
    staged_path = staging_dir / f".{uuid4().hex}.vmware-companion.upload"
    max_bytes = int(settings.memory_upload_max_bytes or settings.memory_max_upload_size or 1)
    size = 0
    row: EvidenceCompanionFile
    try:
        with staged_path.open("xb") as buffer:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise EvidenceCompanionError(
                        "COMPANION_UPLOAD_TOO_LARGE",
                        "Uploaded companion exceeds the configured evidence upload size limit.",
                    )
                buffer.write(chunk)
        if size <= 0:
            raise EvidenceCompanionError("COMPANION_UPLOAD_REJECTED", "Uploaded companion is empty.")
        row = attach_vmware_companion(
            db,
            evidence,
            StagedCompanionUpload(path=staged_path, original_filename=original_filename),
            actor_user_id=user.id,
        )
    except EvidenceCompanionError as exc:
        _raise_companion_error(exc)
        raise  # pragma: no cover - _raise_companion_error always raises
    finally:
        safe_remove(staged_path)
    return row


@router.delete(
    "/cases/{case_id}/evidences/{evidence_id}/companions/{companion_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_companion(
    case_id: str,
    evidence_id: str,
    companion_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    user = require_case_access(case_id)(request, db)
    _require_case(db, case_id)
    evidence = _require_memory_evidence(db, case_id, evidence_id)
    try:
        delete_evidence_companion(db, evidence, companion_id, actor_user_id=user.id)
    except EvidenceCompanionError as exc:
        _raise_companion_error(exc)
