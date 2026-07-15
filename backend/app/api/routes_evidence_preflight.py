"""Preflight Inspection endpoint for the Unified Evidence Ingestion wizard.

This router is intentionally separate from routes_evidence.py: it never
creates an Evidence row, never calls enqueue_ingest, and never writes to
the database. Its only job is to stage an upload (or point at an existing
server path / folder) into a disposable temp directory, run the read-only
app.services.evidence_preflight.run_preflight() inspection, and clean up.

The wizard's actual "Start Processing" step calls the existing, unchanged
upload endpoints in routes_evidence.py (upload_evidence / upload_disk_image /
upload_evidence_folder) with the same file — this router does not duplicate
or replace that logic.
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.evidence_paths import validate_external_path
from app.core.storage import ensure_within_directory, sanitize_relative_path
from app.models.case import Case
from app.schemas.evidence_preflight import PreflightReport
from app.services.evidence_preflight import run_preflight

router = APIRouter(prefix="/api/cases", tags=["evidence-preflight"])
logger = logging.getLogger(__name__)


def _stage_single_file(upload: UploadFile, tmp_dir: Path) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(upload.filename or "upload.bin").name
    target = tmp_dir / filename
    with target.open("wb") as buffer:
        while chunk := upload.file.read(1024 * 1024):
            buffer.write(chunk)
    return target


def _stage_folder(files: list[UploadFile], tmp_dir: Path) -> Path:
    root = tmp_dir / "folder"
    root.mkdir(parents=True, exist_ok=True)
    for upload in files:
        relative = sanitize_relative_path(upload.filename or "file.bin")
        target = root / relative
        ensure_within_directory(root, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as buffer:
            while chunk := upload.file.read(1024 * 1024):
                buffer.write(chunk)
    return root


@router.post("/{case_id}/evidence-preflight", response_model=PreflightReport)
def preflight_evidence(
    case_id: str,
    files: list[UploadFile] | None = File(None),
    folder_upload: bool = Form(False),
    server_path: str | None = Form(None),
    declared_platform: str | None = Form(None),
    db: Session = Depends(get_db),
) -> PreflightReport:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if not files and not server_path:
        raise HTTPException(status_code=400, detail="No file, folder, or server path was provided for preflight inspection.")

    settings = get_settings()
    token = str(uuid4())
    tmp_dir = settings.backend_temp_dir / "preflight" / token
    declared = declared_platform if declared_platform and declared_platform != "auto" else None

    try:
        if server_path:
            validation = validate_external_path(server_path)
            if not validation.get("valid"):
                raise HTTPException(
                    status_code=400,
                    detail=validation.get("message") or "The server path could not be validated for ingestion.",
                )
            target_path = Path(str(validation["resolved_path"]))
            original_filename = target_path.name
            report = run_preflight(
                target_path,
                token=token,
                original_filename=original_filename,
                declared_platform=declared,
                tmp_dir=tmp_dir,
            )
        elif folder_upload and files and len(files) > 1:
            staged_root = _stage_folder(files, tmp_dir)
            report = run_preflight(
                staged_root,
                token=token,
                original_filename=f"{len(files)} files",
                declared_platform=declared,
                tmp_dir=tmp_dir,
            )
        else:
            assert files is not None
            staged_path = _stage_single_file(files[0], tmp_dir)
            report = run_preflight(
                staged_path,
                token=token,
                original_filename=files[0].filename or staged_path.name,
                declared_platform=declared,
                tmp_dir=tmp_dir,
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Preflight inspection failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Preflight inspection failed: {exc.__class__.__name__}") from exc
    finally:
        # tmp_dir may hold staged upload bytes (file/folder branches) and/or
        # scratch files run_preflight wrote for itself (disk image workspace,
        # hostname/os-release peek extraction) - always clean it up. The
        # server_path branch never stages the source file itself here, but
        # run_preflight may still have used tmp_dir as scratch space.
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return report
