from __future__ import annotations

import re
import shutil
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.core.database import get_db
from app.models.evidence import Evidence
from app.services.audit import log_audit
from app.services.disk_file_explorer import DiskFileExplorerError, export_files, find_files, list_directory, list_volumes

router = APIRouter()


class DiskFileExportItem(BaseModel):
    path: str
    inode: int | None = None
    parent_inode: int | None = None


class DiskFileExportRequest(BaseModel):
    items: list[DiskFileExportItem] = Field(default_factory=list, max_length=1000)
    include_deleted: bool = False


def _evidence(db: Session, case_id: str, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found in this case.")
    return evidence


def _raise(exc: DiskFileExplorerError) -> None:
    raise HTTPException(status_code=exc.status_code, detail={"error_code": exc.code, "message": exc.message}) from exc


_BASE = "/api/cases/{case_id}/evidences/{evidence_id}/files"


@router.get(f"{_BASE}/volumes")
def get_disk_file_volumes(case_id: str, evidence_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    evidence = _evidence(db, case_id, evidence_id)
    try:
        return list_volumes(db, evidence)
    except DiskFileExplorerError as exc:
        _raise(exc)


@router.get(f"{_BASE}/volumes/{{volume_id}}/list")
def get_disk_file_directory(
    case_id: str,
    evidence_id: str,
    volume_id: str,
    path: str | None = Query(default=None),
    inode: int | None = Query(default=None, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    evidence = _evidence(db, case_id, evidence_id)
    try:
        return list_directory(db, evidence, volume_id, path=path, inode=inode)
    except DiskFileExplorerError as exc:
        _raise(exc)


@router.get(f"{_BASE}/volumes/{{volume_id}}/find")
def find_disk_files(
    case_id: str,
    evidence_id: str,
    volume_id: str,
    q: str = Query(min_length=1, max_length=256),
    path: str | None = Query(default=None),
    include_deleted: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    evidence = _evidence(db, case_id, evidence_id)
    try:
        return find_files(db, evidence, volume_id, pattern=q, path=path, include_deleted=include_deleted)
    except DiskFileExplorerError as exc:
        _raise(exc)


def _download_name(evidence: Evidence, items: list[DiskFileExportItem]) -> str:
    stem = items[0].path.rstrip("/").rsplit("/", 1)[-1] if len(items) == 1 else f"{len(items)}-items"
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "export"
    return f"kairon-{evidence.id[:8]}-{stem[:80]}.zip"


@router.post(f"{_BASE}/volumes/{{volume_id}}/export")
def export_disk_files(
    case_id: str,
    evidence_id: str,
    volume_id: str,
    payload: DiskFileExportRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> FileResponse:
    evidence = _evidence(db, case_id, evidence_id)
    user = getattr(request.state, "user", None)
    items = [item.model_dump() for item in payload.items]
    try:
        archive, summary = export_files(db, evidence, volume_id, items=items, include_deleted=payload.include_deleted)
    except DiskFileExplorerError as exc:
        log_audit("disk_files_export", actor_user_id=getattr(user, "id", None), case_id=case_id, resource_type="evidence", resource_id=evidence_id,
                  result="failure", metadata={"volume_id": volume_id, "items": items[:100], "error": exc.code})
        _raise(exc)
    files = summary["files"]
    log_audit("disk_files_export", actor_user_id=getattr(user, "id", None), case_id=case_id, resource_type="evidence", resource_id=evidence_id,
              metadata={
                  "volume_id": volume_id,
                  "include_deleted": payload.include_deleted,
                  "files": [{key: item.get(key) for key in ("path", "inode", "result", "size", "sha256")} for item in files[:500]],
                  "file_count": len(files),
                  "truncated": summary["truncated"],
              })
    return FileResponse(
        archive,
        media_type="application/zip",
        filename=_download_name(evidence, payload.items),
        headers={"X-Content-Type-Options": "nosniff", "Access-Control-Expose-Headers": "Content-Disposition, X-Kairon-Export-Summary",
                 "X-Kairon-Export-Summary": f"{sum(1 for item in files if item.get('result') in {'exported', 'recovered'})}/{len(files)}"},
        background=BackgroundTask(shutil.rmtree, archive.parent, True),
    )
