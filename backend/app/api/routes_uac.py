from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.evidence import Evidence
from app.services import uac_bodyfile

router = APIRouter(tags=["uac"])


def _evidence(db: Session, case_id: str, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.get("/api/cases/{case_id}/evidences/{evidence_id}/uac/bodyfile/summary")
def get_bodyfile_summary(case_id: str, evidence_id: str, db: Session = Depends(get_db)) -> dict:
    return uac_bodyfile.summarize(_evidence(db, case_id, evidence_id))


@router.get("/api/cases/{case_id}/evidences/{evidence_id}/uac/bodyfile")
def search_bodyfile(
    case_id: str,
    evidence_id: str,
    path_contains: str = Query(..., min_length=2, max_length=512),
    sort: str = Query(default="mtime", pattern="^(atime|mtime|ctime|crtime)$"),
    limit: int = Query(default=200, ge=1, le=uac_bodyfile.MAX_RESULTS),
    db: Session = Depends(get_db),
) -> dict:
    """Files of a UAC collection's bodyfile whose path contains ``path_contains``, newest first by ``sort``."""
    return uac_bodyfile.search(_evidence(db, case_id, evidence_id), path_contains=path_contains, sort=sort, limit=limit)
