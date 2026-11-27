from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.ingest.macos.fsevents import CHANGE_KINDS
from app.models.evidence import Evidence
from app.services import macos_fsevents

router = APIRouter(tags=["macos"])


def _evidence(db: Session, case_id: str, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.get("/api/cases/{case_id}/evidences/{evidence_id}/macos/fsevents/summary")
def get_fsevents_summary(case_id: str, evidence_id: str, db: Session = Depends(get_db)) -> dict:
    """Which volumes of this evidence have an FSEvents journal, and how many page files each."""
    return macos_fsevents.summarize(_evidence(db, case_id, evidence_id))


@router.get("/api/cases/{case_id}/evidences/{evidence_id}/macos/fsevents")
def search_fsevents(
    case_id: str,
    evidence_id: str,
    path_contains: str = Query(..., min_length=2, max_length=512),
    changes: list[str] = Query(default=[]),
    item_type: str | None = Query(default=None, pattern="^(file|folder)$"),
    limit: int = Query(default=200, ge=1, le=macos_fsevents.MAX_RESULTS),
    db: Session = Depends(get_db),
) -> dict:
    """FSEvents records whose path contains ``path_contains`` (case-insensitive), newest first.

    Read on demand from the evidence's .fseventsd pages; nothing is indexed. ``changes`` keeps
    records with any of the given change kinds.
    """
    unknown = [change for change in changes if change not in CHANGE_KINDS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown change kinds: {', '.join(unknown)}")
    return macos_fsevents.search(_evidence(db, case_id, evidence_id), path_contains=path_contains, changes=changes, item_type=item_type, limit=limit)
