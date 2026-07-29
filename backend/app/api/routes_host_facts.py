from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.host_facts import resolve_host_facts

router = APIRouter()


@router.get("/api/cases/{case_id}/host-facts")
def get_case_host_facts(
    case_id: str,
    host_id: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    fact_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    """Resolved Host Facts for one host or one evidence item, generic over fact_type.

    Reusable infrastructure for future consumers (Host Info UI, Timeline,
    Correlation, AI) -- this endpoint does not assume ``host.timezone`` is
    the only fact_type that will ever exist, it just happens to be the
    only one with observations today.

    Exactly one of ``host_id`` or ``evidence_id`` is required: conflict
    resolution only makes sense within a single host's observations, so a
    case-wide "every host at once" mode is deliberately not offered here
    (that grouping belongs to the future Host Info UI, not this endpoint).
    """
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if host_id and evidence_id:
        raise HTTPException(status_code=422, detail="Provide host_id or evidence_id, not both")
    if not host_id and not evidence_id:
        raise HTTPException(status_code=422, detail="host_id or evidence_id is required")
    scope = {"host_id": host_id} if host_id else {"evidence_id": evidence_id}
    facts = resolve_host_facts(db, case_id=case_id, fact_type=fact_type, **scope)
    return {"case_id": case_id, "scope": "host" if host_id else "evidence", **scope, "facts": facts}
