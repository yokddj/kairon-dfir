from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.host_users import resolve_host_users

router = APIRouter()


@router.get("/api/cases/{case_id}/host-users")
def get_case_host_users(
    case_id: str,
    host_id: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    """Host User Inventory for one host or one evidence item: one entry per
    local account, correlated from passwd/shadow/lastlog/group observations.

    Same scope contract as /host-facts -- exactly one of host_id or
    evidence_id is required, and results are never merged across hosts.
    """
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if host_id and evidence_id:
        raise HTTPException(status_code=422, detail="Provide host_id or evidence_id, not both")
    if not host_id and not evidence_id:
        raise HTTPException(status_code=422, detail="host_id or evidence_id is required")
    scope = {"host_id": host_id} if host_id else {"evidence_id": evidence_id}
    users = resolve_host_users(db, case_id=case_id, **scope)
    return {"case_id": case_id, "scope": "host" if host_id else "evidence", **scope, "users": users}
