from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.host_information_repair import rebuild_host_information
from app.services.host_users import resolve_host_users, resolve_unverified_host_profiles

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


@router.get("/api/cases/{case_id}/host-users/unverified-profiles")
def get_case_host_unverified_profiles(
    case_id: str,
    host_id: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    """ProfileList SIDs observed on this host with no matching local SAM
    account -- most often a domain account's cached profile from an
    interactive logon. Deliberately separate from /host-users: that
    endpoint's contract is "verified local accounts only", so an
    unverified SID never appears there, synthetic or otherwise. This
    endpoint exists for exactly the case where an analyst needs to know
    who else has touched the host without SAM corroboration.
    """
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if host_id and evidence_id:
        raise HTTPException(status_code=422, detail="Provide host_id or evidence_id, not both")
    if not host_id and not evidence_id:
        raise HTTPException(status_code=422, detail="host_id or evidence_id is required")
    scope = {"host_id": host_id} if host_id else {"evidence_id": evidence_id}
    profiles = resolve_unverified_host_profiles(db, case_id=case_id, **scope)
    return {"case_id": case_id, "scope": "host" if host_id else "evidence", **scope, "profiles": profiles}


@router.post("/api/cases/{case_id}/host-information/rebuild")
def rebuild_case_host_information(
    case_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Re-derive Host Facts and Host User Facts from the events already indexed.

    For a case ingested before these layers were harvested on every ingest path,
    this recovers them without re-ingesting the evidence.
    """
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return rebuild_host_information(db, case_id)
