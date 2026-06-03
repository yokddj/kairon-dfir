from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.host_identity import build_case_host_candidates, get_case_hosts, get_host_identity_audit, merge_hosts, rename_canonical_host, split_alias


router = APIRouter(prefix="/api/cases/{case_id}/hosts", tags=["hosts"])


class MergeHostsRequest(BaseModel):
    canonical_host_id: str
    aliases: list[str] = Field(default_factory=list)
    reason: str | None = None
    analyst: str | None = None


class AddAliasesRequest(BaseModel):
    aliases: list[str] = Field(default_factory=list)
    reason: str | None = None
    analyst: str | None = None


class RenameHostRequest(BaseModel):
    canonical_name: str | None = None
    display_name: str | None = None
    reason: str | None = None
    analyst: str | None = None


class SplitAliasRequest(BaseModel):
    reason: str | None = None
    analyst: str | None = None


def _ensure_case(db: Session, case_id: str) -> None:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")


@router.get("")
def list_case_hosts(case_id: str, db: Session = Depends(get_db)) -> dict:
    _ensure_case(db, case_id)
    return {
        "case_id": case_id,
        "hosts": get_case_hosts(db, case_id),
        "host_candidates": build_case_host_candidates(db, case_id),
    }


@router.post("/merge")
def merge_case_hosts(case_id: str, payload: MergeHostsRequest, db: Session = Depends(get_db)) -> dict:
    _ensure_case(db, case_id)
    try:
        host = merge_hosts(
            db,
            case_id,
            canonical_host_id=payload.canonical_host_id,
            aliases=payload.aliases,
            reason=payload.reason,
            analyst=payload.analyst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"case_id": case_id, "host": host}


@router.post("/{host_id}/aliases", status_code=status.HTTP_200_OK)
def add_host_aliases(case_id: str, host_id: str, payload: AddAliasesRequest, db: Session = Depends(get_db)) -> dict:
    _ensure_case(db, case_id)
    try:
        host = merge_hosts(
            db,
            case_id,
            canonical_host_id=host_id,
            aliases=payload.aliases,
            reason=payload.reason,
            analyst=payload.analyst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"case_id": case_id, "host": host}


@router.delete("/{host_id}/aliases/{alias_id}")
def remove_host_alias(
    case_id: str,
    host_id: str = Path(...),
    alias_id: str = Path(...),
    reason: str | None = None,
    analyst: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    _ensure_case(db, case_id)
    try:
        host = split_alias(db, case_id, alias_id=alias_id, reason=reason, analyst=analyst)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"case_id": case_id, "detached_host": host, "source_host_id": host_id}


@router.patch("/{host_id}")
def update_case_host(case_id: str, host_id: str, payload: RenameHostRequest, db: Session = Depends(get_db)) -> dict:
    _ensure_case(db, case_id)
    target_name = payload.display_name or payload.canonical_name
    if not target_name:
        raise HTTPException(status_code=400, detail="display_name or canonical_name is required")
    try:
        host = rename_canonical_host(
            db,
            case_id,
            host_id=host_id,
            new_name=target_name,
            reason=payload.reason,
            analyst=payload.analyst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"case_id": case_id, "host": host}


@router.get("/audit")
def list_case_host_audit(case_id: str, db: Session = Depends(get_db)) -> dict:
    _ensure_case(db, case_id)
    return {"case_id": case_id, "items": get_host_identity_audit(db, case_id)}
