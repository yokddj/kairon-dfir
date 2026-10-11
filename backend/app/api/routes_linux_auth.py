from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.linux_auth_investigation import build_linux_auth_investigation

router = APIRouter()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid timestamp: {value}") from exc


@router.get("/api/cases/{case_id}/linux-authentication")
def get_linux_authentication(
    case_id: str,
    username: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    result: str | None = Query(default=None),
    service: str | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    host_id: str | None = Query(default=None),
    event_group: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    payload = build_linux_auth_investigation(
        case_id,
        {
            "username": username,
            "source_ip": source_ip,
            "result": result,
            "service": service,
            "time_from": _parse_time(time_from),
            "time_to": _parse_time(time_to),
            "evidence_id": evidence_id,
            "host_id": host_id,
        },
        event_group=event_group,
        offset=offset,
        limit=limit,
    )
    return payload
