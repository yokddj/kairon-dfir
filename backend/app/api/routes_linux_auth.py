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
    attempted_username: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    source_port: int | None = Query(default=None),
    result: str | None = Query(default=None),
    service: str | None = Query(default=None),
    session_state: str | None = Query(default=None),
    brute_force_only: bool = Query(default=False),
    followed_by_success: bool | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    host_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    payload = build_linux_auth_investigation(
        case_id,
        {
            "username": username,
            "attempted_username": attempted_username,
            "source_ip": source_ip,
            "source_port": source_port,
            "result": result,
            "service": service,
            "time_from": _parse_time(time_from),
            "time_to": _parse_time(time_to),
            "evidence_id": evidence_id,
            "host_id": host_id,
        },
    )
    if session_state:
        payload["sessions"] = [item for item in payload["sessions"] if item.get("status") == session_state]
    if followed_by_success is not None:
        payload["brute_force"] = [item for item in payload["brute_force"] if bool(item.get("followed_by_success")) is followed_by_success]
    if brute_force_only:
        usernames = {item.get("target_account") for item in payload["brute_force"]}
        source_ips = {item.get("source_ip") for item in payload["brute_force"]}
        payload["failed_authentication"] = [item for item in payload["failed_authentication"] if item.get("attempted_username") in usernames and item.get("source_ip") in source_ips]
    return payload
