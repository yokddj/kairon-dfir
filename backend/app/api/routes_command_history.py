from __future__ import annotations

from fastapi import APIRouter, Query

from app.services.command_history import get_command_history


router = APIRouter(tags=["command-history"])


@router.get("/api/cases/{case_id}/command-history")
def case_command_history(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    shell: str | None = Query(default=None),
    family: str | None = Query(default=None),
    launcher: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
    q: str | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    risk_min: int | None = Query(default=None, ge=0, le=100),
    risk_max: int | None = Query(default=None, ge=0, le=100),
    only_suspicious: bool | None = Query(default=None),
    has_supporting_sources: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    sort: str | None = Query(default=None),
    sort_by: str | None = Query(default=None),
    sort_order: str | None = Query(default=None),
) -> dict:
    return get_command_history(
        case_id,
        {
            "evidence_id": evidence_id,
            "host": host,
            "user": user,
            "shell": shell,
            "family": family,
            "launcher": launcher,
            "source_type": source_type,
            "q": q,
            "time_from": time_from,
            "time_to": time_to,
            "risk_min": risk_min,
            "risk_max": risk_max,
            "only_suspicious": only_suspicious,
            "has_supporting_sources": has_supporting_sources,
            "page": page,
            "page_size": page_size,
            "sort": sort,
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )
