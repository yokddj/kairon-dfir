from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.startup_persistence import list_startup_persistence_items


router = APIRouter(tags=["startup-persistence"])


@router.get("/api/cases/{case_id}/startup-persistence")
def case_startup_persistence(
    case_id: str,
    host: list[str] | None = Query(default=None),
    type: list[str] | None = Query(default=None),  # noqa: A002 - API query name
    source: list[str] | None = Query(default=None),
    q: str | None = Query(default=None),
    suspicious_only: bool = Query(default=False),
    risk_min: int | None = Query(default=None, ge=0, le=100),
    enabled: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    default_sources = ["services", "scheduled_tasks"] if not source and not q and not type else source
    return list_startup_persistence_items(
        db,
        case_id,
        {
            "host": host,
            "type": type,
            "source": default_sources,
            "q": q,
            "suspicious_only": suspicious_only,
            "risk_min": risk_min,
            "enabled": enabled,
            "page": page,
            "page_size": page_size,
        },
    )
