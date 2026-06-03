from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.motw import list_motw_items


router = APIRouter(tags=["motw"])


@router.get("/api/cases/{case_id}/motw")
def case_motw(
    case_id: str,
    host: list[str] | None = Query(default=None),
    q: str | None = Query(default=None),
    zone_id: list[int] | None = Query(default=None),
    extension: list[str] | None = Query(default=None),
    source: list[str] | None = Query(default=None),
    risk_min: int | None = Query(default=None, ge=0, le=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    return list_motw_items(
        db,
        case_id,
        {
            "host": host,
            "q": q,
            "zone_id": zone_id,
            "extension": extension,
            "source": source,
            "risk_min": risk_min,
            "page": page,
            "page_size": page_size,
        },
    )
