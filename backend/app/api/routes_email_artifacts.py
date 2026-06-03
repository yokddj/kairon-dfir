from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.email_artifacts import list_email_artifacts


router = APIRouter(tags=["email-artifacts"])


@router.get("/api/cases/{case_id}/email-artifacts")
def case_email_artifacts(
    case_id: str,
    host: list[str] | None = Query(default=None),
    artifact_type: list[str] | None = Query(default=None),
    client: list[str] | None = Query(default=None),
    q: str | None = Query(default=None),
    interesting_only: bool = Query(default=False),
    include_technical: bool = Query(default=False),
    risk_min: int | None = Query(default=None, ge=0, le=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    return list_email_artifacts(
        db,
        case_id,
        {
            "host": host,
            "artifact_type": artifact_type,
            "client": client,
            "q": q,
            "interesting_only": interesting_only,
            "include_technical": include_technical,
            "risk_min": risk_min,
            "page": page,
            "page_size": page_size,
        },
    )
