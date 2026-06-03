from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.activity import AppActivityEvent
from app.schemas.activity import ActivityRead


router = APIRouter(tags=["activity"])


@router.get("/api/activity", response_model=list[ActivityRead])
def list_activity(db: Session = Depends(get_db)) -> list[AppActivityEvent]:
    return db.query(AppActivityEvent).order_by(AppActivityEvent.created_at.desc()).limit(500).all()


@router.get("/api/cases/{case_id}/activity", response_model=list[ActivityRead])
def list_case_activity(case_id: str, db: Session = Depends(get_db)) -> list[AppActivityEvent]:
    return (
        db.query(AppActivityEvent)
        .filter(AppActivityEvent.case_id == case_id)
        .order_by(AppActivityEvent.created_at.desc())
        .limit(500)
        .all()
    )
