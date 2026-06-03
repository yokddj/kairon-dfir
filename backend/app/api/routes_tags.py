from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.models.tag import Tag
from app.schemas.tag import TagCreate, TagRead


router = APIRouter(tags=["tags"])

@router.get("/api/cases/{case_id}/tags", response_model=list[TagRead])
def list_tags(case_id: str, db: Session = Depends(get_db)) -> list[Tag]:
    return db.query(Tag).filter(Tag.case_id == case_id).order_by(Tag.name.asc()).all()


@router.post("/api/cases/{case_id}/tags", response_model=TagRead, status_code=status.HTTP_201_CREATED)
def create_tag(case_id: str, payload: TagCreate, db: Session = Depends(get_db)) -> Tag:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    tag = Tag(case_id=case_id, **payload.model_dump())
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag
