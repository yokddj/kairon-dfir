from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.indicator_resolution import extract_and_resolve_indicators, extract_indicators, resolve_indicators


router = APIRouter(tags=["indicators"])


@router.post("/api/cases/{case_id}/indicators/extract")
def extract_case_indicators(case_id: str, payload: dict) -> dict:
    result = extract_indicators(payload)
    result["case_id"] = case_id
    return result


@router.post("/api/cases/{case_id}/indicators/resolve")
def resolve_case_indicators(case_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return resolve_indicators(db, case_id, payload)


@router.post("/api/cases/{case_id}/indicators/extract-resolve")
def extract_and_resolve_case_indicators(case_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return extract_and_resolve_indicators(db, case_id, payload)
