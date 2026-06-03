from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.opensearch import count_documents, get_events_index
from app.models.detection_result import DetectionResult
from app.models.finding import Finding


def count_events(case_id: str | None) -> dict:
    index = get_events_index(case_id)
    query = {"term": {"case_id": case_id}} if case_id else None
    return count_documents(index=index, query=query)


def count_detections(db: Session, case_id: str | None, *, include_deleted: bool = False) -> int:
    query = db.query(func.count(DetectionResult.id))
    if case_id:
        query = query.filter(DetectionResult.case_id == case_id)
    if not include_deleted:
        query = query.filter(DetectionResult.deleted_at.is_(None))
    query = query.filter(DetectionResult.status.notin_(["stale", "stale_event_link"]))
    return query.scalar() or 0


def count_findings(db: Session, case_id: str | None) -> int:
    query = db.query(func.count(Finding.id))
    if case_id:
        query = query.filter(Finding.case_id == case_id)
    return query.scalar() or 0
