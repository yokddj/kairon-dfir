from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from dateutil import parser as date_parser
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.opensearch import fetch_event_by_id
from app.models.event_marking import EventMarking
from app.models.finding import Finding
from app.schemas.event_marking import EVENT_MARKING_STATUSES, EventMarkingCreate, EventMarkingUpdate


def _parse_timestamp(value: object | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = date_parser.parse(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _clean_labels(values: list[str] | None) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _validate_status(status: str) -> str:
    value = str(status or "").strip()
    if value not in EVENT_MARKING_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid event marking status: {status}")
    return value


def serialize_marking(marking: EventMarking) -> dict[str, Any]:
    return {
        "id": marking.id,
        "case_id": marking.case_id,
        "evidence_id": marking.evidence_id,
        "event_id": marking.event_id,
        "search_doc_id": marking.search_doc_id,
        "stable_event_id": marking.stable_event_id,
        "artifact_type": marking.artifact_type,
        "timestamp": marking.timestamp.isoformat() if marking.timestamp else None,
        "host": marking.host,
        "status": marking.status,
        "labels": list(marking.labels or []),
        "note": marking.note,
        "finding_id": marking.finding_id,
        "created_at": marking.created_at.isoformat() if marking.created_at else None,
        "updated_at": marking.updated_at.isoformat() if marking.updated_at else None,
        "created_by": marking.created_by,
    }


def _event_defaults(case_id: str, event_id: str) -> dict[str, Any]:
    event = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
    if not event:
        return {}
    artifact = event.get("artifact") if isinstance(event.get("artifact"), dict) else {}
    host = event.get("host") if isinstance(event.get("host"), dict) else {}
    return {
        "case_id": event.get("case_id") or case_id,
        "evidence_id": event.get("evidence_id"),
        "search_doc_id": event.get("id") or event_id,
        "stable_event_id": event.get("stable_event_id") or event.get("event_fingerprint"),
        "artifact_type": artifact.get("type"),
        "timestamp": _parse_timestamp(event.get("@timestamp")),
        "host": host.get("canonical") or host.get("name") or host.get("hostname"),
    }


def upsert_event_marking(db: Session, event_id: str, payload: EventMarkingCreate) -> dict[str, Any]:
    case_id = str(payload.case_id or "").strip()
    if not case_id:
        defaults = _event_defaults("", event_id)
        case_id = str(defaults.get("case_id") or "").strip()
    if not case_id:
        raise HTTPException(status_code=400, detail="case_id is required")
    defaults = _event_defaults(case_id, event_id)
    status = _validate_status(payload.status)
    marking = db.query(EventMarking).filter(EventMarking.case_id == case_id, EventMarking.event_id == event_id).first()
    if not marking:
        marking = EventMarking(case_id=case_id, event_id=event_id)
    marking.evidence_id = payload.evidence_id or defaults.get("evidence_id")
    marking.search_doc_id = payload.search_doc_id or defaults.get("search_doc_id") or event_id
    marking.stable_event_id = payload.stable_event_id or defaults.get("stable_event_id")
    marking.artifact_type = payload.artifact_type or defaults.get("artifact_type")
    marking.timestamp = payload.timestamp or defaults.get("timestamp")
    marking.host = payload.host or defaults.get("host")
    marking.status = status
    marking.labels = _clean_labels(payload.labels)
    marking.note = str(payload.note or "").strip() or None
    marking.finding_id = str(payload.finding_id or "").strip() or None
    marking.created_by = str(payload.created_by or "analyst").strip() or "analyst"
    db.add(marking)
    db.commit()
    db.refresh(marking)
    if marking.finding_id:
        attach_marking_to_finding(db, marking.id, marking.finding_id)
        db.refresh(marking)
    return serialize_marking(marking)


def update_event_marking(db: Session, marking_id: str, payload: EventMarkingUpdate) -> dict[str, Any]:
    marking = db.get(EventMarking, marking_id)
    if not marking:
        raise HTTPException(status_code=404, detail="Event marking not found")
    if payload.status is not None:
        marking.status = _validate_status(payload.status)
    if payload.labels is not None:
        marking.labels = _clean_labels(payload.labels)
    if payload.note is not None:
        marking.note = str(payload.note or "").strip() or None
    if payload.finding_id is not None:
        marking.finding_id = str(payload.finding_id or "").strip() or None
    db.add(marking)
    db.commit()
    db.refresh(marking)
    if marking.finding_id:
        attach_marking_to_finding(db, marking.id, marking.finding_id)
        db.refresh(marking)
    return serialize_marking(marking)


def delete_event_marking(db: Session, marking_id: str) -> None:
    marking = db.get(EventMarking, marking_id)
    if not marking:
        raise HTTPException(status_code=404, detail="Event marking not found")
    db.delete(marking)
    db.commit()


def list_event_markings(db: Session, *, case_id: str | None = None, evidence_id: str | None = None, status: str | None = None, has_note: bool | None = None, finding_id: str | None = None) -> list[dict[str, Any]]:
    query = db.query(EventMarking)
    if case_id:
        query = query.filter(EventMarking.case_id == case_id)
    if evidence_id:
        query = query.filter(EventMarking.evidence_id == evidence_id)
    if status:
        query = query.filter(EventMarking.status == _validate_status(status))
    if has_note is True:
        query = query.filter(EventMarking.note.isnot(None))
    if has_note is False:
        query = query.filter(EventMarking.note.is_(None))
    if finding_id:
        query = query.filter(EventMarking.finding_id == finding_id)
    rows = query.order_by(EventMarking.timestamp.asc().nullslast(), EventMarking.updated_at.desc()).all()
    return [serialize_marking(row) for row in rows]


def marking_map_for_events(db: Session, case_id: str, rows: list[dict[str, Any]]) -> dict[str, EventMarking]:
    ids = {str(row.get("id") or "") for row in rows if row.get("id")}
    stable_ids = {str((row.get("raw") or {}).get("stable_event_id") or "") for row in rows if isinstance(row.get("raw"), dict) and (row.get("raw") or {}).get("stable_event_id")}
    if not ids and not stable_ids:
        return {}
    query = db.query(EventMarking).filter(EventMarking.case_id == case_id)
    clauses = []
    if ids:
        clauses.append(EventMarking.event_id.in_(ids))
    if stable_ids:
        clauses.append(EventMarking.stable_event_id.in_(stable_ids))
    from sqlalchemy import or_

    markings = query.filter(or_(*clauses)).all()
    output: dict[str, EventMarking] = {}
    for marking in markings:
        output[marking.event_id] = marking
        if marking.stable_event_id:
            output[marking.stable_event_id] = marking
    return output


def event_marking_filter_ids(db: Session, case_id: str, *, status: str | None = None, has_note: bool | None = None, in_finding: bool | None = None) -> tuple[list[str], list[str]]:
    query = db.query(EventMarking).filter(EventMarking.case_id == case_id)
    if status:
        query = query.filter(EventMarking.status == _validate_status(status))
    if has_note is True:
        query = query.filter(EventMarking.note.isnot(None))
    if in_finding is True:
        query = query.filter(EventMarking.finding_id.isnot(None))
    rows = query.all()
    return [row.event_id for row in rows], [row.stable_event_id for row in rows if row.stable_event_id]


def attach_marking_to_finding(db: Session, marking_id: str, finding_id: str) -> dict[str, Any]:
    marking = db.get(EventMarking, marking_id)
    finding = db.get(Finding, finding_id)
    if not marking:
        raise HTTPException(status_code=404, detail="Event marking not found")
    if not finding or finding.case_id != marking.case_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    marking.finding_id = finding.id
    event_ids = list(finding.event_ids or [])
    related_event_ids = list(finding.related_event_ids or [])
    if marking.event_id not in event_ids:
        event_ids.append(marking.event_id)
    if marking.event_id not in related_event_ids:
        related_event_ids.append(marking.event_id)
    finding.event_ids = event_ids
    finding.related_event_ids = related_event_ids
    if marking.evidence_id:
        related_evidence_ids = list(finding.related_evidence_ids or [])
        if marking.evidence_id not in related_evidence_ids:
            related_evidence_ids.append(marking.evidence_id)
        finding.related_evidence_ids = related_evidence_ids
    db.add(marking)
    db.add(finding)
    db.commit()
    db.refresh(marking)
    return serialize_marking(marking)
