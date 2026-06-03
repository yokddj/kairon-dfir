from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.opensearch import get_events_index, get_opensearch_client
from app.schemas.event_marking import EventMarkingCreate, EventMarkingUpdate
from app.services.event_markings import attach_marking_to_finding, delete_event_marking, list_event_markings, update_event_marking, upsert_event_marking


router = APIRouter(tags=["events"])


@router.get("/api/artifacts/{artifact_id}/events")
def get_artifact_events(artifact_id: str, page: int = 1, page_size: int = 100) -> dict:
    client = get_opensearch_client()
    body = {
        "from": (page - 1) * page_size,
        "size": page_size,
        "query": {"term": {"artifact_id": artifact_id}},
        "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
    }
    result = client.search(index=get_events_index(), body=body)
    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"] if isinstance(result["hits"]["total"], dict) else result["hits"]["total"]
    return {"total": total, "items": [{"id": item["_id"], **item["_source"]} for item in hits]}


@router.post("/api/events/{event_id}/mark", status_code=201)
def mark_event(event_id: str, payload: EventMarkingCreate, db: Session = Depends(get_db)) -> dict:
    return upsert_event_marking(db, event_id, payload)


@router.patch("/api/event-markings/{marking_id}")
def patch_event_marking(marking_id: str, payload: EventMarkingUpdate, db: Session = Depends(get_db)) -> dict:
    return update_event_marking(db, marking_id, payload)


@router.delete("/api/event-markings/{marking_id}", status_code=204)
def clear_event_marking(marking_id: str, db: Session = Depends(get_db)) -> Response:
    delete_event_marking(db, marking_id)
    return Response(status_code=204)


@router.post("/api/event-markings/{marking_id}/attach-finding/{finding_id}")
def attach_event_marking_to_finding(marking_id: str, finding_id: str, db: Session = Depends(get_db)) -> dict:
    return attach_marking_to_finding(db, marking_id, finding_id)


@router.get("/api/cases/{case_id}/event-markings")
def get_case_event_markings(
    case_id: str,
    status: str | None = Query(default=None),
    has_note: bool | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[dict]:
    return list_event_markings(db, case_id=case_id, status=status, has_note=has_note, finding_id=finding_id)


@router.get("/api/evidences/{evidence_id}/event-markings")
def get_evidence_event_markings(
    evidence_id: str,
    status: str | None = Query(default=None),
    has_note: bool | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[dict]:
    return list_event_markings(db, evidence_id=evidence_id, status=status, has_note=has_note, finding_id=finding_id)
