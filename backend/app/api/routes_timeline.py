from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.timeline_service import (
    build_incident_timeline_draft,
    build_incident_timeline_story_bundle,
    build_lightweight_timeline_response,
    build_timeline_response,
    create_key_event,
    delete_key_event,
    export_incident_timeline_markdown,
    export_key_events_markdown,
    list_key_events,
    timeline_around_event,
    timeline_around_finding,
    timeline_quick_filters,
    update_incident_timeline_item_status,
    update_key_event,
)


router = APIRouter(tags=["timeline"])


@router.get("/api/cases/{case_id}/timeline")
def get_case_timeline(
    case_id: str,
    host: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    source_category: str | None = Query(default=None),
    source: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    process_entity_id: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    event_kind: list[str] | None = Query(default=None),
    artifact_family: list[str] | None = Query(default=None),
    include_undated: bool = Query(default=False),
    has_correlations: bool | None = Query(default=None),
    mode: str = Query(default="full"),
    q: str | None = Query(default=None),
    artifact_type: list[str] | None = Query(default=None),
    event_type: list[str] | None = Query(default=None),
    event_category: list[str] | None = Query(default=None),
    risk_min: int | None = Query(default=None),
    risk_max: int | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    kind: str | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    process_node_id: str | None = Query(default=None),
    file_path: str | None = Query(default=None),
    process_name: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    user: str | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    sort: str = Query(default="timestamp_desc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    include_findings: bool = Query(default=True),
    include_bookmarks: bool = Query(default=True),
    include_facets: bool = Query(default=True),
    lightweight: bool = Query(default=False),
    group_by: str = Query(default="hour"),
    key_events_only: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    if lightweight:
        return build_lightweight_timeline_response(
            db,
            case_id,
            {
                "host": host,
                "evidence_id": evidence_id,
                "source_category": source_category or source,
                "run_id": run_id,
                "process_entity_id": process_entity_id,
                "pid": pid,
                "event_kind": event_kind,
                "artifact_family": artifact_family,
                "include_undated": include_undated,
                "has_correlations": has_correlations,
                "mode": mode,
                "q": q,
                "artifact_type": artifact_type,
                "event_type": event_type,
                "event_category": event_category,
                "risk_min": risk_min,
                "risk_max": risk_max,
                "severity": severity,
                "kind": kind,
                "finding_id": finding_id,
                "process_node_id": process_node_id,
                "file_path": file_path,
                "process_name": process_name,
                "domain": domain,
                "ip": ip,
                "user": user,
                "time_from": time_from,
                "time_to": time_to,
                "sort": sort,
                "page": page,
                "page_size": page_size,
                "cursor": cursor,
                "include_findings": False,
                "include_bookmarks": False,
                "include_facets": False,
                "group_by": group_by,
                "key_events_only": False,
            },
        )
    return build_timeline_response(
        db,
        case_id,
        {
            "host": host,
            "evidence_id": evidence_id,
            "source_category": source_category or source,
            "run_id": run_id,
            "process_entity_id": process_entity_id,
            "pid": pid,
            "event_kind": event_kind,
            "artifact_family": artifact_family,
            "include_undated": include_undated,
            "has_correlations": has_correlations,
            "mode": mode,
            "q": q,
            "artifact_type": artifact_type,
            "event_type": event_type,
            "event_category": event_category,
            "risk_min": risk_min,
            "risk_max": risk_max,
            "severity": severity,
            "kind": kind,
            "finding_id": finding_id,
            "process_node_id": process_node_id,
            "file_path": file_path,
            "process_name": process_name,
            "domain": domain,
            "ip": ip,
            "user": user,
            "time_from": time_from,
            "time_to": time_to,
            "sort": sort,
            "page": page,
            "page_size": page_size,
            "cursor": cursor,
            "include_findings": include_findings,
            "include_bookmarks": include_bookmarks,
            "include_facets": include_facets,
            "group_by": group_by,
            "key_events_only": key_events_only,
        },
    )


@router.get("/api/cases/{case_id}/timeline/quick-filters")
def get_timeline_quick_filters(case_id: str) -> dict:
    return {"case_id": case_id, "items": timeline_quick_filters()}


@router.get("/api/cases/{case_id}/incident-timeline/draft")
def get_incident_timeline_draft(
    case_id: str,
    sources: list[str] | None = Query(default=None),
    host: list[str] | None = Query(default=None),
    phase: list[str] | None = Query(default=None),
    include_low_signal: bool = Query(default=False),
    max_items: int = Query(default=60, ge=1, le=200),
    regenerate: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    return build_incident_timeline_draft(
        db,
        case_id,
        {
            "sources": sources,
            "host": host,
            "phase": phase,
            "include_low_signal": include_low_signal,
            "max_items": max_items,
            "regenerate": regenerate,
            "generated_by": "manual" if regenerate else "auto",
        },
    )


@router.post("/api/cases/{case_id}/incident-timeline/draft")
def regenerate_incident_timeline_draft(
    case_id: str,
    payload: dict,
    db: Session = Depends(get_db),
) -> dict:
    params = dict(payload or {})
    params["regenerate"] = True
    params["generated_by"] = "manual"
    return build_incident_timeline_draft(db, case_id, params)


@router.post("/api/cases/{case_id}/incident-timeline/export")
def export_incident_timeline(case_id: str, payload: dict) -> Response:
    content = export_incident_timeline_markdown(case_id, payload)
    return Response(content=content, media_type="text/markdown; charset=utf-8")


@router.get("/api/cases/{case_id}/incident-timeline/story-bundle")
def get_incident_timeline_story_bundle(
    case_id: str,
    item_id: str = Query(...),
    db: Session = Depends(get_db),
) -> dict:
    return build_incident_timeline_story_bundle(db, case_id, item_id)


@router.patch("/api/cases/{case_id}/incident-timeline/draft/{timeline_id}/items")
def update_incident_timeline_item(
    case_id: str,
    timeline_id: str,
    payload: dict,
    db: Session = Depends(get_db),
) -> dict:
    item_id = str((payload or {}).get("item_id") or "")
    return update_incident_timeline_item_status(db, case_id, timeline_id, item_id, payload)


@router.get("/api/cases/{case_id}/timeline/around-event/{event_id}")
def get_timeline_around_event(
    case_id: str,
    event_id: str,
    window: str = Query(default="30m"),
    page_size: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
) -> dict:
    return timeline_around_event(db, case_id, event_id, window=window, page_size=page_size)


@router.get("/api/cases/{case_id}/timeline/around-finding/{finding_id}")
def get_timeline_around_finding(
    case_id: str,
    finding_id: str,
    window: str = Query(default="30m"),
    page_size: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
) -> dict:
    return timeline_around_finding(db, case_id, finding_id, window=window, page_size=page_size)


@router.get("/api/cases/{case_id}/timeline/key-events")
def get_case_key_events(case_id: str, db: Session = Depends(get_db)) -> list[dict]:
    return list_key_events(db, case_id)


@router.post("/api/cases/{case_id}/timeline/key-events", status_code=201)
def create_case_key_event(case_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return create_key_event(db, case_id, payload)


@router.patch("/api/cases/{case_id}/timeline/key-events/{bookmark_id}")
def patch_case_key_event(case_id: str, bookmark_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return update_key_event(db, case_id, bookmark_id, payload)


@router.delete("/api/cases/{case_id}/timeline/key-events/{bookmark_id}", status_code=204)
def delete_case_key_event(case_id: str, bookmark_id: str, db: Session = Depends(get_db)) -> Response:
    delete_key_event(db, case_id, bookmark_id)
    return Response(status_code=204)


@router.get("/api/cases/{case_id}/timeline/key-events/export")
def export_case_key_events(case_id: str, host: str | None = Query(default=None), evidence_id: str | None = Query(default=None), format: str = Query(default="markdown"), db: Session = Depends(get_db)) -> Response:
    if format != "markdown":
        return Response(content="Only markdown export is supported for now.", media_type="text/plain", status_code=400)
    content = export_key_events_markdown(db, case_id, filters={"host": host, "evidence_id": evidence_id})
    return Response(content=content, media_type="text/markdown; charset=utf-8")
