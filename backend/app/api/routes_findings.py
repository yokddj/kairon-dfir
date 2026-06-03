from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.database import get_db
from app.core.opensearch import fetch_event_by_id
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.finding import FindingCreate, FindingRead, FindingUpdate
from app.services.correlation_engine import run_correlation_engine
from app.services.host_identity import expand_host_filter


router = APIRouter(tags=["findings"])


class CorrelationRequest(BaseModel):
    evidence_id: str | None = None
    host: str | None = None
    canonical_host: str | None = None
    host_alias_mode: str | None = "alias-aware"
    finding_types: list[str] = Field(default_factory=list)
    force: bool = False
    force_reset_status: bool = False
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=200)


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _default_finding_title(*, event_ids: list[str], detection_ids: list[str], detections: list[DetectionResult], event_previews: list[dict]) -> str:
    if len(detection_ids) == 1 and detections:
        return f"Investigative lead: {detections[0].rule_name}"
    if len(event_ids) == 1 and event_previews:
        event = event_previews[0]
        event_type = ((event.get("event") or {}) if isinstance(event, dict) else {}).get("type")
        event_message = ((event.get("event") or {}) if isinstance(event, dict) else {}).get("message")
        if event_message:
            return str(event_message)[:120]
        if event_type:
            return f"Investigative lead from {event_type}"
        return f"Investigative lead from event {event_ids[0]}"
    if detection_ids:
        return f"Investigative lead from {len(detection_ids)} detections"
    if event_ids:
        return f"Investigative lead from {len(event_ids)} events"
    return "Investigative finding"


def _default_finding_description(*, event_ids: list[str], detection_ids: list[str], detections: list[DetectionResult]) -> str:
    if detection_ids and detections:
        names = ", ".join(sorted({item.rule_name for item in detections[:3]}))
        return f"Finding created from {len(detection_ids)} selected detections. First matches: {names}."
    if event_ids:
        return f"Finding created from {len(event_ids)} selected event(s). Review the linked events to expand the narrative."
    return "Manual finding created by the analyst."


def _normalize_finding_create(case_id: str, payload: FindingCreate, db: Session) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    requested_event_ids = _dedupe(payload.event_ids)
    requested_detection_ids = _dedupe(payload.detection_ids)

    detections: list[DetectionResult] = []
    if requested_detection_ids:
        detections = (
            db.query(DetectionResult)
            .filter(DetectionResult.case_id == case_id, DetectionResult.id.in_(requested_detection_ids))
            .all()
        )
        found_ids = {item.id for item in detections}
        missing_detection_ids = [item for item in requested_detection_ids if item not in found_ids]
        if missing_detection_ids:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Some detections do not belong to the selected case or no longer exist.",
                    "missing_detection_ids": missing_detection_ids,
                },
            )

    event_ids = _dedupe(requested_event_ids + [item.event_id for item in detections if item.event_id])
    event_previews: list[dict] = []
    missing_event_ids: list[str] = []
    for event_id in event_ids:
        event = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
        if not event:
            missing_event_ids.append(event_id)
            continue
        event_previews.append(event)

    if missing_event_ids and not detections:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Some selected events are no longer available in the case index.",
                "missing_event_ids": missing_event_ids,
            },
        )

    if not event_ids and not requested_detection_ids:
        raise HTTPException(status_code=400, detail="A finding must reference at least one event or detection.")

    title = (payload.title or "").strip() or _default_finding_title(
        event_ids=event_ids,
        detection_ids=requested_detection_ids,
        detections=detections,
        event_previews=event_previews,
    )
    description = payload.description or _default_finding_description(
        event_ids=event_ids,
        detection_ids=requested_detection_ids,
        detections=detections,
    )

    return {
        "title": title,
        "description": description,
        "severity": payload.severity,
        "status": payload.status,
        "query": payload.query,
        "event_ids": event_ids,
        "detection_ids": requested_detection_ids,
        "evidence_id": payload.evidence_id,
        "finding_type": payload.finding_type,
        "confidence": payload.confidence,
        "source": payload.source,
        "correlation_version": payload.correlation_version,
        "fingerprint": payload.fingerprint,
        "risk_score": payload.risk_score,
        "time_start": payload.time_start,
        "time_end": payload.time_end,
        "timeline": payload.timeline,
        "related_event_ids": payload.related_event_ids,
        "related_artifact_ids": payload.related_artifact_ids,
        "related_evidence_ids": payload.related_evidence_ids,
        "related_process_node_ids": payload.related_process_node_ids,
        "related_files": payload.related_files,
        "related_domains": payload.related_domains,
        "related_ips": payload.related_ips,
        "related_users": payload.related_users,
        "related_hosts": payload.related_hosts,
        "reasons": payload.reasons,
        "tags": payload.tags,
        "mitre": payload.mitre,
        "recommended_triage": payload.recommended_triage,
        "data_quality": payload.data_quality,
    }


def _get_case_or_404(db: Session, case_id: str) -> Case:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    return item


def _get_case_finding_or_404(db: Session, case_id: str, finding_id: str) -> Finding:
    item = db.get(Finding, finding_id)
    if not item or item.case_id != case_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return item


@router.post("/api/cases/{case_id}/correlate")
def correlate_case(case_id: str, payload: CorrelationRequest | None = Body(default=None), db: Session = Depends(get_db)) -> dict:
    _get_case_or_404(db, case_id)
    request = payload or CorrelationRequest()
    result = run_correlation_engine(
        db,
        case_id,
        evidence_id=request.evidence_id,
        host=request.canonical_host or request.host,
        finding_types=request.finding_types or None,
        force=request.force,
        force_reset_status=request.force_reset_status,
        page=request.page,
        page_size=request.page_size,
    )
    log_activity(
        db,
        activity_type="correlation_ran",
        title="Correlation engine executed",
        message=f"Generated {result['report'].get('findings_generated', 0)} findings",
        case_id=case_id,
        metadata={"evidence_id": request.evidence_id, "host": request.host, "canonical_host": request.canonical_host, "finding_types": request.finding_types, "force": request.force},
    )
    return result


@router.get("/api/cases/{case_id}/findings", response_model=list[FindingRead])
def list_findings(
    case_id: str,
    severity: FindingSeverity | None = Query(default=None),
    confidence: str | None = Query(default=None),
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    finding_type: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[Finding]:
    _get_case_or_404(db, case_id)
    query = db.query(Finding).filter(Finding.case_id == case_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if confidence:
        query = query.filter(Finding.confidence == confidence)
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    if finding_type:
        query = query.filter(Finding.finding_type == finding_type)
    if evidence_id:
        query = query.filter(Finding.evidence_id == evidence_id)
    items = query.order_by(Finding.created_at.desc()).all()
    host_value = host.strip() if isinstance(host, str) else None
    if host_value:
        expanded_hosts = {value.lower() for value in expand_host_filter(db, case_id, host_value)}
        items = [
            item
            for item in items
            if any(str(value).strip().lower() in expanded_hosts for value in (item.related_hosts or []))
        ]
    return items


@router.get("/api/cases/{case_id}/findings/{finding_id}", response_model=FindingRead)
def get_finding(case_id: str, finding_id: str, db: Session = Depends(get_db)) -> Finding:
    _get_case_or_404(db, case_id)
    return _get_case_finding_or_404(db, case_id, finding_id)


@router.post("/api/cases/{case_id}/findings", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
def create_finding(case_id: str, payload: FindingCreate, db: Session = Depends(get_db)) -> Finding:
    normalized = _normalize_finding_create(case_id, payload, db)
    item = Finding(case_id=case_id, **normalized)
    db.add(item)
    db.commit()
    db.refresh(item)
    log_activity(
        db,
        activity_type="finding_created",
        title="Finding created",
        message=f"Created finding {item.title}",
        case_id=case_id,
        metadata={"finding_id": item.id, "event_count": len(item.event_ids), "detection_count": len(item.detection_ids)},
    )
    return item


@router.patch("/api/cases/{case_id}/findings/{finding_id}", response_model=FindingRead)
def update_case_finding(case_id: str, finding_id: str, payload: FindingUpdate, db: Session = Depends(get_db)) -> Finding:
    item = _get_case_finding_or_404(db, case_id, finding_id)
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/api/findings/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: str, payload: FindingUpdate, db: Session = Depends(get_db)) -> Finding:
    item = db.get(Finding, finding_id)
    if not item:
        raise HTTPException(status_code=404, detail="Finding not found")
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item


@router.post("/api/findings/{finding_id}/export-markdown")
def export_markdown(finding_id: str, db: Session = Depends(get_db)) -> Response:
    item = db.get(Finding, finding_id)
    if not item:
        raise HTTPException(status_code=404, detail="Finding not found")
    content = "\n".join(
        [
            f"# {item.title}",
            "",
            f"- Severity: {item.severity.value}",
            f"- Status: {item.status.value}",
            f"- Case ID: {item.case_id}",
            f"- Finding type: {item.finding_type or '_manual_'}",
            f"- Confidence: {item.confidence or '_n/a_'}",
            "",
            item.description or "",
            "",
            "## Query",
            "",
            item.query or "_No query_",
            "",
            "## Reasons",
            "",
            *[f"- {reason}" for reason in (item.reasons or [])],
            "",
            "## Event IDs",
            "",
            *[f"- {event_id}" for event_id in item.related_event_ids or item.event_ids],
            "",
            "## Detection IDs",
            "",
            *[f"- {detection_id}" for detection_id in item.detection_ids],
        ]
    )
    return Response(content=content, media_type="text/markdown")
