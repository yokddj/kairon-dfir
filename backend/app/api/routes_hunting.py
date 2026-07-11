from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import get_db, utc_now
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.rule_run import RuleRun, RuleRunStatus
from app.services.hunting import (
    assign_finding,
    finding_detail,
    finding_to_dict,
    list_detection_runs,
    list_hunting_rules,
    load_hunting_rules,
    rule_to_response,
    run_to_dict,
    suppress_finding,
    unassign_finding,
    unsuppress_finding,
    update_finding_status,
    validate_hunting_rule_content,
    validate_transition,
)


router = APIRouter(tags=["hunting"])


class HuntingEvaluateRequest(BaseModel):
    rule_id: str | None = None
    evidence_id: str | None = None
    process_entity_id: str | None = None
    artifact_family: str | None = None
    dry_run: bool = True
    apply: bool = False
    include_disabled: bool = False
    batch_size: int = Field(default=500, ge=1, le=1000)


class FindingStatusRequest(BaseModel):
    status: str
    analyst: str = "analyst"
    note: str | None = None


class FindingSuppressRequest(BaseModel):
    analyst: str = "analyst"
    reason: str | None = None


class FindingBulkStatusRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    status: str
    analyst: str = "analyst"
    note: str | None = None
    reason: str | None = None


class FindingUnsuppressRequest(BaseModel):
    analyst: str = "analyst"
    reason: str
    target_status: str = "investigating"


class FindingAssignRequest(BaseModel):
    assignee: str
    assigned_by: str = "analyst"


class FindingIndicatorResolveRequest(BaseModel):
    entities: list[dict] = Field(default_factory=list, max_length=500)
    visibility: dict | None = None


def _case_or_404(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _finding_or_404(db: Session, case_id: str, finding_id: str) -> Finding:
    finding = db.get(Finding, finding_id)
    if not finding or finding.case_id != case_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/api/cases/{case_id}/rules")
def case_rules(
    case_id: str,
    status_filter: str | None = Query(default=None, alias="status"),
    category: str | None = None,
    severity: str | None = None,
    artifact_family: str | None = None,
    source_category: str | None = None,
    enabled: bool | None = None,
    tag: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    _case_or_404(db, case_id)
    filters = {"status": status_filter, "category": category, "severity": severity, "artifact_family": artifact_family, "source_category": source_category, "enabled": enabled, "tag": tag}
    rules = list_hunting_rules({k: v for k, v in filters.items() if v is not None})
    for rule in rules:
        rule["findings_count"] = db.query(Finding).filter(Finding.case_id == case_id, Finding.finding_type == rule["rule_id"]).count()
        last_run = db.query(RuleRun).filter(RuleRun.case_id == case_id, RuleRun.engine == "hunting-v1").order_by(RuleRun.created_at.desc()).first()
        rule["last_evaluated"] = last_run.created_at.isoformat() if last_run else None
    return {"items": rules, "total": len(rules)}


@router.get("/api/cases/{case_id}/rules/quality")
def hunting_rules_quality(
    case_id: str,
    rule_id: str | None = None,
    rule_version: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    _case_or_404(db, case_id)
    from app.services.rule_quality import compute_rule_quality_metrics
    metrics = compute_rule_quality_metrics(db, case_id=case_id, rule_id=rule_id, rule_version=rule_version)
    return {"items": metrics, "total": len(metrics)}


@router.get("/api/cases/{case_id}/rules/{rule_id}")
def case_rule_detail(case_id: str, rule_id: str, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    for rule in load_hunting_rules():
        if rule.rule_id == rule_id:
            return {"rule": rule_to_response(rule, findings_count=db.query(Finding).filter(Finding.case_id == case_id, Finding.finding_type == rule_id).count())}
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/api/cases/{case_id}/rules/{rule_id}/evaluate")
def evaluate_case_rule(case_id: str, rule_id: str, payload: HuntingEvaluateRequest | None = Body(default=None), db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    request = payload or HuntingEvaluateRequest()
    try:
        from app.workers.tasks import enqueue_hunting_evaluation

        enqueued = enqueue_hunting_evaluation(
            case_id=case_id,
            evidence_id=request.evidence_id,
            rule_id=rule_id,
            process_entity_id=request.process_entity_id,
            artifact_family=request.artifact_family,
            apply=bool(request.apply and not request.dry_run),
            include_disabled=request.include_disabled,
        )
        return enqueued
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/rules/evaluate")
def evaluate_case_rules(case_id: str, payload: HuntingEvaluateRequest | None = Body(default=None), db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    request = payload or HuntingEvaluateRequest()
    try:
        from app.workers.tasks import enqueue_hunting_evaluation

        enqueued = enqueue_hunting_evaluation(
            case_id=case_id,
            evidence_id=request.evidence_id,
            rule_id=request.rule_id,
            process_entity_id=request.process_entity_id,
            artifact_family=request.artifact_family,
            apply=bool(request.apply and not request.dry_run),
            include_disabled=request.include_disabled,
        )
        return enqueued
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/rules/hunting/validate")
def validate_hunting_rule(payload: dict = Body(...)) -> dict:
    content = str(payload.get("content") or "")
    try:
        rules = validate_hunting_rule_content(content)
        return {"valid": True, "rules": len(rules), "rule_ids": [rule.rule_id for rule in rules]}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail={"valid": False, "error": str(exc)}) from exc


@router.get("/api/cases/{case_id}/findings")
def hunting_list_findings(
    case_id: str,
    status_filter: str | None = Query(default=None, alias="status"),
    severity: FindingSeverity | None = None,
    confidence: str | None = None,
    rule: str | None = None,
    category: str | None = None,
    source_category: str | None = None,
    evidence_id: str | None = None,
    linked_evidence_id: str | None = None,
    linked_host_id: str | None = None,
    q: str | None = None,
    include_archived: bool = False,
    process_entity_id: str | None = None,
    pid: int | None = None,
    tag: str | None = None,
    suppressed: bool | None = None,
    assigned_to: str | None = None,
    has_correlations: bool | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    _case_or_404(db, case_id)
    query = db.query(Finding).filter(Finding.case_id == case_id)
    if status_filter:
        query = query.filter(Finding.status == _safe_status(status_filter))
    if severity:
        query = query.filter(Finding.severity == severity)
    if confidence:
        query = query.filter(Finding.confidence == confidence)
    if rule:
        query = query.filter(Finding.finding_type == rule)
    if evidence_id:
        query = query.filter(or_(Finding.evidence_id == evidence_id, Finding.linked_evidence_id == evidence_id, Finding.related_evidence_ids.contains([evidence_id])))
    if linked_evidence_id:
        query = query.filter(Finding.linked_evidence_id == linked_evidence_id)
    if linked_host_id:
        query = query.filter(Finding.linked_host_id == linked_host_id)
    if tag:
        query = query.filter(Finding.tags.contains([tag]))
    if q:
        token = f"%{q.strip().lower()}%"
        query = query.filter(or_(Finding.title.ilike(token), Finding.description.ilike(token)))
    if not include_archived:
        query = query.filter(Finding.status != FindingStatus.archived, Finding.archived_at.is_(None))
    if time_from:
        query = query.filter(Finding.time_end >= time_from)
    if time_to:
        query = query.filter(Finding.time_start <= time_to)
    rows = query.order_by(Finding.created_at.desc()).all()
    filtered = []
    for row in rows:
        payload = finding_to_dict(row)
        if category and (payload.get("rule_id") or "").split(".")[-1] != category and category not in (row.tags or []):
            continue
        if source_category and source_category not in (payload.get("source_categories") or []):
            continue
        if process_entity_id and payload.get("process_entity_id") != process_entity_id:
            continue
        if pid is not None and payload.get("pid") != pid:
            continue
        if suppressed is not None and (payload.get("suppression_state") == "suppressed") != suppressed:
            continue
        if assigned_to and payload.get("assigned_to") != assigned_to:
            continue
        if has_correlations is not None and bool(row.related_event_ids) != has_correlations:
            continue
        filtered.append(payload)
    total = len(filtered)
    start = (page - 1) * page_size
    return {"items": filtered[start:start + page_size], "results": filtered[start:start + page_size], "total": total, "page": page, "page_size": page_size, "total_pages": (total + page_size - 1) // page_size if total else 0}


@router.get("/api/cases/{case_id}/findings/{finding_id}")
def hunting_get_finding(case_id: str, finding_id: str, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    return finding_detail(_finding_or_404(db, case_id, finding_id))


@router.patch("/api/cases/{case_id}/findings/{finding_id}")
def hunting_patch_finding(case_id: str, finding_id: str, payload: dict = Body(...), db: Session = Depends(get_db)) -> dict:
    finding = _finding_or_404(db, case_id, finding_id)
    allowed = {"title", "description", "confidence", "severity", "tags", "evidence_id", "linked_evidence_id", "linked_host_id", "linked_artifact_id", "linked_artifact_family", "linked_artifact_type", "source_view", "created_by"}
    if "body" in payload and "description" not in payload:
        payload["description"] = payload["body"]
    for evidence_key in ("evidence_id", "linked_evidence_id"):
        if payload.get(evidence_key):
            evidence = db.get(Evidence, payload[evidence_key])
            if not evidence or evidence.case_id != case_id:
                raise HTTPException(status_code=400, detail="Linked evidence must belong to the selected case.")
    if payload.get("linked_host_id"):
        host = db.get(CaseHost, payload["linked_host_id"])
        if not host or host.case_id != case_id:
            raise HTTPException(status_code=400, detail="Linked host must belong to the selected case.")
    if payload.get("linked_artifact_id"):
        artifact = db.get(Artifact, payload["linked_artifact_id"])
        if not artifact or artifact.case_id != case_id:
            raise HTTPException(status_code=400, detail="Linked artifact must belong to the selected case.")
    if "status" in payload:
        finding = update_finding_status(db, finding, status=str(payload["status"]), analyst=str(payload.get("analyst") or "analyst"), note=payload.get("note"), reason=payload.get("reason"))
    if "assigned_to" in payload:
        if payload["assigned_to"]:
            finding = assign_finding(db, finding, assignee=str(payload["assigned_to"]), assigned_by=str(payload.get("assigned_by") or "analyst"))
        else:
            finding = unassign_finding(db, finding, unassigned_by=str(payload.get("assigned_by") or "analyst"))
    for key, value in payload.items():
        if key in allowed:
            if key == "severity" and value is not None:
                value = FindingSeverity(value)
            if key == "tags" and isinstance(value, list):
                value = [str(tag).strip().lower().replace(" ", "-") for tag in value if str(tag).strip()]
            setattr(finding, key, value)
    if "evidence_id" in payload and "linked_evidence_id" not in payload:
        finding.linked_evidence_id = payload["evidence_id"]
    db.commit()
    db.refresh(finding)
    return finding_to_dict(finding)


@router.post("/api/cases/{case_id}/findings/{finding_id}/status")
def hunting_finding_status(case_id: str, finding_id: str, payload: FindingStatusRequest, db: Session = Depends(get_db)) -> dict:
    return finding_to_dict(update_finding_status(db, _finding_or_404(db, case_id, finding_id), status=payload.status, analyst=payload.analyst, note=payload.note))


@router.post("/api/cases/{case_id}/findings/{finding_id}/suppress")
def hunting_suppress_finding(case_id: str, finding_id: str, payload: FindingSuppressRequest | None = Body(default=None), db: Session = Depends(get_db)) -> dict:
    request = payload or FindingSuppressRequest()
    return finding_to_dict(suppress_finding(db, _finding_or_404(db, case_id, finding_id), analyst=request.analyst, reason=request.reason))


@router.post("/api/cases/{case_id}/findings/bulk-status")
def hunting_bulk_status(case_id: str, payload: FindingBulkStatusRequest, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    updated = []
    for finding_id in payload.finding_ids:
        updated.append(finding_to_dict(update_finding_status(db, _finding_or_404(db, case_id, finding_id), status=payload.status, analyst=payload.analyst, note=payload.note, reason=payload.reason)))
    return {"updated": len(updated), "items": updated}


@router.post("/api/cases/{case_id}/findings/{finding_id}/unsuppress")
def hunting_unsuppress_finding(case_id: str, finding_id: str, payload: FindingUnsuppressRequest, db: Session = Depends(get_db)) -> dict:
    return finding_to_dict(unsuppress_finding(db, _finding_or_404(db, case_id, finding_id), analyst=payload.analyst, reason=payload.reason, target_status=payload.target_status))


@router.post("/api/cases/{case_id}/findings/{finding_id}/assign")
def hunting_assign_finding(case_id: str, finding_id: str, payload: FindingAssignRequest, db: Session = Depends(get_db)) -> dict:
    return finding_to_dict(assign_finding(db, _finding_or_404(db, case_id, finding_id), assignee=payload.assignee, assigned_by=payload.assigned_by))


@router.post("/api/cases/{case_id}/findings/{finding_id}/unassign")
def hunting_unassign_finding(case_id: str, finding_id: str, db: Session = Depends(get_db)) -> dict:
    return finding_to_dict(unassign_finding(db, _finding_or_404(db, case_id, finding_id)))


@router.get("/api/cases/{case_id}/detection-runs")
def hunting_detection_runs(case_id: str, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    items = list_detection_runs(db, case_id)
    return {"items": items, "total": len(items)}


@router.get("/api/cases/{case_id}/detection-runs/{run_id}")
def hunting_detection_run(case_id: str, run_id: str, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    run = db.get(RuleRun, run_id)
    if not run or run.case_id != case_id:
        raise HTTPException(status_code=404, detail="Detection run not found")
    result = run_to_dict(run)
    result["job_id"] = (run.metadata_json or {}).get("hunting_job_id")
    return result


@router.post("/api/cases/{case_id}/detection-runs/{run_id}/cancel")
def hunting_cancel_detection_run(case_id: str, run_id: str, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    run = db.get(RuleRun, run_id)
    if not run or run.case_id != case_id:
        raise HTTPException(status_code=404, detail="Detection run not found")
    if run.status in (RuleRunStatus.completed, RuleRunStatus.failed, RuleRunStatus.cancelled, RuleRunStatus.stale, RuleRunStatus.skipped):
        return {"run_id": run.id, "status": run.status.value, "cancelled": False, "message": "Run is already in a terminal state"}
    run.cancel_requested = True
    if run.status == RuleRunStatus.queued:
        run.status = RuleRunStatus.cancelled
        run.current_phase = "cancelled"
        run.finished_at = utc_now().isoformat()
    db.commit()
    db.refresh(run)
    result = run_to_dict(run)
    result["job_id"] = (run.metadata_json or {}).get("hunting_job_id")
    result["cancelled"] = True
    return result


@router.post("/api/cases/{case_id}/finding-indicators/resolve")
def hunting_resolve_finding_indicators(case_id: str, payload: FindingIndicatorResolveRequest, db: Session = Depends(get_db)) -> dict:
    _case_or_404(db, case_id)
    from app.services.finding_indicators import resolve_finding_indicators
    entities = payload.entities[:500]
    for entity in entities:
        if str(entity.get("evidence_id") or "").startswith(case_id):
            entity["evidence_id"] = None
    return resolve_finding_indicators(db, case_id=case_id, entities=entities, visibility=payload.visibility)


@router.get("/api/rules/hunting/quality")
def hunting_rules_global_quality(
    rule_id: str | None = None,
    rule_version: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    from app.services.rule_quality import compute_rule_quality_metrics
    metrics = compute_rule_quality_metrics(db, case_id=None, rule_id=rule_id, rule_version=rule_version)
    return {"items": metrics, "total": len(metrics)}


def _safe_status(value: str) -> FindingStatus:
    try:
        return FindingStatus(value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid finding status")
