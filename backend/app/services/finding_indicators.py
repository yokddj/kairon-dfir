from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingSeverity, ACTIVE_STATUSES
from app.services.hunting import finding_to_dict


def resolve_finding_indicators(
    db: Session,
    *,
    case_id: str,
    entities: list[dict[str, Any]],
) -> dict[str, Any]:
    if not entities:
        return {"results": {}}

    finding_ids_by_key: dict[str, set[str]] = defaultdict(set)
    all_finding_ids: set[str] = set()

    finding_rows = db.query(Finding).filter(Finding.case_id == case_id).all()
    if not finding_rows:
        return {"results": {e["key"]: _empty_indicator(e) for e in entities}}

    for entity in entities:
        key = entity.get("key", entity.get("entity_type", ""))
        matched = _match_findings(finding_rows, case_id, entity)
        finding_ids_by_key[key] = matched
        all_finding_ids.update(matched)

    finding_map: dict[str, Finding] = {f.id: f for f in finding_rows}

    results: dict[str, Any] = {}
    for entity in entities:
        key = entity.get("key", entity.get("entity_type", ""))
        ids = finding_ids_by_key.get(key, set())
        results[key] = _build_indicator(entity, ids, finding_map, case_id)

    return {"results": results}


def _match_findings(findings: list[Finding], case_id: str, entity: dict[str, Any]) -> set[str]:
    matched: set[str] = set()
    entity_type = str(entity.get("entity_type") or "")
    entity_id = str(entity.get("process_entity_id") or entity.get("artifact_id") or entity.get("event_id") or "")
    evidence_id = str(entity.get("evidence_id") or "")
    pid = entity.get("pid")

    for finding in findings:
        if _finding_matches_entity(finding, case_id, entity_type, entity_id, evidence_id, pid):
            matched.add(finding.id)
    return matched


def _finding_matches_entity(
    finding: Finding,
    case_id: str,
    entity_type: str,
    entity_id: str,
    evidence_id: str,
    pid: int | None,
) -> bool:
    if finding.case_id != case_id:
        return False

    if entity_id:
        if entity_id in (finding.related_process_node_ids or []):
            return True
        if entity_id in (finding.related_artifact_ids or []):
            return True

    for ref in (finding.related_process_node_ids or []):
        if entity_id and entity_id in str(ref):
            return True

    if entity_id and entity_type == "process":
        meta = _meta(finding)
        if meta.get("process_entity_id") == entity_id:
            return True
        for artifact in meta.get("matched_artifacts") or []:
            if artifact.get("process_entity_id") == entity_id:
                return True

    if entity_type == "artifact" and entity_id:
        if entity_id in (finding.related_artifact_ids or []):
            return True

    if entity_type == "event" and entity_id:
        if entity_id in (finding.related_event_ids or []):
            return True

    if evidence_id:
        if finding.evidence_id == evidence_id:
            if pid is not None and entity_id:
                return True
            if not entity_id and entity_type in ("artifact", "event"):
                return True

    return False


def _build_indicator(entity: dict[str, Any], finding_ids: set[str], finding_map: dict[str, Finding], case_id: str) -> dict[str, Any]:
    if not finding_ids:
        return _empty_indicator(entity)

    findings = [finding_map[fid] for fid in finding_ids if fid in finding_map]
    active = [f for f in findings if (f.status.value if hasattr(f.status, "value") else str(f.status)) in ACTIVE_STATUSES]
    terminal = [f for f in findings if f not in active]

    severities = [f.severity.value if hasattr(f.severity, "value") else str(f.severity) for f in findings]
    confidences = [f.confidence for f in findings if f.confidence]
    statuses: dict[str, int] = {}
    for f in findings:
        s = f.status.value if hasattr(f.status, "value") else str(f.status)
        statuses[s] = statuses.get(s, 0) + 1

    highest_severity = _max_severity(severities)
    suppressed_count = sum(1 for f in findings if (f.status.value if hasattr(f.status, "value") else str(f.status)) == "suppressed")

    has_process = entity.get("process_entity_id")
    has_artifact = entity.get("artifact_id")
    basis: list[str] = []
    if has_process:
        basis.append("process_entity_id")
    if has_artifact:
        basis.append("artifact_id")
    if entity.get("evidence_id"):
        basis.append("evidence_ref")
    if entity.get("event_id"):
        basis.append("event_id")
    if not basis:
        basis.append("composite_context")

    return {
        "total": len(findings),
        "active": len(active),
        "highest_severity": highest_severity,
        "highest_confidence": _max_confidence(confidences),
        "statuses": statuses,
        "finding_ids": sorted(finding_ids),
        "suppressed_count": suppressed_count,
        "association_basis": basis,
        "partial": False,
    }


def _empty_indicator(entity: dict[str, Any]) -> dict[str, Any]:
    basis: list[str] = []
    if entity.get("process_entity_id"):
        basis.append("process_entity_id")
    if entity.get("artifact_id"):
        basis.append("artifact_id")
    if entity.get("evidence_id"):
        basis.append("evidence_ref")
    if not basis:
        basis.append("composite_context")
    return {
        "total": 0,
        "active": 0,
        "highest_severity": None,
        "highest_confidence": None,
        "statuses": {},
        "finding_ids": [],
        "suppressed_count": 0,
        "association_basis": basis,
        "partial": False,
    }


def _max_severity(values: list[str]) -> str | None:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}
    return max(values, key=lambda v: order.get(v, 0)) if values else None


def _max_confidence(values: list[str]) -> str | None:
    order = {"exact": 4, "high": 3, "medium": 2, "low": 1}
    return max(values, key=lambda v: order.get(v, 0)) if values else None


def _meta(finding: Finding) -> dict[str, Any]:
    for item in finding.timeline or []:
        if isinstance(item, dict) and item.get("kind") == "hunting_meta" and isinstance(item.get("payload"), dict):
            return dict(item["payload"])
    return {}
