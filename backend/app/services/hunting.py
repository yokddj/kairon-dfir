from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy.orm import Session

from app.core.database import utc_now
from app.core.opensearch import get_events_index, get_opensearch_client, index_exists
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.rule_run import RuleRun, RuleRunStatus
from app.services.investigation_memory import memory_search_results


RULE_PACK_PATH = Path(__file__).resolve().parents[1] / "rules" / "hunting_builtin.yaml"
HUNTING_ENGINE_VERSION = "hunting-v1"
MAX_COMMAND_CHARS = 2048
MAX_REASON_CHARS = 500
SENSITIVE_PRIVILEGES = {
    "sedebugprivilege",
    "setcbprivilege",
    "seimpersonateprivilege",
    "seassignprimarytokenprivilege",
    "seloaddriverprivilege",
    "sebackupprivilege",
    "serestoreprivilege",
}
EXPECTED_SYSTEM_PROCESSES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
}
SCRIPT_INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe"}
SHELL_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "services.exe"} | OFFICE_PROCESSES
WRITABLE_PATH_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\recycler\\",
    "\\$recycle.bin\\",
    "\\windows\\temp\\",
    "\\temp\\",
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")
URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)
PUBLIC_IPV4_RE = re.compile(r"^(?!(10|127)\.)(?!(172\.(1[6-9]|2\d|3[0-1]))\.)(?!192\.168\.)(?!169\.254\.)(?:\d{1,3}\.){3}\d{1,3}$")


class HuntingRuleLogic(BaseModel):
    type: str
    name: str

    @field_validator("type")
    @classmethod
    def builtin_only(cls, value: str) -> str:
        if value != "builtin":
            raise ValueError("Only builtin hunting rule logic is supported")
        return value


class HuntingRule(BaseModel):
    rule_id: str
    title: str
    description: str
    version: str
    status: str
    category: str
    artifact_families: list[str]
    supported_source_categories: list[str]
    severity: str
    confidence: str
    tags: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    logic: HuntingRuleLogic
    grouping: dict[str, Any] = Field(default_factory=dict)
    threshold: dict[str, Any] = Field(default_factory=dict)
    suppression: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    guidance: str
    navigation: list[str] = Field(default_factory=list)
    author: str = "Kairon built-in"
    created_at: str | None = None
    updated_at: str | None = None
    checksum: str | None = None

    @field_validator("status")
    @classmethod
    def valid_status(cls, value: str) -> str:
        if value not in {"experimental", "stable", "deprecated", "disabled"}:
            raise ValueError("Invalid hunting rule status")
        return value

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value: str) -> str:
        if value not in {"informational", "info", "low", "medium", "high", "critical"}:
            raise ValueError("Invalid hunting rule severity")
        return "info" if value == "informational" else value

    @field_validator("confidence")
    @classmethod
    def valid_confidence(cls, value: str) -> str:
        if value not in {"low", "medium", "high", "exact"}:
            raise ValueError("Invalid hunting rule confidence")
        return value


class HuntingRulePack(BaseModel):
    schema_version: int
    rules: list[HuntingRule]


@dataclass
class HuntingArtifact:
    artifact_id: str
    family: str
    artifact_type: str
    source_category: str
    producer: str | None = None
    evidence_id: str | None = None
    process_entity_id: str | None = None
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    parent_name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    timestamp: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    raw_reference: dict[str, Any] = field(default_factory=dict)
    navigation_target: dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingCandidate:
    rule: HuntingRule
    title: str
    summary: str
    severity: str
    confidence: str
    artifacts: list[HuntingArtifact]
    reasons: list[str]
    matched_fields: dict[str, list[str]]
    matched_values: dict[str, list[str]]
    contradictory_fields: dict[str, list[str]] = field(default_factory=dict)
    missing_prerequisites: list[str] = field(default_factory=list)
    threshold: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    time_start: str | None = None
    time_end: str | None = None
    suppression_state: str = "active"


def load_hunting_rules(path: Path = RULE_PACK_PATH) -> list[HuntingRule]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    pack = HuntingRulePack.model_validate(raw)
    now = "2026-07-02T00:00:00Z"
    rules: list[HuntingRule] = []
    seen: set[str] = set()
    for rule in pack.rules:
        if rule.rule_id in seen:
            raise ValueError(f"Duplicate hunting rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)
        payload = rule.model_dump(exclude={"checksum"})
        checksum = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        rules.append(rule.model_copy(update={"created_at": rule.created_at or now, "updated_at": rule.updated_at or now, "checksum": checksum}))
    unknown = {rule.logic.name for rule in rules} - set(BUILTIN_EVALUATORS)
    if unknown:
        raise ValueError(f"Unknown builtin hunting evaluator(s): {sorted(unknown)}")
    return rules


def validate_hunting_rule_content(content: str) -> list[HuntingRule]:
    if re.search(r"!!python|subprocess|os\.system|eval\(|exec\(|import\s+", content):
        raise ValueError("Unsafe hunting rule content is not allowed")
    raw = yaml.safe_load(content)
    if isinstance(raw, dict) and "rules" not in raw:
        raw = {"schema_version": 1, "rules": [raw]}
    pack = HuntingRulePack.model_validate(raw)
    return pack.rules


def list_hunting_rules(filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    filters = filters or {}
    rows = []
    for rule in load_hunting_rules():
        if filters.get("status") and rule.status != filters["status"]:
            continue
        if filters.get("category") and rule.category != filters["category"]:
            continue
        if filters.get("severity") and rule.severity != filters["severity"]:
            continue
        if filters.get("artifact_family") and filters["artifact_family"] not in rule.artifact_families:
            continue
        if filters.get("source_category") and filters["source_category"] not in rule.supported_source_categories:
            continue
        if filters.get("enabled") is not None and bool(filters["enabled"]) != (rule.status != "disabled"):
            continue
        if filters.get("tag") and filters["tag"] not in rule.tags:
            continue
        rows.append(rule_to_response(rule))
    return rows


def rule_to_response(rule: HuntingRule, *, findings_count: int = 0, last_evaluated: str | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "id": rule.rule_id,
        "title": rule.title,
        "description": rule.description,
        "version": rule.version,
        "status": rule.status,
        "category": rule.category,
        "artifact_families": rule.artifact_families,
        "supported_source_categories": rule.supported_source_categories,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "tags": rule.tags,
        "attack": rule.attack,
        "prerequisites": rule.prerequisites,
        "logic_summary": rule.explanation,
        "threshold": rule.threshold,
        "grouping": rule.grouping,
        "suppression": rule.suppression,
        "guidance": rule.guidance,
        "navigation": rule.navigation,
        "author": rule.author,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
        "checksum": rule.checksum,
        "enabled": rule.status != "disabled",
        "findings_count": findings_count,
        "last_evaluated": last_evaluated,
    }


def evaluate_hunting_rules(
    db: Session,
    *,
    case_id: str,
    rule_id: str | None = None,
    evidence_id: str | None = None,
    process_entity_id: str | None = None,
    artifact_family: str | None = None,
    apply: bool = False,
    include_disabled: bool = False,
    artifact_provider: Callable[[], list[HuntingArtifact]] | None = None,
) -> dict[str, Any]:
    if not db.get(Case, case_id):
        raise ValueError("Case not found")
    if evidence_id:
        evidence = db.get(Evidence, evidence_id)
        if not evidence or evidence.case_id != case_id:
            raise ValueError("Evidence was not found in this case")
    rules = [r for r in load_hunting_rules() if (include_disabled or r.status != "disabled")]
    if rule_id:
        rules = [r for r in rules if r.rule_id == rule_id]
    if artifact_family:
        rules = [r for r in rules if artifact_family in r.artifact_families]
    if rule_id and not rules:
        raise ValueError("Rule not found or disabled")
    run = _create_run(db, case_id, evidence_id, rules, apply=apply, scope="evidence" if evidence_id else "case")
    started = time.monotonic()
    artifacts = artifact_provider() if artifact_provider else collect_hunting_artifacts(db, case_id=case_id, evidence_id=evidence_id, process_entity_id=process_entity_id)
    artifacts = [a for a in artifacts if not evidence_id or a.evidence_id == evidence_id]
    artifacts = [a for a in artifacts if not process_entity_id or a.process_entity_id == process_entity_id]
    coverage = _coverage(artifacts)
    results = []
    candidates: list[FindingCandidate] = []
    missing_by_rule: dict[str, list[str]] = {}
    for rule in rules:
        missing = [item for item in rule.prerequisites if item not in coverage]
        if missing:
            results.append(_rule_status(rule, "insufficient_data", missing_prerequisites=missing))
            missing_by_rule[rule.rule_id] = missing
            continue
        evaluator = BUILTIN_EVALUATORS[rule.logic.name]
        rule_candidates = evaluator(rule, artifacts)
        candidates.extend(rule_candidates)
        results.append(_rule_status(rule, "completed_with_findings" if rule_candidates else "completed_empty", findings=len(rule_candidates)))
    created = updated = suppressed = 0
    persisted_ids: list[str] = []
    if apply:
        for candidate in candidates:
            item, action = upsert_finding_candidate(db, case_id, candidate, evaluation_run_id=run.id)
            persisted_ids.append(item.id)
            if action == "created":
                created += 1
            elif action == "suppressed":
                suppressed += 1
            else:
                updated += 1
        db.commit()
    run.status = RuleRunStatus.completed
    run.current_phase = "completed_with_findings" if candidates else "completed_empty"
    run.matched = len(candidates)
    run.processed_rules = len(rules)
    run.scanned_events = len(artifacts)
    run.created_detections = created
    run.duplicates = updated
    run.finished_at = utc_now().isoformat()
    run.metadata_json = {
        **(run.metadata_json or {}),
        "hunting": True,
        "apply": apply,
        "artifacts_scanned": len(artifacts),
        "candidate_groups": len(candidates),
        "findings_created": created,
        "findings_updated": updated,
        "findings_suppressed": suppressed,
        "missing_prerequisites": missing_by_rule,
        "duration_seconds": round(time.monotonic() - started, 3),
        "persisted_finding_ids": persisted_ids,
        "rule_results": results,
    }
    db.commit()
    db.refresh(run)
    return {
        "run_id": run.id,
        "status": run.current_phase,
        "apply": apply,
        "scope": {"case_id": case_id, "evidence_id": evidence_id, "process_entity_id": process_entity_id, "artifact_family": artifact_family},
        "rules_evaluated": len(rules),
        "artifacts_scanned": len(artifacts),
        "candidate_groups": len(candidates),
        "findings_created": created,
        "findings_updated": updated,
        "findings_suppressed": suppressed,
        "rules": results,
        "missing_prerequisites": missing_by_rule,
        "duration_seconds": run.metadata_json["duration_seconds"],
        "findings": [candidate_to_response(c) for c in candidates[:100]],
    }


def collect_hunting_artifacts(db: Session, *, case_id: str, evidence_id: str | None = None, process_entity_id: str | None = None) -> list[HuntingArtifact]:
    artifacts: list[HuntingArtifact] = []
    memory_params = {"evidence_id": evidence_id, "process_entity_id": process_entity_id, "page_size": 500}
    for family in ["processes", "command_lines", "network", "modules", "suspicious", "vads", "raw_observations"]:
        payload = memory_search_results(db, case_id, {**memory_params, "artifact_family": family})
        for row in payload.get("results") or []:
            artifacts.append(_artifact_from_memory_row(row))
    artifacts.extend(_collect_disk_event_artifacts(case_id=case_id, evidence_id=evidence_id, process_entity_id=process_entity_id))
    return artifacts


def upsert_finding_candidate(db: Session, case_id: str, candidate: FindingCandidate, *, evaluation_run_id: str) -> tuple[Finding, str]:
    fingerprint = candidate_fingerprint(case_id, candidate)
    existing = db.query(Finding).filter(Finding.case_id == case_id, Finding.fingerprint == fingerprint).one_or_none()
    payload = candidate_to_finding_payload(case_id, candidate, evaluation_run_id=evaluation_run_id, fingerprint=fingerprint)
    history_entry = {"timestamp": utc_now().isoformat(), "status": payload["status"].value, "note": "Hunting evaluation applied", "analyst": "system", "previous_status": None}
    if existing:
        previous_status = existing.status.value if hasattr(existing.status, "value") else str(existing.status)
        for key, value in payload.items():
            if key == "status" and previous_status not in {"new", "open"}:
                continue
            setattr(existing, key, value)
        meta = _finding_meta(existing)
        history_entry["previous_status"] = previous_status
        meta.setdefault("status_history", []).append(history_entry)
        existing.timeline = _set_meta(existing.timeline, meta)
        return existing, "updated"
    meta = payload.pop("_hunting_meta")
    meta["status_history"] = [history_entry]
    item = Finding(case_id=case_id, **payload)
    item.timeline = _set_meta(item.timeline, meta)
    db.add(item)
    db.flush()
    return item, "created"


def update_finding_status(db: Session, finding: Finding, *, status: str, analyst: str = "analyst", note: str | None = None) -> Finding:
    previous = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    finding.status = _status(status)
    meta = _finding_meta(finding)
    meta.setdefault("status_history", []).append({"timestamp": utc_now().isoformat(), "analyst": analyst, "previous_status": previous, "status": status, "note": note or ""})
    finding.timeline = _set_meta(finding.timeline, meta)
    db.commit()
    db.refresh(finding)
    return finding


def suppress_finding(db: Session, finding: Finding, *, analyst: str = "analyst", reason: str | None = None) -> Finding:
    previous = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    finding.status = FindingStatus.dismissed
    meta = _finding_meta(finding)
    meta["suppression_state"] = "suppressed"
    meta.setdefault("suppression_history", []).append({"timestamp": utc_now().isoformat(), "analyst": analyst, "reason": reason or "No reason supplied", "previous_status": previous})
    meta.setdefault("status_history", []).append({"timestamp": utc_now().isoformat(), "analyst": analyst, "previous_status": previous, "status": "suppressed", "note": reason or "Suppressed"})
    finding.timeline = _set_meta(finding.timeline, meta)
    db.commit()
    db.refresh(finding)
    return finding


def finding_detail(finding: Finding) -> dict[str, Any]:
    meta = _finding_meta(finding)
    return {
        "finding": finding_to_dict(finding),
        "rule": meta.get("rule") or {"rule_id": finding.finding_type, "version": finding.correlation_version},
        "evidence_references": meta.get("evidence_references") or [],
        "matched_artifacts": meta.get("matched_artifacts") or [],
        "matched_fields": meta.get("matched_fields") or {},
        "matched_values": meta.get("matched_values") or {},
        "reasons": finding.reasons or [],
        "contradictions": meta.get("contradictory_fields") or {},
        "missing_prerequisites": meta.get("missing_prerequisites") or [],
        "process_summary": meta.get("process_summary"),
        "timeline_context": meta.get("timeline_references") or [],
        "correlation_summaries": meta.get("correlation_references") or [],
        "navigation_targets": meta.get("navigation_targets") or [],
        "status_history": meta.get("status_history") or [],
        "suppression_history": meta.get("suppression_history") or [],
        "raw_references": meta.get("raw_references") or [],
    }


def list_detection_runs(db: Session, case_id: str) -> list[dict[str, Any]]:
    rows = db.query(RuleRun).filter(RuleRun.case_id == case_id, RuleRun.engine == HUNTING_ENGINE_VERSION).order_by(RuleRun.created_at.desc()).all()
    return [run_to_dict(row) for row in rows]


def run_to_dict(run: RuleRun) -> dict[str, Any]:
    meta = dict(run.metadata_json or {})
    return {
        "id": run.id,
        "run_id": run.id,
        "case_id": run.case_id,
        "evidence_id": run.evidence_id,
        "engine": run.engine,
        "status": run.current_phase or (run.status.value if hasattr(run.status, "value") else str(run.status)),
        "scope": meta.get("scope") or {"scope": run.scope},
        "rules": meta.get("rules") or [],
        "counts": {key: meta.get(key, 0) for key in ("artifacts_scanned", "candidate_groups", "findings_created", "findings_updated", "findings_suppressed")},
        "duration_seconds": meta.get("duration_seconds"),
        "errors": run.errors or [],
        "missing_prerequisites": meta.get("missing_prerequisites") or {},
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }


def candidate_to_response(candidate: FindingCandidate) -> dict[str, Any]:
    return {
        "rule_id": candidate.rule.rule_id,
        "rule_version": candidate.rule.version,
        "title": candidate.title,
        "summary": candidate.summary,
        "severity": candidate.severity,
        "confidence": candidate.confidence,
        "reasons": candidate.reasons,
        "matched_fields": candidate.matched_fields,
        "matched_values": candidate.matched_values,
        "contradictory_fields": candidate.contradictory_fields,
        "missing_prerequisites": candidate.missing_prerequisites,
        "evidence_references": _evidence_refs(candidate.artifacts),
        "navigation_targets": _navigation_targets(candidate.artifacts),
    }


def candidate_to_finding_payload(case_id: str, candidate: FindingCandidate, *, evaluation_run_id: str, fingerprint: str) -> dict[str, Any]:
    evidence_ids = sorted({a.evidence_id for a in candidate.artifacts if a.evidence_id})
    source_categories = sorted({a.source_category for a in candidate.artifacts if a.source_category})
    artifact_types = sorted({a.artifact_type for a in candidate.artifacts if a.artifact_type})
    process_ids = sorted({a.process_entity_id for a in candidate.artifacts if a.process_entity_id})
    pids = sorted({a.pid for a in candidate.artifacts if a.pid is not None})
    timestamps = sorted({a.timestamp for a in candidate.artifacts if a.timestamp})
    meta = {
        "hunting_schema_version": 1,
        "rule": rule_to_response(candidate.rule),
        "rule_id": candidate.rule.rule_id,
        "rule_version": candidate.rule.version,
        "evidence_ids": evidence_ids,
        "source_categories": source_categories,
        "artifact_types": artifact_types,
        "process_entity_id": process_ids[0] if process_ids else None,
        "pid": pids[0] if pids else None,
        "ppid": next((a.ppid for a in candidate.artifacts if a.ppid is not None), None),
        "matched_artifacts": [_artifact_ref(a) for a in candidate.artifacts],
        "matched_fields": candidate.matched_fields,
        "matched_values": candidate.matched_values,
        "contradictory_fields": candidate.contradictory_fields,
        "missing_prerequisites": candidate.missing_prerequisites,
        "evidence_references": _evidence_refs(candidate.artifacts),
        "timeline_references": [a.raw_reference for a in candidate.artifacts if a.timestamp],
        "correlation_references": [],
        "raw_references": [a.raw_reference for a in candidate.artifacts if a.raw_reference],
        "navigation_targets": _navigation_targets(candidate.artifacts),
        "severity_rationale": candidate.rule.explanation,
        "confidence_rationale": f"Deterministic rule matched {len(candidate.reasons)} explainable reason(s); no AI score was used.",
        "threshold": candidate.threshold or candidate.rule.threshold,
        "evaluation_run_id": evaluation_run_id,
        "deduplication_key": fingerprint,
        "suppression_state": candidate.suppression_state,
        "process_summary": _process_summary(candidate.artifacts),
    }
    return {
        "title": candidate.title[:255],
        "description": candidate.summary,
        "severity": _severity(candidate.severity),
        "status": FindingStatus.new,
        "query": None,
        "event_ids": [],
        "detection_ids": [],
        "evidence_id": evidence_ids[0] if evidence_ids else None,
        "finding_type": candidate.rule.rule_id,
        "confidence": candidate.confidence,
        "source": ",".join(source_categories),
        "correlation_version": candidate.rule.version,
        "fingerprint": fingerprint,
        "risk_score": _legacy_risk(candidate.severity, candidate.confidence),
        "time_start": _parse_time(candidate.time_start or (timestamps[0] if timestamps else None)),
        "time_end": _parse_time(candidate.time_end or (timestamps[-1] if timestamps else None)),
        "timeline": [{"kind": "hunting_meta", "payload": meta}],
        "related_event_ids": [],
        "related_stable_event_ids": [],
        "related_artifact_ids": [a.artifact_id for a in candidate.artifacts if a.artifact_id],
        "related_evidence_ids": evidence_ids,
        "related_process_node_ids": process_ids,
        "related_files": sorted({a.executable_path for a in candidate.artifacts if a.executable_path}),
        "related_domains": [],
        "related_ips": sorted({str(a.fields.get("remote_address")) for a in candidate.artifacts if a.fields.get("remote_address")}),
        "related_users": sorted({str(a.fields.get("user")) for a in candidate.artifacts if a.fields.get("user")}),
        "related_hosts": sorted({str(a.fields.get("host")) for a in candidate.artifacts if a.fields.get("host")}),
        "reasons": [_clip(reason, MAX_REASON_CHARS) for reason in candidate.reasons],
        "tags": sorted(set(candidate.rule.tags + candidate.tags + ["hunting"])),
        "mitre": candidate.rule.attack,
        "recommended_triage": [candidate.rule.guidance],
        "data_quality": [f"missing_prerequisites:{','.join(candidate.missing_prerequisites)}"] if candidate.missing_prerequisites else [],
        "last_seen_at": _parse_time(timestamps[-1] if timestamps else None),
        "occurrence_count": len(candidate.artifacts),
        "_hunting_meta": meta,
    }


def candidate_fingerprint(case_id: str, candidate: FindingCandidate) -> str:
    parts = [case_id, candidate.rule.rule_id, candidate.rule.version]
    parts.extend(sorted({a.evidence_id or "" for a in candidate.artifacts}))
    parts.extend(sorted({a.process_entity_id or f"pid:{a.pid}" for a in candidate.artifacts if a.process_entity_id or a.pid is not None}))
    parts.extend(sorted({a.artifact_id for a in candidate.artifacts if a.artifact_id})[:20])
    parts.extend(sorted({str(v) for values in candidate.matched_values.values() for v in values})[:20])
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def finding_to_dict(item: Finding) -> dict[str, Any]:
    return {
        "id": item.id,
        "finding_id": item.id,
        "case_id": item.case_id,
        "rule_id": item.finding_type,
        "rule_version": item.correlation_version,
        "title": item.title,
        "summary": item.description,
        "description": item.description,
        "severity": item.severity.value if hasattr(item.severity, "value") else item.severity,
        "confidence": item.confidence,
        "status": item.status.value if hasattr(item.status, "value") else item.status,
        "evidence_id": item.evidence_id,
        "source": item.source,
        "source_categories": [v for v in str(item.source or "").split(",") if v],
        "artifact_types": _finding_meta(item).get("artifact_types") or [],
        "process_entity_id": (_finding_meta(item).get("process_entity_id") or (item.related_process_node_ids or [None])[0]),
        "pid": _finding_meta(item).get("pid"),
        "ppid": _finding_meta(item).get("ppid"),
        "first_seen": item.time_start.isoformat() if item.time_start else None,
        "last_seen": item.time_end.isoformat() if item.time_end else (item.last_seen_at.isoformat() if item.last_seen_at else None),
        "event_count": len(item.related_event_ids or item.event_ids or []),
        "grouped_artifact_count": item.occurrence_count,
        "reasons": item.reasons or [],
        "tags": item.tags or [],
        "attack": item.mitre or [],
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "evaluation_run_id": _finding_meta(item).get("evaluation_run_id"),
        "deduplication_key": item.fingerprint,
        "suppression_state": _finding_meta(item).get("suppression_state", "active"),
        "analyst_notes": None,
        "assigned_to": None,
        "navigation_targets": _finding_meta(item).get("navigation_targets") or [],
        "evidence_references": _finding_meta(item).get("evidence_references") or [],
        "matched_fields": _finding_meta(item).get("matched_fields") or {},
        "matched_values": _finding_meta(item).get("matched_values") or {},
        "contradictory_fields": _finding_meta(item).get("contradictory_fields") or {},
        "missing_prerequisites": _finding_meta(item).get("missing_prerequisites") or [],
    }


def _rule_status(rule: HuntingRule, status: str, *, findings: int = 0, missing_prerequisites: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": rule.rule_id, "version": rule.version, "status": status, "findings": findings, "missing_prerequisites": missing_prerequisites or []}


def _create_run(db: Session, case_id: str, evidence_id: str | None, rules: list[HuntingRule], *, apply: bool, scope: str) -> RuleRun:
    run = RuleRun(
        rule_id=None,
        rule_set_id=None,
        case_id=case_id,
        evidence_id=evidence_id,
        engine=HUNTING_ENGINE_VERSION,
        status=RuleRunStatus.running,
        scope=scope,
        total_rules=len(rules),
        processed_rules=0,
        current_phase="running",
        started_at=utc_now().isoformat(),
        metadata_json={"hunting": True, "apply": apply, "rules": [r.rule_id for r in rules], "scope": {"case_id": case_id, "evidence_id": evidence_id, "scope": scope}},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _coverage(artifacts: list[HuntingArtifact]) -> set[str]:
    coverage: set[str] = set()
    families = {a.family for a in artifacts}
    if {"command_line", "process"} & families or any(a.command_line for a in artifacts):
        coverage.add("command_lines")
    if "process" in families or any(a.process_entity_id or a.pid is not None for a in artifacts):
        coverage.add("process_entities")
    if "network" in families:
        coverage.add("network_connections")
    if "privilege" in families or any(a.fields.get("privileges") or a.fields.get("privilege") for a in artifacts):
        coverage.add("privileges")
    if {"suspicious_memory", "vad"} & families:
        coverage.add("malfind_or_suspicious_regions")
    if "module" in families:
        coverage.add("modules")
    if "persistence" in families:
        coverage.add("persistence_artifacts")
    if any(a.timestamp for a in artifacts):
        coverage.add("timeline_events")
    return coverage


def _artifact_from_memory_row(row: dict[str, Any]) -> HuntingArtifact:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    artifact_family = str(row.get("artifact_family") or row.get("artifact_type") or "memory")
    family_map = {"processes": "process", "command_lines": "command_line", "network": "network", "modules": "module", "suspicious": "suspicious_memory", "vads": "vad", "raw_observations": "process"}
    process = raw.get("process") if isinstance(raw.get("process"), dict) else {}
    observed = raw.get("observed") if isinstance(raw.get("observed"), dict) else {}
    return HuntingArtifact(
        artifact_id=str(row.get("id") or row.get("result_id") or raw.get("document_id") or ""),
        family=family_map.get(artifact_family, artifact_family),
        artifact_type=str(row.get("artifact_type") or raw.get("document_type") or "memory_artifact"),
        source_category="Memory",
        producer=row.get("source_plugin_or_parser") or row.get("source_plugin") or raw.get("source_plugin") or raw.get("plugin_name"),
        evidence_id=row.get("evidence_id") or raw.get("evidence_id"),
        process_entity_id=row.get("process_entity_id") or raw.get("process_entity_id"),
        pid=_int(row.get("pid") or raw.get("pid") or process.get("pid") or observed.get("pid")),
        ppid=_int(row.get("ppid") or process.get("ppid") or observed.get("ppid")),
        process_name=row.get("process_name") or process.get("name") or observed.get("name") or raw.get("process_name"),
        parent_name=process.get("parent_name") or raw.get("parent_name"),
        executable_path=process.get("executable_path") or process.get("path") or observed.get("path") or raw.get("path"),
        command_line=_clip(row.get("summary") or process.get("command_line") or observed.get("command_line") or raw.get("command_line"), MAX_COMMAND_CHARS),
        timestamp=row.get("timestamp") or raw.get("create_time") or process.get("create_time"),
        fields={**raw, "remote_address": raw.get("remote_address"), "remote_port": raw.get("remote_port"), "state": raw.get("connection_state"), "privileges": raw.get("privileges")},
        raw_reference=row.get("raw_reference") or {"artifact_id": row.get("id"), "document_id": raw.get("document_id")},
        navigation_target=row.get("navigation_target") or {},
    )


def _collect_disk_event_artifacts(*, case_id: str, evidence_id: str | None, process_entity_id: str | None) -> list[HuntingArtifact]:
    index = get_events_index(case_id)
    if not index_exists(index):
        return []
    filters: list[dict[str, Any]] = []
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    if process_entity_id:
        filters.append({"bool": {"should": [{"term": {"process.entity_id": process_entity_id}}, {"term": {"process.guid": process_entity_id}}], "minimum_should_match": 1}})
    body = {"size": 500, "query": {"bool": {"filter": filters or [{"match_all": {}}]}}, "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}]}
    hits = get_opensearch_client().search(index=index, body=body).get("hits", {}).get("hits", [])
    return [_artifact_from_event_hit(case_id, hit) for hit in hits]


def _artifact_from_event_hit(case_id: str, hit: dict[str, Any]) -> HuntingArtifact:
    src = hit.get("_source") or {}
    process = src.get("process") if isinstance(src.get("process"), dict) else {}
    parent = process.get("parent") if isinstance(process.get("parent"), dict) else {}
    artifact = src.get("artifact") if isinstance(src.get("artifact"), dict) else {}
    network = src.get("network") if isinstance(src.get("network"), dict) else {}
    src_ep = src.get("source") if isinstance(src.get("source"), dict) else {}
    dst_ep = src.get("destination") if isinstance(src.get("destination"), dict) else {}
    command = process.get("command_line") or src.get("powershell", {}).get("command") if isinstance(src.get("powershell"), dict) else None
    family = "command_line" if command else "network" if network or dst_ep else "persistence" if src.get("autoruns") or src.get("task") or src.get("service") or src.get("registry") else "process"
    parser = artifact.get("parser") or src.get("parser")
    return HuntingArtifact(
        artifact_id=str(src.get("event_id") or hit.get("_id") or ""),
        family=family,
        artifact_type=str(artifact.get("type") or family),
        source_category=_source_category_from_event(src),
        producer=parser,
        evidence_id=src.get("evidence_id"),
        process_entity_id=process.get("entity_id") or process.get("guid"),
        pid=_int(process.get("pid")),
        ppid=_int(parent.get("pid") or process.get("parent_pid")),
        process_name=process.get("name"),
        parent_name=parent.get("name") or process.get("parent_name"),
        executable_path=process.get("executable") or process.get("path") or src.get("file", {}).get("path") if isinstance(src.get("file"), dict) else None,
        command_line=_clip(command or src.get("raw_summary") or src.get("search_text"), MAX_COMMAND_CHARS),
        timestamp=src.get("@timestamp") or src.get("timestamp"),
        fields={**src, "remote_address": dst_ep.get("ip") or network.get("destination_ip"), "remote_port": dst_ep.get("port") or network.get("destination_port"), "local_address": src_ep.get("ip") or network.get("source_ip")},
        raw_reference={"event_id": src.get("event_id"), "opensearch_id": hit.get("_id"), "index": hit.get("_index")},
        navigation_target={"kind": "event", "case_id": case_id, "event_id": src.get("event_id"), "evidence_id": src.get("evidence_id")},
    )


def eval_suspicious_powershell_command_line(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        command = artifact.command_line or ""
        name = _lower(artifact.process_name)
        if "powershell" not in name and "pwsh" not in name and "powershell" not in command.lower():
            continue
        signals = _powershell_signals(command)
        if len(signals) < int(rule.threshold.get("minimum_signals") or 2):
            continue
        out.append(_candidate(rule, [artifact], f"Suspicious PowerShell command in {artifact.process_name or 'process'}", signals, {"process.command_line": [command]}))
    return out


def eval_suspicious_shell_command_line(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        command = artifact.command_line or ""
        if _basename(artifact.process_name) not in {"cmd.exe", "sh", "bash", "zsh", "wscript.exe", "cscript.exe", "mshta.exe"} and not re.search(r"\b(cmd\.exe|/bin/(ba)?sh|wscript|cscript|mshta)\b", command, re.I):
            continue
        signals = _shell_signals(command)
        if len(signals) >= int(rule.threshold.get("minimum_signals") or 2):
            out.append(_candidate(rule, [artifact], f"Suspicious shell command in {artifact.process_name or 'process'}", signals, {"process.command_line": [command]}))
    return out


def eval_scan_only_process(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        if artifact.family != "process":
            continue
        plugins = {str(v).lower() for v in (artifact.fields.get("source_plugins") or [])}
        producer = _lower(artifact.producer)
        if ("psscan" in producer or any("psscan" in p for p in plugins)) and not ("pslist" in producer or any("pslist" in p or "pstree" in p for p in plugins)):
            reasons = ["Observed in scan-oriented source psscan", "Absent from listing-oriented pslist/pstree source fields", "Possible terminated, unlinked, or hidden process; not automatically malicious"]
            out.append(_candidate(rule, [artifact], f"Scan-only process {artifact.process_name or artifact.pid}", reasons, {"source_plugins": sorted(plugins) or [producer]}))
    return out


def eval_anomalous_parent_child(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        child = _basename(artifact.process_name)
        parent = _basename(artifact.parent_name)
        if not child or not parent:
            continue
        reasons = []
        if parent in OFFICE_PROCESSES and child in SCRIPT_INTERPRETERS:
            reasons.append(f"Office/document process {parent} spawned script interpreter {child}")
        if parent in {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"} and child in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            reasons.append(f"Browser process {parent} spawned shell {child}")
        if parent == "services.exe" and child in {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            reasons.append(f"Service control process spawned user-space scripting engine {child}")
        if child in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"} and parent in {"winlogon.exe", "system"}:
            reasons.append(f"Sensitive system parent {parent} spawned unexpected child {child}")
        if reasons:
            if parent in {"winlogon.exe", "system"} and _expected_system_path(artifact.executable_path):
                continue
            out.append(_candidate(rule, [artifact], f"Anomalous parent-child: {parent} -> {child}", reasons, {"process.parent.name": [parent], "process.name": [child]}))
    return out


def eval_suspicious_executable_location(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        path = _normalize_path(artifact.executable_path or _path_from_command(artifact.command_line or ""))
        if not path or _looks_like_installer_context(artifact):
            continue
        marker = next((m for m in WRITABLE_PATH_MARKERS if m in path), None)
        if marker or path.startswith("\\\\"):
            reason = f"Executable path is in unusual or user-writable location: {path[:240]}"
            out.append(_candidate(rule, [artifact], f"Execution from suspicious location: {artifact.process_name or path[-80:]}", [reason], {"process.executable": [path]}))
    return out


def eval_sensitive_privilege_context(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        values = artifact.fields.get("privileges") or artifact.fields.get("privilege") or artifact.fields.get("privilege_name") or []
        if isinstance(values, str):
            values = [values]
        matched = sorted({str(v) for v in values if str(v).lower() in SENSITIVE_PRIVILEGES})
        if not matched:
            continue
        proc = _basename(artifact.process_name)
        path = _normalize_path(artifact.executable_path or "")
        if proc in EXPECTED_SYSTEM_PROCESSES and (not path or "\\windows\\system32\\" in path):
            continue
        reasons = [f"Sensitive privilege observed: {', '.join(matched)}"]
        if path and any(marker in path for marker in WRITABLE_PATH_MARKERS):
            reasons.append("Process path is user-writable or unusual")
        out.append(_candidate(rule, [artifact], f"Sensitive privilege context: {artifact.process_name or artifact.pid}", reasons, {"privileges": matched}))
    return out


def eval_suspicious_network_combination(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    by_proc = _by_process(artifacts)
    out = []
    for network in [a for a in artifacts if a.family == "network"]:
        remote = str(network.fields.get("remote_address") or "")
        if not remote or not PUBLIC_IPV4_RE.match(remote):
            continue
        related = by_proc.get(_process_key(network), [])
        signals = [f"Outbound/public remote endpoint observed: {remote}:{network.fields.get('remote_port') or ''}"]
        if _basename(network.process_name) in {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}:
            signals.append(f"Scripting or LOLBin process owned the connection: {network.process_name}")
        if any(_powershell_signals(a.command_line or "") or _shell_signals(a.command_line or "") for a in related):
            signals.append("Same process has suspicious command-line context")
        if any(any(marker in _normalize_path(a.executable_path or "") for marker in WRITABLE_PATH_MARKERS) for a in related + [network]):
            signals.append("Owning process path is writable or unusual")
        if len(signals) >= int(rule.threshold.get("minimum_signals") or 2):
            out.append(_candidate(rule, [network] + related[:3], f"Suspicious network activity by {network.process_name or network.pid}", signals, {"remote.address": [remote]}))
    return out


def eval_suspicious_memory_region(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        if artifact.family not in {"suspicious_memory", "vad"}:
            continue
        protection = _lower(artifact.fields.get("protection"))
        tag = _lower(artifact.fields.get("tag") or artifact.fields.get("finding"))
        reasons = []
        if "write" in protection and "exec" in protection:
            reasons.append(f"Executable and writable memory protection: {artifact.fields.get('protection')}")
        if "private" in _lower(artifact.fields.get("memory_type")) and "exec" in protection:
            reasons.append("Private executable memory region")
        if tag and tag not in {"none", "clean"}:
            reasons.append(f"Suspicious memory tag/source finding: {tag}")
        if artifact.artifact_type == "memory_suspicious_region" and not reasons:
            reasons.append("Normalized suspicious memory region artifact was present")
        if reasons:
            out.append(_candidate(rule, [artifact], f"Suspicious memory region in {artifact.process_name or artifact.pid}", reasons, {"memory.protection": [str(artifact.fields.get('protection') or '')], "memory.tag": [tag]}))
    return out


def eval_module_discrepancy(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    for artifact in artifacts:
        if artifact.family != "module":
            continue
        path = _normalize_path(str(artifact.fields.get("path") or artifact.executable_path or ""))
        load_state = _lower(artifact.fields.get("load_state") or artifact.fields.get("state"))
        plugins = {str(v).lower() for v in (artifact.fields.get("source_plugins") or [])}
        reasons = []
        if load_state and any(term in load_state for term in ("unlinked", "missing", "discrepancy")):
            reasons.append(f"Module load state indicates discrepancy: {load_state}")
        if path and any(marker in path for marker in WRITABLE_PATH_MARKERS):
            reasons.append(f"Module loaded from writable or unusual path: {path[:240]}")
        if len(plugins) == 1 and any(name in next(iter(plugins)) for name in ("ldrmodules", "modscan")):
            reasons.append("Module observed in one memory module source without corroborating module list source")
        if reasons:
            out.append(_candidate(rule, [artifact], f"Module discrepancy: {artifact.fields.get('module_name') or path[-80:]}", reasons, {"module.path": [path], "module.source_plugins": sorted(plugins)}))
    return out


def eval_persistence_observed_process(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    persistence = [a for a in artifacts if a.family == "persistence"]
    processes = [a for a in artifacts if a.family in {"process", "command_line"}]
    out = []
    for entry in persistence:
        target = _normalize_path(str(entry.fields.get("image_path") or entry.fields.get("command_line") or entry.command_line or entry.executable_path or ""))
        if not target:
            continue
        matches = [p for p in processes if _path_overlap(target, p.executable_path or p.command_line or "")]
        if matches:
            reasons = ["Persistence configuration exists", "Matching process or command evidence was observed", "Execution causality is likely but not proven solely by configuration"]
            out.append(_candidate(rule, [entry] + matches[:3], f"Persistence target observed: {target[-100:]}", reasons, {"persistence.target": [target]}))
    return out


def eval_command_network_temporal_proximity(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    commands = [a for a in artifacts if a.command_line and a.timestamp and (_powershell_signals(a.command_line) or _shell_signals(a.command_line))]
    networks = [a for a in artifacts if a.family == "network" and a.timestamp]
    out = []
    max_delta = int(rule.threshold.get("max_delta_seconds") or 300)
    for command in commands:
        ct = _parse_time(command.timestamp)
        if not ct:
            continue
        for network in networks:
            if _process_key(command) != _process_key(network):
                continue
            nt = _parse_time(network.timestamp)
            if not nt:
                continue
            delta = abs((nt - ct).total_seconds())
            if delta <= max_delta:
                reasons = ["Suspicious command line had real timestamp", "Outbound network connection from same process had real timestamp", f"Time delta {int(delta)}s was within threshold {max_delta}s"]
                out.append(_candidate(rule, [command, network], f"Suspicious command and network proximity: {command.process_name or command.pid}", reasons, {"time_delta_seconds": [str(int(delta))]}, time_start=min(ct, nt).isoformat(), time_end=max(ct, nt).isoformat()))
                break
    return out


def eval_evidence_inconsistency(rule: HuntingRule, artifacts: list[HuntingArtifact]) -> list[FindingCandidate]:
    out = []
    by_entity = defaultdict(list)
    by_pid = defaultdict(list)
    for artifact in artifacts:
        if artifact.process_entity_id:
            by_entity[artifact.process_entity_id].append(artifact)
        if artifact.pid is not None:
            by_pid[(artifact.evidence_id, artifact.pid)].append(artifact)
    for key, group in by_entity.items():
        names = sorted({_basename(a.process_name) for a in group if a.process_name})
        parents = sorted({_basename(a.parent_name) for a in group if a.parent_name})
        paths = sorted({_normalize_path(a.executable_path or "") for a in group if a.executable_path})
        contradictions = {}
        reasons = []
        if len(names) > 1:
            reasons.append(f"Process name mismatch across observations: {', '.join(names[:5])}")
            contradictions["process.name"] = names
        if len(parents) > 1:
            reasons.append(f"Parent mismatch across observations: {', '.join(parents[:5])}")
            contradictions["process.parent.name"] = parents
        if len(paths) > 1:
            reasons.append("Process path mismatch across observations")
            contradictions["process.path"] = paths[:5]
        if reasons:
            cand = _candidate(rule, group[:5], f"Process evidence inconsistency: {key}", reasons, {}, severity="info")
            cand.contradictory_fields = contradictions
            out.append(cand)
    for (evidence, pid), group in by_pid.items():
        entities = sorted({a.process_entity_id for a in group if a.process_entity_id})
        if len(entities) > 1:
            cand = _candidate(rule, group[:5], f"PID reuse ambiguity: {pid}", [f"Same PID maps to multiple process entities in one Evidence: {', '.join(entities[:5])}"], {"process.pid": [str(pid)]}, severity="info")
            cand.contradictory_fields = {"process.entity_id": entities}
            out.append(cand)
    return out


BUILTIN_EVALUATORS: dict[str, Callable[[HuntingRule, list[HuntingArtifact]], list[FindingCandidate]]] = {
    "suspicious_powershell_command_line": eval_suspicious_powershell_command_line,
    "suspicious_shell_command_line": eval_suspicious_shell_command_line,
    "scan_only_process": eval_scan_only_process,
    "anomalous_parent_child": eval_anomalous_parent_child,
    "suspicious_executable_location": eval_suspicious_executable_location,
    "sensitive_privilege_context": eval_sensitive_privilege_context,
    "suspicious_network_combination": eval_suspicious_network_combination,
    "suspicious_memory_region": eval_suspicious_memory_region,
    "module_discrepancy": eval_module_discrepancy,
    "persistence_observed_process": eval_persistence_observed_process,
    "command_network_temporal_proximity": eval_command_network_temporal_proximity,
    "evidence_inconsistency": eval_evidence_inconsistency,
}


def _candidate(rule: HuntingRule, artifacts: list[HuntingArtifact], title: str, reasons: list[str], matched: dict[str, list[str]], *, severity: str | None = None, confidence: str | None = None, time_start: str | None = None, time_end: str | None = None) -> FindingCandidate:
    return FindingCandidate(
        rule=rule,
        title=title,
        summary=f"{rule.title}: {'; '.join(reasons[:3])}",
        severity=severity or rule.severity,
        confidence=confidence or rule.confidence,
        artifacts=artifacts,
        reasons=reasons,
        matched_fields={key: [key] for key in matched},
        matched_values={key: [_clip(value, MAX_COMMAND_CHARS) or "" for value in values] for key, values in matched.items()},
        threshold=rule.threshold,
        time_start=time_start,
        time_end=time_end,
    )


def _powershell_signals(command: str) -> list[str]:
    lower = command.lower()
    signals = []
    checks = [
        (("-enc" in lower or "-encodedcommand" in lower), "EncodedCommand flag"),
        (("-w hidden" in lower or "-windowstyle hidden" in lower), "Hidden window flag"),
        (("executionpolicy bypass" in lower or "-ep bypass" in lower), "ExecutionPolicy bypass"),
        (("-nop" in lower or "-noprofile" in lower), "NoProfile flag"),
        (("downloadstring" in lower or "invoke-webrequest" in lower or "iwr " in lower or "webclient" in lower), "Download cradle pattern"),
        (("iex" in lower or "invoke-expression" in lower or "frombase64string" in lower), "In-memory execution or decode pattern"),
        ((BASE64_RE.search(command) is not None), "Long base64-like argument"),
        (("`" in command or "^" in command or " -join " in lower), "Suspicious string obfuscation"),
    ]
    for matched, reason in checks:
        if matched:
            signals.append(reason)
    return signals


def _shell_signals(command: str) -> list[str]:
    lower = command.lower()
    signals = []
    if re.search(r"\b(whoami|ipconfig|net\s+user|net\s+localgroup|nltest|dsquery|quser|systeminfo)\b", lower) and ("&" in command or "&&" in command or "|" in command):
        signals.append("Chained reconnaissance commands")
    if URL_RE.search(command) and re.search(r"\b(curl|wget|certutil|bitsadmin|powershell|mshta)\b", lower) and re.search(r"\b(start|cmd\s*/c|&|&&|/transfer)\b", lower):
        signals.append("Download-and-execute chain")
    if ">" in command and any(marker in _normalize_path(command) for marker in WRITABLE_PATH_MARKERS):
        signals.append("Redirection to suspicious writable path")
    if BASE64_RE.search(command):
        signals.append("Long encoded or obfuscated payload")
    if re.search(r"\b(mimikatz|sekurlsa|lsass|procdump|comsvcs\.dll|ntdsutil)\b", lower):
        signals.append("Credential or account discovery tooling keyword")
    if re.search(r"\b(rundll32|regsvr32|mshta|wmic|certutil|bitsadmin)\b", lower) and URL_RE.search(command):
        signals.append("Living-off-the-land utility with URL")
    return signals


def _by_process(artifacts: list[HuntingArtifact]) -> dict[str, list[HuntingArtifact]]:
    grouped: dict[str, list[HuntingArtifact]] = defaultdict(list)
    for artifact in artifacts:
        grouped[_process_key(artifact)].append(artifact)
    return grouped


def _process_key(artifact: HuntingArtifact) -> str:
    return artifact.process_entity_id or f"{artifact.evidence_id}:pid:{artifact.pid}" if artifact.pid is not None else artifact.artifact_id


def _severity(value: str) -> FindingSeverity:
    if value == "informational":
        value = "info"
    try:
        return FindingSeverity(value)
    except Exception:
        return FindingSeverity.medium


def _status(value: str) -> FindingStatus:
    aliases = {"triaged": "reviewed", "investigating": "open", "accepted_risk": "reviewed", "resolved": "closed", "suppressed": "dismissed"}
    try:
        return FindingStatus(aliases.get(value, value))
    except Exception:
        return FindingStatus.new


def _legacy_risk(severity: str, confidence: str) -> int:
    s = {"info": 10, "informational": 10, "low": 25, "medium": 50, "high": 75, "critical": 90}.get(severity, 50)
    c = {"low": 0, "medium": 5, "high": 10, "exact": 15}.get(confidence, 5)
    return min(100, s + c)


def _finding_meta(finding: Finding) -> dict[str, Any]:
    for item in finding.timeline or []:
        if isinstance(item, dict) and item.get("kind") == "hunting_meta" and isinstance(item.get("payload"), dict):
            return dict(item["payload"])
    return {}


def _set_meta(timeline: list[dict] | None, meta: dict[str, Any]) -> list[dict]:
    rows = [item for item in (timeline or []) if not (isinstance(item, dict) and item.get("kind") == "hunting_meta")]
    return [{"kind": "hunting_meta", "payload": meta}, *rows[:50]]


def _artifact_ref(a: HuntingArtifact) -> dict[str, Any]:
    return {"artifact_id": a.artifact_id, "artifact_type": a.artifact_type, "artifact_family": a.family, "evidence_id": a.evidence_id, "source_category": a.source_category, "producer": a.producer, "process_entity_id": a.process_entity_id, "pid": a.pid, "timestamp": a.timestamp}


def _evidence_refs(artifacts: list[HuntingArtifact]) -> list[dict[str, Any]]:
    refs = []
    for a in artifacts:
        refs.append({**_artifact_ref(a), "raw_reference": a.raw_reference, "navigation_target": a.navigation_target})
    return refs


def _navigation_targets(artifacts: list[HuntingArtifact]) -> list[dict[str, Any]]:
    targets = []
    seen = set()
    for artifact in artifacts:
        base = {"case_id": artifact.fields.get("case_id"), "evidence_id": artifact.evidence_id, "process_entity_id": artifact.process_entity_id, "pid": artifact.pid}
        candidates = [
            {"kind": "search", **base, "source_category": artifact.source_category},
            {"kind": "timeline", **base, "source_category": artifact.source_category} if artifact.timestamp else None,
            {"kind": "command_history", **base} if artifact.command_line else None,
            {"kind": "process", **base} if artifact.process_entity_id else None,
            {"kind": "graph", **base} if artifact.process_entity_id else None,
            {"kind": "network", **base} if artifact.family == "network" else None,
            {"kind": "raw", **base, "raw_reference": artifact.raw_reference},
            artifact.navigation_target,
        ]
        for target in candidates:
            if not target:
                continue
            key = json.dumps(target, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                targets.append(target)
    return targets[:20]


def _process_summary(artifacts: list[HuntingArtifact]) -> dict[str, Any] | None:
    for artifact in artifacts:
        if artifact.process_entity_id or artifact.pid is not None or artifact.process_name:
            return {"process_entity_id": artifact.process_entity_id, "pid": artifact.pid, "ppid": artifact.ppid, "name": artifact.process_name, "path": artifact.executable_path, "command_line": artifact.command_line}
    return None


def _source_category_from_event(src: dict[str, Any]) -> str:
    artifact = src.get("artifact") if isinstance(src.get("artifact"), dict) else {}
    parser = _lower(artifact.get("parser") or src.get("parser"))
    atype = _lower(artifact.get("type"))
    if "evtx" in parser or src.get("windows"):
        return "Event Log"
    if "registry" in parser or "registry" in atype or src.get("registry"):
        return "Registry"
    if src.get("network"):
        return "Network Log"
    return "Disk"


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _basename(value: str | None) -> str:
    text = _lower(value).replace("/", "\\")
    return text.rsplit("\\", 1)[-1]


def _normalize_path(value: str | None) -> str:
    return str(value or "").strip().strip('"').replace("/", "\\").lower()


def _path_from_command(command: str) -> str:
    text = command.strip()
    if not text:
        return ""
    if text.startswith('"') and '"' in text[1:]:
        return text[1:].split('"', 1)[0]
    return text.split(maxsplit=1)[0]


def _expected_system_path(path: str | None) -> bool:
    normalized = _normalize_path(path)
    return bool(normalized and "\\windows\\system32\\" in normalized)


def _looks_like_installer_context(artifact: HuntingArtifact) -> bool:
    command = _lower(artifact.command_line)
    name = _basename(artifact.process_name)
    parent = _basename(artifact.parent_name)
    return any(term in command for term in ("setup", "install", "update", "msiexec")) or name in {"setup.exe", "msiexec.exe"} or parent in {"msiexec.exe", "trustedinstaller.exe"}


def _path_overlap(left: str, right: str) -> bool:
    l = _normalize_path(left)
    r = _normalize_path(right)
    if not l or not r:
        return False
    left_name = l.rsplit("\\", 1)[-1].strip('"')
    return bool(left_name and (left_name in r or r in l))


def hunting_cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Kairon hunting rules maintenance CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-rules")
    sub.add_parser("validate-rules")
    eval_parser = sub.add_parser("evaluate")
    eval_parser.add_argument("--case-id", required=True)
    eval_parser.add_argument("--evidence-id")
    eval_parser.add_argument("--rule-id")
    eval_parser.add_argument("--process-entity-id")
    eval_parser.add_argument("--artifact-family")
    eval_parser.add_argument("--apply", action="store_true")
    eval_parser.add_argument("--dry-run", action="store_true")
    eval_parser.add_argument("--json", action="store_true")
    eval_parser.add_argument("--batch-size", type=int, default=500)
    sub.add_parser("findings-export").add_argument("--case-id", required=True)
    args = parser.parse_args(argv)
    from app.core.database import SessionLocal

    if args.command == "list-rules":
        print(json.dumps(list_hunting_rules(), indent=2))
        return 0
    if args.command == "validate-rules":
        rules = load_hunting_rules()
        print(json.dumps({"valid": True, "rules": len(rules)}, indent=2))
        return 0
    with SessionLocal() as db:
        if args.command == "evaluate":
            result = evaluate_hunting_rules(db, case_id=args.case_id, evidence_id=args.evidence_id, rule_id=args.rule_id, process_entity_id=args.process_entity_id, artifact_family=args.artifact_family, apply=bool(args.apply and not args.dry_run))
            print(json.dumps(result, indent=2, default=str))
            return 0
        if args.command == "findings-export":
            rows = db.query(Finding).filter(Finding.case_id == args.case_id).all()
            print(json.dumps([finding_to_dict(row) for row in rows], indent=2, default=str))
            return 0
    return 1
