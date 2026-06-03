import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import tempfile
import threading
import time

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import asc, desc, func, or_
from sqlalchemy.orm import Session
import yaml

from app.core.activity import log_activity
from app.core.database import SessionLocal, get_db, utc_now
from app.core.opensearch import count_documents, fetch_event_by_id, get_events_index
from app.core.config import get_settings
from app.ingest.archive import extract_archive
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity
from app.models.rule import Rule, RuleEngine
from app.models.rule_import_run import RuleImportRun, RuleImportRunStatus
from app.models.rule_set import RuleSet
from app.models.rule_run import RuleRun, RuleRunStatus
from app.rules_engine.heuristic import load_heuristic_rule
from app.rules_engine.sigma import (
    analyze_sigma_engine_compatibility,
    compile_sigma_rule,
    ENGINE_COMPATIBILITY_VERSION,
    extract_sigma_metadata,
    preflight_compiled_sigma_rule,
    parse_sigma_rule,
    pysigma_capabilities,
    SIGMA_CATEGORY_EVENT_TYPE_HINTS,
    SIGMA_EVENT_ID_HINTS,
    SIGMA_SERVICE_CHANNEL_HINTS,
    validate_sigma_rule_content,
)
from app.rules_engine.yara_import import classify_yara_import, detect_yara_rules, split_yara_rules
from app.rules_engine.yara_engine import detect_rule_names_from_content, validate_yara_content, yara_available
from app.services.host_identity import is_invalid_host_value
from app.schemas.finding import FindingRead
from app.schemas.rule import (
    DetectionRead,
    DetectionBulkRequest,
    DetectionBulkFilterSet,
    DetectionBulkPreviewRequest,
    DetectionBulkPreviewResponse,
    DetectionBulkActionRequestV2,
    DetectionBulkActionResponse,
    DetectionBulkRuleBreakdown,
    DetectionBulkRunBreakdown,
    DetectionUpdate,
    RuleBulkActionRequest,
    RuleBulkDeleteResponse,
    RuleBulkPreviewResponse,
    RuleBulkUpdateResponse,
    RuleEngineStatusRead,
    RuleCreate,
    RuleImportResponse,
    RuleImportRunListResponse,
    RuleImportRunRead,
    RuleListResponse,
    RuleRead,
    RuleRunActionResponse,
    RuleRunBulkActionRequest,
    RuleRunBulkActionResponse,
    RuleRunBulkDeleteRequest,
    RuleSetListResponse,
    RuleSetRead,
    RuleSetBulkDeleteRequest,
    RuleRunRead,
    RuleRunRequest,
    RuleRunResponse,
    RulesRunRequest,
    SigmaSmokeRequest,
    SigmaSmokeResponse,
    SigmaSmokeRuleResult,
    RuleUpdate,
)
from app.workers.tasks import enqueue_rule_run, enqueue_rules_run


router = APIRouter(tags=["rules", "detections"])
settings = get_settings()
YARA_RULE_RE = re.compile(r"\brule\s+[A-Za-z0-9_]+\s*[:{]")
RULE_METADATA_FILENAMES = {".ds_store"}
DETECTION_SORT_FIELDS = {
    "created_at": DetectionResult.created_at,
    "severity": DetectionResult.severity,
    "engine": DetectionResult.engine,
    "rule_name": DetectionResult.rule_name,
    "status": DetectionResult.status,
}
RULE_RUN_STALE_SECONDS = max(60, int(getattr(settings, "rule_run_stale_after_minutes", 10) * 60))


def _sigma_level_to_severity(level: str | None) -> str | None:
    if level is None:
        return None
    return {
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }.get(str(level).lower(), "medium")


def _safe_finding_severity(value: str | None) -> FindingSeverity:
    try:
        return FindingSeverity(value or "medium")
    except Exception:  # noqa: BLE001
        return FindingSeverity.medium


def _rule_content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def _utc_iso_now() -> str:
    return utc_now().isoformat()


def _safe_error(value: Exception | str) -> str:
    text = str(value).strip()
    return text[:2000] if text else "Unknown error"


def _is_ignored_rule_archive_entry(path_value: str) -> bool:
    normalized = str(path_value or "").replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return True
    filename = parts[-1].lower()
    return (
        "__macosx" in {part.lower() for part in parts}
        or filename in RULE_METADATA_FILENAMES
        or parts[-1].startswith("._")
    )


def _classify_rule_file(path: Path, content: str) -> str:
    lower = path.name.lower()
    if lower.endswith((".yml", ".yaml")):
        return "sigma"
    if lower.endswith((".yar", ".yara")):
        return "yara"
    if detect_yara_rules(content):
        return "yara"
    return "ignored"


def _rule_identity(rule: Rule) -> tuple[str, str]:
    metadata = dict(rule.metadata_json or {})
    external_id = str(metadata.get("external_rule_id") or metadata.get("first_rule_name") or rule.title or rule.name or "").strip().lower()
    return rule.engine.value, external_id or str(rule.content_hash or "").strip().lower()


def _rule_identity_from_values(engine: RuleEngine, external_id: str | None, content_hash: str | None) -> tuple[str, str]:
    normalized = str(external_id or "").strip().lower()
    return engine.value, normalized or str(content_hash or "").strip().lower()


def _find_existing_rule(db: Session, candidate: Rule) -> Rule | None:
    engine_value, identity = _rule_identity(candidate)
    items = db.query(Rule).filter(Rule.engine == candidate.engine).filter(Rule.case_id == candidate.case_id).all()
    for item in items:
        item_engine, item_identity = _rule_identity(item)
        if item_engine == engine_value and item_identity == identity:
            return item
    return None


def _find_existing_rule_set(db: Session, candidate: RuleSet) -> RuleSet | None:
    items = db.query(RuleSet).filter(RuleSet.engine == candidate.engine).filter(RuleSet.case_id == candidate.case_id).all()
    candidate_name = (candidate.name or "").strip().lower()
    for item in items:
        if (item.name or "").strip().lower() == candidate_name:
            return item
    return None


def _prefetch_existing_rules(db: Session, *, case_id: str | None) -> dict[tuple[str, str], Rule]:
    items = db.query(Rule).filter(Rule.case_id == case_id).all()
    return {_rule_identity(item): item for item in items}


def _prefetch_existing_rule_sets(db: Session, *, case_id: str | None) -> dict[str, RuleSet]:
    items = db.query(RuleSet).filter(RuleSet.case_id == case_id).all()
    return {(item.name or "").strip().lower(): item for item in items}


def _import_run_performance(details: dict | None) -> dict[str, float]:
    perf = dict((details or {}).get("performance") or {})
    return {key: float(value or 0.0) for key, value in perf.items()}


def _persist_import_run(db: Session, run: RuleImportRun) -> None:
    db.add(run)
    db.commit()
    db.refresh(run)


def _reload_import_run(db: Session, run_id: str) -> RuleImportRun | None:
    return db.get(RuleImportRun, run_id)


def _mark_import_cancelled(db: Session, run: RuleImportRun, *, reason: str) -> None:
    finished_at = _utc_iso_now()
    run.status = RuleImportRunStatus.cancelled
    run.current_phase = "cancelled"
    run.finished_at = finished_at
    run.cancelled_at = finished_at
    run.elapsed_seconds = max(0.0, (datetime.fromisoformat(finished_at) - datetime.fromisoformat(run.started_at or finished_at)).total_seconds())
    run.last_error = reason
    details = dict(run.details_json or {})
    details["cancelled"] = True
    run.details_json = details
    _persist_import_run(db, run)


def _check_import_cancel_requested(db: Session, run: RuleImportRun) -> bool:
    fresh = _reload_import_run(db, run.id)
    if fresh is None:
        return True
    return bool(fresh.cancel_requested)


def _rebuild_sigma_coverage_for_import(db: Session, run: RuleImportRun) -> dict:
    executable_by_current_engine = 0
    not_executable_by_current_engine = 0
    unsupported_by_feature: dict[str, int] = {}
    examples_by_feature: dict[str, list[str]] = {}
    newly_supported_condition_1_of = 0
    newly_supported_condition_all_of = 0
    sigma_rules = db.query(Rule).filter(Rule.engine == RuleEngine.sigma).all()
    for rule in sigma_rules:
        metadata = dict(rule.metadata_json or {})
        if str(metadata.get("import_run_id") or "") != str(run.id):
            continue
        compatibility = dict(metadata.get("engine_compatibility") or {})
        if not compatibility:
            try:
                compatibility = analyze_sigma_engine_compatibility(yaml.safe_load(rule.content) or {})
            except Exception:
                compatibility = {
                    "executable_by_current_engine": False,
                    "not_executable_by_current_engine": True,
                    "engine_status": "compile_error",
                }
        if compatibility.get("executable_by_current_engine"):
            executable_by_current_engine += 1
            supported_features = set(compatibility.get("supported_features") or [])
            if "condition_1_of" in supported_features or "condition_1_of_them" in supported_features:
                newly_supported_condition_1_of += 1
            if "condition_all_of" in supported_features or "condition_all_of_them" in supported_features:
                newly_supported_condition_all_of += 1
            continue
        not_executable_by_current_engine += 1
        feature_key = str(compatibility.get("engine_status") or "unknown")
        unsupported_by_feature[feature_key] = unsupported_by_feature.get(feature_key, 0) + 1
        examples_by_feature.setdefault(feature_key, [])
        label = str(rule.title or rule.name or rule.id)
        if len(examples_by_feature[feature_key]) < 5 and label not in examples_by_feature[feature_key]:
            examples_by_feature[feature_key].append(label)
    return {
        "total_rules": executable_by_current_engine + not_executable_by_current_engine,
        "executable_by_current_engine": executable_by_current_engine,
        "not_executable_by_current_engine": not_executable_by_current_engine,
        "newly_supported_condition_1_of": newly_supported_condition_1_of,
        "newly_supported_condition_all_of": newly_supported_condition_all_of,
        "unsupported_by_feature": unsupported_by_feature,
        "examples_by_feature": examples_by_feature,
    }


def _import_run_detail(run: RuleImportRun, db: Session | None = None) -> RuleImportRunRead:
    if db is None:
        result = RuleImportRunRead.model_validate(run)
        return _with_import_progress_fields(result)
    details = dict(run.details_json or {})
    changed = False
    if run.engine in {"sigma", "mixed", "unknown"} and not details.get("sigma_engine_coverage_report"):
        details["sigma_engine_coverage_report"] = _rebuild_sigma_coverage_for_import(db, run)
        changed = True
    if "pysigma_evaluation" not in details:
        details["pysigma_evaluation"] = pysigma_capabilities()
        changed = True
    if changed:
        run.details_json = details
        db.add(run)
        db.commit()
        db.refresh(run)
    return _with_import_progress_fields(RuleImportRunRead.model_validate(run))


def _with_import_progress_fields(run: RuleImportRunRead) -> RuleImportRunRead:
    terminal = run.status in {
        RuleImportRunStatus.completed,
        RuleImportRunStatus.completed_with_warnings,
        RuleImportRunStatus.failed,
        RuleImportRunStatus.cancelled,
    }
    progress_pct: float | None = None
    if run.total_files > 0:
        progress_pct = round(min(100.0, (run.processed_files / run.total_files) * 100), 1)
    elif terminal:
        progress_pct = 100.0
    perf = dict((run.details_json or {}).get("performance") or {})
    files_per_sec = perf.get("files_per_second")
    rules_per_sec = perf.get("rules_per_second")
    return run.model_copy(
        update={
            "progress_pct": progress_pct,
            "is_terminal": terminal,
            "files_per_sec": files_per_sec if isinstance(files_per_sec, (int, float)) and files_per_sec > 0 else None,
            "rules_per_sec": rules_per_sec if isinstance(rules_per_sec, (int, float)) and rules_per_sec > 0 else None,
        }
    )


def _parse_run_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _elapsed_seconds(started_at: str | None, finished_at: str | None) -> int | None:
    started = _parse_run_timestamp(started_at)
    if not started:
        return None
    finished = _parse_run_timestamp(finished_at) or datetime.now(timezone.utc)
    return max(0, int((finished - started).total_seconds()))


def _rule_run_status_for_api(run: RuleRun) -> RuleRunStatus:
    heartbeat = _parse_run_timestamp(run.heartbeat_at)
    started = _parse_run_timestamp(run.started_at) or _parse_run_timestamp(run.created_at.isoformat() if run.created_at else None)
    if run.status in {RuleRunStatus.queued, RuleRunStatus.running}:
        if heartbeat is not None:
            age_seconds = (datetime.now(timezone.utc) - heartbeat).total_seconds()
            if age_seconds > RULE_RUN_STALE_SECONDS:
                return RuleRunStatus.stale
        elif started is not None:
            age_seconds = (datetime.now(timezone.utc) - started).total_seconds()
            if age_seconds > RULE_RUN_STALE_SECONDS:
                return RuleRunStatus.stale
    return run.status


def _serialize_rule_run(run: RuleRun) -> RuleRunRead:
    metadata = run.metadata_json or {}
    raw_skipped_by_reason = dict(metadata.get("skipped_by_reason") or {})
    case_compatibility = {
        "applicable_to_case": int(metadata.get("total_rules_executed") or run.processed_rules or 0),
        "skipped_platform": int(raw_skipped_by_reason.get("skipped_unsupported_platform") or 0),
        "skipped_logsource": int(raw_skipped_by_reason.get("skipped_unsupported_logsource") or 0),
        "skipped_missing_fields_in_case": int(raw_skipped_by_reason.get("skipped_missing_fields") or 0),
        "skipped_too_broad": int(raw_skipped_by_reason.get("skipped_too_broad") or 0),
        "runtime_error": int(metadata.get("rules_runtime_error") or 0),
    }
    enriched_metadata = {
        **metadata,
        "candidate_event_evaluations": int(metadata.get("candidate_event_evaluations") or metadata.get("events_scanned") or 0),
        "candidate_events_prefiltered": int(metadata.get("candidate_events_prefiltered") or metadata.get("candidate_event_evaluations") or metadata.get("events_scanned") or 0),
        "query_time_ms_total": int(metadata.get("query_time_ms_total") or 0),
        "dedupe_time_ms_total": int(metadata.get("dedupe_time_ms_total") or 0),
        "write_time_ms_total": int(metadata.get("write_time_ms_total") or 0),
        "bulk_insert_batches": int(metadata.get("bulk_insert_batches") or 0),
        "bulk_duplicate_lookups": int(metadata.get("bulk_duplicate_lookups") or 0),
        "noisy_rules_count": int(metadata.get("noisy_rules_count") or 0),
        "capped_rules_count": int(metadata.get("capped_rules_count") or 0),
        "skipped_too_broad_count": int(metadata.get("skipped_too_broad_count") or 0),
        "matches_capped_count": int(metadata.get("matches_capped_count") or 0),
        "detections_capped_count": int(metadata.get("detections_capped_count") or 0),
        "candidate_count_estimate": int(metadata.get("candidate_count_estimate") or 0),
        "sigma_run_mode": str(metadata.get("sigma_run_mode") or "balanced"),
        "sigma_run_mode_config": dict(metadata.get("sigma_run_mode_config") or {}),
        "top_noisy_rules": list(metadata.get("top_noisy_rules") or []),
        "top_duration_rules": list(metadata.get("top_duration_rules") or []),
        "top_duplicate_rules": list(metadata.get("top_duplicate_rules") or []),
        "case_compatibility": case_compatibility,
    }
    total_rules = int(run.total_rules or metadata.get("rules_evaluated") or 0)
    processed_rules = int(run.processed_rules or 0)
    total_events = int(run.total_events or metadata.get("events_in_scope") or 0)
    scanned_events = int(run.scanned_events or metadata.get("events_in_scope") or 0)
    total_files = int(run.total_files or 0)
    scanned_files = int(run.scanned_files or metadata.get("files_scanned") or 0)
    percent_complete: float | None = None
    if run.engine == "yara" and total_files > 0:
        percent_complete = round(min(100.0, (scanned_files / total_files) * 100), 1)
    elif total_rules > 0:
        percent_complete = round(min(100.0, (processed_rules / total_rules) * 100), 1)
    elif total_files > 0:
        percent_complete = round(min(100.0, (scanned_files / total_files) * 100), 1)
    elif run.status == RuleRunStatus.completed:
        percent_complete = 100.0
    status_for_api = _rule_run_status_for_api(run)
    return RuleRunRead.model_validate(
        {
            "id": run.id,
            "rule_id": run.rule_id,
            "rule_set_id": run.rule_set_id,
            "case_id": run.case_id,
            "evidence_id": run.evidence_id,
            "engine": run.engine,
            "status": status_for_api,
            "scope": run.scope or str(metadata.get("scope") or "case"),
            "matched": run.matched,
            "total_rules": total_rules,
            "processed_rules": processed_rules,
            "total_events": total_events,
            "scanned_events": scanned_events,
            "total_files": total_files,
            "created_detections": run.created_detections,
            "duplicates": run.duplicates,
            "scanned_files": scanned_files,
            "skipped_files": run.skipped_files,
            "current_phase": run.current_phase or str(metadata.get("current_phase") or status_for_api.value),
            "heartbeat_at": run.heartbeat_at,
            "last_error": run.last_error,
            "cancel_requested": bool(run.cancel_requested),
            "retried_from_run_id": metadata.get("retried_from_run_id"),
            "stale_reason": metadata.get("stale_reason"),
            "elapsed_seconds": _elapsed_seconds(run.started_at, run.finished_at),
            "percent_complete": percent_complete,
            "stale": status_for_api == RuleRunStatus.stale,
            "can_cancel": status_for_api in {RuleRunStatus.queued, RuleRunStatus.running, RuleRunStatus.stale},
            "can_retry": status_for_api in {RuleRunStatus.completed, RuleRunStatus.failed, RuleRunStatus.cancelled, RuleRunStatus.stale, RuleRunStatus.skipped},
            "warnings": [str(item) for item in (metadata.get("warnings") or [])],
            "errors": run.errors or [],
            "metadata_json": {**enriched_metadata, "display_status": metadata.get("display_status") or status_for_api.value},
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "created_at": run.created_at,
            "updated_at": run.updated_at,
        }
    )


def _validate_rule_payload(engine: RuleEngine, content: str) -> dict:
    if engine == RuleEngine.sigma:
        return validate_sigma_rule_content(content)
    if engine == RuleEngine.yara:
        return validate_yara_content(content)
    if engine == RuleEngine.heuristic:
        load_heuristic_rule(content)
        return {"valid": True}
    raise ValueError(f"Unsupported engine {engine.value}")


def _build_rule_from_import(
    *,
    filename: str,
    content: str,
    engine: RuleEngine,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
) -> list[Rule]:
    rules: list[Rule] = []
    if engine == RuleEngine.sigma:
        for index, sigma_rule in enumerate(parse_sigma_rule(content), start=1):
            metadata = extract_sigma_metadata(sigma_rule)
            compiled = compile_sigma_rule(sigma_rule)
            rules.append(
                Rule(
                    case_id=case_id,
                    name=metadata["name"] or f"{Path(filename).stem}-{index}",
                    title=metadata["title"],
                    engine=RuleEngine.sigma,
                    namespace=namespace,
                    source="uploaded",
                    description=metadata["description"],
                    author=metadata["author"],
                    rule_version=metadata["rule_version"],
                    level=metadata["level"],
                    content=yaml.safe_dump(sigma_rule, sort_keys=False),
                    content_hash=_rule_content_hash(yaml.safe_dump(sigma_rule, sort_keys=False)),
                    enabled=enabled,
                    severity=_sigma_level_to_severity(metadata["level"]),
                    status=metadata["status"] or "valid",
                    references=metadata["references"] or [],
                    false_positives=metadata["false_positives"] or [],
                    tags=metadata["tags"] or [],
                    mitre=metadata["mitre"] or [],
                    validation_errors=[],
                    metadata_json={
                        "logsource": metadata["logsource"],
                        "condition": metadata["condition"],
                        "sigma_compilation": compiled,
                        "external_rule_id": metadata["id"] or metadata["title"] or metadata["name"],
                        "source_filename": filename,
                        "compile_status": compiled.get("compile_status"),
                        "compile_error": compiled.get("compile_error"),
                        "compile_warnings": compiled.get("compile_warnings") or [],
                    },
                )
            )
        return rules
    if engine == RuleEngine.yara:
        first_match = re.search(r"rule\s+([A-Za-z0-9_]+)", content)
        return [
            Rule(
                case_id=case_id,
                name=first_match.group(1) if first_match else Path(filename).stem,
                title=first_match.group(1) if first_match else Path(filename).stem,
                engine=RuleEngine.yara,
                namespace=namespace,
                source="uploaded",
                description=f"Imported from {filename}",
                content=content,
                content_hash=_rule_content_hash(content),
                enabled=enabled,
                severity=None,
                status="valid" if validate_yara_content(content).get("valid") else "invalid",
                tags=["yara_forge"] if "yara-forge" in filename.lower() or "yara_forge" in filename.lower() else [],
                validation_errors=validate_yara_content(content).get("errors", []),
                metadata_json={
                    "rule_names": detect_rule_names_from_content(content)[:50],
                    "external_rule_id": (first_match.group(1) if first_match else Path(filename).stem),
                    "source_filename": filename,
                    "validation_status": "valid" if validate_yara_content(content).get("valid") else ("not_compiled" if not validate_yara_content(content).get("available") else "invalid"),
                },
            )
        ]
    if engine == RuleEngine.heuristic:
        rule_data = load_heuristic_rule(content)
        return [
            Rule(
                case_id=case_id,
                name=rule_data.get("name") or Path(filename).stem,
                title=rule_data.get("title") or rule_data.get("name") or Path(filename).stem,
                engine=RuleEngine.heuristic,
                namespace=namespace,
                source="uploaded",
                description=rule_data.get("description"),
                content=yaml.safe_dump(rule_data, sort_keys=False),
                content_hash=_rule_content_hash(yaml.safe_dump(rule_data, sort_keys=False)),
                enabled=enabled,
                severity=rule_data.get("severity"),
                tags=rule_data.get("tags") or [],
                status="valid",
            )
        ]
    raise ValueError(f"Unsupported engine: {engine}")


def _build_rule_set_from_import(
    *,
    filename: str,
    content: str,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
    severity: str | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> RuleSet:
    metadata = metadata or {}
    first_rule = detect_yara_rules(content)[:1]
    friendly_name = metadata.get("name") or Path(filename).stem
    return RuleSet(
        case_id=case_id,
        name=str(friendly_name),
        engine=RuleEngine.yara,
        namespace=namespace,
        description=metadata.get("description") or f"Imported YARA rule pack from {filename}",
        source_filename=filename,
        content_path=None,
        content=content,
        rules_count=int(metadata.get("number_of_rules") or metadata.get("rules_count") or len(detect_yara_rules(content))),
        enabled=enabled,
        severity=severity,
        tags=tags or [],
        metadata_json={
            **metadata,
            "first_rules": metadata.get("first_rules") or detect_yara_rules(content)[:50],
            "first_rule_name": first_rule[0] if first_rule else None,
            "external_rule_id": str(friendly_name),
            "source_filename": filename,
        },
    )


def _detect_import_engine(filename: str, content: str, requested: str) -> RuleEngine:
    if requested != "auto":
        return RuleEngine(requested)
    lower = filename.lower()
    if lower.endswith((".yar", ".yara")) or detect_yara_rules(content):
        return RuleEngine.yara
    if lower.endswith((".yml", ".yaml")):
        try:
            docs = parse_sigma_rule(content)
            if docs and all(isinstance(doc, dict) and {"title", "detection"} & set(doc.keys()) for doc in docs):
                return RuleEngine.sigma
        except Exception:  # noqa: BLE001
            pass
    try:
        heuristic = load_heuristic_rule(content)
        if isinstance(heuristic, dict) and ("query" in heuristic or heuristic.get("engine") == "heuristic"):
            return RuleEngine.heuristic
    except Exception:  # noqa: BLE001
        pass
    raise ValueError("Could not detect rule engine automatically")


def _default_namespace(filename: str, namespace: str | None, engine: RuleEngine) -> str | None:
    if namespace:
        return namespace
    lower = filename.lower()
    if engine == RuleEngine.yara and ("yara-forge" in lower or "yara_forge" in lower):
        return "yara_forge"
    if engine == RuleEngine.yara:
        return "imported"
    return None


def _resolve_yara_import_mode(import_mode: str, rules_count: int) -> str:
    normalized = (import_mode or "auto").strip().lower().replace("-", "_")
    if normalized in {"rule_pack", "pack", "ruleset", "rule_set"}:
        return "rule_pack"
    if normalized in {"split", "split_into_individual_rules", "individual", "individual_rules"}:
        return "split"
    if normalized == "auto":
        return "rule_pack" if rules_count > 1 else "individual"
    return "individual"


def _import_content(
    db: Session,
    *,
    filename: str,
    content: str,
    engine: str,
    import_mode: str,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
) -> tuple[list[Rule], list[RuleSet], list[str]]:
    errors: list[str] = []
    imported: list[Rule] = []
    imported_rule_sets: list[RuleSet] = []
    try:
        resolved_engine = _detect_import_engine(filename, content, engine)
        resolved_namespace = _default_namespace(filename, namespace, resolved_engine)
        if resolved_engine == RuleEngine.yara:
            classification = classify_yara_import(content, filename)
            rules_count = int(classification["rules_count"])
            mode = _resolve_yara_import_mode(import_mode, rules_count)
            tags = ["yara_forge"] if str(classification.get("metadata", {}).get("package", "")).lower() == "yara-forge".lower() or "yara-forge" in filename.lower() or "yara_forge" in filename.lower() else []
            if mode == "rule_pack":
                rule_set = _build_rule_set_from_import(
                    filename=filename,
                    content=content,
                    case_id=case_id,
                    namespace=resolved_namespace,
                    enabled=enabled,
                    tags=tags,
                    metadata={**classification["metadata"], "rules_count": rules_count},
                )
                db.add(rule_set)
                db.commit()
                db.refresh(rule_set)
                imported_rule_sets.append(rule_set)
                log_activity(
                    db,
                    activity_type="rule_import_completed",
                    title="YARA rule pack imported",
                    message=f"Imported YARA rule pack {rule_set.name} with {rule_set.rules_count} rules",
                    case_id=rule_set.case_id,
                    metadata={"rule_set_id": rule_set.id, "engine": "yara", "rules_count": rule_set.rules_count},
                )
                return imported, imported_rule_sets, errors
            if mode == "split" and rules_count > 1:
                created = [
                    Rule(
                        case_id=case_id,
                        name=rule_name,
                        engine=RuleEngine.yara,
                        namespace=resolved_namespace,
                        description=f"Imported from {filename}",
                        content=rule_content,
                        enabled=enabled,
                        severity=None,
                        tags=tags,
                    )
                    for rule_name, rule_content in split_yara_rules(content, filename)
                ]
            else:
                created = _build_rule_from_import(
                    filename=filename,
                    content=content,
                    engine=resolved_engine,
                    case_id=case_id,
                    namespace=resolved_namespace,
                    enabled=enabled,
                )
        else:
            created = _build_rule_from_import(
                filename=filename,
                content=content,
                engine=resolved_engine,
                case_id=case_id,
                namespace=resolved_namespace,
                enabled=enabled,
            )
        for rule in created:
            db.add(rule)
        db.commit()
        for rule in created:
            db.refresh(rule)
            log_activity(
                db,
                activity_type="rule_import_completed",
                title="Rule imported",
                message=f"Imported {rule.engine.value} rule {rule.name}",
                case_id=rule.case_id,
                metadata={"rule_id": rule.id, "engine": rule.engine.value},
            )
        imported.extend(created)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        errors.append(f"{filename}: {exc}")
    return imported, imported_rule_sets, errors


def _sigma_compile_summary(imported: list[Rule]) -> dict:
    compiled_count = 0
    unsupported_condition_count = 0
    compile_error_count = 0
    by_product: dict[str, int] = {}
    by_category: dict[str, int] = {}
    executable_by_current_engine = 0
    not_executable_by_current_engine = 0
    unsupported_by_feature: dict[str, int] = {}
    for rule in imported:
        if rule.engine != RuleEngine.sigma:
            continue
        metadata = dict(rule.metadata_json or {})
        compilation = dict(metadata.get("sigma_compilation") or {})
        engine_compatibility = dict(metadata.get("engine_compatibility") or compilation.get("engine_compatibility") or {})
        compile_status = str(compilation.get("compile_status") or "")
        if compile_status == "compiled":
            compiled_count += 1
        elif compile_status == "skipped_unsupported_condition":
            unsupported_condition_count += 1
        elif compile_status:
            compile_error_count += 1
        if engine_compatibility.get("executable_by_current_engine"):
            executable_by_current_engine += 1
        elif engine_compatibility:
            not_executable_by_current_engine += 1
            feature = str(engine_compatibility.get("engine_status") or "unknown")
            unsupported_by_feature[feature] = unsupported_by_feature.get(feature, 0) + 1
        logsource = dict(compilation.get("sigma_logsource") or {})
        product = str(logsource.get("product") or "unknown").strip().lower() or "unknown"
        category = str(logsource.get("category") or "unknown").strip().lower() or "unknown"
        by_product[product] = by_product.get(product, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
    return {
        "compiled_count": compiled_count,
        "unsupported_condition_count": unsupported_condition_count,
        "compile_error_count": compile_error_count,
        "sigma_rules_by_product": by_product,
        "sigma_rules_by_category": by_category,
        "executable_by_current_engine": executable_by_current_engine,
        "not_executable_by_current_engine": not_executable_by_current_engine,
        "unsupported_by_feature": unsupported_by_feature,
    }


def _upsert_imported_rule(
    db: Session,
    *,
    rule: Rule,
    import_run_id: str,
    source_pack: str | None,
    existing: Rule | None = None,
) -> tuple[str, Rule]:
    metadata = dict(rule.metadata_json or {})
    metadata["import_run_id"] = import_run_id
    metadata["source_pack"] = source_pack
    rule.metadata_json = metadata
    existing = existing or _find_existing_rule(db, rule)
    if existing is None:
        db.add(rule)
        db.flush()
        return "imported", rule
    if (existing.content_hash or "") == (rule.content_hash or ""):
        existing_metadata = dict(existing.metadata_json or {})
        incoming_compile_version = str(metadata.get("compile_version") or "")
        current_compile_version = str(existing_metadata.get("compile_version") or "")
        if incoming_compile_version and incoming_compile_version != current_compile_version:
            existing.metadata_json = {
                **existing_metadata,
                **metadata,
                "last_import_status": "updated",
            }
            db.flush()
            return "updated", existing
        existing_metadata.update(
            {
                "import_run_id": import_run_id,
                "source_pack": source_pack,
                "last_import_status": "duplicate",
            }
        )
        existing.metadata_json = existing_metadata
        db.flush()
        return "duplicate", existing
    existing.name = rule.name
    existing.title = rule.title
    existing.namespace = rule.namespace
    existing.source = rule.source
    existing.description = rule.description
    existing.author = rule.author
    existing.rule_version = rule.rule_version
    existing.level = rule.level
    existing.content = rule.content
    existing.content_hash = rule.content_hash
    existing.enabled = rule.enabled
    existing.severity = rule.severity
    existing.status = rule.status
    existing.references = rule.references
    existing.false_positives = rule.false_positives
    existing.tags = rule.tags
    existing.mitre = rule.mitre
    existing.validation_errors = rule.validation_errors
    existing.metadata_json = {
        **dict(existing.metadata_json or {}),
        **metadata,
        "last_import_status": "updated",
    }
    db.flush()
    return "updated", existing


def _upsert_imported_rule_set(
    db: Session,
    *,
    rule_set: RuleSet,
    import_run_id: str,
    source_pack: str | None,
    existing: RuleSet | None = None,
) -> tuple[str, RuleSet]:
    metadata = dict(rule_set.metadata_json or {})
    metadata["import_run_id"] = import_run_id
    metadata["source_pack"] = source_pack
    rule_set.metadata_json = metadata
    existing = existing or _find_existing_rule_set(db, rule_set)
    if existing is None:
        db.add(rule_set)
        db.flush()
        return "imported", rule_set
    new_hash = _rule_content_hash(rule_set.content)
    existing_hash = _rule_content_hash(existing.content)
    if existing_hash == new_hash:
        existing.metadata_json = {
            **dict(existing.metadata_json or {}),
            **metadata,
            "last_import_status": "duplicate",
        }
        db.flush()
        return "duplicate", existing
    existing.name = rule_set.name
    existing.namespace = rule_set.namespace
    existing.description = rule_set.description
    existing.source_filename = rule_set.source_filename
    existing.content_path = rule_set.content_path
    existing.content = rule_set.content
    existing.rules_count = rule_set.rules_count
    existing.enabled = rule_set.enabled
    existing.severity = rule_set.severity
    existing.tags = rule_set.tags
    existing.metadata_json = {
        **dict(existing.metadata_json or {}),
        **metadata,
        "last_import_status": "updated",
    }
    db.flush()
    return "updated", existing


def _build_import_response(
    *,
    run: RuleImportRun,
    imported_rules: list[Rule],
    imported_rule_sets: list[RuleSet],
) -> RuleImportResponse:
    details = dict(run.details_json or {})
    summary = {
        "status": run.status.value,
        "engine": run.engine,
        "current_phase": run.current_phase,
        "total_files": run.total_files,
        "processed_files": run.processed_files,
        "total_rules_found": run.total_rules_found,
        "processed_rules": run.processed_rules,
        "imported_count": run.imported_count,
        "updated_count": run.updated_count,
        "duplicate_count": run.duplicate_count,
        "skipped_count": run.skipped_count,
        "invalid_count": run.invalid_count,
        "compiled_count": run.compiled_count,
        "unsupported_count": run.unsupported_count,
        "warning_count": run.warning_count,
        "error_count": run.error_count,
        "detected_engine_counts": dict(details.get("detected_engine_counts") or {}),
        "sigma_rules_by_product": dict(details.get("sigma_rules_by_product") or {}),
        "sigma_rules_by_category": dict(details.get("sigma_rules_by_category") or {}),
        "unsupported_condition_count": int(details.get("unsupported_condition_count") or 0),
        "compile_error_count": int(details.get("compile_error_count") or 0),
        "sigma_engine_coverage_report": dict(details.get("sigma_engine_coverage_report") or {}),
        "pysigma_evaluation": dict(details.get("pysigma_evaluation") or {}),
        "total_yara_rules_inside": int(details.get("total_yara_rules_inside") or 0),
        "performance": _import_run_performance(details),
    }
    return RuleImportResponse(
        import_run_id=run.id,
        status=run.status.value,
        engine=run.engine,
        summary=summary,
        source_name=run.source_name,
        source_type=run.source_type,
        pack_name=run.pack_name,
        total_files=run.total_files,
        processed_files=run.processed_files,
        total_rules_found=run.total_rules_found,
        imported_count=run.imported_count,
        updated_count=run.updated_count,
        duplicate_count=run.duplicate_count,
        imported_rules=len(imported_rules),
        imported_rule_sets=len(imported_rule_sets),
        total_yara_rules_inside=int(details.get("total_yara_rules_inside") or 0),
        compiled_count=run.compiled_count,
        unsupported_condition_count=int(details.get("unsupported_condition_count") or 0),
        compile_error_count=int(details.get("compile_error_count") or 0),
        invalid_count=run.invalid_count,
        unsupported_count=run.unsupported_count,
        warning_count=run.warning_count,
        error_count=run.error_count,
        sigma_rules_by_product=dict(details.get("sigma_rules_by_product") or {}),
        sigma_rules_by_category=dict(details.get("sigma_rules_by_category") or {}),
        skipped_count=run.skipped_count,
        warnings=[str(item) for item in (run.warnings_summary or [])],
        errors=[str(item) for item in (run.errors_summary or [])],
        invalid_items=list(run.invalid_items or []),
        unsupported_items=list(run.unsupported_items or []),
        detected_engine_counts=dict(details.get("detected_engine_counts") or {}),
        sample_imported=list(details.get("sample_imported") or []),
        rules=imported_rules,
        rule_sets=imported_rule_sets,
    )


def _create_import_run(
    db: Session,
    *,
    uploaded_filename: str,
    source_type: str,
    requested_engine: str,
    import_mode: str,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
    status: RuleImportRunStatus,
    current_phase: str,
    total_files: int = 0,
) -> RuleImportRun:
    run = RuleImportRun(
        case_id=case_id,
        engine="unknown",
        source_name=uploaded_filename,
        source_type=source_type,
        uploaded_filename=uploaded_filename,
        pack_name=Path(uploaded_filename or "rules").stem,
        status=status,
        started_at=_utc_iso_now(),
        total_files=total_files,
        current_phase=current_phase,
        import_options={
            "engine": requested_engine,
            "import_mode": import_mode,
            "namespace": namespace,
            "enabled": enabled,
        },
    )
    _persist_import_run(db, run)
    return run


def _run_import(
    db: Session,
    *,
    run: RuleImportRun,
    uploaded_filename: str,
    source_type: str,
    entries: list[tuple[str, str]],
    requested_engine: str,
    import_mode: str,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
) -> tuple[RuleImportRun, list[Rule], list[RuleSet]]:
    imported_rules: list[Rule] = []
    imported_rule_sets: list[RuleSet] = []
    warnings: list[str] = []
    errors: list[str] = []
    invalid_items: list[dict] = []
    unsupported_items: list[dict] = []
    created_rule_ids: list[str] = []
    updated_rule_ids: list[str] = []
    duplicate_rule_ids: list[str] = []
    detected_engine_counts: dict[str, int] = {}
    sigma_by_product: dict[str, int] = {}
    sigma_by_category: dict[str, int] = {}
    sigma_executable_count = 0
    sigma_not_executable_count = 0
    sigma_unsupported_by_feature: dict[str, int] = {}
    sigma_coverage_examples: dict[str, list[str]] = {}
    sigma_newly_supported_1_of = 0
    sigma_newly_supported_all_of = 0
    compiled_count = 0
    unsupported_condition_count = 0
    compile_error_count = 0
    total_rules_found = 0
    skipped_count = 0
    imported_count = 0
    updated_count = 0
    duplicate_count = 0
    invalid_count = 0
    unsupported_count = 0
    total_yara_rules_inside = 0
    started_at = run.started_at or _utc_iso_now()
    pack_name = run.pack_name or Path(uploaded_filename or "rules").stem
    existing_rules = _prefetch_existing_rules(db, case_id=case_id)
    existing_rule_sets = _prefetch_existing_rule_sets(db, case_id=case_id)
    perf = _import_run_performance(run.details_json)
    overall_started = time.perf_counter()
    last_persist_at = 0.0
    writes_dirty = False

    def persist_progress(*, force: bool = False) -> None:
        nonlocal last_persist_at, writes_dirty
        now = time.perf_counter()
        if not force and now - last_persist_at < 1.0 and (run.processed_files % 25) != 0:
            return
        write_started = time.perf_counter()
        _persist_import_run(db, run)
        perf["db_write_seconds"] = perf.get("db_write_seconds", 0.0) + (time.perf_counter() - write_started)
        last_persist_at = now
        writes_dirty = False

    def cancel_if_requested(reason: str) -> bool:
        fresh = _reload_import_run(db, run.id)
        if fresh and fresh.cancel_requested:
            if writes_dirty:
                persist_progress(force=True)
            _mark_import_cancelled(db, fresh, reason=reason)
            return True
        return False

    try:
        run.status = RuleImportRunStatus.parsing
        run.current_phase = "parsing_rules"
        run.total_files = len(entries)
        persist_progress(force=True)
        for index, (name, content) in enumerate(entries, start=1):
            if cancel_if_requested("Cancel requested during rule import."):
                return _reload_import_run(db, run.id) or run, imported_rules, imported_rule_sets
            run.current_file = name
            run.processed_files = index - 1
            writes_dirty = True
            if _is_ignored_rule_archive_entry(name):
                skipped_count += 1
                warnings.append(f"{name}: ignored macOS metadata")
                run.skipped_count = skipped_count
                persist_progress()
                continue
            file_type = _classify_rule_file(Path(name), content)
            if file_type == "ignored":
                skipped_count += 1
                run.skipped_count = skipped_count
                persist_progress()
                continue
            detected_engine_counts[file_type] = detected_engine_counts.get(file_type, 0) + 1
            if requested_engine not in {"", "auto", file_type} and requested_engine != "mixed":
                warnings.append(f"{name}: looks like {file_type}, requested import engine was {requested_engine}")
            if file_type == "sigma":
                run.status = RuleImportRunStatus.compiling
                run.current_phase = "compiling_sigma"
                writes_dirty = True
                parse_started = time.perf_counter()
                try:
                    sigma_rules = parse_sigma_rule(content)
                except Exception as exc:  # noqa: BLE001
                    perf["parse_seconds"] = perf.get("parse_seconds", 0.0) + (time.perf_counter() - parse_started)
                    invalid_count += 1
                    invalid_items.append({"file": name, "engine": "sigma", "reason": _safe_error(exc)})
                    errors.append(f"{name}: {_safe_error(exc)}")
                    run.invalid_count = invalid_count
                    run.error_count = len(errors)
                    persist_progress()
                    continue
                perf["parse_seconds"] = perf.get("parse_seconds", 0.0) + (time.perf_counter() - parse_started)
                total_rules_found += len(sigma_rules)
                for sigma_rule in sigma_rules:
                    if cancel_if_requested("Cancel requested while compiling Sigma rules."):
                        return _reload_import_run(db, run.id) or run, imported_rules, imported_rule_sets
                    try:
                        metadata = extract_sigma_metadata(sigma_rule)
                        rendered = yaml.safe_dump(sigma_rule, sort_keys=False)
                        rendered_hash = _rule_content_hash(rendered)
                        external_rule_id = metadata.get("id") or metadata.get("title") or metadata.get("name")
                        identity = _rule_identity_from_values(RuleEngine.sigma, str(external_rule_id or ""), rendered_hash)
                        existing_rule = existing_rules.get(identity)
                        existing_compile_version = str(dict(existing_rule.metadata_json or {}).get("compile_version") or "") if existing_rule else ""
                        if existing_rule and (existing_rule.content_hash or "") == rendered_hash and existing_compile_version == ENGINE_COMPATIBILITY_VERSION:
                            existing_metadata = dict(existing_rule.metadata_json or {})
                            existing_metadata.update(
                                {
                                    "import_run_id": run.id,
                                    "source_pack": pack_name,
                                    "last_import_status": "duplicate",
                                }
                            )
                            existing_rule.metadata_json = existing_metadata
                            duplicate_count += 1
                            duplicate_rule_ids.append(existing_rule.id)
                            run.processed_rules += 1
                            writes_dirty = True
                            continue
                        engine_compatibility = analyze_sigma_engine_compatibility(sigma_rule)
                        if engine_compatibility.get("executable_by_current_engine"):
                            sigma_executable_count += 1
                            supported_features = set(engine_compatibility.get("supported_features") or [])
                            if "condition_1_of" in supported_features or "condition_1_of_them" in supported_features:
                                sigma_newly_supported_1_of += 1
                            if "condition_all_of" in supported_features or "condition_all_of_them" in supported_features:
                                sigma_newly_supported_all_of += 1
                        else:
                            sigma_not_executable_count += 1
                            feature_key = str(engine_compatibility.get("engine_status") or "unknown")
                            sigma_unsupported_by_feature[feature_key] = sigma_unsupported_by_feature.get(feature_key, 0) + 1
                            sigma_coverage_examples.setdefault(feature_key, [])
                            example_name = str(metadata.get("title") or metadata.get("name") or external_rule_id or Path(name).stem)
                            if len(sigma_coverage_examples[feature_key]) < 5 and example_name not in sigma_coverage_examples[feature_key]:
                                sigma_coverage_examples[feature_key].append(example_name)
                        compile_started = time.perf_counter()
                        try:
                            compiled = compile_sigma_rule(sigma_rule)
                        except Exception as exc:  # noqa: BLE001
                            compiled = {
                                "compile_status": "compile_error",
                                "compile_error": _safe_error(exc),
                                "compile_warnings": [],
                                "sigma_logsource": metadata.get("logsource") or {},
                            }
                        perf["compile_seconds"] = perf.get("compile_seconds", 0.0) + (time.perf_counter() - compile_started)
                        compile_status = str(compiled.get("compile_status") or "compile_error")
                        if compile_status == "compiled":
                            compiled_count += 1
                        else:
                            unsupported_count += 1
                            unsupported_condition_count += 1 if compile_status == "skipped_unsupported_condition" else 0
                            compile_error_count += 1 if compile_status == "compile_error" else 0
                            unsupported_items.append(
                                {
                                    "file": name,
                                    "engine": "sigma",
                                    "rule": metadata.get("title") or metadata.get("name"),
                                    "status": compile_status,
                                    "reason": compiled.get("compile_error"),
                                    "engine_status": engine_compatibility.get("engine_status"),
                                    "unsupported_features": list(engine_compatibility.get("unsupported_features") or []),
                                }
                            )
                        logsource = dict(compiled.get("sigma_logsource") or {})
                        product = str(logsource.get("product") or "unknown").strip().lower() or "unknown"
                        category = str(logsource.get("category") or "unknown").strip().lower() or "unknown"
                        sigma_by_product[product] = sigma_by_product.get(product, 0) + 1
                        sigma_by_category[category] = sigma_by_category.get(category, 0) + 1
                        rule = Rule(
                            case_id=case_id,
                            name=metadata["title"] or metadata["name"] or Path(name).stem,
                            title=metadata["title"] or metadata["name"] or Path(name).stem,
                            engine=RuleEngine.sigma,
                            namespace=namespace,
                            source="uploaded",
                            description=metadata["description"],
                            author=metadata["author"],
                            rule_version=metadata["rule_version"],
                            level=metadata["level"],
                            content=rendered,
                            content_hash=rendered_hash,
                            enabled=enabled,
                            severity=_sigma_level_to_severity(metadata["level"]),
                            status=metadata["status"] or "valid",
                            references=metadata["references"] or [],
                            false_positives=metadata["false_positives"] or [],
                            tags=metadata["tags"] or [],
                            mitre=metadata["mitre"] or [],
                            validation_errors=[],
                            metadata_json={
                                "logsource": metadata["logsource"],
                                "condition": metadata["condition"],
                                "sigma_compilation": compiled,
                                "engine_compatibility": engine_compatibility,
                                "external_rule_id": external_rule_id,
                                "source_filename": name,
                                "compile_status": compile_status,
                                "compile_error": compiled.get("compile_error"),
                                "compile_warnings": compiled.get("compile_warnings") or [],
                                "compile_source": compiled.get("compile_source") or engine_compatibility.get("compile_source") or "internal",
                                "compile_version": compiled.get("compile_version") or engine_compatibility.get("compile_version") or "rules_v2",
                                "compiled_query_internal": dict(compiled.get("compiled_query") or {}),
                                "compiled_opensearch_query": None,
                                "prefilter": {},
                                "required_fields": list(compiled.get("sigma_required_fields") or engine_compatibility.get("required_fields") or []),
                                "supported_features": list(compiled.get("supported_features") or engine_compatibility.get("supported_features") or []),
                                "unsupported_features": list(compiled.get("unsupported_features") or engine_compatibility.get("unsupported_features") or []),
                                "rule_hash": rendered_hash,
                            },
                        )
                        action, saved_rule = _upsert_imported_rule(db, rule=rule, import_run_id=run.id, source_pack=pack_name, existing=existing_rule)
                        if action == "imported":
                            imported_count += 1
                            created_rule_ids.append(saved_rule.id)
                            imported_rules.append(saved_rule)
                        elif action == "updated":
                            updated_count += 1
                            updated_rule_ids.append(saved_rule.id)
                            imported_rules.append(saved_rule)
                        else:
                            duplicate_count += 1
                            duplicate_rule_ids.append(saved_rule.id)
                        existing_rules[identity] = saved_rule
                        run.processed_rules += 1
                        writes_dirty = True
                    except Exception as exc:  # noqa: BLE001
                        invalid_count += 1
                        run.processed_rules += 1
                        invalid_items.append({"file": name, "engine": "sigma", "reason": _safe_error(exc)})
                        errors.append(f"{name}: {_safe_error(exc)}")
                        writes_dirty = True
                run.status = RuleImportRunStatus.saving
                run.current_phase = "saving_rules"
                run.total_rules_found = total_rules_found
                run.imported_count = imported_count
                run.updated_count = updated_count
                run.duplicate_count = duplicate_count
                run.invalid_count = invalid_count
                run.compiled_count = compiled_count
                run.unsupported_count = unsupported_count
                run.warning_count = len(warnings)
                run.error_count = len(errors)
                persist_progress(force=True)
                continue
            if file_type == "yara":
                run.status = RuleImportRunStatus.validating
                run.current_phase = "validating_yara"
                writes_dirty = True
                validation_started = time.perf_counter()
                validation = validate_yara_content(content)
                perf["compile_seconds"] = perf.get("compile_seconds", 0.0) + (time.perf_counter() - validation_started)
                rules_count = len(detect_yara_rules(content))
                total_rules_found += max(rules_count, 1)
                if not validation.get("valid") and validation.get("available", True):
                    invalid_count += 1
                    invalid_items.append({"file": name, "engine": "yara", "reason": "; ".join(validation.get("errors") or [])})
                    errors.append(f"{name}: {'; '.join(validation.get('errors') or [])}")
                    run.invalid_count = invalid_count
                    run.error_count = len(errors)
                    persist_progress()
                    continue
                if not validation.get("available"):
                    warnings.append("YARA validation is limited because compiler is not available.")
                classification = classify_yara_import(content, name)
                mode = _resolve_yara_import_mode(import_mode, int(classification["rules_count"]))
                tags = ["yara_forge"] if str(classification.get("metadata", {}).get("package", "")).lower() == "yara-forge" else []
                if mode == "rule_pack" and int(classification["rules_count"]) > 1:
                    total_yara_rules_inside += int(classification["rules_count"])
                    rule_set = _build_rule_set_from_import(
                        filename=name,
                        content=content,
                        case_id=case_id,
                        namespace=namespace,
                        enabled=enabled,
                        tags=tags,
                        metadata={**classification["metadata"], "rules_count": int(classification["rules_count"])},
                    )
                    existing_rule_set = existing_rule_sets.get((rule_set.name or "").strip().lower())
                    action, saved_rule_set = _upsert_imported_rule_set(db, rule_set=rule_set, import_run_id=run.id, source_pack=pack_name, existing=existing_rule_set)
                    if action == "imported":
                        imported_count += 1
                        imported_rule_sets.append(saved_rule_set)
                    elif action == "updated":
                        updated_count += 1
                        imported_rule_sets.append(saved_rule_set)
                    else:
                        duplicate_count += 1
                    existing_rule_sets[(saved_rule_set.name or "").strip().lower()] = saved_rule_set
                    run.processed_rules += 1
                    writes_dirty = True
                    persist_progress(force=True)
                    continue
                for yara_rule_name, yara_rule_content in split_yara_rules(content, name):
                    if cancel_if_requested("Cancel requested while validating YARA rules."):
                        return _reload_import_run(db, run.id) or run, imported_rules, imported_rule_sets
                    content_hash = _rule_content_hash(yara_rule_content)
                    identity = _rule_identity_from_values(RuleEngine.yara, yara_rule_name, content_hash)
                    existing_rule = existing_rules.get(identity)
                    if existing_rule and (existing_rule.content_hash or "") == content_hash:
                        existing_metadata = dict(existing_rule.metadata_json or {})
                        existing_metadata.update(
                            {
                                "import_run_id": run.id,
                                "source_pack": pack_name,
                                "last_import_status": "duplicate",
                            }
                        )
                        existing_rule.metadata_json = existing_metadata
                        duplicate_count += 1
                        duplicate_rule_ids.append(existing_rule.id)
                        run.processed_rules += 1
                        writes_dirty = True
                        continue
                    rule = Rule(
                        case_id=case_id,
                        name=yara_rule_name,
                        title=yara_rule_name,
                        engine=RuleEngine.yara,
                        namespace=namespace or _default_namespace(name, namespace, RuleEngine.yara),
                        source="uploaded",
                        description=f"Imported from {name}",
                        content=yara_rule_content,
                        content_hash=_rule_content_hash(yara_rule_content),
                        enabled=enabled,
                        severity=None,
                        status="valid" if validation.get("valid") else "invalid",
                        tags=tags,
                        validation_errors=list(validation.get("errors") or []),
                        metadata_json={
                            "rule_names": [yara_rule_name],
                            "external_rule_id": yara_rule_name,
                            "source_filename": name,
                            "validation_status": "valid" if validation.get("valid") else ("not_compiled" if not validation.get("available") else "invalid"),
                        },
                    )
                    action, saved_rule = _upsert_imported_rule(db, rule=rule, import_run_id=run.id, source_pack=pack_name, existing=existing_rule)
                    if action == "imported":
                        imported_count += 1
                        created_rule_ids.append(saved_rule.id)
                        imported_rules.append(saved_rule)
                    elif action == "updated":
                        updated_count += 1
                        updated_rule_ids.append(saved_rule.id)
                        imported_rules.append(saved_rule)
                    else:
                        duplicate_count += 1
                        duplicate_rule_ids.append(saved_rule.id)
                    existing_rules[identity] = saved_rule
                    run.processed_rules += 1
                    writes_dirty = True
                run.status = RuleImportRunStatus.saving
                run.current_phase = "saving_rules"
                run.total_rules_found = total_rules_found
                run.imported_count = imported_count
                run.updated_count = updated_count
                run.duplicate_count = duplicate_count
                run.invalid_count = invalid_count
                run.warning_count = len(warnings)
                run.error_count = len(errors)
                persist_progress(force=True)
                continue
        final_status = RuleImportRunStatus.completed_with_warnings if (warnings or errors or invalid_items or unsupported_items) else RuleImportRunStatus.completed
        run.engine = "mixed" if len(detected_engine_counts) > 1 else (next(iter(detected_engine_counts.keys()), "unknown"))
        run.status = final_status
        run.current_phase = "completed"
        run.finished_at = _utc_iso_now()
        run.elapsed_seconds = max(0.0, (datetime.fromisoformat(run.finished_at) - datetime.fromisoformat(started_at)).total_seconds())
        run.processed_files = len(entries)
        run.total_rules_found = total_rules_found
        run.processed_rules = max(run.processed_rules, total_rules_found)
        run.imported_count = imported_count
        run.updated_count = updated_count
        run.duplicate_count = duplicate_count
        run.skipped_count = skipped_count
        run.invalid_count = invalid_count
        run.compiled_count = compiled_count
        run.unsupported_count = unsupported_count
        run.warning_count = len(warnings)
        run.error_count = len(errors)
        run.current_file = None
        run.last_error = errors[0] if errors else None
        run.warnings_summary = warnings[:100]
        run.errors_summary = errors[:100]
        run.created_rule_ids = created_rule_ids
        run.updated_rule_ids = updated_rule_ids
        run.duplicate_rule_ids = duplicate_rule_ids
        run.invalid_items = invalid_items[:500]
        run.unsupported_items = unsupported_items[:500]
        total_seconds = max(run.elapsed_seconds or 0.0, 0.001)
        perf["total_seconds"] = total_seconds
        perf["files_per_second"] = round(run.processed_files / total_seconds, 3)
        perf["rules_per_second"] = round((run.processed_rules or total_rules_found) / total_seconds, 3)
        run.details_json = {
            "detected_engine_counts": detected_engine_counts,
            "sample_imported": [rule.name for rule in imported_rules[:10]] + [f"{item.name} — {item.rules_count} rules" for item in imported_rule_sets[:10]],
            "sigma_rules_by_product": sigma_by_product,
            "sigma_rules_by_category": sigma_by_category,
            "unsupported_condition_count": unsupported_condition_count,
            "compile_error_count": compile_error_count,
            "sigma_engine_coverage_report": {
                "total_rules": total_rules_found,
                "executable_by_current_engine": sigma_executable_count,
                "not_executable_by_current_engine": sigma_not_executable_count,
                "newly_supported_condition_1_of": sigma_newly_supported_1_of,
                "newly_supported_condition_all_of": sigma_newly_supported_all_of,
                "unsupported_by_feature": sigma_unsupported_by_feature,
                "examples_by_feature": sigma_coverage_examples,
            },
            "pysigma_evaluation": pysigma_capabilities(),
            "total_yara_rules_inside": total_yara_rules_inside,
            "ignored_macos_metadata_count": sum(1 for item in warnings if "macOS metadata" in item),
            "performance": perf,
        }
        perf["db_write_seconds"] = perf.get("db_write_seconds", 0.0) + 0.0
        _persist_import_run(db, run)
        return run, imported_rules, imported_rule_sets
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        run.status = RuleImportRunStatus.failed
        run.current_phase = "failed"
        run.finished_at = _utc_iso_now()
        run.elapsed_seconds = max(0.0, (datetime.fromisoformat(run.finished_at) - datetime.fromisoformat(started_at)).total_seconds())
        run.last_error = _safe_error(exc)
        run.error_count = max(1, run.error_count)
        run.errors_summary = [run.last_error]
        db.add(run)
        db.commit()
        db.refresh(run)
        return run, imported_rules, imported_rule_sets


@router.get("/api/rules", response_model=RuleListResponse)
def list_rules(
    case_id: str | None = None,
    engine: str | None = None,
    severity: str | None = None,
    namespace: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    enabled: bool | None = None,
    scope: str = Query("all", pattern="^(global|case|all)$"),
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> RuleListResponse:
    query = db.query(Rule)
    query = _apply_rule_filters(
        query,
        case_id=case_id,
        engine=engine,
        severity=severity,
        namespace=namespace,
        import_run_id=import_run_id,
        source_pack=source_pack,
        enabled=enabled,
        scope=scope,
        search=search,
    )
    total = query.count()
    items = query.order_by(Rule.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return RuleListResponse(total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0, items=items)


def _apply_rule_filters(
    query,
    *,
    case_id: str | None,
    engine: str | None,
    severity: str | None,
    namespace: str | None,
    import_run_id: str | None,
    source_pack: str | None,
    enabled: bool | None,
    scope: str,
    search: str | None,
):
    if engine:
        query = query.filter(Rule.engine == RuleEngine(engine))
    if severity:
        query = query.filter(Rule.severity == severity)
    if namespace:
        query = query.filter(Rule.namespace == namespace)
    if import_run_id:
        query = query.filter(Rule.metadata_json["import_run_id"].as_string() == import_run_id)
    if source_pack:
        query = query.filter(Rule.metadata_json["source_pack"].as_string() == source_pack)
    if enabled is not None:
        query = query.filter(Rule.enabled.is_(enabled))
    if case_id and scope == "case":
        query = query.filter(Rule.case_id == case_id)
    elif case_id and scope == "all":
        query = query.filter((Rule.case_id == case_id) | (Rule.case_id.is_(None)))
    elif scope == "global":
        query = query.filter(Rule.case_id.is_(None))
    elif scope == "case":
        query = query.filter(Rule.case_id.is_not(None))
    if search:
        token = f"%{search.strip()}%"
        query = query.filter((Rule.name.ilike(token)) | (Rule.description.ilike(token)) | (Rule.content.ilike(token)))
    return query


def _apply_rule_set_filters(
    query,
    *,
    case_id: str | None,
    engine: str | None,
    severity: str | None,
    namespace: str | None,
    import_run_id: str | None,
    source_pack: str | None,
    enabled: bool | None,
    scope: str,
    search: str | None,
):
    if engine:
        query = query.filter(RuleSet.engine == RuleEngine(engine))
    if namespace:
        query = query.filter(RuleSet.namespace == namespace)
    if import_run_id:
        query = query.filter(RuleSet.metadata_json["import_run_id"].as_string() == import_run_id)
    if source_pack:
        query = query.filter(RuleSet.metadata_json["source_pack"].as_string() == source_pack)
    if severity:
        query = query.filter(RuleSet.severity == severity)
    if enabled is not None:
        query = query.filter(RuleSet.enabled.is_(enabled))
    if case_id and scope == "case":
        query = query.filter(RuleSet.case_id == case_id)
    elif case_id and scope == "all":
        query = query.filter((RuleSet.case_id == case_id) | (RuleSet.case_id.is_(None)))
    elif scope == "global":
        query = query.filter(RuleSet.case_id.is_(None))
    elif scope == "case":
        query = query.filter(RuleSet.case_id.is_not(None))
    if search:
        token = f"%{search.strip()}%"
        query = query.filter((RuleSet.name.ilike(token)) | (RuleSet.description.ilike(token)) | (RuleSet.source_filename.ilike(token)))
    return query


def _rule_is_builtin_heuristic(rule: Rule) -> bool:
    return rule.engine == RuleEngine.heuristic and (rule.source or "builtin") == "builtin"


RULE_LIBRARY_DELETE_CONFIRMATION = "DELETE GLOBAL RULE LIBRARY"
RULES_DELETE_CONFIRMATION = "DELETE RULES"
IMPORTED_RULES_DELETE_CONFIRMATION = "DELETE IMPORTED RULES"
RULE_PACKS_DELETE_CONFIRMATION = "DELETE RULE PACKS"
MASS_RULE_DELETE_THRESHOLD = 25
SIGMA_GLOBAL_PROMOTION_CONFIRMATION = "PROMOTE SIGMA RULES TO GLOBAL"
SIGMA_GENERIC_MAPPING_FIELDS = {"search_text", "message", "content", "summary", "title"}
SIGMA_GENERIC_SIGMA_FIELDS = {"ScriptBlockText", "Details", "Url", "DestinationHostname"}
SIGMA_KNOWN_LOGSOURCE_CATEGORIES = {
    "process_creation",
    "file_event",
    "file_create",
    "registry_set",
    "network_connection",
    "dns_query",
    "image_load",
    "pipe_created",
    "ps_script",
    "powershell",
    "driver_load",
    "process_access",
    "create_remote_thread",
}
SIGMA_KNOWN_LOGSOURCE_SERVICES = {
    "security",
    "sysmon",
    "powershell",
    "powershell-classic",
    "defender",
    "taskscheduler",
    "wmi",
}


def _json_safe(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, RuleEngine):
        return value.value
    return str(value)


def _rule_scope_filter(query, *, case_id: str | None, scope: str):
    if scope == "global":
        return query.filter(Rule.case_id.is_(None))
    if scope == "case":
        return query.filter(Rule.case_id == case_id) if case_id else query.filter(Rule.case_id.is_not(None))
    if case_id:
        return query.filter((Rule.case_id == case_id) | (Rule.case_id.is_(None)))
    return query


def _dedupe_rules_for_execution(rules: list[Rule]) -> tuple[list[Rule], dict]:
    grouped: dict[tuple[str, str], list[Rule]] = {}
    for rule in rules:
        grouped.setdefault(_rule_identity(rule), []).append(rule)
    selected: list[Rule] = []
    suppressed: list[str] = []
    for _, candidates in grouped.items():
        if len(candidates) == 1:
            selected.append(candidates[0])
            continue
        case_rules = [item for item in candidates if item.case_id]
        global_rules = [item for item in candidates if not item.case_id]
        chosen = candidates[0]
        if case_rules and global_rules:
            case_rule = sorted(case_rules, key=lambda item: str(item.updated_at or ""), reverse=True)[0]
            identical_global = next((item for item in global_rules if (item.content_hash or "") == (case_rule.content_hash or "")), None)
            chosen = identical_global or case_rule
        elif case_rules:
            chosen = sorted(case_rules, key=lambda item: str(item.updated_at or ""), reverse=True)[0]
        elif global_rules:
            chosen = sorted(global_rules, key=lambda item: str(item.updated_at or ""), reverse=True)[0]
        selected.append(chosen)
        suppressed.extend([item.id for item in candidates if item.id != chosen.id])
    return selected, {
        "total_available": len(rules),
        "selected_for_execution": len(selected),
        "duplicates_suppressed": len(suppressed),
        "suppressed_rule_ids": suppressed[:100],
    }


def _sigma_rule_support_record(rule: Rule) -> dict:
    metadata = dict(rule.metadata_json or {})
    compilation = dict(metadata.get("sigma_compilation") or {})
    engine_compatibility = dict(metadata.get("engine_compatibility") or compilation.get("engine_compatibility") or {})
    logsource = dict(compilation.get("sigma_logsource") or engine_compatibility.get("logsource") or metadata.get("logsource") or {})
    compile_status = str(compilation.get("compile_status") or metadata.get("compile_status") or "").strip()
    compile_error = compilation.get("compile_error") or metadata.get("compile_error")
    executable = bool(engine_compatibility.get("executable_by_current_engine")) if engine_compatibility else compile_status == "compiled"
    required_fields = [
        str(item)
        for item in (
            compilation.get("sigma_required_fields")
            or engine_compatibility.get("required_fields")
            or metadata.get("required_fields")
            or []
        )
    ]
    field_mappings = dict(compilation.get("sigma_field_mappings") or {})
    unsupported_features = [str(item) for item in (compilation.get("unsupported_features") or engine_compatibility.get("unsupported_features") or [])]
    compile_warnings = [str(item) for item in (compilation.get("compile_warnings") or engine_compatibility.get("expansion_warnings") or [])]

    product = str(logsource.get("product") or "unknown").strip().lower() or "unknown"
    category = str(logsource.get("category") or "unknown").strip().lower() or "unknown"
    service = str(logsource.get("service") or "unknown").strip().lower() or "unknown"

    risk_reasons: list[str] = []
    if not logsource:
        risk_reasons.append("missing_logsource")
    elif product == "unknown" and category == "unknown" and service == "unknown":
        risk_reasons.append("unknown_logsource")
    if category not in {"unknown", ""} and category not in SIGMA_KNOWN_LOGSOURCE_CATEGORIES:
        risk_reasons.append(f"unknown_category:{category}")
    if service not in {"unknown", ""} and service not in SIGMA_KNOWN_LOGSOURCE_SERVICES:
        risk_reasons.append(f"unknown_service:{service}")
    if not required_fields:
        risk_reasons.append("no_required_fields")

    generic_mapping_fields: dict[str, list[str]] = {}
    fallback_fields: list[str] = []
    for sigma_field, mapped in field_mappings.items():
        mapped_fields = [str(item) for item in (mapped or [])]
        if any(item in SIGMA_GENERIC_MAPPING_FIELDS for item in mapped_fields):
            fallback_fields.append(str(sigma_field))
        if str(sigma_field).split("|", 1)[0] in SIGMA_GENERIC_SIGMA_FIELDS and len(mapped_fields) > 1:
            generic_mapping_fields[str(sigma_field)] = mapped_fields
    if fallback_fields:
        risk_reasons.append("generic_search_text_fallback")
    if generic_mapping_fields:
        risk_reasons.append("generic_multi_field_mapping")

    if compile_status != "compiled" or not executable or compile_error:
        support_status = "unsupported"
    elif risk_reasons:
        support_status = "partially_supported"
    else:
        support_status = "fully_supported"

    mapped_field_records: list[dict] = []
    missing_field_mappings: list[str] = []
    for sigma_field in required_fields:
        mapped_fields = [str(item) for item in (field_mappings.get(sigma_field) or [])]
        base_field = sigma_field.split("|", 1)[0]
        field_status = "mapped"
        confidence = "high"
        if not mapped_fields:
            field_status = "missing"
            confidence = "low"
            missing_field_mappings.append(base_field)
        elif any(item in SIGMA_GENERIC_MAPPING_FIELDS for item in mapped_fields):
            field_status = "partial"
            confidence = "low"
        elif mapped_fields == [base_field] and "." not in base_field:
            field_status = "missing"
            confidence = "low"
            missing_field_mappings.append(base_field)
        elif len(mapped_fields) > 1:
            confidence = "medium"
        mapped_field_records.append(
            {
                "sigma_field": sigma_field,
                "normalized_fields": mapped_fields,
                "status": field_status,
                "confidence": confidence,
            }
        )

    event_ids = list(SIGMA_EVENT_ID_HINTS.get(category, []))
    channels = []
    if service in SIGMA_SERVICE_CHANNEL_HINTS:
        channels.extend(SIGMA_SERVICE_CHANNEL_HINTS.get(service) or [])
    if category in SIGMA_CATEGORY_EVENT_TYPE_HINTS:
        event_types = list(SIGMA_CATEGORY_EVENT_TYPE_HINTS.get(category) or [])
    else:
        event_types = [] if category == "unknown" else [category]
    unsupported_reasons = []
    if compile_status != "compiled":
        unsupported_reasons.append(compile_status or "not_compiled")
    if compile_error:
        unsupported_reasons.append(str(compile_error))
    unsupported_reasons.extend(unsupported_features)

    return {
        "rule_id": rule.id,
        "name": rule.name,
        "title": rule.title,
        "case_id": rule.case_id,
        "enabled": bool(rule.enabled),
        "support_status": support_status,
        "status": "disabled" if not rule.enabled else support_status,
        "severity": rule.severity,
        "compile_status": compile_status or "unknown",
        "compile_error": compile_error,
        "executable_by_current_engine": executable,
        "logsource": {"product": product, "category": category, "service": service},
        "required_event_context": {
            "event_ids": event_ids,
            "event_types": event_types,
            "channels": channels,
        },
        "required_fields": required_fields,
        "field_mapping_details": mapped_field_records,
        "field_mappings": field_mappings,
        "missing_field_mappings": sorted(dict.fromkeys(missing_field_mappings)),
        "unsupported_features": unsupported_features,
        "unsupported_reasons": sorted(dict.fromkeys(unsupported_reasons)),
        "compile_warnings": compile_warnings,
        "false_positive_risk_reasons": sorted(dict.fromkeys(risk_reasons)),
        "risky_reasons": sorted(dict.fromkeys(risk_reasons)),
        "generic_mapping_fields": generic_mapping_fields,
    }


def _build_sigma_library_coverage_report(db: Session, *, case_id: str | None, scope: str) -> dict:
    query = db.query(Rule).filter(Rule.engine == RuleEngine.sigma)
    query = _rule_scope_filter(query, case_id=case_id, scope=scope)
    rules = query.all()
    by_support: dict[str, int] = {"fully_supported": 0, "partially_supported": 0, "unsupported": 0, "disabled": 0}
    by_product: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_service: dict[str, int] = {}
    by_compile_status: dict[str, int] = {}
    by_risk_reason: dict[str, int] = {}
    missing_field_mappings: dict[str, int] = {}
    false_positive_risk_count = 0
    mapped_fields: dict[str, int] = {}
    generic_mapping_fields: dict[str, int] = {}
    false_positive_examples: list[dict] = []
    unsupported_examples: list[dict] = []

    for rule in rules:
        record = _sigma_rule_support_record(rule)
        status_value = str(record["support_status"])
        by_support[status_value] = by_support.get(status_value, 0) + 1
        logsource = dict(record["logsource"])
        product = str(logsource.get("product") or "unknown")
        category = str(logsource.get("category") or "unknown")
        service = str(logsource.get("service") or "unknown")
        by_product[product] = by_product.get(product, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        by_service[service] = by_service.get(service, 0) + 1
        compile_status = str(record.get("compile_status") or "unknown")
        by_compile_status[compile_status] = by_compile_status.get(compile_status, 0) + 1
        risk_reasons = record.get("false_positive_risk_reasons") or []
        if risk_reasons:
            false_positive_risk_count += 1
        for reason in risk_reasons:
            by_risk_reason[reason] = by_risk_reason.get(reason, 0) + 1
        for sigma_field, mapped in dict(record.get("field_mappings") or {}).items():
            for field in mapped or []:
                field_name = str(field)
                mapped_fields[field_name] = mapped_fields.get(field_name, 0) + 1
        for field_name in record.get("missing_field_mappings") or []:
            missing_field_mappings[str(field_name)] = missing_field_mappings.get(str(field_name), 0) + 1
        for sigma_field in dict(record.get("generic_mapping_fields") or {}).keys():
            generic_mapping_fields[sigma_field] = generic_mapping_fields.get(sigma_field, 0) + 1
        if record.get("false_positive_risk_reasons") and len(false_positive_examples) < 10:
            false_positive_examples.append(
                {
                    "rule_id": record["rule_id"],
                    "name": record["name"],
                    "title": record["title"],
                    "support_status": status_value,
                    "reasons": record["false_positive_risk_reasons"],
                    "logsource": record["logsource"],
                    "required_fields": record["required_fields"],
                }
            )
        if status_value == "unsupported" and len(unsupported_examples) < 10:
            unsupported_examples.append(
                {
                    "rule_id": record["rule_id"],
                    "name": record["name"],
                    "title": record["title"],
                    "compile_status": record["compile_status"],
                    "compile_error": record["compile_error"],
                    "unsupported_features": record["unsupported_features"],
                }
            )

    total = len(rules)
    global_count = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id.is_(None)).count()
    case_count = (
        db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id == case_id).count()
        if case_id
        else db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id.is_not(None)).count()
    )
    return {
        "scope": scope,
        "case_id": case_id,
        "total": total,
        "fully_supported": by_support.get("fully_supported", 0),
        "partially_supported": by_support.get("partially_supported", 0),
        "partial": by_support.get("partially_supported", 0),
        "unsupported": by_support.get("unsupported", 0),
        "by_support_status": by_support,
        "by_product": dict(sorted(by_product.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_service": dict(sorted(by_service.items())),
        "by_compile_status": dict(sorted(by_compile_status.items())),
        "false_positive_risk_count": false_positive_risk_count,
        "by_false_positive_risk_reason": dict(sorted(by_risk_reason.items())),
        "false_positive_risk_examples": false_positive_examples,
        "unsupported_examples": unsupported_examples,
        "field_mapping": {
            "mapped_fields": dict(sorted(mapped_fields.items())),
            "missing_field_mappings": dict(sorted(missing_field_mappings.items(), key=lambda item: item[1], reverse=True)),
            "generic_mapping_fields": dict(sorted(generic_mapping_fields.items())),
        },
        "missing_field_mappings": dict(sorted(missing_field_mappings.items(), key=lambda item: item[1], reverse=True)),
        "top_missing_fields": [
            {"field": key, "count": value}
            for key, value in sorted(missing_field_mappings.items(), key=lambda item: item[1], reverse=True)[:20]
        ],
        "recommended_parser_followups": [
            {"field": key, "count": value, "recommendation": f"Normalize Sigma field {key} into searchable event documents."}
            for key, value in sorted(missing_field_mappings.items(), key=lambda item: item[1], reverse=True)[:10]
        ],
        "rules_scope": {
            "global_sigma_rules": global_count,
            "case_sigma_rules": case_count,
            "available_for_case": total,
        },
        "generated_at": _utc_iso_now(),
    }


def _create_sigma_rule_library_snapshot(db: Session, *, label: str, case_id: str | None, scope: str) -> dict:
    query = db.query(Rule).filter(Rule.engine == RuleEngine.sigma)
    query = _rule_scope_filter(query, case_id=case_id, scope=scope)
    rules = query.order_by(Rule.case_id.asc().nullsfirst(), Rule.name.asc()).all()
    snapshot_dir = settings.backend_data_dir / "rule_library_snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or "sigma_rules").strip("_") or "sigma_rules"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{safe_label}_{scope}_{timestamp}.json"
    path = snapshot_dir / filename
    payload = {
        "snapshot_type": "sigma_rule_library",
        "label": label,
        "case_id": case_id,
        "scope": scope,
        "created_at": _utc_iso_now(),
        "count": len(rules),
        "coverage": _build_sigma_library_coverage_report(db, case_id=case_id, scope=scope),
        "rules": [
            {
                "id": rule.id,
                "case_id": rule.case_id,
                "name": rule.name,
                "title": rule.title,
                "engine": rule.engine.value,
                "namespace": rule.namespace,
                "source": rule.source,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "content_hash": rule.content_hash,
                "content": rule.content,
                "metadata_json": rule.metadata_json or {},
                "created_at": rule.created_at,
                "updated_at": rule.updated_at,
            }
            for rule in rules
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, default=_json_safe).encode("utf-8")
    path.write_bytes(encoded)
    return {
        "created": True,
        "path": str(path),
        "checksum": hashlib.sha256(encoded).hexdigest(),
        "count": len(rules),
        "scope": scope,
        "case_id": case_id,
        "created_at": payload["created_at"],
    }


@router.get("/api/rules/sigma/coverage")
def get_sigma_library_coverage(
    case_id: str | None = None,
    scope: str = Query("all", pattern="^(global|case|all)$"),
    db: Session = Depends(get_db),
) -> dict:
    return _build_sigma_library_coverage_report(db, case_id=case_id, scope=scope)


@router.get("/api/rules/coverage/summary")
def get_rule_coverage_summary(
    case_id: str | None = None,
    engine: str = Query("sigma", pattern="^sigma$"),
    scope: str = Query("all", pattern="^(global|case|all)$"),
    db: Session = Depends(get_db),
) -> dict:
    report = _build_sigma_library_coverage_report(db, case_id=case_id, scope=scope)
    return {
        **report,
        "compiled": int(report.get("by_compile_status", {}).get("compiled") or 0),
        "unsupported_import": int(report.get("unsupported") or 0),
        "unsupported_logsources": {
            key: value
            for key, value in (report.get("by_false_positive_risk_reason") or {}).items()
            if str(key).startswith("unknown_category:") or str(key).startswith("unknown_service:")
        },
    }


@router.get("/api/rules/coverage")
def get_rule_coverage(
    case_id: str | None = None,
    engine: str = Query("sigma", pattern="^sigma$"),
    scope: str = Query("all", pattern="^(global|case|all)$"),
    status_filter: str | None = Query(None, alias="status"),
    logsource: str | None = None,
    missing_field: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(Rule).filter(Rule.engine == RuleEngine.sigma)
    query = _rule_scope_filter(query, case_id=case_id, scope=scope)
    if severity:
        query = query.filter(Rule.severity == severity)
    records = [_sigma_rule_support_record(rule) for rule in query.order_by(Rule.name.asc()).all()]
    if status_filter:
        records = [item for item in records if item.get("support_status") == status_filter or item.get("status") == status_filter]
    if logsource:
        token = logsource.strip().lower()
        records = [
            item
            for item in records
            if token in {
                str(item.get("logsource", {}).get("product") or "").lower(),
                str(item.get("logsource", {}).get("category") or "").lower(),
                str(item.get("logsource", {}).get("service") or "").lower(),
            }
        ]
    if missing_field:
        token = missing_field.strip().lower()
        records = [item for item in records if token in {str(value).lower() for value in item.get("missing_field_mappings") or []}]
    total = len(records)
    offset = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
        "items": records[offset : offset + page_size],
    }


@router.post("/api/rules/sigma/snapshot")
def create_sigma_library_snapshot(payload: dict = Body(default_factory=dict), db: Session = Depends(get_db)) -> dict:
    scope = str(payload.get("scope") or "all")
    if scope not in {"global", "case", "all"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="scope must be global, case or all")
    case_id = str(payload.get("case_id") or "").strip() or None
    label = str(payload.get("label") or "sigma_rules_snapshot")
    return _create_sigma_rule_library_snapshot(db, label=label, case_id=case_id, scope=scope)


@router.post("/api/rules/sigma/promote-case-to-global")
def promote_case_sigma_rules_to_global(payload: dict = Body(default_factory=dict), db: Session = Depends(get_db)) -> dict:
    case_id = str(payload.get("case_id") or "").strip()
    if not case_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="case_id is required")
    confirm = str(payload.get("confirm") or "").strip()
    mode = str(payload.get("mode") or "copy_keep_case").strip()
    if mode not in {"copy_keep_case", "convert_to_global"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="mode must be copy_keep_case or convert_to_global")
    case_rules = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id == case_id).all()
    if len(case_rules) >= MASS_RULE_DELETE_THRESHOLD and confirm != SIGMA_GLOBAL_PROMOTION_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Type {SIGMA_GLOBAL_PROMOTION_CONFIRMATION!r} to promote {len(case_rules)} case-scoped Sigma rules to global.",
        )
    global_before = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id.is_(None)).count()
    before_snapshot = _create_sigma_rule_library_snapshot(db, label=f"sigma_before_promote_{case_id}", case_id=case_id, scope="case") if case_rules else None
    global_identities = {_rule_identity(item): item for item in db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id.is_(None)).all()}
    promoted = 0
    skipped_duplicates = 0
    duplicate_rule_ids: list[str] = []
    promoted_rule_ids: list[str] = []
    now = _utc_iso_now()
    for rule in case_rules:
        identity = _rule_identity(rule)
        if identity in global_identities:
            skipped_duplicates += 1
            duplicate_rule_ids.append(rule.id)
            continue
        metadata = dict(rule.metadata_json or {})
        if mode == "convert_to_global":
            metadata["promoted_to_global"] = True
            metadata["promoted_from_case_id"] = case_id
            metadata["promoted_at"] = now
            metadata["promotion_mode"] = mode
            rule.metadata_json = metadata
            rule.case_id = None
            db.add(rule)
            global_rule = rule
        else:
            metadata["promoted_to_global"] = True
            metadata["promoted_from_case_id"] = case_id
            metadata["promoted_from_rule_id"] = rule.id
            metadata["promoted_at"] = now
            metadata["promotion_mode"] = mode
            global_rule = Rule(
                case_id=None,
                rule_set_id=None,
                name=rule.name,
                title=rule.title,
                engine=rule.engine,
                namespace=rule.namespace,
                source=rule.source,
                description=rule.description,
                author=rule.author,
                rule_version=rule.rule_version,
                level=rule.level,
                content=rule.content,
                content_hash=rule.content_hash,
                enabled=rule.enabled,
                severity=rule.severity,
                status=rule.status,
                references=list(rule.references or []),
                false_positives=list(rule.false_positives or []),
                tags=list(rule.tags or []),
                mitre=list(rule.mitre or []),
                validation_errors=list(rule.validation_errors or []),
                metadata_json=metadata,
            )
            db.add(global_rule)
            db.flush()
        promoted_rule_ids.append(global_rule.id)
        global_identities[identity] = global_rule
        promoted += 1
    db.commit()
    global_after = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id.is_(None)).count()
    case_after = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.case_id == case_id).count()
    after_snapshot = _create_sigma_rule_library_snapshot(db, label=f"sigma_after_promote_{case_id}", case_id=None, scope="global")
    return {
        "case_id": case_id,
        "matched": len(case_rules),
        "promoted": promoted,
        "skipped_duplicates": skipped_duplicates,
        "duplicate_rule_ids": duplicate_rule_ids[:50],
        "promoted_rule_ids": promoted_rule_ids[:50],
        "mode": mode,
        "global_total_before": global_before,
        "global_total_after": global_after,
        "case_total_after": case_after,
        "confirmation_required": SIGMA_GLOBAL_PROMOTION_CONFIRMATION,
        "before_snapshot": before_snapshot,
        "after_snapshot": after_snapshot,
    }


def _rules_touch_global_library(items: list[Rule]) -> bool:
    return any(item.case_id is None for item in items)


def _rule_sets_touch_global_library(items: list[RuleSet]) -> bool:
    return any(item.case_id is None for item in items)


def _count_rule_set_children(db: Session, items: list[RuleSet]) -> int:
    ids = [item.id for item in items]
    if not ids:
        return 0
    return db.query(Rule).filter(Rule.rule_set_id.in_(ids)).count()


def _required_rule_delete_confirmation(payload: RuleBulkActionRequest, items: list[Rule]) -> str:
    mode = (payload.mode or "selected").strip().lower()
    if not items:
        return ""
    if len(items) > MASS_RULE_DELETE_THRESHOLD or _rules_touch_global_library(items):
        return RULE_LIBRARY_DELETE_CONFIRMATION
    if mode == "all_imported":
        return IMPORTED_RULES_DELETE_CONFIRMATION
    if mode == "matching":
        return RULES_DELETE_CONFIRMATION
    return ""


def _required_rule_set_delete_confirmation(db: Session, payload: RuleSetBulkDeleteRequest, items: list[RuleSet]) -> str:
    mode = (payload.mode or "selected").strip().lower()
    if not items:
        return ""
    child_count = _count_rule_set_children(db, items)
    if child_count > MASS_RULE_DELETE_THRESHOLD or _rule_sets_touch_global_library(items):
        return RULE_LIBRARY_DELETE_CONFIRMATION
    if mode != "selected" or child_count:
        return RULE_PACKS_DELETE_CONFIRMATION
    return ""


def _delete_confirmation_matches(provided: str | None, required: str) -> bool:
    if not required:
        return True
    if (provided or "") == required:
        return True
    return (provided or "") == RULE_LIBRARY_DELETE_CONFIRMATION


def _imported_rule_query(db: Session, *, engine: str | None, case_id: str | None, namespace: str | None, scope: str, search: str | None):
    query = db.query(Rule)
    query = _apply_rule_filters(
        query,
        case_id=case_id,
        engine=engine,
        severity=None,
        namespace=namespace,
        import_run_id=None,
        source_pack=None,
        enabled=None,
        scope=scope,
        search=search,
    )
    return query.filter(Rule.engine != RuleEngine.heuristic).filter((Rule.source == "uploaded") | (Rule.rule_set_id.is_not(None)))


def _resolve_rule_targets(db: Session, payload: RuleBulkActionRequest) -> list[Rule]:
    mode = (payload.mode or "selected").strip().lower()
    if mode == "selected":
        if not payload.rule_ids:
            return []
        return db.query(Rule).filter(Rule.id.in_(payload.rule_ids)).all()
    if mode == "matching":
        query = _apply_rule_filters(
            db.query(Rule),
            case_id=payload.case_id,
            engine=payload.engine,
            severity=payload.severity,
            namespace=payload.namespace,
            import_run_id=payload.import_run_id,
            source_pack=payload.source_pack,
            enabled=payload.enabled,
            scope=payload.scope,
            search=payload.search,
        )
        return query.all()
    if mode == "all_imported":
        query = _imported_rule_query(
            db,
            engine=None if payload.engine in {None, "", "all"} else payload.engine,
            case_id=payload.case_id,
            namespace=payload.namespace,
            scope=payload.scope,
            search=payload.search,
        )
        if payload.import_run_id:
            query = query.filter(Rule.metadata_json["import_run_id"].as_string() == payload.import_run_id)
        if payload.source_pack:
            query = query.filter(Rule.metadata_json["source_pack"].as_string() == payload.source_pack)
        return query.all()
    raise HTTPException(status_code=400, detail="Unsupported bulk rule mode")


def _resolve_rule_set_targets(db: Session, payload: RuleSetBulkDeleteRequest) -> list[RuleSet]:
    mode = (payload.mode or "selected").strip().lower()
    if mode == "selected":
        if not payload.pack_ids:
            return []
        return db.query(RuleSet).filter(RuleSet.id.in_(payload.pack_ids)).all()
    query = _apply_rule_set_filters(
        db.query(RuleSet),
        case_id=payload.case_id,
        engine=payload.engine,
        severity=None,
        namespace=payload.namespace,
        import_run_id=payload.import_run_id,
        source_pack=payload.source_pack,
        enabled=payload.enabled,
        scope=payload.scope,
        search=payload.search,
    )
    return query.all()


def _preview_rule_targets(items: list[Rule]) -> RuleBulkPreviewResponse:
    by_engine: dict[str, int] = {}
    by_source_pack: dict[str, int] = {}
    affected_packs: list[str] = []
    protected = 0
    for item in items:
        by_engine[item.engine.value] = by_engine.get(item.engine.value, 0) + 1
        source_pack = str((item.metadata_json or {}).get("source_pack") or "").strip()
        if source_pack:
            by_source_pack[source_pack] = by_source_pack.get(source_pack, 0) + 1
            if source_pack not in affected_packs:
                affected_packs.append(source_pack)
        if _rule_is_builtin_heuristic(item):
            protected += 1
    return RuleBulkPreviewResponse(
        matched=len(items),
        protected=protected,
        affected_packs=affected_packs,
        by_engine=by_engine,
        by_source_pack=by_source_pack,
    )


def _queued_or_running(status_value: RuleRunStatus) -> bool:
    return status_value in {RuleRunStatus.queued, RuleRunStatus.running}


def _apply_rule_run_filters(query, *, case_id: str | None, engine: str | None, statuses: list[str] | None):
    if case_id:
        query = query.filter(RuleRun.case_id == case_id)
    if engine:
        query = query.filter(RuleRun.engine == engine)
    normalized_statuses = [value for value in (statuses or []) if value]
    if normalized_statuses:
        query = query.filter(RuleRun.status.in_(normalized_statuses))
    return query


def _resolve_rule_run_targets(db: Session, payload: RuleRunBulkActionRequest | RuleRunBulkDeleteRequest) -> list[RuleRun]:
    mode = (payload.mode or "selected").strip().lower()
    if mode == "selected":
        run_ids = getattr(payload, "run_ids", []) or []
        if not run_ids:
            return []
        return db.query(RuleRun).filter(RuleRun.id.in_(run_ids)).all()
    query = _apply_rule_run_filters(
        db.query(RuleRun),
        case_id=getattr(payload, "case_id", None),
        engine=getattr(payload, "engine", None),
        statuses=getattr(payload, "statuses", None),
    )
    if getattr(payload, "older_than_minutes", None):
        cutoff = datetime.now(timezone.utc).timestamp() - int(payload.older_than_minutes or 0) * 60
        items = query.all()
        return [
            item
            for item in items
            if (
                (_parse_run_timestamp(item.heartbeat_at) or _parse_run_timestamp(item.started_at) or _parse_run_timestamp(item.created_at.isoformat()))
                and (_parse_run_timestamp(item.heartbeat_at) or _parse_run_timestamp(item.started_at) or _parse_run_timestamp(item.created_at.isoformat())).timestamp() <= cutoff
            )
        ]
    return query.all()


def _mark_run_stale(run: RuleRun, *, reason: str) -> None:
    metadata = dict(run.metadata_json or {})
    metadata["stale_reason"] = reason
    run.metadata_json = metadata
    run.status = RuleRunStatus.stale
    run.current_phase = "stale"
    run.finished_at = run.finished_at or utc_now().isoformat()
    run.last_error = reason[:2048]


def _run_is_active(run: RuleRun) -> bool:
    return run.status in {RuleRunStatus.queued, RuleRunStatus.running}


def _resolve_rule_ids_for_case_with_dedupe(db: Session, *, case_id: str, payload: RulesRunRequest) -> tuple[list[str], dict]:
    query = db.query(Rule)
    if payload.rule_ids:
        query = query.filter(Rule.id.in_(payload.rule_ids))
    else:
        engines = payload.rule_types or payload.engines or ([payload.engine] if payload.engine else [])
        if engines:
            query = query.filter(Rule.engine.in_(engines))
        query = _apply_rule_filters(
            query,
            case_id=case_id,
            engine=payload.engine,
            severity=payload.severity,
            namespace=payload.namespace,
            import_run_id=None,
            source_pack=None,
            enabled=payload.enabled if payload.enabled is not None else (None if payload.include_disabled else (True if payload.enabled_only else None)),
            scope=payload.scope,
            search=payload.search,
        )
    rules = query.all()
    selected, dedupe = _dedupe_rules_for_execution(rules)
    return [rule.id for rule in selected], dedupe


def _resolve_rule_ids_for_case(db: Session, *, case_id: str, payload: RulesRunRequest) -> list[str]:
    rule_ids, _ = _resolve_rule_ids_for_case_with_dedupe(db, case_id=case_id, payload=payload)
    return rule_ids


SMOKE_RECOMMENDED_TERMS = ("powershell", "encoded", "bypass", "psexec", "rundll32", "defender", "rubeus")


def _sigma_smoke_scope(payload: SigmaSmokeRequest) -> dict:
    return {"host": payload.host, "max_events": max(int(payload.max_events_per_rule or 5000), 1), "profile_sample_size": 1000}


def _sigma_smoke_rule_query(db: Session, payload: SigmaSmokeRequest):
    query = db.query(Rule).filter(Rule.engine == RuleEngine.sigma, Rule.enabled.is_(True))
    query = query.filter(or_(Rule.case_id.is_(None), Rule.case_id == payload.case_id))
    if payload.mode == "single_rule":
        if not payload.rule_id:
            raise HTTPException(status_code=400, detail="rule_id is required for single rule smoke tests.")
        return query.filter(Rule.id == payload.rule_id)
    if payload.rule_ids:
        query = query.filter(Rule.id.in_(payload.rule_ids))
    if payload.severity:
        query = query.filter(or_(Rule.severity == payload.severity, Rule.level == payload.severity))
    if payload.tag:
        token = f"%{payload.tag.strip()}%"
        query = query.filter(or_(Rule.content.ilike(token), Rule.namespace.ilike(token)))
    if payload.keyword:
        token = f"%{payload.keyword.strip()}%"
        query = query.filter(or_(Rule.name.ilike(token), Rule.title.ilike(token), Rule.description.ilike(token), Rule.content.ilike(token)))
    if payload.logsource:
        token = f"%{payload.logsource.strip()}%"
        query = query.filter(or_(Rule.content.ilike(token), Rule.namespace.ilike(token)))
    if payload.mode == "recommended":
        clauses = []
        for term in SMOKE_RECOMMENDED_TERMS:
            token = f"%{term}%"
            clauses.append(or_(Rule.name.ilike(token), Rule.title.ilike(token), Rule.content.ilike(token)))
        query = query.filter(or_(*clauses))
    return query


def _resolve_sigma_smoke_rules(db: Session, payload: SigmaSmokeRequest) -> list[Rule]:
    max_rules = min(max(int(payload.max_rules or 5), 1), 10)
    rules = _sigma_smoke_rule_query(db, payload).order_by(asc(Rule.name)).limit(max_rules + 1).all()
    if len(rules) > max_rules:
        if payload.mode == "recommended":
            return rules[:max_rules]
        raise HTTPException(status_code=400, detail=f"Sigma smoke is capped at {max_rules} rules. Narrow the subset before running.")
    if not rules:
        raise HTTPException(status_code=404, detail="No Sigma rules matched the smoke selection.")
    return rules


def _compile_sigma_smoke_rule(rule: Rule) -> tuple[dict | None, dict, list[str]]:
    try:
        sigma_rules = parse_sigma_rule(rule.content)
        if not sigma_rules:
            return None, {}, ["No Sigma rule found in content."]
        rule_data = sigma_rules[0]
        return compile_sigma_rule(rule_data), extract_sigma_metadata(rule_data), []
    except Exception as exc:  # noqa: BLE001
        return None, {}, [str(exc).splitlines()[0][:240]]


def _sigma_smoke_preflight_results(db: Session, payload: SigmaSmokeRequest, rules: list[Rule]) -> tuple[list[SigmaSmokeRuleResult], dict]:
    from app.workers.tasks import _build_sigma_case_profile_for_scope, _build_sigma_search_body

    profile = _build_sigma_case_profile_for_scope(payload.case_id, payload.evidence_id, _sigma_smoke_scope(payload))
    results: list[SigmaSmokeRuleResult] = []
    for rule in rules:
        compiled, metadata, warnings = _compile_sigma_smoke_rule(rule)
        if not compiled:
            results.append(SigmaSmokeRuleResult(rule_id=rule.id, rule_name=rule.name, title=rule.title, severity=rule.severity or rule.level, status="error", reason="compile_error", warnings=warnings, errors=warnings))
            continue
        preflight = preflight_compiled_sigma_rule(compiled, profile, enabled=rule.enabled)
        estimated_events = 0
        if str(preflight.get("status") or "").startswith("runnable"):
            scan_options = {
                **_sigma_smoke_scope(payload),
                "_sigma_compiled": compiled,
                "_sigma_prefilter": preflight.get("prefilter") or {},
                "sigma_run_mode": "fast_triage",
                "sigma_max_matches_per_rule": payload.max_detections_per_rule,
                "sigma_max_detections_per_rule": payload.max_detections_per_rule,
            }
            try:
                body = _build_sigma_search_body(payload.case_id, payload.evidence_id, rule, scan_options)
                estimated_events = int(count_documents(get_events_index(payload.case_id), body.get("query")).get("count", 0))
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"estimate_failed: {str(exc).splitlines()[0][:160]}")
        status = str(preflight.get("status") or "unsupported")
        smoke_status = "ready" if status.startswith("runnable") else "skipped_missing_fields" if status == "skipped_missing_fields" else "unsupported" if status.startswith("skipped_unsupported") else "skipped"
        results.append(
            SigmaSmokeRuleResult(
                rule_id=rule.id,
                rule_name=rule.name,
                title=rule.title,
                severity=rule.severity or rule.level,
                status=smoke_status,
                reason=str(preflight.get("reason") or status),
                scanned_events=estimated_events,
                expected_logsource=dict(preflight.get("logsource") or metadata.get("logsource") or {}),
                field_mappings=dict(compiled.get("sigma_field_mappings") or {}),
                required_fields=list(preflight.get("fields") or compiled.get("sigma_required_fields") or []),
                missing_fields=list(preflight.get("missing_fields") or []),
                warnings=warnings,
            )
        )
    return results, profile


def _sigma_smoke_summary(*, payload: SigmaSmokeRequest, results: list[SigmaSmokeRuleResult], run_id: str | None = None, preflight_only: bool = False, warnings: list[str] | None = None) -> SigmaSmokeResponse:
    return SigmaSmokeResponse(
        run_id=run_id,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        host=payload.host,
        mode=payload.mode,
        preflight_only=preflight_only,
        max_rules=min(max(int(payload.max_rules or 5), 1), 10),
        max_detections_per_rule=min(max(int(payload.max_detections_per_rule or 10), 1), 100),
        rules_selected=len(results),
        matched=sum(1 for item in results if item.status == "matched"),
        no_match=sum(1 for item in results if item.status == "no_match"),
        skipped=sum(1 for item in results if item.status.startswith("skipped")),
        unsupported=sum(1 for item in results if item.status == "unsupported"),
        errors=sum(1 for item in results if item.status == "error"),
        created_detections=sum(item.created_detections for item in results),
        rules=results,
        warnings=warnings or [],
    )


@router.post("/api/rules/sigma/smoke/preflight", response_model=SigmaSmokeResponse)
def preflight_sigma_smoke(payload: SigmaSmokeRequest, db: Session = Depends(get_db)) -> SigmaSmokeResponse:
    rules = _resolve_sigma_smoke_rules(db, payload)
    results, _ = _sigma_smoke_preflight_results(db, payload, rules)
    return _sigma_smoke_summary(payload=payload, results=results, preflight_only=True)


@router.post("/api/rules/sigma/smoke/run", response_model=SigmaSmokeResponse)
def run_sigma_smoke(payload: SigmaSmokeRequest, db: Session = Depends(get_db)) -> SigmaSmokeResponse:
    rules = _resolve_sigma_smoke_rules(db, payload)
    preflight_results, profile = _sigma_smoke_preflight_results(db, payload, rules)
    runnable_rule_ids = {item.rule_id for item in preflight_results if item.status == "ready"}
    run = RuleRun(
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        engine="sigma",
        status=RuleRunStatus.running,
        scope="evidence" if payload.evidence_id else "case",
        total_rules=len(rules),
        current_phase="sigma_smoke",
        started_at=utc_now().isoformat(),
        metadata_json={"run_type": "smoke", "smoke": True, "mode": payload.mode, "requested_rule_ids": [rule.id for rule in rules], "preflight": [item.model_dump() for item in preflight_results], "sigma_case_profile": profile},
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    from app.workers.tasks import run_rule_on_case

    results_by_rule = {item.rule_id: item for item in preflight_results}
    totals = {"matched": 0, "created": 0, "duplicates": 0, "scanned": 0, "errors": 0}
    for rule in rules:
        if rule.id not in runnable_rule_ids:
            continue
        item = results_by_rule[rule.id]
        try:
            result = run_rule_on_case(
                rule.id,
                payload.case_id,
                evidence_id=payload.evidence_id,
                dry_run=False,
                run_id=run.id,
                scan_options={
                    **_sigma_smoke_scope(payload),
                    "run_type": "smoke",
                    "smoke": True,
                    "sigma_run_mode": "fast_triage",
                    "sigma_max_matches_per_rule": min(max(int(payload.max_detections_per_rule or 10), 1), 100),
                    "sigma_max_detections_per_rule": min(max(int(payload.max_detections_per_rule or 10), 1), 100),
                },
            )
            matched = int(result.get("matched") or result.get("matches_found") or 0)
            item.status = "matched" if matched else "no_match"
            item.matched = matched
            item.created_detections = int(result.get("created_detections") or 0)
            item.duplicates = int(result.get("duplicates") or 0)
            item.scanned_events = int(result.get("scanned_events") or item.scanned_events or 0)
            item.warnings = list(dict.fromkeys([*item.warnings, *[str(value) for value in (result.get("warnings") or [])]]))
            item.errors = [str(value) for value in (result.get("errors") or [])]
            if item.errors:
                item.status = "error"
                totals["errors"] += 1
            totals["matched"] += matched
            totals["created"] += item.created_detections
            totals["duplicates"] += item.duplicates
            totals["scanned"] += item.scanned_events
        except Exception as exc:  # noqa: BLE001
            item.status = "error"
            item.errors = [str(exc).splitlines()[0][:240]]
            totals["errors"] += 1

    detections = (
        db.query(DetectionResult)
        .filter(DetectionResult.case_id == payload.case_id, DetectionResult.raw["rule_run_id"].as_string() == run.id, DetectionResult.raw["run_type"].as_string() == "smoke")
        .order_by(desc(DetectionResult.created_at))
        .limit(50)
        .all()
    )
    by_rule_samples: dict[str, dict[str, list[str]]] = {}
    for detection in detections:
        bucket = by_rule_samples.setdefault(str(detection.rule_id or ""), {"detections": [], "events": []})
        if len(bucket["detections"]) < 3:
            bucket["detections"].append(detection.id)
        if detection.event_id and len(bucket["events"]) < 3:
            bucket["events"].append(detection.event_id)
    final_results = [results_by_rule[rule.id] for rule in rules]
    for item in final_results:
        samples = by_rule_samples.get(item.rule_id) or {}
        item.sample_detection_ids = samples.get("detections") or []
        item.sample_event_ids = samples.get("events") or []
    warnings = ["Unsupported and missing-field rules were skipped; this is expected for smoke validation."] if any(item.status in {"unsupported", "skipped_missing_fields"} for item in final_results) else []
    run.status = RuleRunStatus.completed if not totals["errors"] else RuleRunStatus.failed
    run.finished_at = utc_now().isoformat()
    run.processed_rules = len(rules)
    run.matched = totals["matched"]
    run.created_detections = totals["created"]
    run.duplicates = totals["duplicates"]
    run.scanned_events = totals["scanned"]
    run.current_phase = "completed"
    run.errors = [error for item in final_results for error in item.errors]
    run.metadata_json = {**(run.metadata_json or {}), "run_type": "smoke", "smoke": True, "results": [item.model_dump() for item in final_results], "warnings": warnings, "field_mapping_explanation": True, "display_status": "completed_with_warnings" if warnings else "completed"}
    db.commit()
    log_activity(db, activity_type="sigma_smoke_run", title="Sigma smoke test completed", message=f"Sigma smoke tested {len(rules)} rules and created {totals['created']} detections.", case_id=payload.case_id, evidence_id=payload.evidence_id, metadata={"run_id": run.id, "matched": totals["matched"], "created_detections": totals["created"], "mode": payload.mode})
    return _sigma_smoke_summary(payload=payload, results=final_results, run_id=run.id, warnings=warnings)


def _queue_case_rules_run(
    db: Session,
    *,
    case_id: str,
    payload: RulesRunRequest,
    requested_via: str = "case_rules",
) -> dict:
    evidence = None
    indexed_events_input_count = 0
    if payload.evidence_id:
        evidence = db.get(Evidence, payload.evidence_id)
        if not evidence or evidence.case_id != case_id:
            raise HTTPException(status_code=404, detail="Evidence not found")
        if getattr(evidence, "ingest_status", None) in {"pending", "processing"}:
            raise HTTPException(status_code=409, detail="Evidence ingest is still running. Wait for ingest to finish before running rules on demand.")
        if hasattr(evidence.ingest_status, "value") and evidence.ingest_status.value in {"pending", "processing"}:
            raise HTTPException(status_code=409, detail="Evidence ingest is still running. Wait for ingest to finish before running rules on demand.")
        indexed_events_input_count = int((count_documents(get_events_index(case_id), {"term": {"evidence_id": payload.evidence_id}}).get("count") or 0))
        if indexed_events_input_count <= 0:
            raise HTTPException(status_code=409, detail="This evidence has no indexed documents yet. Run usable search ingest first.")
        if not payload.force:
            active = (
                db.query(RuleRun)
                .filter(
                    RuleRun.case_id == case_id,
                    RuleRun.evidence_id == payload.evidence_id,
                    RuleRun.status.in_([RuleRunStatus.queued, RuleRunStatus.running]),
                )
                .order_by(RuleRun.created_at.desc())
                .first()
            )
            if active:
                raise HTTPException(status_code=409, detail=f"An on-demand rules run is already active for this evidence: {active.id}")
    rule_ids, dedupe_info = _resolve_rule_ids_for_case_with_dedupe(db, case_id=case_id, payload=payload)
    if not rule_ids:
        return {"accepted": True, "status": "skipped", "queued_rules": 0, "message": "No individual rules matched the requested filters."}
    requested_run_mode = str(payload.run_mode or "balanced").strip().lower() or "balanced"
    if requested_run_mode not in {"fast_triage", "balanced", "exhaustive"}:
        requested_run_mode = "balanced"
    scan_options = {
        "scan_parsed_outputs": bool(payload.include_parsed_outputs),
        "scan_archives": bool(payload.include_archives),
        "scan_text_outputs": bool(payload.include_text_outputs),
        "max_file_size_mb": payload.max_file_size_mb or settings.yara_max_file_size_mb,
        "evidence_id": payload.evidence_id,
        "host": payload.host,
        "time_from": payload.time_from,
        "time_to": payload.time_to,
        "selected_paths": payload.selected_paths,
        "sigma_run_mode": requested_run_mode,
    }
    run = RuleRun(
        rule_id=None,
        rule_set_id=None,
        case_id=case_id,
        evidence_id=payload.evidence_id,
        engine="multi",
        scope=payload.scope,
        status=RuleRunStatus.queued,
        total_rules=len(rule_ids),
        current_phase="queued",
        heartbeat_at=utc_now().isoformat(),
        metadata_json={
            "mode": payload.mode or "on_demand",
            "requested_via": requested_via,
            "requested_by": "manual",
            "scope": payload.scope,
            "rule_types": payload.rule_types or payload.engines or ([payload.engine] if payload.engine else []),
            "requested_rule_ids": rule_ids,
            "requested_rule_count": len(rule_ids),
            "rule_execution_deduplication": dedupe_info,
            "duplicates_suppressed": dedupe_info.get("duplicates_suppressed", 0),
            "selected_for_execution": dedupe_info.get("selected_for_execution", len(rule_ids)),
            "host": payload.host,
            "time_from": payload.time_from,
            "time_to": payload.time_to,
            "selected_paths": payload.selected_paths,
            "sigma_run_mode": requested_run_mode,
            "scan_options": scan_options,
            "indexed_events_input_count": indexed_events_input_count,
        },
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    job_id = enqueue_rules_run(case_id=case_id, engines=[], rule_ids=rule_ids, enabled_only=False, scan_options=scan_options, run_id=run.id)
    run.metadata_json = {**(run.metadata_json or {}), "job_id": job_id}
    db.commit()
    db.refresh(run)
    log_activity(
        db,
        activity_type="rule_run_started",
        title="On-demand rules run queued",
        message=f"Queued rule run for case {case_id}",
        case_id=case_id,
        evidence_id=payload.evidence_id,
        metadata={
            "engines": payload.engines or payload.rule_types,
            "rule_ids": rule_ids,
            "rule_execution_deduplication": dedupe_info,
            "enabled_only": payload.enabled_only,
            "enabled": payload.enabled,
            "engine": payload.engine,
            "severity": payload.severity,
            "namespace": payload.namespace,
            "scope": payload.scope,
            "search": payload.search,
            "run_id": run.id,
            "sigma_run_mode": requested_run_mode,
            "mode": payload.mode or "on_demand",
            "requested_via": requested_via,
            "indexed_events_input_count": indexed_events_input_count,
        },
    )
    return {
        "accepted": True,
        "run_id": run.id,
        "status": "queued",
        "queued_rules": len(rule_ids),
        "duplicates_suppressed": dedupe_info.get("duplicates_suppressed", 0),
        "selected_for_execution": dedupe_info.get("selected_for_execution", len(rule_ids)),
        "total_available": dedupe_info.get("total_available", len(rule_ids)),
        "message": f"Queued {len(rule_ids)} rules.",
    }


def _retry_run_from_existing(db: Session, run: RuleRun) -> RuleRun:
    metadata = dict(run.metadata_json or {})
    new_run = RuleRun(
        rule_id=run.rule_id,
        rule_set_id=run.rule_set_id,
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        engine=run.engine,
        scope=run.scope,
        status=RuleRunStatus.queued,
        total_rules=max(int(run.total_rules or 0), 1 if run.rule_id or run.rule_set_id else 0),
        processed_rules=0,
        total_events=0,
        scanned_events=0,
        total_files=0,
        created_detections=0,
        duplicates=0,
        scanned_files=0,
        skipped_files=0,
        current_phase="queued",
        heartbeat_at=utc_now().isoformat(),
        metadata_json={**metadata, "retried_from_run_id": run.id},
    )
    db.add(new_run)
    db.commit()
    db.refresh(new_run)
    scan_options = dict((new_run.metadata_json or {}).get("scan_options") or {})
    if new_run.rule_id or new_run.rule_set_id:
        job_id = enqueue_rule_run(
            rule_id=new_run.rule_id,
            rule_set_id=new_run.rule_set_id,
            case_id=new_run.case_id,
            evidence_id=new_run.evidence_id,
            dry_run=bool((new_run.metadata_json or {}).get("dry_run")),
            run_id=new_run.id,
            scan_options=scan_options or None,
        )
    else:
        requested_rule_ids = [value for value in metadata.get("requested_rule_ids", []) if isinstance(value, str)]
        job_id = enqueue_rules_run(
            case_id=new_run.case_id,
            engines=[],
            rule_ids=requested_rule_ids,
            enabled_only=False,
            scan_options=scan_options or None,
            run_id=new_run.id,
        )
    new_run.metadata_json = {**(new_run.metadata_json or {}), "job_id": job_id}
    db.commit()
    db.refresh(new_run)
    log_activity(
        db,
        activity_type="rule_run_retried",
        title="Rule run retried",
        message=f"Queued retry for rule run {run.id}",
        case_id=new_run.case_id,
        evidence_id=new_run.evidence_id,
        metadata={"run_id": new_run.id, "retried_from_run_id": run.id},
    )
    return new_run


@router.get("/api/rule-sets", response_model=RuleSetListResponse)
def list_rule_sets(
    case_id: str | None = None,
    engine: str | None = None,
    severity: str | None = None,
    namespace: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    enabled: bool | None = None,
    scope: str = Query("all", pattern="^(global|case|all)$"),
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> RuleSetListResponse:
    query = _apply_rule_set_filters(
        db.query(RuleSet),
        case_id=case_id,
        engine=engine,
        severity=severity,
        namespace=namespace,
        import_run_id=import_run_id,
        source_pack=source_pack,
        enabled=enabled,
        scope=scope,
        search=search,
    )
    total = query.count()
    items = query.order_by(RuleSet.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return RuleSetListResponse(total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0, items=items)


@router.get("/api/rules/engines/status")
def rules_engine_status() -> dict[str, RuleEngineStatusRead]:
    yara_ok = yara_available()
    return {
        "heuristic": RuleEngineStatusRead(available=True, runs_on="indexed_events"),
        "sigma": RuleEngineStatusRead(available=True, runs_on="indexed_events", supported="basic Sigma subset"),
        "yara": RuleEngineStatusRead(
            available=yara_ok,
            runs_on="preserved_files",
            supports_rule_packs=True,
            scan_extracted=settings.yara_scan_extracted,
            scan_originals=settings.yara_scan_originals,
            max_file_size_mb=settings.yara_max_file_size_mb,
            error=None if yara_ok else "yara-python not installed",
        ),
    }


@router.post("/api/rules", response_model=RuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)) -> Rule:
    validation = _validate_rule_payload(payload.engine, payload.content)
    data = payload.model_dump()
    data["title"] = payload.title or payload.name
    data["content_hash"] = _rule_content_hash(payload.content)
    data["status"] = "valid" if validation.get("valid", True) else "invalid"
    data["validation_errors"] = validation.get("errors", [])
    item = Rule(**data)
    db.add(item)
    db.commit()
    db.refresh(item)
    log_activity(
        db,
        activity_type="rule_created",
        title="Rule created",
        message=f"Created {item.engine.value} rule {item.name}",
        case_id=item.case_id,
        metadata={"rule_id": item.id},
    )
    return item


@router.post("/api/rules/validate")
def validate_rule(payload: dict) -> dict:
    engine = RuleEngine(str(payload.get("engine") or "sigma"))
    content = str(payload.get("content") or "")
    return _validate_rule_payload(engine, content)


@router.post("/api/rules/upload", response_model=RuleImportResponse)
def upload_rule_alias(
    file: UploadFile = File(...),
    engine: str = Form("auto"),
    import_mode: str = Form("auto"),
    case_id: str | None = Form(None),
    namespace: str | None = Form(None),
    enabled: bool = Form(True),
    db: Session = Depends(get_db),
) -> RuleImportResponse:
    return import_rule_file(file=file, engine=engine, import_mode=import_mode, case_id=case_id, namespace=namespace, enabled=enabled, db=db)


@router.post("/api/rules/import-file", response_model=RuleImportResponse)
def import_rule_file(
    file: UploadFile = File(...),
    engine: str = Form("auto"),
    import_mode: str = Form("auto"),
    case_id: str | None = Form(None),
    namespace: str | None = Form(None),
    enabled: bool = Form(True),
    db: Session = Depends(get_db),
) -> RuleImportResponse:
    content = file.file.read().decode("utf-8", errors="ignore")
    run = _create_import_run(
        db,
        uploaded_filename=file.filename or "rule.txt",
        source_type="single_file",
        requested_engine=engine,
        import_mode=import_mode,
        case_id=case_id,
        namespace=namespace,
        enabled=enabled,
        status=RuleImportRunStatus.uploading,
        current_phase="uploading",
        total_files=1,
    )
    run, imported, imported_rule_sets = _run_import(
        db,
        run=run,
        uploaded_filename=file.filename or "rule.txt",
        source_type="single_file",
        entries=[(file.filename or "rule.txt", content)],
        requested_engine=engine,
        import_mode=import_mode,
        case_id=case_id,
        namespace=namespace,
        enabled=enabled,
    )
    log_activity(
        db,
        activity_type="rule_import_completed" if run.status != RuleImportRunStatus.failed else "rule_import_failed",
        title="Rule import completed" if run.status != RuleImportRunStatus.failed else "Rule import failed",
        message=f"Imported {run.imported_count} items from {file.filename or 'rule.txt'}",
        case_id=case_id,
        metadata={"import_run_id": run.id, "status": run.status.value, "imported_count": run.imported_count, "updated_count": run.updated_count, "duplicate_count": run.duplicate_count, "invalid_count": run.invalid_count, "unsupported_count": run.unsupported_count},
    )
    return _build_import_response(run=run, imported_rules=imported, imported_rule_sets=imported_rule_sets)


def import_rule_archive(
    file: UploadFile = File(...),
    engine: str = Form("auto"),
    import_mode: str = Form("auto"),
    case_id: str | None = Form(None),
    namespace: str | None = Form(None),
    enabled: bool = Form(True),
    db: Session = Depends(get_db),
) -> RuleImportResponse:
    entries: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        archive_path = Path(tmp_dir) / (file.filename or "rules.zip")
        archive_path.write_bytes(file.file.read())
        extract_dir = Path(tmp_dir) / "extracted"
        _, manifest = extract_archive(archive_path, extract_dir)
        for item in manifest:
            if item.get("ignored"):
                entries.append((str(item.get("path") or item.get("display_name") or "ignored"), ""))
                continue
            rule_path = extract_dir / item["path"]
            if not rule_path.is_file():
                continue
            content = rule_path.read_text(encoding="utf-8", errors="ignore")
            entries.append((str(item["path"]), content))
    run, imported, imported_rule_sets = _run_import(
        db,
        run=_create_import_run(
            db,
            uploaded_filename=file.filename or "rules.zip",
            source_type="archive",
            requested_engine=engine,
            import_mode=import_mode,
            case_id=case_id,
            namespace=namespace,
            enabled=enabled,
            status=RuleImportRunStatus.extracting,
            current_phase="extracting_archive",
            total_files=len(entries),
        ),
        uploaded_filename=file.filename or "rules.zip",
        source_type="archive",
        entries=entries,
        requested_engine=engine,
        import_mode=import_mode,
        case_id=case_id,
        namespace=namespace,
        enabled=enabled,
    )
    log_activity(
        db,
        activity_type="rule_import_completed" if run.status != RuleImportRunStatus.failed else "rule_import_failed",
        title="Archive rule import completed" if run.status != RuleImportRunStatus.failed else "Archive rule import failed",
        message=f"Imported {run.imported_count} items from archive {file.filename or 'rules.zip'}",
        case_id=case_id,
        metadata={"import_run_id": run.id, "status": run.status.value, "imported_count": run.imported_count, "updated_count": run.updated_count, "duplicate_count": run.duplicate_count, "invalid_count": run.invalid_count, "unsupported_count": run.unsupported_count},
    )
    return _build_import_response(run=run, imported_rules=imported, imported_rule_sets=imported_rule_sets)


def _run_import_archive_in_background(
    *,
    import_run_id: str,
    archive_bytes: bytes,
    uploaded_filename: str,
    requested_engine: str,
    import_mode: str,
    case_id: str | None,
    namespace: str | None,
    enabled: bool,
) -> None:
    db = SessionLocal()
    try:
        run = db.get(RuleImportRun, import_run_id)
        if not run:
            return
        run.status = RuleImportRunStatus.extracting
        run.current_phase = "extracting_archive"
        _persist_import_run(db, run)
        entries: list[tuple[str, str]] = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / uploaded_filename
            archive_path.write_bytes(archive_bytes)
            extract_dir = Path(tmp_dir) / "extracted"
            _, manifest = extract_archive(archive_path, extract_dir)
            run.total_files = len(manifest)
            _persist_import_run(db, run)
            for item in manifest:
                if _check_import_cancel_requested(db, run):
                    fresh = _reload_import_run(db, import_run_id)
                    if fresh:
                        _mark_import_cancelled(db, fresh, reason="Cancel requested during archive extraction.")
                    return
                if item.get("ignored"):
                    entries.append((str(item.get("path") or item.get("display_name") or "ignored"), ""))
                else:
                    rule_path = extract_dir / item["path"]
                    if rule_path.is_file():
                        entries.append((str(item["path"]), rule_path.read_text(encoding="utf-8", errors="ignore")))
        run = _reload_import_run(db, import_run_id)
        if not run:
            return
        _run_import(
            db,
            run=run,
            uploaded_filename=uploaded_filename,
            source_type="archive",
            entries=entries,
            requested_engine=requested_engine,
            import_mode=import_mode,
            case_id=case_id,
            namespace=namespace,
            enabled=enabled,
        )
    finally:
        db.close()


@router.post("/api/rules/import-archive", response_model=RuleImportResponse)
def import_rule_archive_endpoint(
    file: UploadFile = File(...),
    engine: str = Form("auto"),
    import_mode: str = Form("auto"),
    case_id: str | None = Form(None),
    namespace: str | None = Form(None),
    enabled: bool = Form(True),
    db: Session = Depends(get_db),
) -> RuleImportResponse:
    archive_bytes = file.file.read()
    run = _create_import_run(
        db,
        uploaded_filename=file.filename or "rules.zip",
        source_type="archive",
        requested_engine=engine,
        import_mode=import_mode,
        case_id=case_id,
        namespace=namespace,
        enabled=enabled,
        status=RuleImportRunStatus.uploading,
        current_phase="uploading",
        total_files=0,
    )
    thread = threading.Thread(
        target=_run_import_archive_in_background,
        kwargs={
            "import_run_id": run.id,
            "archive_bytes": archive_bytes,
            "uploaded_filename": file.filename or "rules.zip",
            "requested_engine": engine,
            "import_mode": import_mode,
            "case_id": case_id,
            "namespace": namespace,
            "enabled": enabled,
        },
        daemon=True,
    )
    thread.start()
    return _build_import_response(run=run, imported_rules=[], imported_rule_sets=[])


@router.get("/api/rules/imports", response_model=RuleImportRunListResponse)
def list_rule_imports(
    case_id: str | None = None,
    engine: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> RuleImportRunListResponse:
    query = db.query(RuleImportRun)
    if case_id:
        query = query.filter(RuleImportRun.case_id == case_id)
    if engine:
        query = query.filter(RuleImportRun.engine == engine)
    items = query.order_by(desc(RuleImportRun.created_at)).limit(limit).all()
    return RuleImportRunListResponse(total=len(items), items=[_import_run_detail(item, db) for item in items])


@router.get("/api/rules/imports/{import_run_id}", response_model=RuleImportRunRead)
def get_rule_import(import_run_id: str, db: Session = Depends(get_db)) -> RuleImportRunRead:
    item = db.get(RuleImportRun, import_run_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule import run not found")
    return _import_run_detail(item, db)


@router.post("/api/rules/imports/{import_run_id}/cancel", response_model=RuleImportRunRead)
def cancel_rule_import(import_run_id: str, db: Session = Depends(get_db)) -> RuleImportRunRead:
    item = db.get(RuleImportRun, import_run_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule import run not found")
    if item.status in {RuleImportRunStatus.completed, RuleImportRunStatus.completed_with_warnings, RuleImportRunStatus.failed, RuleImportRunStatus.cancelled}:
        return _import_run_detail(item, db)
    item.cancel_requested = True
    details = dict(item.details_json or {})
    details["cancel_requested_at"] = utc_now().isoformat()
    item.details_json = details
    if item.status == RuleImportRunStatus.queued:
        _mark_import_cancelled(db, item, reason="Cancelled before import processing began.")
        return _import_run_detail(item, db)
    _persist_import_run(db, item)
    return _import_run_detail(item, db)


@router.get("/api/rule-sets/{rule_set_id}", response_model=RuleSetRead)
def get_rule_set(rule_set_id: str, db: Session = Depends(get_db)) -> RuleSet:
    item = db.get(RuleSet, rule_set_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule set not found")
    return item


@router.patch("/api/rule-sets/{rule_set_id}/toggle", response_model=RuleSetRead)
def toggle_rule_set(rule_set_id: str, db: Session = Depends(get_db)) -> RuleSet:
    item = db.get(RuleSet, rule_set_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule set not found")
    item.enabled = not item.enabled
    db.commit()
    db.refresh(item)
    return item


@router.delete("/api/rule-sets/{rule_set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_set(rule_set_id: str, db: Session = Depends(get_db)) -> None:
    item = db.get(RuleSet, rule_set_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule set not found")
    for child_rule in db.query(Rule).filter(Rule.rule_set_id == item.id).all():
        db.delete(child_rule)
    db.delete(item)
    db.commit()


@router.delete("/api/rule-sets/bulk", response_model=RuleBulkDeleteResponse)
def bulk_delete_rule_sets(payload: RuleSetBulkDeleteRequest, db: Session = Depends(get_db)) -> RuleBulkDeleteResponse:
    items = _resolve_rule_set_targets(db, payload)
    if not items:
        return RuleBulkDeleteResponse()
    required_confirm = _required_rule_set_delete_confirmation(db, payload, items)
    if not _delete_confirmation_matches(payload.confirm, required_confirm):
        raise HTTPException(status_code=400, detail=f"Confirm by typing {required_confirm}")
    matched = len(items)
    deleted = 0
    affected_packs: list[str] = []
    for item in items:
        affected_packs.append(item.name)
        for child_rule in db.query(Rule).filter(Rule.rule_set_id == item.id).all():
            db.delete(child_rule)
        db.delete(item)
        deleted += 1
    db.commit()
    log_activity(
        db,
        activity_type="rule_packs_bulk_delete",
        title="Rule packs deleted in bulk",
        message=f"Deleted {deleted} rule packs",
        case_id=payload.case_id,
        metadata={"matched": matched, "deleted": deleted, "affected_packs": affected_packs},
    )
    return RuleBulkDeleteResponse(matched=matched, deleted=deleted, affected_packs=affected_packs)


@router.patch("/api/rules/bulk", response_model=RuleBulkUpdateResponse)
def bulk_update_rules(payload: RuleBulkActionRequest, db: Session = Depends(get_db)) -> RuleBulkUpdateResponse:
    if payload.enabled is None:
        raise HTTPException(status_code=400, detail="enabled must be true or false")
    target_payload = payload
    if (payload.mode or "").strip().lower() == "matching":
        target_payload = payload.model_copy(update={"enabled": None})
    items = _resolve_rule_targets(db, target_payload)
    if not items:
        return RuleBulkUpdateResponse(enabled=bool(payload.enabled))
    updated = 0
    skipped_reasons: dict[str, int] = {}
    warnings = ["Existing detections will remain unless explicitly deleted."]
    for item in items:
        if _rule_is_builtin_heuristic(item) and payload.enabled is True:
            item.enabled = True
            updated += 1
            continue
        item.enabled = bool(payload.enabled)
        updated += 1
    db.commit()
    log_activity(
        db,
        activity_type="rules_bulk_update",
        title="Rules updated in bulk",
        message=f"{'Enabled' if payload.enabled else 'Disabled'} {updated} rules",
        case_id=payload.case_id,
        metadata={"mode": payload.mode, "updated": updated, "matched": len(items), "import_run_id": payload.import_run_id, "source_pack": payload.source_pack},
    )
    return RuleBulkUpdateResponse(matched=len(items), updated=updated, enabled=bool(payload.enabled), skipped_reasons=skipped_reasons, warnings=warnings)


@router.post("/api/rules/bulk/preview", response_model=RuleBulkPreviewResponse)
def preview_bulk_rules(payload: RuleBulkActionRequest, db: Session = Depends(get_db)) -> RuleBulkPreviewResponse:
    items = _resolve_rule_targets(db, payload)
    return _preview_rule_targets(items)


@router.delete("/api/rules/bulk", response_model=RuleBulkDeleteResponse)
def bulk_delete_rules(payload: RuleBulkActionRequest, db: Session = Depends(get_db)) -> RuleBulkDeleteResponse:
    items = _resolve_rule_targets(db, payload)
    if not items:
        return RuleBulkDeleteResponse()
    required_confirm = _required_rule_delete_confirmation(payload, items)
    if not _delete_confirmation_matches(payload.confirm, required_confirm):
        raise HTTPException(status_code=400, detail=f"Confirm by typing {required_confirm}")
    deleted = 0
    skipped = 0
    skipped_reasons: dict[str, int] = {}
    affected_packs: list[str] = []
    warnings = [
        "Existing detections will remain unless explicitly deleted.",
        "Future runs will not use deleted rules.",
    ]
    for item in items:
        if _rule_is_builtin_heuristic(item):
            skipped += 1
            skipped_reasons["protected_builtin_heuristic"] = skipped_reasons.get("protected_builtin_heuristic", 0) + 1
            continue
        if item.rule_set_id:
            pack = db.get(RuleSet, item.rule_set_id)
            if pack and pack.name not in affected_packs:
                affected_packs.append(pack.name)
        db.delete(item)
        deleted += 1
    db.commit()
    log_activity(
        db,
        activity_type="rules_bulk_delete",
        title="Rules deleted in bulk",
        message=f"Deleted {deleted} rules",
        case_id=payload.case_id,
        metadata={"mode": payload.mode, "deleted": deleted, "matched": len(items), "skipped": skipped, "import_run_id": payload.import_run_id, "source_pack": payload.source_pack, "affected_packs": affected_packs},
    )
    return RuleBulkDeleteResponse(matched=len(items), deleted=deleted, skipped=skipped, skipped_reasons=skipped_reasons, affected_packs=affected_packs, warnings=warnings)


@router.get("/api/rules/{rule_id}", response_model=RuleRead)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> Rule:
    item = db.get(Rule, rule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule not found")
    if item.engine == RuleEngine.sigma:
        item.metadata_json = {**dict(item.metadata_json or {}), "sigma_coverage": _sigma_rule_support_record(item)}
    return item


@router.patch("/api/rules/{rule_id}", response_model=RuleRead)
def update_rule(rule_id: str, payload: RuleUpdate, db: Session = Depends(get_db)) -> Rule:
    item = db.get(Rule, rule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, key, value)
    if payload.content is not None or payload.engine is not None:
        validation = _validate_rule_payload(item.engine, item.content)
        item.content_hash = _rule_content_hash(item.content)
        item.status = "valid" if validation.get("valid", True) else "invalid"
        item.validation_errors = validation.get("errors", [])
    db.commit()
    db.refresh(item)
    return item


@router.patch("/api/rules/{rule_id}/toggle", response_model=RuleRead)
def toggle_rule(rule_id: str, db: Session = Depends(get_db)) -> Rule:
    item = db.get(Rule, rule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule not found")
    item.enabled = not item.enabled
    db.commit()
    db.refresh(item)
    return item


@router.delete("/api/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, db: Session = Depends(get_db)) -> None:
    item = db.get(Rule, rule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(item)
    db.commit()


@router.post("/api/rules/{rule_id}/run", response_model=RuleRunResponse)
def run_rule(rule_id: str, payload: RuleRunRequest, db: Session = Depends(get_db)) -> RuleRunResponse:
    item = db.get(Rule, rule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not db.get(Case, payload.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    run = RuleRun(
        rule_id=item.id,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        engine=item.engine.value,
        scope="evidence" if payload.evidence_id else "case",
        status=RuleRunStatus.queued,
        total_rules=1,
        current_phase="queued",
        heartbeat_at=utc_now().isoformat(),
        metadata_json={
            "scope": "evidence" if payload.evidence_id else "case",
            "mode": payload.mode,
            "dry_run": payload.dry_run,
            "scan_options": {
                "scan_parsed_outputs": bool(payload.include_parsed_outputs),
                "scan_archives": bool(payload.include_archives),
                "scan_text_outputs": bool(payload.include_text_outputs),
                "max_file_size_mb": payload.max_file_size_mb,
            },
        },
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    job_id = enqueue_rule_run(
        rule_id=rule_id,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        dry_run=payload.dry_run,
        run_id=run.id,
        scan_options={
            "scan_parsed_outputs": bool(payload.include_parsed_outputs),
            "scan_archives": bool(payload.include_archives),
            "scan_text_outputs": bool(payload.include_text_outputs),
            "max_file_size_mb": payload.max_file_size_mb,
        } if item.engine == RuleEngine.yara else None,
    )
    run.metadata_json = {**(run.metadata_json or {}), "job_id": job_id}
    db.commit()
    db.refresh(run)
    log_activity(
        db,
        activity_type="rule_run_started",
        title="Rule run queued",
        message=f"Queued rule {item.name} for case {payload.case_id}",
        case_id=payload.case_id,
        metadata={"rule_id": rule_id, "evidence_id": payload.evidence_id, "run_id": run.id},
    )
    return RuleRunResponse(
        rule_id=item.id,
        rule_set_id=None,
        engine=item.engine.value,
        case_id=payload.case_id,
        matched=0,
        created_detections=0,
        duplicates=0,
        skipped=False,
        error=None if item.engine != RuleEngine.yara else "YARA run queued. If yara-python is unavailable, the run will be skipped with a warning activity event.",
        status="queued",
        run_id=run.id,
    )


@router.post("/api/rule-sets/{rule_set_id}/run", response_model=RuleRunResponse)
def run_rule_set(rule_set_id: str, payload: RuleRunRequest, db: Session = Depends(get_db)) -> RuleRunResponse:
    item = db.get(RuleSet, rule_set_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule set not found")
    if not db.get(Case, payload.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    run = RuleRun(
        rule_id=None,
        rule_set_id=item.id,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        engine=item.engine.value,
        scope="evidence" if payload.evidence_id else "case",
        status=RuleRunStatus.queued,
        total_rules=1,
        current_phase="queued",
        heartbeat_at=utc_now().isoformat(),
        metadata_json={
            "scope": "evidence" if payload.evidence_id else "case",
            "mode": payload.mode,
            "dry_run": payload.dry_run,
            "scan_options": {
                "scan_parsed_outputs": bool(payload.include_parsed_outputs),
                "scan_archives": bool(payload.include_archives),
                "scan_text_outputs": bool(payload.include_text_outputs),
                "max_file_size_mb": payload.max_file_size_mb,
            },
            "max_file_size_mb": payload.max_file_size_mb,
        },
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    job_id = enqueue_rule_run(
        rule_id=None,
        rule_set_id=item.id,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        dry_run=payload.dry_run,
        run_id=run.id,
        scan_options={
            "scan_parsed_outputs": bool(payload.include_parsed_outputs),
            "scan_archives": bool(payload.include_archives),
            "scan_text_outputs": bool(payload.include_text_outputs),
            "max_file_size_mb": payload.max_file_size_mb,
        },
    )
    run.metadata_json = {**(run.metadata_json or {}), "job_id": job_id}
    db.commit()
    db.refresh(run)
    log_activity(
        db,
        activity_type="rule_run_started",
        title="Rule pack run queued",
        message=f"Queued rule pack {item.name} for case {payload.case_id}",
        case_id=payload.case_id,
        metadata={"rule_set_id": item.id, "evidence_id": payload.evidence_id, "run_id": run.id},
    )
    return RuleRunResponse(
        rule_id=None,
        rule_set_id=item.id,
        engine=item.engine.value,
        case_id=payload.case_id,
        matched=0,
        created_detections=0,
        duplicates=0,
        skipped=False,
        error=None if item.engine != RuleEngine.yara else "YARA rule pack run queued. If yara-python is unavailable, the run will be skipped with a warning activity event.",
        status="queued",
        run_id=run.id,
    )


@router.post("/api/cases/{case_id}/rules/run")
def run_case_rules(case_id: str, payload: RulesRunRequest, db: Session = Depends(get_db)) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return _queue_case_rules_run(db, case_id=case_id, payload=payload, requested_via="case_rules")


@router.get("/api/rules/{rule_id}/runs", response_model=list[RuleRunRead])
def list_rule_runs(rule_id: str, db: Session = Depends(get_db)) -> list[RuleRunRead]:
    items = db.query(RuleRun).filter(RuleRun.rule_id == rule_id).order_by(RuleRun.created_at.desc()).limit(100).all()
    return [_serialize_rule_run(item) for item in items]


@router.get("/api/cases/{case_id}/rule-runs", response_model=list[RuleRunRead])
def list_case_rule_runs(case_id: str, db: Session = Depends(get_db)) -> list[RuleRunRead]:
    items = db.query(RuleRun).filter(RuleRun.case_id == case_id).order_by(RuleRun.created_at.desc()).limit(200).all()
    return [_serialize_rule_run(item) for item in items]


@router.get("/api/rule-runs/{run_id}", response_model=RuleRunRead)
def get_rule_run(run_id: str, db: Session = Depends(get_db)) -> RuleRunRead:
    item = db.get(RuleRun, run_id)
    if not item:
        raise HTTPException(status_code=404, detail="Rule run not found")
    return _serialize_rule_run(item)


@router.get("/api/cases/{case_id}/rules/runs/{run_id}", response_model=RuleRunRead)
def get_case_rule_run(case_id: str, run_id: str, db: Session = Depends(get_db)) -> RuleRunRead:
    item = db.get(RuleRun, run_id)
    if not item or item.case_id != case_id:
        raise HTTPException(status_code=404, detail="Rule run not found")
    return _serialize_rule_run(item)


@router.post("/api/rule-runs/{run_id}/cancel", response_model=RuleRunActionResponse)
def cancel_rule_run(run_id: str, db: Session = Depends(get_db)) -> RuleRunActionResponse:
    run = db.get(RuleRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Rule run not found")
    if run.status in {RuleRunStatus.completed, RuleRunStatus.failed, RuleRunStatus.cancelled}:
        return RuleRunActionResponse(run=_serialize_rule_run(run), message="Run is already finished.")
    run.cancel_requested = True
    metadata = dict(run.metadata_json or {})
    metadata["cancel_requested_at"] = utc_now().isoformat()
    run.metadata_json = metadata
    if run.status == RuleRunStatus.queued and not run.started_at:
        run.status = RuleRunStatus.cancelled
        run.current_phase = "cancelled"
        run.finished_at = utc_now().isoformat()
        run.last_error = "Cancelled before worker pickup."
    db.commit()
    db.refresh(run)
    log_activity(
        db,
        activity_type="rule_run_cancel_requested",
        title="Rule run cancel requested",
        message=f"Cancel requested for rule run {run.id}",
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        metadata={"run_id": run.id, "status": run.status.value},
    )
    return RuleRunActionResponse(
        run=_serialize_rule_run(run),
        message="Cancel requested. The worker will stop at the next checkpoint." if run.status != RuleRunStatus.cancelled else "Queued run cancelled.",
    )


@router.post("/api/rule-runs/{run_id}/mark-stale", response_model=RuleRunActionResponse)
def mark_rule_run_stale(run_id: str, db: Session = Depends(get_db)) -> RuleRunActionResponse:
    run = db.get(RuleRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Rule run not found")
    reason = "Marked stale by analyst: no heartbeat"
    _mark_run_stale(run, reason=reason)
    db.commit()
    db.refresh(run)
    log_activity(
        db,
        activity_type="rule_run_marked_stale",
        title="Rule run marked stale",
        message=f"Marked rule run {run.id} stale",
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        metadata={"run_id": run.id},
    )
    return RuleRunActionResponse(run=_serialize_rule_run(run), message="Run marked stale.")


@router.post("/api/rule-runs/{run_id}/retry", response_model=RuleRunActionResponse)
def retry_rule_run(run_id: str, db: Session = Depends(get_db)) -> RuleRunActionResponse:
    run = db.get(RuleRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Rule run not found")
    new_run = _retry_run_from_existing(db, run)
    return RuleRunActionResponse(run=_serialize_rule_run(new_run), message="Retry queued as a new run.")


@router.delete("/api/rule-runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_run(run_id: str, db: Session = Depends(get_db)) -> None:
    run = db.get(RuleRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Rule run not found")
    if _run_is_active(run):
        raise HTTPException(status_code=409, detail="Cannot delete a queued or running rule run. Cancel or mark it stale first.")
    log_activity(
        db,
        activity_type="rule_run_deleted",
        title="Rule run deleted",
        message=f"Deleted rule run record {run.id}",
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        metadata={"run_id": run.id, "status": run.status.value},
    )
    db.delete(run)
    db.commit()


@router.post("/api/rule-runs/mark-stale-abandoned", response_model=RuleRunBulkActionResponse)
def mark_abandoned_rule_runs_stale(
    case_id: str | None = None,
    older_than_minutes: int = Query(10, ge=1, le=10080),
    db: Session = Depends(get_db),
) -> RuleRunBulkActionResponse:
    payload = RuleRunBulkActionRequest(
        mode="matching",
        case_id=case_id,
        statuses=[RuleRunStatus.queued.value, RuleRunStatus.running.value],
        older_than_minutes=older_than_minutes,
    )
    result = bulk_mark_stale_runs(payload, db)
    result.warnings.append("Runs were marked stale based on heartbeat age. Existing detections remain.")
    return result


@router.post("/api/rule-runs/mark-stale", response_model=RuleRunBulkActionResponse)
def bulk_mark_stale_runs(payload: RuleRunBulkActionRequest, db: Session = Depends(get_db)) -> RuleRunBulkActionResponse:
    items = _resolve_rule_run_targets(db, payload)
    updated = 0
    skipped = 0
    skipped_reasons: dict[str, int] = {}
    for item in items:
        if not _queued_or_running(item.status) and item.status != RuleRunStatus.stale:
            skipped += 1
            skipped_reasons["not_running_or_queued"] = skipped_reasons.get("not_running_or_queued", 0) + 1
            continue
        _mark_run_stale(item, reason="Marked stale by analyst: no heartbeat")
        updated += 1
    db.commit()
    log_activity(
        db,
        activity_type="rule_runs_bulk_mark_stale",
        title="Rule runs marked stale",
        message=f"Marked {updated} rule runs stale",
        case_id=getattr(payload, "case_id", None),
        metadata={"matched": len(items), "updated": updated, "skipped": skipped},
    )
    return RuleRunBulkActionResponse(matched=len(items), updated=updated, skipped=skipped, skipped_reasons=skipped_reasons)


@router.post("/api/rule-runs/bulk/cancel", response_model=RuleRunBulkActionResponse)
def bulk_cancel_rule_runs(payload: RuleRunBulkActionRequest, db: Session = Depends(get_db)) -> RuleRunBulkActionResponse:
    items = _resolve_rule_run_targets(db, payload)
    updated = 0
    for item in items:
        if item.status in {RuleRunStatus.completed, RuleRunStatus.failed, RuleRunStatus.cancelled}:
            continue
        item.cancel_requested = True
        metadata = dict(item.metadata_json or {})
        metadata["cancel_requested_at"] = utc_now().isoformat()
        item.metadata_json = metadata
        if item.status == RuleRunStatus.queued and not item.started_at:
            item.status = RuleRunStatus.cancelled
            item.current_phase = "cancelled"
            item.finished_at = utc_now().isoformat()
            item.last_error = "Cancelled before worker pickup."
        updated += 1
    db.commit()
    log_activity(
        db,
        activity_type="rule_runs_bulk_cancel",
        title="Rule runs cancel requested",
        message=f"Requested cancel for {updated} rule runs",
        case_id=getattr(payload, "case_id", None),
        metadata={"matched": len(items), "updated": updated},
    )
    return RuleRunBulkActionResponse(matched=len(items), updated=updated)


@router.post("/api/rule-runs/bulk/retry", response_model=RuleRunBulkActionResponse)
def bulk_retry_rule_runs(payload: RuleRunBulkActionRequest, db: Session = Depends(get_db)) -> RuleRunBulkActionResponse:
    items = _resolve_rule_run_targets(db, payload)
    created_run_ids: list[str] = []
    skipped = 0
    skipped_reasons: dict[str, int] = {}
    for item in items:
        if item.status not in {RuleRunStatus.completed, RuleRunStatus.failed, RuleRunStatus.cancelled, RuleRunStatus.stale, RuleRunStatus.skipped}:
            skipped += 1
            skipped_reasons["not_retryable"] = skipped_reasons.get("not_retryable", 0) + 1
            continue
        new_run = _retry_run_from_existing(db, item)
        created_run_ids.append(new_run.id)
    log_activity(
        db,
        activity_type="rule_runs_bulk_retry",
        title="Rule runs retried in bulk",
        message=f"Queued {len(created_run_ids)} retry runs",
        case_id=getattr(payload, "case_id", None),
        metadata={"matched": len(items), "created_run_ids": created_run_ids, "skipped": skipped},
    )
    return RuleRunBulkActionResponse(matched=len(items), updated=len(created_run_ids), skipped=skipped, skipped_reasons=skipped_reasons, created_run_ids=created_run_ids)


@router.delete("/api/rule-runs/bulk", response_model=RuleRunBulkActionResponse)
def bulk_delete_rule_runs(payload: RuleRunBulkDeleteRequest, db: Session = Depends(get_db)) -> RuleRunBulkActionResponse:
    items = _resolve_rule_run_targets(db, payload)
    deleted = 0
    skipped = 0
    skipped_reasons: dict[str, int] = {}
    for item in items:
        if _run_is_active(item):
            skipped += 1
            skipped_reasons["active_run"] = skipped_reasons.get("active_run", 0) + 1
            continue
        db.delete(item)
        deleted += 1
    db.commit()
    log_activity(
        db,
        activity_type="rule_runs_bulk_delete",
        title="Rule run records deleted",
        message=f"Deleted {deleted} rule run records",
        case_id=getattr(payload, "case_id", None),
        metadata={"matched": len(items), "deleted": deleted, "skipped": skipped},
    )
    return RuleRunBulkActionResponse(matched=len(items), deleted=deleted, skipped=skipped, skipped_reasons=skipped_reasons, warnings=["Existing detections will remain."])


@router.get("/api/detections")
def list_all_detections(
    case_id: str | None = None,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    rule_name: str | None = None,
    evidence_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    matched_object_type: str | None = None,
    q: str | None = None,
    has_linked_event: bool | None = None,
    has_file_target: bool | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    orphaned_only: bool = False,
    run_type: str | None = None,
    include_deleted: bool = False,
    include_stale: bool = False,
    include_event_preview: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    sort_field: str = "created_at",
    sort_direction: str = "desc",
    db: Session = Depends(get_db),
) -> dict:
    return _list_detections_response(
        db=db,
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        matched_object_type=matched_object_type,
        q=q,
        has_linked_event=has_linked_event,
        has_file_target=has_file_target,
        created_from=created_from,
        created_to=created_to,
        orphaned_only=orphaned_only,
        run_type=run_type,
        include_deleted=include_deleted,
        include_stale=include_stale,
        include_event_preview=include_event_preview,
        page=page,
        page_size=page_size,
        sort_field=sort_field,
        sort_direction=sort_direction,
    )


@router.get("/api/cases/{case_id}/detections")
def list_detections(
    case_id: str,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    rule_name: str | None = None,
    evidence_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    matched_object_type: str | None = None,
    q: str | None = None,
    has_linked_event: bool | None = None,
    has_file_target: bool | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    orphaned_only: bool = False,
    run_type: str | None = None,
    include_deleted: bool = False,
    include_stale: bool = False,
    include_event_preview: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    sort_field: str = "created_at",
    sort_direction: str = "desc",
    db: Session = Depends(get_db),
) -> dict:
    return _list_detections_response(
        db=db,
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        matched_object_type=matched_object_type,
        q=q,
        has_linked_event=has_linked_event,
        has_file_target=has_file_target,
        created_from=created_from,
        created_to=created_to,
        orphaned_only=orphaned_only,
        run_type=run_type,
        include_deleted=include_deleted,
        include_stale=include_stale,
        include_event_preview=include_event_preview,
        page=page,
        page_size=page_size,
        sort_field=sort_field,
        sort_direction=sort_direction,
    )


@router.get("/api/detections/facets")
def detections_facets(case_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    query = db.query(DetectionResult).filter(DetectionResult.deleted_at.is_(None), DetectionResult.status.notin_(["stale", "stale_event_link"]))
    if case_id:
        query = query.filter(DetectionResult.case_id == case_id)
    rows = query.all()

    def facet_values(values: list[str]) -> list[dict]:
        counts: dict[str, int] = {}
        for value in values:
            if value:
                counts[value] = counts.get(value, 0) + 1
        return [{"value": key, "count": count} for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]

    evidence_map = {item.id: item.original_filename for item in db.query(Evidence).all()}
    evidence_counts: dict[str, dict] = {}
    for row in rows:
        if row.evidence_id:
            bucket = evidence_counts.setdefault(
                row.evidence_id,
                {"id": row.evidence_id, "name": evidence_map.get(row.evidence_id, row.evidence_id), "count": 0},
            )
            bucket["count"] += 1

    return {
        "engines": facet_values([row.engine for row in rows]),
        "sources": facet_values([row.source_engine or "" for row in rows]),
        "severities": facet_values([row.severity or "" for row in rows]),
        "statuses": facet_values([row.status for row in rows]),
        "rule_names": facet_values([row.rule_name for row in rows]),
        "hosts": facet_values([_detection_host(row) for row in rows if _detection_host(row) != "unknown"]),
        "matched_object_types": facet_values([row.target_type for row in rows]),
        "evidences": sorted(evidence_counts.values(), key=lambda item: (-item["count"], item["id"])),
        "artifacts": facet_values([row.artifact_id or "" for row in rows]),
        "has_linked_event": [
            {"value": True, "count": sum(1 for row in rows if row.event_id)},
            {"value": False, "count": sum(1 for row in rows if not row.event_id)},
        ],
        "has_file_target": [
            {"value": True, "count": sum(1 for row in rows if row.target_path)},
            {"value": False, "count": sum(1 for row in rows if not row.target_path)},
        ],
    }


def _detection_raw_string(item: DetectionResult, *keys: str) -> str | None:
    raw = item.raw or {}
    for key in keys:
        value = raw.get(key)
        if value:
            return str(value)
    preview = raw.get("event_preview") if isinstance(raw.get("event_preview"), dict) else {}
    for key in keys:
        value = preview.get(key)
        if value:
            return str(value)
    return None


def _detection_artifact_type(item: DetectionResult) -> str:
    return _detection_raw_string(item, "artifact_type", "artifact.type") or str(item.target_type or "unknown")


def _detection_source_file(item: DetectionResult) -> str:
    return _detection_raw_string(item, "source_file", "source.path", "event_source_file") or str(item.target_path or "unknown")


def _detection_user(item: DetectionResult) -> str:
    return _detection_raw_string(item, "user", "user.name", "username") or "unknown"


def _detection_host(item: DetectionResult) -> str:
    host = str(item.host_name or "").strip()
    if is_invalid_host_value(host):
        return "unknown"
    return host


def _detection_rule_run(item: DetectionResult) -> str:
    raw = item.raw or {}
    return str(raw.get("rule_run_id") or raw.get("source_run_id") or "unknown")


def _detection_time(item: DetectionResult) -> datetime | None:
    parsed = _parse_detection_timestamp(item.matched_at)
    value = parsed or item.created_at
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _counter_rows(counter: dict[str, int], *, limit: int = 50) -> list[dict]:
    return [{"key": key, "count": count} for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def _sample_append(values: list[str], value: str | None, *, limit: int = 5) -> None:
    text = str(value or "").strip()
    if text and text not in values and len(values) < limit:
        values.append(text)


def _build_detection_summary(items: list[DetectionResult], *, limit: int = 50, state_items: list[DetectionResult] | None = None) -> dict:
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_host: dict[str, int] = {}
    by_user: dict[str, int] = {}
    by_evidence: dict[str, int] = {}
    by_artifact_type: dict[str, int] = {}
    by_source_file: dict[str, int] = {}
    by_rule_run: dict[str, int] = {}
    grouped: dict[tuple[str | None, str], dict] = {}

    for item in items:
        severity = str(item.severity or "unknown")
        status_key = str(item.status or "unknown")
        host = _detection_host(item)
        user = _detection_user(item)
        evidence_id = str(item.evidence_id or "unknown")
        artifact_type = _detection_artifact_type(item)
        source_file = _detection_source_file(item)
        rule_run_id = _detection_rule_run(item)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1
        by_host[host] = by_host.get(host, 0) + 1
        by_user[user] = by_user.get(user, 0) + 1
        by_evidence[evidence_id] = by_evidence.get(evidence_id, 0) + 1
        by_artifact_type[artifact_type] = by_artifact_type.get(artifact_type, 0) + 1
        by_source_file[source_file] = by_source_file.get(source_file, 0) + 1
        by_rule_run[rule_run_id] = by_rule_run.get(rule_run_id, 0) + 1

        key = (item.rule_id, item.rule_name or item.rule_title or "Unknown rule")
        bucket = grouped.setdefault(
            key,
            {
                "rule_id": item.rule_id,
                "rule_name": item.rule_name or item.rule_title or "Unknown rule",
                "severity": severity,
                "count": 0,
                "new_count": 0,
                "reviewed_count": 0,
                "dismissed_count": 0,
                "confirmed_count": 0,
                "hosts": set(),
                "users": set(),
                "artifact_types": set(),
                "source_files": set(),
                "sample_entities": [],
                "sample_source_files": [],
                "sample_event_ids": [],
                "first_seen": None,
                "last_seen": None,
            },
        )
        bucket["count"] += 1
        if status_key == "new":
            bucket["new_count"] += 1
        elif status_key == "reviewed":
            bucket["reviewed_count"] += 1
        elif status_key == "dismissed":
            bucket["dismissed_count"] += 1
        elif status_key == "confirmed":
            bucket["confirmed_count"] += 1
        bucket["hosts"].add(host)
        bucket["users"].add(user)
        bucket["artifact_types"].add(artifact_type)
        bucket["source_files"].add(source_file)
        _sample_append(bucket["sample_entities"], item.target_path or (host if host != "unknown" else None) or item.message)
        _sample_append(bucket["sample_source_files"], source_file)
        _sample_append(bucket["sample_event_ids"], item.event_id or item.opensearch_id)
        timestamp = _detection_time(item)
        if timestamp:
            if bucket["first_seen"] is None or timestamp < bucket["first_seen"]:
                bucket["first_seen"] = timestamp
            if bucket["last_seen"] is None or timestamp > bucket["last_seen"]:
                bucket["last_seen"] = timestamp

    by_rule = []
    for bucket in grouped.values():
        by_rule.append(
            {
                "rule_id": bucket["rule_id"],
                "rule_name": bucket["rule_name"],
                "severity": bucket["severity"],
                "count": bucket["count"],
                "new_count": bucket["new_count"],
                "reviewed_count": bucket["reviewed_count"],
                "dismissed_count": bucket["dismissed_count"],
                "confirmed_count": bucket["confirmed_count"],
                "unique_hosts": len(bucket["hosts"]),
                "unique_users": len(bucket["users"]),
                "unique_artifact_types": len(bucket["artifact_types"]),
                "unique_source_files": len(bucket["source_files"]),
                "first_seen": bucket["first_seen"].isoformat() if bucket["first_seen"] else None,
                "last_seen": bucket["last_seen"].isoformat() if bucket["last_seen"] else None,
                "sample_entities": bucket["sample_entities"],
                "sample_source_files": bucket["sample_source_files"],
                "sample_event_ids": bucket["sample_event_ids"],
            }
        )
    by_rule.sort(key=lambda item: (-int(item["count"]), str(item["rule_name"])))
    top_noisy = [{**item, "percentage": round((int(item["count"]) / len(items)) * 100, 2) if items else 0.0} for item in by_rule[:10]]
    state_source = state_items if state_items is not None else items
    active_count = sum(1 for item in state_source if item.deleted_at is None and item.status not in {"stale", "stale_event_link"})
    soft_deleted_count = sum(1 for item in state_source if item.deleted_at is not None)
    dismissed_count = sum(1 for item in state_source if item.deleted_at is None and item.status == "dismissed")
    reviewed_count = sum(1 for item in state_source if item.deleted_at is None and item.status == "reviewed")
    confirmed_count = sum(1 for item in state_source if item.deleted_at is None and item.status == "confirmed")
    return {
        "total": len(items),
        "state": {
            "active": active_count,
            "soft_deleted": soft_deleted_count,
            "dismissed": dismissed_count,
            "reviewed": reviewed_count,
            "confirmed": confirmed_count,
        },
        "by_severity": by_severity,
        "by_status": by_status,
        "by_rule": by_rule[:limit],
        "by_host": _counter_rows(by_host, limit=limit),
        "by_user": _counter_rows(by_user, limit=limit),
        "by_evidence": _counter_rows(by_evidence, limit=limit),
        "by_artifact_type": _counter_rows(by_artifact_type, limit=limit),
        "by_source_file": _counter_rows(by_source_file, limit=limit),
        "by_rule_run": _counter_rows(by_rule_run, limit=limit),
        "top_noisy_rules": top_noisy,
        "new_vs_reviewed": {
            "new": by_status.get("new", 0),
            "reviewed": by_status.get("reviewed", 0),
            "dismissed": by_status.get("dismissed", 0),
            "confirmed": by_status.get("confirmed", 0),
        },
    }


@router.get("/api/detections/summary")
def detections_summary(
    case_id: str | None = None,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    rule_name: str | None = None,
    evidence_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    q: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    run_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    base_query = db.query(DetectionResult)
    query = _apply_detection_filters(
        base_query,
        db=db,
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        q=q,
        created_from=created_from,
        created_to=created_to,
        run_type=run_type,
        include_deleted=False,
        include_stale=False,
    )
    state_query = _apply_detection_filters(
        db.query(DetectionResult),
        db=db,
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        q=q,
        created_from=created_from,
        created_to=created_to,
        run_type=run_type,
        include_deleted=True,
        include_stale=False,
    )
    return _build_detection_summary(query.all(), limit=limit, state_items=state_query.all())


@router.get("/api/evidences/{evidence_id}/detections/summary")
def evidence_detections_summary(
    evidence_id: str,
    case_id: str | None = None,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    rule_name: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    q: str | None = None,
    run_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    return detections_summary(
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        q=q,
        run_type=run_type,
        limit=limit,
        db=db,
    )


@router.post("/api/detections/bulk/preview", response_model=DetectionBulkPreviewResponse)
def preview_bulk_detections_route(payload: DetectionBulkPreviewRequest, db: Session = Depends(get_db)) -> DetectionBulkPreviewResponse:
    return preview_bulk_detections(payload, db)


@router.patch("/api/detections/bulk", response_model=DetectionBulkActionResponse)
def update_bulk_detections_route(payload: DetectionBulkActionRequestV2, db: Session = Depends(get_db)) -> DetectionBulkActionResponse:
    return update_bulk_detections(payload, db)


@router.delete("/api/detections/bulk", response_model=DetectionBulkActionResponse)
def delete_bulk_detections_route(payload: DetectionBulkActionRequestV2, db: Session = Depends(get_db)) -> DetectionBulkActionResponse:
    return delete_bulk_detections(payload, db)


@router.get("/api/detections/{detection_id}", response_model=DetectionRead)
def get_detection(detection_id: str, db: Session = Depends(get_db)) -> DetectionResult:
    item = db.get(DetectionResult, detection_id)
    if not item or item.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return item


@router.patch("/api/detections/{detection_id}", response_model=DetectionRead)
def update_detection(detection_id: str, payload: DetectionUpdate, db: Session = Depends(get_db)) -> DetectionResult:
    item = db.get(DetectionResult, detection_id)
    if not item:
        raise HTTPException(status_code=404, detail="Detection not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, key, value)
    if payload.status == "archived":
        item.archived_at = utc_now()
    db.commit()
    db.refresh(item)
    return item


@router.get("/api/cases/{case_id}/detections/{detection_id}", response_model=DetectionRead)
def get_case_detection(case_id: str, detection_id: str, db: Session = Depends(get_db)) -> DetectionResult:
    item = db.get(DetectionResult, detection_id)
    if not item or item.case_id != case_id or item.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return item


@router.patch("/api/cases/{case_id}/detections/{detection_id}", response_model=DetectionRead)
def update_case_detection(case_id: str, detection_id: str, payload: DetectionUpdate, db: Session = Depends(get_db)) -> DetectionResult:
    item = db.get(DetectionResult, detection_id)
    if not item or item.case_id != case_id:
        raise HTTPException(status_code=404, detail="Detection not found")
    return update_detection(detection_id=detection_id, payload=payload, db=db)


@router.delete("/api/detections/{detection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_detection(detection_id: str, db: Session = Depends(get_db)) -> None:
    item = db.get(DetectionResult, detection_id)
    if not item or item.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Detection not found")
    item.deleted_at = utc_now()
    db.commit()
    log_activity(
        db,
        activity_type="detection_deleted",
        title="Detection deleted",
        message=f"Deleted detection {item.rule_name}",
        case_id=item.case_id,
        evidence_id=item.evidence_id,
        metadata={"detection_id": item.id},
    )


@router.post("/api/detections/bulk")
def bulk_detection_action(payload: DetectionBulkRequest, db: Session = Depends(get_db)) -> dict:
    if payload.action not in {"delete", "archive", "mark_reviewed", "mark_false_positive"}:
        raise HTTPException(status_code=400, detail="Unsupported bulk action")
    if payload.detection_ids:
        items = db.query(DetectionResult).filter(DetectionResult.id.in_(payload.detection_ids), DetectionResult.deleted_at.is_(None)).all()
    else:
        filtered_query = _apply_detection_filters(
            db.query(DetectionResult),
            case_id=payload.case_id,
            engine=payload.engine,
            severity=payload.severity,
            status_value=payload.status,
            rule_name=payload.rule_name,
            evidence_id=payload.evidence_id,
            has_linked_event=payload.has_linked_event,
            has_file_target=payload.has_file_target,
            include_deleted=False,
            include_stale=False,
        )
        items = filtered_query.all()
    if not items:
        return {"updated": 0}
    count = 0
    now = utc_now()
    for item in items:
        if payload.action == "delete":
            item.deleted_at = now
            activity_type = "detection_deleted"
        elif payload.action == "archive":
            item.status = "archived"
            item.archived_at = now
            activity_type = "detection_archived"
        elif payload.action == "mark_reviewed":
            item.status = "reviewed"
            activity_type = "detection_marked_reviewed"
        else:
            item.status = "false_positive"
            activity_type = "detection_false_positive"
        count += 1
        log_activity(
            db,
            activity_type=activity_type,
            title="Detection updated",
            message=f"{payload.action} detection {item.rule_name}",
            case_id=item.case_id,
            evidence_id=item.evidence_id,
            metadata={"detection_id": item.id, "action": payload.action},
        )
    db.commit()
    return {"updated": count}


@router.get("/api/detections/{detection_id}/event")
def get_detection_event(detection_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(DetectionResult, detection_id)
    if not item or item.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Detection not found")
    if item.target_type != "event" or not (item.event_id or item.opensearch_id):
        raise HTTPException(status_code=404, detail={"error": "Detection is not linked to an indexed event.", "target_type": item.target_type})
    event = fetch_event_by_id(item.case_id, item.event_id, event_index=item.event_index, opensearch_id=item.opensearch_id)
    if not event:
        item.status = "stale_event_link"
        db.commit()
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Linked event not found in OpenSearch index.",
                "event_id": item.event_id,
                "case_id": item.case_id,
                "opensearch_id": item.opensearch_id,
                "event_index": item.event_index,
            },
        )
    return event


@router.post("/api/detections/{detection_id}/promote-to-finding", response_model=FindingRead)
def promote_detection_to_finding(detection_id: str, db: Session = Depends(get_db)) -> Finding:
    detection = db.get(DetectionResult, detection_id)
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    finding = Finding(
        case_id=detection.case_id,
        title=detection.rule_name,
        description=detection.message or f"Promoted from {detection.engine} detection.",
        severity=_safe_finding_severity(detection.severity),
        event_ids=[detection.event_id] if detection.event_id else [],
        detection_ids=[detection.id],
    )
    db.add(finding)
    detection.status = "promoted_to_finding"
    db.commit()
    db.refresh(finding)
    log_activity(
        db,
        activity_type="finding_created",
        title="Detection promoted to finding",
        message=f"Promoted detection {detection.rule_name} to finding {finding.title}",
        case_id=finding.case_id,
        evidence_id=detection.evidence_id,
        metadata={"finding_id": finding.id, "detection_id": detection.id},
    )
    return finding


def _serialize_detection(item: DetectionResult) -> dict:
    raw = item.raw or {}
    metadata_json = (item.rule.metadata_json or {}) if item.rule else {}
    payload = DetectionRead.model_validate(item).model_dump(mode="json")
    payload["rule_run_id"] = raw.get("rule_run_id") or raw.get("source_run_id")
    payload["rule_import_run_id"] = raw.get("rule_import_run_id") or raw.get("import_run_id") or metadata_json.get("import_run_id")
    payload["rule_source_pack"] = raw.get("rule_source_pack") or raw.get("source_pack") or metadata_json.get("source_pack")
    payload["orphaned_rule"] = bool(item.rule_id and item.rule is None)
    return payload


def _resolve_detection_targets(
    db: Session,
    *,
    mode: str,
    detection_ids: list[str] | None = None,
    filters: DetectionBulkFilterSet | None = None,
    case_id: str | None = None,
    rule_run_id: str | None = None,
    rule_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    include_deleted: bool = False,
):
    detection_ids = [item for item in (detection_ids or []) if str(item).strip()]
    query = db.query(DetectionResult)
    if mode == "selected":
        if not detection_ids:
            return query.filter(False)
        return query.filter(DetectionResult.id.in_(detection_ids))
    if mode == "rule_run":
        if not rule_run_id:
            return query.filter(False)
        merged = _coalesce_detection_filters(case_id=case_id, rule_run_id=rule_run_id, filters=filters)
    elif mode == "rule":
        if not rule_id:
            return query.filter(False)
        merged = _coalesce_detection_filters(case_id=case_id, rule_id=rule_id, filters=filters)
    elif mode == "import_run":
        if not import_run_id:
            return query.filter(False)
        merged = _coalesce_detection_filters(case_id=case_id, import_run_id=import_run_id, filters=filters)
    elif mode == "source_pack":
        if not source_pack:
            return query.filter(False)
        merged = _coalesce_detection_filters(case_id=case_id, source_pack=source_pack, filters=filters)
    elif mode == "orphaned_rules":
        merged = _coalesce_detection_filters(case_id=case_id, orphaned_only=True, filters=filters)
    else:
        merged = _coalesce_detection_filters(case_id=case_id, filters=filters)
    return _apply_detection_filters(
        query,
        db=db,
        case_id=merged["case_id"],
        source=merged["source"],
        engine=merged["engine"],
        rule_id=merged["rule_id"],
        rule_run_id=merged["rule_run_id"],
        import_run_id=merged["import_run_id"],
        source_pack=merged["source_pack"],
        severity=merged["severity"],
        status_value=merged["status_value"],
        rule_name=merged["rule_name"],
        evidence_id=merged["evidence_id"],
        host=merged["host"],
        user=merged["user"],
        artifact_type=merged["artifact_type"],
        source_file=merged["source_file"],
        matched_object_type=merged["matched_object_type"],
        q=merged["q"],
        has_linked_event=merged["has_linked_event"],
        has_file_target=merged["has_file_target"],
        created_from=merged["created_from"],
        created_to=merged["created_to"],
        orphaned_only=merged["orphaned_only"],
        include_deleted=include_deleted,
        include_stale=False,
    )


def _build_detection_bulk_preview(items: list[DetectionResult]) -> DetectionBulkPreviewResponse:
    by_source: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_rule_counts: dict[tuple[str | None, str], int] = {}
    by_run_counts: dict[str, int] = {}
    orphaned_rule_count = 0
    for item in items:
        raw = item.raw or {}
        source_key = str(item.source_engine or item.engine or "unknown")
        by_source[source_key] = by_source.get(source_key, 0) + 1
        status_key = str(item.status or "unknown")
        by_status[status_key] = by_status.get(status_key, 0) + 1
        severity_key = str(item.severity or "unknown")
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
        rule_key = (item.rule_id, item.rule_title or item.rule_name or item.rule_id or "Unknown rule")
        by_rule_counts[rule_key] = by_rule_counts.get(rule_key, 0) + 1
        run_id = str(raw.get("rule_run_id") or raw.get("source_run_id") or "").strip()
        if run_id:
            by_run_counts[run_id] = by_run_counts.get(run_id, 0) + 1
        if item.rule is None and (item.rule_id or raw.get("rule") or raw.get("rule_title") or raw.get("rule_import_run_id") or raw.get("rule_source_pack")):
            orphaned_rule_count += 1
    by_rule = [
        DetectionBulkRuleBreakdown(rule_id=rule_id, title=title, count=count)
        for (rule_id, title), count in sorted(by_rule_counts.items(), key=lambda item: (-item[1], item[0][1]))[:10]
    ]
    by_run = [
        DetectionBulkRunBreakdown(rule_run_id=run_id, count=count)
        for run_id, count in sorted(by_run_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]
    return DetectionBulkPreviewResponse(
        matched=len(items),
        by_source=by_source,
        by_status=by_status,
        by_severity=by_severity,
        by_rule=by_rule,
        by_run=by_run,
        orphaned_rule_count=orphaned_rule_count,
        protected_count=0,
        warnings=[
            "Existing findings will not be deleted automatically.",
            "Reports generated before deletion may reference deleted detections.",
            "Findings and reports are not automatically deleted. Review them separately.",
        ],
    )


def _record_detection_bulk_activity(
    db: Session,
    *,
    activity_type: str,
    title: str,
    message: str,
    case_id: str | None,
    mode: str,
    matched: int,
    updated: int = 0,
    deleted: int = 0,
    filters: dict | None = None,
):
    return log_activity(
        db,
        activity_type=activity_type,
        title=title,
        message=message,
        case_id=case_id,
        metadata={
            "mode": mode,
            "matched": matched,
            "updated": updated,
            "deleted": deleted,
            "filters": filters or {},
        },
    )


def preview_bulk_detections(payload: DetectionBulkPreviewRequest, db: Session = Depends(get_db)) -> DetectionBulkPreviewResponse:
    items = _resolve_detection_targets(
        db,
        mode=payload.mode,
        detection_ids=payload.detection_ids,
        filters=payload.filters,
        case_id=payload.case_id,
        rule_run_id=payload.rule_run_id,
        rule_id=payload.rule_id,
        import_run_id=payload.import_run_id,
        source_pack=payload.source_pack,
    ).all()
    return _build_detection_bulk_preview(items)


def update_bulk_detections(payload: DetectionBulkActionRequestV2, db: Session = Depends(get_db)) -> DetectionBulkActionResponse:
    action_map = {"mark_reviewed": "reviewed", "mark_dismissed": "dismissed", "mark_new": "new"}
    if payload.action not in action_map:
        raise HTTPException(status_code=400, detail="Unsupported detection bulk action")
    items = _resolve_detection_targets(
        db,
        mode=payload.mode,
        detection_ids=payload.detection_ids,
        filters=payload.filters,
        case_id=payload.case_id,
        rule_run_id=payload.rule_run_id,
        rule_id=payload.rule_id,
        import_run_id=payload.import_run_id,
        source_pack=payload.source_pack,
    ).all()
    updated = 0
    for item in items:
        new_status = action_map[payload.action]
        if item.status == new_status:
            continue
        item.status = new_status
        if new_status != "archived":
            item.archived_at = None
        updated += 1
    db.commit()
    activity = _record_detection_bulk_activity(
        db,
        activity_type="detections_bulk_update",
        title="Detections updated in bulk",
        message=f"Updated {updated} detections",
        case_id=payload.case_id or payload.filters.case_id,
        mode=payload.mode,
        matched=len(items),
        updated=updated,
        filters=payload.filters.model_dump(exclude_none=True),
    )
    return DetectionBulkActionResponse(matched=len(items), updated=updated, warnings=["Existing findings and reports were not modified."], activity_id=getattr(activity, "id", None))


def delete_bulk_detections(payload: DetectionBulkActionRequestV2, db: Session = Depends(get_db)) -> DetectionBulkActionResponse:
    items = _resolve_detection_targets(
        db,
        mode=payload.mode,
        detection_ids=payload.detection_ids,
        filters=payload.filters,
        case_id=payload.case_id,
        rule_run_id=payload.rule_run_id,
        rule_id=payload.rule_id,
        import_run_id=payload.import_run_id,
        source_pack=payload.source_pack,
    ).all()
    matched = len(items)
    requires_confirm = matched > 25 or payload.mode != "selected"
    expected_confirm = f"DELETE {matched} DETECTIONS"
    if requires_confirm and payload.confirm != expected_confirm:
        raise HTTPException(status_code=400, detail=f"{expected_confirm} confirmation required")
    now = utc_now()
    deleted = 0
    for item in items:
        if item.deleted_at is not None:
            continue
        item.deleted_at = now
        deleted += 1
    db.commit()
    activity = _record_detection_bulk_activity(
        db,
        activity_type="detections_bulk_delete",
        title="Detections deleted in bulk",
        message=f"Deleted {deleted} detections",
        case_id=payload.case_id or payload.filters.case_id,
        mode=payload.mode,
        matched=matched,
        deleted=deleted,
        filters=payload.filters.model_dump(exclude_none=True),
    )
    return DetectionBulkActionResponse(
        matched=matched,
        deleted=deleted,
        warnings=[
            "Existing findings will remain unless deleted separately.",
            "Reports generated before deletion may still reference deleted detections.",
        ],
        activity_id=getattr(activity, "id", None),
    )


def _apply_rule_run_detection_filter(query, db: Session, rule_run_id: str):
    run = db.get(RuleRun, rule_run_id)
    if not run:
        return query.filter(False)
    query = query.filter(DetectionResult.case_id == run.case_id)
    direct_match = or_(
        DetectionResult.raw["rule_run_id"].as_string() == run.id,
        DetectionResult.raw["source_run_id"].as_string() == run.id,
    )
    fallback_matchers = []
    if run.rule_id:
        fallback_matchers.append(DetectionResult.rule_id == run.rule_id)
    elif run.rule_set_id:
        fallback_matchers.append(DetectionResult.rule_set_id == run.rule_set_id)
    else:
        requested_rule_ids = []
        if isinstance(run.metadata_json, dict):
            requested_rule_ids = [value for value in (run.metadata_json.get("requested_rule_ids") or []) if isinstance(value, str)]
        if requested_rule_ids:
            fallback_matchers.append(DetectionResult.rule_id.in_(requested_rule_ids))
        elif run.engine and run.engine != "multi":
            fallback_matchers.append(DetectionResult.engine == run.engine)
    if run.evidence_id:
        fallback_matchers.append(DetectionResult.evidence_id == run.evidence_id)
    return query.filter(or_(direct_match, *fallback_matchers))


def _detection_import_run_expr():
    return func.coalesce(
        DetectionResult.raw["rule_import_run_id"].as_string(),
        DetectionResult.raw["import_run_id"].as_string(),
        Rule.metadata_json["import_run_id"].as_string(),
    )


def _detection_source_pack_expr():
    return func.coalesce(
        DetectionResult.raw["rule_source_pack"].as_string(),
        DetectionResult.raw["source_pack"].as_string(),
        Rule.metadata_json["source_pack"].as_string(),
    )


def _detection_rule_run_expr():
    return func.coalesce(
        DetectionResult.raw["rule_run_id"].as_string(),
        DetectionResult.raw["source_run_id"].as_string(),
    )


def _parse_detection_timestamp(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _coalesce_detection_filters(
    *,
    case_id: str | None = None,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = None,
    rule_name: str | None = None,
    evidence_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    matched_object_type: str | None = None,
    q: str | None = None,
    has_linked_event: bool | None = None,
    has_file_target: bool | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    orphaned_only: bool | None = None,
    run_type: str | None = None,
    filters: DetectionBulkFilterSet | None = None,
) -> dict:
    values = {
        "case_id": case_id,
        "source": source,
        "engine": engine,
        "rule_id": rule_id,
        "rule_run_id": rule_run_id,
        "import_run_id": import_run_id,
        "source_pack": source_pack,
        "severity": severity,
        "status_value": status_value,
        "rule_name": rule_name,
        "evidence_id": evidence_id,
        "host": host,
        "user": user,
        "artifact_type": artifact_type,
        "source_file": source_file,
        "matched_object_type": matched_object_type,
        "q": q,
        "has_linked_event": has_linked_event,
        "has_file_target": has_file_target,
        "created_from": created_from,
        "created_to": created_to,
        "orphaned_only": orphaned_only,
        "run_type": run_type,
    }
    if filters is None:
        return values
    return {
        "case_id": case_id or filters.case_id,
        "source": source or filters.source,
        "engine": engine or filters.engine,
        "rule_id": rule_id or filters.rule_id,
        "rule_run_id": rule_run_id or filters.rule_run_id,
        "import_run_id": import_run_id or filters.import_run_id,
        "source_pack": source_pack or filters.source_pack,
        "severity": severity or filters.severity,
        "status_value": status_value or filters.status,
        "rule_name": rule_name or filters.rule_name,
        "evidence_id": evidence_id or filters.evidence_id,
        "host": host or filters.host,
        "user": user or filters.user,
        "artifact_type": artifact_type or filters.artifact_type,
        "source_file": source_file or filters.source_file,
        "matched_object_type": matched_object_type or filters.matched_object_type,
        "q": q or filters.q,
        "has_linked_event": has_linked_event if has_linked_event is not None else filters.has_linked_event,
        "has_file_target": has_file_target if has_file_target is not None else filters.has_file_target,
        "created_from": created_from or filters.created_from,
        "created_to": created_to or filters.created_to,
        "orphaned_only": orphaned_only if orphaned_only is not None else filters.orphaned_only,
        "run_type": run_type or filters.run_type,
    }


def _apply_detection_filters(
    query,
    *,
    db: Session | None = None,
    case_id: str | None = None,
    source: str | None = None,
    engine: str | None = None,
    rule_id: str | None = None,
    rule_run_id: str | None = None,
    import_run_id: str | None = None,
    source_pack: str | None = None,
    severity: str | None = None,
    status_value: str | None = None,
    rule_name: str | None = None,
    evidence_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    artifact_type: str | None = None,
    source_file: str | None = None,
    matched_object_type: str | None = None,
    q: str | None = None,
    has_linked_event: bool | None = None,
    has_file_target: bool | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    orphaned_only: bool | None = None,
    run_type: str | None = None,
    include_deleted: bool = False,
    include_stale: bool = False,
):
    query = query.outerjoin(Rule, DetectionResult.rule_id == Rule.id)
    if case_id:
        query = query.filter(DetectionResult.case_id == case_id)
    if not include_deleted:
        query = query.filter(DetectionResult.deleted_at.is_(None))
    if not include_stale:
        query = query.filter(DetectionResult.status.notin_(["stale", "stale_event_link"]))
    if source:
        query = query.filter(DetectionResult.source_engine == source)
    if engine:
        query = query.filter(DetectionResult.engine == engine)
    if rule_id:
        query = query.filter(DetectionResult.rule_id == rule_id)
    if rule_run_id and db is not None:
        query = _apply_rule_run_detection_filter(query, db, rule_run_id)
    if run_type:
        query = query.filter(DetectionResult.raw["run_type"].as_string() == run_type)
    if import_run_id:
        query = query.filter(_detection_import_run_expr() == import_run_id)
    if source_pack:
        query = query.filter(_detection_source_pack_expr() == source_pack)
    if severity:
        query = query.filter(DetectionResult.severity == severity)
    if status_value:
        query = query.filter(DetectionResult.status == status_value)
    if rule_name:
        query = query.filter(DetectionResult.rule_name == rule_name)
    if evidence_id:
        query = query.filter(DetectionResult.evidence_id == evidence_id)
    if host:
        query = query.filter(DetectionResult.host_name == host)
    if user:
        query = query.filter(
            or_(
                DetectionResult.raw["user"].as_string() == user,
                DetectionResult.raw["user.name"].as_string() == user,
                DetectionResult.raw["username"].as_string() == user,
                DetectionResult.raw["event_preview"]["user"].as_string() == user,
            )
        )
    if artifact_type:
        query = query.filter(DetectionResult.raw["artifact_type"].as_string() == artifact_type)
    if source_file:
        token = f"%{source_file.strip()}%"
        query = query.filter(
            or_(
                DetectionResult.raw["source_file"].as_string().ilike(token),
                DetectionResult.raw["source.path"].as_string().ilike(token),
                DetectionResult.raw["event_source_file"].as_string().ilike(token),
                DetectionResult.target_path.ilike(token),
            )
        )
    if matched_object_type:
        query = query.filter(DetectionResult.target_type == matched_object_type)
    if q:
        token = f"%{q.strip()}%"
        query = query.filter(
            (DetectionResult.rule_name.ilike(token))
            | (DetectionResult.rule_title.ilike(token))
            | (DetectionResult.target_path.ilike(token))
            | (DetectionResult.message.ilike(token))
            | (DetectionResult.condition_summary.ilike(token))
            | (_detection_source_pack_expr().ilike(token))
            | (_detection_import_run_expr().ilike(token))
        )
    if has_linked_event is True:
        query = query.filter(DetectionResult.event_id.is_not(None))
    elif has_linked_event is False:
        query = query.filter(DetectionResult.event_id.is_(None))
    if has_file_target is True:
        query = query.filter(DetectionResult.target_path.is_not(None))
    elif has_file_target is False:
        query = query.filter(DetectionResult.target_path.is_(None))
    created_from_ts = _parse_detection_timestamp(created_from)
    if created_from_ts is not None:
        query = query.filter(DetectionResult.created_at >= created_from_ts)
    created_to_ts = _parse_detection_timestamp(created_to)
    if created_to_ts is not None:
        query = query.filter(DetectionResult.created_at <= created_to_ts)
    if orphaned_only:
        query = query.filter(
            Rule.id.is_(None),
            or_(
                DetectionResult.rule_id.is_not(None),
                DetectionResult.raw["rule"].as_string().is_not(None),
                DetectionResult.raw["rule_title"].as_string().is_not(None),
                DetectionResult.raw["rule_import_run_id"].as_string().is_not(None),
                DetectionResult.raw["rule_source_pack"].as_string().is_not(None),
            ),
        )
    return query


def _list_detections_response(
    *,
    db: Session,
    case_id: str | None,
    source: str | None,
    engine: str | None,
    rule_id: str | None,
    rule_run_id: str | None,
    import_run_id: str | None,
    source_pack: str | None,
    severity: str | None,
    status_value: str | None,
    rule_name: str | None,
    evidence_id: str | None,
    host: str | None,
    user: str | None,
    artifact_type: str | None,
    source_file: str | None,
    matched_object_type: str | None,
    q: str | None,
    has_linked_event: bool | None,
    has_file_target: bool | None,
    created_from: str | None,
    created_to: str | None,
    orphaned_only: bool,
    run_type: str | None,
    include_deleted: bool,
    include_stale: bool,
    include_event_preview: bool,
    page: int,
    page_size: int,
    sort_field: str,
    sort_direction: str,
) -> dict:
    base_query = _apply_detection_filters(
        db.query(DetectionResult),
        db=db,
        case_id=case_id,
        source=source,
        engine=engine,
        rule_id=rule_id,
        rule_run_id=rule_run_id,
        import_run_id=import_run_id,
        source_pack=source_pack,
        severity=severity,
        status_value=status_value,
        rule_name=rule_name,
        evidence_id=evidence_id,
        host=host,
        user=user,
        artifact_type=artifact_type,
        source_file=source_file,
        matched_object_type=matched_object_type,
        q=q,
        has_linked_event=has_linked_event,
        has_file_target=has_file_target,
        created_from=created_from,
        created_to=created_to,
        orphaned_only=orphaned_only,
        run_type=run_type,
        include_deleted=include_deleted,
        include_stale=include_stale,
    )
    total = base_query.count()
    sort_column = DETECTION_SORT_FIELDS.get(sort_field, DetectionResult.created_at)
    ordered = base_query.order_by(desc(sort_column) if sort_direction.lower() == "desc" else asc(sort_column), desc(DetectionResult.created_at))
    items = ordered.offset((page - 1) * page_size).limit(page_size).all()
    if include_event_preview:
        for item in items:
            if item.event_id and item.deleted_at is None and item.target_type == "event":
                event = fetch_event_by_id(item.case_id, item.event_id, event_index=item.event_index, opensearch_id=item.opensearch_id)
                if event:
                    item.raw = {
                        **(item.raw or {}),
                        "event_preview": {
                            "timestamp": event.get("@timestamp"),
                            "summary": ((event.get("event") or {}) if isinstance(event, dict) else {}).get("message"),
                            "host": ((event.get("host") or {}) if isinstance(event, dict) else {}).get("name"),
                            "user": ((event.get("user") or {}) if isinstance(event, dict) else {}).get("name"),
                            "artifact_type": ((event.get("artifact") or {}) if isinstance(event, dict) else {}).get("type"),
                            "event_category": ((event.get("event") or {}) if isinstance(event, dict) else {}).get("category"),
                            "event_type": ((event.get("event") or {}) if isinstance(event, dict) else {}).get("type"),
                        },
                    }
    return {
        "items": [_serialize_detection(item) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }
