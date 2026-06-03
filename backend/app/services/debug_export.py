from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import io
import json
from pathlib import PureWindowsPath
import re
import time
from typing import Any
from urllib.parse import unquote
import zipfile

from dateutil import parser as date_parser
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.analysis.semi_auto import build_case_semi_auto_analysis
from app.api.routes_search import build_search_query
from app.core.config import get_settings
from app.core.opensearch import count_documents, fetch_event_by_id, get_events_index, get_opensearch_client, refresh_index, resolve_aggregatable_field, search_documents
from app.core.storage import evidence_manifest_path
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_analysis_job import CaseAnalysisJob
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, resolve_public_evidence_type
from app.services.problematic_artifacts import build_long_tail_artifacts_report, build_problematic_artifacts_report
from app.models.finding import Finding
from app.models.rule_run import RuleRun
from app.schemas.debug_export import DebugExportRequest
from app.schemas.event import SearchRequest
from app.services.host_attribution import build_host_attribution_report
from app.services.host_identity import build_case_host_candidates, get_case_hosts, get_host_identity_audit, normalize_host_alias
from app.services.evidence_runs import get_evidence_run, get_latest_ingest_run
from app.services.ingest_benchmarks import compare_ingest_benchmarks, get_ingest_benchmark_by_run_id, list_ingest_benchmarks
from app.services.parser_backend_evaluation import build_core_parser_backend_evaluation
from app.services.job_watchdog import generate_watchdog_report
from app.services.parser_registry import (
    build_indexed_field_coverage_by_artifact_type,
    build_non_searchable_artifacts_report,
    build_parser_coverage_matrix,
    build_parser_registry_report,
    build_searchable_contract_report,
)
from app.services.usable_ingest import (
    build_indexed_document_counts_by_artifact_type,
    build_parser_tier_report,
    build_search_filter_coverage,
    ingest_mode_metadata,
    normalize_ingest_mode,
)
from app.rules_engine.builtin_catalog import BUILTIN_DETECTION_CATALOG
from app.analysis.suspicious import normalize_windows_path_for_classification


settings = get_settings()
_SENSITIVE_KEY_RE = re.compile(
    r"(keymaterial|password|token|bearer|authorization|cookie|secret|private[_ -]?key|api[_ -]?key|connection[_ -]?string|refresh[_ -]?token|access[_ -]?token)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(bearer\s+[A-Za-z0-9._-]+|-----BEGIN [A-Z ]+ PRIVATE KEY-----|password\s*[=:]|token\s*[=:]|api[_ -]?key\s*[=:]|authorization\s*:)",
    re.IGNORECASE,
)
_README = """# Debug Export Pack

This pack is a reduced validation/debug export for Kairon DFIR.

## What it contains
- Ingest/discovery/parser summaries
- Representative normalized event samples
- EVTX classification samples and aggregate EVTX classification report
- Timeline samples and excluded timeline samples
- Rule matches and semi-automatic analysis output
- Field coverage, data-quality and dedup reports
- OpenSearch indexing error summaries

## What it does not contain by default
- Full raw evidence
- Full EVTX files
- Full raw XML
- Original user files

## Privacy warning
Even with redaction enabled, packs may still contain hostnames, usernames, file paths, domains, artifact names and forensic metadata. Review before sharing externally.

## Recommended review order
1. manifest.json
2. ingest_summary.json
3. discovery_candidates.json
4. parser_audit.json
5. opensearch_indexing_errors.json
6. normalized_events_sample.jsonl
7. field_coverage_report.json
8. data_quality_report.json
9. semiauto_analysis.json

## EVTX note
The EVTX classification report only applies to native_evtx / evtx_raw events. EvtxECmd/Zimmerman events are represented in normalized_events_sample.

## Typical use cases
- Review EVTX misclassification by channel/provider/event_id
- Review LNK targets and missing target metadata
- Review cloud config vs cloud sync root normalization
- Review timeline exclusion due to missing timestamps
- Review OpenSearch mapping/indexing problems
"""


@dataclass
class _DebugPackContext:
    case: Case
    evidences: list[Evidence]
    request: DebugExportRequest
    export_timestamp: datetime


@dataclass
class _FetchedEvents:
    sampled_events: list[dict]
    total_events: int
    evtx_classification_sample: list[dict]
    scope_query: dict[str, Any] | None = None


def _safe_collect(label: str, collector, default):  # noqa: ANN001
    try:
        return collector(), None
    except Exception as exc:  # noqa: BLE001
        return default, f"{label} collection failed: {exc.__class__.__name__}: {exc}"


def _infer_selected_artifact_types(
    context: _DebugPackContext,
    discovery_candidates: list[dict] | None = None,
) -> list[str]:
    explicit = sorted(
        {
            str(category).lower()
            for evidence in context.evidences
            for category in ((evidence.metadata_json or {}).get("selected_artifact_types") or [])
            if category
        }
    )
    if explicit:
        return explicit

    inferred: set[str] = set()
    candidate_rows = discovery_candidates or _collect_discovery_candidates(context)
    for candidate in candidate_rows:
        if candidate.get("selected_for_extraction") is True:
            category = str(candidate.get("category") or "").strip().lower()
            if category:
                inferred.add(category)
    return sorted(inferred)


def _normalize_forensic_path_key(value: object | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    current = text
    for _ in range(4):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    current = current.replace("\\", "/")
    current = re.sub(r"^[A-Za-z]%3[Aa]/", lambda match: f"{match.group(0)[0]}:/", current)
    current = re.sub(r"^([A-Za-z]):(?!/)", lambda match: f"{match.group(1)}:/", current)
    current = re.sub(r"/+", "/", current)
    current = re.sub(r"(?i)%254(?=[^/]+\.evtx$)", "/", current)
    current = re.sub(r"(?i)%4(?=[^/]+\.evtx$)", "/", current)
    current = current.replace("%2f", "/").replace("%2F", "/")
    current = current.replace("%5c", "/").replace("%5C", "/")
    current = re.sub(r"^([A-Za-z]):/", lambda match: f"{match.group(1).lower()}:/", current)
    current = current.lower()
    return current


def generate_debug_pack(db: Session, case_id: str, request: DebugExportRequest) -> tuple[bytes, str]:
    case = db.get(Case, case_id)
    if not case:
        raise ValueError("Case not found")

    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.asc())
    if request.evidence_id:
        evidences = evidences_query.filter(Evidence.id == request.evidence_id).all()
    else:
        evidences = evidences_query.all()
    if request.evidence_id and not evidences:
        raise ValueError("Evidence not found for this case")

    context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
    warnings: list[str] = []

    manifests, manifests_warning = _safe_collect("manifests", lambda: _load_manifests(context), {})
    if manifests_warning:
        warnings.append(manifests_warning)
    parser_audit, parser_warning = _safe_collect("parser audit", lambda: _build_parser_audit(context, manifests), [])
    if parser_warning:
        warnings.append(parser_warning)
    discovery_candidates, discovery_warning = _safe_collect("discovery candidates", lambda: _collect_discovery_candidates(context), [])
    if discovery_warning:
        warnings.append(discovery_warning)
    indexing_errors, indexing_warning = _safe_collect("indexing errors", lambda: _collect_indexing_errors(context, manifests), [])
    if indexing_warning:
        warnings.append(indexing_warning)
    ingest_summary, ingest_warning = _safe_collect("ingest summary", lambda: _build_ingest_summary(context, manifests), [])
    if ingest_warning:
        warnings.append(ingest_warning)
    ingest_performance_report, ingest_performance_warning = _safe_collect(
        "ingest performance",
        lambda: _build_ingest_performance_report(context, manifests, ingest_summary),
        {},
    )
    if ingest_performance_warning:
        warnings.append(ingest_performance_warning)
    problematic_artifacts_report, problematic_artifacts_warning = _safe_collect(
        "problematic artifacts",
        lambda: _build_problematic_artifacts_export(context, manifests),
        {},
    )
    if problematic_artifacts_warning:
        warnings.append(problematic_artifacts_warning)
    long_tail_artifacts_report, long_tail_warning = _safe_collect(
        "long tail artifacts",
        lambda: _build_long_tail_artifacts_export(context),
        {},
    )
    if long_tail_warning:
        warnings.append(long_tail_warning)
    ingest_coverage_comparison = _build_ingest_coverage_comparison_report(
        context,
        problematic_artifacts_report=problematic_artifacts_report,
    )
    usable_ingest_summary = _build_usable_ingest_summary(context, problematic_artifacts_report=problematic_artifacts_report)
    parser_tier_report = _build_parser_tier_export(context, manifests)
    indexed_document_counts_by_artifact_type = _build_indexed_document_counts_export(context, manifests)
    deferred_artifacts_report = _build_deferred_artifacts_export(problematic_artifacts_report)
    search_filter_coverage = _build_search_filter_coverage_export(context, manifests)

    fetched_events_result, events_warning = _safe_collect("events", lambda: _invoke_fetch_events_for_scope(context, parser_audit), _FetchedEvents(sampled_events=[], total_events=0, evtx_classification_sample=[]))
    if events_warning:
        warnings.append(events_warning)
    fetched_events = _coerce_fetched_events(fetched_events_result)
    sanitized_events = [_sanitize_event(event, request) for event in fetched_events.sampled_events]
    parser_registry_report = _build_parser_registry_export(context, manifests)
    searchable_contract_report = _build_searchable_contract_export(context, manifests, sanitized_events)
    parser_coverage_matrix = _build_parser_coverage_matrix_export(context, manifests, sanitized_events)
    indexed_field_coverage_by_artifact_type = _build_indexed_field_coverage_export(sanitized_events)
    non_searchable_artifacts_report = _build_non_searchable_artifacts_export(context, manifests)
    timeline_included = [event for event in sanitized_events if event.get("@timestamp") and (event.get("event", {}) or {}).get("timeline_include", True)]
    timeline_excluded = []
    for event in sanitized_events:
        if event in timeline_included:
            continue
        reasons = list((event.get("data_quality") or []))
        if not event.get("@timestamp"):
            reasons.append("missing_timestamp")
        if not (event.get("event", {}) or {}).get("timeline_include", True):
            reasons.append("timeline_include_false")
        timeline_excluded.append({
            "id": event.get("id"),
            "event_id": event.get("event_id"),
            "artifact": event.get("artifact"),
            "source_file": event.get("source_file"),
            "reasons": sorted(set(filter(None, reasons))),
        })
    evtx_classification_sample = [_reduce_evtx_classification_event(_sanitize_event(event, request)) for event in fetched_events.evtx_classification_sample]

    rules, rules_warning = _safe_collect("rules", lambda: _invoke_collect_rules_matches(db, context, request), [])
    if rules_warning:
        warnings.append(rules_warning)
    semiauto, semiauto_warning = _safe_collect("semiauto", lambda: _collect_semiauto_analysis(db, context), {"warnings": [], "sections": {}, "counts": {}, "activities": []})
    if semiauto_warning:
        warnings.append(semiauto_warning)
    coverage, coverage_warning = _safe_collect("field coverage", lambda: _build_field_coverage_report(sanitized_events), {})
    if coverage_warning:
        warnings.append(coverage_warning)
    data_quality, dq_warning = _safe_collect("data quality", lambda: _build_data_quality_report(sanitized_events), {})
    if dq_warning:
        warnings.append(dq_warning)
    dedup, dedup_warning = _safe_collect("dedup", lambda: _build_dedup_report(sanitized_events), {})
    if dedup_warning:
        warnings.append(dedup_warning)
    suspicious = [
        event for event in sanitized_events
        if _event_is_suspicious(event)
    ]

    indexed_events_total = int(sum(int(item.get("indexed_events") or 0) for item in ingest_summary))
    normalized_events_total = max(fetched_events.total_events, indexed_events_total if request.scope in {"case", "evidence", "artifact_type", "semiauto"} else 0)
    timeline_events_total, suspicious_events_total = _collect_scope_counts(context, fetched_events.scope_query)
    rules_matches_total = _count_rules_matches(db, context)
    detections_report = _build_detections_report(db, context)
    rules_run_report = _build_rules_run_report(db, context)
    sigma_matches = [item for item in rules if item.get("rule_namespace") != "yara"]
    yara_matches = [item for item in rules if "yara" in str(item.get("rule_namespace") or "").lower() or str(item.get("rule_name") or "").lower().startswith("yara")]

    if len(sanitized_events) >= max(request.max_events_per_type * 20, 250):
        warnings.append("Event export is sampled and may not include every event.")
    if request.scope == "semiauto" and not semiauto:
        warnings.append("Semi-automatic analysis was not available and could not be built.")
    if request.include_full_raw:
        warnings.append("include_full_raw was requested, but full raw evidence export is intentionally not included by default in this build.")

    selected_artifact_types = request.artifact_types or _infer_selected_artifact_types(context, discovery_candidates)
    process_graph = _build_process_graph(sanitized_events, context.case.id, request.evidence_id, request.scope)
    process_tree_report = _build_process_tree_report(process_graph, sanitized_events, selected_scope=request.scope)
    process_tree_sample_chains = _build_process_tree_sample_chains(process_graph)
    correlation_findings = _collect_correlation_findings(db, context)
    correlation_findings_report = _build_correlation_findings_report(context, correlation_findings, process_graph)
    correlation_sample_findings = correlation_findings[: min(10, len(correlation_findings))]
    noise_reduction_report = _build_noise_reduction_report(sanitized_events, correlation_findings)
    host_attribution_report = build_host_attribution_report(
        context.case.id,
        evidences=context.evidences,
        findings=db.query(Finding).filter(Finding.case_id == context.case.id).all(),
    )
    host_identity_report = _build_host_identity_report(db, context.case.id, sanitized_events)
    ingest_regression_report = _build_ingest_regression_report(
        context,
        manifests=manifests,
        parser_audit=parser_audit,
        ingest_summary=ingest_summary,
        host_attribution_report=host_attribution_report,
    )
    ingest_plans = [
        {
            "evidence_id": evidence.id,
            "name": evidence.original_filename,
            "ingest_plan": dict((evidence.metadata_json or {}).get("ingest_plan") or {}),
            "ingest_plan_snapshots": list((evidence.metadata_json or {}).get("ingest_plan_snapshots") or []),
            "ingest_plan_preview": dict((evidence.metadata_json or {}).get("ingest_plan_preview") or {}),
        }
        for evidence in context.evidences
    ]
    ingest_plan_diff = [
        {
            "evidence_id": item["evidence_id"],
            "summary": dict((item.get("ingest_plan_preview") or {}).get("summary") or {}),
            "missing_candidates": list((item.get("ingest_plan_preview") or {}).get("missing_candidates") or []),
            "changed_candidates": list((item.get("ingest_plan_preview") or {}).get("changed_candidates") or []),
            "new_candidates": list((item.get("ingest_plan_preview") or {}).get("new_candidates") or []),
            "warnings": list((item.get("ingest_plan_preview") or {}).get("warnings") or []),
        }
        for item in ingest_plans
        if item.get("ingest_plan_preview")
    ]
    ingest_reprocess_report = [
        {
            "evidence_id": item["evidence_id"],
            "name": item["name"],
            "reprocess_mode": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("reprocess_mode"),
            "previous_plan_id": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("previous_plan_id"),
            "plan_version": ((item.get("ingest_plan") or {}).get("plan_version")),
            "selected_candidates": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("selected_candidates", 0),
            "parsed_candidates": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("parsed_candidates", 0),
            "missing_candidates": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("missing_candidates", 0),
            "changed_candidates": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("changed_candidates", 0),
            "new_candidates_not_selected": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("new_candidates_not_selected", 0),
            "full_rediscovery": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("full_rediscovery", False),
            "preserve_analyst_state": ((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("preserve_analyst_state", True),
            "warnings": list((((item.get("ingest_plan") or {}).get("last_reprocess_summary") or {}).get("warnings") or [])),
        }
        for item in ingest_plans
        if item.get("ingest_plan")
    ]

    scope_report = _build_debug_export_scope_report(
        context,
        manifests=manifests,
        parser_audit=parser_audit,
        discovery_candidates=discovery_candidates,
        ingest_summary=ingest_summary,
        fetched_events=fetched_events,
        selected_artifact_types=selected_artifact_types,
        host_attribution_report=host_attribution_report,
        ingest_regression_report=ingest_regression_report,
    )
    event_identity_report = _build_event_identity_report(context, sanitized_events)
    reconciliation_report = _build_reconciliation_report(context)

    manifest_doc = {
        "app_version": getattr(settings, "app_version", None),
        "build": settings.build_identity,
        "export_timestamp": context.export_timestamp.isoformat(),
        "case_id": context.case.id,
        "evidence_id": request.evidence_id,
        "export_scope": request.scope,
        "selected_artifact_types": selected_artifact_types,
        "selected_event_ids": request.event_ids,
        "user_options": request.model_dump(),
        "counts": {
            "evidences": len(context.evidences),
            "artifacts": int(sum(len((manifest.get("artifacts") or [])) for manifest in manifests.values())),
            "candidates": len(discovery_candidates),
            "indexed_events_total": indexed_events_total,
            "normalized_events_total": normalized_events_total,
            "normalized_events_exported": len(sanitized_events),
            "suspicious_events_total": suspicious_events_total,
            "suspicious_events_exported": len(suspicious),
            "timeline_events_total": timeline_events_total,
            "timeline_events_exported": len(timeline_included),
            "rules_matches_total": rules_matches_total,
            "rules_matches_exported": len(rules),
            "findings": _safe_findings_count(db, context.case.id, warnings),
            "indexing_errors": len(indexing_errors),
        },
        "warnings": warnings,
        "limitations": [
            "Heavy raw evidence is excluded by default.",
            "Event samples are truncated and redacted.",
            "Coverage and dedup reports are based on exported scope/sample.",
            "EVTX classification report only applies to native_evtx / evtx_raw events. EvtxECmd/Zimmerman events are represented in normalized_events_sample.",
        ],
    }

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _write_json(zf, "manifest.json", manifest_doc)
        _write_json(zf, "debug_export_scope_report.json", scope_report)
        _write_json(zf, "event_identity_report.json", event_identity_report)
        _write_json(zf, "reconciliation_report.json", reconciliation_report)
        _write_json(zf, "ingest_summary.json", ingest_summary)
        _write_json(zf, "discovery_candidates.json", discovery_candidates)
        _write_json(zf, "parser_audit.json", parser_audit)
        _write_json(zf, "process_graph.json", process_graph)
        _write_json(zf, "process_tree_report.json", process_tree_report)
        _write_jsonl(zf, "process_tree_sample_chains.jsonl", process_tree_sample_chains)
        _write_json(zf, "correlation_findings_report.json", correlation_findings_report)
        _write_jsonl(zf, "correlation_findings.jsonl", correlation_findings)
        _write_jsonl(zf, "correlation_sample_findings.jsonl", correlation_sample_findings)
        _write_json(zf, "noise_reduction_report.json", noise_reduction_report)
        _write_json(zf, "host_attribution_report.json", host_attribution_report)
        _write_json(zf, "host_identity_report.json", host_identity_report)
        _write_json(zf, "ingest_regression_report.json", ingest_regression_report)
        _write_json(zf, "ingest_plan.json", ingest_plans)
        _write_json(zf, "ingest_plan_diff.json", ingest_plan_diff)
        _write_json(zf, "ingest_reprocess_report.json", ingest_reprocess_report)
        _write_json(zf, "ingest_performance_report.json", ingest_performance_report)
        _write_json(zf, "ingest_benchmark_report.json", _build_ingest_benchmark_report(context))
        _write_json(zf, "benchmark_watchdog_report.json", _build_benchmark_watchdog_report(context))
        _write_json(zf, "ingest_coverage_comparison.json", ingest_coverage_comparison)
        _write_json(zf, "usable_ingest_summary.json", usable_ingest_summary)
        _write_json(zf, "parser_tier_report.json", parser_tier_report)
        _write_json(zf, "parser_registry_report.json", parser_registry_report)
        _write_json(zf, "searchable_contract_report.json", searchable_contract_report)
        parser_backend_evaluation = build_core_parser_backend_evaluation()
        _write_json(zf, "parser_backend_inventory.json", parser_backend_evaluation["parser_backend_inventory"])
        _write_json(zf, "parser_backend_benchmark.json", parser_backend_evaluation["parser_backend_benchmark"])
        _write_json(zf, "parser_backend_decisions.json", parser_backend_evaluation["parser_backend_decisions"])
        _write_json(zf, "windows_ez_tools_worker_feasibility.json", parser_backend_evaluation["windows_ez_tools_worker_feasibility"])
        _write_json(zf, "core_ez_tools_backend_plan.json", parser_backend_evaluation["core_ez_tools_backend_plan"])
        _write_json(zf, "parser_coverage_matrix.json", parser_coverage_matrix)
        _write_json(zf, "indexed_document_counts_by_artifact_type.json", indexed_document_counts_by_artifact_type)
        _write_json(zf, "indexed_field_coverage_by_artifact_type.json", indexed_field_coverage_by_artifact_type)
        _write_json(zf, "deferred_artifacts_report.json", deferred_artifacts_report)
        _write_json(zf, "non_searchable_artifacts_report.json", non_searchable_artifacts_report)
        _write_json(zf, "search_filter_coverage.json", search_filter_coverage)
        benchmark_comparison = _build_ingest_benchmark_comparison(context)
        if benchmark_comparison:
            _write_json(zf, "ingest_benchmark_comparison.json", benchmark_comparison)
        _write_json(zf, "problematic_artifacts_report.json", problematic_artifacts_report)
        _write_json(zf, "long_tail_artifacts_report.json", long_tail_artifacts_report)
        _write_json(
            zf,
            "evtx_health_report.json",
            {
                "generated_at": context.export_timestamp.isoformat(),
                "items": [
                    {
                        "artifact_id": item.get("artifact_id"),
                        "name": item.get("name"),
                        "source_path": item.get("source_path"),
                        "status": item.get("status"),
                        "diagnosis": ((item.get("health_check") or {}) if isinstance(item.get("health_check"), dict) else {}).get("diagnosis"),
                        "likely_corrupt": ((item.get("health_check") or {}) if isinstance(item.get("health_check"), dict) else {}).get("likely_corrupt"),
                        "retry_recommended": ((item.get("health_check") or {}) if isinstance(item.get("health_check"), dict) else {}).get("retry_recommended"),
                        "health_check_at": ((item.get("health_check") or {}) if isinstance(item.get("health_check"), dict) else {}).get("health_check_at"),
                        "deep_retry_history": item.get("deep_retry_history") or [],
                    }
                    for item in (problematic_artifacts_report.get("items") or [])
                    if str(item.get("parser") or "").lower() == "evtx_raw" or str(item.get("artifact_type") or "").lower() == "evtx_raw"
                ],
            },
        )
        _write_jsonl(zf, "normalized_events_sample.jsonl", sanitized_events)
        _write_jsonl(zf, "evtx_classification_sample.jsonl", evtx_classification_sample)
        _write_json(
            zf,
            "evtx_classification_report.json",
            _build_evtx_classification_report(
                parser_audit,
                fetched_events.evtx_classification_sample,
                discovery_candidates=discovery_candidates,
                selected_artifact_types=selected_artifact_types,
            ),
        )
        _write_json(zf, "lnk_parse_report.json", _build_lnk_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types))
        _write_json(zf, "prefetch_parse_report.json", _build_prefetch_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types))
        _write_json(zf, "amcache_parse_report.json", _build_amcache_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope))
        _write_json(zf, "shimcache_parse_report.json", _build_shimcache_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope))
        _write_json(zf, "wmi_parse_report.json", _build_wmi_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope))
        mft_parse_report = _build_mft_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        mft_sample_events = _build_mft_sample_events(sanitized_events)
        mft_parse_report["sample_events_count"] = len(mft_sample_events)
        _write_json(zf, "mft_parse_report.json", mft_parse_report)
        _write_jsonl(zf, "mft_sample_events.jsonl", mft_sample_events)
        recycle_parse_report = _build_recycle_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        recycle_sample_events = _build_recycle_sample_events(sanitized_events)
        recycle_parse_report["sample_events_count"] = len(recycle_sample_events)
        _write_json(zf, "recycle_parse_report.json", recycle_parse_report)
        _write_jsonl(zf, "recycle_sample_events.jsonl", recycle_sample_events)
        usb_parse_report = _build_usb_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        usb_sample_events = _build_usb_sample_events(sanitized_events)
        usb_parse_report["sample_events_count"] = len(usb_sample_events)
        _write_json(zf, "usb_parse_report.json", usb_parse_report)
        _write_jsonl(zf, "usb_sample_events.jsonl", usb_sample_events)
        bits_parse_report = _build_bits_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        bits_sample_events = _build_bits_sample_events(sanitized_events)
        bits_parse_report["sample_events_count"] = len(bits_sample_events)
        _write_json(zf, "bits_parse_report.json", bits_parse_report)
        _write_jsonl(zf, "bits_sample_events.jsonl", bits_sample_events)
        wlan_parse_report = _build_wlan_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        wlan_sample_events = _build_wlan_sample_events(sanitized_events)
        wlan_parse_report["sample_events_count"] = len(wlan_sample_events)
        _write_json(zf, "wlan_parse_report.json", wlan_parse_report)
        _write_jsonl(zf, "wlan_sample_events.jsonl", wlan_sample_events)
        dns_parse_report = _build_dns_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        dns_sample_events = _build_dns_sample_events(sanitized_events)
        dns_parse_report["sample_events_count"] = len(dns_sample_events)
        _write_json(zf, "dns_parse_report.json", dns_parse_report)
        _write_jsonl(zf, "dns_sample_events.jsonl", dns_sample_events)
        cloud_parse_report = _build_cloud_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        cloud_sample_events = _build_cloud_sample_events(sanitized_events)
        cloud_parse_report["sample_events_count"] = len(cloud_sample_events)
        _write_json(zf, "cloud_parse_report.json", cloud_parse_report)
        _write_jsonl(zf, "cloud_sample_events.jsonl", cloud_sample_events)
        email_parse_report = _build_email_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        email_sample_events = _build_email_sample_events(sanitized_events)
        email_parse_report["sample_events_count"] = len(email_sample_events)
        _write_json(zf, "email_parse_report.json", email_parse_report)
        _write_jsonl(zf, "email_sample_events.jsonl", email_sample_events)
        user_activity_parse_report = _build_user_activity_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        user_activity_sample_events = _build_user_activity_sample_events(sanitized_events)
        user_activity_parse_report["sample_events_count"] = len(user_activity_sample_events)
        _write_json(zf, "user_activity_parse_report.json", user_activity_parse_report)
        _write_jsonl(zf, "user_activity_sample_events.jsonl", user_activity_sample_events)
        ntfs_parse_report = _build_ntfs_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        ntfs_sample_events = _build_ntfs_sample_events(sanitized_events)
        ntfs_parse_report["sample_events_count"] = len(ntfs_sample_events)
        _write_json(zf, "ntfs_parse_report.json", ntfs_parse_report)
        _write_jsonl(zf, "ntfs_sample_events.jsonl", ntfs_sample_events)
        windows_ui_parse_report = _build_windows_ui_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        windows_ui_sample_events = _build_windows_ui_sample_events(sanitized_events)
        windows_ui_parse_report["sample_events_count"] = len(windows_ui_sample_events)
        _write_json(zf, "windows_ui_parse_report.json", windows_ui_parse_report)
        _write_jsonl(zf, "windows_ui_sample_events.jsonl", windows_ui_sample_events)
        srum_parse_report = _build_srum_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        srum_sample_events = _build_srum_sample_events(sanitized_events)
        srum_parse_report["sample_events_count"] = len(srum_sample_events)
        _write_json(zf, "srum_parse_report.json", srum_parse_report)
        _write_jsonl(zf, "srum_sample_events.jsonl", srum_sample_events)
        browser_parse_report = _build_browser_parse_report(
            parser_audit,
            discovery_candidates,
            sanitized_events,
            selected_artifact_types=selected_artifact_types,
            scope=context.request.scope,
            event_aggregates=_collect_browser_scope_aggregates(context),
        )
        browser_sample_events = _build_browser_sample_events(sanitized_events)
        browser_parse_report["sample_events_count"] = len(browser_sample_events)
        _write_json(zf, "browser_parse_report.json", browser_parse_report)
        _write_jsonl(zf, "browser_sample_events.jsonl", browser_sample_events)
        defender_parse_report = _build_defender_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        defender_sample_events = _build_defender_sample_events(sanitized_events)
        defender_parse_report["sample_events_count"] = len(defender_sample_events)
        _write_json(zf, "defender_parse_report.json", defender_parse_report)
        _write_jsonl(zf, "defender_sample_events.jsonl", defender_sample_events)
        powershell_parse_report = _build_powershell_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        powershell_evtx_sample_events = _collect_powershell_evtx_sample_events(context, sanitized_events)
        powershell_parse_report["powershell_evtx_sample_events_count"] = len(powershell_evtx_sample_events)
        powershell_parse_report["powershell_evtx_sample_events_path"] = "powershell_evtx_sample_events.jsonl"
        powershell_parse_report["powershell_evtx_sample_event_ids"] = [str(_nested_get(item, "windows.event_id") or "") for item in powershell_evtx_sample_events if _nested_get(item, "windows.event_id") not in (None, "")]
        powershell_parse_report["powershell_evtx_sample_warning_count"] = sum(1 for item in powershell_evtx_sample_events if item.get("semantic_normalization_warning"))
        if powershell_parse_report.get("powershell_events_from_evtx_count", 0) > 0 and not powershell_evtx_sample_events:
            powershell_parse_report["powershell_evtx_sample_error"] = "No PowerShell EVTX sample events could be extracted from the current debug export scope"
            powershell_parse_report["sample_query_debug"] = {
                "criteria": [
                    "artifact.parser == powershell_evtx",
                    "powershell.artifact_type == powershell_evtx",
                    "source_format == evtx and windows.channel/provider contains PowerShell",
                    "source_format == evtx and windows.event_id in [4103,4104,400,403,600,800] with PowerShell channel/provider",
                ]
            }
            powershell_parse_report["sample_candidate_count"] = 0
        else:
            powershell_parse_report["sample_candidate_count"] = len(powershell_evtx_sample_events)
        _write_json(zf, "powershell_parse_report.json", powershell_parse_report)
        _write_jsonl(zf, "powershell_evtx_sample_events.jsonl", powershell_evtx_sample_events)
        _write_json(zf, "service_parse_report.json", _build_service_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope))
        _write_json(zf, "scheduled_tasks_parse_report.json", _build_scheduled_tasks_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope))
        autoruns_parse_report = _build_autoruns_parse_report(parser_audit, discovery_candidates, sanitized_events, selected_artifact_types=selected_artifact_types, scope=context.request.scope)
        autoruns_sample_events = _build_autoruns_sample_events(sanitized_events)
        autoruns_parse_report["sample_events_count"] = len(autoruns_sample_events)
        _write_json(zf, "autoruns_parse_report.json", autoruns_parse_report)
        _write_jsonl(zf, "autoruns_sample_events.jsonl", autoruns_sample_events)
        _write_jsonl(zf, "suspicious_events_sample.jsonl", suspicious)
        _write_jsonl(zf, "timeline_sample.jsonl", [_reduce_timeline_event(event) for event in timeline_included])
        _write_jsonl(zf, "timeline_excluded_sample.jsonl", timeline_excluded)
        _write_jsonl(zf, "rules_matches.jsonl", rules)
        _write_json(zf, "detections_report.json", detections_report)
        _write_json(zf, "rules_run_report.json", rules_run_report)
        _write_json(zf, "sigma_case_profile.json", dict(rules_run_report.get("sigma_case_profile") or {}))
        _write_json(zf, "sigma_rule_preflight_report.json", list(rules_run_report.get("sigma_rule_preflight_report") or []))
        _write_json(
            zf,
            "sigma_compilation_report.json",
            {
                "rules_compiled": rules_run_report.get("rules_compiled"),
                "rules_runnable_in_scope": rules_run_report.get("rules_runnable_in_scope"),
                "top_skipped_examples": rules_run_report.get("top_skipped_examples") or [],
            },
        )
        _write_json(
            zf,
            "sigma_scope_preflight_report.json",
            {
                "events_in_scope": rules_run_report.get("events_in_scope"),
                "sigma_case_profile": rules_run_report.get("sigma_case_profile") or {},
                "skipped_by_reason": rules_run_report.get("skipped_by_reason") or {},
            },
        )
        _write_json(
            zf,
            "sigma_run_optimization_report.json",
            {
                "run_id": rules_run_report.get("run_id"),
                "display_status": rules_run_report.get("display_status"),
                "total_rules_considered": rules_run_report.get("total_rules_considered"),
                "rules_compiled": rules_run_report.get("rules_compiled"),
                "rules_runnable_in_scope": rules_run_report.get("rules_runnable_in_scope"),
                "total_rules_runnable": rules_run_report.get("total_rules_runnable"),
                "total_rules_executed": rules_run_report.get("total_rules_executed"),
                "total_rules_skipped": rules_run_report.get("total_rules_skipped"),
                "rules_runtime_error": rules_run_report.get("rules_runtime_error"),
                "skipped_by_reason": rules_run_report.get("skipped_by_reason") or {},
                "events_in_scope": rules_run_report.get("events_in_scope"),
                "candidate_event_evaluations": rules_run_report.get("candidate_event_evaluations"),
                "matches_found": rules_run_report.get("matches_found"),
                "candidate_events_prefiltered": rules_run_report.get("candidate_events_prefiltered"),
                "events_scanned": rules_run_report.get("events_scanned"),
                "detections_created": rules_run_report.get("detections_created"),
                "duplicates": rules_run_report.get("duplicates_skipped"),
                "top_skipped_examples": rules_run_report.get("top_skipped_examples") or [],
                "top_matched_rules": rules_run_report.get("top_matched_rules") or [],
            },
        )
        _write_json(
            zf,
            "sigma_performance_report.json",
            {
                "duration_seconds": rules_run_report.get("duration_seconds"),
                "rules_executed": rules_run_report.get("total_rules_executed"),
                "events_in_scope": rules_run_report.get("events_in_scope"),
                "candidate_event_evaluations": rules_run_report.get("candidate_event_evaluations"),
                "matches_found": rules_run_report.get("matches_found"),
                "detections_created": rules_run_report.get("detections_created"),
                "duplicates": rules_run_report.get("duplicates_skipped"),
                "query_time_ms_total": rules_run_report.get("query_time_ms_total"),
                "dedupe_time_ms_total": rules_run_report.get("dedupe_time_ms_total"),
                "write_time_ms_total": rules_run_report.get("write_time_ms_total"),
                "top_rules_by_matches": rules_run_report.get("top_matched_rules") or [],
                "top_rules_by_duration": rules_run_report.get("top_duration_rules") or [],
                "top_rules_by_duplicates": rules_run_report.get("top_duplicate_rules") or [],
                "noisy_rules": rules_run_report.get("top_noisy_rules") or [],
                "capped_rules": rules_run_report.get("top_noisy_rules") or [],
                "bulk_insert_batches": rules_run_report.get("bulk_insert_batches"),
                "bulk_duplicate_lookups": rules_run_report.get("bulk_duplicate_lookups"),
            },
        )
        _write_jsonl(zf, "sigma_rule_errors.jsonl", [{"error": item} for item in (rules_run_report.get("runtime_errors") or [])])
        _write_jsonl(zf, "sigma_matches.jsonl", sigma_matches)
        _write_jsonl(zf, "yara_matches.jsonl", yara_matches)
        _write_json(zf, "semiauto_analysis.json", semiauto)
        _write_json(zf, "opensearch_indexing_errors.json", indexing_errors)
        _write_json(zf, "field_coverage_report.json", coverage)
        _write_json(zf, "dedup_report.json", dedup)
        _write_json(zf, "data_quality_report.json", data_quality)
        _write_json(zf, "ui_context.json", deepcopy(request.ui_context or {}))
        _write_markdown(zf, "README_DEBUG_PACK.md", _README)
        if request.scope == "selected_events":
            _write_jsonl(zf, "selected_events.jsonl", sanitized_events)
        _write_json(zf, "source_file_inventory_sample.json", _build_source_inventory(manifests))
    zip_buffer.seek(0)

    timestamp_label = context.export_timestamp.strftime("%Y%m%d_%H%M%S")
    case_label = _slugify(case.name or case.id)
    evidence_label = f"_{request.evidence_id}" if request.evidence_id else ""
    filename = f"debug_pack_{case_label}{evidence_label}_{timestamp_label}.zip"
    return zip_buffer.getvalue(), filename


def _coerce_fetched_events(result: Any) -> _FetchedEvents:
    if isinstance(result, _FetchedEvents):
        return result
    if isinstance(result, dict) and "sampled_events" in result:
        return _FetchedEvents(
            sampled_events=list(result.get("sampled_events") or []),
            total_events=int(result.get("total_events") or 0),
            evtx_classification_sample=list(result.get("evtx_classification_sample") or []),
            scope_query=result.get("scope_query"),
        )
    events = list(result or [])
    return _FetchedEvents(sampled_events=events, total_events=len(events), evtx_classification_sample=[event for event in events if _is_evtx_raw_event(event)])


def _build_host_identity_report(db: Session, case_id: str, sanitized_events: list[dict]) -> dict[str, Any]:
    canonical_hosts = get_case_hosts(db, case_id)
    audit_items = get_host_identity_audit(db, case_id)
    evidence = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.desc()).first()
    metadata = dict((evidence.metadata_json or {}) if evidence else {})
    current_run_id = str(metadata.get("latest_ingest_run_id") or metadata.get("current_ingest_run_id") or "").strip()
    current_run = get_evidence_run(metadata, current_run_id) if current_run_id else get_latest_ingest_run(metadata)
    host_identity_metrics = dict(((metadata.get("opensearch_bulk") or {}).get("host_identity")) or {})
    current_run_error = str((current_run or {}).get("last_error") or "")
    historical_errors = [
        {
            "run_id": str(run.get("run_id") or ""),
            "status": str(run.get("status") or ""),
            "last_error": str(run.get("last_error") or ""),
        }
        for run in (metadata.get("ingest_runs") or [])
        if isinstance(run, dict)
        and str(run.get("run_id") or "") != str((current_run or {}).get("run_id") or "")
        and str(run.get("last_error") or "").strip()
    ]
    alias_rows = [
        {
            "case_host_id": host["id"],
            "canonical_name": host["canonical_name"],
            "display_name": host["display_name"],
            "aliases": list(host.get("aliases") or []),
        }
        for host in canonical_hosts
    ]
    return {
        "case_id": case_id,
        "canonical_hosts": canonical_hosts,
        "aliases": alias_rows,
        "manual_merges": [item for item in audit_items if item.get("action") == "merge_hosts"],
        "split_aliases": [item for item in audit_items if item.get("action") == "split_alias"],
        "unresolved_candidates": build_case_host_candidates(db, case_id),
        "current_run_id": str((current_run or {}).get("run_id") or "") or None,
        "report_generated_for_run_id": str((current_run or {}).get("run_id") or "") or None,
        "current_run_errors": [current_run_error] if current_run_error else [],
        "historical_errors": historical_errors,
        "stale_or_historical_sections": {"historical_errors": bool(historical_errors)},
        "metrics": {
            "upserts": int(host_identity_metrics.get("upserts") or 0),
            "conflicts_recovered": int(host_identity_metrics.get("conflicts_recovered") or 0),
            "host_identity_conflict_retries": int(host_identity_metrics.get("host_identity_conflict_retries") or 0),
            "aliases_updated": int(host_identity_metrics.get("aliases_updated") or 0),
        },
        "events_with_observed_host": sum(1 for event in sanitized_events if _nested_get(event, "observed_host.name")),
        "events_without_host": sum(1 for event in sanitized_events if not _nested_get(event, "host.name") and not _nested_get(event, "observed_host.name")),
    }


def _invoke_fetch_events_for_scope(context: _DebugPackContext, parser_audit: list[dict]) -> Any:
    try:
        return _fetch_events_for_scope(context, parser_audit)
    except TypeError:
        return _fetch_events_for_scope(context)  # type: ignore[misc]


def _invoke_collect_rules_matches(db: Session, context: _DebugPackContext, request: DebugExportRequest) -> Any:
    try:
        return _collect_rules_matches(db, context, request)
    except TypeError:
        return _collect_rules_matches(db, context)  # type: ignore[misc]


def _build_scope_search_request(context: _DebugPackContext, *, page_size: int) -> SearchRequest:
    request = context.request
    case_id = context.case.id
    page_size = min(int(page_size), 200)
    if request.scope == "selected_events":
        return SearchRequest(case_id=case_id, query="*", page=1, page_size=page_size)

    search_request = request.search_request
    if search_request is None:
        search_request = SearchRequest(case_id=case_id, query="*", page=1, page_size=page_size)
        if request.evidence_id:
            search_request.filters.evidence_id = [request.evidence_id]
        if request.artifact_types:
            search_request.filters.artifact_type = request.artifact_types
    else:
        search_request = search_request.model_copy(deep=True)
        search_request.case_id = case_id
        search_request.page = 1
        search_request.page_size = page_size
        if request.evidence_id and request.evidence_id not in search_request.filters.evidence_id:
            search_request.filters.evidence_id = [request.evidence_id]
        if request.artifact_types:
            search_request.filters.artifact_type = request.artifact_types
    return search_request


def _build_scope_query(context: _DebugPackContext, *, timeline: bool = False) -> dict[str, Any] | None:
    request = context.request
    if request.scope == "selected_events":
        return None
    page_size = min(max(request.max_events_per_type * 30, 300), 200)
    search_request = _build_scope_search_request(context, page_size=page_size)
    body = build_search_query(search_request, timeline=timeline)
    return body.get("query") or {"match_all": {}}


def _search_scope_events(
    context: _DebugPackContext,
    *,
    size: int,
    extra_filters: list[dict] | None = None,
    timeline: bool = False,
) -> tuple[list[dict], int, dict[str, Any] | None]:
    request = context.request
    if request.scope == "selected_events":
        events = []
        for event_id in request.event_ids:
            event = fetch_event_by_id(context.case.id, event_id)
            if event:
                events.append(event)
        return events[:size], len(events), None

    page_size = min(max(request.max_events_per_type * 30, 300), 200)
    search_request = _build_scope_search_request(context, page_size=page_size)
    body = build_search_query(search_request, timeline=timeline)
    body["size"] = size
    body["track_total_hits"] = True
    body["_source"] = _debug_export_source_fields(
        include_raw_samples=request.include_raw_samples,
        include_raw_xml=request.include_raw_xml,
    )
    if extra_filters:
        filters = (((body.get("query") or {}).get("bool") or {}).get("filter") or [])
        filters.extend(extra_filters)
    response = search_documents(get_events_index(context.case.id), body)
    hits = response.get("hits", {}).get("hits", [])
    total = int((((response.get("hits") or {}).get("total") or {}).get("value")) or 0)
    events = [{"opensearch_id": hit.get("_id"), "search_doc_id": hit.get("_id"), "id": hit.get("_id"), **(hit.get("_source") or {})} for hit in hits]
    return events, total, body.get("query")


def _scope_expected_indexed_events(context: _DebugPackContext) -> int:
    total = 0
    for evidence in context.evidences:
        metadata = evidence.metadata_json or {}
        total += int(metadata.get("indexed_events") or metadata.get("events_indexed") or 0)
    return total


def _fetch_events_for_scope(context: _DebugPackContext, parser_audit: list[dict] | None = None) -> _FetchedEvents:
    request = context.request
    base_events, total_events, scope_query = _search_scope_events(context, size=min(max(request.max_events_per_type * 30, 300), 200))
    expected_indexed = _scope_expected_indexed_events(context)
    if total_events == 0 and expected_indexed > 0:
        refresh_index(
            get_events_index(context.case.id),
            request_timeout=120,
            attempts=3,
            backoff_seconds=(1.0, 3.0, 6.0),
            raise_on_error=False,
        )
        for pause in (0.5, 1.5, 3.0):
            time.sleep(pause)
            base_events, total_events, scope_query = _search_scope_events(context, size=min(max(request.max_events_per_type * 30, 300), 200))
            if total_events > 0:
                break
    sampled = _sample_events_by_group(base_events, request.max_events_per_type)
    group_targets = _collect_priority_groups(base_events, parser_audit or [])
    selected_ids = {str(event.get("id") or event.get("event_id") or "") for event in sampled}
    for artifact_type, parser_name, source_tool in group_targets:
        already_present = any(
            ((event.get("artifact") or {}).get("type") == artifact_type)
            and ((event.get("artifact") or {}).get("parser") == parser_name)
            and ((event.get("source_tool") or "") == (source_tool or ""))
            for event in sampled
        )
        if already_present:
            continue
        filters = [
            {"term": {"artifact.type": artifact_type}},
            {"term": {"artifact.parser": parser_name}},
        ]
        if source_tool:
            filters.append({"term": {"source_tool": source_tool}})
        extra_events, _, _ = _search_scope_events(context, size=max(3, min(request.max_events_per_type, 10)), extra_filters=filters)
        for event in extra_events:
            event_key = str(event.get("id") or event.get("event_id") or "")
            if event_key and event_key not in selected_ids:
                sampled.append(event)
                selected_ids.add(event_key)

    evtx_classification_sample = _collect_evtx_classification_sample(context, base_events, sampled)
    return _FetchedEvents(
        sampled_events=_sample_events_by_group(sampled, request.max_events_per_type),
        total_events=total_events,
        evtx_classification_sample=evtx_classification_sample,
        scope_query=scope_query,
    )

    query = build_search_query(search_request)
    body = {
        **query,
        "size": search_request.page_size,
        "track_total_hits": False,
        "_source": _debug_export_source_fields(include_raw_samples=request.include_raw_samples, include_raw_xml=request.include_raw_xml),
    }
    response = search_documents(get_events_index(case_id), body)
    hits = response.get("hits", {}).get("hits", [])
    events = [{"id": hit.get("_id"), **(hit.get("_source") or {})} for hit in hits]
    return _limit_per_artifact_type(events, request.max_events_per_type)


def _debug_export_source_fields(*, include_raw_samples: bool, include_raw_xml: bool) -> list[str]:
    fields = [
        "id",
        "event_id",
        "stable_event_id",
        "event_fingerprint",
        "event_fingerprint_version",
        "case_id",
        "evidence_id",
        "artifact_id",
        "source_file",
        "source_tool",
        "source_format",
        "@timestamp",
        "timestamp_precision",
        "host",
        "user",
        "artifact",
        "event",
        "windows",
        "process",
        "file",
        "url",
        "download",
        "execution",
        "persistence",
        "service",
        "usb",
        "volume",
        "prefetch",
        "shimcache",
        "appcompat",
        "registry",
        "lnk",
        "browser",
        "powershell",
        "detection",
        "wmi",
        "bits",
        "cloud",
        "network",
        "dns",
        "wlan",
        "srum",
        "recycle",
        "tags",
        "data_quality",
        "risk_score",
        "suspicious_reasons",
        "raw_summary",
    ]
    if include_raw_samples:
        fields.append("raw")
        if include_raw_xml:
            fields.append("raw.RawXml")
            fields.append("raw.raw_xml")
    return fields


def _sample_events_by_group(events: list[dict], limit: int) -> list[dict]:
    counts: dict[tuple[str, str, str], int] = defaultdict(int)
    selected: list[dict] = []
    seen_ids: set[str] = set()
    for event in events:
        artifact = event.get("artifact") or {}
        key = (
            str(artifact.get("type") or "unknown"),
            str(artifact.get("parser") or "unknown"),
            str(event.get("source_tool") or "unknown"),
        )
        if counts[key] >= limit:
            continue
        event_key = str(event.get("id") or event.get("event_id") or "")
        if event_key and event_key in seen_ids:
            continue
        counts[key] += 1
        if event_key:
            seen_ids.add(event_key)
        selected.append(event)
    return selected


def _infer_source_tool_for_parser(parser_name: str | None) -> str | None:
    mapping = {
        "evtx_raw": "native_evtx",
        "lnk_raw": "native_lnk",
        "prefetch_raw": "native_prefetch",
        "windows_service_registry": "native_windows_service",
    }
    return mapping.get(str(parser_name or ""))


def _collect_priority_groups(base_events: list[dict], parser_audit: list[dict]) -> list[tuple[str, str, str | None]]:
    groups: list[tuple[str, str, str | None]] = []
    seen: set[tuple[str, str, str | None]] = set()

    def add_group(artifact_type: str | None, parser_name: str | None, source_tool: str | None = None) -> None:
        if not artifact_type or not parser_name:
            return
        key = (str(artifact_type), str(parser_name), source_tool)
        if key in seen:
            return
        seen.add(key)
        groups.append(key)

    for event in base_events:
        artifact = event.get("artifact") or {}
        add_group(artifact.get("type"), artifact.get("parser"), event.get("source_tool"))

    priority_artifacts = {
        "windows_event",
        "lnk",
        "powershell",
        "scheduled_task",
        "jumplist",
        "browser",
        "defender",
        "recycle_bin",
        "cloud_sync",
        "network",
        "usb",
        "bits",
        "wmi",
        "autoruns",
        "process",
        "srum",
        "registry",
        "service",
        "prefetch",
        "mft",
        "usn",
    }
    for row in parser_audit:
        artifact_type = row.get("artifact_type")
        parser_name = row.get("parser_name")
        if artifact_type not in priority_artifacts and parser_name not in {"evtx_raw", "lnk_raw", "prefetch_raw", "windows_service_registry"}:
            continue
        add_group(artifact_type, parser_name, _infer_source_tool_for_parser(str(parser_name or "")))
    return groups


def _is_evtx_raw_event(event: dict) -> bool:
    artifact = event.get("artifact") or {}
    return artifact.get("type") == "windows_event" and artifact.get("parser") == "evtx_raw"


def _is_matching_provider_or_channel(event: dict, token: str) -> bool:
    channel = str(_nested_get(event, "windows.channel") or "")
    provider = str(_nested_get(event, "windows.provider") or "")
    lowered = token.lower()
    return lowered in channel.lower() or lowered in provider.lower()


def _collect_evtx_classification_sample(context: _DebugPackContext, base_events: list[dict], sampled_events: list[dict]) -> list[dict]:
    request = context.request
    evtx_events = [event for event in _sample_events_by_group(base_events + sampled_events, max(3, request.max_events_per_type // 2)) if _is_evtx_raw_event(event)]
    selected: list[dict] = []
    seen_ids: set[str] = set()

    def add_event(event: dict) -> None:
        event_key = str(event.get("id") or event.get("event_id") or "")
        if event_key and event_key in seen_ids:
            return
        if event_key:
            seen_ids.add(event_key)
        selected.append(event)

    def pick_local(predicate) -> bool:  # noqa: ANN001
        for event in evtx_events:
            if predicate(event):
                add_event(event)
                return True
        return False

    def fetch_targeted(filters: list[dict], predicate) -> None:  # noqa: ANN001
        extra_events, _, _ = _search_scope_events(context, size=3, extra_filters=filters)
        for event in extra_events:
            if _is_evtx_raw_event(event) and predicate(event):
                add_event(event)

    targets = [
        ("security_4624", lambda e: _nested_get(e, "windows.event_id") == 4624 and str(_nested_get(e, "windows.channel") or "") == "Security"),
        ("security_4625", lambda e: _nested_get(e, "windows.event_id") == 4625 and str(_nested_get(e, "windows.channel") or "") == "Security"),
        ("security_4688", lambda e: _nested_get(e, "windows.event_id") == 4688 and str(_nested_get(e, "windows.channel") or "") == "Security"),
        ("system_7045", lambda e: _nested_get(e, "windows.event_id") == 7045 and str(_nested_get(e, "windows.channel") or "") == "System"),
        ("powershell_4104", lambda e: _nested_get(e, "windows.event_id") == 4104 and _is_matching_provider_or_channel(e, "PowerShell")),
        ("powershell_400", lambda e: _nested_get(e, "windows.event_id") == 400 and _is_matching_provider_or_channel(e, "PowerShell")),
        ("powershell_403", lambda e: _nested_get(e, "windows.event_id") == 403 and _is_matching_provider_or_channel(e, "PowerShell")),
        ("wmi_activity", lambda e: int(_nested_get(e, "windows.event_id") or 0) in {5857, 5858, 5859, 5860, 5861} and _is_matching_provider_or_channel(e, "WMI-Activity")),
        ("bits", lambda e: _is_matching_provider_or_channel(e, "Bits-Client")),
        ("wlan", lambda e: _is_matching_provider_or_channel(e, "WLAN-AutoConfig")),
        ("task_scheduler", lambda e: _is_matching_provider_or_channel(e, "TaskScheduler")),
        ("terminal_services", lambda e: any(_is_matching_provider_or_channel(e, token) for token in ("TerminalServices", "RemoteConnectionManager", "LocalSessionManager"))),
        ("generic_windows_event", lambda e: str((_nested_get(e, "event.category") or "")) == "windows_event"),
        ("source_mismatch", lambda e: "source_mismatch" in (e.get("data_quality") or [])),
    ]
    target_filters = {
        "security_4624": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 4624}}, {"term": {"windows.channel": "Security"}}],
        "security_4625": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 4625}}, {"term": {"windows.channel": "Security"}}],
        "security_4688": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 4688}}, {"term": {"windows.channel": "Security"}}],
        "system_7045": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 7045}}, {"term": {"windows.channel": "System"}}],
        "powershell_4104": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 4104}}],
        "powershell_400": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 400}}],
        "powershell_403": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"windows.event_id": 403}}],
        "wmi_activity": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"terms": {"windows.event_id": [5857, 5858, 5859, 5860, 5861]}}],
        "bits": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"query_string": {"query": "Bits-Client", "fields": ["windows.channel", "windows.provider"]}}],
        "wlan": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"query_string": {"query": "WLAN-AutoConfig", "fields": ["windows.channel", "windows.provider"]}}],
        "task_scheduler": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"query_string": {"query": "TaskScheduler", "fields": ["windows.channel", "windows.provider"]}}],
        "terminal_services": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"query_string": {"query": "TerminalServices OR RemoteConnectionManager OR LocalSessionManager", "fields": ["windows.channel", "windows.provider"]}}],
        "generic_windows_event": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"event.category": "windows_event"}}],
        "source_mismatch": [{"term": {"artifact.type": "windows_event"}}, {"term": {"artifact.parser": "evtx_raw"}}, {"term": {"data_quality": "source_mismatch"}}],
    }
    for name, predicate in targets:
        if not pick_local(predicate):
            fetch_targeted(target_filters[name], predicate)

    for event in evtx_events[: max(10, request.max_events_per_type)]:
        add_event(event)
    return selected


def _load_manifests(context: _DebugPackContext) -> dict[str, dict]:
    manifests: dict[str, dict] = {}
    for evidence in context.evidences:
        path = evidence_manifest_path(evidence.case_id, evidence.id)
        if path.exists():
            try:
                manifests[evidence.id] = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                manifests[evidence.id] = {}
        else:
            manifests[evidence.id] = {}
    return manifests


def _build_ingest_summary(context: _DebugPackContext, manifests: dict[str, dict]) -> list[dict]:
    rows = []
    for evidence in context.evidences:
        manifest = manifests.get(evidence.id) or {}
        stats = manifest.get("stats") or {}
        metadata = evidence.metadata_json or {}
        parser_errors = [error for error in (evidence.error_log or {}).get("errors", [])]
        artifacts_detected = int(stats.get("detected_artifacts") or 0)
        raw_artifacts_detected = int(stats.get("raw_artifacts_detected") or 0)
        results_artifacts_detected = int(stats.get("results_artifacts_detected") or 0)
        selected_candidates = int(metadata.get("selected_candidates") or 0)
        plan = dict((metadata.get("last_successful_ingest_plan") or metadata.get("ingest_plan") or {}))
        artifacts_parseable = max(
            selected_candidates,
            artifacts_detected,
            raw_artifacts_detected + results_artifacts_detected,
            results_artifacts_detected,
        )
        rows.append({
            "evidence_id": evidence.id,
            "evidence_name": evidence.original_filename,
            "evidence_type": resolve_public_evidence_type(
                getattr(evidence, "evidence_type", None),
                source_tool=getattr(evidence, "source_tool", None),
                metadata=metadata,
            ).value,
            "source_tool": getattr(evidence, "source_tool", None),
            "status": evidence.ingest_status.value if hasattr(evidence.ingest_status, "value") else str(evidence.ingest_status),
            "storage_mode": getattr(getattr(evidence, "storage_mode", None), "value", getattr(evidence, "storage_mode", "uploaded")),
            "is_external": bool(getattr(evidence, "is_external", False)),
            "copy_to_storage": bool(getattr(evidence, "copy_to_storage", True)),
            "original_path": getattr(evidence, "original_path", None),
            "storage_path": evidence.stored_path,
            "path_validation": getattr(evidence, "path_validation", {}) or {},
            "file_count": getattr(evidence, "file_count", None),
            "performance_profile": metadata.get("performance_profile"),
            "performance_settings": metadata.get("performance_settings") or {},
            "resource_warnings": metadata.get("resource_warnings") or [],
            "created_at": evidence.created_at.isoformat() if evidence.created_at else None,
            "updated_at": evidence.processed_at.isoformat() if evidence.processed_at else None,
            "detected_host": evidence.detected_host,
            "files_scanned": int(metadata.get("discovery_files_scanned") or stats.get("total_files") or 0),
            "files_extracted": int(metadata.get("files_extracted") or stats.get("processed_files") or 0),
            "bytes_extracted": int(metadata.get("bytes_extracted") or 0),
            "artifacts_detected": artifacts_detected,
            "artifacts_selected": selected_candidates,
            "selected_by_artifact_type": dict((plan.get("selected_by_artifact_type") or {})),
            "selected_by_parser": dict((plan.get("selected_by_parser") or {})),
            "artifacts_parseable": artifacts_parseable,
            "artifacts_parsed": int(stats.get("results_artifacts_parsed") or 0) + int(stats.get("raw_artifacts_parsed") or 0),
            "artifacts_failed": int(stats.get("failed_artifacts") or 0),
            "raw_not_parsed": int(stats.get("raw_artifacts_not_parsed") or 0),
            "indexed_events": int(stats.get("indexed_events") or 0),
            "records_per_second": metadata.get("records_per_second"),
            "duration": metadata.get("elapsed_seconds"),
            "warnings": list((evidence.error_log or {}).get("warnings") or []),
            "opensearch_bulk": metadata.get("opensearch_bulk"),
            "opensearch_refresh": metadata.get("opensearch_refresh"),
            "parser_errors": parser_errors,
            "bulk_index_errors": [error for error in parser_errors if "OpenSearch bulk indexing failed" in json.dumps(error)],
        })
    return rows


def _build_ingest_performance_report(
    context: _DebugPackContext,
    manifests: dict[str, dict],
    ingest_summary: list[dict],
) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {
            "evidence_type": "unknown",
            "source_tool": None,
            "duration_seconds": 0,
            "records_per_sec": 0,
            "artifacts_per_sec": 0,
            "bulk_batches": 0,
            "bulk_docs_per_batch": 0,
            "evtx_files_total": 0,
            "evtx_files_parsed": 0,
            "evtx_records_read": 0,
            "ignored_zip_entries": {"__MACOSX": 0, "appledouble": 0},
            "slow_artifacts": [],
            "failed_artifacts": [],
        }

    metadata = dict(evidence.metadata_json or {})
    current_run_id = str(metadata.get("latest_ingest_run_id") or metadata.get("current_ingest_run_id") or "").strip()
    current_run = get_evidence_run(metadata, current_run_id) if current_run_id else get_latest_ingest_run(metadata)
    performance = dict(metadata.get("ingest_performance") or {})
    host_identity_metrics = dict(((metadata.get("opensearch_bulk") or {}).get("host_identity")) or {})
    summary = ingest_summary[0] if len(ingest_summary) == 1 else {}
    manifest = manifests.get(evidence.id) or {}
    manifest_artifacts = list(manifest.get("artifacts") or [])
    parser_audit_rows = [
        artifact.get("ingest_audit") or {}
        for artifact in manifest_artifacts
        if str(artifact.get("parser") or "").lower() == "evtx_raw"
    ]
    selected_by_artifact_type = Counter()
    selected_candidates = list(((metadata.get("last_successful_ingest_plan") or metadata.get("ingest_plan") or {}).get("selected_candidates") or []))
    for candidate in selected_candidates:
        selected_by_artifact_type[str(candidate.get("artifact_type") or "unknown")] += 1
    parsed_by_artifact_type = Counter()
    failed_artifacts = []
    for artifact in manifest_artifacts:
        artifact_type = str(artifact.get("artifact_type") or "unknown")
        if artifact.get("status") == "completed":
            parsed_by_artifact_type[artifact_type] += 1
        elif artifact.get("status") in {"failed", "failed_unsupported"}:
            failed_artifacts.append(
                {
                    "path": artifact.get("source_path") or artifact.get("name"),
                    "artifact_type": artifact_type,
                    "parser": artifact.get("parser"),
                    "status": artifact.get("status"),
                }
            )
    parallel_ingest = dict(metadata.get("parallel_ingest") or {})
    current_events_indexed = int(
        (current_run or {}).get("events_indexed")
        or performance.get("metadata_events_indexed")
        or summary.get("indexed_events")
        or 0
    )
    current_records_read = int((current_run or {}).get("records_read") or performance.get("evtx_records_read") or 0)
    try:
        opensearch_count = int(
            count_documents(
                get_events_index(context.case.id),
                {
                    "bool": {
                        "filter": [
                            {"term": {"case_id": context.case.id}},
                            {"term": {"evidence_id": evidence.id}},
                        ]
                    }
                },
            ).get("count", 0)
        )
    except Exception:  # noqa: BLE001
        opensearch_count = int(summary.get("indexed_events") or current_events_indexed or 0)
    if not current_run and opensearch_count <= 0:
        opensearch_count = int(summary.get("indexed_events") or current_events_indexed or 0)
    historical_errors = [
        {
            "run_id": str(run.get("run_id") or ""),
            "status": str(run.get("status") or ""),
            "last_error": str(run.get("last_error") or ""),
        }
        for run in (metadata.get("ingest_runs") or [])
        if isinstance(run, dict)
        and str(run.get("run_id") or "") != str((current_run or {}).get("run_id") or "")
        and str(run.get("last_error") or "").strip()
    ]
    return {
        "current_run_id": str((current_run or {}).get("run_id") or "") or None,
        "report_generated_for_run_id": str((current_run or {}).get("run_id") or "") or None,
        "stale_or_historical_sections": {"historical_errors": bool(historical_errors)},
        "historical_errors": historical_errors,
        "evidence_type": resolve_public_evidence_type(
            getattr(evidence, "evidence_type", None),
            source_tool=getattr(evidence, "source_tool", None),
            metadata=metadata,
        ).value,
        "source_tool": getattr(evidence, "source_tool", None),
        "duration_seconds": float((current_run or {}).get("elapsed_seconds") or performance.get("duration_seconds") or summary.get("duration") or 0),
        "records_per_sec": float((current_run or {}).get("records_per_sec") or performance.get("records_per_sec") or summary.get("records_per_second") or 0),
        "artifacts_per_sec": performance.get("artifacts_per_sec") or 0,
        "parallel_enabled": bool(parallel_ingest.get("enabled") if parallel_ingest else performance.get("parallel_enabled")),
        "effective_parallelism": int(parallel_ingest.get("effective_parallelism") or performance.get("effective_parallelism") or 1),
        "parallel_mode": str(parallel_ingest.get("mode") or performance.get("parallel_mode") or "off"),
        "parser_capabilities_used": dict(performance.get("parser_capabilities_used") or {}),
        "artifacts_parallelized_by_type": dict(parallel_ingest.get("artifacts_parallelized_by_type") or performance.get("artifacts_parallelized_by_type") or {}),
        "artifacts_sequential_by_type": dict(parallel_ingest.get("artifacts_sequential_by_type") or performance.get("artifacts_sequential_by_type") or {}),
        "duration_by_parser": dict(performance.get("duration_by_parser") or {}),
        "throughput_by_parser": dict(performance.get("throughput_by_parser") or {}),
        "bottleneck": parallel_ingest.get("bottleneck") or performance.get("bottleneck") or "unknown",
        "bulk_batches": performance.get("bulk_batches") or 0,
        "bulk_docs_per_batch": performance.get("bulk_docs_per_batch") or 0,
        "host_identity": {
            "upserts": int(host_identity_metrics.get("upserts") or 0),
            "conflicts_recovered": int(host_identity_metrics.get("conflicts_recovered") or 0),
            "host_identity_conflict_retries": int(host_identity_metrics.get("host_identity_conflict_retries") or 0),
            "aliases_updated": int(host_identity_metrics.get("aliases_updated") or 0),
        },
        "evtx_files_total": performance.get("evtx_files_total") or selected_by_artifact_type.get("evtx_raw", 0),
        "evtx_files_parsed": performance.get("evtx_files_parsed") or parsed_by_artifact_type.get("evtx_raw", 0),
        "evtx_records_read": current_records_read or performance.get("evtx_records_read") or sum(int(row.get("records_read") or 0) for row in parser_audit_rows),
        "evtx_records_indexed": current_events_indexed or performance.get("evtx_records_indexed") or sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in parser_audit_rows),
        "ignored_zip_entries": performance.get("ignored_zip_entries") or {"__MACOSX": 0, "appledouble": 0},
        "slow_artifacts": list(performance.get("slow_artifacts") or []),
        "failed_artifacts": list(performance.get("failed_artifacts") or failed_artifacts),
        "selected_candidates_count": len(selected_candidates),
        "selected_by_artifact_type": dict(sorted(selected_by_artifact_type.items())),
        "parsed_by_artifact_type": dict(sorted(parsed_by_artifact_type.items())),
        "plan_source": ((metadata.get("last_successful_ingest_plan") or metadata.get("ingest_plan") or {}).get("plan_source")),
        "status": (current_run or {}).get("status") or summary.get("status"),
        "events_indexed": current_events_indexed,
        "metadata_coherence": {
            "metadata_events_indexed": current_events_indexed,
            "opensearch_events_count": opensearch_count,
            "delta": opensearch_count - current_events_indexed,
        },
        "by_parser": dict(performance.get("by_parser") or {}),
    }


def _build_ingest_coverage_comparison_report(
    context: _DebugPackContext,
    *,
    problematic_artifacts_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    metadata = dict(evidence.metadata_json or {})
    runs = [dict(item) for item in (metadata.get("ingest_runs") or []) if isinstance(item, dict)]
    current_run_id = str(metadata.get("latest_ingest_run_id") or metadata.get("current_ingest_run_id") or "").strip()
    latest_run = next((item for item in runs if str(item.get("run_id") or "") == current_run_id), None)
    if latest_run is None:
        latest_run = get_latest_ingest_run(metadata) or {}
        current_run_id = str((latest_run or {}).get("run_id") or current_run_id or "")
    previous_runs = [item for item in runs if str(item.get("run_id") or "") != current_run_id]
    previous_run = None
    if previous_runs:
        previous_run = sorted(
            previous_runs,
            key=lambda item: str(item.get("finished_at") or item.get("heartbeat_at") or item.get("created_at") or ""),
            reverse=True,
        )[0]
    current_events = int((latest_run or {}).get("events_indexed") or 0)
    previous_events = int((previous_run or {}).get("events_indexed") or 0)
    problematic_items = list((problematic_artifacts_report or {}).get("items") or [])
    return {
        "evidence_id": evidence.id,
        "current_run_id": current_run_id or None,
        "previous_run_id": str((previous_run or {}).get("run_id") or "") or None,
        "old_events_indexed": previous_events,
        "new_events_indexed": current_events,
        "delta": current_events - previous_events,
        "old_status": (previous_run or {}).get("status"),
        "new_status": (latest_run or {}).get("status"),
        "old_artifacts_failed": int((previous_run or {}).get("artifacts_failed") or 0),
        "new_artifacts_failed": int((latest_run or {}).get("artifacts_failed") or 0),
        "recovered_artifacts": max(int((previous_run or {}).get("artifacts_failed") or 0) - int((latest_run or {}).get("artifacts_failed") or 0), 0),
        "artifacts_still_missing": [
            {
                "artifact_id": item.get("artifact_id"),
                "name": item.get("name"),
                "status": item.get("status"),
                "effective_status": item.get("effective_status"),
                "retryable": item.get("retryable"),
            }
            for item in problematic_items
            if str(item.get("effective_status") or item.get("status") or "").lower() not in {"recovered", "parsed_with_warning"}
        ],
    }


def _build_ingest_benchmark_report(context: _DebugPackContext) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {"current_run_id": None, "items": []}
    metadata = dict(evidence.metadata_json or {})
    current_run_id = str(metadata.get("latest_ingest_run_id") or metadata.get("current_ingest_run_id") or "").strip()
    current_benchmark = get_ingest_benchmark_by_run_id(metadata, current_run_id) if current_run_id else None
    benchmarks = list_ingest_benchmarks(metadata)
    return {
        "current_run_id": current_run_id or None,
        "report_generated_for_run_id": str((current_benchmark or {}).get("run_id") or current_run_id or "") or None,
        "latest_benchmark": current_benchmark or (benchmarks[0] if benchmarks else None),
        "items": benchmarks,
    }


def _build_ingest_benchmark_comparison(context: _DebugPackContext) -> dict[str, Any] | None:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return None
    benchmarks = [
        item
        for item in list_ingest_benchmarks(evidence.metadata_json or {})
        if str(item.get("status") or "") in {"completed", "completed_with_errors", "failed"}
    ]
    if len(benchmarks) < 2:
        return None
    return compare_ingest_benchmarks(benchmarks[1], benchmarks[0])


def _build_benchmark_watchdog_report(context: _DebugPackContext) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {"benchmark_id": None, "run_id": None, "watchdog_status": "unavailable", "actions": []}
    metadata = dict(evidence.metadata_json or {})
    current_run_id = str(metadata.get("latest_ingest_run_id") or metadata.get("current_ingest_run_id") or "").strip()
    benchmark = get_ingest_benchmark_by_run_id(metadata, current_run_id) if current_run_id else None
    if not benchmark:
        benchmarks = list_ingest_benchmarks(metadata)
        benchmark = benchmarks[0] if benchmarks else None
    return generate_watchdog_report(benchmark)


def _build_problematic_artifacts_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {
            "evidence_id": None,
            "summary": {
                "problematic_count": 0,
                "parsed_with_warning": 0,
                "partially_parsed": 0,
                "failed": 0,
                "retryable": 0,
                "indexed_with_warning": 0,
                "recovered_count": 0,
                "unresolved_count": 0,
                "data_loss_expected_count": 0,
                "source_missing_but_indexed": 0,
            },
            "items": [],
        }
    manifest = manifests.get(evidence.id) or {}
    artifact_id_by_key: dict[tuple[str, str], str] = {}
    for artifact in getattr(evidence, "artifacts", []) or []:
        source_path = str(artifact.source_path or "")
        parser_name = str(artifact.parser or "")
        artifact_name = str(artifact.name or "")
        for key in (
            (source_path, parser_name),
            (source_path, ""),
            (artifact_name, parser_name),
            (artifact_name, ""),
        ):
            if key[0]:
                artifact_id_by_key[key] = artifact.id
    return build_problematic_artifacts_report(
        evidence,
        manifest,
        artifact_id_by_key=artifact_id_by_key,
        artifact_rows=list(getattr(evidence, "artifacts", []) or []),
    )


def _build_long_tail_artifacts_export(context: _DebugPackContext) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {"evidence_id": None, "run_id": None, "summary": {"tail_artifacts_total": 0}, "items": []}
    return build_long_tail_artifacts_report(
        evidence,
        artifact_rows=list(getattr(evidence, "artifacts", []) or []),
    )


def _build_usable_ingest_summary(context: _DebugPackContext, *, problematic_artifacts_report: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    metadata = dict(evidence.metadata_json or {})
    ingest_mode = normalize_ingest_mode(metadata.get("ingest_mode"))
    run = get_latest_ingest_run(metadata) or {}
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "ingest_mode": ingest_mode,
        "skipped_features": list((metadata.get("skipped_features") or ingest_mode_metadata(ingest_mode).get("skipped_features") or [])),
        "parser_tiers_enabled": list((metadata.get("parser_tiers_enabled") or ingest_mode_metadata(ingest_mode).get("parser_tiers_enabled") or [])),
        "latest_ingest_run_id": metadata.get("latest_ingest_run_id"),
        "status": evidence.ingest_status.value if hasattr(evidence.ingest_status, "value") else str(evidence.ingest_status),
        "events_indexed": int(metadata.get("events_indexed") or 0),
        "problematic_count": int(((problematic_artifacts_report or {}).get("summary") or {}).get("problematic_count") or 0),
    }


def _build_parser_tier_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    metadata = dict(evidence.metadata_json or {})
    manifest = manifests.get(evidence.id) or {}
    return build_parser_tier_report(
        artifacts=[dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)],
        ingest_mode=metadata.get("ingest_mode"),
    )


def _build_parser_registry_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return build_parser_registry_report()
    manifest = manifests.get(evidence.id) or {}
    artifact_types = sorted({str(item.get("artifact_type") or "").strip().lower() for item in (manifest.get("artifacts") or []) if isinstance(item, dict) and item.get("artifact_type")})
    return build_parser_registry_report(artifact_types=artifact_types or None)


def _build_indexed_document_counts_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    manifest = manifests.get(evidence.id) or {}
    return {
        "evidence_id": evidence.id,
        "counts_by_artifact_type": build_indexed_document_counts_by_artifact_type(
            [dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
        ),
    }


def _build_searchable_contract_export(context: _DebugPackContext, manifests: dict[str, dict], sanitized_events: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    manifest = manifests.get(evidence.id) or {}
    return build_searchable_contract_report(
        artifacts=[dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)],
        sampled_events=sanitized_events,
    )


def _build_parser_coverage_matrix_export(context: _DebugPackContext, manifests: dict[str, dict], sanitized_events: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    manifest = manifests.get(evidence.id) or {}
    return build_parser_coverage_matrix(
        artifacts=[dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)],
        sampled_events=sanitized_events,
    )


def _build_indexed_field_coverage_export(sanitized_events: list[dict[str, Any]]) -> dict[str, Any]:
    return build_indexed_field_coverage_by_artifact_type(sanitized_events)


def _build_deferred_artifacts_export(problematic_artifacts_report: dict[str, Any] | None = None) -> dict[str, Any]:
    items = [
        dict(item)
        for item in ((problematic_artifacts_report or {}).get("items") or [])
        if "deferred" in str(item.get("effective_status") or item.get("status") or "").lower()
        or str(item.get("status") or "").lower().startswith("failed")
        or str(item.get("effective_status") or "").lower().startswith("failed")
        or str(item.get("status") or "").lower().startswith("skipped")
    ]
    return {
        "summary": {
            "deferred_or_problematic_count": len(items),
        },
        "items": items,
    }


def _build_non_searchable_artifacts_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {"summary": {"non_searchable_count": 0}, "items": []}
    manifest = manifests.get(evidence.id) or {}
    return build_non_searchable_artifacts_report(
        [dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    )


def _build_search_filter_coverage_export(context: _DebugPackContext, manifests: dict[str, dict]) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    if not evidence:
        return {}
    manifest = manifests.get(evidence.id) or {}
    return build_search_filter_coverage([dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)])


def _build_ingest_regression_report(
    context: _DebugPackContext,
    *,
    manifests: dict[str, dict],
    parser_audit: list[dict],
    ingest_summary: list[dict],
    host_attribution_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = context.evidences[0] if len(context.evidences) == 1 else None
    evidence_id = getattr(evidence, "id", None)
    metadata = dict(getattr(evidence, "metadata_json", {}) or {}) if evidence else {}
    baseline = dict(metadata.get("reingest_baseline") or {})
    current_summary = (ingest_summary[0] if len(ingest_summary) == 1 else {})
    current_events = int(current_summary.get("indexed_events") or 0)
    expected_events = baseline.get("expected_events_baseline")
    if expected_events in (None, ""):
        expected_events = baseline.get("events_indexed")
    expected_events = int(expected_events or 0)

    by_artifact_type: dict[str, int] = defaultdict(int)
    by_parser: dict[str, int] = defaultdict(int)
    parser_audit_by_parser: dict[str, dict[str, Any]] = {}
    failed_artifacts: list[dict[str, Any]] = []
    source_files_seen: set[str] = set()
    source_files_parsed: set[str] = set()

    for row in parser_audit:
        artifact_type = str(row.get("artifact_type") or "unknown")
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        events_indexed = int(row.get("events_indexed") or 0)
        records_read = int(row.get("records_read") or 0)
        records_parsed = int(row.get("records_parsed") or 0)
        records_failed = int(row.get("records_failed") or 0)
        source_file = str(row.get("source_file") or "")
        by_artifact_type[artifact_type] += events_indexed
        by_parser[parser_name] += events_indexed
        if source_file:
            source_files_seen.add(source_file)
        if events_indexed > 0 and source_file:
            source_files_parsed.add(source_file)
        parser_bucket = parser_audit_by_parser.setdefault(
            parser_name,
            {"events_indexed": 0, "records_read": 0, "records_parsed": 0, "records_failed": 0, "artifacts": 0},
        )
        parser_bucket["events_indexed"] += events_indexed
        parser_bucket["records_read"] += records_read
        parser_bucket["records_parsed"] += records_parsed
        parser_bucket["records_failed"] += records_failed
        parser_bucket["artifacts"] += 1
        if records_failed > 0 or row.get("parser_errors") or row.get("errors"):
            failed_artifacts.append(
                {
                    "artifact_type": artifact_type,
                    "parser": parser_name,
                    "source_file": source_file or None,
                    "records_read": records_read,
                    "records_parsed": records_parsed,
                    "records_failed": records_failed,
                    "errors": list(row.get("parser_errors") or row.get("errors") or []),
                }
            )

    manifest = manifests.get(evidence_id or "") or {}
    stats = dict(manifest.get("stats") or {})
    parser_errors = list(current_summary.get("parser_errors") or [])
    bulk_index_errors = list(current_summary.get("bulk_index_errors") or [])
    warnings: list[str] = []
    suspected_regression_causes: list[str] = []

    if expected_events and current_events < expected_events:
        delta = current_events - expected_events
    else:
        delta = current_events - expected_events if expected_events else 0

    if expected_events and current_events < expected_events:
        warnings.append("events_below_baseline")
    if str(current_summary.get("status") or "").endswith("errors"):
        warnings.append("ingest_completed_with_errors")
        suspected_regression_causes.append("ingest_completed_with_errors")
    if bulk_index_errors:
        warnings.append("bulk_index_errors_present")
        suspected_regression_causes.append("opensearch_bulk_indexing")
    if parser_errors:
        warnings.append("parser_errors_present")
        suspected_regression_causes.append("parser_errors_or_partial_artifact_failure")
    if int(current_summary.get("artifacts_failed") or 0) > 0:
        suspected_regression_causes.append("failed_artifacts_present")
    if baseline and baseline.get("selected_candidates") and int(current_summary.get("artifacts_selected") or 0) < int(baseline.get("selected_candidates") or 0):
        suspected_regression_causes.append("artifact_selection_reduced")
    if baseline and baseline.get("selected_files_total") and int(current_summary.get("files_extracted") or 0) < int(baseline.get("selected_files_total") or 0):
        suspected_regression_causes.append("zip_extraction_or_source_discovery_reduced")
    if expected_events and not parser_errors and not bulk_index_errors and int(current_summary.get("artifacts_failed") or 0) == 0 and current_events < expected_events:
        suspected_regression_causes.append("baseline_delta_unexplained_requires_family_comparison")

    selection_mode = "manual_selection" if int(current_summary.get("artifacts_selected") or 0) > 0 else "full_auto"
    return {
        "case_id": context.case.id,
        "evidence_id": evidence_id,
        "expected_events_baseline": expected_events or None,
        "current_events_indexed": current_events,
        "delta": delta,
        "status": current_summary.get("status"),
        "artifacts_parseable": int(current_summary.get("artifacts_parseable") or 0),
        "artifacts_parsed": int(current_summary.get("artifacts_parsed") or 0),
        "artifacts_failed": int(current_summary.get("artifacts_failed") or 0),
        "by_artifact_type": dict(sorted(by_artifact_type.items(), key=lambda item: (-item[1], item[0]))),
        "by_parser": dict(sorted(by_parser.items(), key=lambda item: (-item[1], item[0]))),
        "parser_audit_by_parser": dict(sorted(parser_audit_by_parser.items())),
        "failed_artifacts": failed_artifacts[:100],
        "parser_errors": parser_errors,
        "bulk_index_errors": bulk_index_errors,
        "top_skipped_files": [],
        "source_files_seen": len(source_files_seen) or int(stats.get("total_files") or 0),
        "source_files_parsed": len(source_files_parsed) or int(stats.get("processed_files") or 0),
        "selection_mode": selection_mode,
        "storage_mode": current_summary.get("storage_mode"),
        "zip_extraction": {
            "selected_files_total": int(metadata.get("selected_files_total") or 0),
            "selected_files_extracted": int(metadata.get("selected_files_extracted") or 0),
            "candidate_files": int(metadata.get("candidate_files") or 0),
            "processed_files": int(stats.get("processed_files") or 0),
            "total_files": int(stats.get("total_files") or 0),
        },
        "host_attribution_summary": {
            "primary_host": (host_attribution_report or {}).get("primary_host"),
            "primary_host_source": (host_attribution_report or {}).get("primary_host_source"),
            "primary_host_confidence": (host_attribution_report or {}).get("primary_host_confidence"),
        },
        "suspected_regression_causes": sorted(set(suspected_regression_causes)),
        "warnings": warnings,
        "baseline_snapshot": baseline or None,
    }


def _collect_discovery_candidates(context: _DebugPackContext) -> list[dict]:
    rows = []
    for evidence in context.evidences:
        discovery = dict((evidence.metadata_json or {}).get("velociraptor_discovery") or {})
        for candidate in discovery.get("candidates") or []:
            rows.append({
                "candidate_id": candidate.get("id"),
                "evidence_id": evidence.id,
                "category": candidate.get("category"),
                "artifact_type": candidate.get("artifact_type"),
                "original_path": candidate.get("original_path"),
                "normalized_windows_path": candidate.get("normalized_windows_path"),
                "lnk_location": candidate.get("lnk_location"),
                "filename": candidate.get("filename"),
                "executable_name_guess": candidate.get("executable_name_guess"),
                "prefetch_hash_guess": candidate.get("prefetch_hash_guess"),
                "size": candidate.get("size"),
                "mtime": candidate.get("mtime"),
                "supported": candidate.get("supported"),
                "parser_status": candidate.get("parser_status"),
                "planned_parser": candidate.get("planned_parser"),
                "reason_detected": candidate.get("reason") or candidate.get("display_name"),
                "selected_for_extraction": candidate.get("selected_for_extraction"),
                "extracted": candidate.get("extracted"),
                "extraction_path": candidate.get("local_path"),
                "warnings": candidate.get("warnings") or [],
            })
    return rows


def _build_parser_audit(context: _DebugPackContext, manifests: dict[str, dict]) -> list[dict]:
    rows = []
    for evidence in context.evidences:
        for artifact in (manifests.get(evidence.id) or {}).get("artifacts") or []:
            ingest_audit = artifact.get("ingest_audit") or {}
            records_read = int(ingest_audit.get("records_read", artifact.get("record_count", 0)) or 0)
            records_parsed = int(ingest_audit.get("records_parsed", artifact.get("record_count", 0)) or 0)
            records_indexed = int(ingest_audit.get("events_indexed", artifact.get("record_count", 0)) or 0)
            records_skipped = int(ingest_audit.get("records_skipped", 0) or 0)
            records_filtered = int(ingest_audit.get("records_filtered", 0) or 0)
            records_failed = int(ingest_audit.get("records_failed", 0) or 0)
            records_unprocessed = int(ingest_audit.get("records_unprocessed", 0) or 0)
            filter_reason = ingest_audit.get("filter_reason")
            records_filtered_by_reason = dict(ingest_audit.get("records_filtered_by_reason") or {})

            if (
                str(artifact.get("parser") or "") == "evtx_raw"
                and records_read > 0
                and records_parsed == 0
                and records_indexed == 0
                and records_skipped == 0
                and records_filtered == 0
                and records_failed == 0
            ):
                records_filtered = records_read
                filter_reason = filter_reason or "no_events_after_filter"
                records_filtered_by_reason.setdefault(filter_reason, records_read)
            elif str(artifact.get("parser") or "") == "evtx_raw" and records_read > 0 and (records_parsed + records_filtered + records_failed) == 0:
                inferred_filtered = max(records_read - records_failed, 0)
                if inferred_filtered > 0:
                    records_filtered = inferred_filtered
                    filter_reason = filter_reason or "parser_policy_filtered"
                    records_filtered_by_reason.setdefault(filter_reason, inferred_filtered)
            computed_gap = max(records_read - (records_parsed + records_filtered + records_failed), 0)
            if computed_gap > 0:
                records_unprocessed = max(records_unprocessed, computed_gap)

            row = {
                "evidence_id": evidence.id,
                "parser_name": artifact.get("parser"),
                "artifact_type": artifact.get("artifact_type"),
                "source_file": artifact.get("source_path"),
                "parser_status": artifact.get("status"),
                "records_read": records_read,
                "records_parsed": records_parsed,
                "records_indexed": records_indexed,
                "records_skipped": records_skipped,
                "records_filtered": records_filtered,
                "records_failed": records_failed,
                "records_unprocessed": records_unprocessed,
                "warnings": ingest_audit.get("warnings", []),
                "errors": ingest_audit.get("errors", []),
                "duration_ms": ingest_audit.get("duration_ms"),
                "deduplicated_count": ingest_audit.get("deduplicated_count", 0),
                "records_extracted": ingest_audit.get("records_extracted"),
                "sample_records": ingest_audit.get("sample_records", []),
                "sample_event_ids": ingest_audit.get("sample_event_ids", []),
                "sample_messages": ingest_audit.get("sample_messages", []),
                "records_accounting_formula": "records_read = records_parsed + records_filtered + records_failed + records_unprocessed",
            }
            if filter_reason:
                row["filter_reason"] = filter_reason
                row["skip_reason"] = filter_reason
            if records_filtered_by_reason:
                row["records_filtered_by_reason"] = records_filtered_by_reason
            for key in (
                "channels_seen",
                "providers_seen",
                "event_ids_seen",
                "classification_counts",
                "by_browser",
                "by_artifact_type",
                "by_event_type",
                "history_count",
                "search_count",
                "download_count",
                "danger_type_counts",
                "data_quality_counts",
                "suspicious_reason_counts",
                "source_mismatch_count",
                "generic_windows_event_count",
                "lnk_files_seen",
                "lnk_files_parsed",
                "lnk_files_failed",
                "lnk_events_indexed",
                "suspicious_lnk_count",
                "missing_target_count",
                "network_path_count",
                "removable_path_count",
                "startup_lnk_count",
                "cloud_path_count",
                "unresolved_target_count",
                "partial_target_count",
                "parse_warnings",
                "prefetch_files_seen",
                "prefetch_files_parsed",
                "prefetch_files_failed",
                "prefetch_events_indexed",
                "prefetch_unsupported_version_count",
                "prefetch_parse_warnings_count",
                "prefetch_resolved_executable_path_count",
                "prefetch_unresolved_executable_path_count",
                "suspicious_prefetch_count",
                "lolbin_prefetch_count",
                "by_version",
                "providers_detected",
                "sync_roots_detected",
                "cloud_client_config_count",
                "cloud_file_activity_count",
                "wlan_profiles_count",
                "hosts_entries_count",
                "dns_entries_count",
                "detected_shimcache_sources",
                "shimcache_events_indexed",
                "control_sets_seen",
                "shimcache_format_counts",
            ):
                if key in ingest_audit:
                    row[key] = ingest_audit[key]
            rows.append(row)
    return rows


def _build_debug_export_scope_report(
    context: _DebugPackContext,
    *,
    manifests: dict[str, dict],
    parser_audit: list[dict],
    discovery_candidates: list[dict],
    ingest_summary: list[dict],
    fetched_events: _FetchedEvents,
    selected_artifact_types: list[str],
    host_attribution_report: dict[str, Any] | None = None,
    ingest_regression_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_ids = [str(evidence.id) for evidence in context.evidences if getattr(evidence, "id", None)]
    artifacts_found = int(sum(len((manifest.get("artifacts") or [])) for manifest in manifests.values()))
    parser_audit_artifact_types: dict[str, int] = defaultdict(int)
    parser_audit_evidence_ids: dict[str, int] = defaultdict(int)
    for row in parser_audit:
        artifact_type = str(row.get("artifact_type") or "unknown")
        parser_audit_artifact_types[artifact_type] += 1
        evidence_id = str(row.get("evidence_id") or "")
        if evidence_id:
            parser_audit_evidence_ids[evidence_id] += 1

    sampled_artifact_types: dict[str, int] = defaultdict(int)
    sampled_event_types: dict[str, int] = defaultdict(int)
    sampled_evidence_ids: dict[str, int] = defaultdict(int)
    for event in fetched_events.sampled_events:
        artifact_type = str(_nested_get(event, "artifact.type") or "unknown")
        event_type = str(_nested_get(event, "event.type") or "unknown")
        evidence_id = str(event.get("evidence_id") or "")
        sampled_artifact_types[artifact_type] += 1
        sampled_event_types[event_type] += 1
        if evidence_id:
            sampled_evidence_ids[evidence_id] += 1

    warnings: list[str] = []
    indexed_events_total = int(sum(int(item.get("indexed_events") or 0) for item in ingest_summary))
    bulk_reports = [item.get("opensearch_bulk") or {} for item in ingest_summary]
    refresh_reports = [item.get("opensearch_refresh") or {} for item in ingest_summary]
    performance_profiles = sorted({str(item.get("performance_profile") or "").strip() for item in ingest_summary if str(item.get("performance_profile") or "").strip()})
    performance_settings_snapshot = next((item.get("performance_settings") for item in ingest_summary if item.get("performance_settings")), {})
    if context.request.scope == "evidence" and context.request.evidence_id and not context.evidences:
        warnings.append("Requested evidence_id did not resolve to any evidence in this case")
    if indexed_events_total > 0 and fetched_events.total_events == 0:
        warnings.append("Scope query returned zero events even though ingest_summary reports indexed events")
    if any(report.get("timeout") for report in refresh_reports):
        warnings.append("opensearch_refresh_timeout_non_fatal")
    if any(int(report.get("timeouts") or 0) > 0 for report in bulk_reports):
        warnings.append("opensearch_bulk_timeout_recovered")
    if artifacts_found > 0 and not parser_audit:
        warnings.append("No parser_audit rows were built even though manifest artifacts exist")

    return {
        "scope": context.request.scope,
        "case_id": context.case.id,
        "evidence_id": context.request.evidence_id,
        "artifact_id": None,
        "selected_artifact_types": selected_artifact_types,
        "evidence_ids_in_scope": evidence_ids,
        "events_query": {
            "filters": {
                "case_id": context.case.id,
                "evidence_id": context.request.evidence_id,
                "artifact_types": selected_artifact_types,
            },
            "opensearch_query": fetched_events.scope_query,
        },
        "events_found": int(fetched_events.total_events or 0),
        "events_sampled": len(fetched_events.sampled_events),
        "sampled_event_artifact_types": dict(sorted(sampled_artifact_types.items())),
        "sampled_event_types": dict(sorted(sampled_event_types.items())),
        "sampled_event_evidence_ids": dict(sorted(sampled_evidence_ids.items())),
        "parser_audit_query": {
            "source": "manifest.artifacts",
            "evidence_ids": evidence_ids,
        },
        "parser_audit_found": len(parser_audit),
        "parser_audit_artifact_types": dict(sorted(parser_audit_artifact_types.items())),
        "parser_audit_evidence_ids": dict(sorted(parser_audit_evidence_ids.items())),
        "artifacts_found": artifacts_found,
        "discovery_candidates_found": len(discovery_candidates),
        "performance_profile": performance_profiles[0] if len(performance_profiles) == 1 else performance_profiles,
        "performance_settings": performance_settings_snapshot or {},
        "opensearch_bulk": bulk_reports,
        "opensearch_refresh": refresh_reports,
        "reports_built": [
            "ingest_summary",
            "discovery_candidates",
            "parser_audit",
            "normalized_events_sample",
            "autoruns_parse_report",
            "autoruns_sample_events",
            "cloud_parse_report",
            "cloud_sample_events",
            "browser_parse_report",
            "browser_sample_events",
            "defender_parse_report",
            "defender_sample_events",
            "field_coverage_report",
            "data_quality_report",
        ],
        "host_attribution": {
            "primary_host": (host_attribution_report or {}).get("primary_host"),
            "primary_host_source": (host_attribution_report or {}).get("primary_host_source"),
            "primary_host_confidence": (host_attribution_report or {}).get("primary_host_confidence"),
            "accepted_hosts": len((host_attribution_report or {}).get("hosts_accepted") or []),
            "alias_candidates": len((host_attribution_report or {}).get("host_alias_candidates") or []),
            "rejected_candidates": len((host_attribution_report or {}).get("host_candidates_rejected") or []),
        },
        "ingest_regression_summary": {
            "expected_events_baseline": (ingest_regression_report or {}).get("expected_events_baseline"),
            "current_events_indexed": (ingest_regression_report or {}).get("current_events_indexed"),
            "delta": (ingest_regression_report or {}).get("delta"),
            "status": (ingest_regression_report or {}).get("status"),
            "artifacts_failed": (ingest_regression_report or {}).get("artifacts_failed"),
            "suspected_regression_causes": (ingest_regression_report or {}).get("suspected_regression_causes") or [],
        },
        "warnings": warnings,
    }


def _collect_rules_matches(db: Session, context: _DebugPackContext, request: DebugExportRequest | None = None) -> list[dict]:
    request = request or context.request
    query = db.query(DetectionResult).filter(
        DetectionResult.case_id == context.case.id,
        DetectionResult.deleted_at.is_(None),
    )
    if context.request.evidence_id:
        query = query.filter(DetectionResult.evidence_id == context.request.evidence_id)
    if context.request.event_ids:
        query = query.filter(DetectionResult.event_id.in_(context.request.event_ids))
    rows = []
    for item in query.order_by(DetectionResult.created_at.desc()).limit(500).all():
        raw = item.raw or {}
        matched_event = fetch_event_by_id(context.case.id, item.event_id, event_index=item.event_index, opensearch_id=item.opensearch_id)
        rule_namespace = raw.get("namespace") or raw.get("rule_namespace") or item.source_engine or item.engine or "builtin"
        stable_rule_id = item.rule_id or f"{rule_namespace}.{_slugify(item.rule_name).replace('_', '.')}"
        builtin_definition = _infer_builtin_definition(item.rule_id, item.rule_name, rule_namespace)
        matched_fields = _coerce_matched_fields(raw)
        if builtin_definition and not matched_fields:
            matched_fields = [str(field) for field in builtin_definition.fields_consulted if field]
        matched_values = _extract_matched_values(raw, matched_fields)
        event_summary = None
        artifact_type = None
        source_file = item.target_path
        tags: list[str] = []
        if matched_event:
            sanitized_event = _sanitize_event(matched_event, request)
            event_summary = (sanitized_event.get("event") or {}).get("message") or sanitized_event.get("raw_summary")
            artifact_type = ((sanitized_event.get("artifact") or {}).get("type")) or None
            source_file = sanitized_event.get("source_file") or source_file
            tags = list(sanitized_event.get("tags") or [])
            if builtin_definition:
                for field in matched_fields:
                    value = _nested_get(sanitized_event, field)
                    if value not in (None, "", [], {}) and field not in matched_values:
                        matched_values[field] = value
        rows.append({
            "rule_id": stable_rule_id,
            "rule_name": item.rule_name,
            "rule_title": item.rule_title,
            "rule_namespace": rule_namespace,
            "source_engine": item.source_engine,
            "severity": item.severity,
            "enabled": raw.get("enabled", True),
            "matched_event_id": item.event_id,
            "matched_file_path": item.target_path,
            "matched_file_hash": item.matched_file_hash,
            "matched_fields": matched_fields,
            "matched_strings": list(item.matched_strings or []),
            "matched_values": _sanitize_value(matched_values, request),
            "reason": item.message,
            "condition_summary": item.condition_summary,
            "confidence": item.confidence if item.confidence is not None else raw.get("confidence"),
            "false_positive_notes": raw.get("false_positive_notes"),
            "event_summary": event_summary,
            "artifact_type": artifact_type,
            "source_file": source_file,
            "tags": tags,
        })
    return rows


def _build_detections_report(db: Session, context: _DebugPackContext) -> dict:
    query = db.query(DetectionResult).filter(
        DetectionResult.case_id == context.case.id,
        DetectionResult.deleted_at.is_(None),
    )
    if context.request.evidence_id:
        query = query.filter(DetectionResult.evidence_id == context.request.evidence_id)
    rows = query.all()
    by_source: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_matched_object_type: dict[str, int] = {}
    for row in rows:
        by_source[row.source_engine or row.engine] = by_source.get(row.source_engine or row.engine, 0) + 1
        by_rule[row.rule_name] = by_rule.get(row.rule_name, 0) + 1
        by_severity[str(row.severity or "unknown")] = by_severity.get(str(row.severity or "unknown"), 0) + 1
        by_status[row.status] = by_status.get(row.status, 0) + 1
        by_matched_object_type[row.target_type] = by_matched_object_type.get(row.target_type, 0) + 1
    duplicate_count = sum(1 for row in rows if row.status == "dismissed" and row.dedup_fingerprint)
    return {
        "case_id": context.case.id,
        "evidence_id": context.request.evidence_id,
        "detections_total": len(rows),
        "by_source": by_source,
        "by_rule": by_rule,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_matched_object_type": by_matched_object_type,
        "duplicates_skipped": duplicate_count,
        "errors": [],
        "warnings": [],
    }


def _build_rules_run_report(db: Session, context: _DebugPackContext) -> dict:
    query = db.query(RuleRun).filter(RuleRun.case_id == context.case.id)
    if context.request.evidence_id:
        query = query.filter((RuleRun.evidence_id == context.request.evidence_id) | (RuleRun.evidence_id.is_(None)))
    runs = query.order_by(RuleRun.created_at.desc()).limit(50).all()
    latest = runs[0] if runs else None
    latest_metadata = latest.metadata_json or {} if latest else {}
    duration_seconds = 0.0
    if latest and latest.started_at and latest.finished_at:
        try:
            duration_seconds = max((datetime.fromisoformat(str(latest.finished_at).replace("Z", "+00:00")) - datetime.fromisoformat(str(latest.started_at).replace("Z", "+00:00"))).total_seconds(), 0.0)
        except ValueError:
            duration_seconds = 0.0
    return {
        "run_id": latest.id if latest else None,
        "rule_types": list(latest_metadata.get("rule_types") or ([latest.engine] if latest else [])),
        "rules_evaluated": int(latest_metadata.get("rules_evaluated") or 0) if latest else 0,
        "rules_compiled": int(latest_metadata.get("rules_compiled") or 0) if latest else 0,
        "rules_runnable_in_scope": int(latest_metadata.get("rules_runnable_in_scope") or 0) if latest else 0,
        "rules_runtime_error": int(latest_metadata.get("rules_runtime_error") or 0) if latest else 0,
        "total_rules_considered": int(latest_metadata.get("total_rules_considered") or 0) if latest else 0,
        "total_rules_runnable": int(latest_metadata.get("total_rules_runnable") or 0) if latest else 0,
        "total_rules_executed": int(latest_metadata.get("total_rules_executed") or 0) if latest else 0,
        "total_rules_skipped": int(latest_metadata.get("total_rules_skipped") or 0) if latest else 0,
        "skipped_by_reason": dict(latest_metadata.get("skipped_by_reason") or {}) if latest else {},
        "events_in_scope": int(latest_metadata.get("events_in_scope") or latest.total_events or 0) if latest else 0,
        "candidate_event_evaluations": int(latest_metadata.get("candidate_event_evaluations") or 0) if latest else 0,
        "matches_found": int(latest_metadata.get("matches_found") or latest.matched or 0) if latest else 0,
        "events_scanned": int(latest_metadata.get("events_scanned") or 0) if latest else 0,
        "candidate_events_prefiltered": int(latest_metadata.get("candidate_events_prefiltered") or 0) if latest else 0,
        "files_scanned": int(latest_metadata.get("files_scanned") or 0) if latest else 0,
        "files_skipped": int(latest.skipped_files or 0) if latest else 0,
        "detections_created": int(latest.created_detections or 0) if latest else 0,
        "duplicates_skipped": int(latest.duplicates or 0) if latest else 0,
        "duration_seconds": duration_seconds,
        "display_status": str(latest_metadata.get("display_status") or latest.status.value) if latest else "completed",
        "errors": list(latest.errors or []) if latest else [],
        "warnings": list(latest_metadata.get("warnings") or []) if latest else [],
        "query_time_ms_total": int(latest_metadata.get("query_time_ms_total") or 0) if latest else 0,
        "dedupe_time_ms_total": int(latest_metadata.get("dedupe_time_ms_total") or 0) if latest else 0,
        "write_time_ms_total": int(latest_metadata.get("write_time_ms_total") or 0) if latest else 0,
        "noisy_rules_count": int(latest_metadata.get("noisy_rules_count") or 0) if latest else 0,
        "capped_rules_count": int(latest_metadata.get("capped_rules_count") or 0) if latest else 0,
        "top_noisy_rules": list(latest_metadata.get("top_noisy_rules") or []) if latest else [],
        "bulk_insert_batches": int(latest_metadata.get("bulk_insert_batches") or 0) if latest else 0,
        "bulk_duplicate_lookups": int(latest_metadata.get("bulk_duplicate_lookups") or 0) if latest else 0,
        "sigma_case_profile": dict(latest_metadata.get("sigma_case_profile") or {}) if latest else {},
        "sigma_rule_preflight_report": list(latest_metadata.get("sigma_rule_preflight_report") or []) if latest else [],
        "top_skipped_examples": list(latest_metadata.get("top_skipped_examples") or []) if latest else [],
        "top_matched_rules": list(latest_metadata.get("top_matched_rules") or []) if latest else [],
        "top_duration_rules": list(latest_metadata.get("top_duration_rules") or []) if latest else [],
        "top_duplicate_rules": list(latest_metadata.get("top_duplicate_rules") or []) if latest else [],
        "runtime_errors": list(latest_metadata.get("runtime_errors") or []) if latest else [],
    }


def _collect_semiauto_analysis(db: Session, context: _DebugPackContext) -> dict:
    request = context.request
    job = (
        db.query(CaseAnalysisJob)
        .filter(CaseAnalysisJob.case_id == context.case.id, CaseAnalysisJob.analysis_type == "semi_auto")
        .order_by(CaseAnalysisJob.created_at.desc())
        .first()
    )
    if request.include_cached_semiauto and job and job.result_json:
        result = deepcopy(job.result_json)
        result.setdefault("warnings", [])
        result["warnings"].append("Semi-automatic analysis exported from cached analysis result.")
        return result
    if request.rebuild_semiauto_for_export:
        result = build_case_semi_auto_analysis(context.case.id)
        result.setdefault("warnings", [])
        result["warnings"].append("Semi-automatic analysis was rebuilt synchronously for this export.")
        return result
    return {
        "warnings": [
            "No cached semi-automatic analysis result was available for this export scope.",
            "Set rebuild_semiauto_for_export=true to rebuild analysis during export.",
        ],
        "sections": {},
        "counts": {},
        "activities": [],
    }


def _collect_indexing_errors(context: _DebugPackContext, manifests: dict[str, dict]) -> list[dict]:
    rows = []
    for evidence in context.evidences:
        for error in (evidence.error_log or {}).get("errors", []):
            payload = json.dumps(error, ensure_ascii=True)
            rows.append({
                "timestamp": evidence.processed_at.isoformat() if evidence.processed_at else None,
                "index": get_events_index(evidence.case_id),
                "operation": "bulk_index",
                "document_id": None,
                "artifact": error.get("artifact") if isinstance(error, dict) else None,
                "source_file": error.get("artifact") if isinstance(error, dict) else None,
                "error_type": _infer_error_type(payload),
                "error_reason": error.get("error") if isinstance(error, dict) else payload,
                "failed_fields": _infer_failed_fields(payload),
                "document_preview": payload[:1000],
                "suggested_fix": _suggest_fix(payload),
            })
        for error in (manifests.get(evidence.id) or {}).get("errors") or []:
            payload = json.dumps(error, ensure_ascii=True)
            rows.append({
                "timestamp": evidence.processed_at.isoformat() if evidence.processed_at else None,
                "index": get_events_index(evidence.case_id),
                "operation": "ingest",
                "document_id": None,
                "artifact": error.get("artifact") if isinstance(error, dict) else None,
                "source_file": error.get("artifact") if isinstance(error, dict) else None,
                "error_type": _infer_error_type(payload),
                "error_reason": error.get("error") if isinstance(error, dict) else payload,
                "failed_fields": _infer_failed_fields(payload),
                "document_preview": payload[:1000],
                "suggested_fix": _suggest_fix(payload),
            })
    return rows


def _build_field_coverage_report(events: list[dict]) -> dict:
    groups: dict[str, dict[str, Any]] = {}
    important_fields = [
        "@timestamp",
        "host.name",
        "user.name",
        "source_file",
        "artifact.type",
        "artifact.parser",
        "event.category",
        "event.type",
    ]
    for event in events:
        artifact = event.get("artifact") or {}
        key = f"{artifact.get('type', 'unknown')}/{artifact.get('parser', 'unknown')}"
        bucket = groups.setdefault(key, {"total_events": 0, "fields": defaultdict(int)})
        bucket["total_events"] += 1
        for field in important_fields:
            if _nested_get(event, field) not in (None, "", [], {}):
                bucket["fields"][field] += 1
        if artifact.get("type") == "windows_event":
            for field in ("windows.event_id", "windows.channel", "windows.provider"):
                if _nested_get(event, field) not in (None, "", [], {}):
                    bucket["fields"][field] += 1
        if artifact.get("type") == "lnk":
            for field in ("lnk.target_path", "lnk.source_file", "lnk.target_accessed"):
                if _nested_get(event, field) not in (None, "", [], {}):
                    bucket["fields"][field] += 1
        if artifact.get("type") == "cloud":
            for field in ("cloud.provider", "cloud.sync_root", "cloud.local_path", "cloud.account"):
                if _nested_get(event, field) not in (None, "", [], {}):
                    bucket["fields"][field] += 1
    report = {}
    for key, bucket in groups.items():
        total = max(bucket["total_events"], 1)
        fields = bucket["fields"]
        report[key] = {
            "total_events": bucket["total_events"],
            "percent_with_timestamp": round((fields.get("@timestamp", 0) / total) * 100, 2),
            "percent_with_host": round((fields.get("host.name", 0) / total) * 100, 2),
            "percent_with_user": round((fields.get("user.name", 0) / total) * 100, 2),
            "percent_with_source_file": round((fields.get("source_file", 0) / total) * 100, 2),
            "missing_common_fields": [field for field in important_fields if fields.get(field, 0) == 0],
            "missing_important_fields": [field for field in important_fields if fields.get(field, 0) < total],
            "timestamp_coverage": fields.get("@timestamp", 0),
            "host_coverage": fields.get("host.name", 0),
            "user_coverage": fields.get("user.name", 0),
            "source_file_coverage": fields.get("source_file", 0),
            "null_ratio_by_field": {
                field: round(1 - (fields.get(field, 0) / total), 4) for field in sorted(fields.keys())
            },
        }
    return report


def _build_data_quality_report(events: list[dict]) -> dict:
    bucket: dict[str, dict[str, Any]] = {}
    artifact_types_affected: set[str] = set()
    source_counts: dict[str, int] = defaultdict(int)
    total_events_with_data_quality = 0
    for event in events:
        flags = list(event.get("data_quality") or [])
        if flags:
            total_events_with_data_quality += 1
        for flag in flags:
            entry = bucket.setdefault(flag, {"count": 0, "sample_event_ids": [], "artifact_types": set(), "source_files": set()})
            entry["count"] += 1
            if len(entry["sample_event_ids"]) < 10 and event.get("id"):
                entry["sample_event_ids"].append(event.get("id"))
            artifact_type = ((event.get("artifact") or {}).get("type")) or "unknown"
            entry["artifact_types"].add(artifact_type)
            artifact_types_affected.add(artifact_type)
            if event.get("source_file"):
                entry["source_files"].add(event["source_file"])
                source_counts[str(event["source_file"])] += 1
    details = {
        key: {
            "count": value["count"],
            "sample_event_ids": value["sample_event_ids"],
            "artifact_types": sorted(value["artifact_types"]),
            "source_files": sorted(value["source_files"])[:25],
        }
        for key, value in bucket.items()
    }
    return {
        "summary": {
            "total_events_with_data_quality": total_events_with_data_quality,
            "data_quality_counts": {key: value["count"] for key, value in sorted(bucket.items())},
            "artifact_types_affected": sorted(artifact_types_affected),
            "top_source_files": [source for source, _count in sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:25]],
        },
        "details": details,
    }


def _build_dedup_report(events: list[dict]) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        artifact_type = ((event.get("artifact") or {}).get("type")) or "unknown"
        if artifact_type == "windows_event":
            key = "|".join([
                str(event.get("case_id") or ""),
                str(event.get("evidence_id") or ""),
                str(event.get("source_file") or ""),
                str(_nested_get(event, "windows.channel") or ""),
                str(_nested_get(event, "windows.record_id") or ""),
                str(_nested_get(event, "windows.event_id") or ""),
                str(event.get("@timestamp") or ""),
            ])
        elif artifact_type == "lnk":
            key = "|".join([
                str(event.get("case_id") or ""),
                str(event.get("evidence_id") or ""),
                str(event.get("source_file") or ""),
                str(_nested_get(event, "lnk.target_path") or ""),
                str(_nested_get(event, "lnk.target_accessed") or ""),
                str(_nested_get(event, "lnk.source_modified") or ""),
            ])
        elif artifact_type == "prefetch":
            key = "|".join([
                str(event.get("case_id") or ""),
                str(event.get("evidence_id") or ""),
                str(_nested_get(event, "prefetch.executable_name") or ""),
                str(_nested_get(event, "prefetch.prefetch_hash") or _nested_get(event, "prefetch.hash") or ""),
                str(_nested_get(event, "prefetch.last_run") or _nested_get(event, "execution.last_run") or ""),
                str(_nested_get(event, "prefetch.run_count") or _nested_get(event, "execution.run_count") or ""),
                str(event.get("source_file") or ""),
            ])
        else:
            canonical = json.dumps({
                "source_file": event.get("source_file"),
                "artifact": event.get("artifact"),
                "event": event.get("event"),
                "timestamp": event.get("@timestamp"),
            }, sort_keys=True, ensure_ascii=True)
            key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        groups[key].append(event)
    duplicates = {key: items for key, items in groups.items() if len(items) > 1}
    return {
        "dedup_strategy": {
            "windows_event": "case_id + evidence_id + source_file + channel + record_id + event_id + timestamp",
            "lnk": "case_id + evidence_id + source_file + target_path + target_accessed + source_modified",
            "prefetch": "case_id + evidence_id + executable_name + prefetch_hash + last_run + run_count + source_file",
            "fallback": "hash of canonical reduced event metadata",
            "external_vs_native": ["native_evtx vs EvtxECmd", "native_lnk vs LECmd", "native_prefetch vs PECmd"],
        },
        "duplicate_groups_count": len(duplicates),
        "deduplicated_events_count": sum(max(len(items) - 1, 0) for items in duplicates.values()),
        "examples": [
            {
                "dedup_key": key,
                "event_ids": [str(item.get("id") or item.get("event_id") or "unknown") for item in items[:10]],
                "artifact.type": ((items[0].get("artifact") or {}).get("type")) if items else None,
                "artifact.parser": ((items[0].get("artifact") or {}).get("parser")) if items else None,
                "source_tool": items[0].get("source_tool") if items else None,
                "source_files": sorted({str(item.get("source_file") or "") for item in items if item.get("source_file")})[:10],
                "reason": "matching_dedup_strategy_key",
                "chosen_canonical_event_id": str((items[0].get("id") or items[0].get("event_id") or "unknown")) if items else None,
            }
            for key, items in list(duplicates.items())[:10]
        ],
    }


def _build_source_inventory(manifests: dict[str, dict]) -> list[dict]:
    rows = []
    for evidence_id, manifest in manifests.items():
        for file_entry in (manifest.get("files") or [])[:100]:
            rows.append({"evidence_id": evidence_id, **file_entry})
    return rows


def _sanitize_event(event: dict, request: DebugExportRequest) -> dict:
    reduced = {
        "id": event.get("id"),
        "event_id": event.get("event_id"),
        "stable_event_id": event.get("stable_event_id"),
        "event_fingerprint": event.get("event_fingerprint"),
        "event_fingerprint_version": event.get("event_fingerprint_version"),
        "case_id": event.get("case_id"),
        "evidence_id": event.get("evidence_id"),
        "artifact_id": event.get("artifact_id"),
        "source_file": event.get("source_file"),
        "source_tool": event.get("source_tool"),
        "source_format": event.get("source_format"),
        "@timestamp": event.get("@timestamp"),
        "timestamp_precision": event.get("timestamp_precision"),
        "host": deepcopy(event.get("host") or {}),
        "user": deepcopy(event.get("user") or {}),
        "artifact": deepcopy(event.get("artifact") or {}),
        "event": deepcopy(event.get("event") or {}),
        "windows": deepcopy(event.get("windows") or {}),
        "process": deepcopy(event.get("process") or {}),
        "execution": deepcopy(event.get("execution") or {}),
        "persistence": deepcopy(event.get("persistence") or {}),
        "service": deepcopy(event.get("service") or {}),
        "file": deepcopy(event.get("file") or {}),
        "url": deepcopy(event.get("url") or {}),
        "download": deepcopy(event.get("download") or {}),
        "usb": deepcopy(event.get("usb") or {}),
        "volume": deepcopy(event.get("volume") or {}),
        "registry": deepcopy(event.get("registry") or {}),
        "lnk": deepcopy(event.get("lnk") or {}),
        "shimcache": deepcopy(event.get("shimcache") or {}),
        "appcompat": deepcopy(event.get("appcompat") or {}),
        "browser": deepcopy(event.get("browser") or {}),
        "powershell": deepcopy(event.get("powershell") or {}),
        "detection": deepcopy(event.get("detection") or {}),
        "wmi": deepcopy(event.get("wmi") or {}),
        "bits": deepcopy(event.get("bits") or {}),
        "cloud": deepcopy(event.get("cloud") or {}),
        "network": deepcopy(event.get("network") or {}),
        "dns": deepcopy(event.get("dns") or {}),
        "wlan": deepcopy(event.get("wlan") or {}),
        "srum": deepcopy(event.get("srum") or {}),
        "recycle": deepcopy(event.get("recycle") or {}),
        "tags": deepcopy(event.get("tags") or []),
        "data_quality": deepcopy(event.get("data_quality") or []),
        "risk_score": event.get("risk_score"),
        "suspicious_reasons": deepcopy(event.get("suspicious_reasons") or []),
        "raw_summary": event.get("raw_summary"),
        "search_text_preview": _truncate_text(str(event.get("search_text") or ""), request.max_field_length),
    }
    if request.include_raw_samples:
        raw = deepcopy(event.get("raw") or {})
        if not request.include_raw_xml and isinstance(raw, dict):
            for key in list(raw.keys()):
                if str(key).lower() in {"rawxml", "raw_xml"}:
                    raw[key] = "[REDACTED]"
        reduced["raw"] = raw
    sanitized = _sanitize_value(reduced, request)
    sanitized = _hydrate_shimcache_export_objects(sanitized)
    if str(_nested_get(sanitized, "artifact.type") or "") == "browser":
        url_obj = sanitized.get("url") if isinstance(sanitized.get("url"), dict) else {}
        if not any(url_obj.get(key) for key in ("full", "domain", "scheme", "path", "query")):
            primary_url = (
                _nested_get(sanitized, "browser.url")
                or _nested_get(sanitized, "browser.final_url")
                or _nested_get(sanitized, "network.url")
            )
            parsed = _parse_url_like(primary_url)
            if isinstance(url_obj, dict):
                url_obj.update(parsed)
                sanitized["url"] = url_obj
            else:
                sanitized["url"] = parsed
    if not request.include_raw_xml and isinstance(sanitized.get("windows"), dict):
        for key in list(sanitized["windows"].keys()):
            if str(key).lower() in {"rawxml", "raw_xml"}:
                sanitized["windows"].pop(key, None)
    if not request.include_source_paths:
        sanitized["source_file"] = None
        if isinstance(sanitized.get("file"), dict):
            sanitized["file"]["path"] = None
        if isinstance(sanitized.get("lnk"), dict):
            sanitized["lnk"]["source_file"] = None
            sanitized["lnk"]["target_path"] = None
        if isinstance(sanitized.get("cloud"), dict):
            sanitized["cloud"]["local_path"] = None
            sanitized["cloud"]["sync_root"] = None
    return sanitized


def _basename_windows(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return PureWindowsPath(path).name or None
    except Exception:  # noqa: BLE001
        value = str(path).replace("/", "\\").rstrip("\\")
        return value.rsplit("\\", 1)[-1] if value else None


def _parse_url_like(value: object | None) -> dict[str, Any]:
    text = str(value or "").strip()
    if not text:
        return {"full": None, "domain": None, "scheme": None, "path": None, "query": None}
    from urllib.parse import urlparse

    parsed = urlparse(text)
    domain = parsed.netloc or None
    return {
        "full": text,
        "domain": domain.lower() if domain else None,
        "scheme": parsed.scheme.lower() if parsed.scheme else None,
        "path": parsed.path or None,
        "query": parsed.query or None,
    }


def _hydrate_shimcache_export_objects(event: dict) -> dict:
    artifact = event.get("artifact") or {}
    if artifact.get("type") != "shimcache":
        return event

    file_info = event.get("file") or {}
    process = event.get("process") or {}
    execution = event.get("execution") or {}
    shimcache = deepcopy(event.get("shimcache") or {})
    appcompat = deepcopy(event.get("appcompat") or {})

    normalized_path = normalize_windows_path_for_classification(
        shimcache.get("path")
        or appcompat.get("path")
        or file_info.get("path")
        or process.get("path")
    )
    file_name = (
        process.get("name")
        or file_info.get("name")
        or appcompat.get("name")
        or _basename_windows(normalized_path)
    )
    source_file = (
        shimcache.get("source_file")
        or appcompat.get("source_file")
        or event.get("source_file")
    )
    interpretation = (
        execution.get("interpretation")
        or appcompat.get("interpretation")
        or "Shimcache/AppCompatCache indicates file presence or compatibility cache entry, not execution by itself"
    )

    shimcache.update(
        {
            "artifact_type": shimcache.get("artifact_type") or ("shimcache_raw" if artifact.get("parser") == "shimcache_raw" else "shimcache_parsed"),
            "path": normalized_path or shimcache.get("path"),
            "last_modified_time": shimcache.get("last_modified_time") or file_info.get("modified") or execution.get("last_modified"),
            "last_update": shimcache.get("last_update"),
            "insert_flags": shimcache.get("insert_flags"),
            "shim_flags": shimcache.get("shim_flags"),
            "executed": shimcache.get("executed"),
            "control_set": shimcache.get("control_set"),
            "source_file": source_file,
            "key_path": shimcache.get("key_path"),
            "parser_status": shimcache.get("parser_status") or ("parsed_native" if artifact.get("parser") == "shimcache_raw" else None),
            "timestamp_interpretation": shimcache.get("timestamp_interpretation") or event.get("timestamp_precision"),
        }
    )
    appcompat.update(
        {
            "artifact_type": appcompat.get("artifact_type") or "shimcache_entry",
            "path": normalized_path or appcompat.get("path"),
            "name": file_name or appcompat.get("name"),
            "last_modified": appcompat.get("last_modified") or shimcache.get("last_modified_time") or file_info.get("modified") or execution.get("last_modified"),
            "last_write_time": appcompat.get("last_write_time"),
            "entry_number": appcompat.get("entry_number") or shimcache.get("entry_number"),
            "source_file": source_file,
            "interpretation": interpretation,
        }
    )

    event["shimcache"] = shimcache
    event["appcompat"] = appcompat
    return event


def _sanitize_value(value: Any, request: DebugExportRequest, *, key: str | None = None) -> Any:
    if isinstance(value, dict):
        result = {}
        for child_key, child_value in value.items():
            if request.redact_secrets and _SENSITIVE_KEY_RE.search(str(child_key)):
                result[child_key] = "[REDACTED]"
                continue
            result[child_key] = _sanitize_value(child_value, request, key=str(child_key))
        return result
    if isinstance(value, list):
        return [_sanitize_value(item, request, key=key) for item in value[:250]]
    if isinstance(value, str):
        text = value
        if request.redact_secrets and ((key and _SENSITIVE_KEY_RE.search(key)) or _SENSITIVE_VALUE_RE.search(text)):
            return "[REDACTED]"
        if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
            return "[REDACTED]"
        return _truncate_text(text, request.max_field_length)
    return value


def _truncate_text(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[:max_length]}...[TRUNCATED]"


def _nested_get(data: dict, dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _reduce_timeline_event(event: dict) -> dict:
    return {
        "timestamp": event.get("@timestamp"),
        "event_id": event.get("event_id"),
        "event.category": (event.get("event") or {}).get("category"),
        "event.type": (event.get("event") or {}).get("type"),
        "summary": (event.get("event") or {}).get("message") or event.get("raw_summary"),
        "source_file": event.get("source_file"),
        "artifact.type": (event.get("artifact") or {}).get("type"),
        "host": (event.get("host") or {}).get("name"),
        "user": (event.get("user") or {}).get("name"),
        "risk_score": event.get("risk_score"),
        "tags": event.get("tags") or [],
    }


def _reduce_evtx_classification_event(event: dict) -> dict:
    return {
        "id": event.get("id"),
        "event_id": _nested_get(event, "windows.event_id"),
        "channel": _nested_get(event, "windows.channel"),
        "provider": _nested_get(event, "windows.provider"),
        "event.type": _nested_get(event, "event.type"),
        "event.category": _nested_get(event, "event.category"),
        "event.message": _nested_get(event, "event.message"),
        "windows.event_data_summary": _truncate_text(str(_nested_get(event, "windows.event_data_summary") or ""), 512),
        "tags": event.get("tags") or [],
        "data_quality": event.get("data_quality") or [],
        "source_file": event.get("source_file"),
    }


def _write_json(zip_file: zipfile.ZipFile, name: str, payload: Any) -> None:
    zip_file.writestr(name, json.dumps(payload, indent=2, ensure_ascii=True, default=str))


def _write_jsonl(zip_file: zipfile.ZipFile, name: str, rows: list[dict]) -> None:
    content = "\n".join(json.dumps(row, ensure_ascii=True, default=str) for row in rows)
    zip_file.writestr(name, content + ("\n" if content else ""))


def _write_markdown(zip_file: zipfile.ZipFile, name: str, content: str) -> None:
    zip_file.writestr(name, content)


def _slugify(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("_")
    return sanitized or "case"


def _infer_error_type(payload: str) -> str:
    lowered = payload.lower()
    if "mapper_parsing_exception" in lowered:
        return "mapper_parsing_exception"
    if "illegal_argument_exception" in lowered:
        return "illegal_argument_exception"
    if "date" in lowered and "parse" in lowered:
        return "date_parse_error"
    return "ingest_error"


def _infer_failed_fields(payload: str) -> list[str]:
    return re.findall(r"\[([A-Za-z0-9_.-]+)\] of type", payload)[:10]


def _suggest_fix(payload: str) -> str | None:
    lowered = payload.lower()
    if "mapper_parsing_exception" in lowered:
        return "Check field type normalization before indexing and compare against explicit OpenSearch mapping."
    if "total fields" in lowered or "dynamic" in lowered:
        return "Check raw/event_data sanitization and ensure dynamic mapping remains disabled."
    if "date" in lowered and "parse" in lowered:
        return "Check timestamp parsing, timezone normalization and timestamp_precision fallback."
    return None


def _event_is_suspicious(event: dict) -> bool:
    return (
        (event.get("risk_score") or 0) > 0
        or bool(event.get("suspicious_reasons"))
        or ((event.get("event", {}) or {}).get("severity") in {"medium", "high", "critical"})
        or any("suspicious" in str(tag).lower() for tag in (event.get("tags") or []))
    )


def _is_process_start_event(event: dict) -> bool:
    event_type = str(_nested_get(event, "event.type") or "")
    artifact_type = str(_nested_get(event, "artifact.type") or "")
    return event_type in {"process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"} or artifact_type == "process"


def _safe_parse_dt(value: object | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = date_parser.parse(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:  # noqa: BLE001
        return None


def _safe_intish(value: object | None) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except Exception:  # noqa: BLE001
        return None


def _safe_name_from_path(value: object | None) -> str | None:
    text = normalize_windows_path_for_classification(str(value or "").strip())
    if not text:
        return None
    try:
        return PureWindowsPath(text).name or text
    except Exception:  # noqa: BLE001
        return text.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or text


def _path_is_user_writable(path: str | None) -> bool:
    lowered = str(path or "").lower()
    return any(token in lowered for token in ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\startup\\", "\\public\\"))


def _path_bucket_reason(path: str | None) -> list[str]:
    lowered = str(path or "").lower()
    reasons: list[str] = []
    if _path_is_user_writable(path):
        reasons.append("Process from user-writable path")
    if "\\temp\\" in lowered:
        reasons.append("Process from Temp")
    if "\\downloads\\" in lowered:
        reasons.append("Process from Downloads")
    return reasons


def _double_extension(path: str | None) -> bool:
    name = _safe_name_from_path(path)
    if not name:
        return False
    parts = name.lower().split(".")
    return len(parts) >= 3 and parts[-1] in {"exe", "scr", "ps1", "bat", "cmd", "js", "vbs", "hta"} and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"}


def _is_program_files_path(path: str | None) -> bool:
    lowered = str(path or "").lower()
    return lowered.startswith("c:\\program files\\") or lowered.startswith("c:\\program files (x86)\\")


def _is_browser_internal_child(parent_name: str | None, child_name: str | None, child_path: str | None) -> bool:
    normalized_parent = str(parent_name or "").lower().strip()
    normalized_child = str(child_name or "").lower().strip()
    if not normalized_parent:
        return False
    browser_process_names = {"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe"}
    browser_internal_child_names = browser_process_names | {"identity_helper.exe"}
    if normalized_parent not in browser_process_names:
        return False
    if normalized_child not in browser_internal_child_names:
        return False
    if normalized_child not in {normalized_parent, "identity_helper.exe"}:
        return False
    return _is_program_files_path(child_path)


def _process_badges_and_risk(node: dict) -> tuple[int, list[str], list[str]]:
    process_name = str(node.get("name") or "").lower()
    command_line = str(node.get("command_line") or "").lower()
    process_path = str(node.get("path") or "")
    reasons: list[str] = []
    badges: list[str] = []
    score = int(node.get("risk_score") or 0)

    if "powershell" in process_name:
        badges.append("powershell")
    if any(name in process_name for name in ("powershell.exe", "pwsh.exe")) and "-encodedcommand" in command_line or " -enc " in command_line:
        badges.append("encoded_command")
        reasons.append("Process uses encoded PowerShell")
        score = max(score, 95)
    if "executionpolicy bypass" in command_line or " -ep bypass" in command_line:
        reasons.append("Process uses execution policy bypass")
        score = max(score, 90)
    if "windowstyle hidden" in command_line or " -w hidden" in command_line:
        reasons.append("Process hidden window")
        score = max(score, 90)
    if any(name in process_name for name in ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")):
        badges.append("lolbin")
    reasons.extend(_path_bucket_reason(process_path))
    if "\\startup\\" in process_path.lower():
        reasons.append("MFT file in Startup folder")
    if _double_extension(process_path):
        reasons.append("Process has double extension")
        score = max(score, 80)
    if any(reason in {"Process from user-writable path", "Process from Temp", "Process from Downloads"} for reason in reasons):
        score = max(score, 70 if process_name.endswith((".exe", ".ps1", ".bat", ".cmd")) else 50)
    return min(score, 100), list(dict.fromkeys(reasons)), list(dict.fromkeys(badges))


def _event_path_candidates(event: dict) -> list[str]:
    values = [
        _nested_get(event, "process.path"),
        _nested_get(event, "file.path"),
        _nested_get(event, "download.target_path"),
        _nested_get(event, "bits.local_path"),
        _nested_get(event, "detection.path"),
        _nested_get(event, "detection.resource"),
        _nested_get(event, "persistence.path"),
        _nested_get(event, "autoruns.image_path"),
    ]
    paths: list[str] = []
    for value in values:
        normalized = normalize_windows_path_for_classification(str(value or "").strip())
        if normalized:
            paths.append(normalized.lower())
    return list(dict.fromkeys(paths))


def _node_matches_event_path(node: dict, event: dict) -> bool:
    node_entity_id = str(node.get("id") or node.get("entity_id") or "").strip()
    event_entity_id = str(_nested_get(event, "process.entity_id") or _nested_get(event, "process.guid") or "").strip()
    if node_entity_id and event_entity_id and node_entity_id == event_entity_id:
        return True
    node_pid = _safe_intish(node.get("pid"))
    event_pid = _safe_intish(_nested_get(event, "process.pid"))
    node_host = str(node.get("host") or "").strip().lower()
    event_host = str(_nested_get(event, "host.name") or "").strip().lower()
    if node_pid is not None and event_pid is not None and node_pid == event_pid and (not node_host or not event_host or node_host == event_host):
        return True
    node_path = normalize_windows_path_for_classification(str(node.get("path") or "").strip())
    if node_path and node_path.lower() in _event_path_candidates(event):
        return True
    node_name = str(node.get("name") or "").lower()
    event_process_name = str(_nested_get(event, "process.name") or "").lower()
    return bool(node_name and event_process_name and node_name == event_process_name)


def _activity_node_payload(event: dict) -> dict | None:
    event_type = str(_nested_get(event, "event.type") or "")
    event_id = str(event.get("id") or event.get("event_id") or "")
    if not event_id:
        return None
    if event_type in {"sysmon_network_connection"}:
        label = f"{_nested_get(event, 'destination.ip') or _nested_get(event, 'destination.hostname') or '?'}:{_nested_get(event, 'destination.port') or '?'}"
        badge = "network_activity"
    elif event_type in {"sysmon_dns_query"}:
        label = str(_nested_get(event, "dns.question.name") or _nested_get(event, "dns.query") or "DNS query")
        badge = "dns_activity"
    elif event_type in {"sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted"}:
        label = str(_nested_get(event, "file.path") or _nested_get(event, "target.filename") or "File activity")
        badge = "file_activity"
    elif event_type in {"sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed"}:
        label = str(_nested_get(event, "registry.path") or _nested_get(event, "registry.key_path") or "Registry activity")
        badge = "registry_activity"
    else:
        return None
    return {
        "id": f"activity:{event_id}",
        "pid": _safe_intish(_nested_get(event, "process.pid")),
        "name": label,
        "path": None,
        "command_line": str(_nested_get(event, "event.message") or label),
        "user": _nested_get(event, "user.name"),
        "sid": _nested_get(event, "user.sid"),
        "host": _nested_get(event, "host.name"),
        "first_seen": event.get("@timestamp"),
        "last_seen": event.get("@timestamp"),
        "source_events": [event_id],
        "risk_score": int(event.get("risk_score") or 0),
        "risk_reasons": list(event.get("suspicious_reasons") or []),
        "badges": [badge],
        "data_quality": list(event.get("data_quality") or []),
        "confidence": "high",
        "node_type": "activity",
    }


def _activity_edge_type(event: dict) -> str:
    event_type = str(_nested_get(event, "event.type") or "")
    if event_type == "sysmon_network_connection":
        return "network_activity"
    if event_type == "sysmon_dns_query":
        return "dns_activity"
    if event_type in {"sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted"}:
        return "file_activity"
    if event_type in {"sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed"}:
        return "registry_activity"
    if event_type in {"sysmon_image_loaded"}:
        return "image_load"
    if event_type in {"sysmon_process_access"}:
        return "process_access"
    if event_type in {"sysmon_create_remote_thread"}:
        return "remote_thread"
    return "activity"


def _activity_group_from_edge(edge_type: str) -> str:
    return {
        "network_activity": "network",
        "dns_activity": "dns",
        "file_activity": "file",
        "registry_activity": "registry",
        "image_load": "image_load",
        "process_access": "process_access",
        "remote_thread": "remote_thread",
    }.get(edge_type, "other")


def _build_process_graph(events: list[dict], case_id: str, evidence_id: str | None, scope: str) -> dict:
    process_events = [event for event in events if _is_process_start_event(event)]
    nodes_by_id: dict[str, dict] = {}
    edges: list[dict] = []
    host_pid_index: dict[tuple[str, int], list[dict]] = defaultdict(list)
    warning_samples: list[str] = []
    warning_counts: Counter[str] = Counter()

    def _record_warning(kind: str, message: str) -> None:
        warning_counts[kind] += 1
        if len(warning_samples) < 10:
            warning_samples.append(message)

    def _parent_fields(node: dict) -> dict:
        return {
            "parent_entity_id": node.get("parent_entity_id"),
            "parent_pid": node.get("parent_pid"),
            "parent_name": node.get("parent_name"),
            "host": node.get("host"),
            "first_seen": node.get("first_seen"),
        }

    def _set_parent_status(node: dict, status: str, reason: str, *, confidence: str = "none") -> None:
        node["parent_link_status"] = status
        node["parent_link_reason"] = reason
        node["parent_link_confidence"] = confidence
        node["parent_fields"] = _parent_fields(node)

    for event in process_events:
        process = event.get("process") or {}
        node_id = str(process.get("entity_id") or event.get("event_id") or event.get("id") or "")
        if not node_id:
            continue
        timestamp = event.get("@timestamp")
        host = str(_nested_get(event, "host.name") or _nested_get(event, "windows.computer") or "")
        event_refs = list(
            dict.fromkeys(
                str(event.get(key) or "").strip()
                for key in ("search_doc_id", "opensearch_id", "id", "event_id", "stable_event_id")
                if str(event.get(key) or "").strip()
            )
        )
        event_ref = event_refs[0] if event_refs else ""
        node = nodes_by_id.setdefault(
            node_id,
            {
                "id": node_id,
                "pid": _safe_intish(process.get("pid")),
                "name": process.get("name"),
                "path": process.get("path"),
                "command_line": process.get("command_line"),
                "user": _nested_get(event, "user.name"),
                "sid": _nested_get(event, "user.sid"),
                "host": host or None,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "source_type": _nested_get(event, "event.type") or _nested_get(event, "artifact.parser") or None,
                "source_event_id": event_ref or None,
                "source_events": [],
                "risk_score": 0,
                "risk_reasons": [],
                "badges": [],
                "data_quality": list(event.get("data_quality") or []),
                "confidence": "high" if process.get("entity_id") else "medium",
                "parent_entity_id": process.get("parent_entity_id"),
                "parent_pid": _safe_intish(process.get("parent_pid") or process.get("ppid")),
                "parent_name": process.get("parent_name"),
                "parent_link_status": "pending",
                "parent_link_reason": "Parent link has not been evaluated yet.",
                "parent_link_confidence": "none",
                "parent_fields": {},
            },
        )
        node["pid"] = node.get("pid") or _safe_intish(process.get("pid"))
        node["path"] = node.get("path") or process.get("path")
        node["command_line"] = node.get("command_line") or process.get("command_line")
        node["user"] = node.get("user") or _nested_get(event, "user.name")
        node["sid"] = node.get("sid") or _nested_get(event, "user.sid")
        node["host"] = node.get("host") or (host or None)
        node["parent_entity_id"] = node.get("parent_entity_id") or process.get("parent_entity_id")
        node["parent_pid"] = node.get("parent_pid") or _safe_intish(process.get("parent_pid") or process.get("ppid"))
        node["parent_name"] = node.get("parent_name") or process.get("parent_name")
        node["parent_fields"] = _parent_fields(node)
        if timestamp and (not node.get("first_seen") or str(timestamp) < str(node.get("first_seen"))):
            node["first_seen"] = timestamp
        if timestamp and (not node.get("last_seen") or str(timestamp) > str(node.get("last_seen"))):
            node["last_seen"] = timestamp
        for event_ref in event_refs:
            if event_ref and event_ref not in node["source_events"]:
                node["source_events"].append(event_ref)
        node["source_event_id"] = node.get("source_event_id") or event_ref or None
        node["source_type"] = node.get("source_type") or _nested_get(event, "event.type") or _nested_get(event, "artifact.parser") or None
        if node.get("host") and node.get("pid") is not None:
            host_pid_index[(str(node["host"]).lower(), int(node["pid"]))].append({"id": node_id, "ts": _safe_parse_dt(timestamp), "event": event})

    def _refine_pid_candidates(
        candidates: list[dict],
        *,
        parent_name: str | None,
    ) -> list[dict]:
        if len(candidates) <= 1:
            return candidates
        normalized_parent_name = str(parent_name or "").strip().lower()
        if not normalized_parent_name:
            return candidates
        name_matched = [
            candidate
            for candidate in candidates
            if str((nodes_by_id.get(str(candidate.get("id"))) or {}).get("name") or "").strip().lower() == normalized_parent_name
        ]
        return name_matched or candidates

    for node_id, node in nodes_by_id.items():
        parent_id = str(node.get("parent_entity_id") or "")
        if parent_id and parent_id in nodes_by_id and parent_id != node_id:
            _set_parent_status(node, "linked", "Linked exactly by Sysmon ProcessGuid / ParentProcessGuid.", confidence="high")
            edges.append(
                {
                    "source": parent_id,
                    "target": node_id,
                    "type": "spawned",
                    "confidence": "high",
                    "source_event_id": node.get("source_events", [None])[0],
                    "reason": "sysmon_parent_process_guid",
                }
            )
            continue
        parent_pid = node.get("parent_pid")
        host = str(node.get("host") or "").lower()
        child_ts = _safe_parse_dt(node.get("first_seen"))
        parent_name = str(node.get("parent_name") or "").strip().lower() or None
        if not parent_pid or not host or not child_ts:
            missing_parts = []
            if not parent_id and not parent_pid:
                missing_parts.append("parent PID/GUID")
            if not host:
                missing_parts.append("host")
            if not child_ts:
                missing_parts.append("timestamp")
            if missing_parts:
                reason = f"Parent fields missing: {', '.join(missing_parts)}."
                status = "parent_fields_missing"
                quality = "parent_fields_missing"
            else:
                reason = "Parent event could not be searched because required context is unavailable."
                status = "parent_not_found"
                quality = "parent_not_found"
            _set_parent_status(node, status, reason)
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {quality, "process_graph_orphan"})
            continue
        candidates = []
        for candidate_ref in host_pid_index.get((host, int(parent_pid)), []):
            if candidate_ref.get("id") == node_id:
                continue
            candidate_ts = candidate_ref.get("ts")
            if not candidate_ts or candidate_ts >= child_ts:
                continue
            if (child_ts - candidate_ts).total_seconds() > 86400:
                continue
            candidates.append({"id": candidate_ref.get("id"), "ts": candidate_ts})
        candidates = _refine_pid_candidates(candidates, parent_name=parent_name)
        if not candidates and parent_name:
            for candidate_node in nodes_by_id.values():
                if candidate_node.get("id") == node_id:
                    continue
                candidate_host = str(candidate_node.get("host") or "").lower()
                if host and candidate_host and candidate_host != host:
                    continue
                if str(candidate_node.get("name") or "").strip().lower() != parent_name:
                    continue
                candidate_ts = _safe_parse_dt(candidate_node.get("first_seen"))
                if not candidate_ts or candidate_ts >= child_ts:
                    continue
                if (child_ts - candidate_ts).total_seconds() > 86400:
                    continue
                candidates.append({"id": candidate_node.get("id"), "ts": candidate_ts})
        if not candidates:
            relaxed_candidates = []
            for candidate_ref in host_pid_index.get((host, int(parent_pid)), []):
                if candidate_ref.get("id") == node_id:
                    continue
                relaxed_candidates.append({"id": candidate_ref.get("id"), "ts": candidate_ref.get("ts")})
            relaxed_candidates = _refine_pid_candidates(relaxed_candidates, parent_name=parent_name)
            if len(relaxed_candidates) == 1:
                candidates = relaxed_candidates
            elif len(relaxed_candidates) > 1:
                _set_parent_status(node, "parent_pid_reused_ambiguous", "Multiple parent candidates matched the same PID; edge omitted to avoid a false parent.", confidence="low")
                node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"possible_pid_reuse", "process_graph_orphan"})
                _record_warning("ambiguous_relaxed_parent_candidates", f"Ambiguous relaxed parent candidates for node {node_id}")
                continue
        if len(candidates) == 1:
            candidate = candidates[0]
            candidate_ts = candidate.get("ts")
            child_delta_seconds = None
            if child_ts and candidate_ts:
                child_delta_seconds = abs((child_ts - candidate_ts).total_seconds())
            reason = "Linked by parent PID and timestamp proximity."
            confidence = "medium"
            if child_delta_seconds is None or child_delta_seconds > 86400:
                reason = "Linked by relaxed parent PID/name inference; parent may be outside the selected time window."
                confidence = "low"
                node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_outside_time_window"})
            _set_parent_status(node, "linked", reason, confidence=confidence)
            edges.append(
                {
                    "source": candidate["id"],
                    "target": node_id,
                    "type": "spawned",
                    "confidence": confidence,
                    "source_event_id": node.get("source_events", [None])[0],
                    "reason": "security_4688_parent_pid_inferred",
                }
            )
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_inferred_by_pid"})
            node["confidence"] = confidence
        elif len(candidates) > 1:
            _set_parent_status(node, "parent_pid_reused_ambiguous", "Multiple parent candidates matched PID/time constraints; edge omitted to avoid a false parent.", confidence="low")
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"possible_pid_reuse", "process_graph_orphan"})
            _record_warning("ambiguous_parent_candidates", f"Ambiguous parent candidates for node {node_id}")
        else:
            _set_parent_status(node, "parent_not_found", "Parent PID/name was present, but no earlier matching parent event was found in the graph context.")
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_not_found", "process_graph_orphan"})

    edge_targets = {edge["target"] for edge in edges}
    for node_id, node in nodes_by_id.items():
        score, reasons, badges = _process_badges_and_risk(node)
        node["risk_score"] = max(int(node.get("risk_score") or 0), score)
        node["risk_reasons"] = list(dict.fromkeys(list(node.get("risk_reasons") or []) + reasons))
        node["badges"] = list(dict.fromkeys(list(node.get("badges") or []) + badges))
        parent_name = str(node.get("parent_name") or "").lower()
        child_name = str(node.get("name") or "").lower()
        if parent_name in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} and child_name in {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            node["risk_score"] = max(int(node["risk_score"]), 90)
            node["risk_reasons"] = list(dict.fromkeys(list(node["risk_reasons"]) + ["Office spawned script interpreter"]))
            node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["office_child", "suspicious_chain"]))
        if parent_name in {"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe"} and child_name.endswith((".exe", ".ps1", ".bat", ".cmd")):
            if _is_browser_internal_child(parent_name, child_name, node.get("path")):
                node["risk_score"] = min(int(node.get("risk_score") or 0), 20)
                node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["browser_internal_child", "low_noise_process"]))
                node["data_quality"] = list(dict.fromkeys(list(node.get("data_quality") or []) + ["noisy_browser_child"]))
            else:
                node["risk_score"] = max(int(node["risk_score"]), 85)
                node["risk_reasons"] = list(dict.fromkeys(list(node["risk_reasons"]) + ["Browser spawned executable"]))
                node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["browser_child", "suspicious_chain"]))
        if node_id not in edge_targets:
            continue

    activity_counts_by_node: Counter[str] = Counter()
    for event in events:
        if _is_process_start_event(event):
            continue
        artifact_type = str(_nested_get(event, "artifact.type") or "")
        event_type = str(_nested_get(event, "event.type") or "")
        for node in list(nodes_by_id.values()):
            if not _node_matches_event_path(node, event):
                continue
            activity_payload = _activity_node_payload(event)
            if activity_payload and activity_counts_by_node[str(node.get("id"))] < 25:
                activity_id = str(activity_payload["id"])
                if activity_id not in nodes_by_id:
                    nodes_by_id[activity_id] = activity_payload
                edge_id = f"activity:{node.get('id')}->{activity_id}"
                if not any(edge.get("id") == edge_id for edge in edges):
                    activity_type = _activity_edge_type(event)
                    edges.append(
                        {
                            "id": edge_id,
                            "source": str(node.get("id")),
                            "target": activity_id,
                            "type": activity_type,
                            "confidence": "high",
                            "source_event_id": str(event.get("id") or event.get("event_id") or ""),
                            "timestamp": event.get("@timestamp"),
                            "reason": event_type or "process_activity",
                            "summary": str(_nested_get(event, "event.message") or activity_payload.get("name") or event_type or activity_type),
                            "weight": 1,
                            "risk": int(event.get("risk_score") or activity_payload.get("risk_score") or 0),
                        }
                    )
                activity_counts_by_node[str(node.get("id"))] += 1
            reasons = list(node.get("risk_reasons") or [])
            badges = list(node.get("badges") or [])
            score = int(node.get("risk_score") or 0)
            if artifact_type == "browser" and event_type == "file_downloaded":
                reasons.append("Process associated with browser download")
                badges.append("browser_download")
                score = max(score, 85)
            elif artifact_type == "bits":
                reasons.append("Process associated with BITS download")
                badges.append("bits_download")
                score = max(score, 80)
            elif artifact_type == "detection":
                reasons.append("Process associated with Defender detection")
                badges.append("defender_detection")
                score = max(score, 85)
            elif artifact_type == "dns" and event.get("suspicious_reasons"):
                reasons.append("Process has suspicious DNS activity")
                badges.append("dns_activity")
                score = max(score, 70)
            elif artifact_type == "srum" and int(_nested_get(event, "srum.bytes_sent") or 0) >= 50_000_000:
                reasons.append("Process has high SRUM outbound bytes")
                badges.append("network_activity")
                score = max(score, 75)
            elif artifact_type == "autorun":
                reasons.append("Autorun process observed")
                badges.append("autorun")
                score = max(score, 75)
            node["risk_reasons"] = list(dict.fromkeys(reasons))
            node["badges"] = list(dict.fromkeys(badges))
            node["risk_score"] = min(score, 100)

    root_nodes_count = sum(1 for node in nodes_by_id.values() if all(edge["target"] != node["id"] for edge in edges))
    high_risk_nodes_count = sum(1 for node in nodes_by_id.values() if int(node.get("risk_score") or 0) >= 70)
    suspicious_chains_count = sum(1 for edge in edges if "suspicious_chain" in (nodes_by_id.get(edge["target"], {}).get("badges") or []))
    orphan_nodes_count = sum(1 for node in nodes_by_id.values() if "process_graph_orphan" in (node.get("data_quality") or []))
    data_quality_counts: Counter[str] = Counter()
    for node in nodes_by_id.values():
        for quality in node.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1

    orphan_diagnostics = [
        {
            "id": node.get("id"),
            "process_name": node.get("name"),
            "pid": node.get("pid"),
            "timestamp": node.get("first_seen"),
            "command_line": node.get("command_line"),
            "parent_fields": node.get("parent_fields") or _parent_fields(node),
            "parent_link_status": node.get("parent_link_status") or "parent_not_found",
            "parent_link_reason": node.get("parent_link_reason") or "Parent could not be linked.",
            "parent_link_confidence": node.get("parent_link_confidence") or "none",
        }
        for node in nodes_by_id.values()
        if "process_graph_orphan" in (node.get("data_quality") or [])
    ]
    orphan_status_counts = Counter(str(item.get("parent_link_status") or "parent_not_found") for item in orphan_diagnostics)

    warnings_summary = {
        "ambiguous_parent_candidates": int(warning_counts.get("ambiguous_parent_candidates") or 0),
        "ambiguous_relaxed_parent_candidates": int(warning_counts.get("ambiguous_relaxed_parent_candidates") or 0),
        "parent_not_found": int(data_quality_counts.get("parent_not_found") or 0),
        "parent_fields_missing": int(data_quality_counts.get("parent_fields_missing") or 0),
        "possible_pid_reuse": int(data_quality_counts.get("possible_pid_reuse") or 0),
        "process_graph_orphan": int(data_quality_counts.get("process_graph_orphan") or 0),
    }
    warnings: list[str] = []
    if warnings_summary["ambiguous_parent_candidates"]:
        warnings.append(
            f"{warnings_summary['ambiguous_parent_candidates']} ambiguous parent candidates. Some edges were omitted to avoid incorrect parent-child links."
        )
    if warnings_summary["ambiguous_relaxed_parent_candidates"]:
        warnings.append(
            f"{warnings_summary['ambiguous_relaxed_parent_candidates']} relaxed parent candidates remained ambiguous after inference."
        )
    if warnings_summary["parent_not_found"]:
        warnings.append(f"{warnings_summary['parent_not_found']} nodes could not be linked to a parent.")
    if warnings_summary["possible_pid_reuse"]:
        warnings.append(f"{warnings_summary['possible_pid_reuse']} nodes were marked with possible PID reuse.")
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scope": scope,
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "summary": {
            "nodes_count": len(nodes_by_id),
            "edges_count": len(edges),
            "root_nodes_count": root_nodes_count,
            "high_risk_nodes_count": high_risk_nodes_count,
            "suspicious_chains_count": suspicious_chains_count,
            "orphan_nodes_count": orphan_nodes_count,
            "warnings": warnings,
            "warnings_summary": warnings_summary,
            "warnings_samples": warning_samples,
            "orphan_diagnostics": orphan_diagnostics[:50],
            "orphan_status_counts": dict(orphan_status_counts),
        },
    }


def _build_process_tree_report(graph: dict, events: list[dict], *, selected_scope: str) -> dict:
    process_events = [event for event in events if _is_process_start_event(event)]
    nodes = {str(node.get("id")): node for node in graph.get("nodes", [])}
    node_counter = Counter(str(node.get("name") or "unknown").lower() for node in nodes.values())
    pair_counter = Counter(
        f"{str((nodes.get(str(edge.get('source'))) or {}).get('name') or 'unknown')} -> {str((nodes.get(str(edge.get('target'))) or {}).get('name') or 'unknown')}"
        for edge in graph.get("edges", [])
    )
    badge_counter = Counter(badge for node in graph.get("nodes", []) for badge in (node.get("badges") or []))
    user_counter = Counter(str(node.get("user") or "unknown") for node in graph.get("nodes", []))
    host_counter = Counter(str(node.get("host") or "unknown") for node in graph.get("nodes", []))
    warnings = list(graph.get("summary", {}).get("warnings") or [])
    sample_chains = _build_process_tree_sample_chains(graph)
    return {
        "selected_scope": selected_scope,
        "process_events_found": len(process_events),
        "sysmon_process_create_count": sum(1 for event in process_events if str(_nested_get(event, "artifact.parser") or "") == "sysmon_evtx"),
        "security_4688_count": sum(1 for event in process_events if str(_nested_get(event, "artifact.parser") or "") == "security_4688" or int(_nested_get(event, "windows.event_id") or 0) == 4688),
        "powershell_enriched_count": sum(1 for node in graph.get("nodes", []) if "powershell" in (node.get("badges") or [])),
        "nodes_count": graph.get("summary", {}).get("nodes_count", 0),
        "edges_count": graph.get("summary", {}).get("edges_count", 0),
        "orphan_nodes_count": graph.get("summary", {}).get("orphan_nodes_count", 0),
        "high_risk_nodes_count": graph.get("summary", {}).get("high_risk_nodes_count", 0),
        "suspicious_chain_count": graph.get("summary", {}).get("suspicious_chains_count", 0),
        "by_process_name": dict(node_counter.most_common(20)),
        "by_parent_child_pair": dict(pair_counter.most_common(20)),
        "by_user": dict(user_counter.most_common(20)),
        "by_host": dict(host_counter.most_common(20)),
        "by_badge": dict(badge_counter.most_common(20)),
        "parser_errors": [],
        "warnings": warnings,
        "sample_chains": sample_chains[:10],
    }


def _build_process_tree_sample_chains(graph: dict) -> list[dict]:
    nodes = {str(node.get("id")): node for node in graph.get("nodes", [])}
    chains: list[dict] = []
    for edge in graph.get("edges", []):
        parent = nodes.get(str(edge.get("source")))
        child = nodes.get(str(edge.get("target")))
        if not parent or not child:
            continue
        if "browser_internal_child" in (child.get("badges") or []) and int(child.get("risk_score") or 0) < 70:
            continue
        if not child.get("risk_reasons") and not child.get("badges"):
            continue
        chains.append(
            {
                "chain": [
                    {
                        "id": parent.get("id"),
                        "name": parent.get("name"),
                        "path": parent.get("path"),
                        "command_line": parent.get("command_line"),
                        "risk_score": parent.get("risk_score"),
                        "badges": parent.get("badges") or [],
                    },
                    {
                        "id": child.get("id"),
                        "name": child.get("name"),
                        "path": child.get("path"),
                        "command_line": child.get("command_line"),
                        "risk_score": child.get("risk_score"),
                        "badges": child.get("badges") or [],
                    },
                ],
                "edge": edge,
                "reasons": child.get("risk_reasons") or [],
            }
        )
    chains.sort(key=lambda item: int(item["chain"][-1].get("risk_score") or 0), reverse=True)
    return chains[:10]


def _filter_process_graph(graph: dict, *, pid: int | None = None, process_name: str | None = None, entity_id: str | None = None) -> dict:
    if pid is None and not process_name and not entity_id:
        return graph

    process_name_lower = (process_name or "").strip().lower()
    focus_ids = {
        str(node.get("id"))
        for node in graph.get("nodes", [])
        if (
            (entity_id and str(node.get("id") or "") == entity_id)
            or (pid is not None and _safe_intish(node.get("pid")) == int(pid))
            or (process_name_lower and process_name_lower in str(node.get("name") or "").lower())
        )
    }
    if not focus_ids:
        return {
            **graph,
            "nodes": [],
            "edges": [],
            "summary": {
                **(graph.get("summary") or {}),
                "nodes_count": 0,
                "edges_count": 0,
                "root_nodes_count": 0,
                "high_risk_nodes_count": 0,
                "suspicious_chains_count": 0,
                "orphan_nodes_count": 0,
                "warnings": sorted(set(list((graph.get("summary") or {}).get("warnings") or []) + ["No process graph nodes matched the selected focus filter."])),
                "warnings_summary": dict((graph.get("summary") or {}).get("warnings_summary") or {}),
                "warnings_samples": list((graph.get("summary") or {}).get("warnings_samples") or []),
            },
        }

    related_ids = set(focus_ids)
    pending = list(focus_ids)
    edges = graph.get("edges", [])
    while pending:
        current = pending.pop()
        for edge in edges:
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source == current and target and target not in related_ids:
                related_ids.add(target)
                pending.append(target)
            if target == current and source and source not in related_ids:
                related_ids.add(source)
                pending.append(source)

    filtered_nodes = [node for node in graph.get("nodes", []) if str(node.get("id") or "") in related_ids]
    filtered_edges = [
        edge
        for edge in edges
        if str(edge.get("source") or "") in related_ids and str(edge.get("target") or "") in related_ids
    ]
    node_map = {str(node.get("id") or ""): node for node in filtered_nodes}
    edge_targets = {str(edge.get("target") or "") for edge in filtered_edges}
    summary = {
        **(graph.get("summary") or {}),
        "nodes_count": len(filtered_nodes),
        "edges_count": len(filtered_edges),
        "root_nodes_count": sum(1 for node in filtered_nodes if str(node.get("id") or "") not in edge_targets),
        "high_risk_nodes_count": sum(1 for node in filtered_nodes if int(node.get("risk_score") or 0) >= 70),
        "suspicious_chains_count": sum(1 for edge in filtered_edges if "suspicious_chain" in ((node_map.get(str(edge.get("target") or ""), {}) or {}).get("badges") or [])),
        "orphan_nodes_count": sum(1 for node in filtered_nodes if "process_graph_orphan" in (node.get("data_quality") or [])),
        "focus_node_ids": sorted(focus_ids),
    }
    filtered_ids = {str(node.get("id") or "") for node in filtered_nodes}
    summary["orphan_diagnostics"] = [
        item
        for item in list((graph.get("summary") or {}).get("orphan_diagnostics") or [])
        if str(item.get("id") or "") in filtered_ids
    ][:50]
    summary["orphan_status_counts"] = dict(Counter(str(item.get("parent_link_status") or "parent_not_found") for item in summary["orphan_diagnostics"]))
    return {
        **graph,
        "nodes": filtered_nodes,
        "edges": filtered_edges,
        "summary": summary,
    }


def _compact_process_graph(
    graph: dict,
    *,
    include_activity: bool = False,
    aggregate_activity: bool = True,
    edge_types: list[str] | None = None,
    max_nodes: int = 50,
    max_activity_per_process: int = 10,
    only_suspicious: bool = False,
    only_marked: bool = False,
) -> dict:
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    node_map = {str(node.get("id") or ""): node for node in nodes}
    activity_types = {"network_activity", "dns_activity", "file_activity", "registry_activity", "image_load", "process_access", "remote_thread", "activity"}
    requested_types = {str(item).strip() for item in (edge_types or []) if str(item).strip()}
    show_activity = include_activity or bool(requested_types & activity_types)
    process_edge_types = {"spawned", "parent_child"}
    omitted_counts: Counter[str] = Counter()
    groups_by_key: dict[tuple[str, str], dict] = {}
    activity_seen_by_source: Counter[str] = Counter()
    kept_edges: list[dict] = []

    for edge in edges:
        edge_type = str(edge.get("type") or "")
        if edge_type == "spawned":
            edge = {**edge, "type": "parent_child", "summary": edge.get("summary") or edge.get("reason") or "Parent-child process relationship", "weight": edge.get("weight") or 1}
            edge_type = "parent_child"
        if requested_types and edge_type not in requested_types:
            if edge_type in activity_types:
                omitted_counts[_activity_group_from_edge(edge_type)] += 1
            continue
        if edge_type in activity_types:
            group = _activity_group_from_edge(edge_type)
            if not show_activity:
                omitted_counts[group] += 1
                key = (str(edge.get("source") or ""), group)
                source_node = node_map.get(key[0]) or {}
                current = groups_by_key.setdefault(
                    key,
                    {
                        "id": f"activity-group:{key[0]}:{group}",
                        "source": key[0],
                        "type": f"{group}_activity_group",
                        "group": group,
                        "count": 0,
                        "samples": [],
                        "source_process": source_node.get("name") or source_node.get("path") or key[0],
                    },
                )
                current["count"] += 1
                if len(current["samples"]) < 5:
                    current["samples"].append(
                        {
                            "target": edge.get("target"),
                            "timestamp": edge.get("timestamp"),
                            "summary": edge.get("summary") or edge.get("reason"),
                            "source_event_id": edge.get("source_event_id"),
                        }
                    )
                continue
            source = str(edge.get("source") or "")
            activity_seen_by_source[source] += 1
            if activity_seen_by_source[source] > max_activity_per_process:
                omitted_counts[group] += 1
                continue
        elif edge_type not in process_edge_types and requested_types:
            continue
        kept_edges.append(edge)

    kept_ids = {str(edge.get("source") or "") for edge in kept_edges} | {str(edge.get("target") or "") for edge in kept_edges}
    if not kept_ids and not show_activity:
        kept_ids = {str(node.get("id") or "") for node in nodes if str(node.get("node_type") or "") != "activity"}
    kept_nodes = [node for node in nodes if str(node.get("id") or "") in kept_ids and (show_activity or str(node.get("node_type") or "") != "activity")]
    if only_suspicious:
        suspicious_ids = {str(node.get("id") or "") for node in kept_nodes if int(node.get("risk_score") or 0) >= 40 or node.get("risk_reasons") or node.get("badges")}
        suspicious_ids |= {str(edge.get("source") or "") for edge in kept_edges if str(edge.get("target") or "") in suspicious_ids}
        suspicious_ids |= {str(edge.get("target") or "") for edge in kept_edges if str(edge.get("source") or "") in suspicious_ids}
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in suspicious_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in suspicious_ids and str(edge.get("target") or "") in suspicious_ids]
    if only_marked:
        marked_ids = {str(node.get("id") or "") for node in kept_nodes if "marked" in (node.get("badges") or [])}
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in marked_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in marked_ids and str(edge.get("target") or "") in marked_ids]

    truncated = False
    if max_nodes > 0 and len(kept_nodes) > max_nodes:
        truncated = True
        priority = {
            str(node.get("id") or ""): (
                int(node.get("risk_score") or 0),
                len(node.get("source_events") or []),
                0 if str(node.get("node_type") or "") == "activity" else 1,
            )
            for node in kept_nodes
        }
        selected_ids = {
            node_id
            for node_id, _score in sorted(priority.items(), key=lambda item: item[1], reverse=True)[:max_nodes]
        }
        for node in kept_nodes:
            node_id = str(node.get("id") or "")
            if node_id not in selected_ids and str(node.get("node_type") or "") == "activity":
                omitted_counts["activity"] += 1
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in selected_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in selected_ids and str(edge.get("target") or "") in selected_ids]

    edge_targets = {str(edge.get("target") or "") for edge in kept_edges}
    kept_node_ids = {str(node.get("id") or "") for node in kept_nodes}
    orphan_diagnostics = [
        item
        for item in list((graph.get("summary") or {}).get("orphan_diagnostics") or [])
        if str(item.get("id") or "") in kept_node_ids
    ][:50]
    summary = {
        **(graph.get("summary") or {}),
        "nodes_count": len(kept_nodes),
        "edges_count": len(kept_edges),
        "root_nodes_count": sum(1 for node in kept_nodes if str(node.get("id") or "") not in edge_targets),
        "high_risk_nodes_count": sum(1 for node in kept_nodes if int(node.get("risk_score") or 0) >= 70),
        "orphan_nodes_count": sum(1 for node in kept_nodes if "process_graph_orphan" in (node.get("data_quality") or [])),
        "truncated": truncated,
        "node_cap": max_nodes,
        "activity_collapsed": not show_activity and aggregate_activity,
        "omitted_counts": dict(omitted_counts),
        "activity_groups_count": len(groups_by_key),
        "orphan_diagnostics": orphan_diagnostics,
        "orphan_status_counts": dict(Counter(str(item.get("parent_link_status") or "parent_not_found") for item in orphan_diagnostics)),
    }
    warnings = list(summary.get("warnings") or [])
    if truncated:
        warnings.append(f"Graph limited to {max_nodes} nodes. Increase Max nodes or narrow the focus.")
    summary["warnings"] = sorted(set(warnings))
    return {
        **graph,
        "nodes": kept_nodes,
        "edges": kept_edges,
        "groups": list(groups_by_key.values()),
        "omitted_counts": dict(omitted_counts),
        "truncated": truncated,
        "summary": summary,
    }


def _process_focus_filter(*, pid: int | None = None, process_name: str | None = None, entity_id: str | None = None) -> dict | None:
    should: list[dict] = []
    if entity_id:
        should.extend(
            [
                {"term": {"process.entity_id": entity_id}},
                {"term": {"process.guid": entity_id}},
                {"term": {"process.parent.entity_id": entity_id}},
                {"term": {"process.parent.guid": entity_id}},
                {"term": {"parent.process.entity_id": entity_id}},
                {"term": {"parent.process.guid": entity_id}},
            ]
        )
    if pid is not None:
        pid_value = str(pid)
        should.extend(
            [
                {"term": {"process.pid": pid_value}},
                {"term": {"process.parent_pid": pid_value}},
                {"term": {"process.parent.pid": pid_value}},
                {"term": {"parent.process.pid": pid_value}},
            ]
        )
    process_name_value = str(process_name or "").strip()
    if process_name_value:
        wildcard_value = f"*{process_name_value.replace('*', '').replace('?', '')}*"
        for field in (
            "process.name",
            "process.executable",
            "process.path",
            "process.command_line",
            "process.parent.name",
            "process.parent.executable",
            "process.parent.path",
            "process.parent.command_line",
            "parent.process.name",
            "parent.process.executable",
            "parent.process.path",
            "parent.process.command_line",
        ):
            should.append({"wildcard": {field: {"value": wildcard_value, "case_insensitive": True}}})
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _process_start_filter() -> dict:
    return {
        "bool": {
            "should": [
                {"terms": {"event.type": ["process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"]}},
                {"term": {"artifact.type": "process"}},
            ],
            "minimum_should_match": 1,
        }
    }


def _process_activity_filter() -> dict:
    return {
        "bool": {
            "should": [
                {"terms": {"artifact.type": ["browser", "bits", "dns", "srum", "detection", "autorun"]}},
                {
                    "terms": {
                        "event.type": [
                            "sysmon_network_connection",
                            "sysmon_file_created",
                            "sysmon_file_create_stream_hash",
                            "sysmon_file_deleted",
                            "sysmon_registry_key_event",
                            "sysmon_registry_value_set",
                            "sysmon_registry_key_renamed",
                            "sysmon_dns_query",
                            "sysmon_image_loaded",
                            "sysmon_process_access",
                            "sysmon_create_remote_thread",
                            "object_access",
                            "object_access_attempted",
                            "file_access",
                        ]
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def _time_window_filter(timestamp: str | None, before_seconds: int | None, after_seconds: int | None) -> dict | None:
    anchor = _safe_parse_dt(timestamp)
    if not anchor:
        return None
    before = max(int(before_seconds or 0), 0)
    after = max(int(after_seconds or 0), 0)
    if before <= 0 and after <= 0:
        return None
    start = anchor - timedelta(seconds=before)
    end = anchor + timedelta(seconds=after)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}


def _identity_filter(*, entity_ids: set[str] | None = None, pids: set[int] | None = None, process_name: str | None = None) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in (entity_ids or set()) if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.entity_id": clean_entity_ids}},
                {"terms": {"process.guid": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in (pids or set()) if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.pid": pid_values}},
                {"terms": {"process.pid": clean_pids}},
            ]
        )
    name = str(process_name or "").strip()
    if name:
        wildcard_value = f"*{name.replace('*', '').replace('?', '')}*"
        should.extend(
            [
                {"wildcard": {"process.name": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.executable": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.path": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.command_line": {"value": wildcard_value, "case_insensitive": True}}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _source_event_filter(source_event_id: str | None) -> dict | None:
    value = str(source_event_id or "").strip()
    if not value:
        return None
    return {
        "bool": {
            "should": [
                {"ids": {"values": [value]}},
                {"term": {"id": value}},
                {"term": {"event_id": value}},
                {"term": {"stable_event_id": value}},
                {"term": {"search_doc_id": value}},
                {"term": {"opensearch_id": value}},
            ],
            "minimum_should_match": 1,
        }
    }


_EXECUTION_STORY_LIGHT_CACHE: dict[str, tuple[datetime, dict[str, Any]]] = {}
_EXECUTION_STORY_LIGHT_CACHE_SECONDS = 300


def _execution_story_cache_key(case_id: str, *, source_event_id: str | None, scope: str, evidence_id: str | None) -> str:
    return "|".join([case_id, scope, str(evidence_id or ""), str(source_event_id or "")])


def _execution_story_cache_get(key: str) -> dict[str, Any] | None:
    cached = _EXECUTION_STORY_LIGHT_CACHE.get(key)
    if not cached:
        return None
    created, payload = cached
    if (datetime.now(UTC) - created).total_seconds() > _EXECUTION_STORY_LIGHT_CACHE_SECONDS:
        _EXECUTION_STORY_LIGHT_CACHE.pop(key, None)
        return None
    response = dict(payload)
    quality = dict(response.get("quality") or {})
    quality["cache"] = {"hit": True, "ttl_seconds": _EXECUTION_STORY_LIGHT_CACHE_SECONDS}
    response["quality"] = quality
    return response


def _execution_story_cache_put(key: str, payload: dict[str, Any]) -> dict[str, Any]:
    quality = dict(payload.get("quality") or {})
    quality["cache"] = {"hit": False, "ttl_seconds": _EXECUTION_STORY_LIGHT_CACHE_SECONDS}
    payload = {**payload, "quality": quality}
    _EXECUTION_STORY_LIGHT_CACHE[key] = (datetime.now(UTC), payload)
    return payload


def _child_process_filter(*, parent_entity_ids: set[str], parent_pids: set[int]) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in parent_entity_ids if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.parent_entity_id": clean_entity_ids}},
                {"terms": {"process.parent.guid": clean_entity_ids}},
                {"terms": {"process.parent.entity_id": clean_entity_ids}},
                {"terms": {"parent.process.guid": clean_entity_ids}},
                {"terms": {"parent.process.entity_id": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in parent_pids if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.parent_pid": pid_values}},
                {"terms": {"process.parent.pid": pid_values}},
                {"terms": {"parent.process.pid": pid_values}},
                {"terms": {"process.parent_pid": clean_pids}},
                {"terms": {"process.parent.pid": clean_pids}},
                {"terms": {"parent.process.pid": clean_pids}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _activity_identity_filter(*, entity_ids: set[str], pids: set[int], process_name: str | None = None) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in entity_ids if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.entity_id": clean_entity_ids}},
                {"terms": {"process.guid": clean_entity_ids}},
                {"terms": {"process.parent_entity_id": clean_entity_ids}},
                {"terms": {"process.parent.guid": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in pids if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.pid": pid_values}},
                {"terms": {"process.pid": clean_pids}},
            ]
        )
    name = str(process_name or "").strip()
    if name:
        wildcard_value = f"*{name.replace('*', '').replace('?', '')}*"
        should.extend(
            [
                {"wildcard": {"process.name": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.executable": {"value": wildcard_value, "case_insensitive": True}}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _dedupe_events(events: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[str] = set()
    for event in events:
        event_id = str(event.get("id") or event.get("event_id") or "")
        if event_id and event_id in seen:
            continue
        if event_id:
            seen.add(event_id)
        deduped.append(event)
    return deduped


def _host_focus_filter(host: str | None) -> dict | None:
    normalized = normalize_host_alias(host)
    if not normalized:
        return None
    aliases = {normalized}
    if "." in normalized:
        aliases.add(normalized.split(".", 1)[0])
    should: list[dict] = []
    for alias in sorted(aliases):
        should.extend(
            [
                {"term": {"host.name": alias}},
                {"term": {"host.canonical": alias}},
                {"wildcard": {"host.name": {"value": f"{alias}.*", "case_insensitive": True}}},
                {"wildcard": {"host.canonical": {"value": f"{alias}.*", "case_insensitive": True}}},
            ]
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def build_process_tree_bundle(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    pid: int | None = None,
    process_name: str | None = None,
    entity_id: str | None = None,
    host: str | None = None,
    include_activity: bool = False,
    aggregate_activity: bool = True,
    edge_types: list[str] | None = None,
    max_nodes: int = 50,
    max_activity_per_process: int = 10,
    only_suspicious: bool = False,
    only_marked: bool = False,
) -> dict:
    request = DebugExportRequest(
        scope=scope,
        evidence_id=evidence_id,
        include_raw_samples=False,
        include_raw_xml=False,
        max_events_per_type=250,
    )
    context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
    base_process_filters = [
        {
            "bool": {
                "should": [
                    {"terms": {"event.type": ["process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"]}},
                    {"term": {"artifact.type": "process"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    host_filter = _host_focus_filter(host)
    if host_filter:
        base_process_filters.append(host_filter)
    process_filters = list(base_process_filters)
    focus_filter = _process_focus_filter(pid=pid, process_name=process_name, entity_id=entity_id)
    if focus_filter:
        process_filters.append(focus_filter)
    focused_query = bool(focus_filter)
    process_events, _, _ = _search_scope_events(context, size=500 if focused_query else 2000, extra_filters=process_filters)
    if focused_query:
        parent_entity_ids = sorted(
            {
                str((event.get("process") or {}).get("parent_entity_id") or "").strip()
                for event in process_events
                if str((event.get("process") or {}).get("parent_entity_id") or "").strip()
            }
        )
        if parent_entity_ids:
            parent_guid_filter = {
                "bool": {
                    "should": [
                        {"terms": {"process.entity_id": parent_entity_ids}},
                        {"terms": {"process.guid": parent_entity_ids}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            parent_guid_events, _, _ = _search_scope_events(context, size=min(max(len(parent_entity_ids) * 4, 50), 500), extra_filters=[*base_process_filters, parent_guid_filter])
            process_events = [*process_events, *parent_guid_events]
        parent_context_events, _, _ = _search_scope_events(context, size=1500, extra_filters=base_process_filters)
        process_events = [*process_events, *parent_context_events]
    enrichment_filters = [
        {
            "bool": {
                "should": [
                    {"terms": {"artifact.type": ["browser", "bits", "dns", "srum", "detection", "autorun"]}},
                    {"terms": {"event.type": ["sysmon_network_connection", "sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted", "sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed", "sysmon_dns_query"]}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if host_filter:
        enrichment_filters.append(host_filter)
    if focus_filter:
        enrichment_filters.append(focus_filter)
    enrichment_events, _, _ = _search_scope_events(
        context,
        size=500 if focused_query else 1000,
        extra_filters=enrichment_filters,
    )

    deduped_events: list[dict] = []
    seen_event_ids: set[str] = set()
    for event in [*process_events, *enrichment_events]:
        event_id_value = str(event.get("id") or event.get("event_id") or "")
        if event_id_value and event_id_value in seen_event_ids:
            continue
        if event_id_value:
            seen_event_ids.add(event_id_value)
        deduped_events.append(event)

    graph = _build_process_graph(deduped_events, case.id, evidence_id, scope)
    filtered_graph = _filter_process_graph(graph, pid=pid, process_name=process_name, entity_id=entity_id)
    compact_graph = _compact_process_graph(
        filtered_graph,
        include_activity=include_activity,
        aggregate_activity=aggregate_activity,
        edge_types=edge_types,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity_per_process,
        only_suspicious=only_suspicious,
        only_marked=only_marked,
    )
    report = _build_process_tree_report(compact_graph, deduped_events, selected_scope=scope)
    sample_chains = _build_process_tree_sample_chains(compact_graph)
    compact_graph.setdefault("summary", {})
    compact_graph["summary"]["suspicious_chains_count"] = len(sample_chains)
    return {
        "graph": compact_graph,
        "report": report,
        "sample_chains": sample_chains,
    }


def _process_identity_from_events(events: list[dict], *, entity_id: str | None, pid: int | None, process_name: str | None) -> tuple[set[str], set[int], set[str], set[int], dict | None]:
    entity_ids = {str(entity_id or "").strip()} if str(entity_id or "").strip() else set()
    pids = {int(pid)} if pid is not None else set()
    parent_entity_ids: set[str] = set()
    parent_pids: set[int] = set()
    base_event: dict | None = events[0] if events else None
    name_value = str(process_name or "").strip().lower()
    for event in events:
        process = event.get("process") or {}
        event_entity_id = str(process.get("entity_id") or process.get("guid") or "").strip()
        event_pid = _safe_intish(process.get("pid"))
        event_name = str(process.get("name") or process.get("executable") or "").strip().lower()
        if entity_id and event_entity_id and event_entity_id != str(entity_id).strip():
            continue
        if pid is not None and event_pid is not None and event_pid != int(pid):
            continue
        if name_value and event_name and name_value not in event_name and name_value not in str(process.get("command_line") or "").lower():
            continue
        if event_entity_id:
            entity_ids.add(event_entity_id)
        if event_pid is not None:
            pids.add(event_pid)
        parent_entity_id = str(process.get("parent_entity_id") or _nested_get(event, "process.parent.entity_id") or _nested_get(event, "parent.process.entity_id") or "").strip()
        if parent_entity_id:
            parent_entity_ids.add(parent_entity_id)
        parent_pid = _safe_intish(process.get("parent_pid") or process.get("ppid") or _nested_get(event, "process.parent.pid") or _nested_get(event, "parent.process.pid"))
        if parent_pid is not None:
            parent_pids.add(parent_pid)
        if base_event is None:
            base_event = event
    return entity_ids, pids, parent_entity_ids, parent_pids, base_event


def build_process_tree_expansion(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    node_id: str | None = None,
    process_guid: str | None = None,
    process_pid: int | None = None,
    process_name: str | None = None,
    timestamp: str | None = None,
    expansion_type: str = "children",
    depth: int = 1,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 50,
    max_activity: int = 25,
    edge_types: list[str] | None = None,
) -> dict:
    expansion = str(expansion_type or "children").strip().lower()
    if expansion not in {"children", "parents", "siblings", "activity", "commands"}:
        raise ValueError("expansion_type must be children, parents, siblings, activity, or commands")
    request = DebugExportRequest(
        scope=scope,
        evidence_id=evidence_id,
        include_raw_samples=False,
        include_raw_xml=False,
        max_events_per_type=250,
    )
    context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
    host_filter = _host_focus_filter(host)
    time_filter = _time_window_filter(timestamp, time_window_before, time_window_after)
    base_process_filters = [_process_start_filter()]
    if host_filter:
        base_process_filters.append(host_filter)
    if time_filter:
        base_process_filters.append(time_filter)

    identity_entity_id = process_guid or node_id
    identity_name_fallback = process_name if not identity_entity_id and process_pid is None else None
    base_identity_filter = _identity_filter(
        entity_ids={identity_entity_id} if identity_entity_id else set(),
        pids={process_pid} if process_pid is not None else set(),
        process_name=identity_name_fallback,
    )
    selected_filters = list(base_process_filters)
    if base_identity_filter:
        selected_filters.append(base_identity_filter)
    selected_events, _, _ = _search_scope_events(context, size=300, extra_filters=selected_filters)
    entity_ids, pids, parent_entity_ids, parent_pids, base_event = _process_identity_from_events(
        selected_events,
        entity_id=identity_entity_id,
        pid=process_pid,
        process_name=process_name,
    )
    if identity_entity_id:
        entity_ids.add(str(identity_entity_id).strip())
    if process_pid is not None:
        pids.add(int(process_pid))

    expansion_events: list[dict] = []
    warnings: list[str] = []
    omitted_counts: Counter[str] = Counter()
    max_nodes = min(max(int(max_nodes or 50), 1), 500)
    max_activity = min(max(int(max_activity or 25), 1), 500)
    depth = min(max(int(depth or 1), 1), 5)

    if expansion == "commands":
        return {
            "base_node": None,
            "added_nodes": [],
            "added_edges": [],
            "activity_groups": [],
            "omitted_counts": {},
            "warnings": ["Use the Command History endpoint for command expansion."],
            "command_history": {
                "process_guid": sorted(entity_ids)[0] if entity_ids else None,
                "process_pid": sorted(pids)[0] if pids else None,
                "process_name": process_name,
            },
        }

    frontier_entity_ids = set(entity_ids)
    frontier_pids = set(pids)
    collected_process_events = list(selected_events)
    if expansion == "children":
        for _ in range(depth):
            child_filter = _child_process_filter(parent_entity_ids=frontier_entity_ids, parent_pids=frontier_pids)
            if not child_filter:
                break
            child_events, _, _ = _search_scope_events(context, size=max_nodes * 4, extra_filters=[*base_process_filters, child_filter])
            child_events = _dedupe_events(child_events)
            if not child_events:
                break
            expansion_events.extend(child_events)
            next_entity_ids, next_pids, _, _, _ = _process_identity_from_events(child_events, entity_id=None, pid=None, process_name=None)
            next_entity_ids -= frontier_entity_ids
            next_pids -= frontier_pids
            frontier_entity_ids = next_entity_ids
            frontier_pids = next_pids
            if not frontier_entity_ids and not frontier_pids:
                break
        if not expansion_events:
            warnings.append("No additional children found for the selected process within the current scope.")
    elif expansion == "parents":
        frontier_parent_entity_ids = set(parent_entity_ids)
        frontier_parent_pids = set(parent_pids)
        for _ in range(depth):
            parent_filter = _identity_filter(entity_ids=frontier_parent_entity_ids, pids=frontier_parent_pids)
            if not parent_filter:
                break
            parent_events, _, _ = _search_scope_events(context, size=max_nodes * 2, extra_filters=[*base_process_filters, parent_filter])
            parent_events = _dedupe_events(parent_events)
            if not parent_events:
                break
            expansion_events.extend(parent_events)
            _, _, next_parent_entity_ids, next_parent_pids, _ = _process_identity_from_events(parent_events, entity_id=None, pid=None, process_name=None)
            frontier_parent_entity_ids = next_parent_entity_ids - frontier_parent_entity_ids
            frontier_parent_pids = next_parent_pids - frontier_parent_pids
            if not frontier_parent_entity_ids and not frontier_parent_pids:
                break
        if not expansion_events:
            warnings.append("No parent process events were found for the selected process.")
    elif expansion == "siblings":
        sibling_filter = _child_process_filter(parent_entity_ids=parent_entity_ids, parent_pids=parent_pids)
        if sibling_filter:
            sibling_events, _, _ = _search_scope_events(context, size=max_nodes * 4, extra_filters=[*base_process_filters, sibling_filter])
            selected_event_ids = {str(event.get("id") or event.get("event_id") or "") for event in selected_events}
            expansion_events = [
                event
                for event in _dedupe_events(sibling_events)
                if str(event.get("id") or event.get("event_id") or "") not in selected_event_ids
            ]
        if not expansion_events:
            warnings.append("No sibling processes found for the selected process within the current scope.")
    elif expansion == "activity":
        activity_filters = [_process_activity_filter()]
        if host_filter:
            activity_filters.append(host_filter)
        if time_filter:
            activity_filters.append(time_filter)
        activity_identity = _activity_identity_filter(entity_ids=entity_ids, pids=pids, process_name=process_name if not entity_ids and not pids else None)
        if activity_identity:
            activity_filters.append(activity_identity)
        activity_events, _, _ = _search_scope_events(context, size=max_activity * 8, extra_filters=activity_filters)
        expansion_events = _dedupe_events(activity_events)
        if not expansion_events:
            warnings.append("No process activity found for the selected process within the current scope.")

    graph_events = _dedupe_events([*collected_process_events, *expansion_events])
    if expansion in {"children", "parents", "siblings"} and expansion_events:
        # Pull a little adjacent context so the returned subgraph can connect via existing edges.
        related_entity_ids, related_pids, related_parent_entity_ids, related_parent_pids, _ = _process_identity_from_events(expansion_events, entity_id=None, pid=None, process_name=None)
        context_filter = _identity_filter(entity_ids=entity_ids | related_entity_ids | parent_entity_ids | related_parent_entity_ids, pids=pids | related_pids | parent_pids | related_parent_pids)
        if context_filter:
            context_events, _, _ = _search_scope_events(context, size=min(max_nodes * 6, 1000), extra_filters=[*base_process_filters, context_filter])
            graph_events = _dedupe_events([*graph_events, *context_events])

    graph = _build_process_graph(graph_events, case.id, evidence_id, scope)
    compact_graph = _compact_process_graph(
        graph,
        include_activity=expansion == "activity" and bool(edge_types),
        aggregate_activity=True,
        edge_types=edge_types,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity,
    )
    summary = compact_graph.get("summary") or {}
    omitted_counts.update({str(key): int(value or 0) for key, value in (compact_graph.get("omitted_counts") or {}).items()})
    warnings.extend(str(item) for item in summary.get("warnings") or [])
    base_graph_node = None
    if base_event:
        base_graph = _build_process_graph([base_event], case.id, evidence_id, scope)
        base_graph_node = (base_graph.get("nodes") or [None])[0]
    return {
        "base_node": base_graph_node,
        "added_nodes": compact_graph.get("nodes") or [],
        "added_edges": compact_graph.get("edges") or [],
        "activity_groups": compact_graph.get("groups") or [],
        "omitted_counts": dict(omitted_counts),
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
        "summary": {
            **summary,
            "expansion_type": expansion,
            "selected_events": len(selected_events),
            "expansion_events": len(expansion_events),
        },
    }


def _merge_graph_parts(parts: list[dict]) -> dict:
    nodes_by_id: dict[str, dict] = {}
    edges_by_id: dict[str, dict] = {}
    groups_by_id: dict[str, dict] = {}
    omitted_counts: Counter[str] = Counter()
    warnings: list[str] = []
    for part in parts:
        for node in part.get("nodes") or part.get("added_nodes") or []:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            if node_id in nodes_by_id:
                merged = dict(nodes_by_id[node_id])
                for key, value in node.items():
                    if value not in (None, "", [], {}):
                        merged[key] = value
                nodes_by_id[node_id] = merged
            else:
                nodes_by_id[node_id] = dict(node)
        for edge in part.get("edges") or part.get("added_edges") or []:
            edge_id = str(edge.get("id") or f"{edge.get('source')}->{edge.get('target')}:{edge.get('type') or ''}")
            if edge_id:
                edges_by_id[edge_id] = dict(edge)
        for group in part.get("groups") or part.get("activity_groups") or []:
            group_id = str(group.get("id") or f"{group.get('source') or ''}:{group.get('group') or ''}")
            if group_id:
                groups_by_id[group_id] = dict(group)
        omitted_counts.update({str(key): int(value or 0) for key, value in (part.get("omitted_counts") or {}).items()})
        warnings.extend(str(item) for item in part.get("warnings") or [])
    return {
        "nodes": list(nodes_by_id.values()),
        "edges": list(edges_by_id.values()),
        "groups": list(groups_by_id.values()),
        "omitted_counts": dict(omitted_counts),
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
    }


def _node_identity_matches(node: dict, *, process_guid: str | None, pid: int | None, source_event_id: str | None, process_name: str | None) -> bool:
    source_events = {str(item) for item in (node.get("source_events") or []) if item}
    if source_event_id and (str(node.get("source_event_id") or "") == str(source_event_id) or str(source_event_id) in source_events):
        return True
    if source_event_id:
        return False
    if process_guid and str(node.get("id") or "").strip() == str(process_guid).strip():
        return True
    if pid is not None and _safe_intish(node.get("pid")) == int(pid):
        name = str(process_name or "").strip().lower()
        if not name:
            return True
        haystack = f"{node.get('name') or ''} {node.get('path') or ''} {node.get('command_line') or ''}".lower()
        return name in haystack
    return False


def _parent_explanation_for_node(node: dict | None) -> str:
    if not node:
        return "Focused process could not be resolved."
    process_name = str(node.get("name") or "This process")
    pid_text = f" PID {node.get('pid')}" if node.get("pid") is not None else ""
    parent_name = str(node.get("parent_name") or "").strip()
    parent_pid = node.get("parent_pid")
    if str(node.get("parent_link_status") or "") == "linked" and (parent_name or parent_pid is not None):
        parent_text = parent_name or "its parent process"
        if parent_pid is not None:
            parent_text = f"{parent_text} PID {parent_pid}"
        return f"This {process_name}{pid_text} was launched by {parent_text}."
    reason = str(node.get("parent_link_reason") or "Parent process could not be found.")
    return f"Parent process could not be linked for {process_name}{pid_text}. Reason: {reason}"


def build_process_tree_focused(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    pid: int | None = None,
    process_guid: str | None = None,
    source_event_id: str | None = None,
    process_name: str | None = None,
    timestamp: str | None = None,
    parent_depth: int = 2,
    child_depth: int = 2,
    include_siblings: bool = True,
    include_activity: bool = False,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 100,
    max_activity: int = 25,
) -> dict:
    parent_depth = min(max(int(parent_depth or 0), 0), 5)
    child_depth = min(max(int(child_depth or 0), 0), 5)
    max_nodes = min(max(int(max_nodes or 100), 1), 500)
    max_activity = min(max(int(max_activity or 25), 1), 500)

    resolved_guid = str(process_guid or "").strip() or None
    resolved_pid = pid
    resolved_name = str(process_name or "").strip() or None
    resolved_timestamp = timestamp
    selected_source_events: list[dict] = []
    if source_event_id:
        request = DebugExportRequest(
            scope=scope,
            evidence_id=evidence_id,
            include_raw_samples=False,
            include_raw_xml=False,
            max_events_per_type=250,
        )
        context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
        source_filters = [_process_start_filter()]
        source_filter = _source_event_filter(source_event_id)
        if source_filter:
            source_filters.append(source_filter)
        selected_source_events, _, _ = _search_scope_events(context, size=25, extra_filters=source_filters)
        if selected_source_events:
            source_process = selected_source_events[0].get("process") or {}
            resolved_guid = resolved_guid or str(source_process.get("entity_id") or source_process.get("guid") or "").strip() or None
            resolved_pid = resolved_pid if resolved_pid is not None else _safe_intish(source_process.get("pid"))
            resolved_name = resolved_name or str(source_process.get("name") or source_process.get("executable") or "").strip() or None
            resolved_timestamp = resolved_timestamp or selected_source_events[0].get("@timestamp")

    base_bundle = build_process_tree_bundle(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        pid=resolved_pid,
        process_name=resolved_name,
        entity_id=resolved_guid,
        include_activity=False,
        aggregate_activity=True,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity,
    )
    base_graph = base_bundle.get("graph") or {}
    base_nodes = list(base_graph.get("nodes") or [])
    exact_identity_requested = bool(source_event_id or process_guid)
    focus_node = next(
        (
            node
            for node in base_nodes
            if _node_identity_matches(node, process_guid=resolved_guid, pid=resolved_pid, source_event_id=source_event_id, process_name=resolved_name)
        ),
        None if exact_identity_requested else base_nodes[0] if base_nodes else None,
    )
    if focus_node:
        resolved_guid = resolved_guid or str(focus_node.get("id") or "").strip() or None
        resolved_pid = resolved_pid if resolved_pid is not None else _safe_intish(focus_node.get("pid"))
        resolved_name = resolved_name or str(focus_node.get("name") or "").strip() or None
        resolved_timestamp = resolved_timestamp or focus_node.get("first_seen") or focus_node.get("last_seen")

    parts = [base_graph]
    warnings: list[str] = []
    if not focus_node:
        if source_event_id:
            warnings.append("Could not build exact story for selected process event. No process node matched the requested source_event_id.")
        elif process_guid:
            warnings.append("Could not build exact story for selected process. No process node matched the requested ProcessGuid.")
        else:
            warnings.append("No process node matched the requested PID, ProcessGuid, or source event.")
    else:
        expansion_kwargs = {
            "scope": scope,
            "evidence_id": evidence_id,
            "host": host or focus_node.get("host"),
            "node_id": str(focus_node.get("id") or resolved_guid or ""),
            "process_guid": str(focus_node.get("id") or resolved_guid or ""),
            "process_pid": resolved_pid,
            "process_name": resolved_name,
            "timestamp": resolved_timestamp,
            "time_window_before": time_window_before,
            "time_window_after": time_window_after,
            "max_nodes": max_nodes,
            "max_activity": max_activity,
        }
        if parent_depth:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="parents",
                    depth=parent_depth,
                    **expansion_kwargs,
                )
            )
        if child_depth:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="children",
                    depth=child_depth,
                    **expansion_kwargs,
                )
            )
        if include_siblings:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="siblings",
                    depth=1,
                    **expansion_kwargs,
                )
            )
        if include_activity:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="activity",
                    depth=1,
                    **expansion_kwargs,
                )
            )

    merged = _merge_graph_parts(parts)
    warnings.extend(merged["warnings"])
    nodes = merged["nodes"]
    edges = merged["edges"]
    focus_id = str((focus_node or {}).get("id") or resolved_guid or "")
    parent_ids = {edge.get("source") for edge in edges if edge.get("target") == focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}}
    child_ids = {edge.get("target") for edge in edges if edge.get("source") == focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}}
    sibling_ids: set[str] = set()
    if parent_ids:
        for edge in edges:
            if edge.get("source") in parent_ids and edge.get("target") != focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}:
                sibling_ids.add(str(edge.get("target")))
    node_by_id = {str(node.get("id")): node for node in nodes}
    ambiguous_candidates = []
    if pid is not None and not process_guid and not source_event_id:
        pid_candidates = [node for node in nodes if _safe_intish(node.get("pid")) == int(pid)]
        if not (timestamp or host or evidence_id) and len(pid_candidates) > 1:
            ambiguous_candidates = pid_candidates
            warnings.append("PID-only focus matched multiple candidates. Add host, evidence, timestamp, or ProcessGuid to disambiguate.")
    method = "source_event_id" if source_event_id else "process_guid" if process_guid else "pid_timestamp_host" if timestamp or host or evidence_id else "pid_only" if pid is not None else "process_name"
    confidence = "high" if process_guid or source_event_id or (pid is not None and (timestamp or host or evidence_id)) else "low" if ambiguous_candidates else "medium"
    target_identity_matches = not bool(source_event_id or process_guid) or bool(focus_node)
    if focus_node and source_event_id:
        target_identity_matches = _node_identity_matches(
            focus_node,
            process_guid=None,
            pid=None,
            source_event_id=source_event_id,
            process_name=None,
        )
        if not target_identity_matches:
            warnings.append("Exact source_event_id did not round-trip to the selected target.")
    elif focus_node and process_guid:
        target_identity_matches = str(focus_node.get("id") or "").strip() == str(process_guid).strip()
        if not target_identity_matches:
            warnings.append("Exact ProcessGuid did not round-trip to the selected target.")
    return {
        "focus_node": node_by_id.get(focus_id) or focus_node,
        "parents": [node_by_id[item] for item in parent_ids if item in node_by_id],
        "children": [node_by_id[item] for item in child_ids if item in node_by_id],
        "siblings": [node_by_id[item] for item in sibling_ids if item in node_by_id],
        "activity_groups": merged["groups"],
        "nodes": nodes,
        "edges": edges,
        "omitted_counts": merged["omitted_counts"],
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
        "identity_resolution": {
            "method": method,
            "confidence": confidence,
            "ambiguous_candidates": ambiguous_candidates[:10],
            "parent_explanation": _parent_explanation_for_node(node_by_id.get(focus_id) or focus_node),
            "target_identity_matches": target_identity_matches,
            "requested_source_event_id": source_event_id,
            "requested_process_guid": process_guid,
        },
    }


def _node_short_label(node: dict | None) -> str:
    if not node:
        return "unknown process"
    label = str(node.get("name") or node.get("path") or "process")
    if node.get("pid") is not None:
        label = f"{label} PID {node.get('pid')}"
    return label


def _children_sentence(target: dict | None, children: list[dict]) -> str:
    if not target:
        return "No execution target was resolved."
    if not children:
        return f"{_node_short_label(target)} did not launch any direct child processes in the selected scope."
    labels = [_node_short_label(child) for child in children[:5]]
    suffix = f" and {len(children) - 5} more" if len(children) > 5 else ""
    return f"It launched {', '.join(labels)}{suffix}."


def _parent_sentence_for_story(target: dict | None, parents: list[dict], fallback: str) -> str:
    if not target:
        return fallback
    if fallback and not fallback.startswith("Parent process could not be linked"):
        return fallback
    candidates = [parent for parent in parents if parent and parent.get("id") != target.get("id")]
    if not candidates:
        return fallback
    target_parent_pid = target.get("parent_pid")
    target_parent_name = str(target.get("parent_name") or "").lower()
    parent = None
    for candidate in candidates:
        candidate_name = str(candidate.get("name") or candidate.get("path") or "").lower()
        if target_parent_pid is not None and candidate.get("pid") == target_parent_pid:
            parent = candidate
            break
        if target_parent_name and target_parent_name in candidate_name:
            parent = candidate
            break
    parent = parent or candidates[-1]
    return f"This {_node_short_label(target)} was launched by {_node_short_label(parent)}."


def _activity_sentence(groups: list[dict], omitted_counts: dict) -> str:
    counts: Counter[str] = Counter()
    for group in groups:
        counts[str(group.get("group") or "activity")] += int(group.get("count") or 0)
    for key, value in (omitted_counts or {}).items():
        counts[str(key)] += int(value or 0)
    interesting = [(name, count) for name, count in counts.items() if count]
    if not interesting:
        return "No grouped file, registry, network or DNS activity was observed for the target process."
    labels = []
    for name, count in sorted(interesting):
        label = {
            "dns": "DNS queries",
            "file": "file events",
            "network": "network connections",
            "registry": "registry events",
        }.get(name, f"{name} events")
        labels.append(f"{count} {label}")
    if len(labels) == 1:
        return f"{labels[0]} were observed."
    return f"{', '.join(labels[:-1])} and {labels[-1]} were observed."


def _risk_sentence(target: dict | None, children: list[dict]) -> str:
    reasons = list((target or {}).get("risk_reasons") or [])
    for child in children:
        reasons.extend(str(item) for item in (child.get("risk_reasons") or []) if item)
    reasons = list(dict.fromkeys([reason for reason in reasons if reason]))[:4]
    if not reasons:
        return "No explicit suspicious reasons were attached to this story."
    return "Suspicious because " + "; ".join(reason[0].lower() + reason[1:] if reason else reason for reason in reasons) + "."


def _event_host(event: dict) -> str | None:
    return str(_nested_get(event, "host.name") or _nested_get(event, "host.hostname") or _nested_get(event, "windows.computer") or "").strip() or None


def _event_source_label(event: dict) -> str:
    provider = str(_nested_get(event, "event.provider") or _nested_get(event, "winlog.provider_name") or "").strip()
    channel = str(_nested_get(event, "event.channel") or _nested_get(event, "winlog.channel") or "").strip()
    event_id = str(_nested_get(event, "windows.event_id") or _nested_get(event, "event.code") or "").strip()
    artifact_type = str(_nested_get(event, "artifact.type") or "").strip()
    parts = [part for part in [provider, channel, f"EventID {event_id}" if event_id else "", artifact_type] if part]
    return " / ".join(parts) or "event"


def _classify_execution_story_source_event(event: dict | None) -> tuple[str, str, str]:
    if not event:
        return "generic", "source_event_id", "low"
    process = event.get("process") or {}
    has_identity = bool(
        str(process.get("entity_id") or process.get("guid") or "").strip()
        or _safe_intish(process.get("pid")) is not None
    )
    has_command = bool(str(process.get("command_line") or "").strip())
    event_id = _safe_intish(_nested_get(event, "windows.event_id") or _nested_get(event, "event.code"))
    provider = str(_nested_get(event, "event.provider") or _nested_get(event, "winlog.provider_name") or "").lower()
    event_type = str(_nested_get(event, "event.type") or "").lower()
    artifact_type = str(_nested_get(event, "artifact.type") or "").lower()
    if _is_process_start_event(event) and has_identity and has_command:
        return "exact", "source_event_id", "high"
    if event_id in {1, 4688} and has_identity and has_command:
        return "exact", "source_event_id", "high"
    if has_identity:
        if "powershell" in provider or "powershell" in event_type or artifact_type == "powershell":
            return "related", "source_event_id_process_context", "medium"
        return "related", "source_event_id_process_context", "medium"
    return "generic", "source_event_id_event_only", "low"


def _event_to_light_summary(event: dict | None, source_event_id: str | None) -> dict[str, Any]:
    if not event:
        return {
            "id": source_event_id,
            "timestamp": None,
            "host": None,
            "source": "event",
            "title": "Source event was not found",
            "summary": "The selected source_event_id was not found in indexed events.",
            "process": {},
        }
    process = event.get("process") or {}
    title = str(event.get("title") or _nested_get(event, "event.action") or _event_source_label(event))
    summary = str(event.get("summary") or _nested_get(event, "event.message") or title)
    if len(summary) > 600:
        summary = summary[:597].rstrip() + "..."
    return {
        "id": str(event.get("id") or event.get("event_id") or source_event_id or ""),
        "timestamp": event.get("@timestamp"),
        "host": _event_host(event),
        "source": _event_source_label(event),
        "title": title[:240],
        "summary": summary,
        "process": {
            "pid": _safe_intish(process.get("pid")),
            "name": process.get("name") or process.get("executable"),
            "command_line": process.get("command_line"),
            "entity_id": process.get("entity_id") or process.get("guid"),
            "user": _nested_get(event, "user.name"),
        },
    }


def _candidate_score_for_event(candidate: dict, source_event: dict | None) -> int:
    process = candidate.get("process") or {}
    source_process = (source_event or {}).get("process") or {}
    score = 0
    if _safe_intish(process.get("pid")) is not None and _safe_intish(process.get("pid")) == _safe_intish(source_process.get("pid")):
        score += 100
    if str(process.get("entity_id") or process.get("guid") or "") and str(process.get("entity_id") or process.get("guid")) == str(source_process.get("entity_id") or source_process.get("guid") or ""):
        score += 120
    candidate_user = str(_nested_get(candidate, "user.name") or "").lower()
    source_user = str(_nested_get(source_event or {}, "user.name") or "").lower()
    if candidate_user and source_user and candidate_user == source_user:
        score += 25
    name = str(process.get("name") or process.get("executable") or "").lower()
    command = str(process.get("command_line") or "").lower()
    if "powershell" in name:
        score += 20
    if any(token in command for token in (" -ep bypass", "executionpolicy bypass", " -nop", " -w hidden", "psexec", "rubeus", "mimikatz")):
        score += 30
    source_ts = _safe_parse_dt((source_event or {}).get("@timestamp"))
    candidate_ts = _safe_parse_dt(candidate.get("@timestamp"))
    if source_ts and candidate_ts:
        delta = abs((candidate_ts - source_ts).total_seconds())
        if delta <= 60:
            score += 25
        elif delta <= 300:
            score += 15
        elif delta <= 1800:
            score += 5
    return score


def _candidate_node_from_event(event: dict, score: int) -> dict:
    graph = _build_process_graph([event], str(event.get("case_id") or ""), str(event.get("evidence_id") or ""), "case")
    nodes = list(graph.get("nodes") or [])
    if nodes:
        node = dict(nodes[0])
    else:
        process = event.get("process") or {}
        event_id = str(event.get("id") or event.get("event_id") or "")
        node = {
            "id": str(process.get("entity_id") or process.get("guid") or event_id),
            "pid": _safe_intish(process.get("pid")),
            "name": process.get("name") or process.get("executable"),
            "path": process.get("path"),
            "command_line": process.get("command_line"),
            "user": _nested_get(event, "user.name"),
            "host": _event_host(event),
            "first_seen": event.get("@timestamp"),
            "source_event_id": event_id,
            "source_events": [event_id] if event_id else [],
        }
    node["candidate_score"] = score
    node["candidate_reason"] = "Ranked by PID, user, time proximity and suspicious command indicators."
    return node


def _related_process_candidates_for_event(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None,
    host: str | None,
    source_event: dict | None,
    limit: int = 8,
) -> list[dict]:
    request = DebugExportRequest(scope=scope, evidence_id=evidence_id, include_raw_samples=False, include_raw_xml=False, max_events_per_type=100)
    context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
    filters = [_process_start_filter()]
    candidate_host = host or _event_host(source_event or {})
    host_filter = _host_focus_filter(candidate_host)
    if host_filter:
        filters.append(host_filter)
    time_filter = _time_window_filter((source_event or {}).get("@timestamp"), 900, 900)
    if time_filter:
        filters.append(time_filter)
    events, _, _ = _search_scope_events(context, size=300, extra_filters=filters)
    scored = sorted(
        [(_candidate_score_for_event(event, source_event), event) for event in _dedupe_events(events)],
        key=lambda item: (item[0], str(item[1].get("@timestamp") or "")),
        reverse=True,
    )
    return [_candidate_node_from_event(event, score) for score, event in scored[:limit]]


def _light_execution_story_for_generic_event(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None,
    host: str | None,
    source_event_id: str,
    source_event: dict | None,
    target_quality: str,
    identity_method: str,
    confidence: str,
) -> dict:
    event_summary = _event_to_light_summary(source_event, source_event_id)
    candidates = _related_process_candidates_for_event(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        source_event=source_event,
        limit=8,
    )
    query_text = str((event_summary.get("process") or {}).get("command_line") or (event_summary.get("process") or {}).get("name") or "")
    recommendations = [
        "Build exact story from a candidate process.",
        "Search around the event timestamp.",
        "Open Command History around this host and time.",
    ]
    if target_quality == "generic":
        recommendations.insert(0, "This event is too broad for an exact process story.")
    story_text = (
        "Opened from a generic PowerShell event. Select a candidate process to build an exact story."
        if target_quality == "generic"
        else "Opened from a process-related event, not a process creation event. Select a candidate process to build an exact story."
    )
    return {
        "target": None,
        "target_node_id": None,
        "default_selected_node_id": None,
        "story": {
            "summary": story_text,
            "parent_sentence": "Parent/child process relationships are not built automatically for this event type.",
            "children_sentence": "Choose a candidate process to load exact children.",
            "activity_sentence": "Activity details are loaded on demand after an exact process target is selected.",
            "risk_sentence": "No exact process risk sentence was generated for this generic event.",
        },
        "parents": [],
        "children": [],
        "siblings": [],
        "activity_groups": {"items": [], "omitted_counts": {}},
        "commands": [],
        "source_events": [source_event_id],
        "visual_tree": {"nodes": [], "edges": []},
        "event_summary": event_summary,
        "candidate_processes": candidates,
        "nearby": {
            "search_query": query_text[:160] if query_text else None,
            "time_window_seconds": 300,
            "host": event_summary.get("host") or host,
        },
        "recommended_action": "build_exact_story_from_candidate" if candidates else "search_around_event",
        "quality": {
            "confidence": confidence,
            "missing_parent": False,
            "ambiguous_pid": False,
            "warnings": [
                "This is not an exact process creation event.",
                "Could not build exact story for selected source_event_id; choose a related process candidate.",
                "Heavy graph/activity expansion was skipped to keep the first response small.",
            ],
            "identity_resolution": {
                "method": identity_method,
                "confidence": confidence,
                "ambiguous_candidates": candidates,
                "parent_explanation": "Select a candidate process to resolve parent/child relationships.",
                "target_identity_matches": False,
                "requested_source_event_id": source_event_id,
                "requested_process_guid": None,
            },
            "exact_story": False,
            "origin": "search_event",
            "filter_scope": "candidate_search",
            "visual_tree_contains_target": False,
            "target_quality": target_quality,
            "identity_method": identity_method,
            "recommended_action": "build_exact_story_from_candidate" if candidates else "search_around_event",
            "recommendations": recommendations,
            "activity_lazy": True,
            "response_mode": "lightweight",
        },
    }


def build_execution_story(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    pid: int | None = None,
    process_guid: str | None = None,
    source_event_id: str | None = None,
    q: str | None = None,
    timestamp: str | None = None,
    parent_depth: int = 3,
    child_depth: int = 2,
    include_activity: bool = True,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 100,
) -> dict:
    if source_event_id:
        cache_key = _execution_story_cache_key(case.id, source_event_id=source_event_id, scope=scope, evidence_id=evidence_id)
        cached = _execution_story_cache_get(cache_key)
        if cached:
            return cached
        request = DebugExportRequest(
            scope=scope,
            evidence_id=evidence_id,
            include_raw_samples=False,
            include_raw_xml=False,
            max_events_per_type=25,
        )
        context = _DebugPackContext(case=case, evidences=evidences, request=request, export_timestamp=datetime.now(UTC))
        source_filter = _source_event_filter(source_event_id)
        source_events: list[dict] = []
        if source_filter:
            source_events, _, _ = _search_scope_events(context, size=1, extra_filters=[source_filter])
        source_event = source_events[0] if source_events else None
        target_quality, identity_method, source_confidence = _classify_execution_story_source_event(source_event)
        if target_quality in {"related", "generic"}:
            return _execution_story_cache_put(
                cache_key,
                _light_execution_story_for_generic_event(
                    case,
                    evidences,
                    scope=scope,
                    evidence_id=evidence_id,
                    host=host,
                    source_event_id=source_event_id,
                    source_event=source_event,
                    target_quality=target_quality,
                    identity_method=identity_method,
                    confidence=source_confidence,
                ),
            )
    focused = build_process_tree_focused(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        pid=pid,
        process_guid=process_guid,
        source_event_id=source_event_id,
        process_name=q,
        timestamp=timestamp,
        parent_depth=parent_depth,
        child_depth=child_depth,
        include_siblings=True,
        include_activity=include_activity,
        time_window_before=time_window_before,
        time_window_after=time_window_after,
        max_nodes=max_nodes,
    )
    target = focused.get("focus_node")
    parents = focused.get("parents") or []
    children = focused.get("children") or []
    groups = focused.get("activity_groups") or []
    omitted_counts = focused.get("omitted_counts") or {}
    parent_sentence = _parent_sentence_for_story(
        target,
        parents,
        str((focused.get("identity_resolution") or {}).get("parent_explanation") or _parent_explanation_for_node(target)),
    )
    children_sentence = _children_sentence(target, children)
    activity_sentence = _activity_sentence(groups, omitted_counts)
    risk_sentence = _risk_sentence(target, children)
    summary_parts = [parent_sentence, children_sentence, activity_sentence]
    if risk_sentence and not risk_sentence.startswith("No explicit"):
        summary_parts.append(risk_sentence)
    identity = focused.get("identity_resolution") or {}
    exact_story = str(identity.get("method") or "") in {"source_event_id", "process_guid"}
    target_node_id = str((target or {}).get("id") or "") or None
    visual_nodes = focused.get("nodes") or []
    visual_edges = focused.get("edges") or []
    visual_tree_contains_target = not bool(target_node_id) or any(str(node.get("id") or "") == target_node_id for node in visual_nodes)
    warnings = list(focused.get("warnings") or [])
    if exact_story and target_node_id and not visual_tree_contains_target:
        warnings.append("Exact story target missing from visual tree.")
    return {
        "target": target,
        "target_node_id": target_node_id,
        "default_selected_node_id": target_node_id,
        "story": {
            "summary": " ".join(part for part in summary_parts if part),
            "parent_sentence": parent_sentence,
            "children_sentence": children_sentence,
            "activity_sentence": activity_sentence,
            "risk_sentence": risk_sentence,
        },
        "parents": parents,
        "children": children,
        "siblings": focused.get("siblings") or [],
        "activity_groups": {
            "items": groups,
            "omitted_counts": omitted_counts,
        },
        "commands": [],
        "source_events": list(dict.fromkeys((target or {}).get("source_events") or [])),
        "visual_tree": {
            "nodes": visual_nodes,
            "edges": visual_edges,
        },
        "quality": {
            "confidence": str(identity.get("confidence") or "unknown"),
            "missing_parent": bool(target and (target.get("parent_link_status") or "") != "linked"),
            "ambiguous_pid": bool(identity.get("ambiguous_candidates")),
            "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
            "identity_resolution": identity,
            "exact_story": exact_story,
            "origin": "search_event" if source_event_id else "direct_search" if q or pid or process_guid else "advanced_graph",
            "filter_scope": "exact_chain" if exact_story else "candidate_search",
            "visual_tree_contains_target": visual_tree_contains_target,
            "target_quality": "exact" if exact_story else "generic",
            "identity_method": str(identity.get("method") or ""),
            "recommended_action": "review_exact_story" if exact_story else "select_candidate",
            "activity_lazy": False,
            "response_mode": "full",
        },
    }


def _serialize_debug_finding(item: Finding) -> dict:
    return {
        "id": item.id,
        "case_id": item.case_id,
        "evidence_id": item.evidence_id,
        "finding_type": item.finding_type,
        "title": item.title,
        "summary": item.description,
        "severity": item.severity.value if hasattr(item.severity, "value") else str(item.severity),
        "confidence": item.confidence,
        "status": item.status.value if hasattr(item.status, "value") else str(item.status),
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "time_start": item.time_start.isoformat() if item.time_start else None,
        "time_end": item.time_end.isoformat() if item.time_end else None,
        "timeline": item.timeline or [],
        "related_event_ids": item.related_event_ids or item.event_ids or [],
        "related_artifact_ids": item.related_artifact_ids or [],
        "related_evidence_ids": item.related_evidence_ids or [],
        "related_process_node_ids": item.related_process_node_ids or [],
        "related_files": item.related_files or [],
        "related_domains": item.related_domains or [],
        "related_ips": item.related_ips or [],
        "related_users": item.related_users or [],
        "related_hosts": item.related_hosts or [],
        "risk_score": item.risk_score or 0,
        "reasons": item.reasons or [],
        "tags": item.tags or [],
        "mitre": item.mitre or [],
        "recommended_triage": item.recommended_triage or [],
        "source": item.source,
        "correlation_version": item.correlation_version,
        "data_quality": item.data_quality or [],
        "fingerprint": item.fingerprint,
    }


def _collect_correlation_findings(db: Session, context: _DebugPackContext) -> list[dict]:
    query = db.query(Finding).filter(Finding.case_id == context.case.id, Finding.source == "correlation_engine").order_by(Finding.created_at.desc())
    if context.request.evidence_id:
        query = query.filter(Finding.evidence_id == context.request.evidence_id)
    return [_serialize_debug_finding(item) for item in query.all()]


def _build_correlation_findings_report(context: _DebugPackContext, findings: list[dict], process_graph: dict) -> dict:
    return {
        "case_id": context.case.id,
        "evidence_id": context.request.evidence_id,
        "findings_generated": len(findings),
        "findings_deduplicated": 0,
        "by_type": dict(Counter(str(item.get("finding_type") or "") for item in findings if item.get("finding_type"))),
        "by_severity": dict(Counter(str(item.get("severity") or "") for item in findings if item.get("severity"))),
        "by_confidence": dict(Counter(str(item.get("confidence") or "") for item in findings if item.get("confidence"))),
        "by_status": dict(Counter(str(item.get("status") or "") for item in findings if item.get("status"))),
        "events_considered": 0,
        "process_graph_available": bool((process_graph or {}).get("nodes")),
        "process_nodes_considered": int(((process_graph or {}).get("summary") or {}).get("nodes_count") or 0),
        "correlation_windows": {},
        "warnings": [],
        "parser_errors": [],
    }


def _build_noise_reduction_report(events: list[dict], findings: list[dict]) -> dict:
    by_reason: Counter[str] = Counter()
    known_good_counts: Counter[str] = Counter()
    suppression_reason_counts: Counter[str] = Counter()
    risk_distribution_before: Counter[str] = Counter()
    risk_distribution_after: Counter[str] = Counter()
    adjusted = 0
    suppressed = 0
    for event in events:
        adjustment = (event.get("event", {}) or {}).get("risk_adjustment") or {}
        base_score = int(adjustment.get("base_score") or event.get("risk_score") or 0)
        final_score = int(adjustment.get("final_score") or event.get("risk_score") or 0)
        risk_distribution_before[str(base_score)] += 1
        risk_distribution_after[str(final_score)] += 1
        negative_reasons = [str(item) for item in (adjustment.get("negative_reasons") or []) if item]
        if negative_reasons or base_score != final_score:
            adjusted += 1
        for reason in negative_reasons:
            by_reason[reason] += 1
        tags = set(str(item) for item in (event.get("tags") or []) if item)
        for tag in {"benign_microsoft_signed", "known_good_windows_path", "known_good_microsoft_task", "known_good_windows_update", "normal_onedrive_sync", "informational_usb_only", "weak_single_signal"}:
            if tag in tags:
                known_good_counts[tag] += 1
        if adjustment.get("suppressed"):
            suppressed += 1
            suppression_reason = str(adjustment.get("suppression_reason") or "suppressed")
            suppression_reason_counts[suppression_reason] += 1
    findings_downgraded = sum(1 for finding in findings if any(flag in set(finding.get("data_quality") or []) for flag in {"filename_only_match", "inventory_only_execution_artifact_used", "process_chain_without_source_events"}))
    top_remaining = sorted(
        [
            {
                "id": event.get("id"),
                "artifact_type": (event.get("artifact", {}) or {}).get("type"),
                "event_type": (event.get("event", {}) or {}).get("type"),
                "risk_score": int(event.get("risk_score") or 0),
                "summary": (event.get("event", {}) or {}).get("message"),
            }
            for event in events
            if int(event.get("risk_score") or 0) >= 70
        ],
        key=lambda item: int(item.get("risk_score") or 0),
        reverse=True,
    )[:10]
    return {
        "events_reviewed": len(events),
        "events_adjusted": adjusted,
        "events_suppressed": suppressed,
        "findings_reviewed": len(findings),
        "findings_downgraded": findings_downgraded,
        "by_reason": dict(by_reason),
        "known_good_counts": dict(known_good_counts),
        "adjusted_counts": dict(suppression_reason_counts),
        "suppression_reason_counts": dict(suppression_reason_counts),
        "risk_distribution_before": dict(risk_distribution_before),
        "risk_distribution_after": dict(risk_distribution_after),
        "top_remaining_high_risk": top_remaining,
        "warnings": [],
    }


def _count_rules_matches(db: Session, context: _DebugPackContext) -> int:
    query = db.query(DetectionResult).filter(DetectionResult.case_id == context.case.id)
    if context.request.evidence_id:
        query = query.filter(DetectionResult.evidence_id == context.request.evidence_id)
    if context.request.event_ids:
        query = query.filter(DetectionResult.event_id.in_(context.request.event_ids))
    return int(query.count())


def _collect_scope_counts(context: _DebugPackContext, scope_query: dict[str, Any] | None) -> tuple[int, int]:
    index = get_events_index(context.case.id)
    if context.request.scope == "selected_events":
        events = _coerce_fetched_events(_fetch_events_for_scope(context)).sampled_events
        timeline_total = sum(
            1
            for event in events
            if event.get("@timestamp") and (event.get("event", {}) or {}).get("timeline_include", True)
        )
        suspicious_total = sum(1 for event in events if _event_is_suspicious(event))
        return timeline_total, suspicious_total
    query = scope_query or _build_scope_query(context)
    timeline_query = _build_scope_query(context, timeline=True)
    suspicious_query = deepcopy(query)
    if suspicious_query is None:
        suspicious_query = {"match_all": {}}
    suspicious_bool = (suspicious_query.get("bool") if isinstance(suspicious_query, dict) else None)
    if suspicious_bool is None:
        suspicious_query = {"bool": {"must": [suspicious_query], "should": [], "minimum_should_match": 1}}
        suspicious_bool = suspicious_query["bool"]
    suspicious_bool.setdefault("should", []).extend([
        {"range": {"risk_score": {"gt": 0}}},
        {"terms": {"event.severity": ["medium", "high", "critical"]}},
        {"exists": {"field": "suspicious_reasons"}},
    ])
    suspicious_bool["minimum_should_match"] = 1
    timeline_total = int(count_documents(index, timeline_query or {"match_all": {}}).get("count", 0))
    suspicious_total = int(count_documents(index, suspicious_query).get("count", 0))
    return timeline_total, suspicious_total


def _coerce_matched_fields(raw: dict[str, Any]) -> list[str]:
    matched_fields = raw.get("matched_fields") or raw.get("fields") or []
    if isinstance(matched_fields, str):
        matched_fields = [matched_fields]
    if matched_fields:
        return [str(item) for item in matched_fields if item]
    matched_values = raw.get("matched_values")
    if isinstance(matched_values, dict):
        return [str(key) for key in matched_values.keys() if key]
    field_like = [
        key for key, value in raw.items()
        if key not in {"namespace", "rule_namespace", "enabled", "confidence", "false_positive_notes"}
        and value not in (None, "", [], {})
        and ("." in key or key.endswith("_path") or key.endswith("_name") or key.endswith("_id"))
    ]
    return field_like[:10]


def _extract_matched_values(raw: dict[str, Any], matched_fields: list[str]) -> dict[str, Any]:
    matched_values = raw.get("matched_values")
    if isinstance(matched_values, dict):
        return matched_values
    values: dict[str, Any] = {}
    for field in matched_fields:
        if field in raw:
            values[field] = raw.get(field)
    return values


_BUILTIN_NAME_TO_KEY = {
    definition.name.lower(): definition.key
    for definition in BUILTIN_DETECTION_CATALOG.values()
}


def _infer_builtin_definition(rule_id: str | None, rule_name: str | None, rule_namespace: str | None):
    if rule_id and rule_id in BUILTIN_DETECTION_CATALOG:
        return BUILTIN_DETECTION_CATALOG[rule_id]
    if (rule_namespace or "").lower() == "builtin" and rule_name:
        key = _BUILTIN_NAME_TO_KEY.get(rule_name.lower())
        if key:
            return BUILTIN_DETECTION_CATALOG[key]
    return None


def _build_evtx_classification_report(
    parser_audit: list[dict],
    evtx_events: list[dict],
    *,
    discovery_candidates: list[dict] | None = None,
    selected_artifact_types: list[str] | None = None,
) -> dict:
    evtx_rows = [row for row in parser_audit if str(row.get("parser_name") or "") == "evtx_raw"]
    selected_types = {str(item).lower() for item in (selected_artifact_types or []) if item}
    selected_evtx = "evtx" in selected_types
    evtx_candidates = [
        candidate
        for candidate in (discovery_candidates or [])
        if str(candidate.get("category") or "").lower() == "evtx"
    ]
    selected_evtx_candidates = [
        candidate for candidate in evtx_candidates if bool(candidate.get("selected_for_extraction"))
    ]
    if not evtx_rows and not evtx_events and not evtx_candidates:
        return {
            "total_evtx_files_seen": 0,
            "total_evtx_files_parseable": 0,
            "total_evtx_files_parsed": 0,
            "total_evtx_records_read": 0,
            "total_evtx_records_indexed": 0,
            "total_evtx_records_filtered": 0,
            "total_evtx_records_failed": 0,
            "evtx_candidates_from_discovery": 0,
            "evtx_candidates_selected": 0,
            "parsed_evtx_files": [],
            "evtx_skipped_with_reason": [],
            "native_evtx_raw_events_found": 0,
            "channels_seen": [],
            "providers_seen": [],
            "event_ids_seen": [],
            "classification_counts": {},
            "source_mismatch_count": 0,
            "generic_windows_event_count": 0,
            "top_channels_by_events": [],
            "top_event_ids_by_events": [],
            "top_generic_event_ids": [],
            "top_filtered_reasons": [],
            "classification_guardrails": {
                "security_logon_requires_security_channel": "not_applicable",
                "powershell_requires_powershell_provider_or_channel": "not_applicable",
                "wmi_requires_wmi_activity_provider_or_channel": "not_applicable",
                "bits_requires_bits_client_provider_or_channel": "not_applicable",
                "wlan_requires_wlan_autoconfig_provider_or_channel": "not_applicable",
                "task_scheduler_requires_task_scheduler_provider_or_channel": "not_applicable",
            },
            "not_applicable_reason": "No native EVTX raw events found in this export scope",
        }
    channels_seen = sorted({str(channel) for row in evtx_rows for channel in (row.get("channels_seen") or []) if channel})
    providers_seen = sorted({
        str(provider)
        for row in evtx_rows
        for provider in (row.get("providers_seen") or [])
        if provider
    } | {
        str(_nested_get(event, "windows.provider"))
        for event in evtx_events
        if _nested_get(event, "windows.provider")
    })
    event_ids_seen = sorted({int(event_id) for row in evtx_rows for event_id in (row.get("event_ids_seen") or []) if str(event_id).isdigit()})
    classification_counts: dict[str, int] = defaultdict(int)
    filtered_reasons: dict[str, int] = defaultdict(int)
    top_channels: dict[str, int] = defaultdict(int)
    top_event_ids: dict[str, int] = defaultdict(int)
    top_generic_ids: dict[str, int] = defaultdict(int)

    total_records_read = 0
    total_records_indexed = 0
    total_records_filtered = 0
    total_records_failed = 0
    for row in evtx_rows:
        total_records_read += int(row.get("records_read") or 0)
        total_records_indexed += int(row.get("records_indexed") or 0)
        total_records_filtered += int(row.get("records_filtered") or 0)
        total_records_failed += int(row.get("records_failed") or 0)
        for key, value in dict(row.get("classification_counts") or {}).items():
            classification_counts[str(key)] += int(value or 0)
        for key, value in dict(row.get("records_filtered_by_reason") or {}).items():
            filtered_reasons[str(key)] += int(value or 0)

    source_mismatch_count = 0
    generic_windows_event_count = 0
    guardrails = {
        "security_logon_requires_security_channel": True,
        "powershell_requires_powershell_provider_or_channel": True,
        "wmi_requires_wmi_activity_provider_or_channel": True,
        "bits_requires_bits_client_provider_or_channel": True,
        "wlan_requires_wlan_autoconfig_provider_or_channel": True,
        "task_scheduler_requires_task_scheduler_provider_or_channel": True,
    }
    for event in evtx_events:
        channel = str(_nested_get(event, "windows.channel") or "")
        provider = str(_nested_get(event, "windows.provider") or "")
        event_id = _nested_get(event, "windows.event_id")
        event_type = str(_nested_get(event, "event.type") or "")
        top_channels[channel] += 1
        top_event_ids[str(event_id or "unknown")] += 1
        if event_type.startswith("event_id_") or str(_nested_get(event, "event.category") or "") == "windows_event":
            generic_windows_event_count += 1
            top_generic_ids[str(event_id or "unknown")] += 1
        if "source_mismatch" in (event.get("data_quality") or []):
            source_mismatch_count += 1
        if event_type in {"logon_success", "logon_failed", "logoff", "explicit_credentials", "special_privileges_assigned"} and channel != "Security":
            guardrails["security_logon_requires_security_channel"] = False
        if event_type.startswith("powershell") and "powershell" not in channel.lower() and "powershell" not in provider.lower():
            guardrails["powershell_requires_powershell_provider_or_channel"] = False
        if event_type.startswith("wmi") and "wmi-activity" not in channel.lower() and "wmi-activity" not in provider.lower():
            guardrails["wmi_requires_wmi_activity_provider_or_channel"] = False
        if "bits" in event_type and "bits-client" not in channel.lower() and "bits-client" not in provider.lower():
            guardrails["bits_requires_bits_client_provider_or_channel"] = False
        if "wlan" in event_type and "wlan-autoconfig" not in channel.lower() and "wlan-autoconfig" not in provider.lower():
            guardrails["wlan_requires_wlan_autoconfig_provider_or_channel"] = False
        if "task" in event_type and "taskscheduler" not in channel.lower() and "taskscheduler" not in provider.lower():
            guardrails["task_scheduler_requires_task_scheduler_provider_or_channel"] = False

    parsed_evtx_files = [
        {
            "source_file": str(row.get("source_file") or ""),
            "records_read": int(row.get("records_read") or 0),
            "records_indexed": int(row.get("records_indexed") or 0),
            "parser_status": row.get("parser_status"),
        }
        for row in evtx_rows
    ]
    parsed_evtx_paths = {str(item.get("source_file") or "").strip() for item in parsed_evtx_files if item.get("source_file")}
    evtx_skipped_with_reason = []
    for candidate in evtx_candidates:
        path = str(candidate.get("normalized_windows_path") or candidate.get("original_path") or candidate.get("source_path") or "").strip()
        if not path or path in parsed_evtx_paths:
            continue
        evtx_skipped_with_reason.append(
            {
                "source_file": path,
                "reason": str(candidate.get("parser_status") or candidate.get("reason_detected") or ("not_selected" if not selected_evtx else "not_present_in_parser_audit")),
            }
        )

    return {
        "total_evtx_files_seen": max(len(evtx_rows), len(evtx_candidates)),
        "total_evtx_files_parseable": len(selected_evtx_candidates) if selected_evtx else len(evtx_candidates),
        "total_evtx_files_parsed": len(evtx_rows),
        "total_evtx_records_read": total_records_read,
        "total_evtx_records_indexed": total_records_indexed,
        "total_evtx_records_filtered": total_records_filtered,
        "total_evtx_records_failed": total_records_failed,
        "evtx_candidates_from_discovery": len(evtx_candidates),
        "evtx_candidates_selected": len(selected_evtx_candidates),
        "parsed_evtx_files": parsed_evtx_files[:50],
        "evtx_skipped_with_reason": evtx_skipped_with_reason[:50],
        "native_evtx_raw_events_found": total_records_read,
        "channels_seen": channels_seen,
        "providers_seen": providers_seen,
        "event_ids_seen": event_ids_seen,
        "classification_counts": dict(sorted(classification_counts.items())),
        "source_mismatch_count": source_mismatch_count + sum(int(row.get("source_mismatch_count") or 0) for row in evtx_rows),
        "generic_windows_event_count": generic_windows_event_count + sum(int(row.get("generic_windows_event_count") or 0) for row in evtx_rows),
        "top_channels_by_events": [{"channel": key, "count": value} for key, value in sorted(top_channels.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "top_event_ids_by_events": [{"event_id": key, "count": value} for key, value in sorted(top_event_ids.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "top_generic_event_ids": [{"event_id": key, "count": value} for key, value in sorted(top_generic_ids.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "top_filtered_reasons": [{"reason": key, "count": value} for key, value in sorted(filtered_reasons.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "classification_guardrails": {key: ("pass" if value else "fail") for key, value in guardrails.items()},
        "not_applicable_reason": None,
    }


def _build_lnk_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None) -> dict:
    lnk_rows = [row for row in parser_audit if str(row.get("parser_name") or "") == "lnk_raw"]
    lnk_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("artifact_type") or "") == "lnk_raw"]
    by_location: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    unresolved_by_location: dict[str, int] = defaultdict(int)
    not_selected_candidates_count_by_category: dict[str, int] = defaultdict(int)
    resolved_by_source: dict[str, int] = defaultdict(int)
    unresolved_start_menu: list[dict] = []
    unresolved_recent: list[dict] = []
    unresolved_taskbar: list[dict] = []
    resolved_target_count = 0

    for candidate in lnk_candidates:
        location = str(candidate.get("lnk_location") or "other")
        by_location[location] += 1
    for candidate in discovery_candidates:
        if candidate.get("selected_for_extraction") is False:
            not_selected_candidates_count_by_category[str(candidate.get("category") or "other")] += 1
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "lnk" or artifact.get("parser") != "lnk_raw":
            continue
        by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
        for warning in (_nested_get(event, "lnk.parse_warnings") or []):
            if warning:
                warning_counts[str(warning)] += 1
        effective_path = _nested_get(event, "lnk.effective_path")
        source_file = str(_nested_get(event, "lnk.source_file") or event.get("source_file") or "")
        lowered_source = source_file.lower()
        if effective_path:
            resolved_target_count += 1
            resolved_by_source[str(_nested_get(event, "lnk.effective_path_source") or "unknown")] += 1
        else:
            location = "other"
            if "\\microsoft\\windows\\recent\\" in lowered_source:
                location = "recent"
            elif "\\microsoft\\office\\recent\\" in lowered_source:
                location = "office_recent"
            elif "\\internet explorer\\quick launch\\user pinned\\taskbar\\" in lowered_source:
                location = "taskbar"
            elif "\\microsoft\\windows\\start menu\\" in lowered_source:
                location = "start_menu"
            unresolved_by_location[location] += 1
            example = {
                "source_file": source_file,
                "display_name": _nested_get(event, "lnk.display_name"),
                "event_type": _nested_get(event, "event.type"),
                "warnings": _nested_get(event, "lnk.parse_warnings") or [],
            }
            if location == "start_menu" and len(unresolved_start_menu) < 10:
                unresolved_start_menu.append(example)
            if location in {"recent", "office_recent"} and len(unresolved_recent) < 10:
                unresolved_recent.append(example)
            if location == "taskbar" and len(unresolved_taskbar) < 10:
                unresolved_taskbar.append(example)

    return {
        "total_lnk_candidates": len(lnk_candidates),
        "total_lnk_parsed": sum(int(row.get("lnk_files_parsed") or 0) for row in lnk_rows),
        "total_lnk_failed": sum(int(row.get("lnk_files_failed") or 0) for row in lnk_rows),
        "by_location": dict(sorted(by_location.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "suspicious_count": sum(int(row.get("suspicious_lnk_count") or 0) for row in lnk_rows),
        "top_parse_warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: item[1], reverse=True)[:10]],
        "parse_warnings_counts": dict(sorted(warning_counts.items())),
        "resolved_target_count": resolved_target_count,
        "resolved_by_source": dict(sorted(resolved_by_source.items())),
        "unresolved_target_count": sum(int(row.get("unresolved_target_count") or 0) for row in lnk_rows),
        "unresolved_by_location": dict(sorted(unresolved_by_location.items())),
        "examples_unresolved_start_menu": unresolved_start_menu,
        "examples_unresolved_recent": unresolved_recent,
        "examples_unresolved_taskbar": unresolved_taskbar,
        "selected_artifact_types": selected_artifact_types or [],
        "not_selected_candidates_count_by_category": dict(sorted(not_selected_candidates_count_by_category.items())),
        "partial_target_count": sum(int(row.get("partial_target_count") or 0) for row in lnk_rows),
        "startup_lnk_count": sum(int(row.get("startup_lnk_count") or 0) for row in lnk_rows),
        "network_path_count": sum(int(row.get("network_path_count") or 0) for row in lnk_rows),
        "removable_path_count": sum(int(row.get("removable_path_count") or 0) for row in lnk_rows),
        "cloud_path_count": sum(int(row.get("cloud_path_count") or 0) for row in lnk_rows),
    }


def _build_prefetch_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None) -> dict:
    prefetch_rows = [row for row in parser_audit if str(row.get("parser_name") or "") == "prefetch_raw"]
    prefetch_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("artifact_type") or "") == "prefetch_raw"]
    by_version: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    magic_counts: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    executable_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    lolbin_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    zero_reason_counts: dict[str, int] = defaultdict(int)
    not_selected_candidates_count_by_category: dict[str, int] = defaultdict(int)
    run_counts: list[int] = []
    timestamps: list[str] = []
    resolved_executable_path_count = 0
    unresolved_executable_path_count = 0
    examples_success: list[str] = []
    examples_partial: list[str] = []
    examples_failed: list[str] = []
    examples_empty: list[str] = []
    examples_zero_records: list[str] = []

    for candidate in discovery_candidates:
        if candidate.get("selected_for_extraction") is False:
            not_selected_candidates_count_by_category[str(candidate.get("category") or "other")] += 1
    for row in prefetch_rows:
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        for key, value in (row.get("by_version") or {}).items():
            by_version[str(key)] += int(value or 0)
        for key, value in (row.get("prefetch_versions_seen") or {}).items():
            by_version[str(key)] += int(value or 0)
        for key, value in (row.get("prefetch_magic_counts") or {}).items():
            magic_counts[str(key)] += int(value or 0)
        for warning in row.get("warnings") or []:
            warning_counts[str(warning)] += 1
        for warning, count in (row.get("parse_warnings_counts") or {}).items():
            warning_counts[str(warning)] += int(count or 0)
        for error in row.get("top_prefetch_errors") or []:
            error_counts[str(error)] += 1
        reason_if_zero_records = str(row.get("reason_if_zero_records") or "").strip()
        if reason_if_zero_records:
            zero_reason_counts[reason_if_zero_records] += 1
        examples_success.extend(str(item) for item in (row.get("examples_success_files") or []) if item)
        examples_partial.extend(str(item) for item in (row.get("examples_partial_files") or row.get("examples_empty_files") or []) if item)
        examples_failed.extend(str(item) for item in (row.get("examples_failed_files") or []) if item)
        if int(row.get("events_indexed") or row.get("prefetch_events_indexed") or 0) == 0:
            examples_zero_records.extend(
                str(item)
                for item in (
                    row.get("examples_failed_files")
                    or row.get("examples_empty_files")
                    or row.get("examples_partial_files")
                    or []
                )
                if item
            )
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "prefetch" or artifact.get("parser") != "prefetch_raw":
            continue
        by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
        executable = str(_nested_get(event, "prefetch.executable_name") or _nested_get(event, "process.name") or "unknown")
        executable_counts[executable] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
        if "lolbin" in set(event.get("tags") or []):
            lolbin_counts[executable] += 1
        for warning in (_nested_get(event, "prefetch.parse_warnings") or []):
            warning_counts[str(warning)] += 1
        run_count = _nested_get(event, "execution.run_count")
        if isinstance(run_count, int):
            run_counts.append(run_count)
        elif str(run_count).isdigit():
            run_counts.append(int(str(run_count)))
        if event.get("@timestamp"):
            timestamps.append(str(event.get("@timestamp")))
        if _nested_get(event, "prefetch.executable_path") or _nested_get(event, "process.path"):
            resolved_executable_path_count += 1
        else:
            unresolved_executable_path_count += 1
            examples_empty.append(str(_nested_get(event, "prefetch.source_file") or _nested_get(event, "artifact.source_path") or ""))

    partial_status_count = sum(int(count or 0) for status, count in by_status.items() if status == "partial")
    completed_status_count = sum(int(count or 0) for status, count in by_status.items() if status in {"parsed_native", "completed"})

    return {
        "total_prefetch_candidates": len(prefetch_candidates),
        "total_prefetch_attempted": sum(int(row.get("prefetch_files_opened") or 0) for row in prefetch_rows),
        "total_prefetch_completed": completed_status_count,
        "total_prefetch_parsed": sum(int(row.get("prefetch_files_parsed") or 0) for row in prefetch_rows),
        "total_prefetch_partial": partial_status_count or by_event_type.get("prefetch_observed", 0),
        "total_prefetch_failed": sum(int(row.get("prefetch_files_failed") or 0) for row in prefetch_rows),
        "total_prefetch_indexed_events": sum(int(row.get("prefetch_events_indexed") or 0) for row in prefetch_rows),
        "by_status": dict(sorted(by_status.items())),
        "by_version": dict(sorted(by_version.items())),
        "version_counts": dict(sorted(by_version.items())),
        "magic_counts": dict(sorted(magic_counts.items())),
        "by_executable_name": dict(sorted(executable_counts.items(), key=lambda item: (-item[1], item[0]))[:50]),
        "by_event_type": dict(sorted(by_event_type.items())),
        "run_count_stats": {
            "min": min(run_counts) if run_counts else None,
            "max": max(run_counts) if run_counts else None,
            "avg": round(sum(run_counts) / len(run_counts), 2) if run_counts else None,
        },
        "last_run_min": min(timestamps) if timestamps else None,
        "last_run_max": max(timestamps) if timestamps else None,
        "suspicious_count": sum(int(row.get("suspicious_prefetch_count") or 0) for row in prefetch_rows),
        "lolbin_count": sum(int(row.get("lolbin_prefetch_count") or 0) for row in prefetch_rows),
        "top_lolbins": dict(sorted(lolbin_counts.items(), key=lambda item: (-item[1], item[0]))[:15]),
        "top_suspicious_reasons": [{"reason": key, "count": value} for key, value in sorted(suspicious_reason_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "resolved_executable_path_count": resolved_executable_path_count or sum(int(row.get("prefetch_resolved_executable_path_count") or 0) for row in prefetch_rows),
        "unresolved_executable_path_count": unresolved_executable_path_count or sum(int(row.get("prefetch_unresolved_executable_path_count") or 0) for row in prefetch_rows),
        "mam_compressed_count": sum(int(row.get("prefetch_mam_compressed_count") or 0) for row in prefetch_rows),
        "decompressed_count": sum(int(row.get("prefetch_decompressed_count") or 0) for row in prefetch_rows),
        "mam_decompressed_count": sum(int(row.get("prefetch_decompressed_count") or 0) for row in prefetch_rows),
        "decompression_failed_count": sum(int(row.get("prefetch_decompression_failed_count") or 0) for row in prefetch_rows),
        "mam_decompression_failed_count": sum(int(row.get("prefetch_decompression_failed_count") or 0) for row in prefetch_rows),
        "parser_empty_count": sum(int(row.get("prefetch_empty_parser_results_count") or 0) for row in prefetch_rows),
        "parser_returned_empty_count": sum(int(row.get("prefetch_empty_parser_results_count") or 0) for row in prefetch_rows),
        "normalizer_dropped_count": warning_counts.get("normalizer_dropped_event", 0),
        "zero_record_reason_counts": dict(sorted(zero_reason_counts.items())),
        "top_parse_warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "top_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "examples_success": sorted(dict.fromkeys(item for item in examples_success if item))[:10],
        "examples_partial": sorted(dict.fromkeys(item for item in examples_partial if item))[:10],
        "examples_failed": sorted(dict.fromkeys(item for item in examples_failed if item))[:10],
        "examples_empty": sorted(dict.fromkeys(item for item in examples_empty if item))[:10],
        "examples_zero_records": sorted(dict.fromkeys(item for item in examples_zero_records if item))[:10],
        "selected_artifact_types": selected_artifact_types or [],
        "not_selected_candidates_count_by_category": dict(sorted(not_selected_candidates_count_by_category.items())),
    }


def _build_amcache_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    amcache_rows = [row for row in parser_audit if str(row.get("parser_name") or "") == "amcache_raw"]
    amcache_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("artifact_type") or "") == "amcache"]
    by_status: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    branch_counts: dict[str, int] = defaultdict(int)
    parser_statuses: list[str] = []
    sample_records: list[dict] = []
    examples: list[str] = []
    not_selected_candidates_count_by_category: dict[str, int] = defaultdict(int)

    for candidate in discovery_candidates:
        if candidate.get("selected_for_extraction") is False:
            not_selected_candidates_count_by_category[str(candidate.get("category") or "other")] += 1
    for row in amcache_rows:
        parser_status = str(row.get("parser_status") or row.get("status") or "unknown")
        by_status[parser_status] += 1
        parser_statuses.append(parser_status)
        for warning in row.get("warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or []:
            error_counts[str(error)] += 1
        for branch, count in (row.get("amcache_branch_counts") or {}).items():
            branch_counts[str(branch)] += int(count or 0)
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_records) < 10:
                sample_records.append(sample)
        if row.get("source_file"):
            examples.append(str(row["source_file"]))
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "amcache" or artifact.get("parser") != "amcache_raw":
            continue
        by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1

    records_read = sum(int(row.get("records_read") or row.get("records_extracted") or 0) for row in amcache_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_extracted") or row.get("records_read") or 0) for row in amcache_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in amcache_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in amcache_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "amcache_artifacts_count": len(amcache_rows),
        "detected_amcache_files": sum(int(row.get("detected_amcache_files") or 0) for row in amcache_rows) or len(amcache_candidates),
        "total_amcache_candidates": len(amcache_candidates),
        "parser_selected": "amcache_raw" if amcache_rows or amcache_candidates else None,
        "parser_status": parser_statuses[0] if len(set(parser_statuses)) == 1 and parser_statuses else (sorted(set(parser_statuses)) if parser_statuses else None),
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_failed": records_failed,
        "records_indexed": records_indexed,
        "records_extracted": sum(int(row.get("records_extracted") or row.get("records_read") or 0) for row in amcache_rows),
        "by_status": dict(sorted(by_status.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "branch_counts": dict(sorted(branch_counts.items())),
        "sample_records": sample_records[:10],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "examples": sorted(dict.fromkeys(item for item in examples if item))[:10],
        "selected_artifact_types": selected_artifact_types or [],
        "not_selected_candidates_count_by_category": dict(sorted(not_selected_candidates_count_by_category.items())),
    }


def _build_shimcache_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    shimcache_rows = [row for row in parser_audit if str(row.get("parser_name") or "") == "shimcache_raw"]
    shimcache_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("artifact_type") or "") == "shimcache"]
    by_status: dict[str, int] = defaultdict(int)
    sample_by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    format_counts: dict[str, int] = defaultdict(int)
    parser_statuses: list[str] = []
    sample_records: list[dict] = []
    examples: list[str] = []
    control_sets_seen: set[str] = set()
    not_selected_candidates_count_by_category: dict[str, int] = defaultdict(int)

    for candidate in discovery_candidates:
        if candidate.get("selected_for_extraction") is False:
            not_selected_candidates_count_by_category[str(candidate.get("category") or "other")] += 1
    for row in shimcache_rows:
        parser_status = str(row.get("parser_status") or row.get("status") or "unknown")
        by_status[parser_status] += 1
        parser_statuses.append(parser_status)
        for warning in row.get("warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or []:
            error_counts[str(error)] += 1
        for cache_format, count in (row.get("shimcache_format_counts") or {}).items():
            format_counts[str(cache_format)] += int(count or 0)
        for control_set in row.get("control_sets_seen") or []:
            control_sets_seen.add(str(control_set))
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_records) < 10:
                sample_records.append(sample)
        if row.get("source_file"):
            examples.append(str(row["source_file"]))
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "shimcache" or artifact.get("parser") != "shimcache_raw":
            continue
        sample_by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
    indexed_by_path: dict[str, dict] = {}
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "shimcache" or artifact.get("parser") != "shimcache_raw":
            continue
        normalized_path = normalize_windows_path_for_classification(
            _nested_get(event, "shimcache.path")
            or _nested_get(event, "appcompat.path")
            or _nested_get(event, "file.path")
            or _nested_get(event, "process.path")
        )
        if normalized_path and normalized_path not in indexed_by_path:
            indexed_by_path[normalized_path] = event

    enriched_sample_records: list[dict] = []
    for sample in sample_records[:10]:
        if not isinstance(sample, dict):
            continue
        normalized_path = normalize_windows_path_for_classification(
            sample.get("normalized_path")
            or sample.get("path")
            or sample.get("original_path")
        )
        enriched = dict(sample)
        if normalized_path:
            enriched["path"] = normalized_path
            enriched["normalized_path"] = normalized_path
        if sample.get("original_path") is None and sample.get("path"):
            enriched["original_path"] = sample.get("path")
        matched_event = indexed_by_path.get(normalized_path or "")
        if matched_event:
            enriched.setdefault("event_type", _nested_get(matched_event, "event.type"))
            enriched.setdefault("risk_score", matched_event.get("risk_score"))
            enriched.setdefault("tags", list(matched_event.get("tags") or []))
        enriched_sample_records.append(enriched)

    records_read = sum(int(row.get("records_read") or row.get("records_extracted") or 0) for row in shimcache_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_extracted") or row.get("records_read") or 0) for row in shimcache_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in shimcache_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in shimcache_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "shimcache_artifacts_count": len(shimcache_rows),
        "detected_shimcache_sources": sum(int(row.get("detected_shimcache_sources") or 0) for row in shimcache_rows) or len(shimcache_candidates),
        "total_shimcache_candidates": len(shimcache_candidates),
        "parser_selected": "shimcache_raw" if shimcache_rows or shimcache_candidates else None,
        "parser_status": parser_statuses[0] if len(set(parser_statuses)) == 1 and parser_statuses else (sorted(set(parser_statuses)) if parser_statuses else None),
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_failed": records_failed,
        "records_indexed": records_indexed,
        "records_extracted": sum(int(row.get("records_extracted") or row.get("records_read") or 0) for row in shimcache_rows),
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "control_sets_seen": sorted(control_sets_seen),
        "format_counts": dict(sorted(format_counts.items())),
        "by_status": dict(sorted(by_status.items())),
        "sample_by_event_type": dict(sorted(sample_by_event_type.items())),
        "sample_records": enriched_sample_records,
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "examples": sorted(dict.fromkeys(item for item in examples if item))[:10],
        "selected_artifact_types": selected_artifact_types or [],
        "not_selected_candidates_count_by_category": dict(sorted(not_selected_candidates_count_by_category.items())),
    }


def _build_scheduled_tasks_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    task_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "scheduled_task"
        or (
            str(row.get("parser_name") or "") in {"scheduled_task_xml", "scheduled_task_csv", "xml", "csv"}
            and "task" in str(row.get("source_file") or "").lower()
        )
    ]
    task_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "scheduled_task"]
    by_status: dict[str, int] = defaultdict(int)
    by_parser_sources: dict[str, int] = defaultdict(int)
    by_parser: dict[str, int] = defaultdict(int)
    sample_by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    sample_records: list[dict] = []
    examples: list[str] = []

    for row in task_rows:
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += 1
        for warning in row.get("warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or []:
            error_counts[str(error)] += 1
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_records) < 10:
                sample_records.append(sample)
        if row.get("source_file"):
            examples.append(str(row.get("source_file")))
    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "scheduled_task":
            continue
        sample_by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1

    records_read = sum(int(row.get("records_read") or 0) for row in task_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in task_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in task_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in task_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "scheduled_task_artifacts_count": len(task_rows),
        "detected_scheduled_task_files": len(task_candidates),
        "parser_selected": sorted(by_parser) if by_parser else None,
        "by_parser": dict(sorted(by_parser.items())),
        "by_status": dict(sorted(by_status.items())),
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "sample_by_event_type": dict(sorted(sample_by_event_type.items())),
        "sample_records": sample_records[:10],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "examples": sorted(dict.fromkeys(item for item in examples if item))[:10],
        "selected_artifact_types": selected_artifact_types or [],
    }


def _build_service_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    service_rows = [
        row
        for row in parser_audit
        if str(row.get("parser_name") or "") == "windows_service_registry"
        or str(row.get("artifact_type") or "") == "service"
    ]
    service_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "service"]
    by_status: dict[str, int] = defaultdict(int)
    sample_by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    sample_records: list[dict] = []
    examples: list[str] = []

    for row in service_rows:
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        for warning in row.get("warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or []:
            error_counts[str(error)] += 1
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_records) < 10:
                sample_records.append(sample)
        if row.get("source_file"):
            examples.append(str(row.get("source_file")))

    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "service":
            continue
        sample_by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1

    records_read = sum(int(row.get("records_read") or 0) for row in service_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in service_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in service_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in service_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "service_artifacts_count": len(service_rows),
        "detected_service_sources": len(service_candidates),
        "parser_selected": ["windows_service_registry"] if service_rows else [],
        "parser_status": dict(sorted(by_status.items())),
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "sample_by_event_type": dict(sorted(sample_by_event_type.items())),
        "sample_records": sample_records[:10],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "examples": sorted(dict.fromkeys(item for item in examples if item))[:10],
        "selected_artifact_types": selected_artifact_types or [],
    }


def _build_autoruns_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    autorun_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() in {"autorun", "autoruns"}
        or str(row.get("parser_name") or row.get("parser") or "").lower().startswith(("autoruns_", "registry_", "startup_folder"))
    ]
    autorun_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "").lower() == "autoruns"]
    autorun_events = [
        event
        for event in events
        if str(_nested_get(event, "artifact.type") or "").lower() in {"autorun", "autoruns"}
        or (str(_nested_get(event, "event.category") or "").lower() == "persistence" and bool(_nested_get(event, "persistence.mechanism")))
    ]
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()
    by_parser: dict[str, int] = defaultdict(int)
    by_mechanism: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    by_scope: dict[str, int] = defaultdict(int)
    by_enabled: dict[str, int] = defaultdict(int)
    by_signed: dict[str, int] = defaultdict(int)
    by_verified: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: list[dict] = []
    skipped_files: list[dict] = []
    records_read = records_parsed = parser_indexed = records_failed = 0

    for row in autorun_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        row_indexed = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser[parser_name] += row_indexed or int(row.get("records_parsed") or row.get("records_read") or 0)
        records_read += int(row.get("records_read") or 0)
        records_parsed += int(row.get("records_parsed") or row.get("records_read") or 0)
        parser_indexed += row_indexed
        records_failed += int(row.get("records_failed") or 0)
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            source_text = str(source_value or "").strip()
            if source_text:
                detected_sources.add(source_text)
                parsed_sources.add(source_text)
        if row.get("error"):
            parser_errors.append({"source_file": row.get("source_file"), "parser": parser_name, "error": row.get("error")})
            failed_sources.add(str(row.get("source_file") or row.get("source_path") or row.get("artifact") or "").strip())

    for candidate in autorun_candidates:
        source_text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if source_text:
            detected_sources.add(source_text)
        if candidate.get("supported") is False:
            skipped_files.append({"source_file": source_text, "parser": candidate.get("parser"), "reason": candidate.get("reason") or candidate.get("parser_status") or "not_supported"})

    for event in autorun_events:
        autoruns = event.get("autoruns") or {}
        persistence = event.get("persistence") or {}
        mechanism = str(persistence.get("mechanism") or "unknown")
        category = str(autoruns.get("category") or "Unknown")
        scope_name = str(persistence.get("scope") or "unknown")
        event_type = str(_nested_get(event, "event.type") or "unknown")
        extension = str(_nested_get(event, "file.extension") or "unknown")
        user_name = str(_nested_get(event, "user.name") or autoruns.get("user") or "unknown")
        by_mechanism[mechanism] += 1
        by_category[category] += 1
        by_scope[scope_name] += 1
        by_enabled["true" if autoruns.get("enabled") is True else "false" if autoruns.get("enabled") is False else "unknown"] += 1
        by_signed["true" if autoruns.get("signed") is True else "false" if autoruns.get("signed") is False else "unknown"] += 1
        by_verified["true" if autoruns.get("verified") is True else "false" if autoruns.get("verified") is False else "unknown"] += 1
        by_user[user_name] += 1
        by_extension[extension] += 1
        by_event_type[event_type] += 1
        for flag in event.get("data_quality") or []:
            data_quality_counts[str(flag)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": max(parser_indexed, len(autorun_events)),
        "records_failed": records_failed,
        "autorun_sources_detected": len(detected_sources),
        "autorun_sources_parsed": len(parsed_sources),
        "autorun_sources_failed": len({item for item in failed_sources if item}),
        "by_parser": dict(sorted(by_parser.items())),
        "by_mechanism": dict(sorted(by_mechanism.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_scope": dict(sorted(by_scope.items())),
        "by_enabled": dict(sorted(by_enabled.items())),
        "by_signed": dict(sorted(by_signed.items())),
        "by_verified": dict(sorted(by_verified.items())),
        "by_user": dict(sorted(by_user.items())),
        "by_extension": dict(sorted(by_extension.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "run_key_count": by_mechanism.get("run_key", 0),
        "runonce_count": by_mechanism.get("runonce_key", 0),
        "startup_folder_count": by_mechanism.get("startup_folder", 0),
        "winlogon_count": by_mechanism.get("winlogon_shell", 0) + by_mechanism.get("winlogon_userinit", 0),
        "ifeo_count": by_mechanism.get("ifeo_debugger", 0),
        "appinit_count": by_mechanism.get("appinit_dll", 0) + by_mechanism.get("appcert_dll", 0),
        "lsa_count": by_mechanism.get("lsa_package", 0),
        "print_monitor_count": by_mechanism.get("print_monitor", 0),
        "lolbin_autorun_count": suspicious_reason_counts.get("Autorun uses LOLBin", 0),
        "powershell_autorun_count": suspicious_reason_counts.get("Autorun uses PowerShell", 0),
        "user_writable_autorun_count": suspicious_reason_counts.get("Autorun points to user-writable path", 0),
        "unsigned_autorun_count": suspicious_reason_counts.get("Autorun unsigned or unverified binary", 0),
        "disabled_count": by_enabled.get("false", 0),
        "high_risk_count": sum(1 for event in autorun_events if int(event.get("risk_score") or 0) >= 80),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": parser_errors[:20],
        "skipped_files": skipped_files[:20],
    }


def _build_autoruns_sample_events(events: list[dict]) -> list[dict]:
    autorun_events = [
        event for event in events
        if str(_nested_get(event, "artifact.type") or "").lower() in {"autorun", "autoruns"}
    ]
    if not autorun_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in enumerate(autorun_events):
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "run_key", 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "startup_folder", 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "ifeo_debugger", 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") in {"winlogon_shell", "winlogon_userinit"}, 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "appinit_dll", 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "lsa_package", 2)
    add_matching(lambda item: str(_nested_get(item, "persistence.mechanism") or "") == "print_monitor", 2)
    add_matching(lambda item: int(item.get("risk_score") or 0) >= 80, 4)
    for index, event in enumerate(autorun_events):
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_bits_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    bits_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "bits"
        or str(row.get("parser_name") or row.get("parser") or "").startswith("bits")
    ]
    bits_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "bits"]
    by_parser: dict[str, int] = defaultdict(int)
    by_artifact_type: dict[str, int] = defaultdict(int)
    by_state: dict[str, int] = defaultdict(int)
    by_owner: dict[str, int] = defaultdict(int)
    by_domain: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    suspicious_counts: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    sample_events: list[dict] = []
    skipped_files: list[dict] = []
    detected_sources: set[str] = set()
    bits_sources_parsed: set[str] = set()
    bits_sources_failed: set[str] = set()
    download_count = complete_count = in_progress_count = error_count = notify_command_count = 0
    executable_download_count = script_download_count = archive_download_count = direct_ip_url_count = http_download_count = suspicious_download_count = 0

    for row in bits_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        by_parser[parser_name] += 1
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        if row.get("by_state"):
            for key, value in (row.get("by_state") or {}).items():
                by_state[str(key)] += int(value or 0)
        if row.get("by_owner"):
            for key, value in (row.get("by_owner") or {}).items():
                by_owner[str(key)] += int(value or 0)
        if row.get("by_domain"):
            for key, value in (row.get("by_domain") or {}).items():
                by_domain[str(key)] += int(value or 0)
        if row.get("by_extension"):
            for key, value in (row.get("by_extension") or {}).items():
                by_extension[str(key)] += int(value or 0)
        if row.get("by_event_type"):
            for key, value in (row.get("by_event_type") or {}).items():
                by_event_type[str(key)] += int(value or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                bits_sources_parsed.add(text)
                if int(row.get("records_failed") or 0) > 0:
                    bits_sources_failed.add(text)
        if int(row.get("records_indexed") or row.get("events_indexed") or 0) == 0:
            skipped_files.append(
                {
                    "source_file": row.get("source_file"),
                    "parser": parser_name,
                    "parser_status": row.get("parser_status") or row.get("status"),
                    "warnings": list(row.get("warnings") or row.get("parse_warnings") or []),
                    "reason": ", ".join(str(item) for item in (row.get("warnings") or row.get("parse_warnings") or ["no_records_indexed"])[:3]),
                }
            )
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_events) < 10:
                sample_events.append(sample)
            if isinstance(sample, dict):
                text = str(sample.get("source_file") or "").strip()
                if text:
                    detected_sources.add(text)

    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "bits":
            continue
        bits = event.get("bits") or {}
        download = event.get("download") or {}
        file = event.get("file") or {}
        network = event.get("network") or {}
        by_event_type[str((event.get("event") or {}).get("type") or "unknown")] += 1
        by_artifact_type[str(bits.get("artifact_type") or "bits_job")] += 1
        if bits.get("state"):
            by_state[str(bits.get("state"))] += 1
        if bits.get("type"):
            by_type[str(bits.get("type"))] += 1
        if bits.get("owner"):
            by_owner[str(bits.get("owner"))] += 1
        if network.get("domain"):
            by_domain[str(network.get("domain"))] += 1
        if file.get("extension"):
            by_extension[str(file.get("extension"))] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_counts[str(reason)] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        if str((event.get("event") or {}).get("type") or "") in {"file_downloaded", "download_started", "download_interrupted"}:
            download_count += 1
        state = str(download.get("state") or "")
        if state == "complete":
            complete_count += 1
        elif state == "in_progress":
            in_progress_count += 1
        elif state in {"error", "interrupted", "cancelled"}:
            error_count += 1
        if bits.get("notify_cmd_line"):
            notify_command_count += 1
        ext = str(file.get("extension") or "").lower()
        if ext in {".exe", ".dll", ".scr", ".msi", ".com"}:
            executable_download_count += 1
        elif ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
            script_download_count += 1
        elif ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
            archive_download_count += 1
        if "BITS URL uses direct IP" in (event.get("suspicious_reasons") or []):
            direct_ip_url_count += 1
        if "BITS download over HTTP" in (event.get("suspicious_reasons") or []):
            http_download_count += 1
        if event.get("suspicious_reasons"):
            suspicious_download_count += 1
        for source_value in (
            bits.get("source_file"),
            artifact.get("source_path"),
            event.get("source_file"),
        ):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in bits_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)

    records_read = sum(int(row.get("records_read") or 0) for row in bits_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in bits_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in bits_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in bits_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "parser": sorted(by_parser) if by_parser else [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "bits_records_read": records_read,
        "bits_records_indexed": records_indexed,
        "bits_sources_detected": len(detected_sources),
        "bits_sources_parsed": len(bits_sources_parsed),
        "bits_sources_failed": len(bits_sources_failed),
        "detected_bits_sources": len(detected_sources),
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "by_parser": dict(sorted(by_parser.items())),
        "by_artifact_type": dict(sorted(by_artifact_type.items())),
        "by_state": dict(sorted(by_state.items())),
        "by_type": dict(sorted(by_type.items())),
        "by_owner": dict(sorted(by_owner.items())),
        "by_domain": dict(sorted(by_domain.items())),
        "by_extension": dict(sorted(by_extension.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_status": dict(sorted(by_status.items())),
        "download_count": download_count,
        "complete_count": complete_count,
        "in_progress_count": in_progress_count,
        "error_count": error_count,
        "notify_command_count": notify_command_count,
        "executable_download_count": executable_download_count,
        "script_download_count": script_download_count,
        "archive_download_count": archive_download_count,
        "direct_ip_url_count": direct_ip_url_count,
        "http_download_count": http_download_count,
        "suspicious_download_count": suspicious_download_count,
        "sample_events": sample_events[:10],
        "suspicious_counts": dict(sorted(suspicious_counts.items())),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "parser_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "skipped_files": skipped_files[:20],
    }


def _build_recycle_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    recycle_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "recycle_bin"
        or "recycle" in str(row.get("parser_name") or row.get("parser") or "").lower()
        or str(row.get("parser_name") or row.get("parser") or "").lower() in {"raw_i_file", "raw_r_file", "rbcmd", "csv"}
    ]
    recycle_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "recycle_bin"]
    by_parser: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    by_sid: dict[str, int] = defaultdict(int)
    by_drive_letter: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    skipped_files: list[dict] = []
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()
    deleted_count = executable_deleted_count = script_deleted_count = archive_deleted_count = 0
    suspicious_deleted_count = incomplete_pair_count = missing_i_file_count = missing_r_file_count = 0

    for row in recycle_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        by_parser[parser_name] += 1
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                parsed_sources.add(text)
                if int(row.get("records_failed") or 0) > 0:
                    failed_sources.add(text)
        if int(row.get("records_failed") or 0) > 0:
            skipped_files.append(
                {
                    "source_file": row.get("source_file"),
                    "parser": parser_name,
                    "reason": ", ".join(str(item) for item in (row.get("errors") or row.get("parser_errors") or ["records_failed"])[:3]),
                }
            )

    for event in events:
        if str(_nested_get(event, "artifact.type") or "") != "recycle_bin":
            continue
        recycle = event.get("recycle") or {}
        file = event.get("file") or {}
        user = event.get("user") or {}
        volume = event.get("volume") or {}
        event_type = str(_nested_get(event, "event.type") or "unknown")
        by_event_type[event_type] += 1
        if file.get("extension"):
            by_extension[str(file.get("extension"))] += 1
        if user.get("name"):
            by_user[str(user.get("name"))] += 1
        if user.get("sid"):
            by_sid[str(user.get("sid"))] += 1
        if volume.get("drive_letter") or recycle.get("drive_letter"):
            by_drive_letter[str(volume.get("drive_letter") or recycle.get("drive_letter"))] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
        if event_type == "file_deleted":
            deleted_count += 1
        if "Deleted executable found in Recycle Bin" in (event.get("suspicious_reasons") or []):
            executable_deleted_count += 1
        if "Deleted script found in Recycle Bin" in (event.get("suspicious_reasons") or []):
            script_deleted_count += 1
        if "Deleted archive found in Recycle Bin" in (event.get("suspicious_reasons") or []):
            archive_deleted_count += 1
        if event.get("suspicious_reasons"):
            suspicious_deleted_count += 1
        if "recycle_pair_incomplete" in (event.get("data_quality") or []):
            incomplete_pair_count += 1
        if "missing_info_file" in (event.get("data_quality") or []):
            missing_i_file_count += 1
        if "missing_recovery_file" in (event.get("data_quality") or []):
            missing_r_file_count += 1
        for source_value in (recycle.get("source_file"), _nested_get(event, "artifact.source_path"), event.get("source_file")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in recycle_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)
        if candidate.get("supported") is False:
            skipped_files.append(
                {
                    "source_file": candidate.get("normalized_windows_path") or candidate.get("path"),
                    "parser": candidate.get("parser"),
                    "reason": candidate.get("reason") or candidate.get("parser_status") or "not_supported",
                }
            )

    records_read = sum(int(row.get("records_read") or 0) for row in recycle_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in recycle_rows)
    parser_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in recycle_rows)
    event_indexed = sum(1 for event in events if str(_nested_get(event, "artifact.type") or "") == "recycle_bin")
    records_indexed = max(parser_indexed, event_indexed)
    records_failed = sum(int(row.get("records_failed") or 0) for row in recycle_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "recycle_sources_detected": len(detected_sources),
        "recycle_sources_parsed": len(parsed_sources),
        "recycle_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_extension": dict(sorted(by_extension.items())),
        "by_user": dict(sorted(by_user.items())),
        "by_sid": dict(sorted(by_sid.items())),
        "by_drive_letter": dict(sorted(by_drive_letter.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "deleted_count": deleted_count,
        "executable_deleted_count": executable_deleted_count,
        "script_deleted_count": script_deleted_count,
        "archive_deleted_count": archive_deleted_count,
        "suspicious_deleted_count": suspicious_deleted_count,
        "incomplete_pair_count": incomplete_pair_count,
        "missing_i_file_count": missing_i_file_count,
        "missing_r_file_count": missing_r_file_count,
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "skipped_files": skipped_files[:20],
    }


def _build_mft_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    mft_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "mft"
        or "mft" in str(row.get("parser_name") or row.get("parser") or "").lower()
    ]
    mft_candidates = [
        candidate
        for candidate in discovery_candidates
        if str(candidate.get("artifact_type") or "").lower() in {"mft", "ntfs_raw"}
        or str(candidate.get("category") or "").lower() == "filesystem"
    ]
    mft_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "mft"]
    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    by_drive_letter: dict[str, int] = defaultdict(int)
    by_deleted: dict[str, int] = defaultdict(int)
    by_in_use: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: list[dict] = []
    skipped_files: list[dict] = []
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()

    records_read = records_parsed = parser_indexed = records_failed = 0
    for row in mft_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        row_indexed = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser[parser_name] += row_indexed or int(row.get("records_parsed") or row.get("records_read") or 0)
        records_read += int(row.get("records_read") or 0)
        records_parsed += int(row.get("records_parsed") or row.get("records_read") or 0)
        parser_indexed += row_indexed
        records_failed += int(row.get("records_failed") or 0)
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                parsed_sources.add(text)
                if int(row.get("records_failed") or 0) > 0:
                    failed_sources.add(text)
        for error in row.get("parser_errors") or row.get("errors") or []:
            parser_errors.append({"source_file": row.get("source_file"), "parser": parser_name, "error": str(error)})
        if int(row.get("records_failed") or 0) > 0:
            skipped_files.append({"source_file": row.get("source_file"), "parser": parser_name, "reason": "records_failed"})

    observed_count = deleted_count = ads_count = zone_identifier_count = 0
    executable_count = script_count = archive_count = suspicious_path_count = 0
    double_extension_count = timestamp_anomaly_count = 0
    for event in mft_events:
        file = event.get("file") or {}
        mft = event.get("mft") or {}
        user = event.get("user") or {}
        volume = event.get("volume") or {}
        event_type = str(_nested_get(event, "event.type") or "unknown")
        by_event_type[event_type] += 1
        extension = str(file.get("extension") or "unknown")
        by_extension[extension] += 1
        if user.get("name"):
            by_user[str(user.get("name"))] += 1
        if volume.get("drive_letter"):
            by_drive_letter[str(volume.get("drive_letter"))] += 1
        by_deleted["true" if file.get("deleted") is True or mft.get("is_deleted") is True else "false"] += 1
        by_in_use["true" if mft.get("in_use") is True else "false" if mft.get("in_use") is False else "unknown"] += 1
        if event_type == "file_observed":
            observed_count += 1
        elif event_type == "file_deleted":
            deleted_count += 1
        elif event_type == "alternate_data_stream":
            ads_count += 1
        if extension in {".exe", ".dll", ".msi", ".scr"}:
            executable_count += 1
        if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
            script_count += 1
        if extension in {".zip", ".rar", ".7z", ".iso", ".img"}:
            archive_count += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
        if any("suspicious path" in str(reason).lower() for reason in (event.get("suspicious_reasons") or [])):
            suspicious_path_count += 1
        if "MFT Zone.Identifier observed" in (event.get("suspicious_reasons") or []):
            zone_identifier_count += 1
        if "MFT double extension" in (event.get("suspicious_reasons") or []):
            double_extension_count += 1
        if "MFT timestamp anomaly" in (event.get("suspicious_reasons") or []) or "MFT possible timestomping" in (event.get("suspicious_reasons") or []):
            timestamp_anomaly_count += 1
        for source_value in (event.get("source_file"), _nested_get(event, "artifact.source_path")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in mft_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)
        if candidate.get("supported") is False:
            skipped_files.append({"source_file": candidate.get("normalized_windows_path") or candidate.get("path"), "parser": candidate.get("parser"), "reason": candidate.get("reason") or candidate.get("parser_status") or "not_supported"})

    records_indexed = max(parser_indexed, len(mft_events))
    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "mft_sources_detected": len(detected_sources),
        "mft_sources_parsed": len(parsed_sources),
        "mft_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_extension": dict(sorted(by_extension.items())),
        "by_user": dict(sorted(by_user.items())),
        "by_drive_letter": dict(sorted(by_drive_letter.items())),
        "by_deleted": dict(sorted(by_deleted.items())),
        "by_in_use": dict(sorted(by_in_use.items())),
        "observed_count": observed_count,
        "deleted_count": deleted_count,
        "ads_count": ads_count,
        "zone_identifier_count": zone_identifier_count,
        "executable_count": executable_count,
        "script_count": script_count,
        "archive_count": archive_count,
        "suspicious_path_count": suspicious_path_count,
        "double_extension_count": double_extension_count,
        "timestamp_anomaly_count": timestamp_anomaly_count,
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": parser_errors[:20],
        "skipped_files": skipped_files[:20],
    }


def _build_mft_sample_events(events: list[dict]) -> list[dict]:
    mft_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "mft"]
    if not mft_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in enumerate(mft_events):
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "alternate_data_stream", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "file_deleted", 3)
    add_matching(lambda item: "MFT possible timestomping" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "MFT double extension" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "MFT file in Startup folder" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "file_observed", 3)
    for index, event in enumerate(mft_events):
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_srum_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    srum_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "srum"
        or "srum" in str(row.get("parser_name") or row.get("parser") or "").lower()
    ]
    srum_candidates = [
        candidate
        for candidate in discovery_candidates
        if str(candidate.get("artifact_type") or "").lower() in {"srum", "srum_database", "srum_checkpoint"}
        or str(candidate.get("category") or "").lower() == "network_activity"
    ]
    by_parser: dict[str, int] = defaultdict(int)
    by_table: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_application: dict[str, int] = defaultdict(int)
    by_user_sid: dict[str, int] = defaultdict(int)
    by_network_profile: dict[str, int] = defaultdict(int)
    by_interface: dict[str, int] = defaultdict(int)
    by_direction: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    skipped_files: list[dict] = []
    parser_errors: list[dict] = []
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()

    records_read = records_parsed = parser_indexed = records_failed = 0
    for row in srum_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        row_indexed = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser[parser_name] += row_indexed or int(row.get("records_parsed") or row.get("records_read") or 1)
        records_read += int(row.get("records_read") or 0)
        records_parsed += int(row.get("records_parsed") or row.get("records_read") or 0)
        parser_indexed += row_indexed
        records_failed += int(row.get("records_failed") or 0)
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                parsed_sources.add(text)
                if int(row.get("records_failed") or 0) > 0:
                    failed_sources.add(text)
        for error in row.get("parser_errors") or row.get("errors") or []:
            parser_errors.append({"source_file": row.get("source_file"), "parser": parser_name, "error": str(error)})
        if int(row.get("records_failed") or 0) > 0:
            skipped_files.append({"source_file": row.get("source_file"), "parser": parser_name, "reason": "records_failed"})
        for key, count in (row.get("by_table") or {}).items():
            by_table[str(key)] += int(count or 0)
        for key, count in (row.get("by_event_type") or {}).items():
            by_event_type[str(key)] += int(count or 0)
        for key, count in (row.get("by_direction") or {}).items():
            by_direction[str(key)] += int(count or 0)
        for key, count in (row.get("by_network_profile") or {}).items():
            by_network_profile[str(key)] += int(count or 0)
        for key, count in (row.get("by_interface") or {}).items():
            by_interface[str(key)] += int(count or 0)
        for warning in row.get("parse_warnings") or []:
            data_quality_counts[str(warning)] += 1

    srum_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "srum"]
    for event in srum_events:
        srum = event.get("srum") or {}
        network = event.get("network") or {}
        process = event.get("process") or {}
        user = event.get("user") or {}
        event_type = str(_nested_get(event, "event.type") or "unknown")
        by_event_type[event_type] += 1
        table_name = str(srum.get("table") or srum.get("artifact_type") or "unknown")
        by_table[table_name] += 1
        application = str(srum.get("app_name") or srum.get("application") or process.get("name") or "unknown")
        by_application[application] += 1
        if user.get("sid") or srum.get("user_sid"):
            by_user_sid[str(user.get("sid") or srum.get("user_sid"))] += 1
        if srum.get("network_profile"):
            by_network_profile[str(srum.get("network_profile"))] += 1
        if srum.get("interface_guid") or srum.get("interface_luid"):
            by_interface[str(srum.get("interface_guid") or srum.get("interface_luid"))] += 1
        by_direction[str(network.get("direction") or "unknown")] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
        for source_value in (srum.get("source_file"), _nested_get(event, "artifact.source_path"), event.get("source_file")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in srum_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)
        if candidate.get("supported") is False:
            skipped_files.append(
                {
                    "source_file": candidate.get("normalized_windows_path") or candidate.get("path"),
                    "parser": candidate.get("parser"),
                    "reason": candidate.get("reason") or candidate.get("parser_status") or "not_supported",
                }
            )

    records_indexed = max(parser_indexed, len(srum_events))
    network_usage_count = sum(1 for event in srum_events if str(_nested_get(event, "event.type") or "") == "network_usage")
    connectivity_count = sum(1 for event in srum_events if str(_nested_get(event, "event.type") or "") == "network_connectivity_observed")
    app_resource_count = sum(1 for event in srum_events if str(_nested_get(event, "event.type") or "") == "app_resource_usage")
    energy_count = sum(1 for event in srum_events if str(_nested_get(event, "event.type") or "") == "energy_usage")
    total_bytes_sent = sum(int(_nested_get(event, "network.bytes_sent") or _nested_get(event, "srum.bytes_sent") or 0) for event in srum_events)
    total_bytes_received = sum(int(_nested_get(event, "network.bytes_received") or _nested_get(event, "srum.bytes_received") or 0) for event in srum_events)
    total_bytes = sum(int(_nested_get(event, "network.bytes_total") or _nested_get(event, "srum.bytes_total") or 0) for event in srum_events)
    high_outbound_count = sum(1 for event in srum_events if "high_upload" in set(event.get("tags") or []))
    upload_heavy_count = sum(1 for event in srum_events if "upload_heavy" in set(event.get("tags") or []))
    scripting_process_network_count = sum(1 for event in srum_events if "scripting_process" in set(event.get("tags") or []))
    lolbin_network_count = sum(1 for event in srum_events if "lolbin_network" in set(event.get("tags") or []))
    user_writable_app_network_count = sum(1 for event in srum_events if "user_writable_app" in set(event.get("tags") or []))
    zero_bytes_count = sum(1 for event in srum_events if "srum_zero_bytes" in set(event.get("data_quality") or []))

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "srum_sources_detected": len(detected_sources),
        "srum_sources_parsed": len(parsed_sources),
        "srum_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_table": dict(sorted(by_table.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_application": dict(sorted(by_application.items())),
        "by_user_sid": dict(sorted(by_user_sid.items())),
        "by_network_profile": dict(sorted(by_network_profile.items())),
        "by_interface": dict(sorted(by_interface.items())),
        "by_direction": dict(sorted(by_direction.items())),
        "network_usage_count": network_usage_count,
        "connectivity_count": connectivity_count,
        "app_resource_count": app_resource_count,
        "energy_count": energy_count,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "total_bytes": total_bytes,
        "high_outbound_count": high_outbound_count,
        "upload_heavy_count": upload_heavy_count,
        "scripting_process_network_count": scripting_process_network_count,
        "lolbin_network_count": lolbin_network_count,
        "user_writable_app_network_count": user_writable_app_network_count,
        "zero_bytes_count": zero_bytes_count,
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": parser_errors[:20],
        "skipped_files": skipped_files[:20],
    }


def _build_usb_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    usb_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "usb"
        or str(row.get("parser_name") or row.get("parser") or "").startswith("usb")
        or str(row.get("parser_name") or row.get("parser") or "") in {"setupapi", "registry_usb"}
    ]
    usb_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "usb"]
    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_device_type: dict[str, int] = defaultdict(int)
    by_vendor: dict[str, int] = defaultdict(int)
    by_product: dict[str, int] = defaultdict(int)
    by_vid_pid: dict[str, int] = defaultdict(int)
    by_serial_presence: dict[str, int] = defaultdict(int)
    by_drive_letter: dict[str, int] = defaultdict(int)
    by_volume_serial: dict[str, int] = defaultdict(int)
    parser_by_event_type: dict[str, int] = defaultdict(int)
    parser_by_device_type: dict[str, int] = defaultdict(int)
    parser_by_vendor: dict[str, int] = defaultdict(int)
    parser_by_product: dict[str, int] = defaultdict(int)
    parser_by_vid_pid: dict[str, int] = defaultdict(int)
    parser_by_serial_presence: dict[str, int] = defaultdict(int)
    parser_by_drive_letter: dict[str, int] = defaultdict(int)
    parser_by_volume_serial: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    skipped_files: list[dict] = []
    empty_sources: list[dict] = []
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()
    connected_count = disconnected_count = installed_count = observed_count = 0
    mass_storage_count = portable_device_count = hid_count = missing_serial_count = 0
    setupapi_count = registry_count = evtx_count = mounted_volume_count = 0
    parser_connected_count = parser_disconnected_count = parser_installed_count = parser_observed_count = 0
    parser_mass_storage_count = parser_portable_device_count = parser_missing_serial_count = 0
    parser_setupapi_count = parser_registry_count = parser_evtx_count = parser_mounted_volume_count = 0

    for row in usb_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        by_parser[parser_name] += 1
        for key, value in (row.get("by_event_type") or {}).items():
            parser_by_event_type[str(key)] += int(value or 0)
        for key, value in (row.get("by_device_type") or {}).items():
            parser_by_device_type[str(key)] += int(value or 0)
        for key, value in (row.get("by_vendor") or {}).items():
            parser_by_vendor[str(key)] += int(value or 0)
        for key, value in (row.get("by_product") or {}).items():
            parser_by_product[str(key)] += int(value or 0)
        for key, value in (row.get("by_vid_pid") or {}).items():
            parser_by_vid_pid[str(key)] += int(value or 0)
        for key, value in (row.get("by_serial_presence") or {}).items():
            parser_by_serial_presence[str(key)] += int(value or 0)
        for key, value in (row.get("by_drive_letter") or {}).items():
            parser_by_drive_letter[str(key)] += int(value or 0)
        for key, value in (row.get("by_volume_serial") or {}).items():
            parser_by_volume_serial[str(key)] += int(value or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1

        parser_connected_count += int(row.get("connected_count") or 0)
        parser_disconnected_count += int(row.get("disconnected_count") or 0)
        parser_installed_count += int(row.get("installed_count") or 0)
        parser_observed_count += int(row.get("observed_count") or 0)
        parser_mass_storage_count += int(row.get("usb_storage_count") or 0)
        parser_portable_device_count += int(row.get("portable_device_count") or 0)
        parser_missing_serial_count += int(row.get("missing_serial") or 0)
        parser_setupapi_count += int(row.get("setupapi_usb_blocks") or 0)
        parser_mounted_volume_count += int(row.get("mounted_device_count") or 0)
        if parser_name.startswith("usb_evtx"):
            parser_evtx_count += int(row.get("records_indexed") or row.get("events_indexed") or 0)
        elif parser_name.startswith("usb_setupapi"):
            parser_setupapi_count += int(row.get("records_indexed") or row.get("events_indexed") or 0)
        else:
            parser_registry_count += int(row.get("records_indexed") or row.get("events_indexed") or 0)

        source_text = str(row.get("source_file") or row.get("artifact") or "").strip()
        if source_text:
            detected_sources.add(source_text)
            parsed_sources.add(source_text)
            if int(row.get("records_failed") or 0) > 0:
                failed_sources.add(source_text)
        if int(row.get("records_indexed") or row.get("events_indexed") or 0) == 0:
            empty_sources.append(
                {
                    "source_file": row.get("source_file"),
                    "parser": parser_name,
                    "status": "completed_empty",
                    "records_read": int(row.get("records_read") or 0),
                    "records_indexed": int(row.get("records_indexed") or row.get("events_indexed") or 0),
                }
            )

    for event in events:
        if str(_nested_get(event, "artifact.type") or "") != "usb":
            continue
        usb = event.get("usb") or {}
        volume = event.get("volume") or {}
        parser_name = str(_nested_get(event, "artifact.parser") or "")
        event_type = str(_nested_get(event, "event.type") or "unknown")
        by_event_type[event_type] += 1
        by_device_type[str(usb.get("device_type") or "unknown")] += 1
        if usb.get("vendor"):
            by_vendor[str(usb.get("vendor"))] += 1
        if usb.get("product"):
            by_product[str(usb.get("product"))] += 1
        if usb.get("vid") or usb.get("pid"):
            by_vid_pid[f"{usb.get('vid') or 'unknown'}:{usb.get('pid') or 'unknown'}"] += 1
        by_serial_presence["present" if usb.get("serial") else "missing"] += 1
        if volume.get("drive_letter"):
            by_drive_letter[str(volume.get("drive_letter"))] += 1
            mounted_volume_count += 1
        if volume.get("serial"):
            by_volume_serial[str(volume.get("serial"))] += 1
        if usb.get("device_type") == "hid":
            hid_count += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        if "USB mass storage device observed" in (event.get("suspicious_reasons") or []):
            mass_storage_count += 1
        if "USB portable device observed" in (event.get("suspicious_reasons") or []):
            portable_device_count += 1
        if "missing_serial" in (event.get("data_quality") or []):
            missing_serial_count += 1
        if event_type == "usb_connected":
            connected_count += 1
        elif event_type == "usb_disconnected":
            disconnected_count += 1
        elif event_type == "usb_installed":
            installed_count += 1
        elif event_type == "usb_observed":
            observed_count += 1
        if parser_name == "usb_setupapi":
            setupapi_count += 1
        elif parser_name == "usb_evtx":
            evtx_count += 1
        else:
            registry_count += 1
        for source_value in (usb.get("source_file"), _nested_get(event, "artifact.source_path"), event.get("source_file")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in usb_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)
        if candidate.get("supported") is False:
            skipped_files.append(
                {
                    "source_file": candidate.get("normalized_windows_path") or candidate.get("path"),
                    "parser": candidate.get("parser"),
                    "reason": candidate.get("reason") or candidate.get("parser_status") or "not_supported",
                }
            )

    records_read = sum(int(row.get("records_read") or 0) for row in usb_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in usb_rows)
    parser_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in usb_rows)
    event_indexed = sum(1 for event in events if str(_nested_get(event, "artifact.type") or "") == "usb")
    records_indexed = max(parser_indexed, event_indexed)
    records_failed = sum(int(row.get("records_failed") or 0) for row in usb_rows)
    if not by_event_type:
        by_event_type = parser_by_event_type
    if not by_device_type:
        by_device_type = parser_by_device_type
    if not by_vendor:
        by_vendor = parser_by_vendor
    if not by_product:
        by_product = parser_by_product
    if not by_vid_pid:
        by_vid_pid = parser_by_vid_pid
    if not by_serial_presence:
        by_serial_presence = parser_by_serial_presence
    if not by_drive_letter:
        by_drive_letter = parser_by_drive_letter
    if not by_volume_serial:
        by_volume_serial = parser_by_volume_serial
    if event_indexed == 0:
        connected_count = parser_connected_count
        disconnected_count = parser_disconnected_count
        installed_count = parser_installed_count
        observed_count = parser_observed_count
        mass_storage_count = parser_mass_storage_count
        portable_device_count = parser_portable_device_count
        missing_serial_count = parser_missing_serial_count
        setupapi_count = parser_setupapi_count
        registry_count = parser_registry_count
        evtx_count = parser_evtx_count
        mounted_volume_count = parser_mounted_volume_count

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "usb_sources_detected": len(detected_sources),
        "usb_sources_parsed": len(parsed_sources),
        "usb_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_device_type": dict(sorted(by_device_type.items())),
        "by_vendor": dict(sorted(by_vendor.items())),
        "by_product": dict(sorted(by_product.items())),
        "by_vid_pid": dict(sorted(by_vid_pid.items())),
        "by_serial_presence": dict(sorted(by_serial_presence.items())),
        "by_drive_letter": dict(sorted(by_drive_letter.items())),
        "by_volume_serial": dict(sorted(by_volume_serial.items())),
        "connected_count": connected_count,
        "disconnected_count": disconnected_count,
        "installed_count": installed_count,
        "observed_count": observed_count,
        "mass_storage_count": mass_storage_count,
        "portable_device_count": portable_device_count,
        "hid_count": hid_count,
        "missing_serial_count": missing_serial_count,
        "setupapi_count": setupapi_count,
        "registry_count": registry_count,
        "evtx_count": evtx_count,
        "mounted_volume_count": mounted_volume_count,
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "skipped_files": skipped_files[:20],
        "empty_sources": empty_sources[:20],
    }


def _build_usb_sample_events(events: list[dict]) -> list[dict]:
    usb_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "usb"]
    if not usb_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in usb_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: "USB mass storage device observed" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "usb_installed", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "usb_connected", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "usb_disconnected", 2)
    add_matching(lambda item: bool(_nested_get(item, "volume.drive_letter")), 3)
    for event in usb_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_recycle_sample_events(events: list[dict]) -> list[dict]:
    recycle_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "recycle_bin"]
    if not recycle_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in recycle_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: "Deleted executable found in Recycle Bin" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: "Deleted script found in Recycle Bin" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: "recycle_pair_incomplete" in (item.get("data_quality") or []), 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "file_deleted", 5)
    for event in recycle_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_srum_sample_events(events: list[dict]) -> list[dict]:
    srum_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "srum"]
    if not srum_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in srum_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: "SRUM network activity by scripting process" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: "SRUM network activity by LOLBin" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: "SRUM high outbound bytes" in (item.get("suspicious_reasons") or []), 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "network_connectivity_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "network_usage", 4)
    for event in srum_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_wlan_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    wlan_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "wlan"
        or "wlan" in str(row.get("parser_name") or row.get("parser") or "").lower()
    ]
    wlan_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "wlan"]
    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_ssid: dict[str, int] = defaultdict(int)
    by_authentication: dict[str, int] = defaultdict(int)
    by_encryption: dict[str, int] = defaultdict(int)
    by_interface: dict[str, int] = defaultdict(int)
    by_bssid: dict[str, int] = defaultdict(int)
    event_parser_counts: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: list[dict] = []
    skipped_files: list[dict] = []
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()
    records_read = records_parsed = parser_indexed = records_failed = 0

    for row in wlan_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        row_indexed = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser[parser_name] += row_indexed or int(row.get("records_parsed") or row.get("records_read") or 1)
        records_read += int(row.get("records_read") or 0)
        records_parsed += int(row.get("records_parsed") or row.get("records_read") or 0)
        parser_indexed += row_indexed
        records_failed += int(row.get("records_failed") or 0)
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                parsed_sources.add(text)
        if int(row.get("records_failed") or 0) > 0:
            skipped_files.append({"source_file": row.get("source_file"), "parser": parser_name, "reason": "records_failed"})
            for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
                text = str(source_value or "").strip()
                if text:
                    failed_sources.add(text)
        for error in row.get("parser_errors") or row.get("errors") or []:
            parser_errors.append({"source_file": row.get("source_file"), "parser": parser_name, "error": str(error)})

    for candidate in discovery_candidates:
        if "wlan" in str(candidate.get("artifact_type") or "").lower():
            text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
            if text:
                detected_sources.add(text)

    for event in wlan_events:
        wlan = event.get("wlan") or {}
        parser_name = str(_nested_get(event, "artifact.parser") or "unknown")
        event_parser_counts[parser_name] += 1
        event_type = str(_nested_get(event, "event.type") or "unknown")
        by_event_type[event_type] += 1
        if wlan.get("ssid"):
            by_ssid[str(wlan.get("ssid"))] += 1
        if wlan.get("authentication"):
            by_authentication[str(wlan.get("authentication"))] += 1
        if wlan.get("encryption"):
            by_encryption[str(wlan.get("encryption"))] += 1
        if wlan.get("interface_guid") or wlan.get("interface_description"):
            by_interface[str(wlan.get("interface_guid") or wlan.get("interface_description"))] += 1
        if wlan.get("bssid"):
            by_bssid[str(wlan.get("bssid"))] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1

    for parser_name, count in event_parser_counts.items():
        if parser_name not in by_parser:
            by_parser[parser_name] = count

    return {
        "aggregation_scope": scope or "case",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": max(parser_indexed, len(wlan_events)),
        "records_failed": records_failed,
        "wlan_sources_detected": len(detected_sources),
        "wlan_sources_parsed": len(parsed_sources),
        "wlan_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_ssid": dict(sorted(by_ssid.items())),
        "by_authentication": dict(sorted(by_authentication.items())),
        "by_encryption": dict(sorted(by_encryption.items())),
        "by_interface": dict(sorted(by_interface.items())),
        "by_bssid": dict(sorted(by_bssid.items())),
        "profile_count": by_event_type.get("wlan_profile", 0),
        "connected_count": by_event_type.get("wlan_connected", 0),
        "disconnected_count": by_event_type.get("wlan_disconnected", 0),
        "connection_failed_count": by_event_type.get("wlan_connection_failed", 0),
        "open_network_count": suspicious_reason_counts.get("WLAN open network profile", 0),
        "weak_encryption_count": suspicious_reason_counts.get("WLAN weak encryption", 0),
        "key_material_redacted_count": data_quality_counts.get("wlan_key_material_redacted", 0),
        "suspicious_ssid_count": suspicious_reason_counts.get("WLAN suspicious SSID", 0),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": parser_errors,
        "skipped_files": skipped_files,
    }


def _build_wlan_sample_events(events: list[dict]) -> list[dict]:
    wlan_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "wlan"]
    if not wlan_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()
    indexed_events = list(enumerate(wlan_events))

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in indexed_events:
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: "WLAN open network profile" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "WLAN weak encryption" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "WLAN key material present and redacted" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "wlan_connection_failed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "wlan_connected", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "wlan_disconnected", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "wlan_profile", 3)
    for index, event in indexed_events:
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_dns_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    dns_rows = [
        row for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "dns"
        or str(row.get("parser_name") or row.get("parser") or "").lower() in {"dns_csv", "dns_json", "dns_jsonl", "dns_evtx", "dns_raw"}
    ]
    dns_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "dns"]
    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_record_type: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    by_domain: dict[str, int] = defaultdict(int)
    by_tld: dict[str, int] = defaultdict(int)
    by_process: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: list[dict] = []
    skipped_files: list[dict] = []
    records_read = records_parsed = records_indexed = records_failed = 0
    detected_sources: set[str] = set()
    parsed_sources: set[str] = set()
    failed_sources: set[str] = set()

    for row in dns_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        indexed = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser[parser_name] += indexed or int(row.get("records_parsed") or row.get("records_read") or 1)
        records_read += int(row.get("records_read") or 0)
        records_parsed += int(row.get("records_parsed") or row.get("records_read") or 0)
        records_indexed += indexed
        records_failed += int(row.get("records_failed") or 0)
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                parsed_sources.add(text)
        if int(row.get("records_failed") or 0) > 0:
            skipped_files.append({"source_file": row.get("source_file"), "parser": parser_name, "reason": "records_failed"})
            for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
                text = str(source_value or "").strip()
                if text:
                    failed_sources.add(text)
        for error in row.get("parser_errors") or row.get("errors") or []:
            parser_errors.append({"source_file": row.get("source_file"), "parser": parser_name, "error": str(error)})

    event_parser_counts: dict[str, int] = defaultdict(int)
    for event in dns_events:
        dns = event.get("dns") or {}
        event_type = str(_nested_get(event, "event.type") or "unknown")
        parser_name = str(_nested_get(event, "artifact.parser") or "unknown")
        event_parser_counts[parser_name] += 1
        by_event_type[event_type] += 1
        record_type = str(dns.get("record_type") or "UNKNOWN")
        by_record_type[record_type] += 1
        status = str(dns.get("status") or "unknown")
        by_status[status] += 1
        domain = str(dns.get("domain") or "").strip().lower()
        if domain:
            by_domain[domain] += 1
            tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
            if tld:
                by_tld[tld] += 1
        process_name = str(_nested_get(event, "process.name") or "").strip().lower()
        if process_name:
            by_process[process_name] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1

    for parser_name, count in event_parser_counts.items():
        if parser_name not in by_parser:
            by_parser[parser_name] = count
    if records_indexed < len(dns_events):
        records_indexed = len(dns_events)

    return {
        "aggregation_scope": scope or "case",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "dns_sources_detected": len(detected_sources),
        "dns_sources_parsed": len(parsed_sources),
        "dns_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_record_type": dict(sorted(by_record_type.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_domain": dict(sorted(by_domain.items())),
        "by_tld": dict(sorted(by_tld.items())),
        "by_process": dict(sorted(by_process.items())),
        "success_count": by_status.get("success", 0) + by_status.get("cached", 0),
        "failed_count": sum(by_status.get(key, 0) for key in ("failed", "timeout", "refused", "nxdomain")),
        "nxdomain_count": by_status.get("nxdomain", 0),
        "a_record_count": by_record_type.get("A", 0),
        "aaaa_record_count": by_record_type.get("AAAA", 0),
        "cname_record_count": by_record_type.get("CNAME", 0),
        "suspicious_domain_count": sum(1 for key in suspicious_reason_counts if "suspicious domain" in key.lower()),
        "punycode_count": suspicious_reason_counts.get("DNS query has punycode domain", 0),
        "dga_like_count": suspicious_reason_counts.get("DNS query has DGA-like domain", 0),
        "long_domain_count": suspicious_reason_counts.get("DNS query has unusually long domain", 0),
        "dynamic_dns_count": suspicious_reason_counts.get("DNS query to dynamic DNS provider", 0),
        "scripting_process_query_count": suspicious_reason_counts.get("DNS query by scripting process", 0),
        "lolbin_query_count": suspicious_reason_counts.get("DNS query by LOLBin", 0),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": parser_errors,
        "skipped_files": skipped_files,
    }


def _build_dns_sample_events(events: list[dict]) -> list[dict]:
    dns_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "dns"]
    if not dns_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()
    indexed_events = list(enumerate(dns_events))

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in indexed_events:
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "dns_query_failed", 3)
    add_matching(lambda item: "DNS query by scripting process" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "DNS query by LOLBin" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "DNS query to dynamic DNS provider" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "DNS query has punycode domain" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: "DNS query has DGA-like domain" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: str(_nested_get(item, "dns.record_type") or "") in {"A", "AAAA", "CNAME"}, 4)
    for index, event in indexed_events:
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_cloud_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    cloud_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") in {"cloud", "cloud_sync"}
        or str(row.get("parser") or row.get("parser_name") or "").startswith("cloud_")
    ]
    cloud_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "cloud"]
    detected_sources = {str(row.get("source_file") or row.get("source_path") or "") for row in cloud_rows if row.get("source_file") or row.get("source_path")}
    parsed_sources = {str(row.get("source_file") or row.get("source_path") or "") for row in cloud_rows if int(row.get("records_parsed") or row.get("events_indexed") or 0) >= 0}
    failed_sources = [row for row in cloud_rows if row.get("error")]
    by_parser: dict[str, int] = defaultdict(int)
    by_provider: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_direction: dict[str, int] = defaultdict(int)
    by_account_domain: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_hydration_status: dict[str, int] = defaultdict(int)
    by_shared: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)

    for row in cloud_rows:
        parser_name = str(row.get("parser") or row.get("parser_name") or "unknown")
        by_parser[parser_name] += int(row.get("records_indexed") or row.get("events_indexed") or row.get("records_parsed") or 0)
    for event in cloud_events:
        cloud = event.get("cloud") or {}
        provider = str(cloud.get("provider") or "Unknown")
        event_type = str(_nested_get(event, "event.type") or "unknown")
        direction = str(cloud.get("direction") or "unknown")
        extension = str(_nested_get(event, "file.extension") or "unknown")
        hydration = str(cloud.get("hydration_status") or "unknown")
        shared = cloud.get("shared")
        account_email = str(cloud.get("account_email") or "")
        by_provider[provider] += 1
        by_event_type[event_type] += 1
        by_direction[direction] += 1
        by_extension[extension] += 1
        by_hydration_status[hydration] += 1
        by_shared["true" if shared is True else "false" if shared is False else "unknown"] += 1
        if "@" in account_email:
            by_account_domain[account_email.split("@", 1)[1].lower()] += 1
        for flag in event.get("data_quality") or []:
            data_quality_counts[str(flag)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1

    return {
        "aggregation_scope": scope or "evidence",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": sum(int(row.get("records_read") or 0) for row in cloud_rows),
        "records_parsed": sum(int(row.get("records_parsed") or 0) for row in cloud_rows),
        "records_indexed": max(sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in cloud_rows), len(cloud_events)),
        "records_failed": sum(int(row.get("records_failed") or 0) for row in cloud_rows),
        "cloud_sources_detected": len(detected_sources),
        "cloud_sources_parsed": len(parsed_sources),
        "cloud_sources_failed": len(failed_sources),
        "by_parser": dict(sorted(by_parser.items())),
        "by_provider": dict(sorted(by_provider.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_direction": dict(sorted(by_direction.items())),
        "by_account_domain": dict(sorted(by_account_domain.items())),
        "by_extension": dict(sorted(by_extension.items())),
        "by_hydration_status": dict(sorted(by_hydration_status.items())),
        "by_shared": dict(sorted(by_shared.items())),
        "syncroot_count": by_event_type.get("cloud_item_observed", 0),
        "upload_count": by_event_type.get("cloud_upload", 0),
        "download_count": by_event_type.get("cloud_download", 0),
        "deleted_count": by_event_type.get("cloud_deleted", 0),
        "placeholder_count": by_hydration_status.get("placeholder", 0),
        "hydrated_count": sum(count for key, count in by_hydration_status.items() if "hydrated" in key.lower() or "pinned" in key.lower()),
        "shared_count": by_shared.get("true", 0),
        "executable_upload_count": suspicious_reason_counts.get("Cloud upload of executable", 0),
        "script_upload_count": suspicious_reason_counts.get("Cloud upload of script", 0),
        "archive_upload_count": suspicious_reason_counts.get("Cloud upload of archive", 0),
        "sensitive_name_count": suspicious_reason_counts.get("Cloud file name contains sensitive keyword", 0),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": [
            {"source_file": row.get("source_file"), "parser": row.get("parser") or row.get("parser_name"), "error": row.get("error")}
            for row in failed_sources[:50]
        ],
        "skipped_files": [],
    }


def _build_cloud_sample_events(events: list[dict]) -> list[dict]:
    cloud_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "cloud"]
    if not cloud_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in enumerate(cloud_events):
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "cloud_item_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "cloud_upload", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "cloud_download", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "cloud_deleted", 2)
    add_matching(lambda item: "Cloud shared sensitive item" in (item.get("suspicious_reasons") or []), 2)
    add_matching(lambda item: str(_nested_get(item, "cloud.hydration_status") or "").lower() == "placeholder", 2)
    for index, event in enumerate(cloud_events):
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_email_sample_events(events: list[dict]) -> list[dict]:
    email_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "email"]
    if not email_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in enumerate(email_events):
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "email_message" and int(item.get("risk_score") or 0) >= 70, 4)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "email_temp_attachment_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "email_mailbox_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "email_client_artifact_observed", 2)
    for index, event in enumerate(email_events):
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_email_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    email_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "email"
        or str(row.get("parser_name") or row.get("parser") or "").lower().startswith("email_")
    ]
    email_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "").lower() == "email"]
    email_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "email"]

    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_sender_domain: dict[str, int] = defaultdict(int)
    by_attachment_extension: dict[str, int] = defaultdict(int)
    unsupported_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)

    for row in email_rows:
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += int(row.get("records_indexed") or row.get("events_indexed") or row.get("records_parsed") or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1
        for key, value in (row.get("by_event_type") or {}).items():
            by_event_type[str(key)] += int(value or 0)
        for key, value in (row.get("by_sender_domain") or {}).items():
            by_sender_domain[str(key)] += int(value or 0)
        for key, value in (row.get("by_attachment_extension") or {}).items():
            by_attachment_extension[str(key)] += int(value or 0)
        for key, value in (row.get("unsupported_counts") or {}).items():
            unsupported_counts[str(key)] += int(value or 0)

    if not by_event_type:
        for event in email_events:
            by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
            sender = str(_nested_get(event, "email.from.address") or "").strip()
            if "@" in sender:
                by_sender_domain[sender.rsplit("@", 1)[-1].lower()] += 1
            for attachment in (_nested_get(event, "email.attachments") or []):
                if isinstance(attachment, dict):
                    by_attachment_extension[str(attachment.get("extension") or "unknown")] += 1
            unsupported_reason = str(_nested_get(event, "email.unsupported_reason") or "").strip()
            if unsupported_reason:
                unsupported_counts[unsupported_reason] += 1

    return {
        "aggregation_scope": scope or "unknown",
        "records_read": sum(int(row.get("records_read") or 0) for row in email_rows),
        "records_parsed": sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in email_rows),
        "records_indexed": sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in email_rows) or len(email_events),
        "records_failed": sum(int(row.get("records_failed") or 0) for row in email_rows),
        "message_count": sum(1 for event in email_events if str(_nested_get(event, "event.type") or "") == "email_message"),
        "attachment_count": sum(len(_nested_get(event, "email.attachments") or []) for event in email_events),
        "mailbox_inventory_count": sum(1 for event in email_events if str(_nested_get(event, "event.type") or "") == "email_mailbox_observed"),
        "temp_attachment_count": sum(1 for event in email_events if str(_nested_get(event, "event.type") or "") == "email_temp_attachment_observed"),
        "suspicious_attachment_count": sum(int(_nested_get(event, "email.suspicious_attachment_count") or 0) for event in email_events),
        "auth_failure_count": sum(1 for event in email_events if bool(_nested_get(event, "email.auth_failure"))),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_sender_domain": dict(sorted(by_sender_domain.items())),
        "by_attachment_extension": dict(sorted(by_attachment_extension.items())),
        "unsupported_counts": dict(sorted(unsupported_counts.items())),
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "selected_artifact_types": selected_artifact_types or [],
        "detected_email_candidates": len(email_candidates),
        "sample_records": [
            {
                "event_type": _nested_get(event, "event.type"),
                "subject": _nested_get(event, "email.subject"),
                "from": _nested_get(event, "email.from.address"),
                "message_id": _nested_get(event, "email.message_id"),
                "source_file": event.get("source_file"),
                "risk_score": event.get("risk_score"),
                "tags": list(event.get("tags") or []),
            }
            for event in email_events[:10]
        ],
    }


def _build_user_activity_sample_events(events: list[dict]) -> list[dict]:
    user_activity_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "user_activity"]
    if not user_activity_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for index, event in enumerate(user_activity_events):
            key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: int(item.get("risk_score") or 0) >= 70, 4)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "office_document_trusted", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "user_folder_access_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "user_activity_registry_hive_observed", 2)
    for index, event in enumerate(user_activity_events):
        key = str(event.get("id") or event.get("event_id") or f"idx:{index}")
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_user_activity_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    audit_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "user_activity"
        or str(row.get("parser_name") or row.get("parser") or "").lower().endswith("_registry")
        or str(row.get("parser_name") or row.get("parser") or "").lower() == "user_activity_registry_raw"
    ]
    candidates = [
        candidate
        for candidate in discovery_candidates
        if str(candidate.get("category") or "").lower() in {"registry", "shellbags"}
        or str(candidate.get("artifact_type") or "").lower() in {"registry_hive_raw", "shellbags_user_hive_ntuser", "shellbags_user_hive_usrclass"}
    ]
    ua_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "user_activity"]

    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    by_activity_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)

    for row in audit_rows:
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += int(row.get("records_indexed") or row.get("events_indexed") or row.get("records_parsed") or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for key, value in (row.get("by_event_type") or {}).items():
            by_event_type[str(key)] += int(value or 0)

    for event in ua_events:
        event_type = str(_nested_get(event, "event.type") or "unknown")
        activity_type = str(
            _nested_get(event, "user_activity.kind")
            or _nested_get(event, "event.action")
            or event_type
            or "unknown"
        )
        parser_name = str(_nested_get(event, "artifact.parser") or "unknown")
        by_event_type[event_type] += 1
        if parser_name not in by_parser:
            by_parser[parser_name] += 1
        by_activity_type[activity_type] += 1
        user_name = str(_nested_get(event, "user.name") or _nested_get(event, "user.sid") or "").strip()
        if user_name:
            by_user[user_name] += 1

    audit_records_read = sum(int(row.get("records_read") or 0) for row in audit_rows)
    audit_records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in audit_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "records_read": max(audit_records_read, len(ua_events)),
        "records_indexed": max(audit_records_indexed, len(ua_events)),
        "records_failed": sum(int(row.get("records_failed") or 0) for row in audit_rows),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_user": dict(sorted(by_user.items())),
        "by_activity_type": dict(sorted(by_activity_type.items())),
        "suspicious_command_count": sum(1 for event in ua_events if str(_nested_get(event, "event.type") or "") == "user_run_command_observed" and int(event.get("risk_score") or 0) >= 70),
        "trusted_office_document_count": sum(1 for event in ua_events if str(_nested_get(event, "event.type") or "") == "office_document_trusted"),
        "shellbag_count": sum(1 for event in ua_events if str(_nested_get(event, "event.type") or "") == "user_folder_access_observed"),
        "recent_document_count": sum(1 for event in ua_events if str(_nested_get(event, "event.type") or "") == "user_recent_document_observed"),
        "bam_execution_count": sum(1 for event in ua_events if str(_nested_get(event, "event.action") or "").startswith("bam_")),
        "userassist_execution_count": sum(1 for event in ua_events if str(_nested_get(event, "event.action") or "") == "userassist_program_execution"),
        "unsupported_raw_hive_count": sum(1 for event in ua_events if str(_nested_get(event, "event.type") or "") == "user_activity_registry_hive_observed"),
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "selected_artifact_types": selected_artifact_types or [],
        "detected_registry_candidates": len(candidates),
        "sample_records": [
            {
                "event_type": _nested_get(event, "event.type"),
                "user": _nested_get(event, "user.name") or _nested_get(event, "user.sid"),
                "path": _nested_get(event, "file.path") or _nested_get(event, "folder.path") or _nested_get(event, "process.command_line"),
                "source_file": event.get("source_file"),
                "risk_score": event.get("risk_score"),
                "tags": list(event.get("tags") or []),
            }
            for event in ua_events[:10]
        ],
    }


def _build_ntfs_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    audit_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "ntfs"
        or str(row.get("parser_name") or row.get("parser") or "").lower().startswith("ntfs_")
    ]
    candidates = [
        candidate
        for candidate in discovery_candidates
        if str(candidate.get("artifact_type") or "").lower() in {"ntfs", "ntfs_raw"}
        or "usnjrnl" in str(candidate.get("source_path") or "").lower()
        or "$logfile" in str(candidate.get("source_path") or "").lower()
        or "$i30" in str(candidate.get("source_path") or "").lower()
    ]
    ntfs_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "ntfs"]

    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_extension: dict[str, int] = defaultdict(int)
    by_zone: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)

    for row in audit_rows:
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += int(row.get("records_indexed") or row.get("events_indexed") or row.get("records_parsed") or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for key, value in (row.get("by_event_type") or {}).items():
            by_event_type[str(key)] += int(value or 0)

    for event in ntfs_events:
        event_type = str(_nested_get(event, "event.type") or "unknown")
        parser_name = str(_nested_get(event, "artifact.parser") or "unknown")
        extension = str(_nested_get(event, "file.extension") or "unknown")
        zone = str(_nested_get(event, "ntfs.zone_name") or _nested_get(event, "ntfs.zone_id") or "").strip()
        by_event_type[event_type] += 1
        if parser_name not in by_parser:
            by_parser[parser_name] += 1
        by_extension[extension] += 1
        if zone:
            by_zone[zone] += 1

    audit_records_read = sum(int(row.get("records_read") or 0) for row in audit_rows)
    audit_records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in audit_rows)
    return {
        "aggregation_scope": scope or "unknown",
        "records_read": max(audit_records_read, len(ntfs_events)),
        "records_indexed": max(audit_records_indexed, len(ntfs_events)),
        "records_failed": sum(int(row.get("records_failed") or 0) for row in audit_rows),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "zone_identifier_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") == "file_zone_identifier_observed"),
        "internet_zone_count": sum(1 for event in ntfs_events if int(_nested_get(event, "ntfs.zone_id") or -1) == 3),
        "untrusted_zone_count": sum(1 for event in ntfs_events if int(_nested_get(event, "ntfs.zone_id") or -1) == 4),
        "usn_create_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") == "file_created_observed"),
        "usn_delete_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") == "file_deleted_observed"),
        "usn_rename_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") == "file_renamed_observed"),
        "i30_deleted_entry_count": sum(1 for event in ntfs_events if str(_nested_get(event, "artifact.parser") or "") == "ntfs_i30" and (bool(_nested_get(event, "file.is_deleted")) or _nested_get(event, "ntfs.in_use") is False)),
        "shadowcopy_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") == "shadowcopy_observed"),
        "suspicious_origin_count": sum(1 for event in ntfs_events if any("Downloaded" in str(reason) for reason in (event.get("suspicious_reasons") or []))),
        "suspicious_delete_count": sum(1 for event in ntfs_events if str(_nested_get(event, "event.type") or "") in {"file_deleted_observed", "file_renamed_observed"} and int(event.get("risk_score") or 0) >= 60),
        "unsupported_raw_count": sum(1 for event in ntfs_events if str(_nested_get(event, "artifact.parser") or "") == "ntfs_generic_raw"),
        "by_extension": dict(sorted(by_extension.items())),
        "by_zone": dict(sorted(by_zone.items())),
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "selected_artifact_types": selected_artifact_types or [],
        "detected_ntfs_candidates": len(candidates),
        "sample_records": [
            {
                "event_type": _nested_get(event, "event.type"),
                "path": _nested_get(event, "file.path"),
                "reason": _nested_get(event, "ntfs.reason"),
                "host_url": _nested_get(event, "ntfs.host_url"),
                "source_file": event.get("source_file"),
                "risk_score": event.get("risk_score"),
                "tags": list(event.get("tags") or []),
            }
            for event in ntfs_events[:10]
        ],
    }


def _build_ntfs_sample_events(events: list[dict]) -> list[dict]:
    ntfs_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "ntfs"]
    if not ntfs_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in ntfs_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "file_zone_identifier_observed", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") in {"file_deleted_observed", "file_renamed_observed"}, 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "directory_entry_observed", 2)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "shadowcopy_observed", 1)
    add_matching(lambda item: str(_nested_get(item, "artifact.parser") or "") == "ntfs_generic_raw", 2)
    for event in ntfs_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_windows_ui_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    audit_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "").lower() == "windows_ui"
        or str(row.get("parser_name") or row.get("parser") or "").lower().startswith(("windows_", "office_"))
    ]
    candidates = [
        candidate
        for candidate in discovery_candidates
        if str(candidate.get("artifact_type") or "").lower() == "windows_ui"
        or any(token in str(candidate.get("source_path") or "").lower() for token in ("thumbcache", "thumbs.db", "activitiescache", "windows.edb", "eventtranscript", "wpndatabase", "oalerts", "officefilecache"))
    ]
    ui_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "windows_ui"]

    by_parser: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)

    for row in audit_rows:
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += int(row.get("records_indexed") or row.get("events_indexed") or row.get("records_parsed") or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for key, value in (row.get("by_event_type") or {}).items():
            by_event_type[str(key)] += int(value or 0)

    for event in ui_events:
        event_type = str(_nested_get(event, "event.type") or "unknown")
        parser_name = str(_nested_get(event, "artifact.parser") or "unknown")
        by_event_type[event_type] += 1
        if parser_name not in by_parser:
            by_parser[parser_name] += 1

    audit_records_read = sum(int(row.get("records_read") or 0) for row in audit_rows)
    audit_records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in audit_rows)
    return {
        "aggregation_scope": scope or "unknown",
        "records_read": max(audit_records_read, len(ui_events)),
        "records_indexed": max(audit_records_indexed, len(ui_events)),
        "records_failed": sum(int(row.get("records_failed") or 0) for row in audit_rows),
        "by_parser": dict(sorted(by_parser.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "thumbnail_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "thumbnail_observed"),
        "notification_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "notification_observed"),
        "activity_history_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "activity_history_observed"),
        "search_index_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "search_index_entry_observed"),
        "event_transcript_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "event_transcript_observed"),
        "office_alert_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "office_alert_observed"),
        "office_cache_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "office_cache_entry_observed"),
        "unsupported_raw_count": sum(1 for event in ui_events if str(_nested_get(event, "artifact.parser") or "") == "windows_ui_generic_raw"),
        "suspicious_ui_file_count": sum(1 for event in ui_events if int(event.get("risk_score") or 0) >= 60 and str(_nested_get(event, "event.type") or "") in {"thumbnail_observed", "activity_history_observed", "search_index_entry_observed"}),
        "office_security_alert_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "office_alert_observed" and int(event.get("risk_score") or 0) >= 70),
        "security_notification_count": sum(1 for event in ui_events if str(_nested_get(event, "event.type") or "") == "notification_observed" and int(event.get("risk_score") or 0) >= 70),
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "selected_artifact_types": selected_artifact_types or [],
        "detected_windows_ui_candidates": len(candidates),
        "sample_records": [
            {
                "event_type": _nested_get(event, "event.type"),
                "path": _nested_get(event, "file.path"),
                "notification_title": _nested_get(event, "notification.title"),
                "activity_display": _nested_get(event, "activity.display_text"),
                "indexed_path": _nested_get(event, "windows_search.indexed_path"),
                "office_alert_text": _nested_get(event, "office.alert_text"),
                "source_file": event.get("source_file"),
                "risk_score": event.get("risk_score"),
                "tags": list(event.get("tags") or []),
            }
            for event in ui_events[:10]
        ],
    }


def _build_windows_ui_sample_events(events: list[dict]) -> list[dict]:
    ui_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "windows_ui"]
    if not ui_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in ui_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "office_alert_observed", 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "notification_observed" and int(item.get("risk_score") or 0) >= 70, 3)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") in {"thumbnail_observed", "activity_history_observed", "search_index_entry_observed"} and int(item.get("risk_score") or 0) >= 60, 4)
    add_matching(lambda item: str(_nested_get(item, "artifact.parser") or "") == "windows_ui_generic_raw", 2)
    for event in ui_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_event_identity_report(context: _DebugPackContext, events: list[dict]) -> dict:
    by_artifact_type = Counter(str(_nested_get(event, "artifact.type") or "unknown") for event in events)
    stable_ids: list[str] = []
    best_effort_count = 0
    collisions: list[str] = []
    seen: set[str] = set()
    for event in events:
        stable_id = str(event.get("stable_event_id") or event.get("event_fingerprint") or "").strip()
        if stable_id:
            stable_ids.append(stable_id)
            if stable_id in seen and stable_id not in collisions:
                collisions.append(stable_id)
            seen.add(stable_id)
        if "fingerprint_best_effort" in (event.get("data_quality") or []):
            best_effort_count += 1
    return {
        "case_id": context.case.id,
        "evidence_id": context.request.evidence_id,
        "fingerprint_version": "v1",
        "events_with_stable_id": len(stable_ids),
        "events_missing_stable_id": max(len(events) - len(stable_ids), 0),
        "best_effort_count": best_effort_count,
        "by_artifact_type": dict(sorted(by_artifact_type.items())),
        "collision_count": len(collisions),
        "collisions": collisions[:20],
        "warnings": ["stable_event_id_collision_detected"] if collisions else [],
    }


def _build_reconciliation_report(context: _DebugPackContext) -> dict:
    evidence = next((item for item in context.evidences if item.id == context.request.evidence_id), None)
    metadata = dict((evidence.metadata_json or {}) if evidence else {})
    report = dict(metadata.get("reconciliation_report") or {})
    if report:
        return report
    return {
        "case_id": context.case.id,
        "evidence_id": context.request.evidence_id,
        "findings_matched_existing": 0,
        "findings_created": 0,
        "findings_stale_removed_or_archived": 0,
        "detections_matched_existing": 0,
        "detections_created": 0,
        "key_events_remapped": 0,
        "key_events_stale": 0,
        "warnings": ["reconciliation_not_available"],
    }


def _build_bits_sample_events(events: list[dict]) -> list[dict]:
    bits_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "bits"]
    if not bits_events:
        return []
    selected: list[dict] = []
    seen: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in bits_events:
            key = str(event.get("id") or event.get("event_id") or len(selected))
            if key in seen or not match_fn(event):
                continue
            selected.append(event)
            seen.add(key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "file_downloaded", 4)
    add_matching(lambda item: bool(_nested_get(item, "bits.notify_cmd_line")), 3)
    add_matching(lambda item: bool(item.get("suspicious_reasons")), 4)
    add_matching(lambda item: str(_nested_get(item, "event.type") or "") == "download_interrupted", 2)
    for event in bits_events:
        key = str(event.get("id") or event.get("event_id") or len(selected))
        if key in seen:
            continue
        selected.append(event)
        seen.add(key)
        if len(selected) >= 10:
            break
    return selected[:10]


def _build_browser_sample_events(events: list[dict]) -> list[dict]:
    browser_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "browser"]
    if not browser_events:
        return []
    selected: list[dict] = []
    seen_ids: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        count = 0
        for event in browser_events:
            event_key = str(event.get("id") or event.get("event_id") or "")
            if event_key and event_key in seen_ids:
                continue
            if not match_fn(event):
                continue
            selected.append(event)
            if event_key:
                seen_ids.add(event_key)
            count += 1
            if count >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "browser.artifact_type") or "") == "history", 5)
    add_matching(lambda item: str(_nested_get(item, "browser.artifact_type") or "") == "download", 5)
    add_matching(lambda item: str(_nested_get(item, "browser.artifact_type") or "") == "download" and bool(item.get("suspicious_reasons")), 3)
    for event in browser_events:
        event_key = str(event.get("id") or event.get("event_id") or "")
        if event_key and event_key in seen_ids:
            continue
        selected.append(event)
        if event_key:
            seen_ids.add(event_key)
        if len(selected) >= 13:
            break
    return selected[:13]


def _collect_browser_scope_aggregates(context: _DebugPackContext) -> dict[str, Any]:
    if context.request.scope == "selected_events":
        return {}
    search_request = _build_scope_search_request(context, page_size=1)
    body = build_search_query(search_request)
    query = deepcopy(body.get("query") or {"match_all": {}})
    if isinstance(query, dict) and "bool" in query:
        bool_query = query["bool"]
        filters = list(bool_query.get("filter") or [])
        filters.append({"term": {"artifact.type": "browser"}})
        bool_query["filter"] = filters
    else:
        query = {"bool": {"must": [query], "filter": [{"term": {"artifact.type": "browser"}}]}}
    index = get_events_index(context.case.id)
    client = get_opensearch_client()
    field_browser = resolve_aggregatable_field(client, index, "browser.browser") or "browser.browser"
    field_artifact_type = resolve_aggregatable_field(client, index, "browser.artifact_type") or "browser.artifact_type"
    field_event_type = resolve_aggregatable_field(client, index, "event.type") or "event.type"
    response = search_documents(
        index,
        {
            "size": 0,
            "track_total_hits": True,
            "query": query,
            "aggs": {
                "by_browser": {"terms": {"field": field_browser, "size": 20}},
                "by_artifact_type": {"terms": {"field": field_artifact_type, "size": 20}},
                "by_event_type": {"terms": {"field": field_event_type, "size": 20}},
            },
        },
    )
    return {
        "total": int((((response.get("hits") or {}).get("total") or {}).get("value")) or 0),
        "by_browser": {
            str(bucket.get("key")): int(bucket.get("doc_count") or 0)
            for bucket in (((response.get("aggregations") or {}).get("by_browser") or {}).get("buckets") or [])
            if bucket.get("key") not in (None, "")
        },
        "by_artifact_type": {
            str(bucket.get("key")): int(bucket.get("doc_count") or 0)
            for bucket in (((response.get("aggregations") or {}).get("by_artifact_type") or {}).get("buckets") or [])
            if bucket.get("key") not in (None, "")
        },
        "by_event_type": {
            str(bucket.get("key")): int(bucket.get("doc_count") or 0)
            for bucket in (((response.get("aggregations") or {}).get("by_event_type") or {}).get("buckets") or [])
            if bucket.get("key") not in (None, "")
        },
    }


def _build_browser_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None, event_aggregates: dict[str, Any] | None = None) -> dict:
    browser_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "browser"
        or str(row.get("parser_name") or row.get("parser") or "").startswith("browser_")
    ]
    browser_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "browser"]
    by_parser_sources: dict[str, int] = defaultdict(int)
    by_parser: dict[str, int] = defaultdict(int)
    by_browser: dict[str, int] = defaultdict(int)
    by_artifact_type: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    danger_type_counts: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: dict[str, int] = defaultdict(int)
    skipped_files: list[dict] = []
    empty_sources: list[dict] = []
    browser_sources_detected: set[str] = set()
    browser_sources_parsed: set[str] = set()
    browser_sources_with_events: set[str] = set()
    has_full_browser_counts = False
    has_full_artifact_counts = False
    has_full_event_counts = False

    def infer_browser_from_source(source_value: object | None) -> str | None:
        text = str(source_value or "").replace("/", "\\").lower()
        if "bravesoftware" in text:
            return "brave"
        if "microsoft\\edge" in text or "microsoft\\edge" in text.replace("%3a", ":"):
            return "edge"
        if "google\\chrome" in text:
            return "chrome"
        if "mozilla\\firefox" in text or text.endswith("\\places.sqlite"):
            return "firefox"
        if "opera software" in text:
            return "opera"
        if "\\history" in text:
            return "chromium"
        return None

    for row in browser_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        indexed_count = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser_sources[parser_name] += 1
        by_parser[parser_name] += indexed_count
        inferred_browser = infer_browser_from_source(row.get("source_file") or row.get("source_path") or row.get("artifact"))
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                browser_sources_detected.add(text)
                browser_sources_parsed.add(text)
                if indexed_count > 0:
                    browser_sources_with_events.add(text)
        for browser_name, count in (row.get("by_browser") or {}).items():
            by_browser[str(browser_name)] += int(count or 0)
        if row.get("by_browser"):
            has_full_browser_counts = True
        elif row.get("browsers_seen"):
            for browser_name, count in (row.get("browsers_seen") or {}).items():
                by_browser[str(browser_name).lower()] += int(count or 0)
            has_full_browser_counts = True
        if inferred_browser and indexed_count > 0 and not row.get("by_browser") and not row.get("browsers_seen"):
            by_browser[inferred_browser] += indexed_count
        for artifact_type, count in (row.get("by_artifact_type") or {}).items():
            by_artifact_type[str(artifact_type)] += int(count or 0)
        if row.get("by_artifact_type"):
            has_full_artifact_counts = True
        if not row.get("by_artifact_type"):
            history_count = int(row.get("history_count") or 0)
            download_count = int(row.get("download_count") or 0)
            search_count = int(row.get("search_count") or 0)
            if history_count:
                by_artifact_type["history"] += history_count
            if download_count:
                by_artifact_type["download"] += download_count
            if search_count:
                by_artifact_type["search_term"] += search_count
            if history_count or download_count or search_count:
                has_full_artifact_counts = True
        for event_type, count in (row.get("by_event_type") or {}).items():
            by_event_type[str(event_type)] += int(count or 0)
        if row.get("by_event_type"):
            has_full_event_counts = True
        if not row.get("by_event_type"):
            history_count = int(row.get("history_count") or 0)
            download_count = int(row.get("download_count") or 0)
            search_count = int(row.get("search_count") or 0)
            if history_count:
                by_event_type["browser_visit"] += history_count
            if download_count:
                by_event_type["file_downloaded"] += download_count
            if search_count:
                by_event_type["browser_search"] += search_count
            if history_count or download_count or search_count:
                has_full_event_counts = True
        for quality, count in (row.get("data_quality_counts") or {}).items():
            data_quality_counts[str(quality)] += int(count or 0)
        for reason, count in (row.get("suspicious_reason_counts") or {}).items():
            suspicious_reason_counts[str(reason)] += int(count or 0)
        for danger, count in (row.get("danger_type_counts") or {}).items():
            danger_type_counts[str(danger)] += int(count or 0)
        for error in row.get("errors") or row.get("parser_errors") or []:
            parser_errors[str(error)] += 1
        parser_status = str(row.get("parser_status") or row.get("status") or "")
        if indexed_count == 0 and parser_status in {"completed", "completed_empty"}:
            empty_sources.append(
                {
                    "source_file": row.get("source_file") or row.get("artifact"),
                    "parser": parser_name,
                    "status": "completed_empty",
                    "records_read": int(row.get("records_read") or 0),
                    "records_indexed": indexed_count,
                }
            )
        elif indexed_count == 0:
            skipped_files.append(
                {
                    "source_file": row.get("source_file") or row.get("artifact"),
                    "parser": parser_name,
                    "reason": parser_status or "no_records_indexed",
                }
            )

    for candidate in browser_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            browser_sources_detected.add(text)

    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "browser":
            continue
        browser = event.get("browser") or {}
        if not has_full_browser_counts and browser.get("browser"):
            by_browser[str(browser.get("browser")).lower()] += 1
        if not has_full_artifact_counts:
            artifact_type = str(browser.get("artifact_type") or "")
            if artifact_type:
                by_artifact_type[artifact_type] += 1
        if not has_full_event_counts:
            event_type = str(_nested_get(event, "event.type") or "")
            if event_type:
                by_event_type[event_type] += 1
        for source_value in (
            (browser.get("source_file")),
            artifact.get("source_path"),
            event.get("source_file"),
        ):
            text = str(source_value or "").strip()
            if text:
                browser_sources_detected.add(text)

    records_read = sum(int(row.get("records_read") or 0) for row in browser_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in browser_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in browser_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in browser_rows)
    aggregate_counts = event_aggregates or {}
    if aggregate_counts.get("by_browser"):
        by_browser = defaultdict(int, {str(key): int(value or 0) for key, value in (aggregate_counts.get("by_browser") or {}).items()})
    if aggregate_counts.get("by_artifact_type"):
        by_artifact_type = defaultdict(int, {str(key): int(value or 0) for key, value in (aggregate_counts.get("by_artifact_type") or {}).items()})
    if aggregate_counts.get("by_event_type"):
        by_event_type = defaultdict(int, {str(key): int(value or 0) for key, value in (aggregate_counts.get("by_event_type") or {}).items()})
    if aggregate_counts.get("total"):
        records_indexed = int(aggregate_counts.get("total") or 0)
        records_read = max(records_read, records_indexed)
        records_parsed = max(records_parsed, records_indexed)

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "browser_sources_detected": len(browser_sources_detected),
        "browser_sources_parsed": len(browser_sources_parsed),
        "browser_sources_with_events": len(browser_sources_with_events),
        "by_parser_sources": dict(sorted(by_parser_sources.items())),
        "by_parser": dict(sorted(by_parser.items())),
        "by_browser": dict(sorted(by_browser.items())),
        "by_artifact_type": dict(sorted(by_artifact_type.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "history_count": by_artifact_type.get("history", 0) or by_event_type.get("browser_visit", 0),
        "download_count": by_artifact_type.get("download", 0) or by_event_type.get("file_downloaded", 0),
        "search_count": by_artifact_type.get("search_term", 0) or by_event_type.get("browser_search", 0),
        "suspicious_download_count": sum(
            1
            for event in events
            if str(_nested_get(event, "artifact.type") or "") == "browser"
            and str(_nested_get(event, "browser.artifact_type") or "") == "download"
            and bool(event.get("suspicious_reasons"))
        ),
        "executable_download_count": sum(1 for event in events if str(_nested_get(event, "artifact.type") or "") == "browser" and "executable_download" in set(event.get("tags") or [])),
        "script_download_count": sum(1 for event in events if str(_nested_get(event, "artifact.type") or "") == "browser" and "script_download" in set(event.get("tags") or [])),
        "archive_download_count": sum(1 for event in events if str(_nested_get(event, "artifact.type") or "") == "browser" and "archive_download" in set(event.get("tags") or [])),
        "direct_ip_url_count": suspicious_reason_counts.get("Browser URL uses direct IP", 0),
        "http_download_count": suspicious_reason_counts.get("Browser download over HTTP", 0),
        "danger_type_counts": dict(sorted(danger_type_counts.items())),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": dict(sorted(parser_errors.items())),
        "empty_sources": empty_sources[:20],
        "skipped_files": skipped_files[:20],
    }


def _build_defender_sample_events(events: list[dict]) -> list[dict]:
    detection_events = [
        event for event in events
        if str(_nested_get(event, "artifact.type") or "") in {"detection", "defender"}
        or str(_nested_get(event, "artifact.parser") or "").startswith("defender_")
        or str(_nested_get(event, "event.category") or "") == "detection"
        or bool(_nested_get(event, "detection.threat_name"))
        or str(_nested_get(event, "windows.provider") or "").lower().find("windows defender") != -1
    ]
    malware = [event for event in detection_events if str(_nested_get(event, "event.type") or "") == "malware_detected"][:5]
    remediation = [event for event in detection_events if str(_nested_get(event, "event.type") or "") == "remediation"][:3]
    config = [event for event in detection_events if str(_nested_get(event, "event.type") or "") in {"configuration_change", "tamper_protection", "suspicious_behavior"}][:3]
    selected: list[dict] = []
    seen: set[str] = set()
    for event in [*malware, *remediation, *config, *detection_events[:10]]:
        key = str(
            event.get("id")
            or event.get("event_id")
            or _nested_get(event, "detection.threat_name")
            or _nested_get(event, "windows.event_id")
            or _nested_get(event, "artifact.parser")
            or len(selected)
        )
        if key not in seen:
            selected.append(event)
            seen.add(key)
    return selected[:10]


def _build_defender_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    defender_rows = [
        row for row in parser_audit
        if str(row.get("artifact_type") or "") in {"defender", "detection"}
        or str(row.get("parser_name") or row.get("parser") or "").startswith("defender_")
    ]
    defender_candidates = [
        candidate for candidate in discovery_candidates
        if str(candidate.get("category") or "") == "defender"
        or str(candidate.get("artifact_type") or "").startswith("defender")
    ]
    by_parser_sources: dict[str, int] = defaultdict(int)
    parser_by_parser: dict[str, int] = defaultdict(int)
    parser_by_threat_name: dict[str, int] = defaultdict(int)
    parser_by_severity: dict[str, int] = defaultdict(int)
    parser_by_category: dict[str, int] = defaultdict(int)
    parser_by_action: dict[str, int] = defaultdict(int)
    parser_by_status: dict[str, int] = defaultdict(int)
    parser_by_remediation_action: dict[str, int] = defaultdict(int)
    parser_by_event_type: dict[str, int] = defaultdict(int)
    event_by_parser: dict[str, int] = defaultdict(int)
    event_by_event_id: dict[str, int] = defaultdict(int)
    event_by_threat_name: dict[str, int] = defaultdict(int)
    event_by_severity: dict[str, int] = defaultdict(int)
    event_by_category: dict[str, int] = defaultdict(int)
    event_by_action: dict[str, int] = defaultdict(int)
    event_by_status: dict[str, int] = defaultdict(int)
    event_by_remediation_action: dict[str, int] = defaultdict(int)
    event_by_event_type: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    suspicious_reason_counts: dict[str, int] = defaultdict(int)
    parser_errors: dict[str, int] = defaultdict(int)
    skipped_files: list[dict] = []
    defender_sources_detected: set[str] = set()
    defender_sources_parsed: set[str] = set()
    defender_sources_failed: set[str] = set()
    event_defender_rows: list[dict] = []

    for row in defender_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        indexed_count = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser_sources[parser_name] += 1
        parser_by_parser[parser_name] += indexed_count
        source_file = str(row.get("source_file") or row.get("source_path") or row.get("artifact") or "").strip()
        if source_file:
            defender_sources_detected.add(source_file)
            defender_sources_parsed.add(source_file)
            if int(row.get("records_failed") or 0) > 0:
                defender_sources_failed.add(source_file)
        for key, value in (row.get("by_threat_name") or {}).items():
            parser_by_threat_name[str(key)] += int(value or 0)
        for key, value in (row.get("by_severity") or {}).items():
            parser_by_severity[str(key)] += int(value or 0)
        for key, value in (row.get("by_category") or {}).items():
            parser_by_category[str(key)] += int(value or 0)
        for key, value in (row.get("by_action") or {}).items():
            parser_by_action[str(key)] += int(value or 0)
        for key, value in (row.get("by_status") or {}).items():
            parser_by_status[str(key)] += int(value or 0)
        for key, value in (row.get("by_remediation_action") or {}).items():
            parser_by_remediation_action[str(key)] += int(value or 0)
        for key, value in (row.get("by_event_type") or {}).items():
            parser_by_event_type[str(key)] += int(value or 0)
        for key, value in (row.get("data_quality_counts") or {}).items():
            data_quality_counts[str(key)] += int(value or 0)
        for key, value in (row.get("suspicious_reason_counts") or {}).items():
            suspicious_reason_counts[str(key)] += int(value or 0)
        for error in row.get("errors") or row.get("parser_errors") or []:
            parser_errors[str(error)] += 1
        if indexed_count == 0 and (row.get("parse_warnings") or row.get("parser_errors") or row.get("errors")):
            skipped_files.append(
                {
                    "source_file": source_file,
                    "parser": parser_name,
                    "reason": ", ".join(str(item) for item in ([*(row.get("parse_warnings") or []), *(row.get("parser_errors") or []), *(row.get("errors") or [])])[:4]),
                }
            )
    for candidate in defender_candidates:
        path = str(candidate.get("normalized_windows_path") or candidate.get("original_path") or candidate.get("path") or "").strip()
        if path:
            defender_sources_detected.add(path)

    for event in events:
        if str(_nested_get(event, "artifact.type") or "") not in {"detection", "defender"} and str(_nested_get(event, "event.category") or "") != "detection":
            continue
        event_defender_rows.append(event)
        detection = event.get("detection") or {}
        windows = event.get("windows") or {}
        artifact = event.get("artifact") or {}
        event_type = str(_nested_get(event, "event.type") or "")
        parser_name = str(artifact.get("parser") or "")
        if parser_name:
            event_by_parser[parser_name] += 1
        if event_type:
            event_by_event_type[event_type] += 1
        if windows.get("event_id") not in (None, ""):
            event_by_event_id[str(windows.get("event_id"))] += 1
        if detection.get("threat_name"):
            event_by_threat_name[str(detection.get("threat_name"))] += 1
        if detection.get("severity"):
            event_by_severity[str(detection.get("severity"))] += 1
        if detection.get("category"):
            event_by_category[str(detection.get("category"))] += 1
        if detection.get("action"):
            event_by_action[str(detection.get("action"))] += 1
        if detection.get("status"):
            event_by_status[str(detection.get("status"))] += 1
        if detection.get("remediation_action"):
            event_by_remediation_action[str(detection.get("remediation_action"))] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1

    records_read = sum(int(row.get("records_read") or 0) for row in defender_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in defender_rows)
    parser_audit_records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in defender_rows)
    indexed_events_count = len(event_defender_rows)
    records_indexed = parser_audit_records_indexed
    records_failed = sum(int(row.get("records_failed") or 0) for row in defender_rows)
    report_warnings: list[str] = []
    if indexed_events_count > records_indexed:
        records_indexed = indexed_events_count
        records_parsed = max(records_parsed, records_indexed)
        records_read = max(records_read, records_indexed)
        report_warnings.append("defender_report_count_reconciled_from_events")
    by_parser = event_by_parser or parser_by_parser
    by_event_id = event_by_event_id
    by_event_type = event_by_event_type or parser_by_event_type
    by_threat_name = event_by_threat_name or parser_by_threat_name
    by_severity = event_by_severity or parser_by_severity
    by_category = event_by_category or parser_by_category
    by_action = event_by_action or parser_by_action
    by_status = event_by_status or parser_by_status
    by_remediation_action = event_by_remediation_action or parser_by_remediation_action
    malware_detected_count = sum(1 for event in event_defender_rows if str(_nested_get(event, "event.type") or "") == "malware_detected")
    remediation_count = [event for event in event_defender_rows if str(_nested_get(event, "event.type") or "") == "remediation"]
    remediation_success_count = sum(1 for event in remediation_count if "failed" not in " ".join(str(item).lower() for item in (event.get("suspicious_reasons") or [])))
    remediation_failed_count = sum(1 for event in remediation_count if any("failed" in str(item).lower() for item in (event.get("suspicious_reasons") or [])))
    quarantine_count = suspicious_reason_counts.get("Defender quarantined threat", 0)
    config_change_count = sum(1 for event in event_defender_rows if str(_nested_get(event, "event.type") or "") == "configuration_change")
    tamper_event_count = sum(1 for event in event_defender_rows if str(_nested_get(event, "event.type") or "") == "tamper_protection")

    return {
        "selected_artifact_types": selected_artifact_types or [],
        "aggregation_scope": scope or "unknown",
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "parser_audit_records_indexed": parser_audit_records_indexed,
        "indexed_events_count": indexed_events_count,
        "warnings": report_warnings,
        "defender_sources_detected": len(defender_sources_detected),
        "defender_sources_parsed": len(defender_sources_parsed),
        "defender_sources_failed": len(defender_sources_failed),
        "by_parser": dict(sorted(by_parser.items())),
        "by_parser_sources": dict(sorted(by_parser_sources.items())),
        "by_event_id": dict(sorted(by_event_id.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_threat_name": dict(sorted(by_threat_name.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_action": dict(sorted(by_action.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_remediation_action": dict(sorted(by_remediation_action.items())),
        "malware_detected_count": malware_detected_count,
        "remediation_success_count": remediation_success_count,
        "remediation_failed_count": remediation_failed_count,
        "quarantine_count": quarantine_count,
        "config_change_count": config_change_count,
        "tamper_event_count": tamper_event_count,
        "delimiter_fallback_count": sum(int(row.get("delimiter_fallback_count") or 0) for row in defender_rows),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "suspicious_reason_counts": dict(sorted(suspicious_reason_counts.items())),
        "parser_errors": dict(sorted(parser_errors.items())),
        "skipped_files": skipped_files[:20],
    }


def _build_powershell_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    def _is_powershell_evtx_path(value: object | None) -> bool:
        text = str(value or "").replace("/", "\\").lower()
        return any(
            token in text
            for token in (
                "microsoft-windows-powershell\\operational.evtx",
                "microsoft-windows-powershell%4operational.evtx",
                "windows powershell.evtx",
                "powershellcore\\operational.evtx",
                "powershellcore%4operational.evtx",
            )
        )

    ps_rows = [
        row
        for row in parser_audit
        if str(row.get("artifact_type") or "") == "powershell"
        or str(row.get("parser_name") or row.get("parser") or "").startswith("powershell")
        or str(row.get("parser_name") or row.get("parser") or "") in {"psreadline", "transcript", "script", "json", "jsonl", "csv"}
    ]
    ps_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "powershell"]
    inferred_types = {str(item).lower() for item in (selected_artifact_types or []) if item}
    if not inferred_types:
        inferred_types = {
            str(candidate.get("category") or "").lower()
            for candidate in discovery_candidates
            if candidate.get("selected_for_extraction") is True and candidate.get("category")
        }
    selected_types = inferred_types
    selected_powershell = "powershell" in selected_types
    selected_evtx = "evtx" in selected_types
    if selected_powershell and selected_evtx:
        selection_mode = "powershell_plus_evtx"
    elif selected_powershell:
        selection_mode = "powershell_only"
    elif selected_evtx:
        selection_mode = "evtx_only"
    else:
        selection_mode = "unknown"
    by_parser_sources: dict[str, int] = defaultdict(int)
    by_parser_events: dict[str, int] = defaultdict(int)
    by_artifact_type: dict[str, int] = defaultdict(int)
    by_event_type: dict[str, int] = defaultdict(int)
    by_event_id: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    suspicious_counts: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    sample_events: list[dict] = []
    skipped_files: list[dict] = []
    detected_sources: set[str] = set()
    powershell_direct_sources: set[str] = set()
    powershell_evtx_sources: set[str] = set()
    powershell_evtx_source_keys: set[str] = set()
    powershell_events_from_evtx_count = 0
    evtx_candidate_paths: dict[str, str] = {}
    selected_evtx_candidate_paths: dict[str, str] = {}
    parsed_powershell_evtx_files: dict[str, dict[str, Any]] = {}
    skipped_powershell_evtx_files: list[dict] = []
    powershell_evtx_event_ids_count: dict[str, int] = defaultdict(int)
    powershell_evtx_event_ids_seen: set[str] = set()
    powershell_evtx_classification_counts: dict[str, int] = defaultdict(int)
    path_matching_debug: list[dict[str, Any]] = []
    encoded_command_count = decoded_command_count = download_count = iex_count = defender_tampering_count = persistence_command_count = 0
    has_full_artifact_counts = False
    has_full_event_counts = False
    has_audit_indicator_counts = False
    has_powershell_evtx_audit_rows = any(
        str(row.get("parser_name") or row.get("parser") or "") == "evtx_raw"
        and (
            _is_powershell_evtx_path(row.get("source_file"))
            or any("powershell" in str(channel).lower() for channel in (row.get("channels_seen") or []))
        )
        for row in parser_audit
    )

    for row in ps_rows:
        parser_name = str(row.get("parser_name") or row.get("parser") or "unknown")
        by_parser_sources[parser_name] += 1
        indexed_count = int(row.get("records_indexed") or row.get("events_indexed") or 0)
        by_parser_events[parser_name] += indexed_count
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        row_artifact_counts = row.get("by_artifact_type") or {}
        row_event_counts = row.get("by_event_type") or {}
        if row_artifact_counts:
            has_full_artifact_counts = True
        if row_event_counts:
            has_full_event_counts = True
        for artifact_name, count in row_artifact_counts.items():
            by_artifact_type[str(artifact_name)] += int(count or 0)
        for event_name, count in row_event_counts.items():
            by_event_type[str(event_name)] += int(count or 0)
        has_audit_indicator_counts = has_audit_indicator_counts or any(
            row.get(key) not in (None, 0, "0")
            for key in (
                "encoded_command_count",
                "decoded_command_count",
                "download_cradle_count",
                "iex_count",
                "defender_tampering_count",
                "persistence_count",
            )
        )
        encoded_command_count += int(row.get("encoded_command_count") or 0)
        decoded_command_count += int(row.get("decoded_command_count") or 0)
        download_count += int(row.get("download_cradle_count") or 0)
        iex_count += int(row.get("iex_count") or 0)
        defender_tampering_count += int(row.get("defender_tampering_count") or 0)
        persistence_command_count += int(row.get("persistence_count") or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1
        for source_value in (row.get("source_file"), row.get("source_path"), row.get("artifact")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                if parser_name.startswith("powershell"):
                    powershell_direct_sources.add(text)
        if int(row.get("records_indexed") or row.get("events_indexed") or 0) == 0:
            skipped_files.append(
                {
                    "source_file": row.get("source_file"),
                    "parser": parser_name,
                    "parser_status": row.get("parser_status") or row.get("status"),
                    "warnings": list(row.get("warnings") or row.get("parse_warnings") or []),
                }
            )
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_events) < 10:
                sample_events.append(sample)
            if isinstance(sample, dict):
                text = str(sample.get("source_file") or "").strip()
                if text:
                    detected_sources.add(text)

    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "powershell":
            continue
        powershell = event.get("powershell") or {}
        is_powershell_evtx_event = str(event.get("source_format") or "") == "evtx" or str(artifact.get("parser") or "") == "powershell_evtx"
        if is_powershell_evtx_event and not has_powershell_evtx_audit_rows:
            powershell_events_from_evtx_count += 1
        if not has_full_artifact_counts:
            by_artifact_type[str(powershell.get("artifact_type") or "powershell")] += 1
        if not has_full_event_counts:
            by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
        raw_event_id = _nested_get(event, "windows.event_id")
        if raw_event_id not in (None, ""):
            by_event_id[str(raw_event_id)] += 1
            if is_powershell_evtx_event and not has_powershell_evtx_audit_rows:
                powershell_evtx_event_ids_count[str(raw_event_id)] += 1
                powershell_evtx_event_ids_seen.add(str(raw_event_id))
        if not has_audit_indicator_counts:
            if powershell.get("has_encoded_command"):
                encoded_command_count += 1
            if powershell.get("decoded_command_preview"):
                decoded_command_count += 1
            if powershell.get("has_download"):
                download_count += 1
            if powershell.get("has_iex"):
                iex_count += 1
            if powershell.get("has_defender_tampering"):
                defender_tampering_count += 1
            if powershell.get("has_persistence"):
                persistence_command_count += 1
        for reason in event.get("suspicious_reasons") or []:
            suspicious_counts[str(reason)] += 1
        for quality in event.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for source_value in (powershell.get("source_file"), artifact.get("source_path"), event.get("source_file")):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
                if is_powershell_evtx_event:
                    powershell_evtx_sources.add(text)
                    powershell_evtx_source_keys.add(_normalize_forensic_path_key(text))
                else:
                    powershell_direct_sources.add(text)

    for candidate in ps_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)
            powershell_direct_sources.add(text)
    for candidate in discovery_candidates:
        candidate_path = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if candidate_path and str(candidate.get("category") or "") == "evtx" and _is_powershell_evtx_path(candidate_path):
            normalized_key = _normalize_forensic_path_key(candidate_path)
            evtx_candidate_paths.setdefault(normalized_key, candidate_path)
            if bool(candidate.get("selected_for_extraction")):
                selected_evtx_candidate_paths.setdefault(normalized_key, candidate_path)

    for row in parser_audit:
        if str(row.get("parser_name") or row.get("parser") or "") != "evtx_raw":
            continue
        source_file = str(row.get("source_file") or "").strip()
        channels_seen = [str(channel) for channel in (row.get("channels_seen") or []) if channel]
        if source_file and (_is_powershell_evtx_path(source_file) or any("powershell" in channel.lower() for channel in channels_seen)):
            has_powershell_evtx_audit_rows = True
            normalized_key = _normalize_forensic_path_key(source_file)
            parsed_powershell_evtx_files[normalized_key] = {
                "original_path": evtx_candidate_paths.get(normalized_key) or source_file,
                "parser_audit_source_file": source_file,
                "normalized_key": normalized_key,
                "records_read": int(row.get("records_read") or 0),
                "records_indexed": int(row.get("records_indexed") or row.get("events_indexed") or 0),
                "channels_seen": channels_seen,
                "event_ids_seen": [str(event_id) for event_id in (row.get("event_ids_seen") or []) if event_id not in (None, "")],
                "classification_counts": dict(row.get("classification_counts") or {}),
            }
            powershell_evtx_sources.add(source_file)
            powershell_evtx_source_keys.add(normalized_key)
            powershell_events_from_evtx_count += int(row.get("records_indexed") or row.get("events_indexed") or 0)
            for event_id in row.get("event_ids_seen") or []:
                event_id_text = str(event_id)
                if event_id_text:
                    powershell_evtx_event_ids_seen.add(event_id_text)
                    powershell_evtx_event_ids_count[event_id_text] = max(powershell_evtx_event_ids_count.get(event_id_text, 0), 1)
            for classification_name, count in (row.get("classification_counts") or {}).items():
                powershell_evtx_classification_counts[str(classification_name)] += int(count or 0)

    for normalized_key, original_path in sorted(evtx_candidate_paths.items(), key=lambda item: item[1]):
        if normalized_key in parsed_powershell_evtx_files:
            continue
        reason = "not_selected"
        if selected_evtx and normalized_key in selected_evtx_candidate_paths:
            reason = "selected_but_not_present_in_parser_audit"
        elif selected_evtx:
            reason = "not_selected_for_extraction"
        skipped_powershell_evtx_files.append({"original_path": original_path, "normalized_key": normalized_key, "reason": reason})

    for normalized_key, original_path in selected_evtx_candidate_paths.items():
        path_matching_debug.append(
            {
                "selected_original": original_path,
                "selected_normalized_key": normalized_key,
                "parser_audit_original": (parsed_powershell_evtx_files.get(normalized_key) or {}).get("parser_audit_source_file"),
                "parser_audit_normalized_key": normalized_key if normalized_key in parsed_powershell_evtx_files else None,
                "matched": normalized_key in parsed_powershell_evtx_files,
            }
        )

    evtx_files_scanned_for_powershell = len(selected_evtx_candidate_paths or parsed_powershell_evtx_files) if selected_evtx else 0
    skipped_powershell_evtx_reason = (
        "EVTX not selected; PowerShell EVTX channels were not scanned"
        if selected_powershell and not selected_evtx and evtx_candidate_paths
        else None
    )

    records_read = sum(int(row.get("records_read") or 0) for row in ps_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in ps_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in ps_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in ps_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "parser": sorted(by_parser_sources) if by_parser_sources else [],
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "powershell_records_read": records_read,
        "powershell_records_indexed": records_indexed,
        "detected_powershell_sources": len(detected_sources),
        "powershell_direct_sources_count": len(powershell_direct_sources),
        "powershell_evtx_sources_count": len(powershell_evtx_source_keys or powershell_evtx_sources),
        "powershell_events_from_evtx_count": powershell_events_from_evtx_count,
        "evtx_files_scanned_for_powershell": evtx_files_scanned_for_powershell,
        "selection_mode": selection_mode,
        "skipped_powershell_evtx_reason": skipped_powershell_evtx_reason,
        "discovered_powershell_evtx_candidates": [path for _, path in sorted(evtx_candidate_paths.items(), key=lambda item: item[1])],
        "selected_powershell_evtx_candidates": [path for _, path in sorted(selected_evtx_candidate_paths.items(), key=lambda item: item[1])],
        "parsed_powershell_evtx_files": [parsed_powershell_evtx_files[key] for key, _ in sorted(parsed_powershell_evtx_files.items(), key=lambda item: item[1].get("original_path") or item[1].get("parser_audit_source_file") or "")],
        "skipped_powershell_evtx_files": skipped_powershell_evtx_files[:25],
        "powershell_evtx_event_ids_count": dict(sorted(powershell_evtx_event_ids_count.items(), key=lambda item: item[0])),
        "powershell_evtx_event_ids_seen": sorted(powershell_evtx_event_ids_seen, key=lambda item: (len(item), item)),
        "powershell_evtx_classification_counts": dict(sorted(powershell_evtx_classification_counts.items())),
        "path_matching_debug": path_matching_debug[:25],
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "by_parser": dict(sorted(by_parser_sources.items())),
        "by_parser_sources": dict(sorted(by_parser_sources.items())),
        "by_parser_events": dict(sorted(by_parser_events.items())),
        "by_artifact_type": dict(sorted(by_artifact_type.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_event_id": dict(sorted(by_event_id.items(), key=lambda item: item[0])),
        "by_status": dict(sorted(by_status.items())),
        "encoded_command_count": encoded_command_count,
        "decoded_command_count": decoded_command_count,
        "download_count": download_count,
        "iex_count": iex_count,
        "defender_tampering_count": defender_tampering_count,
        "persistence_command_count": persistence_command_count,
        "sample_events": sample_events[:10],
        "suspicious_counts": dict(sorted(suspicious_counts.items())),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "parser_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "skipped_files": skipped_files[:20],
    }


def _is_powershell_evtx_event_candidate(event: dict) -> bool:
    artifact = event.get("artifact") or {}
    windows = event.get("windows") or {}
    powershell = event.get("powershell") or {}
    parser = str(artifact.get("parser") or "")
    artifact_type = str(artifact.get("type") or "")
    source_format = str(event.get("source_format") or "")
    powershell_artifact_type = str(powershell.get("artifact_type") or "")
    channel = str(windows.get("channel") or "")
    provider = str(windows.get("provider") or "")
    event_id = _nested_get(event, "windows.event_id")
    event_id_text = str(event_id) if event_id not in (None, "") else ""
    if parser == "powershell_evtx" or powershell_artifact_type == "powershell_evtx":
        return True
    if source_format == "evtx" and ("powershell" in channel.lower() or "powershell" in provider.lower()):
        return True
    if artifact_type in {"powershell", "windows_event"} and source_format == "evtx" and event_id_text in {"4103", "4104", "400", "403", "600", "800"} and ("powershell" in channel.lower() or "powershell" in provider.lower()):
        return True
    return False


def _reduce_powershell_evtx_sample_event(event: dict) -> dict:
    artifact = event.get("artifact") or {}
    reduced = {
        "id": event.get("id"),
        "source_file": event.get("source_file") or _nested_get(event, "powershell.source_file") or _nested_get(event, "artifact.source_path"),
        "source_format": event.get("source_format"),
        "source_tool": event.get("source_tool"),
        "artifact": {
            "type": artifact.get("type"),
            "parser": artifact.get("parser"),
        },
        "event": {
            "category": _nested_get(event, "event.category"),
            "type": _nested_get(event, "event.type"),
            "action": _nested_get(event, "event.action"),
            "timeline_include": _nested_get(event, "event.timeline_include"),
            "message": _nested_get(event, "event.message"),
        },
        "windows": {
            "channel": _nested_get(event, "windows.channel"),
            "provider": _nested_get(event, "windows.provider"),
            "event_id": _nested_get(event, "windows.event_id"),
            "record_id": _nested_get(event, "windows.record_id"),
        },
        "powershell": {
            "artifact_type": _nested_get(event, "powershell.artifact_type"),
            "command_preview": _nested_get(event, "powershell.command_preview"),
            "has_encoded_command": _nested_get(event, "powershell.has_encoded_command"),
            "has_download": _nested_get(event, "powershell.has_download"),
            "has_iex": _nested_get(event, "powershell.has_iex"),
            "has_execution_policy_bypass": _nested_get(event, "powershell.has_execution_policy_bypass"),
            "urls": _nested_get(event, "powershell.urls") or [],
            "domains": _nested_get(event, "powershell.domains") or [],
            "paths": _nested_get(event, "powershell.paths") or [],
        },
        "execution": {
            "source": _nested_get(event, "execution.source"),
            "is_execution_confirmed": _nested_get(event, "execution.is_execution_confirmed"),
            "confidence": _nested_get(event, "execution.confidence"),
        },
        "risk_score": event.get("risk_score"),
        "suspicious_reasons": event.get("suspicious_reasons") or [],
        "data_quality": event.get("data_quality") or [],
    }
    if str(artifact.get("type") or "") != "powershell" or str(artifact.get("parser") or "") != "powershell_evtx":
        reduced["semantic_normalization_warning"] = "expected artifact.type=powershell parser=powershell_evtx"
    return reduced


def _build_powershell_evtx_sample_events(events: list[dict]) -> list[dict]:
    filtered = [event for event in events if _is_powershell_evtx_event_candidate(event)]
    if not filtered:
        return []
    picked: list[dict] = []
    seen_ids: set[str] = set()

    def add_matching(match_fn, limit: int) -> None:  # noqa: ANN001
        nonlocal picked
        for event in filtered:
            event_key = str(event.get("id") or "")
            if event_key and event_key in seen_ids:
                continue
            if not match_fn(event):
                continue
            picked.append(_reduce_powershell_evtx_sample_event(event))
            if event_key:
                seen_ids.add(event_key)
            if len([item for item in picked if match_fn(item)]) >= limit:
                break

    add_matching(lambda item: str(_nested_get(item, "windows.event_id") or "") == "4104", 5)
    add_matching(lambda item: str(_nested_get(item, "windows.event_id") or "") == "4103", 3)
    add_matching(lambda item: str(_nested_get(item, "windows.event_id") or "") in {"400", "403", "600", "800"}, 3)
    for event in filtered:
        event_key = str(event.get("id") or "")
        if event_key and event_key in seen_ids:
            continue
        picked.append(_reduce_powershell_evtx_sample_event(event))
        if event_key:
            seen_ids.add(event_key)
        if len(picked) >= 10:
            break
    return picked[:10]


def _collect_powershell_evtx_sample_events(context: _DebugPackContext, existing_events: list[dict]) -> list[dict]:
    local_sample = _build_powershell_evtx_sample_events(existing_events)
    if local_sample:
        return local_sample
    search_request = _build_scope_search_request(context, page_size=250)
    body = build_search_query(search_request)
    body["size"] = 250
    body["track_total_hits"] = False
    body["_source"] = _debug_export_source_fields(
        include_raw_samples=context.request.include_raw_samples,
        include_raw_xml=context.request.include_raw_xml,
    )
    base_query = body.get("query") or {"match_all": {}}
    body["query"] = {
        "bool": {
            "must": [
                base_query,
                {
                    "bool": {
                        "should": [
                            {"term": {"artifact.parser": "powershell_evtx"}},
                            {"term": {"powershell.artifact_type": "powershell_evtx"}},
                            {
                                "bool": {
                                    "must": [
                                        {"term": {"source_format": "evtx"}},
                                        {"terms": {"windows.event_id": [4103, 4104, 400, 403, 600, 800]}},
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }
    response = search_documents(get_events_index(context.case.id), body)
    extra_events = [{"id": hit.get("_id"), **(hit.get("_source") or {})} for hit in (response.get("hits", {}).get("hits", []) or [])]
    sanitized_extra = [_sanitize_event(event, context.request) for event in extra_events]
    return _build_powershell_evtx_sample_events(sanitized_extra)


def _build_wmi_parse_report(parser_audit: list[dict], discovery_candidates: list[dict], events: list[dict], *, selected_artifact_types: list[str] | None = None, scope: str | None = None) -> dict:
    wmi_rows = [row for row in parser_audit if str(row.get("artifact_type") or "") == "wmi" or str(row.get("parser_name") or "").startswith("wmi")]
    wmi_candidates = [candidate for candidate in discovery_candidates if str(candidate.get("category") or "") == "wmi"]
    parseable_wmi_candidates = [
        candidate
        for candidate in wmi_candidates
        if bool(candidate.get("selected_for_extraction"))
        or bool(candidate.get("supported"))
        or str(candidate.get("parser_status") or "").lower() in {"ready", "handled_by_wmi_parser", "handled_by_evtx_parser", "parsed_native"}
    ]
    by_parser: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    sample_by_event_type: dict[str, int] = defaultdict(int)
    suspicious_counts: dict[str, int] = defaultdict(int)
    data_quality_counts: dict[str, int] = defaultdict(int)
    warning_counts: dict[str, int] = defaultdict(int)
    error_counts: dict[str, int] = defaultdict(int)
    sample_records: list[dict] = []
    detected_sources: set[str] = set()

    for row in wmi_rows:
        by_parser[str(row.get("parser_name") or row.get("parser") or "unknown")] += 1
        by_status[str(row.get("parser_status") or row.get("status") or "unknown")] += 1
        for source_value in (
            row.get("source_file"),
            row.get("source_path"),
            row.get("artifact"),
        ):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)
        for key, value in (row.get("suspicious_counts") or {}).items():
            suspicious_counts[str(key)] += int(value or 0)
        for key, value in (row.get("data_quality_counts") or {}).items():
            data_quality_counts[str(key)] += int(value or 0)
        for warning in row.get("warnings") or row.get("parse_warnings") or []:
            warning_counts[str(warning)] += 1
        for error in row.get("errors") or row.get("parser_errors") or []:
            error_counts[str(error)] += 1
        for sample in row.get("sample_records") or []:
            if isinstance(sample, dict) and len(sample_records) < 10:
                sample_records.append(sample)
            if isinstance(sample, dict):
                sample_source = str(sample.get("source_file") or sample.get("source_path") or "").strip()
                if sample_source:
                    detected_sources.add(sample_source)

    for event in events:
        artifact = event.get("artifact") or {}
        if artifact.get("type") != "wmi":
            continue
        sample_by_event_type[str(_nested_get(event, "event.type") or "unknown")] += 1
        for source_value in (
            _nested_get(event, "wmi.source_file"),
            event.get("source_file"),
            artifact.get("source_path"),
        ):
            text = str(source_value or "").strip()
            if text:
                detected_sources.add(text)

    for candidate in parseable_wmi_candidates:
        text = str(candidate.get("normalized_windows_path") or candidate.get("path") or candidate.get("source_path") or candidate.get("name") or "").strip()
        if text:
            detected_sources.add(text)

    records_read = sum(int(row.get("records_read") or 0) for row in wmi_rows)
    records_parsed = sum(int(row.get("records_parsed") or row.get("records_read") or 0) for row in wmi_rows)
    records_indexed = sum(int(row.get("records_indexed") or row.get("events_indexed") or 0) for row in wmi_rows)
    records_failed = sum(int(row.get("records_failed") or 0) for row in wmi_rows)

    return {
        "aggregation_scope": scope or "unknown",
        "selected_artifact_types": selected_artifact_types or [],
        "parser": sorted(by_parser) if by_parser else [],
        "detected_wmi_sources": len(detected_sources),
        "records_read": records_read,
        "records_parsed": records_parsed,
        "records_indexed": records_indexed,
        "records_failed": records_failed,
        "totals": {
            "records_read": records_read,
            "records_parsed": records_parsed,
            "records_indexed": records_indexed,
            "records_failed": records_failed,
        },
        "by_parser": dict(sorted(by_parser.items())),
        "by_status": dict(sorted(by_status.items())),
        "sample_by_event_type": dict(sorted(sample_by_event_type.items())),
        "sample_events": sample_records[:10],
        "suspicious_counts": dict(sorted(suspicious_counts.items())),
        "data_quality_counts": dict(sorted(data_quality_counts.items())),
        "parser_errors": [{"error": key, "count": value} for key, value in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
        "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))[:15]],
    }


def _safe_findings_count(db: Session, case_id: str, warnings: list[str]) -> int:
    try:
        result = db.execute(text("SELECT COUNT(*) FROM findings WHERE case_id = :case_id"), {"case_id": case_id})
        value = result.scalar()
        return int(value or 0)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"findings count failed: {exc.__class__.__name__}: {exc}")
        return 0
