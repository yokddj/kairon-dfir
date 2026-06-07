import json
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis import Redis
from rq import Queue
from rq.command import send_stop_job_command
from rq.job import Job
from rq.registry import StartedJobRegistry
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.activity import log_activity
from app.core.app_settings import load_runtime_settings
from app.core.config import get_settings
from app.core.database import get_db
from app.core.evidence_paths import fingerprint_external_path, storage_capabilities, validate_external_path
from app.core.manifest import default_manifest, write_manifest
from app.core.opensearch import OpenSearchIngestBlockedError, count_documents, delete_events_by_evidence, get_events_index, get_opensearch_client, resolve_aggregatable_field, search_documents
from app.core.storage import build_evidence_root, evidence_manifest_path, evidence_staging_dir, import_existing_path, reset_extracted_dir, reset_staging_dir, safe_remove, save_folder_uploads, save_upload, sha256_file
from app.ingest.detector import detect_evidence_type
from app.ingest.velociraptor import discover_velociraptor_evidences, open_evidence_container
from app.ingest.velociraptor.zip_inventory import is_supported_archive_container
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.rule_run import RuleRun, RuleRunStatus
from app.schemas.evidence import ArtifactRead, EvidenceRead, EvidenceRunQueuedResponse, EvidenceRunRead
from app.schemas.evidence import EvidenceBenchmarkQueuedResponse, EvidenceBenchmarkRead
from app.schemas.rule import DetectionRead, RuleRunRead, RulesRunRequest
from app.services.evidence_runs import (
    get_evidence_run,
    list_evidence_runs,
    mark_opensearch_infrastructure_block,
    merge_evidence_metadata,
    sync_ingest_run_from_metadata,
    start_ingest_run,
    upsert_ingest_run,
)
from app.services.ingest_benchmarks import (
    benchmark_mode_to_reprocess_mode,
    compare_ingest_benchmarks,
    create_ingest_benchmark,
    get_ingest_benchmark,
    get_ingest_benchmark_by_run_id,
    list_ingest_benchmarks,
    upsert_ingest_benchmark,
)
from app.services.ingest_plan import (
    append_plan_snapshot,
    build_plan,
    build_reprocess_preview,
    candidate_map_from_discovery,
    get_last_successful_plan,
    legacy_plan_from_metadata,
    persist_requested_plan,
    persist_plan,
    rebuild_ingest_plan_from_last_run,
)
from app.services.indexing_profiles import build_indexing_plan, create_indexing_plan_run, evidence_has_active_indexing, normalize_indexing_profile
from app.services.job_watchdog import run_benchmark_watchdog
from app.services.on_demand_modules import build_on_demand_module_registry
from app.services.parser_registry import (
    build_indexed_field_coverage_by_artifact_type,
    build_parser_coverage_matrix,
    build_parser_registry_report,
    build_searchable_contract_report,
)
from app.services.problematic_artifacts import (
    build_long_tail_artifacts_report,
    build_problematic_artifacts_report,
    problematic_artifacts_require_error_status,
    resolve_problematic_artifact_path,
    run_evtx_health_check,
)
from app.services.host_identity import is_invalid_host_value
from app.services.usable_ingest import FULL_FORENSIC_MODE, USABLE_INGEST_MODE, ingest_mode_metadata, normalize_ingest_mode
from datetime import UTC, datetime
from app.services.reconciliation import capture_reprocess_baseline
from app.workers.tasks import _resolve_retry_profile, enqueue_core_ez_rebuild, enqueue_defender_evtx_index, enqueue_ingest, enqueue_mft_full_index, enqueue_mft_summary_index, enqueue_problematic_artifact_retry, enqueue_recmd_user_activity_index, enqueue_srum_index


router = APIRouter(tags=["evidences"])
settings = get_settings()
redis_conn = Redis.from_url(settings.redis_url)
ingest_queue = Queue("dfir-ingest", connection=redis_conn)

RAW_COLLECTION_ENTRY_PATTERNS = (
    r"(^|/)(uploads/auto/|results/)",
    r"(^|/)(windows|users|programdata|documents and settings)/",
    r"windows/system32/winevt/logs/",
    r"windows/system32/wbem/repository/",
    r"windows/inf/setupapi\.dev\.log$",
    r"programdata/microsoft/network/downloader/(qmgr0\.dat|qmgr1\.dat|qmgr\.db)$",
    r"windows/system32/config/(system|software|sam|security)$",
    r"users/[^/]+/(ntuser\.dat|appdata/local/microsoft/windows/usrclass\.dat)$",
)


def _load_evidence_manifest(item: Evidence) -> dict:
    manifest_path = evidence_manifest_path(item.case_id, item.id)
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return default_manifest(item)
    return default_manifest(item)


def _artifact_id_lookup(artifact_rows: list[Artifact]) -> dict[tuple[str, str], str]:
    artifact_id_by_key: dict[tuple[str, str], str] = {}
    for artifact in artifact_rows:
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
    return artifact_id_by_key


def _problematic_artifacts_report_for_evidence(item: Evidence, db: Session) -> dict[str, Any]:
    manifest = _load_evidence_manifest(item)
    artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == item.id).all()
    return build_problematic_artifacts_report(item, manifest, artifact_id_by_key=_artifact_id_lookup(artifact_rows), artifact_rows=artifact_rows)


def _build_problematic_retry_candidates(report: dict[str, Any]) -> dict[str, Any]:
    items = list(report.get("items") or [])
    candidates: list[dict[str, Any]] = []
    excluded_skipped_empty = 0
    excluded_warnings = 0
    excluded_other = 0
    affected_families: dict[str, int] = {}
    for item in items:
        effective_status = str(item.get("effective_status") or item.get("status") or "").strip().lower()
        status = str(item.get("status") or "").strip().lower()
        records_read = int(item.get("effective_records_read") or item.get("records_read") or 0)
        records_indexed = int(item.get("effective_records_indexed") or item.get("records_indexed") or 0)
        retryable = bool(item.get("retryable"))
        data_loss_expected = bool(item.get("current_data_loss_expected") if item.get("current_data_loss_expected") is not None else item.get("data_loss_expected"))
        fully_indexed_warning = effective_status in {"parsed_with_warning", "accepted_warning", "health_check_only_valid", "source_missing_but_indexed"} and records_read > 0 and records_read == records_indexed
        no_records = effective_status in {"skipped_empty", "completed_no_records", "unsupported_no_records"} or status in {"skipped_empty", "completed_no_records", "unsupported_no_records"}
        if retryable and data_loss_expected and not no_records and not fully_indexed_warning and item.get("artifact_id"):
            candidate = dict(item)
            candidates.append(candidate)
            family = str(candidate.get("artifact_type") or candidate.get("parser") or "unknown").strip() or "unknown"
            affected_families[family] = affected_families.get(family, 0) + 1
        elif no_records:
            excluded_skipped_empty += 1
        elif fully_indexed_warning:
            excluded_warnings += 1
        else:
            excluded_other += 1
    return {
        "retry_candidates": candidates,
        "retry_candidate_count": len(candidates),
        "artifact_ids": [str(item.get("artifact_id")) for item in candidates if item.get("artifact_id")],
        "affected_families": affected_families,
        "excluded": {
            "skipped_empty": excluded_skipped_empty,
            "warnings_fully_indexed": excluded_warnings,
            "other_non_retryable": excluded_other,
        },
    }


def _fetch_evidence_sample_events(item: Evidence, *, size: int = 200) -> list[dict[str, Any]]:
    index = get_events_index(item.case_id)
    query = {"term": {"evidence_id": item.id}}
    aggregation_result = search_documents(
        index,
        {
            "size": 0,
            "query": query,
            "aggs": {
                "artifact_type": {"terms": {"field": "artifact.type", "size": 12}},
            },
        },
    )
    buckets = list((((aggregation_result.get("aggregations") or {}).get("artifact_type") or {}).get("buckets") or []))
    artifact_types = [str(bucket.get("key") or "").strip().lower() for bucket in buckets if bucket.get("key")]
    if not artifact_types:
        result = search_documents(
            index,
            {
                "size": size,
                "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
                "query": query,
            },
        )
        hits = list((result.get("hits") or {}).get("hits") or [])
        return [dict(hit.get("_source") or {}) for hit in hits if isinstance(hit, dict)]

    per_type = max(1, min(25, size // max(len(artifact_types), 1)))
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for artifact_type in artifact_types:
        result = search_documents(
            index,
            {
                "size": per_type,
                "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
                "query": {
                    "bool": {
                        "filter": [
                            query,
                            {"term": {"artifact.type": artifact_type}},
                        ]
                    }
                },
            },
        )
        hits = list((result.get("hits") or {}).get("hits") or [])
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            event_id = str(hit.get("_id") or "")
            if event_id and event_id in seen_ids:
                continue
            if event_id:
                seen_ids.add(event_id)
            source = dict(hit.get("_source") or {})
            if source:
                events.append(source)
        if len(events) >= size:
            break
    return events[:size]


def _build_evidence_search_summary(item: Evidence) -> dict[str, Any]:
    index = get_events_index(item.case_id)
    query = {"term": {"evidence_id": item.id}}
    total = int((count_documents(index, query).get("count") or 0))
    client = get_opensearch_client()
    source_file_field = resolve_aggregatable_field(client, index, "source_file") or "source_file.keyword"
    host_field = resolve_aggregatable_field(client, index, "host.name") or "host.name"
    user_field = resolve_aggregatable_field(client, index, "user.name") or "user.name"
    aggregation_result = search_documents(
        index,
        {
            "size": 0,
            "query": query,
            "aggs": {
                "artifact_type": {"terms": {"field": "artifact.type", "size": 12}},
                "parser": {"terms": {"field": "artifact.parser", "size": 12}},
                "source_file": {"terms": {"field": source_file_field, "size": 12}},
                "host": {"terms": {"field": host_field, "size": 12}},
                "user": {"terms": {"field": user_field, "size": 12}},
            },
        },
    )
    aggregations = dict(aggregation_result.get("aggregations") or {})

    def _bucket_map(name: str) -> dict[str, int]:
        buckets = list((aggregations.get(name) or {}).get("buckets") or [])
        values: dict[str, int] = {}
        for bucket in buckets:
            key = str(bucket.get("key") or "").strip()
            if not key:
                continue
            values[key] = int(bucket.get("doc_count") or 0)
        return values

    problematic_summary = (item.metadata_json or {}).get("problematic_artifacts_summary")
    problematic_summary = problematic_summary if isinstance(problematic_summary, dict) else {}
    warning_count = int(
        (item.metadata_json or {}).get("warning_count")
        if (item.metadata_json or {}).get("warning_count") is not None
        else problematic_summary.get("indexed_with_warning")
        if problematic_summary
        else len((item.metadata_json or {}).get("warnings") or [])
    )
    error_count = int(
        (item.metadata_json or {}).get("error_count")
        if (item.metadata_json or {}).get("error_count") is not None
        else problematic_summary.get("data_loss_expected_count")
        if problematic_summary
        else 0
    )

    return {
        "evidence_id": item.id,
        "case_id": item.case_id,
        "ingest_status": item.ingest_status.value if hasattr(item.ingest_status, "value") else str(item.ingest_status or ""),
        "display_status": str((item.metadata_json or {}).get("display_status") or "").strip() or None,
        "latest_ingest_run_id": str((item.metadata_json or {}).get("latest_ingest_run_id") or ""),
        "total_indexed_docs": total,
        "investigation_ready": bool((item.metadata_json or {}).get("investigation_ready")) or total > 0,
        "searchable_documents_count": int((item.metadata_json or {}).get("searchable_documents_count") or total),
        "status_reason": str((item.metadata_json or {}).get("status_reason") or "").strip() or None,
        "warning_count": warning_count,
        "error_count": error_count,
        "last_successful_ingest_run_id": str((item.metadata_json or {}).get("last_successful_ingest_run_id") or "").strip() or None,
        "artifact_type_counts": _bucket_map("artifact_type"),
        "parser_counts": _bucket_map("parser"),
        "source_file_counts": _bucket_map("source_file"),
        "host_counts": _bucket_map("host"),
        "user_counts": _bucket_map("user"),
    }


def _count_evidence_indexed_docs(item: Evidence) -> int:
    index = get_events_index(item.case_id)
    query = {"term": {"evidence_id": item.id}}
    return int((count_documents(index, query).get("count") or 0))


def _is_mft_candidate(entry: dict[str, Any]) -> bool:
    artifact_type = str(entry.get("artifact_type") or "").lower()
    parser = str(entry.get("parser") or entry.get("planned_parser") or "").lower()
    path_values = [
        entry.get("name"),
        entry.get("display_name"),
        entry.get("source_path"),
        entry.get("relative_path"),
        entry.get("path"),
    ]
    lowered_path = " ".join(str(value or "").lower() for value in path_values)
    if artifact_type in {"mft", "usn"} or parser in {"mftecmd", "mftecmd_csv", "mft_csv", "mft_json", "mft_jsonl", "mft_raw"}:
        return True
    return any(token in lowered_path for token in ("$mft", "mftecmd", "_mft.csv", "ntfs_raw"))


def _mft_backend_available() -> bool:
    try:
        from app.ingest.raw_parsers.mftecmd_backend import detect_mftecmd_backend

        return bool(detect_mftecmd_backend().get("available"))
    except Exception:
        return False


def _safe_count_mft_docs(item: Evidence) -> int:
    index = get_events_index(item.case_id)
    query = {
        "bool": {
            "filter": [{"term": {"evidence_id": item.id}}],
            "should": [
                {"terms": {"artifact.type": ["mft", "usn", "ntfs_raw"]}},
                {"terms": {"artifact.parser": ["mftecmd", "mftecmd_csv", "mft_csv", "mft_json", "mft_jsonl", "mft_raw", "ntfs_raw"]}},
                {"wildcard": {"source_file": {"value": "*MFT*", "case_insensitive": True}}},
            ],
            "minimum_should_match": 1,
        }
    }
    try:
        return int((count_documents(index, query).get("count") or 0))
    except Exception:
        return 0


def build_mft_diagnostic(item: Evidence, db: Session) -> dict[str, Any]:
    metadata = dict(item.metadata_json or {})
    mft_summary = dict(metadata.get("mft_summary") or {})
    manifest = _load_evidence_manifest(item)
    manifest_artifacts = [dict(entry) for entry in (manifest.get("artifacts") or []) if isinstance(entry, dict)]
    manifest_files = [dict(entry) for entry in (manifest.get("files") or []) if isinstance(entry, dict)]
    ingest_plan = dict(metadata.get("ingest_plan") or {})
    plan_disabled = [dict(entry) for entry in (ingest_plan.get("disabled_candidates") or []) if isinstance(entry, dict)]
    plan_selected = dict(ingest_plan.get("selected_by_parser") or {})
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    discovery_candidates = [dict(entry) for entry in (discovery.get("candidates") or []) if isinstance(entry, dict)]
    artifact_rows = [
        {
            "name": artifact.name,
            "source_path": artifact.source_path,
            "artifact_type": artifact.artifact_type,
            "parser": artifact.parser,
            "status": artifact.status,
            "record_count": artifact.record_count,
        }
        for artifact in db.query(Artifact).filter(Artifact.evidence_id == item.id).all()
    ]

    candidates = manifest_artifacts + manifest_files + plan_disabled + discovery_candidates + artifact_rows
    mft_candidates = [entry for entry in candidates if _is_mft_candidate(entry)]
    mft_candidates.sort(
        key=lambda entry: (
            0 if "$mft" in " ".join(str(entry.get(key) or "").lower() for key in ("name", "display_name", "source_path", "relative_path", "path")) else 1,
            str(entry.get("source_path") or entry.get("relative_path") or entry.get("name") or entry.get("display_name") or ""),
        )
    )
    selected_candidates = [
        entry
        for entry in mft_candidates
        if str(entry.get("status") or "").lower() in {"completed", "parsed", "indexed", "available", "selected"}
        or bool(entry.get("enabled"))
        or str(entry.get("parser") or "").lower() in {"mftecmd", "mftecmd_csv", "mft_csv", "mft_json", "mft_jsonl"}
    ]
    disabled_candidates = [
        entry
        for entry in mft_candidates
        if str(entry.get("status") or "").lower() in {"unsupported", "detected_not_parsed", "not_selected", "skipped", "deferred"}
        or str(entry.get("reason") or "").strip()
        or entry.get("enabled") is False
    ]
    indexed_docs = _safe_count_mft_docs(item)
    backend_available = _mft_backend_available()
    present = bool(mft_candidates)
    selected = indexed_docs > 0 or bool(selected_candidates) or any(str(key).lower() in {"mft", "mftecmd", "ntfs_raw"} for key in plan_selected)

    skipped_reason = ""
    if indexed_docs > 0:
        skipped_reason = ""
    elif not present:
        skipped_reason = "not_present"
    elif backend_available:
        skipped_reason = "available_on_demand"
    elif disabled_candidates:
        first = disabled_candidates[0]
        status = str(first.get("status") or "detected_not_indexed").strip()
        reason = str(first.get("reason") or "").strip()
        parser = str(first.get("parser") or "").strip()
        skipped_reason = reason or status or (f"detected as {parser}" if parser else "detected_not_indexed")
    elif not backend_available:
        skipped_reason = "backend_missing"
    else:
        skipped_reason = "detected_not_indexed"

    if indexed_docs > 0:
        recommended_action = "Open MFT / Filesystem view."
    elif present and backend_available:
        recommended_action = "Raw $MFT is present and MFTECmd is available. Use a scoped MFT summary or full MFT indexing action; it was not indexed in the main workflow."
    elif present:
        recommended_action = "Raw NTFS artifacts are present, but MFT indexing requires an available MFTECmd backend."
    else:
        recommended_action = "No action needed unless another evidence source contains MFT output."

    full_metadata = dict(metadata.get("mft_full") or {})
    full_is_current = str(metadata.get("mft_index_mode") or "").lower() == "full"
    current_records_total = metadata.get("mft_records_total") if full_is_current else mft_summary.get("records_total")
    current_records_indexed = metadata.get("mft_records_indexed") if full_is_current else mft_summary.get("records_indexed")
    current_records_skipped = metadata.get("mft_records_skipped") if full_is_current else mft_summary.get("records_skipped")
    current_elapsed_seconds = metadata.get("mft_elapsed_seconds") if full_is_current else mft_summary.get("elapsed_seconds")
    current_phase_timings = (full_metadata.get("phase_timings") or metadata.get("mft_phase_timings")) if full_is_current else mft_summary.get("phase_timings")
    current_selection_strategy = None if full_is_current else mft_summary.get("selection_strategy")
    current_source_hits = {} if full_is_current else dict(mft_summary.get("source_hits") or {})
    current_records_selected = current_records_indexed if full_is_current else (mft_summary.get("records_selected") or mft_summary.get("records_indexed") or indexed_docs)

    return {
        "evidence_id": item.id,
        "case_id": item.case_id,
        "mft_present_in_evidence": present,
        "mft_detected_by_inventory": bool(mft_candidates),
        "mft_selected_for_indexing": selected,
        "mft_indexed_docs": indexed_docs,
        "mft_skipped_reason": skipped_reason,
        "mft_backend_available": backend_available,
        "mft_parser_backend": metadata.get("mft_parser_backend") or (mft_summary.get("backend") if indexed_docs > 0 else None),
        "mft_parser_backend_version": metadata.get("mft_parser_backend_version") or mft_summary.get("backend_version"),
        "mft_index_mode": metadata.get("mft_index_mode") or mft_summary.get("mode"),
        "mft_coverage_status": metadata.get("mft_coverage_status") or mft_summary.get("coverage_status"),
        "mft_records_total": int(current_records_total or metadata.get("mft_records_total") or 0),
        "mft_records_indexed": int(current_records_indexed or metadata.get("mft_records_indexed") or indexed_docs or 0),
        "mft_records_skipped": int(current_records_skipped or metadata.get("mft_records_skipped") or 0),
        "mft_elapsed_seconds": float(current_elapsed_seconds or metadata.get("mft_elapsed_seconds") or 0),
        "mft_phase_timings": dict(current_phase_timings or {}),
        "mft_selection_strategy": current_selection_strategy,
        "mft_source_hits": current_source_hits,
        "mft_records_selected": int(current_records_selected or indexed_docs or 0),
        "mft_summary_status": (dict(metadata.get("mft_summary") or {}).get("status") or None),
        "mft_summary_records_indexed": int((dict(metadata.get("mft_summary") or {}).get("records_indexed") or 0)),
        "mft_full_status": metadata.get("mft_full_status") or (dict(metadata.get("mft_full") or {}).get("status") or "not_indexed"),
        "mft_full_records_total": int(metadata.get("mft_full_records_total") or (dict(metadata.get("mft_full") or {}).get("records_total") or 0)),
        "mft_full_records_indexed": int(metadata.get("mft_full_records_indexed") or (dict(metadata.get("mft_full") or {}).get("records_indexed") or 0)),
        "mft_full_started_at": metadata.get("mft_full_started_at") or (dict(metadata.get("mft_full") or {}).get("started_at")),
        "mft_full_finished_at": metadata.get("mft_full_finished_at") or (dict(metadata.get("mft_full") or {}).get("finished_at")),
        "mft_full_elapsed_seconds": float(metadata.get("mft_full_elapsed_seconds") or (dict(metadata.get("mft_full") or {}).get("elapsed_seconds") or 0)),
        "mft_full_coverage_status": metadata.get("mft_full_coverage_status") or (dict(metadata.get("mft_full") or {}).get("coverage_status")),
        "mft_full_backend": metadata.get("mft_full_backend") or (dict(metadata.get("mft_full") or {}).get("backend")),
        "mft_full_limits": dict(metadata.get("mft_full_limits") or (dict(metadata.get("mft_full") or {}).get("limits") or {})),
        "recommended_action": recommended_action,
        "detected_candidates": [
            {
                "name": entry.get("name") or entry.get("display_name") or "$MFT",
                "source_path": entry.get("source_path") or entry.get("relative_path") or entry.get("path") or "",
                "artifact_type": entry.get("artifact_type") or "",
                "parser": entry.get("parser") or entry.get("planned_parser") or "",
                "status": entry.get("status") or "",
                "reason": entry.get("reason") or "",
                "size": entry.get("size"),
            }
            for entry in mft_candidates[:10]
        ],
    }


def _recompute_evidence_status(item: Evidence, db: Session) -> dict[str, Any]:
    previous_status = item.ingest_status.value if hasattr(item.ingest_status, "value") else str(item.ingest_status or "")
    indexed_docs = _count_evidence_indexed_docs(item)
    metadata = dict(item.metadata_json or {})
    warnings = list(metadata.get("warnings") or [])
    error_log = dict(metadata.get("error_log") or item.error_log or {})
    has_searchable_data = indexed_docs > 0
    fatal_type = str(error_log.get("fatal_type") or "").strip()
    problematic_report = _problematic_artifacts_report_for_evidence(item, db)
    problematic_summary = dict(problematic_report.get("summary") or {})
    has_real_parser_failures = problematic_artifacts_require_error_status(problematic_report)
    skipped_empty_count = int(problematic_summary.get("skipped_empty") or 0)
    warning_count = int(problematic_summary.get("indexed_with_warning") or 0) + len(warnings)
    has_noncritical_errors = bool(warning_count or skipped_empty_count or (error_log and not has_real_parser_failures))
    latest_run_id = str(metadata.get("latest_ingest_run_id") or "").strip() or None

    if has_searchable_data:
        has_fatal_infrastructure_error = bool(fatal_type)
        new_status = IngestStatus.completed_with_errors if has_real_parser_failures or has_fatal_infrastructure_error else IngestStatus.completed
        reason = (
            "reconciled_failed_status_with_searchable_documents"
            if previous_status == IngestStatus.failed.value
            else "recomputed_searchable_evidence_status"
        )
        item.ingest_status = new_status
        metadata["investigation_ready"] = True
        metadata["searchable_documents_count"] = indexed_docs
        metadata["status_reason"] = reason
        metadata["display_status"] = new_status.value if has_real_parser_failures or has_fatal_infrastructure_error else "completed_with_warnings" if has_noncritical_errors else new_status.value
        metadata["warning_count"] = warning_count + skipped_empty_count
        metadata["error_count"] = int(problematic_summary.get("data_loss_expected_count") or 0) if has_real_parser_failures else 1 if has_fatal_infrastructure_error else 0
        metadata["problematic_artifacts_summary"] = problematic_summary
        metadata["last_successful_ingest_run_id"] = latest_run_id or str(metadata.get("run_id") or "")
        if not has_real_parser_failures and not has_fatal_infrastructure_error:
            historical_parser_errors = list(metadata.get("parser_errors") or [])
            historical_bulk_errors = list(metadata.get("bulk_index_errors") or [])
            if historical_parser_errors:
                metadata.setdefault("historical_parser_errors", historical_parser_errors)
            if historical_bulk_errors:
                metadata.setdefault("historical_bulk_index_errors", historical_bulk_errors)
            metadata["parser_errors"] = []
            metadata["bulk_index_errors"] = []
            if isinstance(metadata.get("error_log"), dict):
                next_error_log = dict(metadata.get("error_log") or {})
                if next_error_log.get("errors"):
                    next_error_log["historical_errors"] = list(next_error_log.get("historical_errors") or next_error_log.get("errors") or [])
                next_error_log["errors"] = []
                metadata["error_log"] = next_error_log
            cleaned_runs = []
            for run in metadata.get("ingest_runs") or []:
                if not isinstance(run, dict):
                    cleaned_runs.append(run)
                    continue
                next_run = dict(run)
                if str(next_run.get("run_id") or "") == (latest_run_id or str(metadata.get("run_id") or "")):
                    next_run["status"] = "completed"
                    next_run["phase"] = metadata["display_status"]
                    next_run["progress"] = 100
                    next_run["last_error"] = None
                    next_run["artifacts_failed"] = 0
                    next_run["failed_artifacts_count"] = 0
                    next_run["recovered_count"] = int(problematic_summary.get("recovered_count") or metadata.get("retry_recovered_count") or 0)
                    next_run["still_failed_count"] = 0
                    next_run["final_message"] = "Recovered parser failures; evidence is ready with warnings." if problematic_summary.get("recovered_count") else next_run.get("final_message")
                cleaned_runs.append(next_run)
            if cleaned_runs:
                metadata["ingest_runs"] = cleaned_runs
            metadata["progress_pct"] = 100
            metadata["current_phase"] = metadata["display_status"]
            metadata["artifacts_failed"] = 0
            if metadata.get("artifacts_total"):
                metadata["artifacts_done"] = metadata.get("artifacts_total")
                metadata["artifacts_processed"] = metadata.get("artifacts_total")
            metadata["retry_recovered_count"] = int(problematic_summary.get("recovered_count") or metadata.get("retry_recovered_count") or 0)
            metadata["retry_still_failed_count"] = 0
        metadata.setdefault("status_repairs", []).append(
            {
                "repaired_at": datetime.now(UTC).isoformat(),
                "previous_status": previous_status,
                "new_status": item.ingest_status.value,
                "reason": reason,
                "indexed_documents": indexed_docs,
                "fatal_type": fatal_type or None,
                "run_id": latest_run_id,
                "real_parser_failures": has_real_parser_failures,
                "skipped_empty": skipped_empty_count,
            }
        )
        item.metadata_json = metadata
        flag_modified(item, "metadata_json")
        if not item.processed_at:
            item.processed_at = datetime.now(UTC)
    else:
        metadata["investigation_ready"] = False
        metadata["searchable_documents_count"] = 0
        metadata["status_reason"] = "no_searchable_documents_indexed"
        metadata["display_status"] = item.ingest_status.value if hasattr(item.ingest_status, "value") else str(item.ingest_status or "")
        metadata["warning_count"] = len(warnings)
        metadata["error_count"] = 1 if error_log else 0
        item.metadata_json = metadata
        flag_modified(item, "metadata_json")

    db.add(item)
    log_activity(
        db,
        activity_type="evidence_status_recomputed",
        title="Evidence status recomputed",
        message=f"Evidence {item.original_filename} status recomputed from {previous_status} to {item.ingest_status.value if hasattr(item.ingest_status, 'value') else item.ingest_status}.",
        severity="warning" if item.ingest_status == IngestStatus.completed_with_errors else "info",
        case_id=item.case_id,
        evidence_id=item.id,
        metadata={
            "previous_status": previous_status,
            "new_status": item.ingest_status.value if hasattr(item.ingest_status, "value") else str(item.ingest_status),
            "indexed_documents": indexed_docs,
            "investigation_ready": bool(metadata.get("investigation_ready")),
            "status_reason": metadata.get("status_reason"),
            "fatal_type": fatal_type or None,
            "run_id": latest_run_id,
        },
        commit=False,
    )
    db.commit()
    db.refresh(item)
    return {
        "evidence_id": item.id,
        "previous_status": previous_status,
        "new_status": item.ingest_status.value if hasattr(item.ingest_status, "value") else str(item.ingest_status),
        "indexed_documents": indexed_docs,
        "has_searchable_data": has_searchable_data,
        "investigation_ready": bool(metadata.get("investigation_ready")),
        "has_noncritical_errors": has_noncritical_errors,
        "status_reason": metadata.get("status_reason"),
        "last_successful_ingest_run_id": metadata.get("last_successful_ingest_run_id"),
    }


def _source_tool_for_detected_evidence_type(evidence_type: EvidenceType) -> str | None:
    if evidence_type == EvidenceType.evtx:
        return "windows_event_log"
    return None


def _build_single_file_ingest_plan(evidence: Evidence, metadata: dict) -> dict | None:
    path = Path(str(evidence.stored_path or ""))
    if not path.is_file() or evidence.evidence_type != EvidenceType.evtx:
        return None
    selected_candidates = [
        {
            "candidate_id": f"single-evtx-{evidence.id}",
            "source_path": path.name,
            "relative_path": path.name,
            "artifact_type": "windows_event",
            "parser": "evtx_raw",
            "enabled": True,
            "reason": "single_evtx_file_detected",
            "fingerprint": evidence.sha256,
            "size": evidence.size_bytes,
            "mtime": int(path.stat().st_mtime) if path.exists() else None,
            "status": "available",
            "supported": True,
            "warnings": [],
            "display_name": path.name,
            "category": "evtx",
        }
    ]
    previous = dict(metadata.get("ingest_plan") or {})
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "created_at": previous.get("created_at") or datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "plan_version": 1,
        "source_kind": "raw_file",
        "discovery_mode": "single_file_detected",
        "selected_candidates": selected_candidates,
        "disabled_candidates": [],
        "parser_options": dict(previous.get("parser_options") or {}),
        "original_discovery_summary": {
            "collection_root": str(path.parent),
            "hostname": None,
            "summary": {"total_candidates": 1, "supported_candidates": 1},
            "warnings": [],
            "total_files_scanned": 1,
        },
        "last_reprocess_summary": dict(previous.get("last_reprocess_summary") or {}),
        "selected_by_artifact_type": {"windows_event": 1},
        "selected_by_parser": {"evtx_raw": 1},
    }


class ValidatePathRequest(BaseModel):
    path: str
    copy_to_storage: bool = False
    evidence_intent: str | None = None
    packaging: str | None = None


class RegisterPathRequest(BaseModel):
    path: str
    name: str | None = None
    copy_to_storage: bool = False
    start_ingest: bool = True
    storage_mode: str | None = None
    artifact_selection: dict | None = None
    evidence_intent: str | None = None
    packaging: str | None = None
    ingest_mode: str | None = None
    provided_host: str | None = None
    evtx_profile: str | None = None


class ReprocessPreviewRequest(BaseModel):
    mode: str = "previous_selection"


class ReprocessEvidenceRequest(BaseModel):
    mode: str = "previous_selection"
    selected_candidate_ids: list[str] = []
    parser_options: dict | None = None
    preserve_analyst_state: bool = True
    explicit_confirm: bool = False
    ingest_mode: str | None = None
    provided_host: str | None = None
    evtx_profile: str | None = None


class BenchmarkEvidenceRequest(BaseModel):
    mode: str = "reprocess_previous_selection"
    profile: str = "current"
    label: str | None = None
    notes: str | None = None
    stop_after_overlap_observed: bool = False
    max_duration_seconds: int = 3600
    skip_detections: bool = True
    skip_rules: bool = True
    autopilot: bool = False
    max_attempts: int = 2
    max_wall_time_seconds: int = 7200
    no_progress_timeout_seconds: int = 600
    heartbeat_timeout_seconds: int = 300


class BenchmarkCompareRequest(BaseModel):
    benchmark_ids: list[str]


class ProblematicArtifactsRetryRequest(BaseModel):
    artifact_ids: list[str] = []
    mode: str = "default"
    timeout_seconds: int | None = None
    preserve_existing_events: bool = True
    replace_existing_events_for_artifact: bool = False


class MftSummaryIndexRequest(BaseModel):
    max_records: int | None = None
    force: bool = False


class MftFullIndexRequest(BaseModel):
    max_records: int | None = None
    force: bool = False


class RecmdUserActivityIndexRequest(BaseModel):
    force: bool = False


class DefenderEvtxIndexRequest(BaseModel):
    force: bool = False


class SrumIndexRequest(BaseModel):
    force: bool = False


class EvidenceIndexingPlanRunRequest(BaseModel):
    profile: str = "recommended"
    force: bool = False


class EvidenceIndexingCancelRequest(BaseModel):
    reason: str | None = None


class CoreEzRebuildRequest(BaseModel):
    force: bool = True


class EvtxHealthCheckRequest(BaseModel):
    record_timeout_seconds: int | None = None
    max_records: int | None = None


class ProblematicArtifactAcceptWarningRequest(BaseModel):
    accepted_reason: str | None = None


class LongTailDeferRequest(BaseModel):
    artifact_ids: list[str] = []
    reason: str | None = None


def _normalize_reprocess_mode(value: str | None, *, has_previous_plan: bool) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return "previous_selection" if has_previous_plan else "choose_again"
    aliases = {
        "previous_selection": "previous_selection",
        "updated_discovery": "choose_again",
        "choose_again": "choose_again",
        "manual": "manual_selection",
        "manual_selection": "manual_selection",
        "full_rediscovery": "full_rediscovery",
    }
    return aliases.get(normalized, "previous_selection" if has_previous_plan else "choose_again")


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _mark_evidence_blocked_before_ingest(
    db: Session,
    evidence: Evidence,
    *,
    exc: OpenSearchIngestBlockedError,
    run_id: str | None = None,
    benchmark_id: str | None = None,
) -> None:
    metadata = mark_opensearch_infrastructure_block(
        evidence.metadata_json or {},
        reason=str(exc),
        run_id=run_id,
        benchmark_id=benchmark_id,
        preflight=getattr(exc, "details", None),
        finished_at=_utcnow_iso(),
    )
    if run_id:
        metadata["reprocess_request"] = None
    if benchmark_id:
        metadata["benchmark_request"] = None
    evidence.ingest_status = IngestStatus.failed
    evidence.error_log = dict(metadata.get("error_log") or {})
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    evidence.processed_at = datetime.now(UTC).replace(tzinfo=None)
    db.commit()
    db.refresh(evidence)


def _preserve_run_history(existing_metadata: dict, new_metadata: dict) -> dict:
    return merge_evidence_metadata(existing_metadata, new_metadata)


def _initial_metadata(extra: dict | None = None) -> dict:
    return {
        "phases": ["uploaded"],
        "current_phase": "uploaded",
        "progress_pct": 0,
        "tree": [],
        "detected_artifacts": 0,
        "processed_artifacts": 0,
        "indexed_events": 0,
        "records_processed": 0,
        "events_indexed": 0,
        "artifacts_processed": 0,
        "artifacts_total": 0,
        "raw_artifacts_detected": 0,
        "raw_artifacts_not_parsed": 0,
        **ingest_mode_metadata(FULL_FORENSIC_MODE),
        **(extra or {}),
    }


def _write_initial_manifest(evidence: Evidence) -> None:
    write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), default_manifest(evidence))


def _raw_collection_initial_metadata(extra: dict | None = None) -> dict:
    return {
        "phases": ["uploaded", "indexing_zip", "discovering_candidates", "waiting_selection", "extracting_selected", "parsing", "indexing_events"],
        "current_phase": "indexing_zip",
        "progress_pct": 10,
        "tree": [],
        "detected_artifacts": 0,
        "processed_artifacts": 0,
        "indexed_events": 0,
        "records_processed": 0,
        "events_indexed": 0,
        "artifacts_processed": 0,
        "artifacts_total": 0,
        "raw_artifacts_detected": 0,
        "raw_artifacts_not_parsed": 0,
        "source_type": "raw_collection",
        **ingest_mode_metadata(FULL_FORENSIC_MODE),
        **(extra or {}),
    }


def _normalize_entry_paths(entries: list[str]) -> list[str]:
    return [entry.replace("\\", "/").strip().lower() for entry in entries if entry]


def _looks_like_raw_collection_entries(entries: list[str]) -> bool:
    normalized_entries = _normalize_entry_paths(entries)
    meaningful_entries = [
        entry
        for entry in normalized_entries
        if entry
        and "__macosx/" not in entry
        and not Path(entry).name.startswith("._")
        and not entry.endswith("/.ds_store")
        and not entry.endswith("/thumbs.db")
        and not entry.endswith("/desktop.ini")
    ]
    evtx_entries = [entry for entry in meaningful_entries if entry.endswith(".evtx")]
    if len(evtx_entries) >= 3:
        return True
    for entry in meaningful_entries:
        for pattern in RAW_COLLECTION_ENTRY_PATTERNS:
            if re.search(pattern, entry, flags=re.IGNORECASE):
                return True
    return False


def _should_route_to_raw_collection_discovery(path: Path, entries: list[str] | None = None) -> bool:
    evidence_type = detect_evidence_type(path, entries)
    if evidence_type == EvidenceType.velociraptor_zip:
        return True
    if entries and _looks_like_raw_collection_entries(entries):
        return True
    return False


def _sample_directory_entries(path: Path, limit: int = 5000) -> list[str]:
    entries: list[str] = []
    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        entries.append(str(candidate.relative_to(path)).replace("\\", "/"))
        if len(entries) >= limit:
            break
    return entries


def _ensure_browser_folder_upload_allowed(files: list[UploadFile]) -> None:
    if not settings.backend_enable_experimental_folder_upload:
        raise HTTPException(
            status_code=403,
            detail="Browser folder upload is disabled. Compress the folder into ZIP/TAR/7z or use Register server-mounted path.",
        )
    file_count = len(files)
    total_bytes = sum(int(upload.size or 0) for upload in files)
    if file_count > settings.backend_experimental_folder_upload_max_files:
        raise HTTPException(
            status_code=413,
            detail=(
                "Browser folder upload limit exceeded: "
                f"{file_count} files > {settings.backend_experimental_folder_upload_max_files}. "
                "Use ZIP/TAR/7z or Register server-mounted path for large folders."
            ),
        )
    if total_bytes > settings.backend_experimental_folder_upload_max_total_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                "Browser folder upload size limit exceeded: "
                f"{total_bytes} bytes > {settings.backend_experimental_folder_upload_max_total_bytes}. "
                "Use ZIP/TAR/7z or Register server-mounted path for large folders."
            ),
        )


def _normalize_evidence_intent(value: str | None) -> str:
    normalized = str(value or "auto").strip().lower()
    if normalized in {"raw", "parsed", "mounted", "auto"}:
        return normalized
    return "auto"


def _normalize_packaging(value: str | None, *, folder_upload: bool = False) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"single_file", "archive", "directory", "mounted_path"}:
        return normalized
    return "directory" if folder_upload else "single_file"


def _normalize_provided_host(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    if is_invalid_host_value(normalized):
        return None
    return normalized or None


def _require_provided_host(value: str | None) -> str:
    normalized = _normalize_provided_host(value)
    if not normalized:
        raise HTTPException(status_code=400, detail="Host name is required for evidence indexing.")
    return normalized


def _evidence_intent_warnings(*, evidence_intent: str, detected_type: EvidenceType, path: Path) -> list[str]:
    warnings: list[str] = []
    suffix = path.suffix.lower()
    if evidence_intent == "raw" and detected_type in {EvidenceType.csv, EvidenceType.json, EvidenceType.jsonl}:
        warnings.append("This file looks like parsed evidence. Select Parsed evidence or continue as RAW.")
    if evidence_intent == "parsed" and suffix == ".evtx":
        warnings.append("This file looks like RAW Windows Event Log evidence and will be processed with the EVTX parser.")
    return warnings


def _finalize_raw_collection_discovery(db: Session, evidence: Evidence) -> Evidence:
    stored_path = Path(evidence.stored_path)
    container = open_evidence_container(stored_path)
    inventory_entries = container.list_entries()
    discovery = discover_velociraptor_evidences(container).as_dict()
    manifest = default_manifest(evidence)
    manifest["files"] = [
        {
            "path": entry.path,
            "size": entry.size,
            "sha256": None,
            "extension": Path(entry.path).suffix.lower(),
            "ignored": entry.ignored,
            "reason": entry.reason,
        }
        for entry in inventory_entries
    ]
    manifest["stats"]["total_files"] = len(inventory_entries)
    manifest["stats"]["processed_files"] = 0
    manifest["stats"]["ignored_files"] = sum(1 for entry in inventory_entries if entry.ignored)
    manifest["stats"]["detected_artifacts"] = discovery["summary"]["total_candidates"]
    write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), manifest)

    metadata = dict(evidence.metadata_json or {})
    metadata.update(
        {
            "current_phase": "waiting_selection",
            "progress_pct": 20,
            "tree": [],
            "detected_artifacts": discovery["summary"]["total_candidates"],
            "artifacts_total": discovery["summary"]["total_candidates"],
            "velociraptor_discovery": discovery,
            "folder_entries": [{"path": entry.path, "ignored": entry.ignored, "reason": entry.reason} for entry in inventory_entries],
            "total_zip_entries": len(inventory_entries),
            "ignored_entries": sum(1 for entry in inventory_entries if entry.ignored),
            "candidate_files": discovery["summary"]["total_candidates"],
            "collection_kind": "raw_evidence_collection",
        }
    )
    recommended_ids = [str(candidate.get("id") or "") for candidate in discovery.get("candidates") or [] if candidate.get("supported")]
    metadata = persist_plan(
        metadata,
        build_plan(
            evidence,
            metadata,
            discovery_mode="updated_discovery",
            selected_candidate_ids=recommended_ids,
            disabled_candidate_ids=[],
            selected_reason="recommended",
        ),
    )
    evidence.metadata_json = metadata
    evidence.source_tool = "raw_collection"
    evidence.evidence_type = EvidenceType.velociraptor_zip
    db.commit()
    db.refresh(evidence)
    return evidence


def _storage_metadata(*, mode: EvidenceStorageMode, original_path: str | None, storage_path: str, copied: bool, allowed_root: str | None, validation: dict) -> dict:
    return {
        "storage_mode": mode.value,
        "is_external": not copied,
        "copy_to_storage": copied,
        "original_path": original_path,
        "storage_path": storage_path,
        "path_validation": validation.get("path_validation") or {},
        "ingest_source": {
            "mode": mode.value,
            "original_path": original_path,
            "storage_path": storage_path,
            "copied": copied,
            "allowed_root": allowed_root,
            "registered_at": None,
            "registered_by": "ui_or_api",
        },
    }


def _velociraptor_reprocess_metadata(existing_metadata: dict) -> dict:
    discovery = dict(existing_metadata.get("velociraptor_discovery") or {})
    candidates = discovery.get("candidates") or []
    selected_ids = list(existing_metadata.get("velociraptor_selected_candidate_ids") or [])
    if not selected_ids:
        selected_ids = [str(candidate.get("id")) for candidate in candidates if candidate.get("id")]
    selected_categories = list(existing_metadata.get("velociraptor_selected_categories") or [])
    if not selected_categories:
        selected_categories = sorted(
            {
                str(candidate.get("category"))
                for candidate in candidates
                if candidate.get("category") and str(candidate.get("id")) in set(selected_ids)
            }
        )
    metadata = {
        "phases": ["uploaded"],
        "current_phase": "uploaded",
        "progress_pct": 0,
        "tree": [],
        "detected_artifacts": len(candidates),
        "processed_artifacts": 0,
        "indexed_events": 0,
        "records_processed": 0,
        "events_indexed": 0,
        "artifacts_processed": 0,
        "artifacts_total": len(candidates),
        "raw_artifacts_detected": 0,
        "raw_artifacts_not_parsed": 0,
        "source_type": existing_metadata.get("source_type") or "raw_collection",
        "velociraptor_discovery": discovery,
        "folder_entries": existing_metadata.get("folder_entries") or [],
        "total_zip_entries": existing_metadata.get("total_zip_entries"),
        "ignored_entries": existing_metadata.get("ignored_entries"),
        "candidate_files": existing_metadata.get("candidate_files", len(candidates)),
        "velociraptor_selected_candidate_ids": selected_ids,
        "velociraptor_selected_categories": selected_categories,
        "selected_candidates": len(selected_ids),
        "selected_files_total": None,
        "selected_files_extracted": 0,
        "current_item": None,
        "collection_kind": existing_metadata.get("collection_kind") or "raw_evidence_collection",
        "reprocessed": True,
        "artifact_retry_runs": list(existing_metadata.get("artifact_retry_runs") or []),
        "ingest_runs": list(existing_metadata.get("ingest_runs") or []),
        "latest_ingest_run_id": existing_metadata.get("latest_ingest_run_id"),
    }
    return metadata


def _apply_reprocess_selection_metadata(evidence: Evidence, existing_metadata: dict, selected_candidate_ids: list[str], mode: str, parser_options: dict | None = None) -> dict:
    metadata = _velociraptor_reprocess_metadata(existing_metadata)
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    candidates = list(discovery.get("candidates") or [])
    selected_ids = {str(item) for item in selected_candidate_ids if item}
    selected_categories = sorted(
        {
            str(candidate.get("category") or "")
            for candidate in candidates
            if str(candidate.get("id") or "") in selected_ids and candidate.get("category")
        }
    )
    not_selected_by_category: dict[str, int] = {}
    updated_candidates: list[dict] = []
    for candidate in candidates:
        candidate_copy = dict(candidate)
        candidate_id = str(candidate.get("id") or "")
        is_selected = candidate_id in selected_ids
        candidate_copy["selected_for_extraction"] = is_selected
        if not is_selected:
            category = str(candidate.get("category") or "other")
            not_selected_by_category[category] = not_selected_by_category.get(category, 0) + 1
        updated_candidates.append(candidate_copy)
    discovery["candidates"] = updated_candidates
    metadata["velociraptor_discovery"] = discovery
    metadata["velociraptor_selected_candidate_ids"] = sorted(selected_ids)
    metadata["velociraptor_selected_categories"] = selected_categories
    metadata["selected_artifact_types"] = selected_categories
    metadata["not_selected_candidates_count_by_category"] = not_selected_by_category
    metadata["selected_candidates"] = len(selected_ids)
    plan = build_plan(
        evidence,
        metadata,
        discovery_mode=mode,
        selected_candidate_ids=sorted(selected_ids),
        disabled_candidate_ids=[str(candidate.get("id") or "") for candidate in candidates if str(candidate.get("id") or "") not in selected_ids],
        parser_options=parser_options or {},
        selected_reason="selected_by_user" if mode in {"manual_selection", "choose_again"} else "previous_plan" if mode == "previous_selection" else "recommended",
    )
    metadata = persist_plan(metadata, plan)
    adjusted_selected_ids = {str(item.get("candidate_id") or "") for item in plan.get("selected_candidates") or [] if item.get("candidate_id")}
    adjusted_categories = sorted(
        {
            str(candidate.get("category") or "")
            for candidate in candidates
            if str(candidate.get("id") or "") in adjusted_selected_ids and candidate.get("category")
        }
    )
    adjusted_not_selected_by_category: dict[str, int] = {}
    adjusted_candidates: list[dict] = []
    for candidate in candidates:
        candidate_copy = dict(candidate)
        is_selected = str(candidate.get("id") or "") in adjusted_selected_ids
        candidate_copy["selected_for_extraction"] = is_selected
        if not is_selected:
            category = str(candidate.get("category") or "other")
            adjusted_not_selected_by_category[category] = adjusted_not_selected_by_category.get(category, 0) + 1
            if str(candidate.get("id") or "") in {str(item.get("artifact_id") or "") for item in metadata.get("evtx_deferred_files") or []}:
                candidate_copy["parser_status"] = "evtx_profile_deferred"
        adjusted_candidates.append(candidate_copy)
    discovery["candidates"] = adjusted_candidates
    metadata["velociraptor_discovery"] = discovery
    metadata["velociraptor_selected_candidate_ids"] = sorted(adjusted_selected_ids)
    metadata["velociraptor_selected_categories"] = adjusted_categories
    metadata["selected_artifact_types"] = adjusted_categories
    metadata["not_selected_candidates_count_by_category"] = adjusted_not_selected_by_category
    metadata["selected_candidates"] = len(adjusted_selected_ids)
    return metadata


def _rehydrate_raw_collection_metadata(item: Evidence, existing_metadata: dict) -> dict | None:
    stored_path = Path(item.stored_path)
    try:
        container = open_evidence_container(stored_path)
        inventory_entries = container.list_entries()
        entry_paths = [entry.path for entry in inventory_entries if not entry.is_dir]
        if not _should_route_to_raw_collection_discovery(stored_path, entry_paths):
            return None
        discovery = discover_velociraptor_evidences(container).as_dict()
    except Exception:  # noqa: BLE001
        return None
    rehydrated = dict(existing_metadata)
    rehydrated.update(
        {
            "source_type": existing_metadata.get("source_type") or "raw_collection",
            "collection_kind": existing_metadata.get("collection_kind") or "raw_evidence_collection",
            "velociraptor_discovery": discovery,
            "folder_entries": [{"path": entry.path, "ignored": entry.ignored, "reason": entry.reason} for entry in inventory_entries],
            "total_zip_entries": len(inventory_entries),
            "ignored_entries": sum(1 for entry in inventory_entries if entry.ignored),
            "candidate_files": discovery["summary"]["total_candidates"],
        }
    )
    return rehydrated


def _is_raw_collection_with_discovery(item: Evidence, existing_metadata: dict) -> bool:
    discovery = existing_metadata.get("velociraptor_discovery")
    if not discovery:
        return False
    collection_kind = str(existing_metadata.get("collection_kind") or "")
    source_type = str(existing_metadata.get("source_type") or "")
    if collection_kind == "raw_evidence_collection" or source_type == "raw_collection":
        return True
    return item.evidence_type == EvidenceType.velociraptor_zip


def _prepare_reprocess_state(item: Evidence, existing_metadata: dict) -> tuple[dict, bool]:
    if _is_raw_collection_with_discovery(item, existing_metadata):
        return _velociraptor_reprocess_metadata(existing_metadata), True
    return _initial_metadata({"reprocessed": True}), True


def _preview_selected_candidate_ids(preview: dict) -> list[str]:
    return [str(item.get("candidate_id") or "") for item in (preview.get("selected_candidates") or []) if item.get("candidate_id")]


def _recommended_supported_candidate_ids(metadata: dict) -> list[str]:
    requested_plan = metadata.get("requested_ingest_plan") if isinstance(metadata.get("requested_ingest_plan"), dict) else None
    ingest_plan = metadata.get("ingest_plan") if isinstance(metadata.get("ingest_plan"), dict) else None
    for plan in (requested_plan, ingest_plan):
        selected = [
            str(item.get("candidate_id") or item.get("id") or "")
            for item in ((plan or {}).get("selected_candidates") or [])
            if str(item.get("candidate_id") or item.get("id") or "").strip()
        ]
        if selected:
            return selected
    discovery = metadata.get("velociraptor_discovery") if isinstance(metadata.get("velociraptor_discovery"), dict) else {}
    return [
        str(candidate.get("id") or "")
        for candidate in (discovery.get("candidates") or [])
        if candidate.get("supported") and str(candidate.get("id") or "").strip()
    ]


def _persist_generic_ingest_plan(db: Session, evidence: Evidence, *, discovery_mode: str = "manual") -> Evidence:
    metadata = dict(evidence.metadata_json or {})
    plan = _build_single_file_ingest_plan(evidence, metadata)
    if not plan:
        plan = build_plan(evidence, metadata, discovery_mode=discovery_mode, selected_candidate_ids=[], disabled_candidate_ids=[])
    metadata = persist_plan(metadata, plan)
    evidence.metadata_json = metadata
    db.commit()
    db.refresh(evidence)
    return evidence


def _ensure_rebuilt_ingest_plan(db: Session, evidence: Evidence) -> Evidence:
    metadata = dict(evidence.metadata_json or {})
    current_plan = metadata.get("ingest_plan") if isinstance(metadata.get("ingest_plan"), dict) else None
    has_selected_candidates = bool((current_plan or {}).get("selected_candidates"))
    if has_selected_candidates:
        return evidence
    rebuilt = rebuild_ingest_plan_from_last_run(db, evidence, metadata, persist=True)
    if rebuilt:
        return db.get(Evidence, evidence.id) or evidence
    return evidence


def _capture_reingest_baseline(item: Evidence, existing_metadata: dict, previous_manifest: dict) -> dict:
    captured_at = getattr(item, "processed_at", None) or getattr(item, "created_at", None)
    previous_stats = dict(previous_manifest.get("stats") or {})
    baseline_events = int(
        previous_stats.get("indexed_events")
        or existing_metadata.get("events_indexed")
        or existing_metadata.get("indexed_events")
        or 0
    )
    by_parser: dict[str, int] = {}
    by_artifact_type: dict[str, int] = {}
    for artifact in previous_manifest.get("artifacts") or []:
        parser_name = str(artifact.get("parser") or artifact.get("planned_parser") or artifact.get("artifact_type") or "unknown")
        artifact_type = str(artifact.get("artifact_type") or "unknown")
        ingest_audit = dict(artifact.get("ingest_audit") or {})
        indexed = int(ingest_audit.get("events_indexed") or artifact.get("record_count") or 0)
        by_parser[parser_name] = by_parser.get(parser_name, 0) + indexed
        by_artifact_type[artifact_type] = by_artifact_type.get(artifact_type, 0) + indexed
    return {
        "captured_at": captured_at.isoformat() if captured_at else None,
        "evidence_id": item.id,
        "case_id": item.case_id,
        "expected_events_baseline": baseline_events,
        "events_indexed": baseline_events,
        "artifacts_detected": int(previous_stats.get("detected_artifacts") or 0),
        "artifacts_parsed": int(previous_stats.get("results_artifacts_parsed") or 0) + int(previous_stats.get("raw_artifacts_parsed") or 0),
        "artifacts_failed": int(previous_stats.get("failed_artifacts") or 0),
        "selected_candidates": int(existing_metadata.get("selected_candidates") or 0),
        "selected_files_total": int(existing_metadata.get("selected_files_total") or 0),
        "selected_files_extracted": int(existing_metadata.get("selected_files_extracted") or 0),
        "candidate_files": int(existing_metadata.get("candidate_files") or 0),
        "source_type": existing_metadata.get("source_type"),
        "collection_kind": existing_metadata.get("collection_kind"),
        "detected_host": item.detected_host,
        "by_parser": dict(sorted(by_parser.items())),
        "by_artifact_type": dict(sorted(by_artifact_type.items())),
    }


@router.post("/api/cases/{case_id}/evidences/upload", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    folder_upload: bool = Form(False),
    folder_name: str | None = Form(None),
    evidence_intent: str | None = Form(None),
    packaging: str | None = Form(None),
    ingest_mode: str | None = Form(None),
    provided_host: str | None = Form(None),
    evtx_profile: str | None = Form(None),
    db: Session = Depends(get_db),
) -> Evidence:
    if hasattr(ingest_mode, "get") and not hasattr(db, "get"):
        db = ingest_mode  # type: ignore[assignment]
        ingest_mode = None
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    normalized_provided_host = _require_provided_host(provided_host)
    evidence_id, stored_path, size = save_upload(case_id, file)
    uploaded_name = file.filename or stored_path.name
    raw_collection = False
    folder_entries: list[dict] = []
    file_count: int | None = None
    normalized_intent = _normalize_evidence_intent(evidence_intent)
    normalized_packaging = _normalize_packaging(packaging, folder_upload=folder_upload)
    normalized_ingest_mode = normalize_ingest_mode(ingest_mode)
    normalized_evtx_profile = str(evtx_profile or "").strip() or None
    detected_type = detect_evidence_type(stored_path)
    if is_supported_archive_container(stored_path):
        try:
            container = open_evidence_container(stored_path)
            inventory_entries = container.list_entries()
            entry_paths = [entry.path for entry in inventory_entries if not entry.is_dir]
            raw_collection = _should_route_to_raw_collection_discovery(stored_path, entry_paths)
            detected_type = detect_evidence_type(stored_path, entry_paths)
            if folder_upload:
                folder_entries = [{"path": entry.path, "ignored": entry.ignored, "reason": entry.reason} for entry in inventory_entries]
                file_count = sum(1 for entry in inventory_entries if not entry.is_dir and not entry.ignored)
        except Exception:  # noqa: BLE001
            raw_collection = False
            folder_entries = []
            file_count = None
    display_name = (folder_name or "").strip() or uploaded_name
    detected_warnings = _evidence_intent_warnings(evidence_intent=normalized_intent, detected_type=detected_type, path=stored_path)
    source_tool = "raw_collection" if raw_collection else _source_tool_for_detected_evidence_type(detected_type)
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=display_name,
        stored_path=str(stored_path),
        original_path=str(stored_path),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip if raw_collection else EvidenceType.parsed_folder if folder_upload else detected_type,
        sha256=sha256_file(stored_path),
        size_bytes=size,
        file_count=file_count,
        ingest_status=IngestStatus.pending,
        source_tool=source_tool,
        path_validation={},
        ingest_source={
            "mode": EvidenceStorageMode.uploaded.value,
            "original_path": str(stored_path),
            "storage_path": str(stored_path),
            "copied": True,
            "evidence_intent": normalized_intent,
            "packaging": normalized_packaging,
            "ingest_mode": normalized_ingest_mode,
            "provided_host": normalized_provided_host,
            "evtx_profile": normalized_evtx_profile,
        },
        metadata_json=_raw_collection_initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "folder_entries": folder_entries, "folder_upload": True, "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile})
        if raw_collection and folder_upload
        else _raw_collection_initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile})
        if raw_collection
        else _initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "folder_entries": folder_entries, "folder_upload": True, "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile})
        if folder_upload
        else _initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile}),
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    evidence.ingest_source = {
        **(evidence.ingest_source or {}),
        "registered_at": evidence.created_at.isoformat() if evidence.created_at else None,
    }
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    if raw_collection:
        evidence = _finalize_raw_collection_discovery(db, evidence)
        log_activity(
            db,
            activity_type="evidence_uploaded",
            title="Raw evidence collection discovered",
            message=f"Discovered raw evidences in {evidence.original_filename}",
            case_id=case_id,
            evidence_id=evidence.id,
            metadata={"source_type": "raw_collection", "evidence_intent": normalized_intent, "packaging": normalized_packaging, "ingest_mode": normalized_ingest_mode},
        )
        return evidence
    evidence = _persist_generic_ingest_plan(db, evidence)
    log_activity(
        db,
        activity_type="evidence_uploaded",
        title="Folder evidence uploaded" if folder_upload else "Evidence uploaded",
        message=f"Uploaded parsed folder {evidence.original_filename}" if folder_upload else f"Uploaded evidence {evidence.original_filename}",
        case_id=case_id,
        evidence_id=evidence.id,
        metadata={"evidence_type": evidence.evidence_type.value, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "ingest_mode": normalized_ingest_mode},
    )
    try:
        enqueue_ingest(evidence.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, evidence, exc=exc)
    return evidence


@router.post("/api/cases/{case_id}/evidences/upload-folder", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def upload_evidence_folder(case_id: str, files: list[UploadFile] = File(...), db: Session = Depends(get_db)) -> Evidence:
    _ensure_browser_folder_upload_allowed(files)
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    evidence_id, folder_path, total_size, folder_sha256, folder_entries, folder_label = save_folder_uploads(case_id, files)
    raw_collection = _should_route_to_raw_collection_discovery(folder_path, [str(item.get("path") or "") for item in folder_entries])
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=folder_label,
        stored_path=str(folder_path),
        original_path=str(folder_path),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip if raw_collection else EvidenceType.parsed_folder,
        sha256=folder_sha256,
        size_bytes=total_size,
        file_count=len([item for item in folder_entries if not item.get("ignored")]),
        ingest_status=IngestStatus.pending,
        source_tool="raw_collection" if raw_collection else None,
        path_validation={},
        ingest_source={"mode": EvidenceStorageMode.uploaded.value, "original_path": str(folder_path), "storage_path": str(folder_path), "copied": True},
        metadata_json=_raw_collection_initial_metadata({"folder_entries": folder_entries}) if raw_collection else _initial_metadata({"folder_entries": folder_entries}),
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    if raw_collection:
        evidence = _finalize_raw_collection_discovery(db, evidence)
        log_activity(
            db,
            activity_type="evidence_uploaded",
            title="Raw evidence collection discovered",
            message=f"Discovered raw evidences in {evidence.original_filename}",
            case_id=case_id,
            evidence_id=evidence.id,
            metadata={"source_type": "raw_collection"},
        )
        return evidence
    evidence = _persist_generic_ingest_plan(db, evidence)
    log_activity(
        db,
        activity_type="evidence_uploaded",
        title="Folder evidence uploaded",
        message=f"Uploaded parsed folder {evidence.original_filename}",
        case_id=case_id,
        evidence_id=evidence.id,
        metadata={"evidence_type": evidence.evidence_type.value},
    )
    try:
        enqueue_ingest(evidence.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, evidence, exc=exc)
    return evidence


@router.get("/api/storage/allowed-roots")
def get_allowed_storage_roots() -> dict:
    return storage_capabilities()


@router.post("/api/evidence/validate-path")
def validate_storage_path(payload: ValidatePathRequest, db: Session = Depends(get_db)) -> dict:
    runtime_settings = load_runtime_settings(db)
    scan_limit = max(100, int(runtime_settings.get("MOUNTED_PATH_SCAN_LIMIT", 5000)))
    result = validate_external_path(payload.path, scan_limit=scan_limit)
    result["evidence_intent"] = _normalize_evidence_intent(payload.evidence_intent)
    result["packaging"] = _normalize_packaging(payload.packaging)
    return result


@router.post("/api/cases/{case_id}/evidences/register-path", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
@router.post("/api/cases/{case_id}/evidence/register-path", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def register_evidence_path(case_id: str, payload: RegisterPathRequest, db: Session = Depends(get_db)) -> Evidence:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    runtime_settings = load_runtime_settings(db)
    scan_limit = max(100, int(runtime_settings.get("MOUNTED_PATH_SCAN_LIMIT", 5000)))
    validation = validate_external_path(payload.path, scan_limit=scan_limit)
    if not validation.get("valid"):
        raise HTTPException(status_code=400, detail=validation.get("error") or "invalid_path")

    resolved_path = Path(str(validation["resolved_path"]))
    copy_to_storage = bool(payload.copy_to_storage)
    storage_mode = EvidenceStorageMode.shared_path if str(payload.storage_mode or "").strip() == "shared_path" else EvidenceStorageMode.mounted_path
    normalized_intent = _normalize_evidence_intent(payload.evidence_intent or "mounted")
    normalized_packaging = _normalize_packaging(payload.packaging or "mounted_path")
    normalized_ingest_mode = normalize_ingest_mode(payload.ingest_mode)
    normalized_provided_host = _require_provided_host(payload.provided_host)
    normalized_evtx_profile = str(payload.evtx_profile or "").strip() or None

    if copy_to_storage:
        evidence_id, stored_path, size_bytes = import_existing_path(case_id, resolved_path)
        sha256 = sha256_file(stored_path) if stored_path.is_file() else fingerprint_external_path(stored_path)
        is_external = False
    else:
        evidence_id = str(uuid4())
        build_evidence_root(case_id, evidence_id)
        stored_path = resolved_path
        size_bytes = int(validation.get("size_bytes") or 0)
        sha256 = sha256_file(resolved_path) if resolved_path.is_file() else fingerprint_external_path(resolved_path)
        is_external = True

    entry_paths = None
    if stored_path.is_dir():
        entry_paths = _sample_directory_entries(stored_path, limit=scan_limit)
    elif stored_path.suffix.lower() == ".zip":
        try:
            container = open_evidence_container(stored_path)
            entry_paths = [entry.path for entry in container.list_entries() if not entry.is_dir]
        except Exception:
            entry_paths = None
    raw_collection = _should_route_to_raw_collection_discovery(stored_path, entry_paths)
    detected_type = detect_evidence_type(stored_path, entry_paths)
    original_name = payload.name or resolved_path.name
    detected_warnings = _evidence_intent_warnings(evidence_intent=normalized_intent, detected_type=detected_type, path=stored_path)
    storage_meta = _storage_metadata(
        mode=storage_mode if is_external else EvidenceStorageMode.uploaded,
        original_path=str(resolved_path),
        storage_path=str(stored_path),
        copied=copy_to_storage,
        allowed_root=str(validation.get("allowed_root") or ""),
        validation=validation,
    )
    ingest_source = dict(storage_meta["ingest_source"])
    ingest_source["registered_at"] = None
    ingest_source["evidence_intent"] = normalized_intent
    ingest_source["packaging"] = normalized_packaging
    ingest_source["ingest_mode"] = normalized_ingest_mode
    ingest_source["provided_host"] = normalized_provided_host
    ingest_source["evtx_profile"] = normalized_evtx_profile

    metadata = (
        _raw_collection_initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), **storage_meta, "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile})
        if raw_collection
        else _initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), **storage_meta, "warnings": detected_warnings, "evidence_intent": normalized_intent, "packaging": normalized_packaging, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile})
    )
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=original_name,
        stored_path=str(stored_path),
        original_path=str(resolved_path),
        storage_mode=storage_mode if is_external else EvidenceStorageMode.uploaded,
        is_external=is_external,
        copy_to_storage=copy_to_storage,
        evidence_type=EvidenceType.velociraptor_zip if raw_collection else detected_type,
        sha256=sha256,
        size_bytes=size_bytes,
        file_count=validation.get("file_count"),
        ingest_status=IngestStatus.pending,
        source_tool="raw_collection" if raw_collection else _source_tool_for_detected_evidence_type(detected_type),
        path_validation=validation.get("path_validation") or {},
        ingest_source=ingest_source,
        metadata_json=metadata,
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    if raw_collection:
        evidence = _finalize_raw_collection_discovery(db, evidence)
    else:
        evidence = _persist_generic_ingest_plan(db, evidence)
    log_activity(
        db,
        activity_type="evidence_registered_path",
        title="Evidence registered from server path",
        message=f"Registered evidence from {resolved_path}",
        case_id=case_id,
        evidence_id=evidence.id,
        metadata={"path": str(resolved_path), "copied": copy_to_storage, "storage_mode": evidence.storage_mode.value, "ingest_mode": normalized_ingest_mode},
    )
    if payload.start_ingest and not raw_collection:
        try:
            enqueue_ingest(evidence.id)
        except OpenSearchIngestBlockedError as exc:
            _mark_evidence_blocked_before_ingest(db, evidence, exc=exc)
    return evidence


@router.get("/api/cases/{case_id}/evidences", response_model=list[EvidenceRead])
def list_evidences(case_id: str, db: Session = Depends(get_db)) -> list[Evidence]:
    return db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.desc()).all()


@router.get("/api/evidences/{evidence_id}", response_model=EvidenceRead)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)) -> Evidence:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _ensure_rebuilt_ingest_plan(db, item)


@router.get("/api/evidences/{evidence_id}/manifest")
def get_evidence_manifest(evidence_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    path = evidence_manifest_path(item.case_id, item.id)
    if not path.exists():
        return JSONResponse(default_manifest(item))
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@router.get("/api/evidences/{evidence_id}/problematic-artifacts")
def get_problematic_artifacts(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _problematic_artifacts_report_for_evidence(item, db)


@router.get("/api/evidences/{evidence_id}/problematic-artifacts/retry-candidates")
def get_problematic_artifact_retry_candidates(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    report = _problematic_artifacts_report_for_evidence(item, db)
    candidates = _build_problematic_retry_candidates(report)
    return {
        "evidence_id": item.id,
        "summary": report.get("summary") or {},
        **candidates,
    }


@router.get("/api/evidences/{evidence_id}/long-tail-artifacts")
def get_long_tail_artifacts(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == item.id).all()
    return build_long_tail_artifacts_report(item, artifact_rows=artifact_rows)


def _store_long_tail_defer_request(item: Evidence, *, artifact_ids: list[str], reason: str | None = None) -> dict[str, Any]:
    metadata = dict(item.metadata_json or {})
    requests = [dict(entry) for entry in (metadata.get("long_tail_defer_requests") or []) if isinstance(entry, dict)]
    existing_by_id = {str(entry.get("artifact_id") or ""): entry for entry in requests if str(entry.get("artifact_id") or "")}
    for artifact_id in artifact_ids:
        existing_by_id[str(artifact_id)] = {
            "artifact_id": str(artifact_id),
            "requested_at": _utcnow_iso(),
            "reason": reason or "manual_long_tail_defer_request",
            "state": "requested",
        }
    metadata["long_tail_defer_requests"] = list(existing_by_id.values())[-100:]
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    return metadata


def _apply_safe_long_tail_defer(
    item: Evidence,
    artifact_rows: list[Artifact],
    *,
    artifact_ids: list[str],
    reason: str | None = None,
) -> tuple[list[str], list[str]]:
    metadata = _store_long_tail_defer_request(item, artifact_ids=artifact_ids, reason=reason)
    running_source_paths = {
        str(entry.get("source_path") or "")
        for entry in (metadata.get("tail_current_artifacts") or [])
        if isinstance(entry, dict)
    }
    deferred_now: list[str] = []
    request_only: list[str] = []
    for artifact in artifact_rows:
        if artifact.id not in artifact_ids:
            continue
        source_path = str(artifact.source_path or "")
        if source_path and source_path in running_source_paths:
            request_only.append(artifact.id)
            continue
        if artifact.status in {"queued_parallel", "processing"}:
            artifact.status = "partial_indexed_deferred" if int(artifact.record_count or 0) > 0 else "deferred_long_tail"
            deferred_now.append(artifact.id)
        else:
            request_only.append(artifact.id)
    return deferred_now, request_only


def _find_active_ingest_job_for_evidence(evidence_id: str) -> Job | None:
    started = StartedJobRegistry(queue=ingest_queue)
    for job_id in started.get_job_ids():
        try:
            job = Job.fetch(job_id, connection=redis_conn)
        except Exception:  # noqa: BLE001
            continue
        if str(job.func_name or "") != "app.workers.tasks.ingest_evidence":
            continue
        if not job.args:
            continue
        if str(job.args[0] or "") == evidence_id:
            return job
    return None


def _finalize_long_tail_deferred_run(
    db: Session,
    *,
    evidence: Evidence,
    run_id: str,
    artifact_rows: list[Artifact],
    deferred_artifact_ids: list[str],
    reason: str,
) -> dict[str, Any]:
    manifest_path = evidence_manifest_path(evidence.case_id, evidence.id)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else default_manifest(evidence)
    manifest_artifacts = [item for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    manifest_by_source = {str(item.get("source_path") or ""): item for item in manifest_artifacts if str(item.get("source_path") or "").strip()}
    tail_items = {
        str(item.get("source_path") or ""): dict(item)
        for item in (dict(evidence.metadata_json or {}).get("tail_current_artifacts") or [])
        if isinstance(item, dict)
    }
    errors = list(manifest.get("errors") or [])

    for artifact in artifact_rows:
        if artifact.id not in deferred_artifact_ids:
            continue
        runtime = tail_items.get(str(artifact.source_path or ""), {})
        records_read = max(int(runtime.get("records_read") or 0), int(artifact.record_count or 0))
        records_indexed = max(int(runtime.get("records_indexed") or 0), int(artifact.record_count or 0))
        artifact.record_count = records_indexed
        artifact.status = "partial_indexed_deferred" if records_indexed > 0 else "deferred_long_tail"
        manifest_artifact = manifest_by_source.get(str(artifact.source_path or ""))
        if manifest_artifact is None:
            manifest_artifact = {
                "name": artifact.name,
                "source_path": artifact.source_path,
                "artifact_type": artifact.artifact_type,
                "parser": artifact.parser,
            }
            manifest_artifacts.append(manifest_artifact)
            manifest_by_source[str(artifact.source_path or "")] = manifest_artifact
        manifest_artifact["status"] = artifact.status
        ingest_audit = dict(manifest_artifact.get("ingest_audit") or {})
        ingest_audit["records_read"] = records_read
        ingest_audit["records_indexed"] = records_indexed
        ingest_audit["events_indexed"] = records_indexed
        ingest_audit["deferred_at"] = _utcnow_iso()
        ingest_audit["deferred_reason"] = reason
        ingest_audit["last_progress_at"] = dict(evidence.metadata_json or {}).get("tail_last_progress_at")
        manifest_artifact["ingest_audit"] = ingest_audit
        if not any(str(item.get("artifact") or "") == artifact.name for item in errors if isinstance(item, dict)):
            errors.append(
                {
                    "artifact": artifact.name,
                    "error": "Artifact did not reach terminal parser completion before long-tail defer finalized the main ingest.",
                }
            )

    manifest["artifacts"] = manifest_artifacts
    manifest["errors"] = errors
    manifest["processed_at"] = _utcnow_iso()
    write_manifest(manifest_path, manifest)

    metadata = dict(evidence.metadata_json or {})
    completed_count = db.query(Artifact).filter(Artifact.evidence_id == evidence.id, Artifact.status == "completed").count()
    failed_count = db.query(Artifact).filter(
        Artifact.evidence_id == evidence.id,
        Artifact.status.in_(["failed", "failed_timeout", "failed_aborted", "partial_indexed_deferred", "deferred_long_tail"]),
    ).count()
    events_indexed = int(metadata.get("events_indexed") or 0)
    records_read = int(metadata.get("records_processed") or 0)
    finished_at = _utcnow_iso()
    metadata.update(
        {
            "current_ingest_run_id": None,
            "current_phase": "completed_with_errors",
            "current_action": "long_tail_deferred_finalized",
            "current_artifact": None,
            "current_artifact_path": None,
            "current_artifact_source": None,
            "current_artifact_records_read": 0,
            "current_artifact_records_indexed": 0,
            "tail_artifacts_total": 0,
            "tail_artifacts_running": 0,
            "tail_artifacts_queued": 0,
            "tail_artifacts_completed": completed_count,
            "tail_artifacts_failed": failed_count,
            "tail_records_read": 0,
            "tail_records_indexed": 0,
            "tail_last_progress_at": finished_at,
            "tail_records_per_sec": 0,
            "tail_current_artifacts": [],
            "tail_slowest_artifacts": [],
            "long_tail_deferred_at": finished_at,
            "long_tail_deferred_reason": reason,
        }
    )
    metadata = upsert_ingest_run(
        metadata,
        run_id,
        {
            "status": "completed_with_errors",
            "phase": "completed_with_errors",
            "finished_at": finished_at,
            "current_artifact": None,
            "artifact_progress": None,
            "artifacts_total": int(metadata.get("artifacts_total") or completed_count + failed_count),
            "artifacts_done": completed_count,
            "artifacts_failed": failed_count,
            "failed_artifacts_count": failed_count,
            "records_read": records_read,
            "records_indexed": events_indexed,
            "events_indexed": events_indexed,
            "last_error": "Main ingest finalized with deferred long-tail artifacts.",
        },
    )
    report = build_problematic_artifacts_report(evidence, manifest, artifact_rows=artifact_rows)
    metadata["problematic_artifacts_summary"] = report.get("summary") or {}
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    evidence.ingest_status = IngestStatus.completed_with_errors
    evidence.processed_at = datetime.now(UTC).replace(tzinfo=None)
    flag_modified(evidence, "metadata_json")
    db.commit()
    db.refresh(evidence)
    return {
        "completed_count": completed_count,
        "failed_count": failed_count,
        "events_indexed": events_indexed,
        "records_read": records_read,
        "report": report,
    }


@router.post("/api/evidences/{evidence_id}/artifacts/{artifact_id}/defer-long-tail")
def defer_single_long_tail_artifact(
    evidence_id: str,
    artifact_id: str,
    payload: LongTailDeferRequest | None = None,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact = db.get(Artifact, artifact_id)
    if not artifact or artifact.evidence_id != item.id:
        raise HTTPException(status_code=404, detail="Artifact not found")
    deferred_now, request_only = _apply_safe_long_tail_defer(item, [artifact], artifact_ids=[artifact.id], reason=(payload.reason if payload else None))
    db.commit()
    return {
        "accepted": True,
        "artifact_ids": [artifact.id],
        "reason": (payload.reason if payload else None) or "manual_long_tail_defer_request",
        "status": "deferred" if deferred_now else "defer_requested",
        "deferred_now": deferred_now,
        "request_only": request_only,
    }


@router.post("/api/evidences/{evidence_id}/long-tail/defer")
def defer_long_tail_artifacts(
    evidence_id: str,
    payload: LongTailDeferRequest,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == item.id).all()
    report = build_long_tail_artifacts_report(item, artifact_rows=artifact_rows)
    artifact_ids = list(dict.fromkeys([str(artifact_id) for artifact_id in payload.artifact_ids if artifact_id]))
    if not artifact_ids:
        artifact_ids = [
            str(entry.get("artifact_id"))
            for entry in report.get("items") or []
            if entry.get("artifact_id") and str(entry.get("long_tail_state") or "") in {"slow_progressing", "stalled_no_progress", "queued_tail"}
        ]
    if not artifact_ids:
        raise HTTPException(status_code=400, detail="No long-tail artifacts are eligible for defer request.")
    deferred_now, request_only = _apply_safe_long_tail_defer(item, artifact_rows, artifact_ids=artifact_ids, reason=payload.reason)
    non_terminal_artifact_ids = {
        artifact.id
        for artifact in artifact_rows
        if str(artifact.status or "").strip().lower() in {"processing", "queued_parallel"}
    }
    only_tail_remaining = non_terminal_artifact_ids and non_terminal_artifact_ids.issubset(set(artifact_ids))
    finalized = False
    if only_tail_remaining:
        active_job = _find_active_ingest_job_for_evidence(item.id)
        if active_job:
            try:
                send_stop_job_command(redis_conn, active_job.id)
            except Exception:  # noqa: BLE001
                pass
        finalization = _finalize_long_tail_deferred_run(
            db,
            evidence=item,
            run_id=str((item.metadata_json or {}).get("current_ingest_run_id") or (item.metadata_json or {}).get("latest_ingest_run_id") or ""),
            artifact_rows=artifact_rows,
            deferred_artifact_ids=artifact_ids,
            reason=payload.reason or "operator_decision_long_tail_blocks_ingest",
        )
        finalized = True
        return {
            "accepted": True,
            "artifact_ids": artifact_ids,
            "reason": payload.reason or "operator_decision_long_tail_blocks_ingest",
            "status": "finalized_with_deferred_long_tail",
            "deferred_now": artifact_ids,
            "request_only": [],
            "finalized": finalized,
            "events_indexed": finalization["events_indexed"],
            "records_read": finalization["records_read"],
        }
    db.commit()
    return {
        "accepted": True,
        "artifact_ids": artifact_ids,
        "reason": payload.reason or "manual_long_tail_defer_request",
        "status": "deferred" if deferred_now and not request_only else "defer_requested",
        "deferred_now": deferred_now,
        "request_only": request_only,
        "finalized": finalized,
    }


def _store_artifact_health_check(item: Evidence, payload: dict) -> None:
    metadata = dict(item.metadata_json or {})
    rows = list(metadata.get("artifact_health_checks") or [])
    artifact_key = str(payload.get("artifact_key") or "")
    rows = [row for row in rows if str(row.get("artifact_key") or "") != artifact_key]
    rows.append(payload)
    metadata["artifact_health_checks"] = rows[-100:]
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")


def _store_artifact_warning_acceptance(item: Evidence, *, artifact_key: str, accepted_reason: str | None = None) -> None:
    metadata = dict(item.metadata_json or {})
    rows = dict(metadata.get("artifact_warning_acceptances") or {})
    rows[str(artifact_key)] = {
        "accepted_at": _utcnow_iso(),
        "accepted_reason": accepted_reason,
    }
    metadata["artifact_warning_acceptances"] = rows
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")


@router.post("/api/evidences/{evidence_id}/artifacts/{artifact_id}/evtx-health-check")
def evtx_health_check(
    evidence_id: str,
    artifact_id: str,
    payload: EvtxHealthCheckRequest | None = None,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact = db.get(Artifact, artifact_id)
    if not artifact or artifact.evidence_id != item.id:
        raise HTTPException(status_code=404, detail="Artifact not found")
    manifest_path = evidence_manifest_path(item.case_id, item.id)
    manifest = default_manifest(item)
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            manifest = default_manifest(item)
    path = resolve_problematic_artifact_path(
        item,
        source_path=str(artifact.source_path or ""),
        artifact_name=str(artifact.name or ""),
        manifest=manifest,
    )
    timeout_seconds = max(int((payload.record_timeout_seconds if payload else None) or 60), 1)
    max_records = max(int((payload.max_records if payload else None) or 200), 1)
    health = run_evtx_health_check(path or Path("__missing__"), record_timeout_seconds=timeout_seconds, max_records=max_records)
    response = {
        "artifact_id": artifact.id,
        "filename": artifact.name,
        "exists": bool(path and path.exists()),
        "resolved_path": str(path) if path else None,
        **health,
        "health_check_at": _utcnow_iso(),
        "artifact_key": artifact.id,
    }
    _store_artifact_health_check(item, response)
    db.commit()
    return response


@router.post("/api/evidences/{evidence_id}/problematic-artifacts/{artifact_id}/accept-warning")
def accept_problematic_artifact_warning(
    evidence_id: str,
    artifact_id: str,
    payload: ProblematicArtifactAcceptWarningRequest | None = None,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact = db.get(Artifact, artifact_id)
    if not artifact or artifact.evidence_id != item.id:
        raise HTTPException(status_code=404, detail="Artifact not found")
    _store_artifact_warning_acceptance(
        item,
        artifact_key=artifact.id,
        accepted_reason=(payload.accepted_reason if payload else None),
    )
    db.commit()
    manifest_path = evidence_manifest_path(item.case_id, item.id)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else default_manifest(item)
    artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == item.id).all()
    artifact_id_by_key: dict[tuple[str, str], str] = {}
    for row in artifact_rows:
        source_path = str(row.source_path or "")
        parser_name = str(row.parser or "")
        artifact_name = str(row.name or "")
        for key in ((source_path, parser_name), (source_path, ""), (artifact_name, parser_name), (artifact_name, "")):
            if key[0]:
                artifact_id_by_key[key] = row.id
    report = build_problematic_artifacts_report(item, manifest, artifact_id_by_key=artifact_id_by_key)
    for problem_item in report.get("items") or []:
        if str(problem_item.get("artifact_id") or "") == artifact_id:
            return problem_item
    raise HTTPException(status_code=404, detail="Problematic artifact not found")


@router.get("/api/evidences/{evidence_id}/runs", response_model=list[EvidenceRunRead])
def get_evidence_runs(evidence_id: str, db: Session = Depends(get_db)) -> list[dict]:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    metadata = dict(item.metadata_json or {})
    latest_run_id = str(metadata.get("latest_ingest_run_id") or "").strip()
    if latest_run_id:
        metadata = sync_ingest_run_from_metadata(metadata, run_id=latest_run_id, ingest_status=str(item.ingest_status or ""))
    return list_evidence_runs(metadata)


@router.get("/api/evidences/{evidence_id}/runs/{run_id}", response_model=EvidenceRunRead)
def get_evidence_run_detail(evidence_id: str, run_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    metadata = dict(item.metadata_json or {})
    latest_run_id = str(metadata.get("latest_ingest_run_id") or "").strip()
    if run_id and run_id == latest_run_id:
        metadata = sync_ingest_run_from_metadata(metadata, run_id=run_id, ingest_status=str(item.ingest_status or ""))
    run = get_evidence_run(metadata, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.post("/api/evidences/{evidence_id}/artifacts/{artifact_id}/retry")
def retry_problematic_artifact(
    evidence_id: str,
    artifact_id: str,
    payload: ProblematicArtifactsRetryRequest,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    artifact = db.get(Artifact, artifact_id)
    if not artifact or artifact.evidence_id != item.id:
        raise HTTPException(status_code=404, detail="Artifact not found")
    if payload.replace_existing_events_for_artifact:
        raise HTTPException(status_code=400, detail="Replacing existing events for a single artifact is not supported yet.")
    run_id = enqueue_problematic_artifact_retry(
        evidence_id=item.id,
        artifact_ids=[artifact.id],
        mode=payload.mode,
        timeout_seconds=payload.timeout_seconds,
        preserve_existing_events=payload.preserve_existing_events,
        replace_existing_events_for_artifact=payload.replace_existing_events_for_artifact,
    )
    metadata = dict(item.metadata_json or {})
    retry_runs = list(metadata.get("artifact_retry_runs") or [])
    retry_runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "mode": payload.mode,
            "artifact_ids": [artifact.id],
            "started_at": None,
            "finished_at": None,
            "items": [],
            "retry_profile": _resolve_retry_profile(payload.mode, payload.timeout_seconds),
        }
    )
    metadata["artifact_retry_runs"] = retry_runs[-25:]
    item.metadata_json = metadata
    db.commit()
    return {"accepted": True, "run_id": run_id, "artifact_ids": [artifact.id], "mode": payload.mode}


@router.post("/api/evidences/{evidence_id}/problematic-artifacts/retry")
def retry_problematic_artifacts(
    evidence_id: str,
    payload: ProblematicArtifactsRetryRequest,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if payload.replace_existing_events_for_artifact:
        raise HTTPException(status_code=400, detail="Replacing existing events for selected artifacts is not supported yet.")
    artifact_ids = list(dict.fromkeys(payload.artifact_ids))
    if not artifact_ids:
        report = _problematic_artifacts_report_for_evidence(item, db)
        artifact_ids = _build_problematic_retry_candidates(report)["artifact_ids"]
    if not artifact_ids:
        raise HTTPException(status_code=400, detail="No retryable problematic artifacts found for this evidence.")
    run_id = enqueue_problematic_artifact_retry(
        evidence_id=item.id,
        artifact_ids=artifact_ids,
        mode=payload.mode,
        timeout_seconds=payload.timeout_seconds,
        preserve_existing_events=payload.preserve_existing_events,
        replace_existing_events_for_artifact=payload.replace_existing_events_for_artifact,
    )
    metadata = dict(item.metadata_json or {})
    retry_runs = list(metadata.get("artifact_retry_runs") or [])
    retry_runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "mode": payload.mode,
            "artifact_ids": artifact_ids,
            "started_at": None,
            "finished_at": None,
            "items": [],
            "retry_profile": _resolve_retry_profile(payload.mode, payload.timeout_seconds),
        }
    )
    metadata["artifact_retry_runs"] = retry_runs[-25:]
    item.metadata_json = metadata
    db.commit()
    return {"accepted": True, "run_id": run_id, "artifact_ids": artifact_ids, "mode": payload.mode}


@router.post("/api/evidences/{evidence_id}/reprocess/preview")
def preview_reprocess_evidence(
    evidence_id: str,
    payload: ReprocessPreviewRequest,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    item = _ensure_rebuilt_ingest_plan(db, item)

    existing_metadata = dict(item.metadata_json or {})
    previous_plan = get_last_successful_plan(item, existing_metadata)
    mode = _normalize_reprocess_mode(payload.mode, has_previous_plan=previous_plan is not None)
    rehydrated_raw_collection = _rehydrate_raw_collection_metadata(item, existing_metadata)
    current_metadata = rehydrated_raw_collection or existing_metadata

    if _is_raw_collection_with_discovery(item, current_metadata):
        return build_reprocess_preview(
            item,
            metadata=existing_metadata,
            current_metadata=current_metadata,
            mode=mode,
        )

    warnings: list[str] = []
    if not previous_plan:
        warnings.append("No previous ingest plan is stored for this evidence.")
    return {
        "evidence_id": item.id,
        "previous_plan_available": previous_plan is not None,
        "mode": mode,
        "summary": {
            "previous_selected": len((previous_plan or {}).get("selected_candidates") or []),
            "available_again": len((previous_plan or {}).get("selected_candidates") or []),
            "missing": 0,
            "changed": 0,
            "new_candidates": 0,
            "unsupported": 0,
        },
        "selected_candidates": list((previous_plan or {}).get("selected_candidates") or []),
        "missing_candidates": [],
        "new_candidates": [],
        "changed_candidates": [],
        "warnings": warnings,
        "previous_plan": previous_plan,
    }


@router.post("/api/evidences/{evidence_id}/reprocess", response_model=EvidenceRunQueuedResponse)
def reprocess_evidence(
    evidence_id: str,
    payload: ReprocessEvidenceRequest,
    db: Session = Depends(get_db),
) -> Evidence:
    return _queue_reprocess_request(
        evidence_id,
        payload,
        db,
        benchmark_request=None,
    )


def _queue_reprocess_request(
    evidence_id: str,
    payload: ReprocessEvidenceRequest,
    db: Session,
    *,
    benchmark_request: dict | None,
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    item = _ensure_rebuilt_ingest_plan(db, item)
    existing_metadata = dict(item.metadata_json or {})
    existing_request = dict(existing_metadata.get("reprocess_request") or {})
    active_run_id = str(existing_metadata.get("current_ingest_run_id") or existing_request.get("run_id") or "")
    if item.ingest_status in {IngestStatus.pending, IngestStatus.processing} and active_run_id:
        if benchmark_request:
            active_benchmark = get_ingest_benchmark_by_run_id(existing_metadata, active_run_id)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "active_ingest_exists",
                    "active_run_id": active_run_id,
                    "active_benchmark_id": (active_benchmark or {}).get("benchmark_id"),
                    "message": "An ingest/reprocess is already active for this evidence.",
                },
            )
        return {
            "accepted": True,
            "evidence_id": item.id,
            "run_id": active_run_id,
            "status": "processing" if item.ingest_status == IngestStatus.processing else "queued",
            "mode": str(existing_request.get("mode") or payload.mode or "previous_selection"),
        }
    previous_plan = get_last_successful_plan(item, existing_metadata)
    mode = _normalize_reprocess_mode(payload.mode, has_previous_plan=previous_plan is not None)
    requested_ingest_mode = normalize_ingest_mode(getattr(payload, "ingest_mode", None) or existing_metadata.get("ingest_mode"))
    requested_provided_host = _normalize_provided_host(getattr(payload, "provided_host", None)) or _normalize_provided_host(existing_metadata.get("provided_host"))
    if not requested_provided_host:
        raise HTTPException(status_code=400, detail="Host name is required for evidence reprocess.")
    requested_evtx_profile = str(getattr(payload, "evtx_profile", None) or existing_metadata.get("evtx_profile") or "").strip() or None
    if mode == "full_rediscovery" and not payload.explicit_confirm:
        raise HTTPException(status_code=400, detail="Full rediscovery requires explicit confirmation.")
    rehydrated_raw_collection = _rehydrate_raw_collection_metadata(item, existing_metadata)
    if rehydrated_raw_collection:
        existing_metadata = rehydrated_raw_collection
        item.evidence_type = EvidenceType.velociraptor_zip
        item.source_tool = "raw_collection"
    manifest_path = evidence_manifest_path(item.case_id, item.id)
    previous_manifest = default_manifest(item)
    if manifest_path.exists():
        try:
            previous_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            previous_manifest = default_manifest(item)

    is_raw_with_discovery = _is_raw_collection_with_discovery(item, existing_metadata)
    preserve_analyst_state = bool(payload.preserve_analyst_state)
    skip_detection_cleanup_for_mode = requested_ingest_mode == USABLE_INGEST_MODE
    if skip_detection_cleanup_for_mode:
        preserve_analyst_state = False
    if preserve_analyst_state:
        existing_metadata["reconciliation_baseline_pending"] = {
            "requested_at": _utcnow_iso(),
            "preserve_analyst_state": True,
        }

    selected_candidate_ids: list[str] = []
    reprocess_preview: dict | None = None
    if is_raw_with_discovery:
        if mode in {"manual_selection", "choose_again"}:
            selected_candidate_ids = [str(item_id) for item_id in payload.selected_candidate_ids if item_id]
            if mode == "manual_selection" and not selected_candidate_ids:
                raise HTTPException(status_code=400, detail="Manual reprocess requires at least one selected candidate.")
            if mode == "choose_again" and not selected_candidate_ids:
                reprocess_preview = build_reprocess_preview(
                    item,
                    metadata=existing_metadata,
                    current_metadata=existing_metadata,
                    mode=mode,
                )
                selected_candidate_ids = _preview_selected_candidate_ids(reprocess_preview)
        else:
            reprocess_preview = build_reprocess_preview(
                item,
                metadata=existing_metadata,
                current_metadata=existing_metadata,
                mode=mode,
            )
            if mode == "previous_selection" and not reprocess_preview.get("previous_plan_available"):
                raise HTTPException(
                    status_code=400,
                    detail="No previous ingest plan is stored for this evidence. Use choose_again, full rediscovery or manual selection.",
                )
            selected_candidate_ids = _preview_selected_candidate_ids(reprocess_preview)

    run_id = f"ingest-{uuid4()}"
    benchmark_id = str((benchmark_request or {}).get("benchmark_id") or "")

    if is_raw_with_discovery:
        new_metadata = _apply_reprocess_selection_metadata(
            item,
            existing_metadata,
            selected_candidate_ids,
            mode,
            parser_options={**(payload.parser_options or {}), "ingest_mode": requested_ingest_mode, "evtx_profile": requested_evtx_profile},
        )
        new_metadata = merge_evidence_metadata(new_metadata, ingest_mode_metadata(requested_ingest_mode))
        new_metadata["evtx_profile"] = new_metadata.get("evtx_profile") or requested_evtx_profile
        requested_plan = dict(new_metadata.get("ingest_plan") or {})
        new_metadata = persist_requested_plan(new_metadata, requested_plan)
        new_metadata["ingest_plan_preview"] = reprocess_preview or {}
        new_metadata["reprocess_request"] = {
            "run_id": run_id,
            "mode": mode,
            "ingest_mode": requested_ingest_mode,
            "provided_host": requested_provided_host,
            "evtx_profile": new_metadata.get("evtx_profile"),
            "selected_candidate_ids": selected_candidate_ids,
            "requested_at": _utcnow_iso(),
        }
        if benchmark_request:
            new_metadata["benchmark_request"] = {
                **benchmark_request,
                "benchmark_id": benchmark_id,
                "run_id": run_id,
                "mode": mode,
                "requested_at": _utcnow_iso(),
            }
        skip_detection_cleanup = bool((benchmark_request or {}).get("skip_detections")) or skip_detection_cleanup_for_mode
        new_metadata["reprocess_cleanup_pending"] = {
            "delete_events": True,
            "stale_detection_statuses": [] if skip_detection_cleanup else ["new", "open", "stale"],
            "detections_cleanup_skipped": bool(skip_detection_cleanup),
            "detection_cleanup_reason": "usable_search_skip_detections" if skip_detection_cleanup_for_mode else ("benchmark_skip_detections" if skip_detection_cleanup else None),
            "delete_artifacts": True,
            "reset_extracted_dir": True,
            "reset_staging_dir": bool(mode == "full_rediscovery"),
            "preserve_staging": bool(mode != "full_rediscovery"),
            "requested_at": _utcnow_iso(),
        }
        new_metadata = _preserve_run_history(existing_metadata, new_metadata)
        new_metadata = start_ingest_run(
            new_metadata,
            run_id=run_id,
            run_type="reprocess",
            mode=mode,
            status="queued",
            selected_by_artifact_type=dict((requested_plan or {}).get("selected_by_artifact_type") or {}),
            selected_by_parser=dict((requested_plan or {}).get("selected_by_parser") or {}),
        )
        if existing_metadata.get("artifact_retry_runs"):
            new_metadata["artifact_retry_runs"] = list(existing_metadata.get("artifact_retry_runs") or [])
        if requested_provided_host:
            new_metadata["provided_host"] = requested_provided_host
        should_enqueue = True
    else:
        new_metadata = _initial_metadata({**ingest_mode_metadata(requested_ingest_mode), "reprocessed": True, "provided_host": requested_provided_host})
        requested_plan = build_plan(
            item,
            existing_metadata,
            discovery_mode=mode,
            selected_candidate_ids=[],
            disabled_candidate_ids=[],
            parser_options={**(payload.parser_options or {}), "ingest_mode": requested_ingest_mode, "evtx_profile": requested_evtx_profile},
        )
        new_metadata = persist_requested_plan(new_metadata, requested_plan)
        new_metadata["reprocess_request"] = {
            "run_id": run_id,
            "mode": mode,
            "ingest_mode": requested_ingest_mode,
            "provided_host": requested_provided_host,
            "evtx_profile": requested_plan.get("evtx_profile") or requested_evtx_profile,
            "selected_candidate_ids": [],
            "requested_at": _utcnow_iso(),
        }
        if benchmark_request:
            new_metadata["benchmark_request"] = {
                **benchmark_request,
                "benchmark_id": benchmark_id,
                "run_id": run_id,
                "mode": mode,
                "requested_at": _utcnow_iso(),
            }
        skip_detection_cleanup = bool((benchmark_request or {}).get("skip_detections")) or skip_detection_cleanup_for_mode
        new_metadata["reprocess_cleanup_pending"] = {
            "delete_events": True,
            "stale_detection_statuses": [] if skip_detection_cleanup else ["new", "open", "stale"],
            "detections_cleanup_skipped": bool(skip_detection_cleanup),
            "detection_cleanup_reason": "usable_search_skip_detections" if skip_detection_cleanup_for_mode else ("benchmark_skip_detections" if skip_detection_cleanup else None),
            "delete_artifacts": True,
            "reset_extracted_dir": True,
            "reset_staging_dir": True,
            "preserve_staging": False,
            "requested_at": _utcnow_iso(),
        }
        new_metadata = _preserve_run_history(existing_metadata, new_metadata)
        new_metadata = start_ingest_run(
            new_metadata,
            run_id=run_id,
            run_type="reprocess",
            mode=mode,
            status="queued",
            selected_by_artifact_type=dict((requested_plan or {}).get("selected_by_artifact_type") or {}),
            selected_by_parser=dict((requested_plan or {}).get("selected_by_parser") or {}),
        )
        if existing_metadata.get("artifact_retry_runs"):
            new_metadata["artifact_retry_runs"] = list(existing_metadata.get("artifact_retry_runs") or [])
        if requested_provided_host:
            new_metadata["provided_host"] = requested_provided_host
        should_enqueue = True

    if benchmark_request:
        new_metadata = create_ingest_benchmark(
            new_metadata,
            benchmark_id=benchmark_id,
            evidence_id=item.id,
            case_id=item.case_id,
            run_id=run_id,
            mode=str((benchmark_request or {}).get("mode") or "reprocess_previous_selection"),
            profile=str((benchmark_request or {}).get("profile") or "current"),
            label=(benchmark_request or {}).get("label"),
            notes=(benchmark_request or {}).get("notes"),
            status="queued",
            benchmark_options={
                "stop_after_overlap_observed": bool((benchmark_request or {}).get("stop_after_overlap_observed")),
                "max_duration_seconds": int((benchmark_request or {}).get("max_duration_seconds") or 3600),
                "skip_detections": bool((benchmark_request or {}).get("skip_detections")),
                "skip_rules": bool((benchmark_request or {}).get("skip_rules", True)),
                "autopilot": bool((benchmark_request or {}).get("autopilot")),
                "max_attempts": int((benchmark_request or {}).get("max_attempts") or 2),
                "max_wall_time_seconds": int((benchmark_request or {}).get("max_wall_time_seconds") or 7200),
                "no_progress_timeout_seconds": int((benchmark_request or {}).get("no_progress_timeout_seconds") or 600),
                "heartbeat_timeout_seconds": int((benchmark_request or {}).get("heartbeat_timeout_seconds") or 300),
            },
        )

    new_metadata["reingest_baseline"] = _capture_reingest_baseline(item, existing_metadata, previous_manifest)
    item.ingest_status = IngestStatus.pending
    item.error_log = {}
    item.processed_at = None
    item.metadata_json = merge_evidence_metadata(existing_metadata, new_metadata)
    db.commit()
    db.refresh(item)
    item.metadata_json = merge_evidence_metadata(existing_metadata, item.metadata_json or {})
    db.commit()
    db.refresh(item)
    _write_initial_manifest(item)
    log_activity(
        db,
        activity_type="evidence_reprocessed",
        title="Evidence reprocessed",
        message=f"Requeued evidence {item.original_filename} with mode {payload.mode}",
        case_id=item.case_id,
        evidence_id=item.id,
        metadata={
            "reprocess_mode": mode,
            "selected_candidate_ids": selected_candidate_ids,
            "preserve_analyst_state": preserve_analyst_state,
            "ingest_mode": requested_ingest_mode,
            "provided_host": requested_provided_host,
        },
    )
    if should_enqueue:
        try:
            enqueue_ingest(item.id)
        except OpenSearchIngestBlockedError as exc:
            _mark_evidence_blocked_before_ingest(
                db,
                item,
                exc=exc,
                run_id=run_id,
                benchmark_id=benchmark_id or None,
            )
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            failure_metadata = dict(item.metadata_json or {})
            failure_ts = _utcnow_iso()
            if benchmark_request:
                failure_metadata = upsert_ingest_run(
                    failure_metadata,
                    run_id,
                    {
                        "status": "failed",
                        "phase": "failed",
                        "last_error": f"Failed to enqueue benchmark ingest: {exc}",
                        "finished_at": failure_ts,
                    },
                )
                failure_metadata = upsert_ingest_benchmark(
                    failure_metadata,
                    benchmark_id,
                    {
                        "status": "failed",
                        "run_id": run_id,
                        "error": f"Failed to enqueue benchmark ingest: {exc}",
                        "finished_at": failure_ts,
                    },
                )
                failure_metadata["benchmark_request"] = None
            failure_metadata["current_ingest_run_id"] = None
            failure_metadata["reprocess_request"] = None
            item.ingest_status = IngestStatus.failed
            item.metadata_json = merge_evidence_metadata(item.metadata_json or {}, failure_metadata)
            db.commit()
            raise HTTPException(status_code=500, detail=f"Failed to enqueue ingest run: {exc}") from exc
    return {
        "accepted": True,
        "evidence_id": item.id,
        "run_id": run_id,
        "status": "queued",
        "mode": mode,
    }


@router.get("/api/evidences/{evidence_id}/benchmarks", response_model=list[EvidenceBenchmarkRead])
def get_evidence_benchmarks(evidence_id: str, db: Session = Depends(get_db)) -> list[dict]:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    for benchmark in list_ingest_benchmarks(item.metadata_json or {}):
        if not bool(benchmark.get("autopilot_enabled")):
            continue
        if str(benchmark.get("status") or "") not in {"queued", "running"}:
            continue
        run_benchmark_watchdog(db, evidence_id, str(benchmark.get("benchmark_id") or ""))
        db.refresh(item)
    return list_ingest_benchmarks(item.metadata_json or {})


@router.get("/api/evidences/{evidence_id}/benchmarks/{benchmark_id}", response_model=EvidenceBenchmarkRead)
def get_evidence_benchmark_detail(evidence_id: str, benchmark_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    run_benchmark_watchdog(db, evidence_id, benchmark_id)
    db.refresh(item)
    benchmark = get_ingest_benchmark(item.metadata_json or {}, benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    return benchmark


@router.post("/api/evidences/{evidence_id}/benchmarks/{benchmark_id}/watchdog/run", response_model=EvidenceBenchmarkRead)
def run_evidence_benchmark_watchdog(evidence_id: str, benchmark_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    benchmark = run_benchmark_watchdog(db, evidence_id, benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    db.refresh(item)
    result = get_ingest_benchmark(item.metadata_json or {}, benchmark_id)
    if not result:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    return result


@router.post("/api/evidences/{evidence_id}/benchmarks", response_model=EvidenceBenchmarkQueuedResponse)
def run_evidence_benchmark(
    evidence_id: str,
    payload: BenchmarkEvidenceRequest,
    db: Session = Depends(get_db),
) -> dict:
    benchmark_id = f"bench-{uuid4()}"
    profile = str(payload.profile or "current").strip().lower()
    if profile not in {"current", "safe", "balanced", "performance", "max"}:
        raise HTTPException(status_code=400, detail="profile must be current, safe, balanced, performance or max")
    benchmark_mode = str(payload.mode or "reprocess_previous_selection").strip().lower()
    reprocess_mode = benchmark_mode_to_reprocess_mode(benchmark_mode)
    result = _queue_reprocess_request(
        evidence_id,
        ReprocessEvidenceRequest(
            mode=reprocess_mode,
            selected_candidate_ids=[],
            parser_options={},
            preserve_analyst_state=not (payload.skip_detections or payload.skip_rules),
            explicit_confirm=reprocess_mode == "full_rediscovery",
        ),
        db,
        benchmark_request={
            "benchmark_id": benchmark_id,
            "mode": benchmark_mode,
            "profile": profile,
            "label": payload.label,
            "notes": payload.notes,
            "stop_after_overlap_observed": payload.stop_after_overlap_observed,
            "max_duration_seconds": payload.max_duration_seconds,
            "skip_detections": payload.skip_detections,
            "skip_rules": payload.skip_rules,
            "autopilot": payload.autopilot,
            "max_attempts": payload.max_attempts,
            "max_wall_time_seconds": payload.max_wall_time_seconds,
            "no_progress_timeout_seconds": payload.no_progress_timeout_seconds,
            "heartbeat_timeout_seconds": payload.heartbeat_timeout_seconds,
        },
    )
    return {
        "accepted": True,
        "benchmark_id": benchmark_id,
        "evidence_id": evidence_id,
        "run_id": result["run_id"],
        "status": result["status"],
        "mode": benchmark_mode,
        "profile": profile,
    }


@router.post("/api/evidences/{evidence_id}/benchmarks/compare")
def compare_evidence_benchmarks(
    evidence_id: str,
    payload: BenchmarkCompareRequest,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    benchmark_ids = [str(item_id) for item_id in payload.benchmark_ids if str(item_id or "").strip()]
    if len(benchmark_ids) < 2:
        raise HTTPException(status_code=400, detail="At least two benchmark_ids are required")
    benchmarks = [get_ingest_benchmark(item.metadata_json or {}, benchmark_id) for benchmark_id in benchmark_ids]
    if any(entry is None for entry in benchmarks):
        raise HTTPException(status_code=404, detail="One or more benchmark_ids were not found")
    return compare_ingest_benchmarks(benchmarks[0], benchmarks[1])


@router.get("/api/evidences/{evidence_id}/on-demand-modules")
def get_evidence_on_demand_modules(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    report = get_problematic_artifacts(evidence_id, db)
    problematic_count = int((report.get("summary") or {}).get("problematic_count") or 0)
    indexed_docs = _count_evidence_indexed_docs(item)
    return {
        "evidence_id": item.id,
        "case_id": item.case_id,
        "core_flow": {
            "recommended_ingest_mode": normalize_ingest_mode((item.metadata_json or {}).get("ingest_mode")),
            "steps": ["evidence", "usable_search_ingest", "search_timeline"],
        },
        "modules": build_on_demand_module_registry(case_id=item.case_id, evidence_id=item.id, problematic_count=problematic_count, indexed_docs=indexed_docs),
    }


@router.post("/api/evidences/{evidence_id}/rules/run")
def run_evidence_rules(evidence_id: str, payload: RulesRunRequest, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    from app.api.routes_rules import _queue_case_rules_run

    effective_payload = payload.model_copy(update={"evidence_id": evidence_id, "scope": "evidence", "mode": payload.mode or "on_demand"})
    return _queue_case_rules_run(db, case_id=item.case_id, payload=effective_payload, requested_via="evidence_on_demand")


@router.get("/api/evidences/{evidence_id}/rules/runs", response_model=list[RuleRunRead])
def list_evidence_rule_runs(evidence_id: str, db: Session = Depends(get_db)) -> list[RuleRunRead]:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    from app.api.routes_rules import _serialize_rule_run

    items = db.query(RuleRun).filter(RuleRun.evidence_id == evidence_id).order_by(RuleRun.created_at.desc()).limit(100).all()
    return [_serialize_rule_run(entry) for entry in items]


@router.get("/api/evidences/{evidence_id}/detections", response_model=list[DetectionRead])
def list_evidence_detections(evidence_id: str, db: Session = Depends(get_db)) -> list[DetectionRead]:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    from app.api.routes_rules import _serialize_detection

    detections = db.query(DetectionResult).filter(DetectionResult.evidence_id == evidence_id).order_by(DetectionResult.created_at.desc()).limit(250).all()
    return [DetectionRead.model_validate(_serialize_detection(detection)) for detection in detections]


@router.get("/api/evidences/{evidence_id}/search-summary")
def get_evidence_search_summary(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    summary = _build_evidence_search_summary(item)
    summary["mft_diagnostic"] = build_mft_diagnostic(item, db)
    return summary


@router.get("/api/evidences/{evidence_id}/mft-diagnostic")
def get_evidence_mft_diagnostic(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return build_mft_diagnostic(item, db)


@router.get("/api/evidences/{evidence_id}/indexing-plan")
def get_evidence_indexing_plan(evidence_id: str, profile: str = "recommended", db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    metadata = dict(item.metadata_json or {})
    active, active_job = evidence_has_active_indexing(metadata, item.ingest_status)
    return build_indexing_plan(
        profile=profile,
        metadata=metadata,
        mft_diagnostic=build_mft_diagnostic(item, db),
        indexed_docs=_count_evidence_indexed_docs(item),
        active=active,
        active_job=active_job,
    )


def _enqueue_indexing_plan_steps(item: Evidence, steps: list[dict[str, Any]], *, force: bool) -> list[dict[str, Any]]:
    queued: list[dict[str, Any]] = []
    previous_job = None
    timeout = max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60)
    for step in steps:
        endpoint = str(step.get("endpoint") or "")
        step_id = str(step.get("id") or endpoint)
        job = None
        if endpoint == "mft-summary-index":
            job = ingest_queue.enqueue(
                "app.workers.tasks.index_mft_summary_for_evidence",
                item.id,
                None,
                force,
                depends_on=previous_job,
                job_timeout=timeout,
            )
        elif endpoint == "mft-full-index":
            job = ingest_queue.enqueue(
                "app.workers.tasks.index_mft_full_for_evidence",
                item.id,
                None,
                force,
                depends_on=previous_job,
                job_timeout=timeout,
            )
        elif endpoint == "recmd-user-activity-index":
            job = ingest_queue.enqueue(
                "app.workers.tasks.index_recmd_user_activity_for_evidence",
                item.id,
                force,
                depends_on=previous_job,
                job_timeout=timeout,
            )
        elif endpoint == "defender-evtx-index":
            job = ingest_queue.enqueue(
                "app.workers.tasks.index_defender_evtx_for_evidence",
                item.id,
                force,
                depends_on=previous_job,
                job_timeout=timeout,
            )
        if job is None:
            continue
        previous_job = job
        queued.append({"step_id": step_id, "run_id": job.id, "status": "queued"})
    return queued


def _queue_recommended_raw_discovery_ingest(item: Evidence, metadata: dict, *, profile: str, force: bool, db: Session) -> dict | None:
    if not _is_raw_collection_with_discovery(item, metadata):
        return None
    indexed_docs = _count_evidence_indexed_docs(item)
    current_phase = str(metadata.get("current_phase") or metadata.get("phase") or "").strip().lower()
    if indexed_docs > 0 and not force:
        return None
    selected_candidate_ids = _recommended_supported_candidate_ids(metadata)
    if not selected_candidate_ids:
        return {
            "accepted": False,
            "reason": "no_supported_artifacts",
            "selected_candidate_ids": [],
        }
    requested_ingest_mode = normalize_ingest_mode(metadata.get("ingest_mode") or USABLE_INGEST_MODE)
    requested_provided_host = _normalize_provided_host(metadata.get("provided_host")) or _normalize_provided_host((item.ingest_source or {}).get("provided_host"))
    if not requested_provided_host:
        raise HTTPException(status_code=400, detail="Host name is required for evidence indexing.")
    requested_evtx_profile = str(metadata.get("evtx_profile") or "").strip() or None
    new_metadata = _apply_reprocess_selection_metadata(
        item,
        metadata,
        selected_candidate_ids,
        "recommended_indexing" if current_phase in {"waiting_selection", "selection_pending"} else "recommended",
        parser_options={"ingest_mode": requested_ingest_mode, "evtx_profile": requested_evtx_profile},
    )
    new_metadata = merge_evidence_metadata(new_metadata, ingest_mode_metadata(requested_ingest_mode))
    new_metadata["ingest_mode"] = requested_ingest_mode
    new_metadata["provided_host"] = requested_provided_host
    new_metadata["current_phase"] = "extracting_selected"
    new_metadata["progress_pct"] = 25
    new_metadata["selected_files_extracted"] = 0
    new_metadata["current_item"] = None
    new_metadata["indexing_profile"] = profile
    new_metadata["indexing_plan_recovered_waiting_selection"] = current_phase in {"waiting_selection", "selection_pending"}
    item.metadata_json = merge_evidence_metadata(metadata, new_metadata)
    item.ingest_source = {
        **(item.ingest_source or {}),
        "ingest_mode": requested_ingest_mode,
        "provided_host": requested_provided_host,
        "evtx_profile": new_metadata.get("evtx_profile"),
    }
    item.ingest_status = IngestStatus.pending
    item.error_log = {}
    item.processed_at = None
    flag_modified(item, "metadata_json")
    db.commit()
    db.refresh(item)
    try:
        run_id = enqueue_ingest(item.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, item, exc=exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "accepted": True,
        "run_id": str(run_id or ""),
        "status": "queued",
        "selected_candidate_ids": list(new_metadata.get("velociraptor_selected_candidate_ids") or []),
        "selected_categories": list(new_metadata.get("velociraptor_selected_categories") or []),
    }


@router.post("/api/evidences/{evidence_id}/indexing-plan/run")
def run_evidence_indexing_plan(evidence_id: str, payload: EvidenceIndexingPlanRunRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    metadata = dict(item.metadata_json or {})
    active, active_job = evidence_has_active_indexing(metadata, item.ingest_status)
    if active:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "active_indexing_job_exists",
                "active_job": active_job,
                "message": "An indexing job is already running for this evidence. Wait for it to finish before starting another indexing profile.",
            },
        )
    profile = normalize_indexing_profile(payload.profile if payload else "recommended")
    plan = build_indexing_plan(
        profile=profile,
        metadata=metadata,
        mft_diagnostic=build_mft_diagnostic(item, db),
        indexed_docs=_count_evidence_indexed_docs(item),
        active=False,
        active_job=None,
    )
    if profile == "advanced_custom":
        raise HTTPException(status_code=400, detail="Advanced custom exposes individual actions and is not executed as a bundled plan.")
    core_ingest = _queue_recommended_raw_discovery_ingest(item, metadata, profile=profile, force=bool(payload.force if payload else False), db=db)
    if core_ingest and core_ingest.get("accepted"):
        run = create_indexing_plan_run(plan, [])
        run["status"] = "queued"
        run["queued_jobs"] = [{"step_id": "core_artifacts", "run_id": core_ingest.get("run_id") or "", "status": "queued"}]
        metadata = dict(item.metadata_json or {})
        metadata["indexing_profile"] = profile
        metadata["indexing_plan_run"] = run
        metadata["indexing_plan_steps"] = run["steps"]
        item.metadata_json = metadata
        flag_modified(item, "metadata_json")
        db.commit()
        return {
            "accepted": True,
            "evidence_id": item.id,
            "profile": profile,
            "run_id": run["run_id"],
            "status": "queued",
            "queued_jobs": run["queued_jobs"],
            "plan": run,
            "selected_candidate_ids": core_ingest.get("selected_candidate_ids") or [],
            "selected_categories": core_ingest.get("selected_categories") or [],
        }
    if core_ingest and core_ingest.get("reason") == "no_supported_artifacts":
        metadata = dict(item.metadata_json or {})
        metadata["current_phase"] = "no_supported_artifacts"
        metadata["status_reason"] = "No supported artifacts were found for recommended indexing."
        metadata["current_ingest_run_id"] = None
        item.metadata_json = metadata
        item.ingest_status = IngestStatus.failed
        item.processed_at = datetime.now(UTC).replace(tzinfo=None)
        flag_modified(item, "metadata_json")
        db.commit()
        raise HTTPException(status_code=400, detail="No supported artifacts found for recommended indexing.")
    queued_jobs = _enqueue_indexing_plan_steps(item, list(plan.get("runnable_steps") or []), force=bool(payload.force if payload else False))
    run = create_indexing_plan_run(plan, queued_jobs)
    metadata["indexing_profile"] = profile
    metadata["indexing_plan_run"] = run
    metadata["indexing_plan_steps"] = run["steps"]
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {
        "accepted": True,
        "evidence_id": item.id,
        "profile": profile,
        "run_id": run["run_id"],
        "status": run["status"],
        "queued_jobs": queued_jobs,
        "plan": run,
    }


@router.post("/api/evidences/{evidence_id}/indexing/cancel")
def cancel_evidence_indexing(evidence_id: str, payload: EvidenceIndexingCancelRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    metadata = dict(item.metadata_json or {})
    now = datetime.now(UTC).isoformat()
    previous_status = str(getattr(item.ingest_status, "value", item.ingest_status) or "")
    previous_phase = str(metadata.get("current_phase") or metadata.get("phase") or "")
    run_id = str(metadata.get("current_ingest_run_id") or metadata.get("latest_ingest_run_id") or "").strip()
    reason = str((payload.reason if payload else None) or "Cancelled by analyst to recover indexing state.").strip()
    if run_id:
        metadata = upsert_ingest_run(
            metadata,
            run_id,
            {
                "status": "cancelled",
                "phase": "cancelled",
                "finished_at": now,
                "last_error": reason,
            },
        )
    metadata["current_ingest_run_id"] = None
    metadata["reprocess_request"] = None
    metadata["benchmark_request"] = None
    metadata["indexing_plan_run"] = {
        **dict(metadata.get("indexing_plan_run") or {}),
        "status": "cancelled",
        "updated_at": now,
        "cancelled_at": now,
        "cancel_reason": reason,
    }
    metadata["current_phase"] = "cancelled"
    metadata["progress_pct"] = 0 if int(metadata.get("events_indexed") or 0) <= 0 else metadata.get("progress_pct", 0)
    metadata["status_reason"] = reason
    metadata["stale_recovery"] = {
        "previous_status": previous_status,
        "previous_phase": previous_phase,
        "reason": reason,
        "recovered_at": now,
    }
    if int(metadata.get("events_indexed") or metadata.get("searchable_documents_count") or 0) > 0:
        item.ingest_status = IngestStatus.completed_with_errors
    else:
        item.ingest_status = IngestStatus.failed
    item.metadata_json = metadata
    item.error_log = dict(item.error_log or {})
    item.processed_at = datetime.now(UTC).replace(tzinfo=None)
    flag_modified(item, "metadata_json")
    db.commit()
    db.refresh(item)
    return {
        "accepted": True,
        "evidence_id": item.id,
        "status": "cancelled",
        "previous_status": previous_status,
        "previous_phase": previous_phase,
        "lock_released": True,
        "retry_allowed": True,
    }


@router.post("/api/evidences/{evidence_id}/mft-summary-index")
def index_evidence_mft_summary(evidence_id: str, payload: MftSummaryIndexRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    diagnostic = build_mft_diagnostic(item, db)
    if not diagnostic.get("mft_present_in_evidence"):
        raise HTTPException(status_code=400, detail="No MFT artifact detected in this evidence.")
    if not diagnostic.get("mft_backend_available"):
        raise HTTPException(status_code=503, detail="MFTECmd backend is not available.")
    run_id = enqueue_mft_summary_index(
        item.id,
        max_records=(payload.max_records if payload else None),
        force=bool(payload.force if payload else False),
    )
    metadata = dict(item.metadata_json or {})
    runs = list(metadata.get("mft_summary_runs") or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "backend": "mftecmd_csv",
            "mode": "summary",
            "max_records": payload.max_records if payload else None,
            "force": bool(payload.force if payload else False),
            "queued_at": _utcnow_iso(),
        }
    )
    metadata["mft_summary_runs"] = runs[-10:]
    metadata["mft_summary"] = runs[-1]
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "backend": "mftecmd_csv", "mode": "summary"}


@router.post("/api/evidences/{evidence_id}/mft-full-index")
def index_evidence_mft_full(evidence_id: str, payload: MftFullIndexRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    diagnostic = build_mft_diagnostic(item, db)
    if not diagnostic.get("mft_present_in_evidence"):
        raise HTTPException(status_code=400, detail="No MFT artifact detected in this evidence.")
    if not diagnostic.get("mft_backend_available"):
        raise HTTPException(status_code=503, detail="MFTECmd backend is not available.")
    run_id = enqueue_mft_full_index(
        item.id,
        max_records=(payload.max_records if payload else None),
        force=bool(payload.force if payload else False),
    )
    metadata = dict(item.metadata_json or {})
    runs = list(metadata.get("mft_full_runs") or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "backend": "mftecmd_csv",
            "mode": "full",
            "max_records": payload.max_records if payload else None,
            "force": bool(payload.force if payload else False),
            "queued_at": _utcnow_iso(),
        }
    )
    metadata["mft_full_runs"] = runs[-10:]
    metadata["mft_full"] = runs[-1]
    metadata["mft_full_status"] = "queued"
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "backend": "mftecmd_csv", "mode": "full"}


@router.post("/api/evidences/{evidence_id}/recmd-user-activity-index")
def index_evidence_recmd_user_activity(evidence_id: str, payload: RecmdUserActivityIndexRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    run_id = enqueue_recmd_user_activity_index(item.id, force=bool(payload.force if payload else False))
    metadata = dict(item.metadata_json or {})
    runs = list(metadata.get("recmd_user_activity_runs") or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "backend": "recmd_csv",
            "mode": "user_activity",
            "force": bool(payload.force if payload else False),
            "queued_at": _utcnow_iso(),
        }
    )
    metadata["recmd_user_activity_runs"] = runs[-10:]
    metadata["recmd_user_activity"] = runs[-1]
    metadata["registry_user_activity_status"] = "queued"
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "backend": "recmd_csv", "mode": "user_activity"}


@router.post("/api/evidences/{evidence_id}/defender-evtx-index")
def index_evidence_defender_evtx(evidence_id: str, payload: DefenderEvtxIndexRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    run_id = enqueue_defender_evtx_index(item.id, force=bool(payload.force if payload else False))
    metadata = dict(item.metadata_json or {})
    runs = list(metadata.get("defender_evtx_runs") or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "parser": "defender_evtx",
            "mode": "defender",
            "force": bool(payload.force if payload else False),
            "queued_at": _utcnow_iso(),
        }
    )
    metadata["defender_evtx_runs"] = runs[-10:]
    metadata["defender_evtx"] = runs[-1]
    metadata["defender_evtx_status"] = "queued"
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "parser": "defender_evtx", "mode": "defender"}


@router.post("/api/evidences/{evidence_id}/srum-index")
def index_evidence_srum(evidence_id: str, payload: SrumIndexRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    run_id = enqueue_srum_index(item.id, force=bool(payload.force if payload else False))
    metadata = dict(item.metadata_json or {})
    runs = list(metadata.get("srum_runs") or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "backend": "srumecmd_csv",
            "mode": "srum",
            "force": bool(payload.force if payload else False),
            "queued_at": _utcnow_iso(),
        }
    )
    metadata["srum_runs"] = runs[-10:]
    metadata["srum"] = runs[-1]
    metadata["srum_status"] = "queued"
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "backend": "srumecmd_csv", "mode": "srum"}


@router.post("/api/evidences/{evidence_id}/core-ez-rebuild/{artifact_type}")
def rebuild_evidence_core_ez_artifact(evidence_id: str, artifact_type: str, payload: CoreEzRebuildRequest | None = None, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    normalized_type = str(artifact_type or "").strip().lower()
    if normalized_type == "appcompat":
        normalized_type = "shimcache"
    supported = {
        "lnk": ("LECmd", "lecmd_csv"),
        "jumplist": ("JLECmd", "jlecmd_csv"),
        "amcache": ("AmcacheParser", "amcacheparser_csv"),
        "shimcache": ("AppCompatCacheParser", "appcompatcacheparser_csv"),
    }
    if normalized_type == "prefetch":
        raise HTTPException(status_code=400, detail="PECmd is available, but raw Prefetch parsing on Linux requires Windows decompression support. Internal prefetch_raw remains active.")
    if normalized_type not in supported:
        raise HTTPException(status_code=400, detail="Unsupported advanced EZ rebuild artifact type.")
    tool, backend = supported[normalized_type]
    run_id = enqueue_core_ez_rebuild(item.id, normalized_type, force=bool(payload.force if payload else True))
    metadata = dict(item.metadata_json or {})
    all_runs = dict(metadata.get("core_ez_rebuilds") or {})
    runs = list(all_runs.get(normalized_type) or [])
    runs.append(
        {
            "run_id": run_id,
            "status": "queued",
            "artifact_type": normalized_type,
            "tool": tool,
            "backend": backend,
            "backend_variant": "advanced",
            "force": bool(payload.force if payload else True),
            "queued_at": _utcnow_iso(),
        }
    )
    all_runs[normalized_type] = runs[-10:]
    metadata["core_ez_rebuilds"] = all_runs
    metadata[f"{normalized_type}_ez_rebuild"] = runs[-1]
    item.metadata_json = metadata
    flag_modified(item, "metadata_json")
    db.commit()
    return {"accepted": True, "run_id": run_id, "evidence_id": item.id, "status": "queued", "artifact_type": normalized_type, "tool": tool, "backend": backend, "backend_variant": "advanced"}


@router.post("/api/evidences/{evidence_id}/recompute-status")
def recompute_evidence_status(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _recompute_evidence_status(item, db)


@router.get("/api/parser-registry")
def get_parser_registry() -> dict:
    return build_parser_registry_report()


@router.get("/api/evidences/{evidence_id}/searchable-contract")
def get_evidence_searchable_contract(evidence_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    manifest = _load_evidence_manifest(item)
    artifacts = [dict(entry) for entry in (manifest.get("artifacts") or []) if isinstance(entry, dict)]
    sampled_events = _fetch_evidence_sample_events(item)
    return {
        "evidence_id": item.id,
        "case_id": item.case_id,
        "latest_ingest_run_id": str((item.metadata_json or {}).get("latest_ingest_run_id") or ""),
        "parser_registry": build_parser_registry_report(
            artifact_types=sorted({str(entry.get("artifact_type") or "").strip().lower() for entry in artifacts if entry.get("artifact_type")}) or None
        ),
        "searchable_document_contract": build_searchable_contract_report(
            artifacts=artifacts,
            sampled_events=sampled_events,
        ),
        "parser_coverage_matrix": build_parser_coverage_matrix(
            artifacts=artifacts,
            sampled_events=sampled_events,
        ),
        "field_coverage": build_indexed_field_coverage_by_artifact_type(sampled_events),
    }


@router.delete("/api/evidences/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_evidence(evidence_id: str, db: Session = Depends(get_db)) -> None:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    delete_events_by_evidence(item.id, item.case_id)
    safe_remove(evidence_manifest_path(item.case_id, item.id).parent)
    log_activity(
        db,
        activity_type="evidence_deleted",
        title="Evidence deleted",
        message=f"Deleted evidence {item.original_filename}",
        case_id=item.case_id,
        evidence_id=item.id,
    )
    db.delete(item)
    db.commit()


@router.get("/api/cases/{case_id}/artifacts", response_model=list[ArtifactRead])
def list_artifacts(case_id: str, db: Session = Depends(get_db)) -> list[Artifact]:
    return db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.created_at.desc()).all()
