from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any

from app.core.config import get_settings
from app.core.storage import build_evidence_root, evidence_extract_dir, evidence_staging_dir


HIGH_IMPORTANCE_KEYWORDS = (
    "cve",
    "exploit",
    "zerologon",
    "petitpotam",
    "bluekeep",
    "uac",
    "credential",
    "powershell",
    "sysmon",
    "defender",
    "ransomware",
    "lateral",
    "privilege",
)

HIGH_IMPORTANCE_EVENT_HINTS = (
    "security",
    "sysmon",
    "powershell",
    "defender",
    "taskscheduler",
    "terminalservices",
)

HIGH_VALUE_LONG_TAIL_PATTERNS = (
    "security.evtx",
    "system.evtx",
    "microsoft-windows-sysmon%4operational.evtx",
    "microsoft-windows-powershell%4operational.evtx",
    "windows powershell.evtx",
    "setup.evtx",
)

READ_INDEXED_PATTERN = re.compile(r"\((?P<read>\d+)\s+read\s*/\s*(?P<indexed>\d+)\s+indexed\)", re.IGNORECASE)
EVTX_HEADER_MAGIC = b"ElfFile\x00"
DEFERRED_PROBLEMATIC_STATUSES = {"deferred_long_tail", "partial_indexed_deferred"}


def _lookup_artifact_id(
    artifact_id_by_key: dict[tuple[str, str], str],
    *,
    source_path: str,
    parser_name: str,
    artifact_name: str,
) -> str | None:
    candidates = (
        (source_path, parser_name),
        (source_path, ""),
        (artifact_name, parser_name),
        (artifact_name, ""),
    )
    for key in candidates:
        artifact_id = artifact_id_by_key.get(key)
        if artifact_id:
            return artifact_id
    return None


def classify_problematic_artifact_status(*, records_read: int, records_indexed: int, error_type: str | None = None) -> tuple[str, bool, bool]:
    error_type = str(error_type or "").strip().lower()
    if records_read == 0 and records_indexed == 0 and error_type in {"no_records", "empty", "skipped_empty"}:
        return "skipped_empty", False, False
    if records_read > 0 and records_indexed == records_read:
        return "parsed_with_warning", True, False
    if records_read > records_indexed > 0:
        return "partially_parsed", True, True
    if records_read == 0 and error_type == "timeout":
        return "skipped_timeout", False, True
    if records_read > 0 and records_indexed == 0 and error_type in {"timeout", "stalled"}:
        return "stalled", False, True
    if records_indexed == 0:
        return "failed", False, True
    return "failed", False, True


def classify_problematic_artifact_health(*, status: str, records_read: int, records_indexed: int, data_loss_expected: bool) -> tuple[str, str]:
    if status in {"skipped_empty", "completed_no_records", "unsupported_no_records"} and records_read == 0 and records_indexed == 0:
        return "No records produced", "No expected data loss"
    if status == "parsed_with_warning" and records_read > 0 and records_indexed == records_read and not data_loss_expected:
        return "Indexed records available", "No expected data loss"
    if status in {"skipped_timeout", "failed", "stalled", "failed_timeout", "stalled_timeout", "failed_aborted", "deferred_long_tail", "partial_indexed_deferred"} and records_read == 0 and records_indexed == 0:
        return "Not parsed", "Data loss expected"
    if data_loss_expected:
        return "Partial indexing", "Expected data loss"
    return "Warning requires review", "Data loss not confirmed"


def _artifact_key(item: dict[str, Any]) -> str:
    artifact_id = str(item.get("artifact_id") or "").strip()
    if artifact_id:
        return artifact_id
    return f"{str(item.get('source_path') or '').strip()}|{str(item.get('parser') or '').strip()}"


def _health_check_by_key(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = list(metadata.get("artifact_health_checks") or [])
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("artifact_key") or "").strip()
        if key:
            result[key] = dict(row)
    return result


def _deep_retry_history(item: dict[str, Any]) -> list[dict[str, Any]]:
    history = list(item.get("retry_history") or [])
    return [entry for entry in history if str(entry.get("mode") or "").strip().lower() == "deep_safe_mode"]


def _accepted_warning_by_key(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = metadata.get("artifact_warning_acceptances") or {}
    if not isinstance(rows, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for key, value in rows.items():
        text_key = str(key or "").strip()
        if text_key and isinstance(value, dict):
            result[text_key] = dict(value)
    return result


def _latest_retry(item: dict[str, Any]) -> dict[str, Any] | None:
    retry_history = list(item.get("retry_history") or [])
    if not retry_history:
        return None
    return dict(retry_history[-1])


def _effective_problematic_state(item: dict[str, Any], *, health_check: dict[str, Any] | None, accepted_warning: dict[str, Any] | None) -> dict[str, Any]:
    original_status = str(item.get("status") or "").strip().lower()
    records_read = int(item.get("records_read") or 0)
    records_indexed = int(item.get("records_indexed") or 0)
    latest_retry = _latest_retry(item)
    latest_health_check = dict(health_check or {})
    latest_retry_status = str((latest_retry or {}).get("status") or "").strip().lower()
    latest_retry_outcome = str((latest_retry or {}).get("outcome") or "").strip().lower()
    retry_records_read = int((latest_retry or {}).get("records_read") or 0)
    retry_records_indexed = int((latest_retry or {}).get("records_indexed") or 0)
    retry_recovered = latest_retry_outcome == "recovered_more_data" and retry_records_indexed > 0
    effective_records_read = retry_records_read if retry_records_read > 0 else records_read
    effective_records_indexed = retry_records_indexed if retry_records_indexed > 0 else records_indexed
    health_diagnosis = str(latest_health_check.get("diagnosis") or "").strip().lower()

    effective_status = original_status or "failed"
    effective_resolution = "historical_issue"
    current_data_loss_expected = bool(item.get("data_loss_expected"))
    recovered = False
    recovered_records = 0
    suggested_primary_action = "check_health"

    if original_status in {"skipped_empty", "completed_no_records", "unsupported_no_records"} and effective_records_read == 0 and effective_records_indexed == 0:
        effective_status = original_status
        effective_resolution = "no_records_produced"
        current_data_loss_expected = False
        suggested_primary_action = "no_action_needed"
    elif retry_recovered:
        recovered = True
        recovered_records = retry_records_indexed
        current_data_loss_expected = not (effective_records_read > 0 and effective_records_read == effective_records_indexed)
        effective_status = "recovered_with_warning" if latest_retry_status == "parsed_with_warning" else "recovered"
        effective_resolution = "recovered_by_retry"
        suggested_primary_action = "search_indexed_events"
    elif effective_records_read > 0 and effective_records_indexed == effective_records_read and not current_data_loss_expected:
        effective_status = "parsed_with_warning"
        effective_resolution = "indexed_records_available"
        suggested_primary_action = "search_indexed_events"
        if health_diagnosis == "file_missing":
            effective_status = "source_missing_but_indexed"
            effective_resolution = "source_missing_but_indexed"
        elif health_diagnosis == "valid_evtx":
            effective_status = "health_check_only_valid"
            effective_resolution = "health_check_valid"
    elif health_diagnosis == "valid_evtx":
        effective_status = "health_check_only_valid"
        effective_resolution = "health_check_valid"
        current_data_loss_expected = records_indexed == 0
        suggested_primary_action = "retry_deep_safe_mode"
    elif health_diagnosis in {"corrupt_header", "truncated_or_unreadable", "parser_unsupported_record", "unknown_error"} and effective_records_indexed == 0:
        effective_status = "health_check_failed"
        effective_resolution = health_diagnosis or "health_check_failed"
        current_data_loss_expected = True
        suggested_primary_action = "retry_deep_safe_mode"
    elif effective_records_indexed == 0:
        effective_status = "unresolved_timeout" if original_status in {"skipped_timeout", "failed_timeout", "stalled_timeout"} else "unresolved_failed"
        effective_resolution = "still_unresolved"
        current_data_loss_expected = True
        suggested_primary_action = "retry_deep_safe_mode"

    if accepted_warning and not current_data_loss_expected:
        effective_status = "accepted_warning"
        effective_resolution = "warning_accepted"
        suggested_primary_action = "search_indexed_events"

    return {
        "original_status": original_status or "failed",
        "effective_status": effective_status,
        "effective_resolution": effective_resolution,
        "historical_data_loss_expected": bool(item.get("data_loss_expected")),
        "current_data_loss_expected": current_data_loss_expected,
        "recovered": recovered,
        "recovered_records": recovered_records,
        "latest_retry": latest_retry,
        "latest_health_check": latest_health_check or None,
        "accepted_warning": bool(accepted_warning),
        "accepted_at": str((accepted_warning or {}).get("accepted_at") or "") or None,
        "accepted_reason": str((accepted_warning or {}).get("accepted_reason") or "") or None,
        "suggested_primary_action": suggested_primary_action,
        "effective_records_read": effective_records_read,
        "effective_records_indexed": effective_records_indexed,
    }


def resolve_problematic_artifact_path(
    evidence: Any,
    *,
    source_path: str,
    artifact_name: str,
    manifest: dict[str, Any] | None = None,
) -> Path | None:
    root = build_evidence_root(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", "")))
    original_path = Path(str(getattr(evidence, "stored_path", "") or ""))
    source_path = str(source_path or "").strip()
    artifact_name = str(artifact_name or "").strip()
    candidates: list[Path] = []
    if original_path and original_path.exists() and original_path.is_file() and original_path.suffix.lower() == ".evtx":
        candidates.append(original_path)
    if source_path:
        candidates.extend(
            [
                evidence_staging_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / source_path,
                evidence_extract_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / source_path,
                root / "original_folder" / source_path,
                root / "original" / Path(source_path).name,
            ]
        )
    if artifact_name:
        candidates.extend(
            [
                evidence_staging_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / artifact_name,
                evidence_extract_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / artifact_name,
                root / "original_folder" / artifact_name,
                root / "original" / artifact_name,
            ]
        )
    if manifest:
        for entry in manifest.get("files") or []:
            entry_path = str(entry.get("path") or "").strip()
            if entry_path and entry_path in {source_path, artifact_name, Path(source_path).name if source_path else ""}:
                candidates.extend(
                    [
                        evidence_extract_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / entry_path,
                        evidence_staging_dir(str(getattr(evidence, "case_id", "")), str(getattr(evidence, "id", ""))) / entry_path,
                        root / "original_folder" / entry_path,
                    ]
                )
    seen: set[str] = set()
    for candidate in candidates:
        text = str(candidate)
        if not text or text in seen:
            continue
        seen.add(text)
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def run_evtx_health_check(path: Path, *, record_timeout_seconds: int = 60, max_records: int = 200) -> dict[str, Any]:
    from app.ingest.raw_parsers.evtx_parser import iter_evtx_xml_record_results

    result: dict[str, Any] = {
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else None,
        "evtx_header_valid": False,
        "records_seen": 0,
        "first_record_ok": False,
        "last_record_ok": False,
        "parse_errors": 0,
        "timed_out": False,
        "corrupt_header": False,
        "truncated_file": False,
        "diagnosis": "unknown_error",
        "likely_corrupt": False,
        "retry_recommended": False,
        "suggested_retry_mode": None,
    }
    if not path.exists():
        result["diagnosis"] = "file_missing"
        return result
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
        result["evtx_header_valid"] = header == EVTX_HEADER_MAGIC
        if not result["evtx_header_valid"]:
            result["corrupt_header"] = True
            result["likely_corrupt"] = True
            result["diagnosis"] = "corrupt_header"
            return result
        if int(result["size_bytes"] or 0) < 4096:
            result["truncated_file"] = True
            result["likely_corrupt"] = True
            result["diagnosis"] = "truncated_or_unreadable"
            return result
        last_ok = False
        first_error: str | None = None
        for record_index, _xml_text, record_error in iter_evtx_xml_record_results(path, record_timeout_seconds=record_timeout_seconds):
            if record_index > max_records:
                break
            if record_error is not None:
                result["parse_errors"] = int(result["parse_errors"] or 0) + 1
                first_error = first_error or str(record_error)
                if isinstance(record_error, TimeoutError):
                    result["timed_out"] = True
                    break
                continue
            result["records_seen"] = int(result["records_seen"] or 0) + 1
            if result["records_seen"] == 1:
                result["first_record_ok"] = True
            last_ok = True
        result["last_record_ok"] = last_ok
        if result["timed_out"] and int(result["records_seen"] or 0) == 0:
            result["diagnosis"] = "valid_header_but_record_iteration_timeout"
            result["retry_recommended"] = True
            result["suggested_retry_mode"] = "deep_safe_mode"
        elif int(result["records_seen"] or 0) > 0 and int(result["parse_errors"] or 0) == 0:
            result["diagnosis"] = "valid_evtx"
            result["retry_recommended"] = False
        elif int(result["records_seen"] or 0) > 0 and int(result["parse_errors"] or 0) > 0:
            result["diagnosis"] = "valid_with_warnings"
            result["retry_recommended"] = True
            result["suggested_retry_mode"] = "deep_safe_mode"
        elif first_error:
            result["diagnosis"] = "parser_unsupported_record"
            result["retry_recommended"] = True
            result["suggested_retry_mode"] = "deep_safe_mode"
        else:
            result["diagnosis"] = "unknown_error"
            result["retry_recommended"] = True
            result["suggested_retry_mode"] = "deep_safe_mode"
    except TimeoutError:
        result["timed_out"] = True
        result["diagnosis"] = "valid_header_but_record_iteration_timeout" if result["evtx_header_valid"] else "unknown_error"
        result["retry_recommended"] = True
        result["suggested_retry_mode"] = "deep_safe_mode"
    except Exception:
        result["diagnosis"] = "truncated_or_unreadable" if result["evtx_header_valid"] else "unknown_error"
        result["likely_corrupt"] = True
        result["retry_recommended"] = False
    return result


def score_problematic_artifact_importance(item: dict[str, Any]) -> tuple[str, list[str]]:
    name = str(item.get("name") or "").lower()
    source_path = str(item.get("source_path") or "").lower()
    parser_name = str(item.get("parser") or "").lower()
    records_read = int(item.get("records_read") or 0)
    records_indexed = int(item.get("records_indexed") or 0)
    data_loss_expected = bool(item.get("data_loss_expected"))
    reasons: list[str] = []

    if parser_name == "evtx_raw":
        reasons.append("evtx")
    if any(keyword in name or keyword in source_path for keyword in HIGH_IMPORTANCE_KEYWORDS):
        reasons.append("attack_sample_name")
    if any(hint in name or hint in source_path for hint in HIGH_IMPORTANCE_EVENT_HINTS):
        reasons.append("high_value_log")
    if data_loss_expected:
        reasons.append("partial_data_loss")
    if records_indexed > 0:
        reasons.append("partial_data_indexed")
    if records_read >= 1000:
        reasons.append("large_record_count")

    if {"attack_sample_name", "high_value_log", "partial_data_loss"} & set(reasons):
        return "high", sorted(set(reasons))
    if {"evtx", "large_record_count", "partial_data_loss"} & set(reasons):
        return "medium", sorted(set(reasons))
    if records_indexed == 0:
        return "low", sorted(set(reasons))
    return "medium", sorted(set(reasons))


def classify_long_tail_artifact_importance(item: dict[str, Any]) -> tuple[str, list[str]]:
    source_path = str(item.get("source_path") or "").lower()
    name = str(item.get("name") or item.get("artifact") or "").lower()
    parser_name = str(item.get("parser") or "").lower()
    reasons: list[str] = []
    if parser_name == "evtx_raw":
        reasons.append("evtx")
    if any(pattern in source_path or pattern in name for pattern in HIGH_VALUE_LONG_TAIL_PATTERNS):
        reasons.append("high_value_log")
    if int(item.get("records_indexed") or 0) > 0:
        reasons.append("partial_indexed")
    if int(item.get("records_read") or 0) >= 1000:
        reasons.append("large_record_count")
    if "high_value_log" in reasons:
        return "high", sorted(set(reasons))
    if "evtx" in reasons:
        return "medium", sorted(set(reasons))
    return "low", sorted(set(reasons))


def classify_long_tail_artifact_state(
    item: dict[str, Any],
    *,
    warning_seconds: int,
    stall_seconds: int,
    max_runtime_seconds: int,
    defer_after_seconds: int,
) -> dict[str, Any]:
    records_read = int(item.get("records_read") or 0)
    records_indexed = int(item.get("records_indexed") or 0)
    elapsed_seconds = float(item.get("elapsed_seconds") or 0.0)
    no_progress_seconds = float(item.get("last_progress_seconds_ago") or 0.0)
    raw_status = str(item.get("status") or "").strip().lower()
    importance, reasons = classify_long_tail_artifact_importance(item)

    long_tail_state = "active_progressing"
    if raw_status in {"deferred_long_tail", "partial_indexed_deferred"}:
        long_tail_state = raw_status
    elif raw_status in {"failed_timeout", "stalled_timeout"}:
        long_tail_state = "failed_timeout"
    elif raw_status == "completed":
        long_tail_state = "completed"
    elif no_progress_seconds >= stall_seconds:
        long_tail_state = "stalled_no_progress"
    elif elapsed_seconds >= warning_seconds:
        long_tail_state = "slow_progressing"

    partial_coverage_warning = records_indexed > 0 and long_tail_state not in {
        "completed",
        "deferred_long_tail",
        "partial_indexed_deferred",
    }
    defer_recommended = long_tail_state in {"stalled_no_progress", "slow_progressing"} and elapsed_seconds >= defer_after_seconds
    hard_timeout_recommended = long_tail_state == "stalled_no_progress" and elapsed_seconds >= max_runtime_seconds

    return {
        "long_tail_state": long_tail_state,
        "importance": importance,
        "importance_reasons": reasons,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "no_progress_seconds": round(no_progress_seconds, 2),
        "partial_coverage_warning": partial_coverage_warning,
        "data_loss_expected": records_indexed < records_read or long_tail_state in {"deferred_long_tail", "partial_indexed_deferred", "failed_timeout"},
        "retryable": bool(item.get("source_path")),
        "suggested_retry_mode": "deep_safe_mode" if str(item.get("parser") or "").lower() == "evtx_raw" else "safe_mode",
        "defer_recommended": defer_recommended,
        "hard_timeout_recommended": hard_timeout_recommended,
    }


def build_problematic_artifacts_report(
    evidence: Any,
    manifest: dict[str, Any],
    *,
    artifact_id_by_key: dict[tuple[str, str], str] | None = None,
    artifact_rows: list[Any] | None = None,
) -> dict[str, Any]:
    artifact_id_by_key = artifact_id_by_key or {}
    metadata = dict(getattr(evidence, "metadata_json", {}) or {})
    health_checks = _health_check_by_key(metadata)
    accepted_warnings = _accepted_warning_by_key(metadata)
    retry_history = list(metadata.get("artifact_retry_runs") or [])
    retry_history_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for run in retry_history:
        for item in run.get("items") or []:
            key = (str(item.get("source_path") or ""), str(item.get("parser") or ""))
            retry_history_by_key.setdefault(key, []).append(item)

    items: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for artifact in manifest.get("artifacts") or []:
        ingest_audit = dict(artifact.get("ingest_audit") or {})
        error_text = None
        artifact_name = str(artifact.get("name") or "")
        for error in manifest.get("errors") or []:
            if str(error.get("artifact") or "") == artifact_name:
                error_text = str(error.get("error") or "")
                break
        original_manifest_status = str(artifact.get("status") or "").strip().lower()
        if not error_text and not any(flag in original_manifest_status for flag in ("failed", "partial")) and original_manifest_status not in {"skipped_empty", "completed_no_records", "unsupported_no_records"}:
            continue
        records_read = int(ingest_audit.get("records_read") or artifact.get("record_count") or 0)
        records_indexed = int(ingest_audit.get("records_indexed") or ingest_audit.get("events_indexed") or artifact.get("record_count") or 0)
        if records_read == 0 and records_indexed == 0 and error_text:
            match = READ_INDEXED_PATTERN.search(error_text)
            if match:
                records_read = int(match.group("read") or 0)
                records_indexed = int(match.group("indexed") or 0)
        error_type = (
            "no_records"
            if original_manifest_status in {"skipped_empty", "completed_no_records", "unsupported_no_records"}
            else "timeout"
            if "timed out" in str(error_text or "").lower() or "stalled" in str(error_text or "").lower()
            else None
        )
        if original_manifest_status in DEFERRED_PROBLEMATIC_STATUSES:
            fine_status = original_manifest_status
            partial_data_indexed = records_indexed > 0
            data_loss_expected = True
        else:
            fine_status, partial_data_indexed, data_loss_expected = classify_problematic_artifact_status(
                records_read=records_read,
                records_indexed=records_indexed,
                error_type=error_type,
            )
        item: dict[str, Any] = {
            "artifact_id": _lookup_artifact_id(
                artifact_id_by_key,
                source_path=str(artifact.get("source_path") or ""),
                parser_name=str(artifact.get("parser") or ""),
                artifact_name=artifact_name,
            ),
            "name": artifact_name,
            "source_path": artifact.get("source_path"),
            "artifact_type": artifact.get("artifact_type"),
            "parser": artifact.get("parser"),
            "status": fine_status,
            "records_read": records_read,
            "records_indexed": records_indexed,
            "bulk_batches": int(ingest_audit.get("bulk_batches") or 0),
            "error_type": error_type or ("warning" if partial_data_indexed else "failure"),
            "error_message": error_text or ("No records produced / empty or unsupported EVTX channel." if error_type == "no_records" else None),
            "timeout_seconds": int(ingest_audit.get("timeout_seconds") or 0),
            "partial_data_indexed": partial_data_indexed,
            "data_loss_expected": data_loss_expected,
            "retryable": str(artifact.get("parser") or "").lower() == "evtx_raw" and fine_status not in {"skipped_empty", "completed_no_records", "unsupported_no_records"},
            "suggested_retry_mode": "deep_safe_mode" if data_loss_expected else "no_detections",
            "retry_history": retry_history_by_key.get((str(artifact.get("source_path") or ""), str(artifact.get("parser") or "")), []),
        }
        summary_label, loss_label = classify_problematic_artifact_health(
            status=fine_status,
            records_read=records_read,
            records_indexed=records_indexed,
            data_loss_expected=data_loss_expected,
        )
        item["health_summary"] = summary_label
        item["loss_summary"] = loss_label
        item["deep_retry_history"] = _deep_retry_history(item)
        item["health_check"] = health_checks.get(_artifact_key(item))
        item.update(
            _effective_problematic_state(
                item,
                health_check=item.get("health_check"),
                accepted_warning=accepted_warnings.get(_artifact_key(item)),
            )
        )
        item["data_loss_expected"] = bool(item.get("current_data_loss_expected"))
        importance, reasons = score_problematic_artifact_importance(item)
        item["importance"] = importance
        item["importance_reasons"] = reasons
        items.append(item)
        seen_keys.add(_artifact_key(item))

    fallback_problematic_statuses = {
        "failed",
        "failed_timeout",
        "failed_aborted",
        "cancelled_orphaned",
        "stalled_timeout",
        "aborted_before_completion",
        "worker_lost_reconciled",
        "deferred_long_tail",
        "partial_indexed_deferred",
        "skipped_empty",
        "completed_no_records",
        "unsupported_no_records",
    }
    for artifact_row in artifact_rows or []:
        status = str(getattr(artifact_row, "status", None) or (artifact_row.get("status") if isinstance(artifact_row, dict) else "")).strip().lower()
        if status not in fallback_problematic_statuses:
            continue
        source_path = str(getattr(artifact_row, "source_path", None) or (artifact_row.get("source_path") if isinstance(artifact_row, dict) else "") or "")
        parser_name = str(getattr(artifact_row, "parser", None) or (artifact_row.get("parser") if isinstance(artifact_row, dict) else "") or "")
        artifact_name = str(getattr(artifact_row, "name", None) or (artifact_row.get("name") if isinstance(artifact_row, dict) else "") or "")
        artifact_id = str(getattr(artifact_row, "id", None) or (artifact_row.get("id") if isinstance(artifact_row, dict) else "") or "") or None
        fallback_key = artifact_id or f"{source_path}|{parser_name or status}"
        if fallback_key in seen_keys:
            continue
        records_indexed = int(getattr(artifact_row, "record_count", None) or (artifact_row.get("record_count") if isinstance(artifact_row, dict) else 0) or 0)
        records_read = records_indexed
        no_records_status = status in {"skipped_empty", "completed_no_records", "unsupported_no_records"}
        error_type = "no_records" if no_records_status else "timeout" if "timeout" in status or "stalled" in status else "aborted"
        retryable = bool(source_path) and not no_records_status
        suggested_retry_mode = "deep_safe_mode" if parser_name.lower() == "evtx_raw" else "safe_mode"
        error_message = (
            "Artifact did not reach terminal parser completion before worker/run abort."
            if status in {"failed_aborted", "aborted_before_completion", "worker_lost_reconciled", "cancelled_orphaned"}
            else "Artifact was explicitly deferred by long-tail policy so the main ingest could finish safely."
            if status in {"deferred_long_tail", "partial_indexed_deferred"}
            else "Artifact did not finish before timeout."
            if status in {"failed_timeout", "stalled_timeout"}
            else "No records produced / empty or unsupported EVTX channel."
            if no_records_status
            else "Artifact failed during ingest."
        )
        item = {
            "artifact_id": artifact_id or _lookup_artifact_id(
                artifact_id_by_key,
                source_path=source_path,
                parser_name=parser_name,
                artifact_name=artifact_name,
            ),
            "name": artifact_name,
            "source_path": source_path,
            "artifact_type": getattr(artifact_row, "artifact_type", None) if not isinstance(artifact_row, dict) else artifact_row.get("artifact_type"),
            "parser": parser_name,
            "status": status,
            "records_read": records_read,
            "records_indexed": records_indexed,
            "bulk_batches": 0,
            "error_type": error_type,
            "error_message": error_message,
            "timeout_seconds": 0,
            "partial_data_indexed": records_indexed > 0,
            "data_loss_expected": not no_records_status,
            "retryable": retryable,
            "suggested_retry_mode": suggested_retry_mode,
            "retry_history": retry_history_by_key.get((source_path, parser_name), []),
        }
        summary_label, loss_label = classify_problematic_artifact_health(
            status=status,
            records_read=records_read,
            records_indexed=records_indexed,
            data_loss_expected=not no_records_status,
        )
        item["health_summary"] = summary_label
        item["loss_summary"] = loss_label
        item["deep_retry_history"] = _deep_retry_history(item)
        item["health_check"] = health_checks.get(_artifact_key(item))
        item.update(
            _effective_problematic_state(
                item,
                health_check=item.get("health_check"),
                accepted_warning=accepted_warnings.get(_artifact_key(item)),
            )
        )
        item["original_status"] = status
        item["effective_status"] = str(item.get("effective_status") or status)
        item["data_loss_expected"] = bool(item.get("current_data_loss_expected", not no_records_status))
        importance, reasons = score_problematic_artifact_importance(item)
        item["importance"] = importance
        item["importance_reasons"] = reasons
        items.append(item)
        seen_keys.add(_artifact_key(item))

    for deferred in metadata.get("evtx_deferred_files") or []:
        if not isinstance(deferred, dict):
            continue
        source_path = str(deferred.get("path") or "").strip()
        artifact_id = str(deferred.get("artifact_id") or "").strip() or None
        fallback_key = artifact_id or f"{source_path}|evtx_profile_deferred"
        if fallback_key in seen_keys:
            continue
        item = {
            "artifact_id": artifact_id,
            "name": Path(source_path).name or source_path,
            "source_path": source_path,
            "artifact_type": "windows_event",
            "parser": "evtx_raw",
            "status": "deferred_evtx_profile",
            "original_status": "deferred_evtx_profile",
            "effective_status": "deferred_evtx_profile",
            "effective_resolution": "evtx_profile_deferred",
            "records_read": 0,
            "records_indexed": 0,
            "effective_records_read": 0,
            "effective_records_indexed": 0,
            "bulk_batches": 0,
            "error_type": "deferred",
            "error_message": "EVTX deferred by Fast EVTX profile. Nothing was deleted.",
            "timeout_seconds": 0,
            "partial_data_indexed": False,
            "data_loss_expected": True,
            "historical_data_loss_expected": True,
            "current_data_loss_expected": True,
            "retryable": True,
            "suggested_retry_mode": "full_evtx_indexing",
            "suggested_primary_action": str(deferred.get("suggested_action") or "Run Full EVTX indexing / Deep retry"),
            "retry_history": [],
            "health_summary": "Deferred",
            "loss_summary": "Available for later indexing",
            "importance": "medium",
            "importance_reasons": ["evtx_profile_deferred", str(deferred.get("profile") or "")],
            "profile": deferred.get("profile"),
            "can_run_later": bool(deferred.get("can_run_later", True)),
            "channel": deferred.get("channel"),
        }
        items.append(item)
        seen_keys.add(fallback_key)

    for partial in metadata.get("evtx_partial_files") or []:
        if not isinstance(partial, dict):
            continue
        source_path = str(partial.get("path") or partial.get("file") or "").strip()
        artifact_id = str(partial.get("artifact_id") or "").strip() or None
        fallback_key = artifact_id or f"{source_path}|evtx_profile_partial"
        if fallback_key in seen_keys:
            continue
        records_read = int(partial.get("records_read") or partial.get("records_indexed") or 0)
        records_indexed = int(partial.get("records_indexed") or 0)
        item = {
            "artifact_id": artifact_id,
            "name": str(partial.get("file") or Path(source_path).name or source_path),
            "source_path": source_path,
            "artifact_type": "windows_event",
            "parser": "evtx_raw",
            "status": "partial_evtx_profile",
            "original_status": "partial_evtx_profile",
            "effective_status": "partial_evtx_profile",
            "effective_resolution": "evtx_profile_partial",
            "records_read": records_read,
            "records_indexed": records_indexed,
            "effective_records_read": records_read,
            "effective_records_indexed": records_indexed,
            "bulk_batches": 0,
            "error_type": "partial",
            "error_message": f"EVTX partially indexed by Fast EVTX profile limit: {partial.get('reason') or 'evtx_fast_limit'}",
            "timeout_seconds": 0,
            "partial_data_indexed": records_indexed > 0,
            "data_loss_expected": True,
            "historical_data_loss_expected": True,
            "current_data_loss_expected": True,
            "retryable": True,
            "suggested_retry_mode": "continue_evtx_indexing",
            "suggested_primary_action": str(partial.get("suggested_action") or "Continue EVTX indexing / Full EVTX indexing"),
            "retry_history": [],
            "health_summary": "Partial",
            "loss_summary": "Fast profile indexed a bounded prefix; remaining records are available for later indexing",
            "importance": "high",
            "importance_reasons": ["evtx_profile_partial", str(partial.get("reason") or "")],
            "profile": partial.get("profile"),
            "can_run_later": bool(partial.get("can_continue_later", True)),
            "limit_reason": partial.get("reason"),
        }
        items.append(item)
        seen_keys.add(fallback_key)

    status_counts = Counter(str(item.get("status") or "unknown") for item in items)
    effective_status_counts = Counter(str(item.get("effective_status") or "unknown") for item in items)
    return {
        "evidence_id": str(getattr(evidence, "id", "")),
        "summary": {
            "problematic_count": len(items),
            "parsed_with_warning": status_counts.get("parsed_with_warning", 0),
            "partially_parsed": status_counts.get("partially_parsed", 0),
            "failed": status_counts.get("failed", 0),
            "skipped_empty": status_counts.get("skipped_empty", 0) + status_counts.get("completed_no_records", 0) + status_counts.get("unsupported_no_records", 0),
            "retryable": sum(1 for item in items if item.get("retryable")),
            "indexed_with_warning": sum(1 for item in items if item.get("effective_status") in {"parsed_with_warning", "accepted_warning", "health_check_only_valid"}),
            "recovered_count": sum(1 for item in items if item.get("recovered")),
            "unresolved_count": sum(1 for item in items if str(item.get("effective_status") or "").startswith("unresolved") or item.get("effective_status") == "health_check_failed"),
            "data_loss_expected_count": sum(1 for item in items if item.get("current_data_loss_expected")),
            "source_missing_but_indexed": effective_status_counts.get("source_missing_but_indexed", 0),
            "evtx_profile_deferred": status_counts.get("deferred_evtx_profile", 0),
            "evtx_profile_partial": status_counts.get("partial_evtx_profile", 0),
        },
        "items": items,
    }


def problematic_artifacts_require_error_status(report: dict[str, Any] | None) -> bool:
    if not report:
        return False
    for item in report.get("items") or []:
        effective_status = str(item.get("effective_status") or "").strip().lower()
        if not effective_status:
            latest_retry = _latest_retry(item)
            latest_retry_status = str((latest_retry or {}).get("status") or "").strip().lower()
            latest_retry_outcome = str((latest_retry or {}).get("outcome") or "").strip().lower()
            latest_retry_read = int((latest_retry or {}).get("records_read") or 0)
            latest_retry_indexed = int((latest_retry or {}).get("records_indexed") or 0)
            if latest_retry_outcome == "recovered_more_data" and latest_retry_indexed > 0:
                effective_status = "recovered_with_warning" if latest_retry_status == "parsed_with_warning" else "recovered"
            elif latest_retry_status:
                effective_status = latest_retry_status
            elif latest_retry_read > 0 and latest_retry_read == latest_retry_indexed:
                effective_status = "parsed_with_warning"
            else:
                effective_status = str(item.get("status") or "").strip().lower()
        if effective_status in {"parsed_with_warning", "recovered", "recovered_with_warning", "accepted_warning", "source_missing_but_indexed", "health_check_only_valid", "skipped_empty", "completed_no_records", "unsupported_no_records"}:
            continue
        if effective_status in {"partially_parsed", "failed", "skipped_timeout", "stalled", "unresolved_timeout", "unresolved_failed", "health_check_failed"}:
            return True
        current_data_loss_expected = item.get("current_data_loss_expected")
        if current_data_loss_expected is None and effective_status in {"parsed_with_warning", "recovered", "recovered_with_warning", "accepted_warning", "source_missing_but_indexed", "health_check_only_valid"}:
            current_data_loss_expected = False
        if bool(current_data_loss_expected if current_data_loss_expected is not None else item.get("data_loss_expected")):
            return True
    return False


def build_long_tail_artifacts_report(
    evidence: Any,
    *,
    artifact_rows: list[Any] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    metadata = dict(getattr(evidence, "metadata_json", {}) or {})
    current_run_id = str(metadata.get("current_ingest_run_id") or metadata.get("latest_ingest_run_id") or "").strip() or None
    running_items = list(metadata.get("tail_current_artifacts") or [])
    queued_count = int(metadata.get("tail_artifacts_queued") or 0)
    defer_requests = {
        str(item.get("artifact_id") or ""): dict(item)
        for item in (metadata.get("long_tail_defer_requests") or [])
        if isinstance(item, dict)
    }
    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    running_source_paths = {str(item.get("source_path") or "") for item in running_items if str(item.get("source_path") or "")}

    for running_item in running_items:
        source_path = str(running_item.get("source_path") or "")
        artifact_row = next(
            (
                row
                for row in (artifact_rows or [])
                if str(getattr(row, "source_path", None) or (row.get("source_path") if isinstance(row, dict) else "") or "") == source_path
            ),
            None,
        )
        artifact_id = str(getattr(artifact_row, "id", None) or (artifact_row.get("id") if isinstance(artifact_row, dict) else "") or "") or None
        row_status = str(getattr(artifact_row, "status", None) or (artifact_row.get("status") if isinstance(artifact_row, dict) else "") or "processing")
        item = {
            "artifact_id": artifact_id,
            "name": running_item.get("artifact"),
            "artifact": running_item.get("artifact"),
            "artifact_type": running_item.get("artifact_type"),
            "parser": running_item.get("parser"),
            "source_path": source_path,
            "records_read": int(running_item.get("records_read") or 0),
            "records_indexed": int(running_item.get("records_indexed") or 0),
            "status": row_status,
            "defer_requested": bool(artifact_id and artifact_id in defer_requests),
            "defer_request": defer_requests.get(artifact_id or ""),
        }
        item.update(
            classify_long_tail_artifact_state(
                item | running_item,
                warning_seconds=max(int(settings.evtx_long_tail_warning_seconds or 900), 1),
                stall_seconds=max(int(settings.evtx_no_progress_stall_seconds or 600), 1),
                max_runtime_seconds=max(int(settings.evtx_max_active_runtime_seconds or 3600), 1),
                defer_after_seconds=max(int(settings.evtx_defer_after_seconds or 3600), 1),
            )
        )
        if item["defer_requested"] and item["long_tail_state"] not in {"deferred_long_tail", "partial_indexed_deferred"}:
            item["long_tail_state"] = "defer_requested"
        items.append(item)
        if artifact_id:
            seen_ids.add(artifact_id)

    for artifact_row in artifact_rows or []:
        artifact_id = str(getattr(artifact_row, "id", None) or (artifact_row.get("id") if isinstance(artifact_row, dict) else "") or "")
        source_path = str(getattr(artifact_row, "source_path", None) or (artifact_row.get("source_path") if isinstance(artifact_row, dict) else "") or "")
        if artifact_id in seen_ids or source_path in running_source_paths:
            continue
        status = str(getattr(artifact_row, "status", None) or (artifact_row.get("status") if isinstance(artifact_row, dict) else "") or "").strip().lower()
        if status not in {"queued_parallel", "deferred_long_tail", "partial_indexed_deferred", "failed_timeout", "stalled_timeout"}:
            continue
        item = {
            "artifact_id": artifact_id or None,
            "name": getattr(artifact_row, "name", None) if not isinstance(artifact_row, dict) else artifact_row.get("name"),
            "artifact_type": getattr(artifact_row, "artifact_type", None) if not isinstance(artifact_row, dict) else artifact_row.get("artifact_type"),
            "parser": getattr(artifact_row, "parser", None) if not isinstance(artifact_row, dict) else artifact_row.get("parser"),
            "source_path": source_path,
            "records_read": int(getattr(artifact_row, "record_count", None) or (artifact_row.get("record_count") if isinstance(artifact_row, dict) else 0) or 0),
            "records_indexed": int(getattr(artifact_row, "record_count", None) or (artifact_row.get("record_count") if isinstance(artifact_row, dict) else 0) or 0),
            "status": status,
            "elapsed_seconds": 0,
            "last_progress_seconds_ago": 0,
            "defer_requested": bool(artifact_id and artifact_id in defer_requests),
            "defer_request": defer_requests.get(artifact_id or ""),
        }
        item.update(
            classify_long_tail_artifact_state(
                item,
                warning_seconds=max(int(settings.evtx_long_tail_warning_seconds or 900), 1),
                stall_seconds=max(int(settings.evtx_no_progress_stall_seconds or 600), 1),
                max_runtime_seconds=max(int(settings.evtx_max_active_runtime_seconds or 3600), 1),
                defer_after_seconds=max(int(settings.evtx_defer_after_seconds or 3600), 1),
            )
        )
        if status == "queued_parallel":
            item["long_tail_state"] = "queued_tail"
        items.append(item)
        if artifact_id:
            seen_ids.add(artifact_id)

    state_counts = Counter(str(item.get("long_tail_state") or "unknown") for item in items)
    return {
        "evidence_id": str(getattr(evidence, "id", "")),
        "run_id": current_run_id,
        "summary": {
            "tail_artifacts_total": len(items),
            "running_count": state_counts.get("active_progressing", 0) + state_counts.get("slow_progressing", 0) + state_counts.get("stalled_no_progress", 0) + state_counts.get("defer_requested", 0),
            "queued_count": state_counts.get("queued_tail", 0),
            "deferred_count": state_counts.get("deferred_long_tail", 0) + state_counts.get("partial_indexed_deferred", 0),
            "stalled_count": state_counts.get("stalled_no_progress", 0),
            "high_value_count": sum(1 for item in items if item.get("importance") == "high"),
            "partial_indexed_count": sum(1 for item in items if int(item.get("records_indexed") or 0) > 0),
            "queued_artifacts": queued_count,
        },
        "items": items,
    }
