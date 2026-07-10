from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import re
from typing import Any

from sqlalchemy.orm import Session, selectinload

from app.models.artifact import Artifact
from app.models.evidence import Evidence, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.evidence_runs import list_evidence_runs, sync_ingest_run_from_metadata


PROCESSING_STATES = {
    "pending",
    "queued",
    "running",
    "completed",
    "completed_with_warnings",
    "failed",
    "cancelled",
    "unknown",
}

_PATH_RE = re.compile(r"(?:[A-Za-z]:\\\\|/)[^\s'\"]+")
_SENSITIVE_KEYS = {"path", "source_path", "stored_path", "original_path", "output_dir", "output_relative_path", "file", "filename"}


def _status_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "").split(".")[-1].strip().lower()


def _public_status(evidence: Evidence, runs: list[dict], warnings: int, failed_parsers: int) -> str:
    ingest = _status_value(evidence.ingest_status)
    latest = _status_value(runs[0].get("status") if runs else None)
    active = latest or ingest
    if active in {"queued"}:
        return "queued"
    if active in {"processing", "running"}:
        return "running"
    if active in {"cancelled", "canceled"}:
        return "cancelled"
    if active in {"failed", "timed_out", "timeout"} or ingest == "failed":
        return "failed"
    if active in {"completed_with_errors", "completed_with_warnings"} or ingest == "completed_with_errors" or failed_parsers or warnings:
        return "completed_with_warnings"
    if active == "completed" or ingest == "completed":
        return "completed"
    if ingest == "pending":
        return "pending"
    return "unknown"


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _iso(value: Any) -> str | None:
    parsed = _parse_dt(value)
    return parsed.isoformat() if parsed else (str(value) if value else None)


def _duration_seconds(started: Any, finished: Any, fallback: Any = None) -> float | None:
    if isinstance(fallback, (int, float)):
        return round(float(fallback), 3)
    start = _parse_dt(started)
    end = _parse_dt(finished)
    if start and end:
        return round(max((end - start).total_seconds(), 0), 3)
    return None


def _sanitize_text(value: Any, *, limit: int = 500) -> str | None:
    if value is None:
        return None
    text = _PATH_RE.sub("[redacted-path]", str(value)).strip()
    return text[:limit] if text else None


def _sanitize_details(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if key_lower in _SENSITIVE_KEYS or key_lower.endswith("_path") or key_lower.endswith("_dir"):
                continue
            result[key_text] = _sanitize_details(item)
        return result
    if isinstance(value, list):
        return [_sanitize_details(item) for item in value[:25]]
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _error_items(evidence: Evidence) -> list[dict]:
    error_log = evidence.error_log if isinstance(evidence.error_log, dict) else {}
    metadata = evidence.metadata_json if isinstance(evidence.metadata_json, dict) else {}
    raw_errors: list[Any] = []
    if error_log.get("fatal"):
        raw_errors.append({"error": error_log.get("fatal"), "type": error_log.get("fatal_type")})
    if isinstance(error_log.get("errors"), list):
        raw_errors.extend(error_log.get("errors") or [])
    if isinstance(metadata.get("warnings"), list):
        raw_errors.extend({"warning": item, "severity": "warning"} for item in metadata.get("warnings") or [])
    items: list[dict] = []
    for item in raw_errors[:50]:
        if isinstance(item, dict):
            parser = str(item.get("parser") or item.get("artifact") or item.get("name") or "unknown").strip() or "unknown"
            summary = item.get("error") or item.get("message") or item.get("warning") or item.get("detail") or item
            items.append({"parser": parser, "summary": _sanitize_text(summary), "severity": str(item.get("severity") or ("warning" if item.get("warning") else "error")), "details": _sanitize_details(item)})
        else:
            items.append({"parser": "unknown", "summary": _sanitize_text(item), "severity": "error", "details": {}})
    return items


def _artifact_rows_by_evidence(db: Session, case_id: str) -> dict[str, list[Artifact]]:
    rows = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    grouped: dict[str, list[Artifact]] = defaultdict(list)
    for row in rows:
        grouped[row.evidence_id].append(row)
    return grouped


def _memory_runs_by_evidence(db: Session, case_id: str) -> dict[str, list[MemoryScanRun]]:
    rows = (
        db.query(MemoryScanRun)
        .options(selectinload(MemoryScanRun.plugin_runs))
        .filter(MemoryScanRun.case_id == case_id)
        .order_by(MemoryScanRun.created_at.desc())
        .all()
    )
    grouped: dict[str, list[MemoryScanRun]] = defaultdict(list)
    for row in rows:
        grouped[row.evidence_id].append(row)
    return grouped


def _runs_for_evidence(evidence: Evidence, memory_runs: list[MemoryScanRun]) -> list[dict]:
    metadata = dict(evidence.metadata_json or {})
    latest_run_id = str(metadata.get("latest_ingest_run_id") or "").strip()
    if latest_run_id:
        metadata = sync_ingest_run_from_metadata(metadata, run_id=latest_run_id, ingest_status=_status_value(evidence.ingest_status))
    runs = [normalize_ingest_run(run) for run in list_evidence_runs(metadata)]
    runs.extend(normalize_memory_run(run) for run in memory_runs)
    return sorted(runs, key=lambda item: item.get("started_at") or item.get("finished_at") or item.get("run_id") or "", reverse=True)


def normalize_ingest_run(run: dict) -> dict:
    status = _status_value(run.get("status")) or "unknown"
    warnings = list(run.get("warnings") or [])
    failed = int(run.get("artifacts_failed") or run.get("failed_artifacts_count") or run.get("still_failed_count") or 0)
    if status == "completed_with_errors":
        status = "completed_with_warnings"
    parser_counts = dict(run.get("selected_by_parser") or {})
    return {
        "run_id": str(run.get("run_id") or ""),
        "evidence_id": None,
        "status": status,
        "started_at": _iso(run.get("started_at") or run.get("created_at")),
        "finished_at": _iso(run.get("finished_at")),
        "duration": _duration_seconds(run.get("started_at") or run.get("created_at"), run.get("finished_at"), run.get("elapsed_seconds")),
        "triggered_by": str(run.get("run_type") or "ingest"),
        "parser_family": "artifact",
        "parser_name": str(run.get("mode") or run.get("run_type") or "ingest"),
        "message": _sanitize_text(run.get("final_message") or run.get("phase") or run.get("artifact_progress")),
        "error_summary": _sanitize_text(run.get("last_error")),
        "error_details": _sanitize_details({"warnings": warnings, "items": run.get("items") or []}),
        "artifact_count": int(run.get("artifacts_done") or run.get("artifacts_total") or sum(int(v or 0) for v in parser_counts.values()) or 0),
        "parser_runs": [],
        "warning_count": len(warnings),
        "failed_parser_count": failed,
    }


def normalize_memory_run(run: MemoryScanRun) -> dict:
    status = _status_value(run.status) or "unknown"
    if status == "completed_with_errors":
        status = "completed_with_warnings"
    parser_runs = [normalize_memory_plugin(plugin) for plugin in run.plugin_runs]
    return {
        "run_id": run.id,
        "evidence_id": run.evidence_id,
        "status": status,
        "started_at": _iso(run.started_at or run.created_at),
        "finished_at": _iso(run.completed_at),
        "duration": round((run.duration_ms or 0) / 1000, 3) if run.duration_ms is not None else _duration_seconds(run.started_at, run.completed_at),
        "triggered_by": "memory_analysis",
        "parser_family": "memory",
        "parser_name": run.profile,
        "message": _sanitize_text((run.metadata_json or {}).get("message") or run.backend),
        "error_summary": _sanitize_text((run.error_log or {}).get("fatal") or (run.error_log or {}).get("error")),
        "error_details": _sanitize_details(run.error_log or {}),
        "artifact_count": sum(int(plugin.row_count or 0) for plugin in run.plugin_runs),
        "parser_runs": parser_runs,
        "warning_count": 0,
        "failed_parser_count": sum(1 for item in parser_runs if item["status"] in {"failed", "timed_out"}),
    }


def normalize_memory_plugin(plugin: MemoryPluginRun) -> dict:
    return {
        "run_id": plugin.id,
        "parser": plugin.plugin,
        "family": "memory",
        "status": _status_value(plugin.status) or "unknown",
        "started_at": _iso(plugin.started_at),
        "finished_at": _iso(plugin.completed_at),
        "duration": round((plugin.duration_ms or 0) / 1000, 3) if plugin.duration_ms is not None else _duration_seconds(plugin.started_at, plugin.completed_at),
        "artifacts": int(plugin.row_count or 0),
        "error": _sanitize_text(plugin.error_message or plugin.error_code),
    }


def _parser_rows(artifacts: list[Artifact], errors: list[dict], memory_runs: list[MemoryScanRun]) -> list[dict]:
    grouped: dict[tuple[str, str], dict] = {}
    for artifact in artifacts:
        key = (artifact.parser or "unknown", artifact.artifact_type or "artifact")
        row = grouped.setdefault(key, {"parser": key[0], "family": key[1], "status": "completed", "artifacts": 0, "records": 0, "error": None})
        row["artifacts"] += 1
        row["records"] += int(artifact.record_count or 0)
    for error in errors:
        if error.get("severity") == "warning":
            continue
        parser = str(error.get("parser") or "unknown")
        key = (parser, "artifact")
        row = grouped.setdefault(key, {"parser": parser, "family": "artifact", "status": "failed", "artifacts": 0, "records": 0, "error": None})
        row["status"] = "failed"
        row["error"] = row["error"] or error.get("summary")
    for run in memory_runs:
        for plugin in run.plugin_runs:
            key = (plugin.plugin, "memory")
            row = grouped.setdefault(key, {"parser": plugin.plugin, "family": "memory", "status": _status_value(plugin.status), "artifacts": 0, "records": 0, "error": None})
            row["status"] = _status_value(plugin.status) or row["status"]
            row["artifacts"] += 1
            row["records"] += int(plugin.row_count or 0)
            row["error"] = row["error"] or _sanitize_text(plugin.error_message or plugin.error_code)
    return sorted(grouped.values(), key=lambda item: (item["family"], item["parser"]))


def build_processing_item(evidence: Evidence, artifacts: list[Artifact], memory_runs: list[MemoryScanRun]) -> dict:
    errors = _error_items(evidence)
    runs = _runs_for_evidence(evidence, memory_runs)
    parser_rows = _parser_rows(artifacts, errors, memory_runs)
    parser_statuses = Counter(row["status"] for row in parser_rows)
    warning_count = sum(int(run.get("warning_count") or 0) for run in runs) + len([row for row in errors if row.get("details", {}).get("warning")])
    failed_parser_count = sum(1 for row in parser_rows if row["status"] in {"failed", "timed_out", "error"})
    status = _public_status(evidence, runs, warning_count, failed_parser_count)
    latest = runs[0] if runs else None
    host = getattr(getattr(evidence, "host", None), "display_name", None) or getattr(getattr(evidence, "host", None), "canonical_name", None) or (evidence.metadata_json or {}).get("provided_host") or evidence.detected_host
    artifact_count = len(artifacts) + sum(int(plugin.row_count or 0) for run in memory_runs for plugin in run.plugin_runs)
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "filename": evidence.original_filename,
        "evidence_type": _status_value(evidence.evidence_type) or str(evidence.evidence_type or "unknown"),
        "host": host,
        "uploaded_at": _iso(getattr(evidence, "uploaded_at", None) or evidence.created_at),
        "processing_status": status,
        "last_run_status": latest.get("status") if latest else status,
        "last_run_started_at": latest.get("started_at") if latest else None,
        "last_run_finished_at": latest.get("finished_at") if latest else _iso(evidence.processed_at),
        "duration": latest.get("duration") if latest else None,
        "parser_count": len(parser_rows) or sum(int(v or 0) for v in (latest or {}).get("selected_by_parser", {}).values()) if latest else len(parser_rows),
        "successful_parser_count": parser_statuses.get("completed", 0),
        "failed_parser_count": failed_parser_count,
        "warning_count": warning_count,
        "artifact_count": artifact_count,
        "last_error": errors[0]["summary"] if errors else (latest.get("error_summary") if latest else None),
        "runs": runs,
        "parser_runs": parser_rows,
        "errors": errors,
        "links": {
            "evidence": f"/evidences/{evidence.id}",
            "artifacts": f"/cases/{evidence.case_id}/artifacts?evidence_id={evidence.id}",
            "search": f"/cases/{evidence.case_id}/search?evidence_id={evidence.id}",
            "memory": f"/cases/{evidence.case_id}/memory/{evidence.id}/overview" if _status_value(evidence.evidence_type) == "memory_dump" else None,
        },
    }


def list_case_processing(db: Session, case_id: str) -> dict:
    evidences = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.desc()).all()
    artifacts_by_evidence = _artifact_rows_by_evidence(db, case_id)
    memory_by_evidence = _memory_runs_by_evidence(db, case_id)
    items = [build_processing_item(evidence, artifacts_by_evidence.get(evidence.id, []), memory_by_evidence.get(evidence.id, [])) for evidence in evidences]
    counts = Counter(item["processing_status"] for item in items)
    return {
        "case_id": case_id,
        "summary": {state: int(counts.get(state, 0)) for state in sorted(PROCESSING_STATES)},
        "items": items,
    }


def get_evidence_processing(db: Session, case_id: str, evidence_id: str) -> dict | None:
    evidence = db.get(Evidence, evidence_id)
    if not evidence or evidence.case_id != case_id:
        return None
    artifacts = db.query(Artifact).filter(Artifact.case_id == case_id, Artifact.evidence_id == evidence_id).all()
    memory_runs = (
        db.query(MemoryScanRun)
        .options(selectinload(MemoryScanRun.plugin_runs))
        .filter(MemoryScanRun.case_id == case_id, MemoryScanRun.evidence_id == evidence_id)
        .order_by(MemoryScanRun.created_at.desc())
        .all()
    )
    return build_processing_item(evidence, artifacts, memory_runs)


def get_evidence_processing_run(db: Session, case_id: str, evidence_id: str, run_id: str) -> dict | None:
    processing = get_evidence_processing(db, case_id, evidence_id)
    if not processing:
        return None
    for run in processing["runs"]:
        if str(run.get("run_id") or "") == run_id:
            return run
    return None
