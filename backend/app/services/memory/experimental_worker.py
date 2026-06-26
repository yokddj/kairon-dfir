"""Worker entry points for experimental mismatched-symbol analysis."""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.models.evidence import Evidence
from app.models.memory import MemoryExperimentalRun, MemoryExperimentalSymbolCandidate, MemoryPluginRun, MemoryScanRun
from app.services.memory.evidence_access import MemoryStorageAccessError, validate_current_process_evidence_access, validate_current_process_output_access
from app.services.memory.execution import (
    _normalize_artifact_payload,
    _normalize_process_payload,
    _plugin_run_for,
    _row_count,
    _sanitize_message,
)
from app.services.memory.experimental_catalogue import EXPERIMENTAL_CANARY_PLUGINS, allowed_profiles_for_canary_outcome, get_experimental_profile
from app.services.memory.experimental_import import ExperimentalImportError, verify_candidate_integrity
from app.services.memory.experimental_indexing import delete_experimental_documents_by_run, index_experimental_documents
from app.services.memory.experimental_lifecycle import (
    ExperimentalLifecycleError,
    cancel_run,
    finalise_run,
    finalize_canary,
    mark_canary_running,
    mark_full_run_running,
    record_profile_progress,
    request_full_run,
    update_worker_heartbeat,
)
from app.services.memory.experimental_trust import (
    ANALYSIS_MODE_EXPERIMENTAL,
    RUN_STATUS_CANCELLED,
    RUN_STATUS_CANARY_DEGRADED,
    RUN_STATUS_CANARY_FAILED,
    RUN_STATUS_CANARY_INCONCLUSIVE,
    RUN_STATUS_CANARY_PASSED,
    TRUST_LEVEL_UNTRUSTED,
    is_experimental_enabled,
)
from app.services.memory.normalizers import merge_memory_process_results, normalize_windows_info
from app.services.memory.storage import experimental_memory_run_dir, relative_to_data_dir, write_atomic_bytes, write_atomic_json
from app.services.memory.volatility_runner import VolatilityRunnerError, run_plugin


logger = logging.getLogger(__name__)
settings = get_settings()


def _resolve_run_dir(case_id: str, evidence_id: str, run_id: str) -> Path:
    return experimental_memory_run_dir(case_id, evidence_id, run_id)


def _resolve_evidence_path(db: Session, evidence_id: str) -> Path:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise ExperimentalLifecycleError("EXPERIMENTAL_EVIDENCE_NOT_FOUND", "Experimental evidence was not found.", http_status=404)
    try:
        validate_current_process_output_access()
        access = validate_current_process_evidence_access(evidence)
    except MemoryStorageAccessError as exc:
        raise ExperimentalLifecycleError(exc.code, exc.message, http_status=409) from exc
    return access.path


def _build_overlay_symbol_dir(run_dir: Path, run: MemoryExperimentalRun, candidate_isf_path: Path) -> tuple[Path, Path]:
    overlay_root = run_dir / "symbol-overlay"
    cache_root = run_dir / "volatility-cache"
    symbol_root = overlay_root / "windows" / str(run.acknowledgement_required_pdb_name or "")
    target = symbol_root / f"{str(run.acknowledgement_required_pdb_guid or '').upper()}-{int(run.acknowledgement_required_pdb_age or 0)}.json.xz"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copy2(candidate_isf_path, target)
    return cache_root, overlay_root


def _ensure_scan_run(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    profile: str,
    plugins: list[str],
) -> MemoryScanRun:
    scan_run = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.experimental_run_id == run.id, MemoryScanRun.profile == profile)
        .order_by(MemoryScanRun.created_at.desc())
        .first()
    )
    if scan_run is not None:
        return scan_run
    scan_run = MemoryScanRun(
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        backend="volatility3",
        profile=profile,
        status="pending",
        requested_plugin_count=len(plugins),
        plugin_count=len(plugins),
        plugins_completed=0,
        plugins_failed=0,
        metadata_json={"plugins": list(plugins), "experimental": True, "profile": profile},
        error_log={},
        analysis_mode=ANALYSIS_MODE_EXPERIMENTAL,
        trust_level=TRUST_LEVEL_UNTRUSTED,
        symbol_match_type="guid_only_age_mismatch",
        experimental_run_id=run.id,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    return scan_run


def _write_plugin_metadata(run_dir: Path, plugin: str, stdout: bytes, *, max_output_bytes: int | None = None) -> dict[str, Any]:
    return write_atomic_bytes(run_dir / f"{plugin}.json", stdout, max_bytes=max_output_bytes)


def _execute_plugin_for_scan(
    db: Session,
    *,
    scan_run: MemoryScanRun,
    plugin: str,
    evidence_path: Path,
    run_dir: Path,
    cache_path: Path,
    symbol_path: Path,
    timeout_seconds: int,
) -> tuple[Any | None, MemoryPluginRun, dict[str, Any]]:
    plugin_run = _plugin_run_for(db, scan_run, plugin)
    plugin_run.analysis_mode = ANALYSIS_MODE_EXPERIMENTAL
    plugin_run.trust_level = TRUST_LEVEL_UNTRUSTED
    plugin_run.status = "running"
    plugin_run.started_at = utc_now_naive()
    db.add(plugin_run)
    db.commit()
    try:
        result = run_plugin(
            plugin,
            evidence_path,
            run_dir,
            timeout_seconds=timeout_seconds,
            offline=True,
            cache_path=cache_path,
            symbol_path=symbol_path,
        )
        raw_info = _write_plugin_metadata(run_dir, plugin, result.stdout)
        payload = json.loads(result.stdout.decode("utf-8"))
        plugin_run.status = "completed"
        plugin_run.completed_at = utc_now_naive()
        plugin_run.duration_ms = result.duration_ms
        plugin_run.row_count = _row_count(payload)
        plugin_run.output_relative_path = raw_info["path"]
        plugin_run.output_sha256 = raw_info["sha256"]
        plugin_run.output_size = raw_info["size"]
        plugin_run.metadata_json = {"argv": result.argv_display, "experimental": True}
        db.add(plugin_run)
        db.commit()
        db.refresh(plugin_run)
        return payload, plugin_run, {"status": plugin_run.status, "row_count": plugin_run.row_count}
    except (VolatilityRunnerError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, VolatilityRunnerError) else "VOLATILITY_OUTPUT_INVALID"
        message = exc.message if isinstance(exc, VolatilityRunnerError) else "Volatility output could not be parsed."
        plugin_run.status = "timed_out" if code == "PLUGIN_TIMEOUT" else "failed"
        plugin_run.completed_at = utc_now_naive()
        plugin_run.error_code = code
        plugin_run.error_message = _sanitize_message(message)
        plugin_run.metadata_json = {"experimental": True, "error": plugin_run.error_message}
        db.add(plugin_run)
        db.commit()
        db.refresh(plugin_run)
        return None, plugin_run, {"status": plugin_run.status, "error_code": code}


def _finalize_scan_status(db: Session, scan_run: MemoryScanRun) -> MemoryScanRun:
    scan_run.plugins_completed = sum(1 for item in scan_run.plugin_runs if item.status == "completed")
    scan_run.plugins_failed = sum(1 for item in scan_run.plugin_runs if item.status in {"failed", "timed_out"})
    scan_run.completed_at = utc_now_naive()
    if scan_run.plugins_completed and not scan_run.plugins_failed:
        scan_run.status = "completed"
    elif scan_run.plugins_completed:
        scan_run.status = "completed_with_errors"
    else:
        scan_run.status = "failed"
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    return scan_run


def _inject_experimental_fields(run: MemoryExperimentalRun, row: dict[str, Any], *, document_type: str, source_plugin: str, scan_run_id: str, plugin_run_id: str | None) -> dict[str, Any]:
    doc = dict(row)
    doc["case_id"] = run.case_id
    doc["evidence_id"] = run.evidence_id
    doc["experimental_run_id"] = run.id
    doc["analysis_mode"] = ANALYSIS_MODE_EXPERIMENTAL
    doc["trust_level"] = TRUST_LEVEL_UNTRUSTED
    doc["symbol_match_type"] = "guid_only_age_mismatch"
    doc["required_pdb_name"] = run.acknowledgement_required_pdb_name
    doc["required_pdb_guid"] = run.acknowledgement_required_pdb_guid
    doc["required_pdb_age"] = run.acknowledgement_required_pdb_age
    doc["observed_pdb_name"] = run.acknowledgement_observed_pdb_name
    doc["observed_pdb_guid"] = run.acknowledgement_observed_pdb_guid
    doc["observed_pdb_age"] = run.acknowledgement_observed_pdb_age
    doc["canary_status"] = run.canary_status
    doc["canary_score"] = run.canary_score
    doc["document_type"] = document_type
    doc["source_plugin"] = source_plugin
    doc["scan_run_id"] = scan_run_id
    doc["plugin_run_id"] = plugin_run_id
    return doc


def _normalize_experimental_documents(
    *,
    run: MemoryExperimentalRun,
    scan_run: MemoryScanRun,
    plugin_payloads: dict[str, Any],
    plugin_runs: dict[str, MemoryPluginRun],
    profile_definition: dict[str, Any],
) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    if "windows.info" in plugin_payloads:
        info_doc = normalize_windows_info(
            plugin_payloads["windows.info"],
            case_id=run.case_id,
            evidence_id=run.evidence_id,
            memory_run_id=scan_run.id,
            memory_plugin_run_id=plugin_runs["windows.info"].id,
            backend_version=scan_run.backend_version,
        )
        docs.append(
            _inject_experimental_fields(
                run,
                info_doc,
                document_type="memory_system_info",
                source_plugin="windows.info",
                scan_run_id=scan_run.id,
                plugin_run_id=plugin_runs["windows.info"].id,
            )
        )
    process_payloads = []
    for plugin in ("windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"):
        if plugin in plugin_payloads:
            process_payloads.append(_normalize_process_payload(plugin, plugin_payloads[plugin]))
    if process_payloads:
        merged = merge_memory_process_results(
            process_payloads,
            case_id=run.case_id,
            evidence_id=run.evidence_id,
            memory_run_id=scan_run.id,
        )
        for item in merged["processes"] + merged["edges"]:
            docs.append(
                _inject_experimental_fields(
                    run,
                    item,
                    document_type=str(item.get("document_type") or profile_definition["family"]),
                    source_plugin=str(item.get("source_plugin") or profile_definition["family"]),
                    scan_run_id=scan_run.id,
                    plugin_run_id=None,
                )
            )
    for plugin, payload in plugin_payloads.items():
        if plugin in {"windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}:
            continue
        normalized = _normalize_artifact_payload(
            plugin,
            payload,
            case_id=run.case_id,
            evidence_id=run.evidence_id,
            scan_run_id=scan_run.id,
            plugin_run_id=plugin_runs[plugin].id,
        )
        for item in normalized.get("items", []):
            docs.append(
                _inject_experimental_fields(
                    run,
                    item,
                    document_type=str(item.get("document_type") or profile_definition["family"]),
                    source_plugin=plugin,
                    scan_run_id=scan_run.id,
                    plugin_run_id=plugin_runs[plugin].id,
                )
            )
    return [doc for doc in docs if doc.get("document_id")]


def _reconcile_run_terminal_state(db: Session, run: MemoryExperimentalRun) -> MemoryExperimentalRun:
    if run.status not in {"full_run_running", "full_run_queued"}:
        return run
    total_finished = int(run.profiles_completed or 0) + int(run.profiles_failed or 0) + int(run.profiles_cancelled or 0)
    if total_finished < int(run.profiles_queued or 0):
        return run
    if int(run.profiles_completed or 0) == 0:
        return finalise_run(db, run=run, outcome="failed_untrusted")
    if int(run.profiles_failed or 0) > 0 or int(run.profiles_cancelled or 0) > 0:
        return finalise_run(db, run=run, outcome="partial_untrusted")
    return finalise_run(db, run=run, outcome="completed_untrusted")


def run_experimental_canary(experimental_run_id: str) -> str:
    with SessionLocal() as db:
        run = db.get(MemoryExperimentalRun, experimental_run_id)
        if run is None:
            logger.warning("experimental canary: run %s not found", experimental_run_id)
            return "not_found"
        if not is_experimental_enabled():
            cancel_run(db, run=run, actor="system", reason="feature_disabled")
            return "feature_disabled"
        if run.status in {RUN_STATUS_CANARY_PASSED, RUN_STATUS_CANARY_DEGRADED, RUN_STATUS_CANARY_INCONCLUSIVE, RUN_STATUS_CANARY_FAILED}:
            return "already_finalised"
        if run.deleted_at is not None:
            return "deleted"
        candidate = db.get(MemoryExperimentalSymbolCandidate, run.candidate_id)
        try:
            if candidate is None:
                raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate was not found.")
            _, _, candidate_isf_path = verify_candidate_integrity(db, candidate=candidate)
            evidence_path = _resolve_evidence_path(db, run.evidence_id)
            run = mark_canary_running(db, run=run)
            run = update_worker_heartbeat(db, run=run, stage="canary_running")
            run_dir = _resolve_run_dir(run.case_id, run.evidence_id, run.id)
            cache_path, symbol_path = _build_overlay_symbol_dir(run_dir, run, candidate_isf_path)
            scan_run = _ensure_scan_run(db, run=run, profile="experimental_canary", plugins=list(EXPERIMENTAL_CANARY_PLUGINS))
            scan_run.output_dir = relative_to_data_dir(run_dir)
            scan_run.started_at = utc_now_naive()
            scan_run.status = "running"
            db.add(scan_run)
            db.commit()
            plugin_rows: dict[str, list[dict[str, Any]]] = {}
            plugin_results: dict[str, dict[str, Any]] = {}
            for plugin in EXPERIMENTAL_CANARY_PLUGINS:
                payload, _, result = _execute_plugin_for_scan(
                    db,
                    scan_run=scan_run,
                    plugin=plugin,
                    evidence_path=evidence_path,
                    run_dir=run_dir,
                    cache_path=cache_path,
                    symbol_path=symbol_path,
                    timeout_seconds=int(settings.memory_experimental_canary_timeout_seconds),
                )
                plugin_results[plugin] = result
                if isinstance(payload, list):
                    plugin_rows[plugin] = [item for item in payload if isinstance(item, dict)]
                elif isinstance(payload, dict):
                    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else payload.get("data")
                    if isinstance(rows, list):
                        plugin_rows[plugin] = [item for item in rows if isinstance(item, dict)]
                    else:
                        plugin_rows[plugin] = [payload]
                else:
                    plugin_rows[plugin] = []
                update_worker_heartbeat(db, run=run, stage=f"canary_plugin:{plugin}")
            _finalize_scan_status(db, scan_run)
            flattened = plugin_rows.get("windows.pslist") or plugin_rows.get("windows.info") or []
            run = finalize_canary(
                db,
                run=run,
                rows=flattened,
                plugin_rows=plugin_rows,
                plugin_results=plugin_results,
            )
            return run.canary_status or "unknown"
        except (ExperimentalLifecycleError, ExperimentalImportError) as exc:
            cancel_run(db, run=run, actor="system", reason=exc.code if hasattr(exc, "code") else "canary_failed")
            return getattr(exc, "code", "canary_failed")


def queue_experimental_full_run(db: Session, *, run: MemoryExperimentalRun) -> int:
    allowed = allowed_profiles_for_canary_outcome(run.canary_status)
    if run.canary_status == "degraded":
        allowed = [name for name in allowed if name in set(run.requested_profiles or [])]
    elif run.canary_status == "passed":
        allowed = [name for name in allowed if name in set(run.requested_profiles or [])]
    if not allowed:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANARY_BLOCKED",
            "No experimental profile is allowed for the current canary outcome.",
        )
    scan_run_ids: list[str] = []
    for profile_name in allowed:
        definition = get_experimental_profile(profile_name)
        if definition is None:
            continue
        scan_run = _ensure_scan_run(db, run=run, profile=profile_name, plugins=list(definition["plugins"]))
        scan_run_ids.append(scan_run.id)
    request_full_run(db, run=run, worker_task_id=None)
    record_profile_progress(db, run=run, status_increment={"queued": len(scan_run_ids)})
    return len(scan_run_ids)


def run_experimental_profile(experimental_run_id: str, profile: str) -> str:
    with SessionLocal() as db:
        run = db.get(MemoryExperimentalRun, experimental_run_id)
        if run is None:
            return "not_found"
        if run.deleted_at is not None:
            return "deleted"
        if not is_experimental_enabled():
            return "feature_disabled"
        profile_definition = get_experimental_profile(profile)
        if profile_definition is None:
            return "unknown_profile"
        allowed = set(allowed_profiles_for_canary_outcome(run.canary_status))
        if profile not in allowed or profile not in set(run.requested_profiles or []):
            return "profile_not_allowed"
        candidate = db.get(MemoryExperimentalSymbolCandidate, run.candidate_id)
        try:
            if candidate is None:
                raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate was not found.")
            _, _, candidate_isf_path = verify_candidate_integrity(db, candidate=candidate)
            evidence_path = _resolve_evidence_path(db, run.evidence_id)
            try:
                mark_full_run_running(db, run=run)
            except ExperimentalLifecycleError:
                pass
            update_worker_heartbeat(db, run=run, stage=f"profile_running:{profile}")
            run_dir = _resolve_run_dir(run.case_id, run.evidence_id, run.id)
            cache_path, symbol_path = _build_overlay_symbol_dir(run_dir, run, candidate_isf_path)
            scan_run = _ensure_scan_run(db, run=run, profile=profile, plugins=list(profile_definition["plugins"]))
            scan_run.output_dir = relative_to_data_dir(run_dir)
            scan_run.started_at = scan_run.started_at or utc_now_naive()
            scan_run.status = "running"
            db.add(scan_run)
            db.commit()
            plugin_payloads: dict[str, Any] = {}
            plugin_runs: dict[str, MemoryPluginRun] = {}
            had_failure = False
            for plugin_name in profile_definition["plugins"]:
                payload, plugin_run, result = _execute_plugin_for_scan(
                    db,
                    scan_run=scan_run,
                    plugin=plugin_name,
                    evidence_path=evidence_path,
                    run_dir=run_dir,
                    cache_path=cache_path,
                    symbol_path=symbol_path,
                    timeout_seconds=int(settings.memory_experimental_run_timeout_seconds),
                )
                plugin_runs[plugin_name] = plugin_run
                if payload is not None:
                    plugin_payloads[plugin_name] = payload
                if result.get("status") != "completed":
                    had_failure = True
                update_worker_heartbeat(db, run=run, stage=f"profile_plugin:{profile}:{plugin_name}")
            _finalize_scan_status(db, scan_run)
            documents = _normalize_experimental_documents(
                run=run,
                scan_run=scan_run,
                plugin_payloads=plugin_payloads,
                plugin_runs=plugin_runs,
                profile_definition=profile_definition,
            )
            if documents:
                index_experimental_documents(run.case_id, documents, experimental_run_id=run.id)
            record_profile_progress(db, run=run, status_increment={"failed": 1} if had_failure and not documents else {"completed": 1})
            run = db.get(MemoryExperimentalRun, run.id) or run
            _reconcile_run_terminal_state(db, run)
            write_atomic_json(run_dir / f"{profile}.manifest.json", {"profile": profile, "plugins": list(plugin_payloads.keys()), "document_count": len(documents)})
            return "ok" if documents else ("failed" if had_failure else "no_documents")
        except (ExperimentalLifecycleError, ExperimentalImportError) as exc:
            try:
                record_profile_progress(db, run=run, status_increment={"failed": 1})
                _reconcile_run_terminal_state(db, run)
            except Exception:
                logger.warning("experimental run reconciliation failed", exc_info=True)
            return getattr(exc, "code", "experimental_profile_failed")


def delete_experimental_run_artifacts(case_id: str, evidence_id: str, experimental_run_id: str) -> dict[str, Any]:
    return delete_experimental_documents_by_run(case_id, evidence_id=evidence_id, experimental_run_id=experimental_run_id)


__all__ = [
    "delete_experimental_run_artifacts",
    "queue_experimental_full_run",
    "run_experimental_canary",
    "run_experimental_profile",
]
