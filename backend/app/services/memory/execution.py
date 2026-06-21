from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, utc_now_naive
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun
from app.services.memory import backend_readiness
from app.services.memory.evidence_access import MemoryStorageAccessError, validate_current_process_output_access
from app.services.memory.artifact_indexing import (
    index_artifact_documents,
    link_process_entities,
)
from app.services.memory.artifact_normalizers import (
    NORMALIZATION_VERSION,
    merge_module_documents,
    normalize_windows_dlllist,
    normalize_windows_driverscan,
    normalize_windows_handles,
    normalize_windows_ldrmodules,
    normalize_windows_malfind,
    normalize_windows_modules,
    normalize_windows_netscan,
)
from app.services.memory.indexing import index_memory_documents, index_memory_system_info
from app.services.memory.normalizers import merge_memory_process_results, normalize_windows_cmdline, normalize_windows_info, normalize_windows_pslist, normalize_windows_psscan, normalize_windows_pstree
from app.services.memory.storage import memory_run_dir, relative_to_data_dir, write_atomic_bytes, write_atomic_json
from app.services.memory.validation import MemoryExecutionValidationError, validate_memory_execution_request
from app.services.memory.volatility_runner import VolatilityRunnerError, probe_windows_symbol_identity, run_plugin
from app.services.memory import volatility_runner
from app.services.memory.symbol_control import record_symbol_requirement


logger = logging.getLogger(__name__)

ACTIVE_STATUSES = {"pending", "queued", "running"}
TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "timed_out", "disabled", "backend_unavailable", "invalid_evidence", "cancelled"}
PROFILE_PLUGINS = {
    "metadata_only": ["windows.info"],
    "processes_basic": ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"],
    "processes_extended": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"],
    "network_basic": ["windows.netscan", "windows.info"],
    "modules_basic": ["windows.dlllist", "windows.ldrmodules", "windows.info"],
    "handles_basic": ["windows.handles", "windows.info"],
    "kernel_basic": ["windows.modules", "windows.driverscan", "windows.info"],
    "suspicious_memory": ["windows.malfind", "windows.info"],
}
PROCESS_PLUGINS = {"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}
ARTIFACT_PROFILES = {
    "network_basic",
    "modules_basic",
    "handles_basic",
    "kernel_basic",
    "suspicious_memory",
}
ARTIFACT_PLUGIN_NORMALIZER = {
    "windows.netscan": "memory_network_connection",
    "windows.dlllist": "memory_process_module",
    "windows.ldrmodules": "memory_process_module",
    "windows.handles": "memory_handle",
    "windows.modules": "memory_kernel_module",
    "windows.driverscan": "memory_driver",
    "windows.malfind": "memory_suspicious_region",
}
ARTIFACT_PLUGIN_LIMITS = {
    # Per-plugin guard-rails to keep offline execution bounded.
    "windows.netscan": {"timeout_seconds": 300, "max_output_bytes": 16 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.dlllist": {"timeout_seconds": 300, "max_output_bytes": 32 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.ldrmodules": {"timeout_seconds": 300, "max_output_bytes": 32 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.handles": {"timeout_seconds": 600, "max_output_bytes": 64 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.modules": {"timeout_seconds": 300, "max_output_bytes": 16 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.driverscan": {"timeout_seconds": 300, "max_output_bytes": 16 * 1024 * 1024, "max_records": 200000, "max_preview_bytes": 0},
    "windows.malfind": {"timeout_seconds": 1800, "max_output_bytes": 32 * 1024 * 1024, "max_records": 50000, "max_preview_bytes": 256},
}


def utc_iso(value: datetime | None = None) -> str:
    dt = value or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _duration_ms(started_at: datetime | None, completed_at: datetime | None) -> int | None:
    if not started_at or not completed_at:
        return None
    return int(max((completed_at - started_at).total_seconds(), 0) * 1000)


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return utc_iso(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _sanitize_message(value: object) -> str:
    return backend_readiness.sanitize_backend_error(value)


def active_run_for_evidence(db: Session, evidence_id: str, profile: str = "metadata_only") -> MemoryScanRun | None:
    return (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.evidence_id == evidence_id, MemoryScanRun.profile == profile, MemoryScanRun.status.in_(ACTIVE_STATUSES))
        .order_by(MemoryScanRun.created_at.desc())
        .first()
    )


def resolve_profile_plugins(profile: str) -> list[str]:
    settings = backend_readiness.get_settings()
    profile = str(profile or settings.default_memory_profile).strip()
    if profile not in settings.allowed_memory_profiles or profile not in PROFILE_PLUGINS:
        raise MemoryExecutionValidationError("UNKNOWN_PROFILE", "Unknown memory analysis profile.")
    if profile != "metadata_only" and not settings.memory_process_profile_enabled:
        raise MemoryExecutionValidationError("PROCESS_PROFILE_DISABLED", "Memory process profiles are disabled by server configuration.")
    # Runtime check: the network_basic profile requires a Windows
    # network plugin that is not present in the installed Volatility
    # 3.28.0 build.  Reject the start before any MemoryScanRun is
    # created and before any Redis task is enqueued.
    if profile == "network_basic":
        available, explanation = volatility_runner.network_basic_available()
        if not available:
            raise MemoryExecutionValidationError("MEMORY_PROFILE_UNAVAILABLE", explanation)
    plugins = PROFILE_PLUGINS[profile]
    allowed_plugins = set(settings.allowed_memory_plugins)
    required = set(plugins)
    if not required.issubset(allowed_plugins):
        raise MemoryExecutionValidationError("PLUGIN_NOT_ALLOWED", "Configured memory plugin allowlist does not permit the requested profile.")
    return plugins


def create_memory_metadata_run(db: Session, evidence_id: str, profile: str = "metadata_only") -> MemoryScanRun:
    validated = validate_memory_execution_request(db, evidence_id)
    plugins = resolve_profile_plugins(profile)
    run = MemoryScanRun(
        case_id=validated.evidence.case_id,
        evidence_id=validated.evidence.id,
        backend="volatility3",
        profile=profile,
        status="pending",
        requested_plugin_count=len(plugins),
        plugin_count=len(plugins),
        plugins_completed=0,
        plugins_failed=0,
        metadata_json={"plugins": plugins, "source_layer": "memory", "profile": profile},
        error_log={},
    )
    db.add(run)
    db.flush()
    for plugin in plugins:
        plugin_run = MemoryPluginRun(
            memory_scan_run_id=run.id,
            case_id=run.case_id,
            evidence_id=run.evidence_id,
            plugin=plugin,
            status="pending",
            metadata_json={},
        )
        db.add(plugin_run)
    db.commit()
    db.refresh(run)
    return run


def mark_run_queued(db: Session, run_id: str, worker_task_id: str | None) -> MemoryScanRun | None:
    run = db.get(MemoryScanRun, run_id)
    if not run:
        return None
    run.status = "queued"
    run.worker_task_id = worker_task_id
    db.commit()
    db.refresh(run)
    return run


def run_memory_metadata_scan(memory_scan_run_id: str) -> None:
    with SessionLocal() as db:
        run = db.get(MemoryScanRun, memory_scan_run_id)
        if run is None or run.status in TERMINAL_STATUSES:
            return
        _advance_owning_batch = None
        started_at = utc_now_naive()
        run.status = "running"
        run.started_at = started_at
        db.commit()
        logger.info("memory scan started", extra={"run_id": run.id, "case_id": run.case_id, "evidence_id": run.evidence_id, "backend": "volatility3", "profile": run.profile})

        try:
            validated = validate_memory_execution_request(db, run.evidence_id)
            readiness = backend_readiness.check_volatility3_backend()
            if not readiness.get("ready"):
                raise MemoryExecutionValidationError("BACKEND_UNAVAILABLE", "Volatility 3 backend is not ready for execution.")
            try:
                validate_current_process_output_access()
            except MemoryStorageAccessError as exc:
                raise MemoryExecutionValidationError(exc.code, exc.message) from None
            run.backend_version = readiness.get("version")
            output_dir = memory_run_dir(run.case_id, run.evidence_id, run.id)
            run.output_dir = relative_to_data_dir(output_dir)
            db.commit()
            plugins = list((run.metadata_json or {}).get("plugins") or PROFILE_PLUGINS.get(run.profile, ["windows.info"]))
            system_info = None
            raw_outputs = {}
            process_results = []
            artifact_results: dict[str, dict[str, Any]] = {}
            manifest_plugins = []
            fatal = False
            blocking_error: VolatilityRunnerError | None = None
            for plugin in plugins:
                plugin_run = _plugin_run_for(db, run, plugin)
                try:
                    payload, raw_info, duration_ms, argv_display = _execute_plugin(db, run, plugin_run, plugin, validated.path, output_dir)
                    raw_outputs[plugin] = raw_info
                    manifest_plugins.append({"plugin": plugin, "argv": argv_display, "raw_output": raw_info, "duration_ms": duration_ms})
                    try:
                        if plugin == "windows.info":
                            system_info = _json_safe(normalize_windows_info(payload, case_id=run.case_id, evidence_id=run.evidence_id, memory_run_id=run.id, memory_plugin_run_id=plugin_run.id, backend_version=run.backend_version))
                            plugin_run.metadata_json = {"normalized_type": "memory_system_info", "raw_output_retained": True}
                        elif plugin in PROCESS_PLUGINS:
                            process_results.append(_normalize_process_payload(plugin, payload))
                            plugin_run.metadata_json = {"normalized_type": "memory_process", "raw_output_retained": True}
                        elif plugin in ARTIFACT_PLUGIN_NORMALIZER:
                            artifact_results[plugin] = _normalize_artifact_payload(
                                plugin,
                                payload,
                                case_id=run.case_id,
                                evidence_id=run.evidence_id,
                                scan_run_id=run.id,
                                plugin_run_id=plugin_run.id,
                            )
                            plugin_run.metadata_json = {
                                "normalized_type": ARTIFACT_PLUGIN_NORMALIZER[plugin],
                                "raw_output_retained": True,
                                "raw_count": artifact_results[plugin].get("raw_count", 0),
                                "accepted_count": artifact_results[plugin].get("accepted_count", 0),
                                "dropped_count": artifact_results[plugin].get("dropped_count", 0),
                                "warnings": artifact_results[plugin].get("warnings", [])[:20],
                                "normalization_version": artifact_results[plugin].get("normalization_version", NORMALIZATION_VERSION),
                            }
                    except Exception as exc:  # noqa: BLE001
                        raise VolatilityRunnerError("MEMORY_ARTIFACT_NORMALIZATION_FAILED", f"Volatility {plugin} completed, but Kairon could not normalize its output.", return_code=0) from exc
                    plugin_run.status = "completed"
                    plugin_run.completed_at = utc_now_naive()
                    plugin_run.duration_ms = duration_ms
                    plugin_run.row_count = _row_count(payload)
                    plugin_run.output_relative_path = raw_info["path"]
                    plugin_run.output_sha256 = raw_info["sha256"]
                    plugin_run.output_size = raw_info["size"]
                    run.plugins_completed += 1
                    db.commit()
                except VolatilityRunnerError as exc:
                    _write_plugin_error(run, plugin_run, exc)
                    plugin_run.status = "timed_out" if exc.code == "PLUGIN_TIMEOUT" else "failed"
                    plugin_run.completed_at = utc_now_naive()
                    plugin_run.error_code = exc.code
                    plugin_run.error_message = _sanitize_message(exc.message)
                    run.plugins_failed += 1
                    blocking_error = exc
                    db.commit()
                    if plugin == "windows.info" and exc.code == "SYMBOLS_UNAVAILABLE":
                        requirement = probe_windows_symbol_identity(validated.path, output_dir)
                        if requirement:
                            record_symbol_requirement(db, run, plugin_run.id, requirement)
                    if plugin == "windows.info":
                        fatal = True
                        break
                    continue
            write_atomic_json(output_dir / "run_manifest.json", {"run_id": run.id, "evidence_id": run.evidence_id, "backend": "volatility3", "profile": run.profile, "plugins": manifest_plugins, "completed_at": utc_iso()})
            run.metadata_json = {"system_info": system_info, "plugins": plugins, "raw_output": raw_outputs, "profile": run.profile}
            if fatal:
                _mark_dependency_skipped(db, run, blocking_plugin="windows.info")
                raise blocking_error or VolatilityRunnerError("PLUGIN_FAILED", "windows.info failed; remaining memory plugins were not executed.")
            try:
                indexing = {}
                if system_info:
                    indexing["system_info"] = index_memory_system_info(run.case_id, system_info)
                if process_results:
                    merged = merge_memory_process_results(process_results, case_id=run.case_id, evidence_id=run.evidence_id, memory_run_id=run.id)
                    documents = merged["processes"] + merged["edges"]
                    if len(merged["processes"]) > int(backend_readiness.get_settings().memory_max_process_rows):
                        raise VolatilityRunnerError("PROCESS_ROW_LIMIT_EXCEEDED", "Memory process result exceeded the configured row limit.")
                    indexing["processes"] = index_memory_documents(run.case_id, documents)
                    run.metadata_json = {**(run.metadata_json or {}), "process_counts": {"memory_process": len(merged["processes"]), "memory_process_edge": len(merged["edges"])}, "parse_warnings": merged["warnings"]}
                    _upsert_summary(db, run, "memory_process", len(merged["processes"]), {"profile": run.profile, "sources": sorted({plugin for item in merged["processes"] for plugin in item.get("plugins", [])}), "warnings": merged["warnings"][:20]})
                    _upsert_summary(db, run, "memory_process_edge", len(merged["edges"]), {"profile": run.profile})
                    command_count = len([item for item in merged["processes"] if item.get("process", {}).get("command_line")])
                    _upsert_summary(db, run, "memory_command_line_count", command_count, {"profile": run.profile})
                if artifact_results:
                    artifact_indexing = _index_artifact_results(run.case_id, artifact_results, db, run)
                    indexing["artifacts"] = artifact_indexing
                run.status = "completed" if run.plugins_failed == 0 else "completed_with_errors"
                run.metadata_json = {**(run.metadata_json or {}), "indexing": indexing}
            except Exception as exc:  # noqa: BLE001
                run.status = "completed_with_errors"
                run.error_log = {"code": "INDEXING_FAILED", "message": _sanitize_message(exc)}
                logger.warning("memory indexing failed", extra={"run_id": run.id, "case_id": run.case_id, "error": _sanitize_message(exc)})

            completed_at = utc_now_naive()
            run.completed_at = completed_at
            run.duration_ms = _duration_ms(run.started_at, completed_at)
            db.commit()
            logger.info("memory scan completed", extra={"run_id": run.id, "status": run.status, "duration_ms": run.duration_ms})
            _advance_owning_batch = run
        except MemoryExecutionValidationError as exc:
            if exc.code in {"MEMORY_EVIDENCE_PERMISSION_DENIED", "MEMORY_OUTPUT_PERMISSION_DENIED"}:
                status = "failed"
            else:
                status = "invalid_evidence" if exc.code.startswith(("EVIDENCE", "INVALID", "UNSAFE", "EMPTY")) else "backend_unavailable"
            _fail_run(db, run, None, status, exc.code, exc.message)
            _advance_owning_batch = run
        except VolatilityRunnerError as exc:
            status = "timed_out" if exc.code == "PLUGIN_TIMEOUT" else "failed"
            _fail_run(db, run, None, status, exc.code, exc.message)
            _advance_owning_batch = run
        except Exception as exc:  # noqa: BLE001
            _fail_run(db, run, None, "failed", "MEMORY_SCAN_FAILED", _sanitize_message(exc))
            _advance_owning_batch = run

    if _advance_owning_batch is not None:
        _advance_batch_after_run(_advance_owning_batch)


def _plugin_run_for(db: Session, run: MemoryScanRun, plugin: str) -> MemoryPluginRun:
    plugin_run = (
        db.query(MemoryPluginRun)
        .filter(MemoryPluginRun.memory_scan_run_id == run.id, MemoryPluginRun.plugin == plugin)
        .order_by(MemoryPluginRun.created_at.asc())
        .first()
    )
    if plugin_run is None:
        plugin_run = MemoryPluginRun(memory_scan_run_id=run.id, case_id=run.case_id, evidence_id=run.evidence_id, plugin=plugin, status="pending", metadata_json={})
        db.add(plugin_run)
        db.commit()
    return plugin_run


def _plugin_filename(plugin: str) -> str:
    return f"{plugin}.json"


def _normalize_artifact_payload(
    plugin: str,
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
) -> dict[str, Any]:
    """Dispatch a single plugin payload to its canonical normalizer.

    Returns the canonical normalizer result; the caller is responsible
    for indexing and linking process entities.
    """
    common = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scan_run_id": scan_run_id,
        "plugin_run_id": plugin_run_id,
    }
    if plugin == "windows.netscan":
        return normalize_windows_netscan(payload, source_plugin=plugin, **common)
    if plugin == "windows.dlllist":
        return normalize_windows_dlllist(payload, source_plugin=plugin, **common)
    if plugin == "windows.ldrmodules":
        return normalize_windows_ldrmodules(payload, source_plugin=plugin, **common)
    if plugin == "windows.handles":
        return normalize_windows_handles(payload, source_plugin=plugin, **common)
    if plugin == "windows.modules":
        return normalize_windows_modules(payload, source_plugin=plugin, **common)
    if plugin == "windows.driverscan":
        return normalize_windows_driverscan(payload, source_plugin=plugin, **common)
    if plugin == "windows.malfind":
        return normalize_windows_malfind(payload, source_plugin=plugin, **common)
    return {
        "items": [],
        "warnings": [f"unsupported_artifact_plugin:{plugin}"],
        "raw_count": 0,
        "accepted_count": 0,
        "dropped_count": 0,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _index_artifact_results(
    case_id: str,
    artifact_results: dict[str, dict[str, Any]],
    db: Session,
    run: MemoryScanRun,
) -> dict[str, Any]:
    """Index the artifact documents produced by ``artifact_results``.

    For profiles that need cross-plugin consolidation (modules_basic),
    the per-plugin outputs are merged before indexing.  For all other
    profiles the canonical items are indexed directly.  Process-entity
    linking happens after indexing to keep the contract simple.
    """
    result: dict[str, Any] = {}
    profile = run.profile
    if profile == "modules_basic":
        dlllist = artifact_results.get("windows.dlllist")
        ldrmodules = artifact_results.get("windows.ldrmodules")
        groups = []
        if dlllist:
            groups.append(dlllist)
        if ldrmodules:
            groups.append(ldrmodules)
        merged = merge_module_documents(*groups)
        if merged["items"]:
            result["memory_process_module"] = index_artifact_documents(case_id, merged["items"])
        result["module_discrepancies"] = merged["conflicts"]
        result["normalization_version"] = merged["normalization_version"]
    else:
        for plugin, payload in artifact_results.items():
            items = payload.get("items", [])
            if not items:
                continue
            doc_type = ARTIFACT_PLUGIN_NORMALIZER.get(plugin, "memory_artifact")
            result[doc_type] = index_artifact_documents(case_id, items)
            result["normalization_version"] = payload.get("normalization_version", NORMALIZATION_VERSION)
    # Best-effort process entity linking.
    if result:
        try:
            link_process_entities(case_id, scan_run_id=run.id, document_type="memory_process_module")
            link_process_entities(case_id, scan_run_id=run.id, document_type="memory_handle")
            link_process_entities(case_id, scan_run_id=run.id, document_type="memory_network_connection")
        except Exception as exc:  # noqa: BLE001
            logger.warning("artifact process linking failed: %s", _sanitize_message(exc))
    # Persist a summary row per artifact type so the Runs view can show
    # the counts without re-querying OpenSearch.
    for plugin, payload in artifact_results.items():
        doc_type = ARTIFACT_PLUGIN_NORMALIZER.get(plugin)
        if not doc_type:
            continue
        _upsert_summary(
            db,
            run,
            doc_type,
            int(payload.get("accepted_count", 0)),
            {
                "profile": profile,
                "plugin": plugin,
                "warnings": payload.get("warnings", [])[:20],
                "normalization_version": payload.get("normalization_version", NORMALIZATION_VERSION),
            },
        )
    return result


def _execute_plugin(db: Session, run: MemoryScanRun, plugin_run: MemoryPluginRun, plugin: str, evidence_path, output_dir) -> tuple[Any, dict, int, list[str]]:
    plugin_run.status = "running"
    plugin_run.started_at = utc_now_naive()
    db.commit()
    # Per-plugin guard-rails (timeout, output size) for the new artifact
    # plugins.  Falls back to the global default for process plugins.
    overrides = ARTIFACT_PLUGIN_LIMITS.get(plugin, {})
    max_output_bytes = int(overrides.get("max_output_bytes") or 0) or None
    timeout_seconds = int(overrides.get("timeout_seconds") or 0) or None
    if timeout_seconds or max_output_bytes:
        result = run_plugin(
            plugin,
            evidence_path,
            output_dir,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    else:
        result = run_plugin(plugin, evidence_path, output_dir)
    try:
        raw_info = write_atomic_bytes(output_dir / _plugin_filename(plugin), result.stdout, max_bytes=max_output_bytes)
    except ValueError as exc:
        if str(exc) == "output_too_large":
            raise VolatilityRunnerError("OUTPUT_TOO_LARGE", f"Volatility {plugin} output exceeded the configured size limit.", stdout=result.stdout[:max_output_bytes or 0], stderr=result.stderr[:4096]) from exc
        raise
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise VolatilityRunnerError("VOLATILITY_OUTPUT_INVALID", f"Volatility {plugin} executed, but its output could not be parsed.", stdout=result.stdout, stderr=result.stderr, return_code=0) from exc
    return payload, raw_info, result.duration_ms, result.argv_display


def _normalize_process_payload(plugin: str, payload: Any) -> dict[str, Any]:
    settings = backend_readiness.get_settings()
    kwargs = {"command_limit": int(settings.memory_max_command_line_length), "raw_limit": int(settings.memory_max_raw_field_length)}
    if plugin == "windows.pslist":
        return normalize_windows_pslist(payload, **kwargs)
    if plugin == "windows.pstree":
        return normalize_windows_pstree(payload, **kwargs)
    if plugin == "windows.psscan":
        return normalize_windows_psscan(payload, **kwargs)
    if plugin == "windows.cmdline":
        return normalize_windows_cmdline(payload, **kwargs)
    return {"plugin": plugin, "processes": [], "edges": [], "warnings": ["unsupported_process_plugin"], "row_count": 0}


def _upsert_summary(db: Session, run: MemoryScanRun, artifact_type: str, count: int, metadata: dict[str, Any]) -> None:
    summary = (
        db.query(MemoryArtifactSummary)
        .filter(MemoryArtifactSummary.memory_run_id == run.id, MemoryArtifactSummary.memory_artifact_type == artifact_type)
        .first()
    )
    if summary is None:
        summary = MemoryArtifactSummary(case_id=run.case_id, evidence_id=run.evidence_id, memory_run_id=run.id, memory_artifact_type=artifact_type, count=count, metadata_json=metadata)
        db.add(summary)
    else:
        summary.count = count
        summary.metadata_json = metadata


def _row_count(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("rows", "data"):
            if isinstance(payload.get(key), list):
                return len(payload[key])
        return 1
    return 0


def _write_plugin_error(run: MemoryScanRun, plugin_run: MemoryPluginRun, exc: VolatilityRunnerError) -> None:
    plugin_run.metadata_json = {
        **(plugin_run.metadata_json or {}),
        "return_code": exc.return_code,
        "stdout_length": exc.stdout_length,
        "stderr_length": exc.stderr_length,
        "stdout_retained_bytes": len(exc.stdout),
        "stderr_retained_bytes": len(exc.stderr),
    }
    if not exc.stderr:
        return
    try:
        output_dir = memory_run_dir(run.case_id, run.evidence_id, run.id)
        write_atomic_json(output_dir / "plugin_error.json", {"code": exc.code, "message": _sanitize_message(exc.message), "stderr": _sanitize_message(exc.stderr.decode("utf-8", errors="replace"))})
    except Exception:  # noqa: BLE001
        logger.warning("memory plugin error file could not be written", extra={"run_id": run.id, "plugin_run_id": plugin_run.id})


def _advance_batch_after_run(run: MemoryScanRun) -> None:
    """Advance the owning batch (if any) after a run has reached a
    terminal state.  Opens a fresh DB session and delegates to the
    batch service.
    """
    if run.batch_id is None:
        return
    try:
        from app.services.memory.batch import advance_batch

        with SessionLocal() as db:
            fresh = db.get(MemoryScanRun, run.id)
            if fresh is None:
                return
            advance_batch(db, run=fresh)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "memory batch advancement failed",
            extra={"run_id": run.id, "batch_id": run.batch_id, "error": _sanitize_message(exc)},
        )


def _fail_run(db: Session, run: MemoryScanRun, plugin_run: MemoryPluginRun | None, status: str, code: str, message: str) -> None:
    completed_at = utc_now_naive()
    run.status = status
    run.completed_at = completed_at
    run.duration_ms = _duration_ms(run.started_at, completed_at)
    if plugin_run:
        run.plugins_failed = 1
    run.error_log = {"code": code, "message": _sanitize_message(message)}
    if plugin_run:
        plugin_run.status = "timed_out" if status == "timed_out" else "failed"
        plugin_run.completed_at = completed_at
        plugin_run.duration_ms = _duration_ms(plugin_run.started_at, completed_at)
        plugin_run.error_code = code
        plugin_run.error_message = _sanitize_message(message)
    db.commit()
    logger.warning("memory scan failed", extra={"run_id": run.id, "status": run.status, "error_code": code})


def _mark_dependency_skipped(db: Session, run: MemoryScanRun, *, blocking_plugin: str) -> None:
    now = utc_now_naive()
    for plugin_run in run.plugin_runs:
        if plugin_run.plugin == blocking_plugin or plugin_run.status != "pending":
            continue
        plugin_run.status = "skipped_dependency"
        plugin_run.completed_at = now
        plugin_run.error_code = "SKIPPED_DEPENDENCY"
        plugin_run.error_message = f"Skipped because {blocking_plugin} did not complete successfully."
    db.commit()


def count_runs(db: Session) -> int:
    return int(db.query(func.count(MemoryScanRun.id)).scalar() or 0)
