from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, utc_now_naive
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.memory import backend_readiness
from app.services.memory.indexing import index_memory_system_info
from app.services.memory.normalizers import normalize_windows_info
from app.services.memory.storage import memory_run_dir, relative_to_data_dir, write_atomic_bytes, write_atomic_json
from app.services.memory.validation import MemoryExecutionValidationError, validate_memory_execution_request
from app.services.memory.volatility_runner import VolatilityRunnerError, run_windows_info


logger = logging.getLogger(__name__)

ACTIVE_STATUSES = {"pending", "queued", "running"}
TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "timed_out", "disabled", "backend_unavailable", "invalid_evidence", "cancelled"}
ALLOWED_PLUGIN = "windows.info"


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


def create_memory_metadata_run(db: Session, evidence_id: str) -> MemoryScanRun:
    validated = validate_memory_execution_request(db, evidence_id)
    run = MemoryScanRun(
        case_id=validated.evidence.case_id,
        evidence_id=validated.evidence.id,
        backend="volatility3",
        profile="metadata_only",
        status="pending",
        requested_plugin_count=1,
        plugin_count=1,
        plugins_completed=0,
        plugins_failed=0,
        metadata_json={"plugins": [ALLOWED_PLUGIN], "source_layer": "memory"},
        error_log={},
    )
    db.add(run)
    db.flush()
    plugin_run = MemoryPluginRun(
        memory_scan_run_id=run.id,
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        plugin=ALLOWED_PLUGIN,
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
        plugin_run = (
            db.query(MemoryPluginRun)
            .filter(MemoryPluginRun.memory_scan_run_id == run.id, MemoryPluginRun.plugin == ALLOWED_PLUGIN)
            .order_by(MemoryPluginRun.created_at.asc())
            .first()
        )
        if plugin_run is None:
            plugin_run = MemoryPluginRun(memory_scan_run_id=run.id, case_id=run.case_id, evidence_id=run.evidence_id, plugin=ALLOWED_PLUGIN, status="pending")
            db.add(plugin_run)
            db.commit()

        started_at = utc_now_naive()
        run.status = "running"
        run.started_at = started_at
        plugin_run.status = "running"
        plugin_run.started_at = started_at
        db.commit()
        logger.info("memory scan started", extra={"run_id": run.id, "case_id": run.case_id, "evidence_id": run.evidence_id, "backend": "volatility3", "plugin": ALLOWED_PLUGIN})

        try:
            validated = validate_memory_execution_request(db, run.evidence_id)
            readiness = backend_readiness.check_volatility3_backend()
            if not readiness.get("ready"):
                raise MemoryExecutionValidationError("BACKEND_UNAVAILABLE", "Volatility 3 backend is not ready for execution.")
            run.backend_version = readiness.get("version")
            output_dir = memory_run_dir(run.case_id, run.evidence_id, run.id)
            run.output_dir = relative_to_data_dir(output_dir)
            db.commit()

            result = run_windows_info(validated.path, output_dir)
            raw_info = write_atomic_bytes(output_dir / "windows.info.json", result.stdout)
            try:
                payload = json.loads(result.stdout.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                raise VolatilityRunnerError("MALFORMED_OUTPUT", "Volatility windows.info returned malformed JSON.", stdout=result.stdout, stderr=result.stderr) from exc

            normalized = normalize_windows_info(
                payload,
                case_id=run.case_id,
                evidence_id=run.evidence_id,
                memory_run_id=run.id,
                memory_plugin_run_id=plugin_run.id,
                backend_version=run.backend_version,
            )
            normalized_safe = _json_safe(normalized)
            manifest = {
                "run_id": run.id,
                "evidence_id": run.evidence_id,
                "backend": "volatility3",
                "plugin": ALLOWED_PLUGIN,
                "argv": result.argv_display,
                "raw_output": raw_info,
                "duration_ms": result.duration_ms,
                "completed_at": utc_iso(),
            }
            write_atomic_json(output_dir / "run_manifest.json", manifest)

            plugin_run.status = "completed"
            plugin_run.completed_at = utc_now_naive()
            plugin_run.duration_ms = result.duration_ms
            plugin_run.row_count = _row_count(payload)
            plugin_run.output_relative_path = raw_info["path"]
            plugin_run.output_sha256 = raw_info["sha256"]
            plugin_run.output_size = raw_info["size"]
            plugin_run.metadata_json = {"normalized_type": "memory_system_info", "raw_output_retained": True}
            run.plugins_completed = 1
            run.plugins_failed = 0
            run.metadata_json = {"system_info": normalized_safe, "plugins": [ALLOWED_PLUGIN], "raw_output": raw_info}
            db.commit()

            try:
                index_result = index_memory_system_info(run.case_id, normalized_safe)
                run.status = "completed"
                run.metadata_json = {**(run.metadata_json or {}), "indexing": index_result}
            except Exception as exc:  # noqa: BLE001
                run.status = "completed_with_errors"
                run.error_log = {"code": "INDEXING_FAILED", "message": _sanitize_message(exc)}
                logger.warning("memory indexing failed", extra={"run_id": run.id, "case_id": run.case_id, "error": _sanitize_message(exc)})

            completed_at = utc_now_naive()
            run.completed_at = completed_at
            run.duration_ms = _duration_ms(run.started_at, completed_at)
            db.commit()
            logger.info("memory scan completed", extra={"run_id": run.id, "status": run.status, "duration_ms": run.duration_ms})
        except MemoryExecutionValidationError as exc:
            _fail_run(db, run, plugin_run, "invalid_evidence" if exc.code.startswith(("EVIDENCE", "INVALID", "UNSAFE", "EMPTY")) else "backend_unavailable", exc.code, exc.message)
        except VolatilityRunnerError as exc:
            status = "timed_out" if exc.code == "PLUGIN_TIMEOUT" else "failed"
            _write_plugin_error(run, plugin_run, exc)
            _fail_run(db, run, plugin_run, status, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001
            _fail_run(db, run, plugin_run, "failed", "MEMORY_SCAN_FAILED", _sanitize_message(exc))


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
    if not exc.stderr:
        return
    try:
        output_dir = memory_run_dir(run.case_id, run.evidence_id, run.id)
        write_atomic_json(output_dir / "plugin_error.json", {"code": exc.code, "message": _sanitize_message(exc.message), "stderr": _sanitize_message(exc.stderr.decode("utf-8", errors="replace"))})
    except Exception:  # noqa: BLE001
        logger.warning("memory plugin error file could not be written", extra={"run_id": run.id, "plugin_run_id": plugin_run.id})


def _fail_run(db: Session, run: MemoryScanRun, plugin_run: MemoryPluginRun, status: str, code: str, message: str) -> None:
    completed_at = utc_now_naive()
    run.status = status
    run.completed_at = completed_at
    run.duration_ms = _duration_ms(run.started_at, completed_at)
    run.plugins_failed = 1 if plugin_run else 0
    run.error_log = {"code": code, "message": _sanitize_message(message)}
    if plugin_run:
        plugin_run.status = "timed_out" if status == "timed_out" else "failed"
        plugin_run.completed_at = completed_at
        plugin_run.duration_ms = _duration_ms(plugin_run.started_at, completed_at)
        plugin_run.error_code = code
        plugin_run.error_message = _sanitize_message(message)
    db.commit()
    logger.warning("memory scan failed", extra={"run_id": run.id, "status": run.status, "error_code": code})


def count_runs(db: Session) -> int:
    return int(db.query(func.count(MemoryScanRun.id)).scalar() or 0)
