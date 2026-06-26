"""Volatility-native compatibility probe for Windows symbol requirements.

When Kairon's internal PDB parser reports an age mismatch (e.g. required=1,
observed=5), this module runs the pinned stock Volatility engine with full
automagic against the evidence.  If Volatility succeeds and produces structurally
valid output, the evidence is marked compatible and normal validated analysis
can proceed.

The probe performs genuine stock Volatility execution — no custom ISF, no
forced --offline, no manually selected symbol table.  Volatility is authoritative.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.models.memory import MemoryNativeProbe, MemorySymbolRequirement

logger = logging.getLogger(__name__)

COMPATIBLE_REASON = "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE"
NATIVE_PROBE_ALLOWED_PLUGINS = {"windows.pslist.PsList"}

OUTPUT_VALIDATION_KEYS = frozenset((
    "row_count", "pid_present", "pid4_system", "printable_name_ratio",
    "malformed_row_ratio", "timestamps_parseable", "offsets_in_range",
))


class NativeProbeError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Enqueue / queue orchestration
# ---------------------------------------------------------------------------


def queue_native_probe(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    requirement_id: str,
    actor: str = "server-operator",
) -> MemoryNativeProbe:
    settings = get_settings()
    if not settings.memory_native_probe_enabled:
        raise NativeProbeError(
            "NATIVE_PROBE_DISABLED",
            "Native Volatility compatibility probe is not enabled.",
        )
    existing = _active_probe_for(db, evidence_id=evidence_id)
    if existing is not None:
        return existing
    probe = MemoryNativeProbe(
        case_id=case_id,
        evidence_id=evidence_id,
        requirement_id=requirement_id,
        status="queued",
        plugin=settings.memory_native_probe_plugin,
    )
    db.add(probe)
    db.flush()

    from app.workers.tasks import enqueue_native_probe

    job_id = enqueue_native_probe(str(probe.id))
    probe.queue_job_id = job_id
    db.add(probe)
    db.commit()
    return probe


# ---------------------------------------------------------------------------
# Worker execution entry point
# ---------------------------------------------------------------------------


def execute_native_probe(probe_id: str) -> str:
    with SessionLocal() as db:
        probe = db.get(MemoryNativeProbe, probe_id)
        if probe is None:
            logger.warning("native probe %s not found", probe_id)
            return "not_found"
        settings = get_settings()
        probe.status = "running"
        probe.started_at = utc_now_naive()
        probe.heartbeat_at = utc_now_naive()
        db.add(probe)
        db.commit()

        try:
            requirement = db.get(MemorySymbolRequirement, probe.requirement_id)
            if requirement is None:
                raise NativeProbeError(
                    "NATIVE_PROBE_REQUIREMENT_MISSING", "Requirement not found."
                )
            _record_vol_version(probe, db)
            _execute_stock_plugin(db, probe)
            _finalise_success(db, probe)
            logger.info("native probe %s: compatible", probe_id)
            return "compatible"
        except NativeProbeError as exc:
            _finalise_error(db, probe, exc)
            logger.warning("native probe %s: %s - %s", probe_id, exc.code, exc.message)
            return exc.code
        except Exception:
            logger.exception("native probe %s: unexpected error", probe_id)
            _finalise_error(
                db, probe, NativeProbeError("NATIVE_PROBE_INTERNAL_ERROR", "Unexpected error.")
            )
            return "NATIVE_PROBE_INTERNAL_ERROR"
        finally:
            _update_heartbeat(db, probe)


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def reconcile_stale_probes(db: Session) -> int:
    settings = get_settings()
    cutoff = utc_now_naive() - timedelta(seconds=settings.memory_native_probe_stale_seconds)
    stale = (
        db.query(MemoryNativeProbe)
        .filter(
            MemoryNativeProbe.status.in_({"queued", "running"}),
            MemoryNativeProbe.heartbeat_at < cutoff,
        )
        .all()
    )
    for probe in stale:
        probe.status = "failed"
        probe.sanitized_error = "NATIVE_PROBE_STALE: Stale probe reconciled (no recent heartbeat)."
        probe.completed_at = utc_now_naive()
        db.add(probe)
    db.commit()
    return len(stale)


_RECONCILE_KEY = "kairon:native_probe:reconcile_lock"
_RECONCILE_INTERVAL = 300  # seconds


def schedule_periodic_reconciliation_if_needed() -> bool:
    """Schedule a reconciliation task if one is not already pending.

    Uses a Redis key with TTL to prevent duplicate scheduling across
    multiple backend instances or workers.  Returns True when a new
    task was enqueued.
    """
    from app.core.config import get_settings as _gs
    import redis as _redis

    try:
        rconn = _redis.Redis.from_url(_gs().redis_url)
    except Exception:
        return False
    acquired = rconn.set(_RECONCILE_KEY, "1", nx=True, ex=_RECONCILE_INTERVAL)
    if not acquired:
        return False
    try:
        from app.workers.tasks import _enqueue_native_probe_reconciliation
        _enqueue_native_probe_reconciliation()
        return True
    except Exception:
        rconn.delete(_RECONCILE_KEY)
        return False


def run_periodic_reconciliation() -> str:
    """RQ task entry point for periodic stale-probe reconciliation."""
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        count = reconcile_stale_probes(db)
        if count > 0:
            logger.info("native probe periodic reconciliation: %d stale", count)
        return f"reconciled_{count}"
    finally:
        db.close()


def reconciliation_diagnostics() -> dict:
    return {
        "mechanism": "redis_distributed_lock",
        "interval_seconds": _RECONCILE_INTERVAL,
        "lock_key": _RECONCILE_KEY,
        "available": True,
    }


# ---------------------------------------------------------------------------
# Compatibility check (read-only)
# ---------------------------------------------------------------------------


def check_native_compatibility(
    db: Session, *, evidence_id: str, requirement_id: str
) -> dict[str, Any] | None:
    probe = (
        db.query(MemoryNativeProbe)
        .filter(
            MemoryNativeProbe.evidence_id == evidence_id,
            MemoryNativeProbe.requirement_id == requirement_id,
            MemoryNativeProbe.status == "compatible",
        )
        .order_by(MemoryNativeProbe.completed_at.desc())
        .first()
    )
    if probe is None:
        return None
    return {
        "compatible": True,
        "reason": COMPATIBLE_REASON,
        "probe_id": str(probe.id),
        "plugin": probe.plugin,
        "vol_version": probe.vol_version,
        "output_row_count": probe.output_row_count,
        "completed_at": probe.completed_at.isoformat() if probe.completed_at else None,
    }


# ---------------------------------------------------------------------------
# Output validation
# ---------------------------------------------------------------------------


def validate_native_probe_output(
    raw_output: str,
    *,
    min_rows: int | None = None,
    malformed_ratio: float | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    if min_rows is None:
        min_rows = settings.memory_native_probe_min_process_rows
    if malformed_ratio is None:
        malformed_ratio = settings.memory_native_probe_malformed_row_ratio

    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError:
        return {"valid": False, "reason": "Malformed JSON output."}

    rows = _extract_rows(payload)
    checks: dict[str, Any] = {}
    issues: list[str] = []

    row_count = len(rows)
    checks["row_count"] = row_count
    if row_count < min_rows:
        issues.append(f"Only {row_count} process row(s); minimum is {min_rows}.")

    pid_found = _any_valid_pid(rows)
    checks["pid_present"] = pid_found
    if not pid_found:
        issues.append("No valid PID column found.")

    pid4_found = _has_pid4_system(rows)
    checks["pid4_system"] = pid4_found
    if not pid4_found:
        issues.append("PID 4 / System process not found.")

    printable_ratio = _printable_name_ratio(rows)
    checks["printable_name_ratio"] = printable_ratio
    if printable_ratio < 0.3:
        issues.append(f"Only {printable_ratio:.0%} of process names are printable.")

    malformed = _malformed_row_ratio(rows)
    checks["malformed_row_ratio"] = malformed
    if malformed > malformed_ratio:
        issues.append(
            f"{malformed:.0%} of rows are malformed; max is {malformed_ratio:.0%}."
        )

    timestamps_ok = _timestamps_parseable(rows)
    checks["timestamps_parseable"] = timestamps_ok

    offsets_ok = _offsets_in_range(rows)
    checks["offsets_in_range"] = offsets_ok

    valid = pid_found and pid4_found and row_count >= min_rows and malformed <= malformed_ratio and printable_ratio >= 0.3
    return {
        "valid": valid,
        "reason": "Compatible" if valid else "; ".join(issues),
        "row_count": row_count,
        "checks": checks,
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _active_probe_for(db: Session, *, evidence_id: str) -> MemoryNativeProbe | None:
    return (
        db.query(MemoryNativeProbe)
        .filter(
            MemoryNativeProbe.evidence_id == evidence_id,
            MemoryNativeProbe.status.in_({"queued", "running"}),
        )
        .order_by(MemoryNativeProbe.created_at.desc())
        .first()
    )


def _update_heartbeat(db: Session, probe: MemoryNativeProbe) -> None:
    probe.heartbeat_at = utc_now_naive()
    db.add(probe)
    db.commit()


def _record_vol_version(probe: MemoryNativeProbe, db: Session | None = None) -> None:
    try:
        from volatility3 import framework as volfw
        probe.vol_version = getattr(volfw.constants, "PACKAGE_VERSION", None)
    except Exception:
        pass


def _canonical_evidence_path(db: Session, evidence_id: str) -> Path:
    from app.models.evidence import Evidence
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise NativeProbeError(
            "NATIVE_PROBE_EVIDENCE_MISSING", "Evidence not found."
        )
    stored = getattr(evidence, "stored_path", None) or getattr(evidence, "original_path", None)
    if not stored:
        raise NativeProbeError(
            "NATIVE_PROBE_EVIDENCE_PATH_MISSING",
            "Evidence file path could not be resolved.",
        )
    path = Path(stored)
    if not path.exists():
        raise NativeProbeError(
            "NATIVE_PROBE_EVIDENCE_FILE_MISSING",
            "Evidence file does not exist on the filesystem.",
        )
    return path


def _resolve_vol_executable() -> str:
    return os.environ.get("VOLATILITY3_EXECUTABLE", "vol")


def _execute_stock_plugin(
    db: Session,
    probe: MemoryNativeProbe,
) -> None:
    settings = get_settings()
    evidence_path = _canonical_evidence_path(db, probe.evidence_id)
    vol_exe = _resolve_vol_executable()

    if probe.plugin not in NATIVE_PROBE_ALLOWED_PLUGINS:
        raise NativeProbeError(
            "NATIVE_PROBE_PLUGIN_REJECTED",
            f"Plugin {probe.plugin!r} is not in the native probe allowlist.",
        )

    argv = [
        vol_exe,
        "-f", str(evidence_path),
        "-r", "json",
        probe.plugin,
    ]

    logger.debug("native probe argv: %s", argv)

    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=settings.memory_native_probe_timeout_seconds,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise NativeProbeError(
            "NATIVE_PROBE_TIMEOUT",
            f"Volatility did not complete within {settings.memory_native_probe_timeout_seconds}s.",
        )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    probe.exit_code = proc.returncode

    if len(stdout.encode("utf-8")) > settings.memory_native_probe_max_output_bytes:
        raise NativeProbeError(
            "NATIVE_PROBE_OUTPUT_TOO_LARGE",
            "Volatility output exceeds the configured size limit.",
        )

    if proc.returncode != 0:
        sanitised = _sanitise_stderr(stderr)
        raise NativeProbeError(
            "NATIVE_PROBE_EXECUTION_FAILED",
            f"Volatility exited with code {proc.returncode}. {sanitised}",
        )

    output_hash = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
    validation = validate_native_probe_output(stdout)

    probe.output_hash = output_hash
    probe.output_row_count = validation.get("row_count", 0)
    probe.structural_validation = validation

    if not validation.get("valid"):
        reason = validation.get("reason", "Output failed structural validation.")
        raise NativeProbeError("NATIVE_PROBE_INCOMPATIBLE", reason)


def _finalise_success(db: Session, probe: MemoryNativeProbe) -> None:
    probe.status = "compatible"
    probe.completed_at = utc_now_naive()
    probe.heartbeat_at = utc_now_naive()
    db.add(probe)
    db.commit()


def _finalise_error(db: Session, probe: MemoryNativeProbe, exc: NativeProbeError) -> None:
    code = exc.code or "NATIVE_PROBE_FAILED"
    if "TIMEOUT" in code:
        probe.status = "timeout"
    elif code == "NATIVE_PROBE_INCOMPATIBLE":
        probe.status = "incompatible"
    else:
        probe.status = "failed"
    probe.sanitized_error = exc.message[:1024]
    probe.completed_at = utc_now_naive()
    probe.heartbeat_at = utc_now_naive()
    db.add(probe)
    db.commit()


def _sanitise_stderr(stderr: str) -> str:
    sanitised = stderr.replace("\n", " ").strip()
    if len(sanitised) > 500:
        sanitised = sanitised[:500] + "..."
    return sanitised


def _hash_file(path: Path, max_bytes: int = 2 * 1024 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        total = 0
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > max_bytes:
                break
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Row extraction and validation helpers
# ---------------------------------------------------------------------------


def _extract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
        return []
    return []


_PID_RE = re.compile(r"^(PID|pid|\d+|0x[0-9a-fA-F]+)$")
_PRINTABLE_RE = re.compile(r"^[\x20-\x7e\u00a0-\uffff]+$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T|^\d{10}$|^\d{13}$")


def _any_valid_pid(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        for key in row:
            if _PID_RE.match(key) and isinstance(row.get(key), (int, float, str)):
                return True
    return False


def _has_pid4_system(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        for key in row:
            if _PID_RE.match(key) and str(row.get(key)) in ("4", "0x4"):
                name = str(row.get("ImageFileName", "") or row.get("Name", "") or "")
                if "ystem" in name or "System" in name or name == "System":
                    return True
    return False


def _printable_name_ratio(rows: list[dict[str, Any]]) -> float:
    name_keys = {"ImageFileName", "Name", "name", "ProcessName", "process_name"}
    total = 0
    printable = 0
    for row in rows:
        for key in name_keys:
            val = row.get(key)
            if isinstance(val, str) and val.strip():
                total += 1
                if _PRINTABLE_RE.match(val):
                    printable += 1
    return 1.0 if total == 0 else printable / total


def _malformed_row_ratio(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 1.0
    malformed = 0
    for row in rows:
        keys = list(row.keys())
        if len(keys) == 0:
            malformed += 1
            continue
        values = list(row.values())
        if not any(isinstance(v, (str, int, float)) and v for v in values):
            malformed += 1
    return malformed / len(rows)


def _timestamps_parseable(rows: list[dict[str, Any]]) -> bool:
    ts_keys = {"CreateTime", "ExitTime", "start_time", "end_time", "Timestamp", "timestamp"}
    for row in rows:
        for key in ts_keys:
            val = row.get(key)
            if isinstance(val, str) and _TIMESTAMP_RE.match(val):
                return True
    return False


def _offsets_in_range(rows: list[dict[str, Any]]) -> bool:
    offset_keys = {"Offset", "offset", "VirtualOffset", "PhysicalOffset", "Addr", "addr", "Offset(V)", "Offset(P)"}
    for row in rows:
        for key in offset_keys:
            val = row.get(key)
            if isinstance(val, (int, float)) and val > 0:
                return True
            if isinstance(val, str) and val.startswith(("0x", "0X")):
                return True
    return False
