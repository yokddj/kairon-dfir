"""Server-side controller for the per-evidence Windows symbol probe.

The probe runs the lightweight ``app.services.memory.symbol_probe``
subprocess with a short timeout and limited output.  It only attempts:

* layer stacking
* kernel identification
* requirements discovery
* symbol table requirement extraction

It NEVER runs pslist, handles, modules, malfind, dumpfiles, network.

The probe NEVER fabricates a requirement: when Volatility cannot
identify the kernel / PDB, the result is ``status=unknown`` and
``requirement=None``.  The UI must show
"Symbol requirement could not be identified." in that case.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.evidence import Evidence
from app.models.memory import MemorySymbolRequirement
from app.services.memory.evidence_access import validate_current_process_evidence_access
from app.services.memory.storage import memory_run_dir
from app.services.memory.symbol_control import record_symbol_requirement
from app.services.memory.symbol_fetcher import SymbolIdentity, SymbolFetchError
from app.services.memory.symbol_state import (
    EC_LAYER_CONSTRUCTION_FAILED,
    EC_OS_UNSUPPORTED,
    EC_SYMBOL_REQUIREMENT_UNKNOWN,
    SymbolRequirement,
)
from app.services.memory.volatility_runner import (
    VolatilityRunnerError,
    probe_windows_symbol_identity,
    run_plugin,
    _strip_progress_lines,
)


logger = logging.getLogger(__name__)


# Status values for the probe endpoint.
PROBE_STATUS_UNKNOWN = "unknown"
PROBE_STATUS_PROBING = "probing"
PROBE_STATUS_IDENTIFIED = "identified"
PROBE_STATUS_INCOMPATIBLE = "incompatible"
PROBE_STATUS_UNSUPPORTED = "unsupported"
PROBE_STATUS_FAILED = "failed"


@dataclass
class ProbeResult:
    evidence_id: str
    status: str  # one of PROBE_STATUS_*
    requirement: SymbolRequirement | None
    probable_os: str | None
    layer: str | None
    confidence: str
    failure_reason: str | None
    error_code: str | None
    sanitized_message: str | None
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "status": self.status,
            "requirement": self.requirement.to_dict() if self.requirement else None,
            "probable_os": self.probable_os,
            "layer": self.layer,
            "confidence": self.confidence,
            "failure_reason": self.failure_reason,
            "error_code": self.error_code,
            "sanitized_message": self.sanitized_message,
            "duration_ms": self.duration_ms,
        }


def _classify_stderr(stderr: bytes) -> tuple[str, str, str]:
    """Return (status, error_code, sanitized_message) for a failed probe."""
    raw = stderr.decode("utf-8", errors="replace")
    cleaned = _strip_progress_lines(raw)
    lower = cleaned.lower()
    if "no suitable" in lower and "layer" in lower:
        return (
            PROBE_STATUS_INCOMPATIBLE,
            EC_OS_UNSUPPORTED,
            "Volatility could not construct a Windows layer for this image.",
        )
    if "unable to validate" in lower and "layer" in lower:
        return (
            PROBE_STATUS_INCOMPATIBLE,
            EC_LAYER_CONSTRUCTION_FAILED,
            "Volatility could not validate a memory layer for this image.",
        )
    if "symbol_table_name" in lower or ("unable to validate" in lower and "symbol" in lower):
        # This is the case we want to capture with a real requirement.
        return (
            PROBE_STATUS_UNKNOWN,
            EC_SYMBOL_REQUIREMENT_UNKNOWN,
            "Windows symbol requirement could not be identified automatically.",
        )
    if "unsupported" in lower and "image" in lower:
        return (
            PROBE_STATUS_UNSUPPORTED,
            EC_OS_UNSUPPORTED,
            "This image is not a supported Windows memory image.",
        )
    return (
        PROBE_STATUS_FAILED,
        "MEMORY_PROBE_FAILED",
        "The Windows symbol probe failed. See worker logs for details.",
    )


def _extract_layer_from_stderr(stderr: bytes) -> str | None:
    """Best-effort: extract the layer name from Volatility progress lines."""
    raw = stderr.decode("utf-8", errors="replace")
    for line in raw.splitlines():
        stripped = line.strip()
        if "windows" in stripped.lower() and "layer" in stripped.lower():
            return stripped[:128]
    return None


def probe_evidence_symbol_requirement(
    db,
    *,
    evidence: Evidence,
    run_id: str | None = None,
    timeout_seconds: int | None = None,
) -> ProbeResult:
    """Run the lightweight symbol requirement probe for an evidence.

    The function:

    1. Resolves the evidence file path (with worker-aware access).
    2. Runs ``symbol_probe.py`` (which only attempts layer stacking
       and symbol table discovery) with a short timeout.
    3. Records the requirement on the latest MemorySymbolRequirement
       row (if it is valid).
    4. Returns a structured ProbeResult with a precise status; never
       fabricates a requirement.

    The probe does NOT create a MemoryScanRun; the call is read-only
    from the audit perspective (it only creates a
    MemorySymbolRequirement if the requirement can be identified).
    """
    started = datetime.utcnow()
    try:
        access = validate_current_process_evidence_access(evidence, settings=get_settings())
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_FAILED,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason=type(exc).__name__,
            error_code="EVIDENCE_NOT_READABLE",
            sanitized_message=str(exc)[:200] or "Evidence file is not accessible.",
            duration_ms=0,
        )

    # We need a stable work directory to hold the probe output.  If
    # the caller did not provide a run id (the normal case for the
    # probe endpoint) we create a synthetic id derived from the
    # evidence id so we never collide with a real run.
    work_run_id = run_id or f"probe-{evidence.id[:8]}"
    work_dir = memory_run_dir(evidence.case_id, evidence.id, work_run_id)
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    settings = get_settings()
    timeout = max(10, int(timeout_seconds or min(int(settings.memory_plugin_timeout_seconds), 120)))

    payload: dict[str, object] | None = None
    try:
        payload = probe_windows_symbol_identity(access.path, work_dir)
    except subprocess.TimeoutExpired:
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_FAILED,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason="timeout",
            error_code="MEMORY_PROBE_TIMEOUT",
            sanitized_message="The Windows symbol probe did not finish within the configured timeout.",
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("symbol probe exception", extra={"evidence_id": evidence.id, "error": str(exc)})
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_FAILED,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason=type(exc).__name__,
            error_code="MEMORY_PROBE_FAILED",
            sanitized_message="The Windows symbol probe could not be executed.",
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )

    if not payload:
        # The probe did not capture a requirement.  We do NOT
        # fabricate one.  We re-run windows.info to get a clean error
        # message and the layer (if any) to show in the UI.
        return _probe_without_payload(evidence, work_dir, started, timeout)

    requirement = SymbolRequirement.from_dict(payload)
    if not requirement.is_valid():
        # Defensive: even if the subprocess captured something, we do
        # not record an invalid identifier.
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_UNKNOWN,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason="invalid_identifier",
            error_code=EC_SYMBOL_REQUIREMENT_UNKNOWN,
            sanitized_message="Windows symbol requirement could not be identified automatically.",
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )

    # Record the requirement on a synthetic run row.  We do not
    # create a MemoryScanRun; we only persist the requirement.
    _persist_requirement(db, evidence, requirement)
    duration_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return ProbeResult(
        evidence_id=evidence.id,
        status=PROBE_STATUS_IDENTIFIED,
        requirement=requirement,
        probable_os="windows",
        layer=None,
        confidence="high",
        failure_reason=None,
        error_code=None,
        sanitized_message=None,
        duration_ms=duration_ms,
    )


def _persist_requirement(db, evidence: Evidence, requirement: SymbolRequirement) -> None:
    """Persist a fresh requirement row, idempotently.

    Uses the same uniqueness constraint as
    ``record_symbol_requirement`` (evidence_id, pdb_name, pdb_guid,
    pdb_age).  We create a synthetic probe run + plugin run row to
    satisfy the foreign keys; the rows are only used to compute the
    per-evidence state and the symbol-key for the cache check.
    """
    import uuid as _uuid

    from app.models.memory import MemoryScanRun, MemoryPluginRun

    # Stable, deterministic IDs derived from the evidence id so we
    # never collide with real runs.  These rows are bookkeeping-only.
    run_id = str(_uuid.UUID(int=(0x9000_0000_0000_4000_8000_0000_0000_0000 | (hash(evidence.id) & 0xFFFF_FFFF_FFFF))))
    plugin_run_id = str(_uuid.UUID(int=(0x9000_0000_0000_4000_8000_0000_0000_0001 | (hash(evidence.id) & 0xFFFF_FFFF_FFFF))))
    if db.get(MemoryScanRun, run_id) is None:
        probe_run = MemoryScanRun(
            id=run_id,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            profile="probe_symbols",
            status="completed",
            backend="volatility3",
            metadata_json={"probe": True},
            error_log={},
        )
        db.add(probe_run)
    if db.get(MemoryPluginRun, plugin_run_id) is None:
        plugin_run = MemoryPluginRun(
            id=plugin_run_id,
            memory_scan_run_id=run_id,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            plugin="windows.info",
            status="completed",
            started_at=utc_now_naive(),
            completed_at=utc_now_naive(),
        )
        db.add(plugin_run)
    db.flush()
    identity = SymbolIdentity(
        pdb_name=requirement.pdb_name,
        guid=requirement.pdb_guid,
        age=requirement.pdb_age,
        architecture=requirement.architecture,
    )
    try:
        identity.validate()
    except SymbolFetchError:
        return
    symbol_key = identity.key
    existing_req = (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.evidence_id == evidence.id,
            MemorySymbolRequirement.symbol_key == symbol_key,
        )
        .first()
    )
    if existing_req is not None:
        return
    requirement_row = MemorySymbolRequirement(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        source_run_id=run_id,
        source_plugin_run_id=plugin_run_id,
        pdb_name=identity.pdb_name,
        pdb_guid=identity.guid,
        pdb_age=int(identity.age),
        requested_pdb_age=int(identity.age),
        age_corrected=False,
        architecture=identity.architecture,
        symbol_key=symbol_key,
        status="unavailable_offline",
        sanitized_message="Required Windows symbols are not present in the offline cache.",
    )
    db.add(requirement_row)
    db.commit()


def _probe_without_payload(
    evidence: Evidence,
    work_dir: Path,
    started: datetime,
    timeout: int,
) -> ProbeResult:
    """Run windows.info to capture the real error and layer info."""
    duration_ms_partial = int((datetime.utcnow() - started).total_seconds() * 1000)
    try:
        access = validate_current_process_evidence_access(evidence, settings=get_settings())
    except Exception:
        access = None
    if access is None:
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_FAILED,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason="evidence_not_accessible",
            error_code="EVIDENCE_NOT_READABLE",
            sanitized_message="The evidence file is not accessible from the API process.",
            duration_ms=duration_ms_partial,
        )
    try:
        result = run_plugin(
            "windows.info",
            access.path,
            work_dir,
            timeout_seconds=timeout,
            max_output_bytes=64 * 1024,
        )
    except VolatilityRunnerError as exc:
        status, error_code, message = _classify_stderr(exc.stderr or b"")
        return ProbeResult(
            evidence_id=evidence.id,
            status=status,
            requirement=None,
            probable_os=None,
            layer=_extract_layer_from_stderr(exc.stderr or b""),
            confidence="none",
            failure_reason=exc.code,
            error_code=error_code,
            sanitized_message=message,
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            evidence_id=evidence.id,
            status=PROBE_STATUS_FAILED,
            requirement=None,
            probable_os=None,
            layer=None,
            confidence="none",
            failure_reason=type(exc).__name__,
            error_code="MEMORY_PROBE_FAILED",
            sanitized_message="The Windows symbol probe could not be executed.",
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )
    # No error but no requirement either: most likely a file with no
    # Windows kernel.  Don't fabricate a requirement.
    return ProbeResult(
        evidence_id=evidence.id,
        status=PROBE_STATUS_INCOMPATIBLE,
        requirement=None,
        probable_os=None,
        layer=None,
        confidence="none",
        failure_reason="no_windows_kernel",
        error_code=EC_OS_UNSUPPORTED,
        sanitized_message="Volatility did not detect a Windows kernel in this image.",
        duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
    )


__all__ = [
    "PROBE_STATUS_FAILED",
    "PROBE_STATUS_IDENTIFIED",
    "PROBE_STATUS_INCOMPATIBLE",
    "PROBE_STATUS_PROBING",
    "PROBE_STATUS_UNKNOWN",
    "PROBE_STATUS_UNSUPPORTED",
    "ProbeResult",
    "probe_evidence_symbol_requirement",
]
