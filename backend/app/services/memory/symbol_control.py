from __future__ import annotations

import os
import stat
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.memory import MemoryScanRun


NETWORK_ISOLATION_REQUIRED = "SYMBOL_ACQUISITION_NETWORK_ISOLATION_REQUIRED"
ADMIN_AUTH_REQUIRED = "SYMBOL_ACQUISITION_ADMIN_AUTH_REQUIRED"


def acquisition_gate(settings=None) -> tuple[bool, str | None, str]:
    settings = settings or get_settings()
    if settings.memory_symbol_execution_mode != "managed_download" or not settings.memory_symbol_managed_download_enabled:
        return False, "SYMBOL_ACQUISITION_DISABLED", "Managed symbol acquisition is disabled. Offline-only mode remains active."
    if not settings.memory_symbol_network_isolation_ready:
        return False, NETWORK_ISOLATION_REQUIRED, "Managed symbol acquisition is unavailable until restricted egress is verified by an administrator."
    if not settings.memory_symbol_admin_authorization_enforced:
        return False, ADMIN_AUTH_REQUIRED, "Managed symbol acquisition is unavailable until administrator authorization is enforced."
    if not settings.memory_symbol_hosts:
        return False, "SYMBOL_SOURCE_NOT_ALLOWED", "No reviewed official symbol destinations are configured."
    return True, None, "Managed symbol acquisition is available."


def latest_symbols_failure(db: Session, case_id: str, evidence_id: str) -> MemoryScanRun | None:
    run = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id, MemoryScanRun.evidence_id == evidence_id)
        .order_by(MemoryScanRun.created_at.desc())
        .first()
    )
    return run if run is not None and (run.error_log or {}).get("code") == "SYMBOLS_UNAVAILABLE" else None


def evidence_symbol_readiness(db: Session, case_id: str, evidence_id: str, *, settings=None) -> dict[str, object]:
    settings = settings or get_settings()
    failed_run = latest_symbols_failure(db, case_id, evidence_id)
    available, _, _ = acquisition_gate(settings)
    symbols_required = failed_run is not None
    return {
        "symbols_required": symbols_required,
        "symbol_identifier_present": False,
        "acquisition_available": bool(available and symbols_required),
        "acquisition_status": "symbols_required" if symbols_required else None,
        "can_analyze_offline": not symbols_required,
    }


def _cache_usage(root: Path) -> tuple[int, int]:
    total = count = 0
    try:
        root_stat = root.lstat()
    except OSError:
        return 0, 0
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        return 0, 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(current) / name).is_symlink()]
        for name in files:
            candidate = Path(current) / name
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and not candidate.is_symlink():
                total += metadata.st_size
                if name.lower().endswith((".json", ".json.xz", ".isf")):
                    count += 1
    return total, count


def cache_status(*, settings=None) -> dict[str, object]:
    settings = settings or get_settings()
    total, symbol_count = _cache_usage(settings.memory_symbol_cache_path)
    maximum = max(0, int(settings.memory_symbol_cache_max_bytes))
    available, error_code, message = acquisition_gate(settings)
    return {
        "mode": settings.memory_symbol_execution_mode,
        "acquisition_enabled": available,
        "network_isolation_ready": bool(settings.memory_symbol_network_isolation_ready),
        "administrator_authorization_available": bool(settings.memory_symbol_admin_authorization_enforced),
        "total_bytes": total,
        "configured_max_bytes": maximum,
        "available_bytes": max(0, maximum - total),
        "symbol_count": symbol_count,
        "active_requests": 0,
        "failed_requests": 0,
        "last_success_at": None,
        "error_code": error_code,
        "message": message,
    }
