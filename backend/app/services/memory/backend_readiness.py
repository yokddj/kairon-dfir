from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import shutil
import subprocess
import time

from app.core.config import get_settings


logger = logging.getLogger(__name__)

BACKEND_DISPLAY_NAMES = {
    "volatility3": "Volatility 3",
    "memprocfs": "MemProcFS",
}
MAX_CAPTURE_BYTES = 8192
MAX_VERSION_LENGTH = 160
SHELL_TOKEN_PATTERN = re.compile(r"[\s;&|`$<>\n\r]")
_CACHE: dict[str, object] = {"expires_at": 0.0, "overview": None}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clear_memory_backend_readiness_cache() -> None:
    _CACHE["expires_at"] = 0.0
    _CACHE["overview"] = None


def sanitize_backend_error(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "Backend readiness check failed."
    text = text.replace("\r", " ").replace("\n", " ")
    text = re.sub(r"/[A-Za-z0-9._~+\-/:@%]+", "[path]", text)
    text = re.sub(r"([A-Za-z]:\\\\)[^ ]+", r"\1[path]", text)
    text = re.sub(r"\s+", " ", text)
    return text[:MAX_VERSION_LENGTH]


def _status(
    *,
    backend: str,
    configured: bool,
    executable_found: bool,
    execution_allowed: bool,
    available: bool,
    ready: bool,
    status: str,
    message: str,
    checked_at: datetime,
    version: str | None = None,
    command_display: str | None = None,
    error_code: str | None = None,
) -> dict:
    return {
        "backend": backend,
        "display_name": BACKEND_DISPLAY_NAMES[backend],
        "configured": configured,
        "executable_found": executable_found,
        "execution_allowed": execution_allowed,
        "available": available,
        "ready": ready,
        "version": version,
        "command_display": command_display,
        "status": status,
        "message": message,
        "checked_at": checked_at,
        "error_code": error_code,
    }


def _command_display(command: str) -> str | None:
    value = str(command or "").strip()
    if not value:
        return None
    return Path(value).name


def resolve_configured_executable(command: str | None) -> tuple[bool, str | None, str | None, str | None]:
    value = str(command or "").strip()
    if not value:
        return False, None, None, "not_configured"
    if SHELL_TOKEN_PATTERN.search(value):
        return False, None, _command_display(value), "invalid_command"
    candidate = Path(value)
    if candidate.is_absolute():
        if candidate.is_file():
            return True, str(candidate), candidate.name, None
        return True, None, candidate.name, "not_found"
    if "/" in value or "\\" in value:
        return False, None, _command_display(value), "invalid_command"
    resolved = shutil.which(value)
    return True, resolved, value, None if resolved else "not_found"


def _extract_version(output: str) -> str | None:
    bounded = output[:MAX_CAPTURE_BYTES]
    for line in bounded.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if "volatility" in lower or "memprocfs" in lower or "version" in lower:
            return stripped[:MAX_VERSION_LENGTH]
    return None


def _harmless_help_check(backend: str, executable: str, timeout_seconds: int) -> tuple[bool, str | None, str | None]:
    args = [executable, "--help"]
    logger.info("memory backend harmless check started", extra={"backend": backend})
    try:
        result = subprocess.run(
            args,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_seconds)),
        )
    except subprocess.TimeoutExpired:
        logger.warning("memory backend harmless check timed out", extra={"backend": backend})
        return False, None, "check_timeout"
    except OSError as exc:
        logger.warning("memory backend harmless check failed to start", extra={"backend": backend, "error": sanitize_backend_error(exc)})
        return False, None, "check_failed"

    output = f"{result.stdout or ''}\n{result.stderr or ''}"[:MAX_CAPTURE_BYTES]
    if result.returncode != 0:
        logger.warning("memory backend harmless check failed", extra={"backend": backend, "returncode": result.returncode})
        return False, None, "check_failed"
    logger.info("memory backend harmless check succeeded", extra={"backend": backend})
    return True, _extract_version(output), None


def _check_backend(backend: str, command: str | None) -> dict:
    settings = get_settings()
    checked_at = _utc_now()
    execution_allowed = bool(settings.memory_allow_external_tool_execution)
    logger.info("memory backend readiness check started", extra={"backend": backend})

    configured, executable, command_display, config_error = resolve_configured_executable(command)
    if not configured:
        status = "not_configured" if config_error == "not_configured" else "blocked"
        message = (
            f"{BACKEND_DISPLAY_NAMES[backend]} is not configured."
            if config_error == "not_configured"
            else f"{BACKEND_DISPLAY_NAMES[backend]} command configuration is invalid. Configure only an executable name or absolute executable path."
        )
        logger.info("memory backend not configured", extra={"backend": backend, "status": status})
        return _status(
            backend=backend,
            configured=False,
            executable_found=False,
            execution_allowed=execution_allowed,
            available=False,
            ready=False,
            status=status,
            message=message,
            checked_at=checked_at,
            command_display=command_display,
            error_code=config_error,
        )

    if not executable:
        logger.info("memory backend executable not found", extra={"backend": backend})
        return _status(
            backend=backend,
            configured=True,
            executable_found=False,
            execution_allowed=execution_allowed,
            available=False,
            ready=False,
            status="not_found",
            message=f"{BACKEND_DISPLAY_NAMES[backend]} is configured but was not found in the server environment.",
            checked_at=checked_at,
            command_display=command_display,
            error_code="executable_not_found",
        )

    logger.info("memory backend executable found", extra={"backend": backend, "command": command_display})
    ok, version, check_error = _harmless_help_check(backend, executable, settings.memory_backend_check_timeout_seconds)
    if not ok:
        return _status(
            backend=backend,
            configured=True,
            executable_found=True,
            execution_allowed=execution_allowed,
            available=False,
            ready=False,
            status="check_failed",
            message=f"{BACKEND_DISPLAY_NAMES[backend]} was found, but its harmless readiness check failed.",
            checked_at=checked_at,
            command_display=command_display,
            error_code=check_error,
        )

    feature_enabled = bool(settings.memory_analysis_enabled)
    ready = feature_enabled and execution_allowed
    if not feature_enabled:
        status = "disabled"
        message = "Memory Analysis is disabled by server configuration."
    elif not execution_allowed:
        status = "blocked"
        message = f"{BACKEND_DISPLAY_NAMES[backend]} is detected, but external memory-tool execution is disabled."
    else:
        status = "available"
        message = f"{BACKEND_DISPLAY_NAMES[backend]} is available and administratively enabled for future memory analysis."

    logger.info("memory backend readiness state", extra={"backend": backend, "status": status, "ready": ready})
    return _status(
        backend=backend,
        configured=True,
        executable_found=True,
        execution_allowed=execution_allowed,
        available=True,
        ready=ready,
        status=status,
        message=message,
        checked_at=checked_at,
        version=version,
        command_display=command_display,
    )


def check_volatility3_backend() -> dict:
    return _check_backend("volatility3", get_settings().volatility3_command)


def check_memprocfs_backend() -> dict:
    return _check_backend("memprocfs", get_settings().memprocfs_command)


def _build_overview() -> dict:
    settings = get_settings()
    backends = [check_volatility3_backend(), check_memprocfs_backend()]
    ready_count = len([backend for backend in backends if backend["ready"]])
    if ready_count:
        message = f"{ready_count} memory-analysis backend is ready for a future sprint."
    elif any(backend["available"] for backend in backends):
        message = "External memory-analysis backends are available but not administratively ready."
    else:
        message = "No external memory-analysis backend is ready. Disk-only workflows remain fully available."
    return {
        "memory_analysis_enabled": bool(settings.memory_analysis_enabled),
        "external_execution_allowed": bool(settings.memory_allow_external_tool_execution),
        "backends": backends,
        "preferred_backend": settings.preferred_memory_backend,
        "ready_backend_count": ready_count,
        "message": message,
    }


def get_memory_backend_overview() -> dict:
    settings = get_settings()
    now = time.monotonic()
    cached = _CACHE.get("overview")
    if cached is not None and now < float(_CACHE.get("expires_at") or 0):
        return cached  # type: ignore[return-value]
    overview = _build_overview()
    _CACHE["overview"] = overview
    _CACHE["expires_at"] = now + max(0, int(settings.memory_backend_status_cache_seconds))
    return overview
