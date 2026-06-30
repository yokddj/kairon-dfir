from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from redis import Redis

from app.core.config import get_settings
from app.services.memory.worker_capability import list_memory_worker_capabilities


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
    extra: dict | None = None,
) -> dict:
    payload = {
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
    if extra:
        payload.update(extra)
    return payload


def _dedicated_worker_status(command: str | None) -> dict:
    settings = get_settings()
    checked_at = _utc_now()
    queue_reachable = False
    capabilities: list[dict] = []
    try:
        redis_conn = Redis.from_url(settings.redis_url)
        redis_conn.ping()
        queue_reachable = True
        capabilities = list_memory_worker_capabilities(redis_conn)
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory worker capability check failed", extra={"error": sanitize_backend_error(exc)})

    healthy = [item for item in capabilities if item.get("healthy") and item.get("queue") == settings.memory_queue_name]
    selected = healthy[0] if healthy else (capabilities[0] if capabilities else {})
    worker_online = bool(healthy)
    execution_allowed = bool(settings.memory_allow_external_tool_execution)
    feature_enabled = bool(settings.memory_analysis_enabled)
    process_enabled = bool(settings.memory_process_profile_enabled)
    supported_profiles = [str(item) for item in selected.get("supported_profiles") or []]
    supported_plugins = [str(item) for item in selected.get("supported_plugins") or []]
    plugins = selected.get("plugins") if isinstance(selected.get("plugins"), dict) else {}
    backend_version = selected.get("volatility_version")
    available = worker_online and queue_reachable
    ready = bool(feature_enabled and execution_allowed and available)
    if not worker_online:
        status = "not_found" if queue_reachable else "check_failed"
        message = "Kairon is running without the optional memory worker. Disk analysis remains fully available."
        error_code = selected.get("error_code") or "memory_worker_offline"
    elif not feature_enabled:
        status = "disabled"
        message = "The isolated memory worker is online, but Memory Analysis is disabled by server configuration."
        error_code = None
    elif not execution_allowed:
        status = "blocked"
        message = "The isolated memory worker is online, but external memory-tool execution is disabled."
        error_code = None
    else:
        status = "available"
        message = f"The isolated memory worker is ready. Volatility 3 {backend_version or ''} is available for authorized memory analysis.".strip()
        error_code = None
    return _status(
        backend="volatility3",
        configured=bool(str(command or "").strip()),
        executable_found=worker_online,
        execution_allowed=execution_allowed,
        available=available,
        ready=ready,
        status=status,
        message=message,
        checked_at=checked_at,
        version=backend_version,
        command_display=_command_display(command or "vol"),
        error_code=error_code,
        extra={
            "execution_mode": "dedicated_worker",
            "dedicated_worker_required": bool(settings.memory_require_dedicated_worker),
            "dedicated_worker_online": worker_online,
            "queue": settings.memory_queue_name,
            "queue_reachable": queue_reachable,
            "backend_available": available,
            "backend_version": backend_version,
            "supported_profiles": supported_profiles or settings.allowed_memory_profiles,
            "supported_plugins": supported_plugins or settings.allowed_memory_plugins,
            "plugins": plugins,
            "symbol_network_enabled": bool(selected.get("symbol_network_enabled", settings.memory_symbol_network_access_enabled)),
            "process_profiles_enabled": process_enabled,
        },
    )


def _memory_worker_observation(settings) -> dict:
    try:
        redis_conn = Redis.from_url(settings.redis_url)
        redis_conn.ping()
        capabilities = list_memory_worker_capabilities(redis_conn)
    except Exception:
        return {
            "dedicated_worker_required": bool(settings.memory_require_dedicated_worker),
            "dedicated_worker_online": False,
            "queue": settings.memory_queue_name,
            "queue_reachable": False,
            "supported_profiles": [],
            "supported_plugins": [],
            "symbol_network_enabled": None,
        }
    healthy = [item for item in capabilities if item.get("healthy") and item.get("queue") == settings.memory_queue_name]
    selected = healthy[0] if healthy else (capabilities[0] if capabilities else {})
    return {
        "dedicated_worker_required": bool(settings.memory_require_dedicated_worker),
        "dedicated_worker_online": bool(healthy),
        "queue": settings.memory_queue_name,
        "queue_reachable": True,
        "backend_version": selected.get("volatility_version"),
        "supported_profiles": [str(item) for item in selected.get("supported_profiles") or []],
        "supported_plugins": [str(item) for item in selected.get("supported_plugins") or []],
        "plugins": selected.get("plugins") if isinstance(selected.get("plugins"), dict) else {},
        "symbol_network_enabled": selected.get("symbol_network_enabled") if selected else None,
    }


def _command_display(command: str) -> str | None:
    value = str(command or "").strip()
    if not value:
        return None
    try:
        parts = shlex.split(value)
    except ValueError:
        return Path(value).name
    if len(parts) >= 3 and parts[1] == "-m":
        return f"{Path(parts[0]).name} -m {parts[2]}"
    return Path(parts[0] if parts else value).name


def resolve_configured_command(command: str | None) -> tuple[bool, list[str] | None, str | None, str | None]:
    value = str(command or "").strip()
    if not value:
        return False, None, None, "not_configured"
    try:
        parts = shlex.split(value)
    except ValueError:
        return False, None, _command_display(value), "invalid_command"
    if not parts:
        return False, None, None, "not_configured"
    if any(re.search(r"[;&|`$<>\n\r]", part) for part in parts):
        return False, None, _command_display(value), "invalid_command"
    if len(parts) > 1 and not (len(parts) == 3 and parts[1] == "-m" and parts[2] == "volatility3"):
        return False, None, _command_display(value), "invalid_command"
    executable_name = parts[0]
    candidate = Path(executable_name)
    if candidate.is_absolute():
        if not candidate.is_file():
            return True, None, _command_display(value), "python_missing" if len(parts) == 3 else "not_found"
        executable = str(candidate)
    else:
        if "/" in executable_name or "\\" in executable_name:
            return False, None, _command_display(value), "invalid_command"
        resolved = shutil.which(executable_name)
        if not resolved:
            return True, None, _command_display(value), "python_missing" if len(parts) == 3 else "not_found"
        executable = resolved
    return True, [executable, *parts[1:]], _command_display(value), None


def resolve_configured_executable(command: str | None) -> tuple[bool, str | None, str | None, str | None]:
    configured, argv, display, error = resolve_configured_command(command)
    return configured, (argv[0] if argv else None), display, error


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


def _harmless_help_check(backend: str, argv_prefix: list[str], timeout_seconds: int) -> tuple[bool, str | None, str | None]:
    args = [*argv_prefix, "--help"]
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
        if "No module named volatility3" in output or "No module named 'volatility3'" in output:
            return False, None, "module_missing"
        return False, None, "check_failed"
    logger.info("memory backend harmless check succeeded", extra={"backend": backend})
    return True, _extract_version(output), None


def _check_backend(backend: str, command: str | None) -> dict:
    settings = get_settings()
    checked_at = _utc_now()
    execution_allowed = bool(settings.memory_allow_external_tool_execution)
    logger.info("memory backend readiness check started", extra={"backend": backend})
    if backend == "volatility3" and settings.memory_execution_mode == "dedicated_worker":
        return _dedicated_worker_status(command)
    worker_extra = _memory_worker_observation(settings) if backend == "volatility3" else {}

    configured, argv_prefix, command_display, config_error = resolve_configured_command(command)
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
        extra={"execution_mode": settings.memory_execution_mode, "queue": settings.memory_queue_name, **worker_extra},
        )

    if not argv_prefix:
        logger.info("memory backend executable not found", extra={"backend": backend})
        missing_code = "volatility_module_missing" if config_error == "module_missing" else "python_missing" if config_error == "python_missing" else "executable_not_found"
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
            error_code=missing_code,
            extra={"execution_mode": settings.memory_execution_mode, "queue": settings.memory_queue_name, **worker_extra},
        )

    logger.info("memory backend executable found", extra={"backend": backend, "command": command_display})
    ok, version, check_error = _harmless_help_check(backend, argv_prefix, settings.memory_backend_check_timeout_seconds)
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
            extra={"execution_mode": settings.memory_execution_mode, "queue": settings.memory_queue_name, **worker_extra},
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
        extra={"execution_mode": settings.memory_execution_mode, "queue": settings.memory_queue_name, "backend_available": True, "backend_version": version, **worker_extra},
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
