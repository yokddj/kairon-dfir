from __future__ import annotations

from datetime import datetime, timezone
from importlib import metadata
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Any

from redis import Redis

from app.core.config import get_settings


CAPABILITY_PREFIX = "kairon:memory-worker:"
CAPABILITY_TTL_SECONDS = 90
MAX_CAPTURE_BYTES = 8192


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _version_from_help(output: str) -> str | None:
    for line in output[:MAX_CAPTURE_BYTES].splitlines():
        stripped = line.strip()
        if stripped and ("volatility" in stripped.lower() or "version" in stripped.lower()):
            return stripped[:160]
    return None


def _installed_volatility_version() -> str | None:
    try:
        version = metadata.version("volatility3")
    except metadata.PackageNotFoundError:
        return None
    return f"Volatility 3 Framework {version}" if version else None


def build_memory_worker_capability() -> dict[str, Any]:
    settings = get_settings()
    executable = shutil.which(settings.volatility3_command) if settings.volatility3_command else None
    healthy = False
    version = None
    error_code = None
    if executable:
        try:
            result = subprocess.run(
                [executable, "--help"],
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=max(1, int(settings.memory_backend_check_timeout_seconds)),
            )
            output = f"{result.stdout or ''}\n{result.stderr or ''}"[:MAX_CAPTURE_BYTES]
            healthy = result.returncode == 0
            version = _installed_volatility_version() or _version_from_help(output)
            if not healthy:
                error_code = "VOLATILITY_HELP_FAILED"
        except subprocess.TimeoutExpired:
            error_code = "VOLATILITY_HELP_TIMEOUT"
        except OSError:
            error_code = "VOLATILITY_HELP_FAILED"
    else:
        error_code = "VOLATILITY_NOT_FOUND"

    return {
        "worker_type": "memory",
        "worker_identifier": os.environ.get("KAIRON_WORKER_ID") or socket.gethostname(),
        "application_commit": os.environ.get("KAIRON_COMMIT", "unknown"),
        "volatility_executable": "vol" if executable else None,
        "volatility_version": version,
        "supported_profiles": settings.allowed_memory_profiles,
        "supported_plugins": settings.allowed_memory_plugins,
        "queue": settings.memory_queue_name,
        "healthy": healthy,
        "execution_enabled": bool(settings.memory_analysis_enabled and settings.memory_allow_external_tool_execution),
        "symbol_network_enabled": bool(settings.memory_symbol_network_access_enabled),
        "last_heartbeat": _utc_iso(),
        "error_code": error_code,
    }


def capability_key(identifier: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in identifier)[:120]
    return f"{CAPABILITY_PREFIX}{safe or 'unknown'}"


def publish_memory_worker_capability(redis_conn: Redis, capability: dict[str, Any] | None = None, *, ttl_seconds: int = CAPABILITY_TTL_SECONDS) -> dict[str, Any]:
    payload = dict(capability or build_memory_worker_capability())
    payload["last_heartbeat"] = _utc_iso()
    key = capability_key(str(payload.get("worker_identifier") or "unknown"))
    redis_conn.setex(key, max(10, int(ttl_seconds)), json.dumps(payload, sort_keys=True))
    return payload


def start_memory_worker_heartbeat(redis_conn: Redis, *, interval_seconds: int = 30) -> threading.Thread:
    def _loop() -> None:
        while True:
            try:
                publish_memory_worker_capability(redis_conn)
            except Exception:
                pass
            time.sleep(max(5, int(interval_seconds)))

    thread = threading.Thread(target=_loop, name="memory-worker-heartbeat", daemon=True)
    thread.start()
    return thread


def list_memory_worker_capabilities(redis_conn: Redis) -> list[dict[str, Any]]:
    capabilities: list[dict[str, Any]] = []
    for raw_key in redis_conn.scan_iter(f"{CAPABILITY_PREFIX}*"):
        value = redis_conn.get(raw_key)
        if not value:
            continue
        try:
            decoded = json.loads(value.decode("utf-8") if isinstance(value, bytes) else str(value))
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            capabilities.append(decoded)
    return capabilities
