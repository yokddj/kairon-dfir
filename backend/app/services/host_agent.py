"""The backend's side of the optional host agent (scripts/kairon-agent.sh).

The backend never runs Docker. To restart or upgrade Kairon it writes a request file into
/app/agent/requests/ (./agent on the host, mounted by the backend only); the agent on the host
carries it out and writes status/<id>.json and logs/<id>.log, and heartbeat.json every few
seconds. The UI offers the actions only while that heartbeat is fresh.

Neither action is accepted while a job is queued or running in Kairon's queues (an upgrade or a
restart would kill it); the agent checks again before it acts, through ``active-jobs`` below.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AGENT_DIR = Path(os.getenv("KAIRON_AGENT_DIR", "/app/agent"))
HEARTBEAT_MAX_AGE_SECONDS = 30
ACTIONS = ("restart", "upgrade")
SERVICES = ("backend", "worker", "memory-worker")
LOG_TAIL_LINES = 60
_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[a-f0-9]{8,32}$")
_FINAL_STATES = {"done", "failed", "refused"}


class HostAgentError(ValueError):
    """A request the backend refuses, with the reason for the administrator."""


def _dirs() -> tuple[Path, Path, Path]:
    return AGENT_DIR / "requests", AGENT_DIR / "status", AGENT_DIR / "logs"


def agent_alive(now: float | None = None) -> dict[str, Any]:
    path = AGENT_DIR / "heartbeat.json"
    try:
        beat = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False}
    seen_at = float(beat.get("seen_at") or 0)
    age = (now if now is not None else time.time()) - seen_at
    return {
        "available": 0 <= age <= HEARTBEAT_MAX_AGE_SECONDS,
        "seen_seconds_ago": int(age) if age >= 0 else None,
        "busy": str(beat.get("busy") or "") or None,
    }


def _queue_names() -> list[str]:
    from app.core.config import get_settings

    settings = get_settings()
    names = ["dfir-ingest", "dfir-rules", "dfir-analysis"]
    for attribute in ("memory_queue_name", "memory_experimental_queue_name", "memory_symbol_queue_name", "memory_native_probe_queue_name"):
        value = getattr(settings, attribute, None)
        if value and value not in names:
            names.append(str(value))
    return names


def active_jobs() -> dict[str, Any]:
    """Jobs queued or running, per queue. Raises when Redis cannot be read: unknown is not none."""
    from redis import Redis
    from rq import Queue
    from rq.registry import StartedJobRegistry

    from app.core.config import get_settings

    connection = Redis.from_url(get_settings().redis_url, socket_connect_timeout=3, socket_timeout=5)
    queues: dict[str, int] = {}
    for name in _queue_names():
        count = Queue(name, connection=connection).count + len(StartedJobRegistry(name, connection=connection))
        if count:
            queues[name] = count
    return {"total": sum(queues.values()), "queues": queues}


def _read_status(request_id: str) -> dict[str, Any] | None:
    try:
        return json.loads((_dirs()[1] / f"{request_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_request(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def _log_tail(request_id: str) -> str:
    try:
        lines = (_dirs()[2] / f"{request_id}.log").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-LOG_TAIL_LINES:])


def list_requests(limit: int = 5) -> list[dict[str, Any]]:
    requests_dir = _dirs()[0]
    try:
        files = sorted((path for path in requests_dir.glob("*.req") if _ID_RE.match(path.stem)), reverse=True)[:limit]
    except OSError:
        return []
    items = []
    for path in files:
        request = _read_request(path)
        status = _read_status(path.stem) or {"state": "queued", "step": None, "message": "Waiting for the host agent."}
        items.append(
            {
                "id": path.stem,
                "action": request.get("action"),
                "services": request.get("services", "").split() if request.get("services") else [],
                "requested_by": request.get("requested_by"),
                "requested_at": request.get("requested_at"),
                **{key: status.get(key) for key in ("state", "step", "message", "exit_code", "started_at", "finished_at")},
                "log_tail": _log_tail(path.stem),
            }
        )
    return items


def state() -> dict[str, Any]:
    try:
        jobs: dict[str, Any] | None = active_jobs()
    except Exception:  # noqa: BLE001 - shown as unknown
        jobs = None
    return {**agent_alive(), "active_jobs": jobs, "requests": list_requests()}


def create_request(action: str, services: list[str] | None, requested_by: str) -> dict[str, Any]:
    if action not in ACTIONS:
        raise HostAgentError(f"Unknown action: {action}")
    chosen: list[str] = []
    if action == "restart":
        chosen = [service for service in SERVICES if service in set(services or [])]
        unknown = sorted(set(services or []) - set(SERVICES))
        if unknown or not chosen:
            raise HostAgentError(f"Services to restart must be among: {', '.join(SERVICES)}")
    if not agent_alive()["available"]:
        raise HostAgentError("The host agent is not running on the server.")
    try:
        jobs = active_jobs()
    except Exception as exc:  # noqa: BLE001
        raise HostAgentError("Could not check Kairon's running jobs; nothing was requested.") from exc
    if jobs["total"]:
        raise HostAgentError(f"{jobs['total']} job(s) are queued or running; try again when they finish.")
    pending = [item for item in list_requests(limit=20) if item.get("state") not in _FINAL_STATES]
    if pending:
        raise HostAgentError("Another request is still waiting or running.")
    requests_dir = _dirs()[0]
    requests_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    request_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(6)}"
    safe_actor = re.sub(r"[^A-Za-z0-9_.@-]", "_", requested_by or "admin")[:64]
    lines = [f"id={request_id}", f"action={action}", f"requested_by={safe_actor}", f"requested_at={now.isoformat().replace('+00:00', 'Z')}"]
    if chosen:
        lines.append(f"services={' '.join(chosen)}")
    temporary = requests_dir / f".{request_id}.tmp"
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(requests_dir / f"{request_id}.req")
    return next(item for item in list_requests(limit=20) if item["id"] == request_id)


def main(argv: list[str]) -> int:
    if argv[1:] == ["active-jobs"]:
        print(active_jobs()["total"])
        return 0
    print("Usage: python -m app.services.host_agent active-jobs", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
