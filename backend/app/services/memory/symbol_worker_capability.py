from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import threading
import time

from redis import Redis

from app.core.config import get_settings


PREFIX = "kairon:symbol-fetcher:"
TTL_SECONDS = 90


def build_capability() -> dict[str, object]:
    settings = get_settings()
    root = settings.memory_symbol_cache_path
    writable = root.exists() and root.is_dir() and os.access(root, os.W_OK | os.X_OK)
    return {
        "worker_type": "memory-symbols",
        "worker_identifier": os.environ.get("KAIRON_WORKER_ID", "symbol-fetcher"),
        "queue": settings.memory_symbol_queue_name,
        "healthy": writable,
        "cache_writable": writable,
        "network_isolation_ready": bool(settings.memory_symbol_network_isolation_ready),
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
    }


def publish(redis_conn: Redis, *, ttl_seconds: int = TTL_SECONDS) -> dict[str, object]:
    payload = build_capability()
    identifier = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(payload["worker_identifier"]))[:120]
    redis_conn.setex(f"{PREFIX}{identifier or 'unknown'}", max(10, ttl_seconds), json.dumps(payload, sort_keys=True))
    return payload


def start_heartbeat(redis_conn: Redis, *, interval_seconds: int = 30) -> threading.Thread:
    def loop() -> None:
        while True:
            try:
                publish(redis_conn)
            except Exception:
                pass
            time.sleep(max(5, interval_seconds))

    thread = threading.Thread(target=loop, name="symbol-fetcher-heartbeat", daemon=True)
    thread.start()
    return thread


def fetcher_online(redis_conn: Redis) -> bool:
    for key in redis_conn.scan_iter(f"{PREFIX}*"):
        value = redis_conn.get(key)
        if not value:
            continue
        try:
            payload = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            continue
        if payload.get("healthy") and payload.get("queue") == get_settings().memory_symbol_queue_name:
            return True
    return False
