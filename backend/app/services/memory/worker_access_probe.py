"""Ask the memory worker whether it can really use a memory evidence.

Whether the worker can read an evidence file used to be predicted in the
backend from the file's owner, group and mode bits. That prediction is wrong
wherever the storage does not enforce ownership the way it reports it (e.g.
bind mounts that report root:root 0640 yet let any uid read), and it then
blocked analysis that would have worked. The worker instead answers by doing
what an analysis does -- open and read the evidence, write to its output root
-- through the same validators the analysis itself runs.

The probe is served by a thread of its own in the memory worker, so it is
answered even while a long analysis keeps the RQ worker busy. Results are
cached per evidence and keyed to the file's identity, so replacing the file
or changing its permissions asks again.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

from redis import Redis


logger = logging.getLogger(__name__)

REQUEST_LIST = "kairon:memory-access:requests"
RESULT_PREFIX = "kairon:memory-access:result:"
PENDING_PREFIX = "kairon:memory-access:pending:"
RESULT_TTL_SECONDS = 600
# A failure is re-checked sooner, so an administrator's fix shows up quickly.
FAILURE_TTL_SECONDS = 60
PENDING_TTL_SECONDS = 15
DEFAULT_WAIT_SECONDS = 2.0


def file_identity(st: os.stat_result) -> str:
    # ctime moves on chmod/chown too, so a permission fix is re-checked.
    return f"{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"


def probe_evidence_access(evidence, *, settings=None) -> dict[str, Any]:
    """Run in the memory worker: check access the way an analysis would."""
    from app.services.memory.evidence_access import (
        MemoryStorageAccessError,
        validate_current_process_evidence_access,
        validate_current_process_output_access,
    )

    result: dict[str, Any] = {
        "readable": False,
        "output_writable": False,
        "error_code": None,
        "message": None,
        "identity": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        access = validate_current_process_evidence_access(evidence, settings=settings)
        result["readable"] = True
        result["identity"] = file_identity(access.path.lstat())
    except MemoryStorageAccessError as exc:
        result["error_code"], result["message"] = exc.code, exc.message
        return result
    except OSError:
        result["error_code"], result["message"] = "EVIDENCE_FILE_NOT_FOUND", "Memory evidence file was not found."
        return result
    try:
        validate_current_process_output_access()
        result["output_writable"] = True
    except MemoryStorageAccessError as exc:
        result["error_code"], result["message"] = exc.code, exc.message
    return result


def _handle_request(redis_conn: Redis, evidence_id: str) -> None:
    from app.core.database import SessionLocal
    from app.models.evidence import Evidence, EvidenceType

    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None or evidence.evidence_type != EvidenceType.memory_dump:
            return
        result = probe_evidence_access(evidence)
    finally:
        db.close()
    ttl = RESULT_TTL_SECONDS if result["readable"] and result["output_writable"] else FAILURE_TTL_SECONDS
    redis_conn.setex(f"{RESULT_PREFIX}{evidence_id}", ttl, json.dumps(result, sort_keys=True))
    redis_conn.delete(f"{PENDING_PREFIX}{evidence_id}")


def serve_access_requests(redis_conn: Redis, *, block_seconds: int = 5) -> None:
    while True:
        try:
            item = redis_conn.blpop([REQUEST_LIST], timeout=block_seconds)
            if not item:
                continue
            raw = item[1]
            evidence_id = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            _handle_request(redis_conn, evidence_id)
        except Exception:  # noqa: BLE001 -- the probe must never take the worker down
            logger.warning("memory access probe failed", exc_info=True)
            time.sleep(1)


def start_access_probe_server(redis_conn: Redis) -> threading.Thread:
    thread = threading.Thread(
        target=serve_access_requests, args=(redis_conn,), name="memory-access-probe", daemon=True
    )
    thread.start()
    return thread


def _read_result(redis_conn: Redis, evidence_id: str, identity: str | None) -> dict[str, Any] | None:
    raw = redis_conn.get(f"{RESULT_PREFIX}{evidence_id}")
    if not raw:
        return None
    try:
        result = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
    except json.JSONDecodeError:
        return None
    # A result for an older version of the file (replaced, chmod'ed) is stale.
    # Results without an identity are failures before the file could be
    # opened; they are only trusted until they expire.
    if identity and result.get("identity") and result["identity"] != identity:
        return None
    return result


def probe_redis() -> Redis | None:
    """A Redis connection for asking the worker, or None when there is none."""
    from app.core.config import get_settings

    try:
        return Redis.from_url(get_settings().redis_url, socket_timeout=3)
    except Exception:  # noqa: BLE001
        return None


def worker_evidence_access(
    redis_conn: Redis | None,
    evidence_id: str,
    identity: str | None,
    *,
    wait_seconds: float | None = None,
) -> dict[str, Any] | None:
    """Run in the backend: the worker's verdict, or None when it has none yet.

    None means "not verified", never "blocked": the caller must not report a
    problem it has not observed.
    """
    if redis_conn is None:
        return None
    try:
        cached = _read_result(redis_conn, evidence_id, identity)
        if cached is not None:
            return cached
        if redis_conn.set(f"{PENDING_PREFIX}{evidence_id}", "1", nx=True, ex=PENDING_TTL_SECONDS):
            redis_conn.rpush(REQUEST_LIST, evidence_id)
        wait = DEFAULT_WAIT_SECONDS if wait_seconds is None else wait_seconds
        deadline = time.monotonic() + max(0.0, wait)
        while time.monotonic() < deadline:
            time.sleep(0.1)
            result = _read_result(redis_conn, evidence_id, identity)
            if result is not None:
                return result
    except Exception:  # noqa: BLE001 -- Redis trouble means "unverified", not "blocked"
        logger.warning("could not query the memory worker for evidence access", exc_info=True)
    return None
