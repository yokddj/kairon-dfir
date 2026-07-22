"""Shared distributed locking primitive for upload session lifecycles.

Extracted from the memory upload pipeline (the original chunk-level and
finalize-level lock, previously private to
app.services.memory.upload_sessions) so any upload session backend -
memory or evidence - can serialize concurrent requests against the same
logical resource (a chunk index, an append offset, a finalize step)
across worker processes, where a Python-level asyncio.Lock would not be
visible across processes.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from uuid import uuid4

import redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

DEFAULT_LOCK_TTL_SECONDS = 1800


class UploadLockBusyError(RuntimeError):
    """Raised when a distributed upload lock is already held by another request."""


class UploadLockUnavailableError(RuntimeError):
    """Raised when the locking backend (Redis) could not be reached."""


@contextmanager
def redis_upload_lock(key: str, *, ttl: int = DEFAULT_LOCK_TTL_SECONDS):
    token = str(uuid4())
    redis_conn: redis.Redis | None = None
    acquired = False
    try:
        redis_conn = redis.Redis.from_url(get_settings().redis_url)
        acquired = bool(redis_conn.set(key, token, nx=True, ex=ttl))
    except Exception:  # noqa: BLE001 - tests commonly run without Redis
        if "PYTEST_CURRENT_TEST" not in os.environ:
            raise UploadLockUnavailableError("Upload locking backend is unavailable. Retry later.")
        acquired = True
        redis_conn = None
    if not acquired:
        raise UploadLockBusyError("This upload session is busy. Retry shortly.")
    try:
        yield
    finally:
        if redis_conn is not None:
            try:
                script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
                redis_conn.eval(script, 1, key, token)
            except Exception:  # noqa: BLE001
                logger.warning("upload lock release failed", extra={"lock_key": key})
