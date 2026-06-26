"""Dedicated worker for Volatility-native compatibility probes.

Consumes only the ``memory-native-probe`` queue.  When a native probe
task is dequeued it runs the pinned stock Volatility engine against
the evidence with full automagic — no custom ISF, no forced --offline.
"""
from __future__ import annotations

import logging

from redis import Redis
from rq import Worker

from app.core.config import get_settings
from app.core.database import init_db

settings = get_settings()
logging.basicConfig(level=settings.backend_log_level)


def main() -> None:
    init_db()
    connection = Redis.from_url(settings.redis_url)
    worker = Worker(
        [settings.memory_native_probe_queue_name],
        connection=connection,
    )
    worker.work()


if __name__ == "__main__":
    main()
