"""Dedicated worker for the experimental mismatched-symbol analysis.

The worker is intentionally separate from the validated
``memory-worker`` and listens on a different RQ queue
(``memory-experimental``) so experimental work cannot starve
validated analysis.  The worker is started with the
``experimental`` docker compose profile; if the experimental
feature flag is off the worker exits gracefully.
"""
from __future__ import annotations

import logging

from redis import Redis
from rq import Worker

from app.core.config import get_settings
from app.core.database import init_db
from app.services.memory.experimental_trust import is_experimental_enabled


settings = get_settings()
logging.basicConfig(level=settings.backend_log_level)


def main() -> None:
    init_db()
    if not is_experimental_enabled():
        logging.info(
            "experimental mismatched-symbol worker disabled "
            "(memory_symbol_experimental_mismatch_enabled=False); "
            "not consuming from the queue."
        )
        return
    connection = Redis.from_url(settings.redis_url)
    worker = Worker(
        [settings.memory_experimental_queue_name], connection=connection
    )
    worker.work()


if __name__ == "__main__":
    main()
