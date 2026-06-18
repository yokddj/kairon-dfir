import logging

from redis import Redis
from rq import Worker

from app.core.config import get_settings
from app.core.database import init_db
from app.services.memory.worker_capability import publish_memory_worker_capability, start_memory_worker_heartbeat


settings = get_settings()
logging.basicConfig(level=settings.backend_log_level)


def main() -> None:
    init_db()
    connection = Redis.from_url(settings.redis_url)
    publish_memory_worker_capability(connection)
    start_memory_worker_heartbeat(connection)
    worker = Worker([settings.memory_queue_name], connection=connection)
    worker.work()


if __name__ == "__main__":
    main()
