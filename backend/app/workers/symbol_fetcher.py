import logging

from redis import Redis
from rq import Worker

from app.core.config import get_settings
from app.core.database import init_db
from app.services.memory.symbol_worker_capability import publish, start_heartbeat


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.backend_log_level)
    init_db()
    connection = Redis.from_url(settings.redis_url)
    publish(connection)
    start_heartbeat(connection)
    Worker([settings.memory_symbol_queue_name], connection=connection).work()


if __name__ == "__main__":
    main()
