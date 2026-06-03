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
    worker = Worker(["dfir-ingest", "dfir-rules", "dfir-analysis"], connection=connection)
    worker.work()


if __name__ == "__main__":
    main()
