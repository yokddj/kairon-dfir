from pathlib import Path

from app.ingest.eztools.base import iter_delimited_rows
from app.ingest.scheduled_tasks.helpers import canonicalize_header, looks_like_scheduled_task_artifact


def looks_like_scheduled_task_csv(path: Path, headers: list[str] | None = None) -> bool:
    if path.suffix.lower() != ".csv":
        return False
    if looks_like_scheduled_task_artifact(path, headers):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return bool({"taskname", "taskpath", "command", "arguments", "enabled"} & header_set)


def read_scheduled_task_csv_rows(path: Path):
    yield from iter_delimited_rows(path)
