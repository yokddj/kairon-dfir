import shutil
import sqlite3
import tempfile
from pathlib import Path

from app.core.config import get_settings


settings = get_settings()


def prepare_sqlite_for_reading(path: Path) -> tuple[Path, list[str]]:
    temp_dir = Path(tempfile.mkdtemp(prefix="browser-sqlite-", dir=settings.backend_temp_dir))
    copied = []
    db_copy = temp_dir / path.name
    shutil.copy2(path, db_copy)
    copied.append(str(db_copy))
    for suffix in ("-wal", "-shm"):
        companion = path.with_name(path.name + suffix)
        if companion.exists():
            copied_companion = temp_dir / companion.name
            shutil.copy2(companion, copied_companion)
            copied.append(str(copied_companion))
    return db_copy, copied


def open_sqlite_readonly(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.DatabaseError:
        return set()
    return {str(row["name"]) for row in rows}
