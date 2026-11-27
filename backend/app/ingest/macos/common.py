"""Shared helpers for the macOS artifact parsers."""
from __future__ import annotations

import plistlib
from xml.parsers.expat import ExpatError
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Core Data / NSDate times count seconds from 2001-01-01 00:00:00 UTC.
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
_MAX_PLIST_BYTES = 16 * 1024 * 1024
_USER_HOME_RE = re.compile(r"(?:^|/)Users/(?P<user>[^/]+)/", re.IGNORECASE)
_ROOT_HOME_RE = re.compile(r"(?:^|/)(?:private/)?var/root/", re.IGNORECASE)
_SHARED_HOMES = {"shared", "guest", ".localized"}


def cocoa_to_iso(value: Any) -> str | None:
    """A Cocoa timestamp (seconds since 2001-01-01 UTC) as ISO-8601 UTC, or None when unset."""
    if value in (None, "", 0, 0.0):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    # Values far outside the range of a running Mac are not times (a corrupt or unset column).
    if not -31_536_000 < seconds < 3_155_760_000:
        return None
    return (COCOA_EPOCH + timedelta(seconds=seconds)).isoformat()


def unix_to_iso(value: Any) -> str | None:
    if value in (None, "", 0):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 < seconds < 4_102_444_800:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def datetime_to_iso(value: Any) -> str | None:
    """A plist <date> (naive UTC from plistlib) as ISO-8601 UTC."""
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
    return None


def file_mtime_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


_BARE_AMPERSAND_RE = re.compile(rb"&(?!(?:[A-Za-z][A-Za-z0-9]*|#[0-9]+|#x[0-9A-Fa-f]+);)")


def load_plist(path: Path) -> Any:
    """A binary or XML property list. Raises ValueError when the file is not one.

    An XML plist with a bare "&" (not written as &amp;), which some vendors ship, is read again with
    those escaped; any other malformed XML stays unreadable. The XML parser's own error is not a
    ValueError, and escaped every caller's handling of unreadable plists."""
    if path.stat().st_size > _MAX_PLIST_BYTES:
        raise ValueError("property list larger than 16 MiB")
    data = path.read_bytes()
    try:
        return plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ExpatError) as exc:
        first_error = exc
    if not data.startswith(b"bplist") and b"&" in data:
        try:
            return plistlib.loads(_BARE_AMPERSAND_RE.sub(b"&amp;", data))
        except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ExpatError):
            pass
    raise ValueError(f"not a readable property list: {first_error}") from first_error


def user_from_path(source_path: str) -> str:
    """The account whose home a collected file sits in (/Users/<name>/..., /var/root/...)."""
    normalized = str(source_path or "").replace("\\", "/")
    match = _USER_HOME_RE.search(normalized)
    if match and match.group("user").lower() not in _SHARED_HOMES:
        return match.group("user")
    if _ROOT_HOME_RE.search(normalized):
        return "root"
    return ""


def original_path(source_path: str) -> str:
    """The path the file had on the Mac: what follows UAC's ``[root]/`` when present."""
    normalized = str(source_path or "").replace("\\", "/")
    index = normalized.find("[root]/")
    if index >= 0:
        return "/" + normalized[index + len("[root]/"):]
    return normalized if normalized.startswith("/") else "/" + normalized


@contextmanager
def open_sqlite_copy(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a copy of a SQLite database together with its -wal/-shm, read-only.

    macOS databases run in WAL mode: the newest rows often live only in the -wal file, which SQLite
    reads only when it sits beside the database under the same name. Working on a copy also keeps
    the evidence file untouched.
    """
    from app.core.config import get_settings

    temp_root = Path(get_settings().backend_temp_dir)
    temp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="macos-sqlite-", dir=str(temp_root)))
    try:
        copy = work_dir / "database.sqlite"
        shutil.copyfile(path, copy)
        for suffix in ("-wal", "-shm"):
            companion = path.with_name(path.name + suffix)
            if companion.is_file():
                shutil.copyfile(companion, work_dir / f"database.sqlite{suffix}")
        connection = sqlite3.connect(str(copy))
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()}
    except sqlite3.DatabaseError:
        return set()


def first_text(value: Any) -> str:
    """dslocal stores every attribute as an array; the first element is the value."""
    if isinstance(value, list):
        value = value[0] if value else ""
    if isinstance(value, bytes):
        return ""
    return str(value or "").strip()
