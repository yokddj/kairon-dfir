"""Rows of a very large log, folded and ordered on disk instead of in memory.

A Mac's Unified Logs hold tens of millions of entries; even after the forensic filter, keeping
every row in a Python list (then sorting it and folding repeats) took the worker past the memory of
a laptop's Docker VM and the kernel killed it. Rows go to a temporary SQLite file instead, folded
as they arrive with the same rule as ``app.ingest.macos.logs.collapse_repeats`` (same hour, same
message once its numbers are masked: the first occurrence is kept with how many there were and the
last time), and are read back in time order, a slice at a time.

``CollapsedRows`` is a read-only sequence (len, index, slice, iteration), so the ingest can batch
it as it batches a list; the file is deleted when the sequence is no longer referenced.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import weakref
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

from app.ingest.macos.logs import _NUMBERS_RE

_INSERT_BATCH = 5000
_READ_CHUNK = 2000


def _remove(path: str) -> None:
    for suffix in ("", "-journal", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


class CollapsedRows(Sequence):
    def __init__(self, path: str, count: int):
        self._path = path
        self._count = count
        self._finalizer = weakref.finalize(self, _remove, path)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    @staticmethod
    def _row(data: str, count: int, last_seen: str | None) -> dict[str, Any]:
        row = json.loads(data)
        if count > 1:
            row["repeat_count"] = count
            row["last_seen"] = last_seen
            row["message"] = f"{row.get('message') or ''} [repeated {count} times until {str(last_seen or '')[11:19]} UTC]"
        return row

    def _range(self, start: int, stop: int) -> list[dict[str, Any]]:
        if stop <= start:
            return []
        with self._connect() as connection:
            cursor = connection.execute("SELECT data, n, last_seen FROM final WHERE rowid > ? AND rowid <= ? ORDER BY rowid", (start, stop))
            return [self._row(*item) for item in cursor]

    def __len__(self) -> int:
        return self._count

    def __getitem__(self, index):  # type: ignore[override]
        if isinstance(index, slice):
            start, stop, step = index.indices(self._count)
            rows = self._range(start, stop)
            return rows if step == 1 else rows[::step]
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError(index)
        return self._range(index, index + 1)[0]

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for start in range(0, self._count, _READ_CHUNK):
            yield from self._range(start, min(start + _READ_CHUNK, self._count))

    def close(self) -> None:
        self._finalizer()


def collapse_to_disk(rows: Iterable[dict[str, Any]], *, temp_dir: Path) -> CollapsedRows:
    """Folds and orders ``rows`` (dicts with ``timestamp`` and ``message``) in a temporary SQLite file."""
    temp_dir.mkdir(parents=True, exist_ok=True)
    handle, path = tempfile.mkstemp(prefix="collapsed-rows-", suffix=".sqlite", dir=str(temp_dir))
    os.close(handle)
    try:
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("CREATE TABLE stage (key TEXT PRIMARY KEY, ts TEXT, seq INTEGER, data TEXT, n INTEGER, last_seen TEXT)")
        upsert = (
            "INSERT INTO stage (key, ts, seq, data, n, last_seen) VALUES (?, ?, ?, ?, 1, ?) "
            "ON CONFLICT(key) DO UPDATE SET n = n + 1, last_seen = max(last_seen, excluded.ts), "
            "data = CASE WHEN excluded.ts < ts THEN excluded.data ELSE data END, "
            "seq = CASE WHEN excluded.ts < ts THEN excluded.seq ELSE seq END, "
            "ts = min(ts, excluded.ts)"
        )
        pending: list[tuple[str, str, int, str, str]] = []
        for seq, row in enumerate(rows):
            stamp = str(row.get("timestamp") or "")
            # Lines without a time are never folded (collapse_repeats).
            key = f"{stamp[:13]}\x00{_NUMBERS_RE.sub('#', str(row.get('message') or ''))}" if stamp else f"\x01{seq}"
            pending.append((key, stamp, seq, json.dumps(row, default=str), stamp))
            if len(pending) >= _INSERT_BATCH:
                connection.executemany(upsert, pending)
                pending.clear()
        if pending:
            connection.executemany(upsert, pending)
        # Time order, as the list was sorted before (rows without a time first), stable by arrival.
        connection.execute("CREATE TABLE final AS SELECT data, n, last_seen FROM stage ORDER BY ts, seq")
        connection.execute("DROP TABLE stage")
        connection.commit()
        count = connection.execute("SELECT count(*) FROM final").fetchone()[0]
        connection.close()
    except BaseException:
        _remove(path)
        raise
    return CollapsedRows(path, int(count))
