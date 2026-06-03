from __future__ import annotations

from pathlib import Path

from app.ingest.eztools.base import read_delimited_rows


def read_jumplist_csv_rows(path: Path) -> list[dict]:
    return read_delimited_rows(path)
