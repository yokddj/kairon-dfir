from __future__ import annotations

from pathlib import Path

from app.ingest.eztools.base import read_delimited_rows


def parse_cloud_csv_file(path: Path) -> list[dict]:
    return list(read_delimited_rows(path))


__all__ = ["parse_cloud_csv_file"]
