from __future__ import annotations

from pathlib import Path

from app.ingest.cloud_sync.helpers import read_cloud_json_rows


def parse_cloud_json_file(path: Path) -> list[dict]:
    return read_cloud_json_rows(path)


__all__ = ["parse_cloud_json_file"]
