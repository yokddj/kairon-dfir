from __future__ import annotations

import csv
from pathlib import Path

from app.ingest.autoruns.helpers import sniff_delimiter
from app.ingest.eztools.base import ensure_csv_field_limit


def parse_autoruns_csv_file(path: Path) -> list[dict]:
    ensure_csv_field_limit()
    encodings = ("utf-8-sig", "utf-8", "utf-16", "utf-16le", "latin-1")
    last_error: Exception | None = None
    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding, errors="ignore", newline="") as handle:
                sample = handle.read(4096)
                handle.seek(0)
                delimiter = sniff_delimiter(sample, default=",")
                reader = csv.DictReader(handle, delimiter=delimiter)
                return [dict(row) for row in reader]
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    if last_error:
        raise last_error
    return []


__all__ = ["parse_autoruns_csv_file"]
