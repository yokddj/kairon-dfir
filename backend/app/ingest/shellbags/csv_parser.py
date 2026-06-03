from __future__ import annotations

import csv
from pathlib import Path

from app.ingest.eztools.base import ensure_csv_field_limit


def read_shellbags_csv_rows(path: Path):
    ensure_csv_field_limit()
    for encoding in ("utf-8-sig", "utf-8", "utf-16le", "latin-1"):
        try:
            with path.open("r", encoding=encoding, errors="ignore", newline="") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    if isinstance(row, dict):
                        yield row
            return
        except Exception:  # noqa: BLE001
            continue

