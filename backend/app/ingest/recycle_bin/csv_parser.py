from __future__ import annotations

import csv
import json
from pathlib import Path

from app.ingest.eztools.base import ensure_csv_field_limit


def read_recycle_bin_csv_rows(path: Path):
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


def read_recycle_bin_json_rows(path: Path):
    try:
        if path.suffix.lower() == ".jsonl":
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if isinstance(row, dict):
                    yield row
            return
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, dict):
            yield payload
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item
    except Exception:  # noqa: BLE001
        return
