from __future__ import annotations

import csv
import json
from pathlib import Path


def parse_dns_csv_file(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
        return list(csv.DictReader(handle))


def parse_dns_json_file(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("items", "entries", "records", "results"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return [payload]
    return []
