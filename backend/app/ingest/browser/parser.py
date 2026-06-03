import csv
import json
from pathlib import Path


def _load_json_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("rows"), list):
            return [item for item in data["rows"] if isinstance(item, dict)]
        return [data]
    return []


def read_browser_records(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
            return list(csv.DictReader(handle))
    if suffix == ".json":
        return _load_json_records(path)
    if suffix == ".jsonl":
        records: list[dict] = []
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
        return records
    return []
