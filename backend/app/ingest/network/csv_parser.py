from __future__ import annotations

import csv
from pathlib import Path


def parse_network_csv_file(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
        return list(csv.DictReader(handle))
