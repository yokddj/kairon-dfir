from __future__ import annotations

from pathlib import Path

from app.ingest.eztools.base import read_delimited_rows


def parse_autoruns_wmi_csv_file(path: Path) -> list[dict]:
    rows = []
    for row in read_delimited_rows(path):
        blob = " ".join(str(value or "") for value in row.values()).lower()
        if "wmi" in blob or "eventconsumer" in blob or "eventfilter" in blob or "filtertoconsumerbinding" in blob:
            rows.append(dict(row))
    return rows


__all__ = ["parse_autoruns_wmi_csv_file"]
