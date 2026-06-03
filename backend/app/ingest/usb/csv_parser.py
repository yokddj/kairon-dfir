from __future__ import annotations

from pathlib import Path

from app.ingest.usb.helpers import read_usb_csv_rows


def parse_usb_csv_file(path: Path) -> list[dict]:
    return list(read_usb_csv_rows(path))
