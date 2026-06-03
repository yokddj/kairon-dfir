from __future__ import annotations

from pathlib import Path

from app.ingest.bits.helpers import read_bits_csv_rows


def parse_bits_csv_file(path: Path) -> list[dict]:
    return list(read_bits_csv_rows(path))
