from __future__ import annotations

from pathlib import Path
import re


def parse_bitsadmin_file(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    blocks = re.split(r"\n\s*\n", text)
    rows: list[dict] = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        row: dict[str, str] = {"RawBlock": block, "SourceFile": str(path)}
        for line in block.splitlines():
            match = re.match(r"^\s*([^:]+?)\s*:\s*(.+?)\s*$", line)
            if not match:
                continue
            key = re.sub(r"[^A-Za-z0-9]+", "", match.group(1))
            value = match.group(2).strip()
            if key:
                row[key] = value
        if len(row) > 2:
            rows.append(row)
    return rows
