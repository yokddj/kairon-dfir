from __future__ import annotations

from pathlib import Path
import re

from app.ingest.cloud_sync.helpers import clean_value


KV_RE = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9 _-]+)\s*[:=]\s*(?P<value>.+)")


def parse_cloud_log_file(path: Path) -> list[dict]:
    rows: list[dict] = []
    current: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                rows.append(current)
                current = {}
            continue
        match = KV_RE.match(line)
        if match:
            key = match.group("key").strip()
            value = clean_value(match.group("value").strip())
            current[key] = value or ""
    if current:
        rows.append(current)
    return rows


__all__ = ["parse_cloud_log_file"]
