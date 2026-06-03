from __future__ import annotations

from pathlib import Path


def parse_hosts_file(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        comment = None
        if "#" in stripped:
            stripped, comment = stripped.split("#", 1)
            stripped = stripped.strip()
            comment = comment.strip()
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for hostname in parts[1:]:
            rows.append(
                {
                    "ArtifactType": "hosts_file",
                    "IP": ip,
                    "HostName": hostname,
                    "Comment": comment,
                    "LineNumber": line_number,
                }
            )
    return rows
