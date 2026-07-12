"""Cron parser for /etc/crontab, /etc/cron.d/*, /var/spool/cron/*."""
from __future__ import annotations
import re

_CRON_TIME_FIELDS = 5
_COMMENT_RE = re.compile(r"^\s*#")
_EMPTY_RE = re.compile(r"^\s*$")
_ENV_ASSIGN_RE = re.compile(r"^\s*(\w+)\s*=\s*(.*)$")


def parse_cron(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped) or _EMPTY_RE.match(stripped):
            continue
        if _ENV_ASSIGN_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        parts = stripped.split(None, _CRON_TIME_FIELDS + 1)
        if len(parts) < 7:
            continue
        schedule = " ".join(parts[:_CRON_TIME_FIELDS])
        line_user = parts[_CRON_TIME_FIELDS]
        command = parts[_CRON_TIME_FIELDS + 1] if len(parts) > _CRON_TIME_FIELDS + 1 else ""
        effective_user = line_user if not line_user.isdigit() and re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]*$", line_user) else None
        command_part = " ".join(parts[_CRON_TIME_FIELDS:]) if effective_user is None else command
        if effective_user is None and len(parts) == 6:
            schedule = " ".join(parts[:_CRON_TIME_FIELDS])
            command_part = parts[_CRON_TIME_FIELDS]
        results.append({
            "artifact_family": "linux_cron",
            "artifact_type": "crontab",
            "source_file": source_path,
            "line_number": line_number,
            "schedule": schedule,
            "username": effective_user or username,
            "command": command_part[:2000],
            "message": f"{schedule} {effective_user or ''} {command_part[:500]}".strip(),
            "raw_excerpt": raw_excerpt,
        })
    return results
