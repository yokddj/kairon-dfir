"""Syslog/messages/kern.log generic parser."""
from __future__ import annotations
import re
from datetime import datetime, timezone

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s+(.*)$"
)

_SEVERITY_RE = re.compile(r"<(\d)>")


def _parse_syslog_timestamp(ts_str: str, year: int | None = None) -> str | None:
    ts_str = ts_str.strip()
    if year is None:
        year = datetime.now(tz=timezone.utc).year
    match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts_str)
    if not match:
        return None
    month_str, day_str, hour_str, minute_str, second_str = match.groups()
    month = _MONTH_MAP.get(month_str.lower())
    if month is None:
        return None
    try:
        dt = datetime(year, month, int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError):
        return None


def parse_syslog(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        raw_excerpt = stripped[:2000]

        syslog_match = _SYSLOG_RE.match(stripped)
        if syslog_match:
            ts_str, host, process_raw, pid_str, message = syslog_match.groups()
            timestamp = _parse_syslog_timestamp(ts_str)
            process = process_raw.rstrip(":") if process_raw else None
            pid = int(pid_str) if pid_str else None
            severity = None
            sev_match = _SEVERITY_RE.match(stripped)
            if sev_match:
                severity = sev_match.group(1)
            results.append({
                "artifact_family": "linux_syslog",
                "artifact_type": "syslog",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": timestamp,
                "host": host,
                "process": process,
                "pid": pid,
                "severity": severity,
                "message": message[:2000],
                "raw_excerpt": raw_excerpt,
            })
        else:
            results.append({
                "artifact_family": "linux_syslog",
                "artifact_type": "syslog",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": None,
                "host": None,
                "process": None,
                "pid": None,
                "severity": None,
                "message": stripped[:2000],
                "raw_excerpt": raw_excerpt,
            })
    return results
