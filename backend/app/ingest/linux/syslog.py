"""Syslog/messages/kern.log generic parser."""
from __future__ import annotations
import re
from datetime import datetime, timezone

from app.ingest.linux.netfilter import enrich_with_netfilter
from app.ingest.linux.sysmon_linux import enrich_with_sysmon

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# The optional "<facility.severity>" tag (e.g. "<auth.err>") appears between
# the timestamp and hostname on BSD syslogd installs (seen on a NetScaler
# appliance's own /var/log/messages) whenever the message came through a
# non-default facility -- its own "newsyslog"/rotation notices are the only
# lines logged without it, which is why only those previously matched at
# all; every forwarded auth/kernel-tagged line fell through to the
# no-match branch (timestamp/host/process all None) instead.
_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:<([\w.]+)>\s+)?(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s+(.*)$"
)

_SEVERITY_RE = re.compile(r"<(\d)>")

# A device can be configured to forward its own native audit/event log to
# this host's syslog (seen as a NetScaler "audit syslogAction" relaying
# its ns.log-style lines through local0): the BSD envelope wraps a second,
# inner timestamp in NetScaler's own "MM/DD/YYYY:HH:MM:SS GMT" format,
# followed by the *source* device's hostname and an internal unit id
# (e.g. "0-PPE-2") standing in for a process name -- a completely
# different shape _SYSLOG_RE's single "host process[pid]: message" slot
# can't capture, which is why these lines still had no timestamp/host
# even after that fix (confirmed: every line that fails this pattern on
# real affected files already matches _SYSLOG_RE, and vice versa -- the
# two are mutually exclusive, not competing for the same lines).
_FORWARDED_AUDIT_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+<([\w.]+)>\s+(\S+)\s+"
    r"(\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+GMT\s+(\S+)\s+(\S+)\s*:\s+(.*)$"
)


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


def _parse_forwarded_audit_timestamp(ts_str: str) -> str | None:
    match = re.match(r"^(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})$", ts_str.strip())
    if not match:
        return None
    month_str, day_str, year_str, hour_str, minute_str, second_str = match.groups()
    try:
        dt = datetime(int(year_str), int(month_str), int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc)
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

        forwarded_match = _FORWARDED_AUDIT_RE.match(stripped)
        if forwarded_match:
            outer_ts_str, facility, source_ip, inner_ts_str, host, unit_id, message = forwarded_match.groups()
            timestamp = _parse_forwarded_audit_timestamp(inner_ts_str) or _parse_syslog_timestamp(outer_ts_str)
            results.append({
                "artifact_family": "linux_syslog",
                "artifact_type": "syslog",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": timestamp,
                "host": host,
                "process": unit_id,
                "pid": None,
                "severity": facility,
                "message": f"[forwarded from {source_ip}] {message}"[:2000],
                "raw_excerpt": raw_excerpt,
            })
            continue

        syslog_match = _SYSLOG_RE.match(stripped)
        if syslog_match:
            ts_str, facility, host, process_raw, pid_str, message = syslog_match.groups()
            timestamp = _parse_syslog_timestamp(ts_str)
            process = process_raw.rstrip(":") if process_raw else None
            pid = int(pid_str) if pid_str else None
            sev_match = _SEVERITY_RE.match(stripped)
            # Prefer the numeric PRI tag ("<N>" at line start) when present;
            # otherwise the "<facility.severity>" tag this regex just
            # captured (e.g. "auth.err") is itself a real severity signal,
            # not nothing.
            severity = sev_match.group(1) if sev_match else facility
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
            # Before the 2000-character clip above: a Sysmon event line is routinely longer.
            enrich_with_sysmon(results[-1], message)
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
            enrich_with_sysmon(results[-1], stripped)
    for row in results:
        enrich_with_netfilter(row, str(row.get("message") or ""))
    return results
