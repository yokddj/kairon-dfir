"""macOS text logs whose line format the generic Linux log parser does not read correctly.

* ``/private/var/log/install.log`` (and its rotated copies): ``2026-01-02 10:00:00+01 host
  process[pid]: message``. The UTC offset is honoured. Lines that report a finished installation
  (``Installed "Name" (version)``) and package receipts are marked as such; continuation lines
  are folded into the line they continue.
* ``/private/var/log/com.apple.xpc.launchd/launchd.log``: ISO local times, read by the generic log
  parser; folded like wifi.log (see collapse_repeats).
* ``/private/var/log/wifi.log`` (and rotated ``.bz2`` copies): ``Thu Jan  2 10:00:00.123 message``,
  local time with no year or zone. The year and zone are resolved like any year-less Linux log
  (see app.ingest.linux.local_time), with UAC's recorded time zone as a fallback.

``system.log`` is classic syslog and stays with the generic log parser.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.ingest.linux.generic_log import read_log_text
from app.ingest.linux.local_time import ASSUMED_YEAR, file_reference_time, host_clock_for, resolve_local_times
from app.ingest.uac.collection import uac_host_clock

ARTIFACT_FAMILY = "macos_logs"
_INSTALL_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})(?P<offset>[+-]\d{2}(?::?\d{2})?)? (?P<host>\S+) (?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
_INSTALLED_RE = re.compile(r'Installed "(?P<name>[^"]+)" \((?P<version>[^)]*)\)')
_RECEIPT_RE = re.compile(r"Writing receipt for (?P<package>\S+)")
_WIFI_RE = re.compile(
    r"^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d+))? (?P<message>.*)$"
)
_MONTHS = {name: index for index, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_MAX_MESSAGE = 4000


def log_kind(original: str) -> str | None:
    name = original.rsplit("/", 1)[-1].lower()
    lowered = original.lower()
    if not ("/private/var/log/" in lowered or lowered.startswith("/var/log/")):
        return None
    if re.match(r"^install\.log(?:\.\d+)?(?:\.(?:gz|bz2))?$", name):
        return "install_log"
    if re.match(r"^wifi\.log(?:\.\d+)?(?:\.(?:gz|bz2))?$", name):
        return "wifi_log"
    if re.match(r"^launchd\.log(?:\.\d+)?(?:\.(?:gz|bz2))?$", name) and "/com.apple.xpc.launchd/" in lowered:
        return "launchd_log"
    return None


_NUMBERS_RE = re.compile(r"0x[0-9a-fA-F]+|\d+")


def collapse_repeats(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold lines that differ only in their numbers (PIDs, counters, addresses) within the same
    hour into the first of them, with how many there were and when the last one came.

    launchd.log and wifi.log are mostly the same few messages repeated thousands of times (165k
    launchd lines held 56k distinct messages per hour on a test Mac; 100k wifi lines, 8.7k). Every
    distinct message is kept, with its first occurrence's exact text and time; only the repeats'
    numbers are lost. Lines without a time are never folded.
    """
    folded: dict[tuple[str, str], dict[str, Any]] = {}
    result: list[dict[str, Any]] = []
    for row in rows:
        stamp = str(row.get("timestamp") or "")
        if not stamp:
            result.append(row)
            continue
        key = (stamp[:13], _NUMBERS_RE.sub("#", str(row.get("message") or "")))
        first = folded.get(key)
        if first is None:
            folded[key] = row
            result.append(row)
            continue
        first["repeat_count"] = int(first.get("repeat_count") or 1) + 1
        first["last_seen"] = stamp
    for row in folded.values():
        if row.get("repeat_count"):
            row["message"] = f"{row.get('message') or ''} [repeated {row['repeat_count']} times until {row['last_seen'][11:19]} UTC]"
    return result


def _offset(value: str | None) -> timezone | None:
    if not value:
        return None
    sign = -1 if value[0] == "-" else 1
    digits = value[1:].replace(":", "")
    hours = int(digits[:2])
    minutes = int(digits[2:4]) if len(digits) >= 4 else 0
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def parse_install_log(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    text, truncated = read_log_text(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _INSTALL_RE.match(line)
        if not match:
            if rows and line.strip() and len(rows[-1]["message"]) < _MAX_MESSAGE:
                rows[-1]["message"] = (rows[-1]["message"] + "\n" + line)[:_MAX_MESSAGE]
            continue
        zone = _offset(match.group("offset"))
        try:
            local = datetime.strptime(f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        message = match.group("message")[:_MAX_MESSAGE]
        row: dict[str, Any] = {
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": "install_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": local.replace(tzinfo=zone or timezone.utc).astimezone(timezone.utc).isoformat(),
            "timestamp_status": "ok" if zone else "assumed_utc",
            "process": match.group("process"),
            "pid": int(match.group("pid")) if match.group("pid") else None,
            "event_action": "install_log_entry",
            "message": message,
        }
        installed = _INSTALLED_RE.search(message)
        receipt = _RECEIPT_RE.search(message)
        if installed:
            row.update({"event_action": "package_installed", "package": installed.group("name"), "package_version": installed.group("version")})
        elif receipt:
            row.update({"event_action": "package_receipt_written", "package": receipt.group("package")})
        rows.append(row)
    if truncated and rows:
        rows[-1]["truncated"] = True
    if any(row["timestamp_status"] == "assumed_utc" for row in rows):
        clock = host_clock_for(path)
        if clock.zone is None:
            clock = uac_host_clock(path)
        resolve_local_times(rows, reference=file_reference_time(path), clock=clock)
    return rows


def parse_wifi_log(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    text, truncated = read_log_text(path)
    year = datetime.now(tz=timezone.utc).year
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _WIFI_RE.match(line)
        if not match:
            continue
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        fraction = int((match.group("fraction") or "0")[:6].ljust(6, "0"))
        try:
            local = datetime(year, _MONTHS[match.group("mon")], int(match.group("day")), hour, minute, second, fraction)
        except ValueError:
            # 29 February: placed in a leap year until the real year is resolved.
            local = datetime(2024, _MONTHS[match.group("mon")], int(match.group("day")), hour, minute, second, fraction)
        rows.append({
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": "wifi_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": local.isoformat(),
            "timestamp_status": ASSUMED_YEAR,
            "event_action": "wifi_log_entry",
            "message": match.group("message")[:_MAX_MESSAGE],
        })
    if truncated and rows:
        rows[-1]["truncated"] = True
    if rows:
        clock = host_clock_for(path)
        if clock.zone is None:
            clock = uac_host_clock(path)
        resolve_local_times(rows, reference=file_reference_time(path), clock=clock)
        for row in rows:
            if row["timestamp_status"] == ASSUMED_YEAR:
                # Nothing could place it: keep the line, without a made-up time.
                row["timestamp"] = None
                row["timestamp_status"] = "missing"
    return collapse_repeats(rows)


def parse_launchd_log(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    """launchd's own log, read by the generic log parser (ISO local times, levels), then folded."""
    from app.ingest.linux.dispatch import parse_linux_artifact_file

    rows = parse_linux_artifact_file(path, parser="linux_generic_raw", artifact_type="generic_log", source_path=source_path)
    for row in rows:
        row["artifact_family"] = ARTIFACT_FAMILY
        row["artifact_type"] = "launchd_log"
        row["event_action"] = "launchd_log_entry"
    return collapse_repeats(rows)
