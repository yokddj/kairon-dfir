"""Generic text-log parser for Linux logs no dedicated parser recognises.

A last-resort parser: ``looks_like_linux_artifact`` only routes a file here after every
specific Linux detector (auth, syslog, apache, ...) has declined it, so it never changes
how a recognised artifact is parsed. It handles nginx / fail2ban / ufw / dpkg / application
logs and their rotated or compressed copies by sniffing one line format per file:

* ``json``   - one JSON object per line (JSONL / NDJSON)
* ``iso``    - ``2024-03-01T10:20:30Z``, ``2024-03-01 10:20:30,123`` or ``[2024/03/01 10:20:30]``
* ``syslog`` - ``Mar  1 10:20:30 host proc[123]: message`` (no year in the line)
* ``clf``    - Common/Combined Log Format ``[01/Mar/2024:10:20:30 +0000]``
* ``none``   - no recognisable timestamp; every line becomes an undated event

Every event keeps its original line in ``raw_excerpt`` and records how trustworthy its
time is in ``timestamp_status``, so an analyst can tell a real UTC instant from one this
parser had to assume.
"""
from __future__ import annotations

import bz2
import gzip
import json
import lzma
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from app.ingest.linux.syslog import _SYSLOG_RE, _parse_syslog_timestamp

MAX_MESSAGE_CHARS = 2000
MAX_CONTINUATION_LINES = 200
FORMAT_SAMPLE_LINES = 200
FORMAT_MIN_RATIO = 0.5
# Decompressed bytes read per file. A compressed log can expand by orders of magnitude, so
# the cap applies to the text actually parsed, not to the size on disk.
MAX_LOG_BYTES = 256 * 1024 * 1024
# Small chunks: on a damaged archive the exception discards the chunk being decoded, so a
# smaller chunk keeps more of what was readable.
_READ_CHUNK = 64 * 1024
_MIN_YEAR = 1990

ARTIFACT_FAMILY = "linux_generic_log"
ARTIFACT_TYPE = "generic_log"

_ISO_RE = re.compile(
    r"^[\[(]?(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?[\])]?[\s:|-]*(.*)$"
)
_CLF_RE = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?\]")
_CLF_MAX_OFFSET = 120
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_USER_KV_RE = re.compile(r"\buser(?:name)?=[\"']?([\w.@-]{1,64})", re.IGNORECASE)
_USER_FOR_RE = re.compile(r"\bfor (?:invalid )?user ([\w.@-]{1,64})", re.IGNORECASE)
_PROC_RE = re.compile(r"^([A-Za-z][\w./-]{0,63})\[(\d+)\]:?\s*(.*)$", re.DOTALL)
_SEVERITY_RE = re.compile(r"\b(emerg|alert|crit|critical|fatal|err|error|warn|warning|notice|info|debug)\b", re.IGNORECASE)
_SEVERITY_ALIASES = {"critical": "crit", "err": "error", "warn": "warning"}

_JSON_TIME_KEYS = ("@timestamp", "timestamp", "time", "ts", "t", "datetime", "date", "eventTime", "event_time")
_JSON_MESSAGE_KEYS = ("message", "msg", "log", "event", "text")
_JSON_USER_KEYS = ("user", "username", "user_name", "usr")
_JSON_IP_KEYS = ("remote_addr", "client_ip", "src_ip", "source_ip", "ip", "remote_ip", "clientip")
_JSON_PROC_KEYS = ("process", "program", "service", "app", "logger", "component")
_JSON_SEVERITY_KEYS = ("level", "severity", "lvl", "loglevel", "log_level")

# (iso timestamp | None, timestamp_status, remaining text, extra fields)
_Parsed = tuple[Optional[str], str, str, dict[str, Any]]


def looks_binary(sample: str) -> bool:
    return "\x00" in sample[:4096]


def read_log_text(path: Path, *, limit: int = MAX_LOG_BYTES) -> tuple[str, bool]:
    """Read a plain or gzip/bzip2/xz-compressed log as text, capped at ``limit`` bytes.

    Compression is detected from the magic bytes rather than the extension, so a renamed
    or extensionless rotated copy still opens. Returns ``(text, truncated)``; ``truncated``
    is also set when a damaged archive stops early, with whatever was readable kept.
    """
    with path.open("rb") as raw:
        magic = raw.read(6)
    if magic[:2] == b"\x1f\x8b":
        opener: Callable[[], Any] = lambda: gzip.open(path, "rb")  # noqa: E731
    elif magic[:3] == b"BZh":
        opener = lambda: bz2.open(path, "rb")  # noqa: E731
    elif magic[:6] == b"\xfd7zXZ\x00":
        opener = lambda: lzma.open(path, "rb")  # noqa: E731
    else:
        opener = lambda: path.open("rb")  # noqa: E731

    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        with opener() as handle:
            while total <= limit:
                chunk = handle.read(_READ_CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            else:
                truncated = True
    except (OSError, EOFError, lzma.LZMAError):
        truncated = True
    data = b"".join(chunks)
    if len(data) > limit:
        data = data[:limit]
        truncated = True
    return data.decode("utf-8", errors="replace"), truncated


def _utc_iso(dt: datetime) -> str | None:
    if dt.year < _MIN_YEAR or dt > datetime.now(tz=timezone.utc) + timedelta(days=366):
        return None
    return dt.astimezone(timezone.utc).isoformat()


def _offset(token: str | None) -> timezone | None:
    if not token:
        return None
    if token == "Z":
        return timezone.utc
    digits = token.replace(":", "")
    sign = -1 if digits[0] == "-" else 1
    try:
        return timezone(sign * timedelta(hours=int(digits[1:3]), minutes=int(digits[3:5])))
    except ValueError:
        return None


def _parse_iso_line(line: str) -> _Parsed | None:
    match = _ISO_RE.match(line)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, zone, rest = match.groups()
    tz = _offset(zone)
    try:
        micro = int((fraction or "0")[:6].ljust(6, "0"))
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tzinfo=tz or timezone.utc)
    except ValueError:
        return None
    stamp = _utc_iso(dt)
    if stamp is None:
        return None
    return stamp, "ok" if tz else "assumed_utc", rest, {}


def _parse_syslog_line(line: str) -> _Parsed | None:
    match = _SYSLOG_RE.match(line)
    if not match:
        return None
    ts_str, facility, host, process, pid, message = match.groups()
    now = datetime.now(tz=timezone.utc)
    stamp = _parse_syslog_timestamp(ts_str, now.year)
    if stamp and datetime.fromisoformat(stamp) > now + timedelta(days=1):
        # A December line read in January belongs to last year, not next December.
        stamp = _parse_syslog_timestamp(ts_str, now.year - 1)
    if stamp is None:
        return None
    extras: dict[str, Any] = {"host": host, "process": process, "pid": int(pid) if pid else None}
    if facility:
        extras["severity"] = facility
    return stamp, "assumed_year_utc", message, extras


def _parse_clf_line(line: str) -> _Parsed | None:
    match = _CLF_RE.search(line[:_CLF_MAX_OFFSET])
    if not match:
        return None
    day, month, year, hour, minute, second, zone = match.groups()
    month_number = _MONTHS.get(month.lower())
    if month_number is None:
        return None
    tz = _offset(zone)
    try:
        dt = datetime(int(year), month_number, int(day), int(hour), int(minute), int(second), tzinfo=tz or timezone.utc)
    except ValueError:
        return None
    stamp = _utc_iso(dt)
    if stamp is None:
        return None
    return stamp, "ok" if tz else "assumed_utc", line, {}


def _first_present(record: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _json_timestamp(value: Any) -> tuple[str | None, str]:
    if isinstance(value, bool) or value is None:
        return None, "missing"
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # milliseconds
            seconds /= 1000.0
        try:
            return _utc_iso(datetime.fromtimestamp(seconds, tz=timezone.utc)) or None, "ok"
        except (OverflowError, OSError, ValueError):
            return None, "missing"
    parsed = _parse_iso_line(str(value).strip())
    if parsed:
        return parsed[0], parsed[1]
    return None, "missing"


def _parse_json_line(line: str) -> _Parsed | None:
    if not line.startswith("{"):
        return None
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    stamp, status = _json_timestamp(_first_present(record, _JSON_TIME_KEYS))
    message = _first_present(record, _JSON_MESSAGE_KEYS)
    extras: dict[str, Any] = {}
    for target, keys in (("username", _JSON_USER_KEYS), ("source_ip", _JSON_IP_KEYS), ("process", _JSON_PROC_KEYS)):
        value = _first_present(record, keys)
        if isinstance(value, (str, int)):
            extras[target] = str(value)[:128]
    severity = _first_present(record, _JSON_SEVERITY_KEYS)
    if isinstance(severity, (str, int)):
        extras["severity"] = str(severity).lower()[:32]
    extras["json"] = True
    text = message if isinstance(message, str) else line
    return stamp, status, text, extras


_PARSERS: dict[str, Callable[[str], _Parsed | None]] = {
    "json": _parse_json_line,
    "iso": _parse_iso_line,
    "syslog": _parse_syslog_line,
    "clf": _parse_clf_line,
}


def detect_format(lines: list[str]) -> str:
    """Pick the line format that matches most of the sampled non-indented lines."""
    sample = [line for line in lines if line.strip() and not line[:1].isspace()][:FORMAT_SAMPLE_LINES]
    if not sample:
        return "none"
    best, best_hits = "none", 0
    for name, parse in _PARSERS.items():
        hits = sum(1 for line in sample if parse(line.strip()) is not None)
        if hits > best_hits:
            best, best_hits = name, hits
    return best if best_hits / len(sample) >= FORMAT_MIN_RATIO else "none"


def _enrich(message: str, extras: dict[str, Any]) -> dict[str, Any]:
    out = dict(extras)
    if not out.get("source_ip"):
        ip = _IPV4_RE.search(message)
        if ip:
            out["source_ip"] = ip.group(0)
    if not out.get("username"):
        user = _USER_KV_RE.search(message) or _USER_FOR_RE.search(message)
        if user:
            out["username"] = user.group(1)
    if not out.get("process"):
        proc = _PROC_RE.match(message)
        if proc:
            out["process"] = proc.group(1)
            out["pid"] = int(proc.group(2))
    if not out.get("severity"):
        sev = _SEVERITY_RE.search(message[:60])
        if sev:
            word = sev.group(1).lower()
            out["severity"] = _SEVERITY_ALIASES.get(word, word)
    return out


def _row(source_path: str, line_number: int, raw: str, parsed: _Parsed | None, log_format: str) -> dict[str, Any]:
    stamp, status, message, extras = parsed if parsed else (None, "missing", raw, {})
    extras = _enrich(message, extras)
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": ARTIFACT_TYPE,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": stamp,
        "timestamp_status": status,
        "log_format": log_format,
        "host": extras.get("host"),
        "process": extras.get("process"),
        "pid": extras.get("pid"),
        "severity": extras.get("severity"),
        "username": extras.get("username"),
        "source_ip": extras.get("source_ip"),
        "message": message[:MAX_MESSAGE_CHARS],
        "raw_excerpt": raw[:MAX_MESSAGE_CHARS],
    }


def parse_generic_log(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict]:
    """Turn a free-form text log into one event per logical entry.

    Lines that do not start a new entry (stack traces, wrapped output) are folded into the
    entry before them. A file with no recognisable timestamps still yields one undated
    event per line, flagged ``timestamp_status="missing"``, so it stays searchable.
    Binary content yields nothing.
    """
    if looks_binary(content):
        return []
    lines = content.splitlines()
    log_format = detect_format(lines)
    parse = _PARSERS.get(log_format)

    rows: list[dict] = []
    continuation = 0
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parsed = parse(stripped) if parse else None
        if parsed is not None or parse is None or not rows:
            rows.append(_row(source_path, number, stripped, parsed, log_format))
            continuation = 0
            continue
        if continuation < MAX_CONTINUATION_LINES:
            previous = rows[-1]
            if len(previous["message"]) < MAX_MESSAGE_CHARS:
                previous["message"] = f"{previous['message']}\n{stripped}"[:MAX_MESSAGE_CHARS]
            continuation += 1

    if truncated:
        rows.append(_row(
            source_path,
            len(lines) + 1,
            "",
            (None, "missing", "[kairon] log truncated: only the first part of this file was parsed (size limit or damaged archive)", {}),
            log_format,
        ))
    return rows
