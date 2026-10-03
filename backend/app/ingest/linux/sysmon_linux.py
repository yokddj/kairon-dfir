"""Sysmon for Linux events carried in syslog / the journal.

Sysmon for Linux writes each event as one line of Windows-style XML to syslog (tag ``sysmon``):

    <Event><System>...<EventID>1</EventID>...<Computer>web01</Computer></System>
    <EventData><Data Name="Image">/usr/bin/curl</Data><Data Name="CommandLine">curl http://...</Data>...

Until now those lines were plain syslog text: the process, its parent, the command line, the
connection and the file were buried inside an XML string. They are the structured events Sigma's
Linux ``process_creation``, ``network_connection`` and ``file_event`` rules were written for, so
extracting them is what lets those rules match real process and network activity rather than only
typed shell history.

The input is untrusted evidence, so this does not use an XML parser (no entity expansion, no
external references): it reads the fixed ``<EventID>``, ``<Computer>``, ``<TimeCreated>`` and
``<Data Name="...">`` shapes with bounded regular expressions, on at most ``MAX_EVENT_CHARS``.
"""
from __future__ import annotations

import html
import posixpath
import re
from datetime import datetime, timezone
from typing import Any

MARKER = "Linux-Sysmon"
MAX_EVENT_CHARS = 64 * 1024
MAX_DATA_ITEMS = 128
MAX_VALUE_CHARS = 4000

_EVENT_ID_RE = re.compile(r"<EventID>(\d{1,4})</EventID>")
_COMPUTER_RE = re.compile(r"<Computer>([^<]{0,255})</Computer>")
_TIME_RE = re.compile(r'<TimeCreated SystemTime="([^"]{1,40})"')
_DATA_RE = re.compile(r'<Data Name="([A-Za-z0-9_]{1,64})"(?:/>|>(.*?)</Data>)', re.S)

# Event ids Sysmon for Linux emits. label = the event.type Kairon's Sigma logsource gate recognises.
EVENTS: dict[int, tuple[str, str]] = {
    1: ("process_created", "sysmon_process_created"),
    3: ("network_connection", "sysmon_network_connection"),
    4: ("sysmon_state_changed", "sysmon_state_changed"),
    5: ("process_terminated", "sysmon_process_terminated"),
    9: ("raw_access_read", "sysmon_raw_access_read"),
    11: ("file_created", "sysmon_file_created"),
    16: ("config_changed", "sysmon_config_changed"),
    23: ("file_deleted", "sysmon_file_deleted"),
}


def looks_like_sysmon_event(message: str) -> bool:
    return "<Event" in message and MARKER in message


def _datetime(value: str) -> str | None:
    text = value.strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    elif "+" not in text[10:] and "-" not in text[10:]:
        text += "+00:00"
    # fromisoformat accepts at most 6 fractional digits; Sysmon writes 7-9.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() and 0 <= int(value) <= 65535 else None


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def _clean(value: str | None) -> str:
    text = html.unescape(value or "").strip()
    return "" if text in {"-", "(null)"} else text[:MAX_VALUE_CHARS]


def _sha256(hashes: str) -> str:
    match = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes)
    return match.group(1).lower() if match else ""


def _summary(code: int, d: dict[str, str]) -> str:
    image = d.get("Image", "")
    if code == 1:
        parent = d.get("ParentImage", "")
        return f"Process created: {d.get('CommandLine') or image}" + (f" (parent {parent})" if parent else "")
    if code == 3:
        arrow = "->" if d.get("Initiated", "true").lower() != "false" else "<-"
        remote = d.get("DestinationIp", "") + (f":{d['DestinationPort']}" if d.get("DestinationPort") else "")
        return f"Network connection {arrow} {remote or d.get('DestinationHostname', '')} by {image}".strip()
    if code == 5:
        return f"Process terminated: {image}"
    if code == 11:
        return f"File created: {d.get('TargetFilename', '')} by {image}".strip()
    if code == 23:
        return f"File deleted: {d.get('TargetFilename', '')} by {image}".strip()
    return f"Sysmon event {code}" + (f": {image}" if image else "")


def parse_sysmon_event(message: str) -> dict[str, Any] | None:
    """Fields of a Sysmon for Linux event line, or None when the text is not one."""
    if not looks_like_sysmon_event(message):
        return None
    text = message[:MAX_EVENT_CHARS]
    id_match = _EVENT_ID_RE.search(text)
    if not id_match:
        return None
    code = int(id_match.group(1))
    data: dict[str, str] = {}
    for count, match in enumerate(_DATA_RE.finditer(text)):
        if count >= MAX_DATA_ITEMS:
            break
        data[match.group(1)] = _clean(match.group(2))
    if not data:
        return None

    name, label = EVENTS.get(code, (f"event_{code}", f"sysmon_event_{code}"))
    time_match = _TIME_RE.search(text)
    stamp = _datetime(time_match.group(1)) if time_match else None
    if stamp is None and data.get("UtcTime"):
        stamp = _datetime(data["UtcTime"])
    image = data.get("Image", "")
    computer = _COMPUTER_RE.search(text)

    out: dict[str, Any] = {
        "sysmon_event_id": code,
        "sysmon_event": name,
        "event_label": label,
        "timestamp": stamp,
        "timestamp_status": "ok" if stamp else "missing",
        "message": _summary(code, data)[:2000],
        "image": image,
        "process": posixpath.basename(image) if image else None,
        "exe": image,
        "pid": _int(data.get("ProcessId")),
        "username": data.get("User") or None,
        "process_guid": data.get("ProcessGuid", ""),
        "current_directory": data.get("CurrentDirectory", ""),
        "hashes": data.get("Hashes", ""),
        "sha256": _sha256(data.get("Hashes", "")),
    }
    if computer and _clean(computer.group(1)):
        out["host"] = _clean(computer.group(1))
    if code == 1:
        out.update({
            "command": data.get("CommandLine", ""),
            "command_line": data.get("CommandLine", ""),
            "parent_image": data.get("ParentImage", ""),
            "parent_command_line": data.get("ParentCommandLine", ""),
            "parent_pid": _int(data.get("ParentProcessId")),
            "parent_guid": data.get("ParentProcessGuid", ""),
            "parent_user": data.get("ParentUser", ""),
        })
    elif code == 3:
        out.update({
            "network_protocol": data.get("Protocol", "").lower(),
            "initiated": data.get("Initiated", "").lower() != "false",
            "source_ip": data.get("SourceIp", ""),
            "source_port": _port(data.get("SourcePort")),
            "destination_ip": data.get("DestinationIp", ""),
            "destination_port": _port(data.get("DestinationPort")),
            "destination_hostname": data.get("DestinationHostname", ""),
        })
    elif code in {11, 23}:
        out["target_filename"] = data.get("TargetFilename", "")
    return out


def enrich_with_sysmon(row: dict[str, Any], message: str) -> dict[str, Any]:
    """Merge a Sysmon for Linux event into a parsed syslog/journal row, in place.

    The original line is kept in ``raw_excerpt``; ``message`` becomes a readable summary.
    """
    event = parse_sysmon_event(message)
    if event is None:
        return row
    if not row.get("raw_excerpt"):
        row["raw_excerpt"] = message[:2000]
    for key, value in event.items():
        if key == "host":
            # The syslog header already names the host; fall back to the event's own Computer.
            row["host"] = row.get("host") or value
        elif value not in (None, "") or key == "timestamp":
            row[key] = value
    return row
