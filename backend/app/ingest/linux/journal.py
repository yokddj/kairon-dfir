from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.ingest.linux.netfilter import enrich_with_netfilter


def _normalize_timestamp(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        number = int(raw)
        if number > 10_000_000_000_000:
            number = number // 1_000_000
        elif number > 10_000_000_000:
            number = number // 1_000
        return datetime.fromtimestamp(number, tz=UTC).isoformat()
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC).isoformat()
    except ValueError:
        return raw


def _row_from_fields(fields: dict[str, object], source_path: str) -> dict[str, object]:
    message = str(fields.get("MESSAGE") or fields.get("message") or "").strip()
    process = str(fields.get("SYSLOG_IDENTIFIER") or fields.get("_COMM") or fields.get("process") or "").strip() or None
    hostname = str(fields.get("_HOSTNAME") or fields.get("hostname") or "").strip() or None
    username = str(fields.get("_UID") or fields.get("uid") or fields.get("user") or "").strip() or None
    pid = str(fields.get("_PID") or fields.get("pid") or "").strip() or None
    priority = str(fields.get("PRIORITY") or fields.get("priority") or "").strip() or None
    action = str(fields.get("_SYSTEMD_UNIT") or fields.get("UNIT") or fields.get("unit") or process or "journal_event").strip()
    row = {
        "timestamp": _normalize_timestamp(fields.get("__REALTIME_TIMESTAMP") or fields.get("timestamp") or fields.get("_SOURCE_REALTIME_TIMESTAMP")),
        "message": message,
        "hostname": hostname,
        "username": username,
        "process": process,
        "pid": pid,
        "event_action": action,
        "severity": priority,
        "artifact_family": "linux_journal",
        "artifact_type": "linux_journal",
        "source_path": source_path,
    }
    return enrich_with_netfilter(row, message)


def _parse_export_blocks(text: str, source_path: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    current: dict[str, object] = {}
    for line in text.splitlines():
        stripped = line.rstrip("\n")
        if not stripped.strip():
            if current:
                records.append(_row_from_fields(current, source_path))
                current = {}
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        current[key.strip()] = value.strip()
    if current:
        records.append(_row_from_fields(current, source_path))
    return records


def parse_journal(text: str, *, source_path: str | None = None) -> list[dict[str, object]]:
    path = str(source_path or "")
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(_row_from_fields(payload, path))
    if rows:
        return rows
    return _parse_export_blocks(text, path)


_MAX_FIELD_CHARS = 4000


def _realtime_iso(microseconds: int) -> str | None:
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_journal_binary_file(path: Path, *, source_path: str | None = None) -> list[dict[str, object]]:
    """Parse a binary systemd journal file into the same rows the text exports produce.

    Adds what only the binary form carries: the exact microsecond time, executable, unit,
    transport, boot id, uid/gid and the entry's sequence number.
    """
    from app.ingest.linux.journal_binary import read_journal_entries

    source = str(source_path or path)
    entries, info = read_journal_entries(path)
    rows: list[dict[str, object]] = []
    for seqnum, realtime, boot_id, raw in entries:
        fields = {name: value.decode("utf-8", "replace")[:_MAX_FIELD_CHARS] for name, value in raw.items()}
        row = _row_from_fields(fields, source)
        row["timestamp"] = _realtime_iso(realtime)
        row["seqnum"] = seqnum
        row["boot_id"] = boot_id.hex()
        for key, name in (("exe", "_EXE"), ("unit", "_SYSTEMD_UNIT"), ("transport", "_TRANSPORT"), ("uid", "_UID"), ("gid", "_GID")):
            value = fields.get(name)
            if value:
                row[key] = value
        rows.append(row)
    notes = []
    if info.get("truncated"):
        notes.append("the file is damaged or larger than the entry limit, so only the entries read before that point are shown")
    if info.get("undecodable_fields"):
        notes.append(f"{info['undecodable_fields']} compressed field(s) could not be decoded")
    if notes:
        marker = _row_from_fields({"MESSAGE": "[kairon] binary journal incomplete: " + "; ".join(notes)}, source)
        marker["timestamp"] = None
        rows.append(marker)
    return rows
