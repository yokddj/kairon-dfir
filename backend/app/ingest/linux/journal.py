from __future__ import annotations

import json
from datetime import UTC, datetime


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
    return {
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
