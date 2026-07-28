"""Parser for Linux /var/log/lastlog binary records."""
from __future__ import annotations

import ipaddress
import struct
from datetime import datetime, timezone


_LASTLOG_LAYOUTS = (
    (struct.Struct("<i32s256s"), "linux_lastlog_32"),
    (struct.Struct("<q32s256s"), "linux_lastlog_64"),
)
_MAX_TIMESTAMP = 4_102_444_800  # 2100-01-01 UTC, rejects corrupt sparse noise.
_MAX_SCAN_RECORDS = 131_072


def _clean_bytes(value: bytes) -> str:
    return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _parse_passwd(passwd_content: str | bytes | None) -> dict[int, str]:
    if isinstance(passwd_content, bytes):
        passwd_content = passwd_content.decode("utf-8", errors="replace")
    users: dict[int, str] = {}
    for line in (passwd_content or "").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        name = parts[0].strip()
        if name:
            users[uid] = name
    return users


def _host_fields(host: str) -> tuple[str, str]:
    if not host:
        return "", ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "", host
    return host, ""


def _candidate_layout(content: bytes) -> tuple[struct.Struct, str] | None:
    best: tuple[int, struct.Struct, str] | None = None
    for layout, layout_name in _LASTLOG_LAYOUTS:
        if len(content) < layout.size:
            continue
        records = min(len(content) // layout.size, _MAX_SCAN_RECORDS)
        score = 0
        for index in range(records):
            offset = index * layout.size
            chunk = content[offset:offset + layout.size]
            if not chunk or chunk == b"\x00" * len(chunk):
                continue
            try:
                seconds, terminal_raw, host_raw = layout.unpack(chunk)
            except struct.error:
                continue
            terminal = _clean_bytes(terminal_raw)
            host = _clean_bytes(host_raw)
            if 0 < int(seconds) <= _MAX_TIMESTAMP and (terminal or host):
                score += 1
        if score and (best is None or score > best[0]):
            best = (score, layout, layout_name)
    if best is None:
        return None
    return best[1], best[2]


def parse_lastlog(content: bytes, *, source_path: str = "", passwd_content: str | bytes | None = None) -> list[dict]:
    if not content:
        return []
    selected = _candidate_layout(content)
    if selected is None:
        return []
    layout, layout_name = selected
    users = _parse_passwd(passwd_content)
    rows: list[dict] = []
    record_count = min(len(content) // layout.size, _MAX_SCAN_RECORDS)
    for uid in range(record_count):
        offset = uid * layout.size
        chunk = content[offset:offset + layout.size]
        if len(chunk) != layout.size or chunk == b"\x00" * len(chunk):
            continue
        try:
            seconds, terminal_raw, host_raw = layout.unpack(chunk)
        except struct.error:
            continue
        seconds = int(seconds)
        if seconds <= 0 or seconds > _MAX_TIMESTAMP:
            continue
        terminal = _clean_bytes(terminal_raw)
        host = _clean_bytes(host_raw)
        if not terminal and not host:
            continue
        source_ip, remote_host = _host_fields(host)
        username = users.get(uid, "")
        timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        identity = username or f"uid={uid}"
        message = f"lastlog {identity} terminal={terminal or '-'} source={host or '-'}"
        rows.append({
            "artifact_family": "linux_lastlog",
            "artifact_type": "lastlog",
            "source_file": source_path,
            "timestamp": timestamp,
            "timestamp_status": "valid",
            "username": username,
            "uid": uid,
            "process": "login",
            "service": "login",
            "source_ip": source_ip,
            "remote_host": remote_host,
            "lastlog_host": host,
            "terminal": terminal,
            "lastlog_tty": terminal,
            "event_action": "last_login_record",
            "auth_event_type": "login_success",
            "authentication_result": "success",
            "event_outcome": "success",
            "record_type": layout_name,
            "record_offset": offset,
            "record_size": layout.size,
            "message": message,
            "raw_excerpt": message,
        })
    return rows
