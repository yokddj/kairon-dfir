"""Windows push notification database (wpndatabase.db).

%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db is the SQLite
store behind the Action Center. It keeps the notifications still pending or
recently shown (toast text, tile content, badges) with the app that sent
them, and every app registered to send notifications with when it was
registered. Toasts often hold what is nowhere else: the preview of a mail or
chat message, a site's push message, a Defender or firewall warning.

The database runs in WAL mode and recent rows usually sit in -wal only, so it
is copied with its -wal/-shm into a scratch folder and opened there: SQLite
replays the WAL on that copy, never on the evidence. Rows come out in the
shape the Windows UI normalizer reads from notification CSV exports.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from xml.etree import ElementTree

from app.core.config import get_settings

WPNDATABASE_NAME = "wpndatabase.db"
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_SQLITE_MAGIC = b"SQLite format 3\x00"
_MAX_BODY = 2000


def is_wpndatabase(path: Path) -> bool:
    path = Path(path)
    if path.name.lower() != WPNDATABASE_NAME or not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC


def filetime_iso(value) -> str | None:
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    try:
        moment = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None
    return moment.isoformat() if 1990 <= moment.year <= 2100 else None


def handler_time_iso(value) -> str | None:
    """NotificationHandler times are SQLite UTC text on current builds and
    FILETIME integers on some older ones."""
    if isinstance(value, str) and not value.strip().isdigit():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).isoformat()
    return filetime_iso(value)


def _payload_text(payload) -> str:
    if payload is None:
        return ""
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload).decode("utf-8", errors="replace")
    return str(payload)


def payload_content(payload_type: str, raw: str) -> dict:
    """Title, body lines, launch target and image sources from a toast, tile
    or badge payload. A tile repeats its text once per size, so lines are
    deduplicated in order."""
    result: dict = {"title": None, "lines": [], "launch": None, "images": [], "status": []}
    text = raw.strip().lstrip("﻿")
    if not text.startswith("<"):
        result["lines"] = [line for line in re.split(r"[\r\n]+", text) if line.strip()][:20]
        return result
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        stripped = re.sub(r"<[^>]+>", " ", text)
        result["lines"] = [re.sub(r"\s+", " ", stripped).strip()][:1]
        return result
    if root.tag == "badge":
        value = root.get("value")
        result["title"] = f"Badge {value}" if value else "Badge"
        return result
    result["launch"] = root.get("launch") or None
    lines: list[str] = []
    for element in root.iter("text"):
        value = re.sub(r"\s+", " ", "".join(element.itertext())).strip()
        if value and value not in lines:
            lines.append(value)
    for element in root.iter("visual"):
        for key in ("hint-lockDetailedStatus1", "hint-lockDetailedStatus2", "hint-lockDetailedStatus3"):
            value = (element.get(key) or "").strip()
            if value and value not in result["status"]:
                result["status"].append(value)
    for element in root.iter("image"):
        source = (element.get("src") or "").strip()
        if source and source not in result["images"]:
            result["images"].append(source)
    if lines:
        result["title"] = lines[0]
        result["lines"] = lines[1:]
    elif result["status"]:
        result["title"] = result["status"][0]
        result["lines"] = result["status"][1:]
    return result


def _copy_with_wal(path: Path, scratch: Path) -> Path:
    target = scratch / path.name
    shutil.copy2(path, target)
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.is_file():
            shutil.copy2(sibling, scratch / sibling.name)
    return target


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}


def parse_wpndatabase(path: Path, *, source_path: str | None = None) -> tuple[list[dict], dict]:
    path = Path(path)
    source = source_path or str(path)
    audit: dict = {"records_read": 0, "records_parsed": 0, "records_failed": 0, "warnings": [], "parser_errors": []}
    if not path.with_name(path.name + "-wal").is_file():
        audit["warnings"].append("wpndatabase_wal_missing")
    rows: list[dict] = []
    with tempfile.TemporaryDirectory(dir=get_settings().backend_temp_dir) as scratch:
        try:
            connection = sqlite3.connect(_copy_with_wal(path, Path(scratch)))
        except sqlite3.Error as exc:
            audit["parser_errors"].append(f"open_failed: {exc}")
            return rows, audit
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"Notification", "NotificationHandler"} <= tables:
                audit["parser_errors"].append("not_a_notification_database")
                return rows, audit
            handler_columns = _columns(connection, "NotificationHandler")
            handlers = {
                record[0]: record
                for record in connection.execute(
                    "SELECT RecordId, PrimaryId, HandlerType, "
                    + ("CreatedTime, ModifiedTime" if {"CreatedTime", "ModifiedTime"} <= handler_columns else "NULL, NULL")
                    + " FROM NotificationHandler"
                )
            }
            note_columns = _columns(connection, "Notification")
            wanted = ["Id", "HandlerId", "Type", "Payload", "Tag", "Group", "ExpiryTime", "ArrivalTime", "PayloadType"]
            select = ", ".join(f'"{column}"' if column in note_columns else "NULL" for column in wanted)
            for record in connection.execute(f"SELECT {select} FROM Notification"):
                audit["records_read"] += 1
                try:
                    rows.append(_notification_row(dict(zip(wanted, record)), handlers, source))
                    audit["records_parsed"] += 1
                except Exception as exc:  # noqa: BLE001
                    audit["records_failed"] += 1
                    audit["parser_errors"].append(f"notification {record[0]}: {type(exc).__name__}: {exc}"[:300])
            for record_id, primary_id, handler_type, created, modified in handlers.values():
                audit["records_read"] += 1
                created_iso = handler_time_iso(created)
                # Windows' own handlers are all registered when the profile is created.
                if not created_iso or not primary_id or str(handler_type or "").lower() == "app:system":
                    continue
                rows.append({
                    "EventType": "notification_app_registered",
                    "WindowsUIParser": "windows_notifications",
                    "TimestampSource": "notification_handler_created",
                    "Timestamp": created_iso,
                    "CreatedTime": created_iso,
                    "ModifiedTime": handler_time_iso(modified),
                    "Title": f"Notification app registered: {primary_id}",
                    "AppId": primary_id,
                    "HandlerType": handler_type,
                    "HandlerRecordId": record_id,
                    "SourceFile": source,
                })
                audit["records_parsed"] += 1
        finally:
            connection.close()
    return rows, audit


def _notification_row(record: dict, handlers: dict, source: str) -> dict:
    handler = handlers.get(record.get("HandlerId")) or (None, None, None, None, None)
    payload_type = str(record.get("Type") or "").lower()
    raw = _payload_text(record.get("Payload"))
    content = payload_content(payload_type, raw)
    arrival = filetime_iso(record.get("ArrivalTime"))
    parts: list[str] = []
    for part in [*content["lines"], *content["status"]]:
        if part != content["title"] and part not in parts:
            parts.append(part)
    body = " | ".join(parts)
    is_markup = raw.strip().lstrip("\ufeff").startswith("<")
    return {
        "EventType": "notification_observed",
        "WindowsUIParser": "windows_notifications",
        "TimestampSource": "notification_arrival",
        "Timestamp": arrival,
        "CreatedTime": arrival,
        "ExpiryTime": filetime_iso(record.get("ExpiryTime")),
        "Title": content["title"] or f"{payload_type or 'notification'} from {handler[1] or 'unknown app'}",
        "Body": body[:_MAX_BODY] or None,
        "AppId": handler[1],
        "NotificationId": record.get("Id"),
        "NotificationType": payload_type or None,
        "Tag": record.get("Tag"),
        "Group": record.get("Group"),
        "LaunchUri": content["launch"],
        "Images": content["images"][:10],
        "PayloadPreview": raw[:_MAX_BODY] if not is_markup and not content["title"] and not body else None,
        "SourceFile": source,
    }
