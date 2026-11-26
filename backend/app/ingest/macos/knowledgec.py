"""knowledgeC.db: CoreDuet's record of app, web and device activity (Screen Time's data source).

Each ZOBJECT row is an interval on a named stream (``/app/usage``, ``/app/webUsage``...) with a start
and end time. Only streams whose meaning is documented and stable across macOS releases are read:

* ``/app/usage``, ``/app/inFocus``, ``/app/activity``: an application was in use, by bundle id.
* ``/app/webUsage``: a web page was in use in a browser (URL and domain when recorded).
* ``/app/mediaUsage``: media was playing in an app (its page URL when recorded).
* ``/app/intents``: an app donated an intent (an action such as sending a message).
* ``/display/isBacklit``, ``/device/isLocked``: screen on/off, device locked/unlocked.
* ``/bluetooth/isConnected``: a Bluetooth device was connected (name and address).
* ``/notification/usage``: a notification was received or acted on, by app.

The user's own database lives in ``~/Library/Application Support/Knowledge/``; older releases kept
a system-wide one in ``/private/var/db/CoreDuet/Knowledge/``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ingest.macos.common import cocoa_to_iso, open_sqlite_copy, table_columns, user_from_path

ARTIFACT_FAMILY = "macos_knowledgec"
_APP_STREAMS = {"/app/usage": "app_usage", "/app/inFocus": "app_in_focus", "/app/activity": "app_activity"}
_STREAMS = {
    **_APP_STREAMS,
    "/app/webUsage": "web_usage",
    "/app/mediaUsage": "media_usage",
    "/app/intents": "app_intent",
    "/display/isBacklit": "display_backlight",
    "/device/isLocked": "device_lock",
    "/bluetooth/isConnected": "bluetooth_connection",
    "/notification/usage": "notification",
}
# Structured-metadata columns read when present (they vary between releases).
_METADATA_COLUMNS = {
    "web_url": "Z_DKDIGITALHEALTHMETADATAKEY__WEBPAGEURL",
    "web_domain": "Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN",
    "media_url": "Z_DKAPPMEDIAUSAGEMETADATAKEY__URL",
    "intent_class": "Z_DKINTENTMETADATAKEY__INTENTCLASS",
    "intent_verb": "Z_DKINTENTMETADATAKEY__INTENTVERB",
    "bluetooth_name": "Z_DKBLUETOOTHMETADATAKEY__NAME",
    "bluetooth_address": "Z_DKBLUETOOTHMETADATAKEY__ADDRESS",
    "notification_bundle": "Z_DKNOTIFICATIONUSAGEMETADATAKEY__BUNDLEID",
}


def _duration(start: Any, end: Any) -> float | None:
    try:
        value = float(end) - float(start)
    except (TypeError, ValueError):
        return None
    return round(value, 3) if value >= 0 else None


def _message(kind: str, row: dict[str, Any]) -> str:
    app = row.get("bundle_id") or "an app"
    seconds = row.get("duration_seconds")
    span = f" for {int(seconds)}s" if seconds else ""
    if kind in _APP_STREAMS.values():
        return f"Application in use: {app}{span}"
    if kind == "web_usage":
        return f"Web page in use in {app}: {row.get('url') or row.get('web_domain') or 'unknown page'}{span}"
    if kind == "media_usage":
        return f"Media playing in {app}" + (f": {row['url']}" if row.get("url") else "") + span
    if kind == "app_intent":
        action = " ".join(part for part in (row.get("intent_verb"), row.get("intent_class")) if part)
        return f"App intent from {app}" + (f": {action}" if action else "")
    if kind == "display_backlight":
        return "Display turned on" if row.get("value") == 1 else "Display turned off"
    if kind == "device_lock":
        return "Device locked" if row.get("value") == 1 else "Device unlocked"
    if kind == "bluetooth_connection":
        device = row.get("bluetooth_name") or row.get("bluetooth_address") or "a device"
        return f"Bluetooth device connected: {device}{span}"
    if kind == "notification":
        return f"Notification {str(row.get('value_text') or '').lower() or 'event'} for {row.get('bundle_id') or 'an app'}"
    return kind


def parse_knowledgec(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    username = user_from_path(source_path)
    rows: list[dict[str, Any]] = []
    with open_sqlite_copy(path) as connection:
        object_columns = table_columns(connection, "ZOBJECT")
        if not {"ZSTREAMNAME", "ZSTARTDATE"} <= object_columns:
            return []
        metadata_columns = table_columns(connection, "ZSTRUCTUREDMETADATA")
        source_columns = table_columns(connection, "ZSOURCE")
        selected_metadata = {alias: column for alias, column in _METADATA_COLUMNS.items() if column in metadata_columns}
        metadata_select = "".join(f', m."{column}" AS "{alias}"' for alias, column in selected_metadata.items())
        join_metadata = "LEFT JOIN ZSTRUCTUREDMETADATA m ON m.Z_PK = o.ZSTRUCTUREDMETADATA" if selected_metadata and "ZSTRUCTUREDMETADATA" in object_columns else ""
        if not join_metadata:
            metadata_select = ""
        source_select = ', s.ZBUNDLEID AS source_bundle_id' if "ZBUNDLEID" in source_columns and "ZSOURCE" in object_columns else ""
        join_source = "LEFT JOIN ZSOURCE s ON s.Z_PK = o.ZSOURCE" if source_select else ""
        value_integer = "o.ZVALUEINTEGER" if "ZVALUEINTEGER" in object_columns else "NULL"
        value_string = "o.ZVALUESTRING" if "ZVALUESTRING" in object_columns else "NULL"
        end_date = "o.ZENDDATE" if "ZENDDATE" in object_columns else "NULL"
        offset = "o.ZSECONDSFROMGMT" if "ZSECONDSFROMGMT" in object_columns else "NULL"
        placeholders = ",".join("?" for _ in _STREAMS)
        query = (
            f"SELECT o.Z_PK AS pk, o.ZSTREAMNAME AS stream, o.ZSTARTDATE AS start_date, {end_date} AS end_date, "
            f"{value_string} AS value_text, {value_integer} AS value_integer, {offset} AS gmt_offset"
            f"{metadata_select}{source_select} FROM ZOBJECT o {join_metadata} {join_source} "
            f"WHERE o.ZSTREAMNAME IN ({placeholders}) ORDER BY o.ZSTARTDATE"
        )
        for record in connection.execute(query, tuple(_STREAMS)):
            data = dict(record)
            kind = _STREAMS[str(data["stream"])]
            row: dict[str, Any] = {
                "artifact_family": ARTIFACT_FAMILY,
                "artifact_type": kind,
                "source_file": source_path,
                "line_number": data.get("pk"),
                "timestamp": cocoa_to_iso(data.get("start_date")),
                "end_time": cocoa_to_iso(data.get("end_date")),
                "duration_seconds": _duration(data.get("start_date"), data.get("end_date")),
                "stream": data["stream"],
                "username": username,
                "event_action": kind,
                "gmt_offset_seconds": data.get("gmt_offset"),
                "value": data.get("value_integer"),
                "value_text": data.get("value_text") or "",
            }
            if kind in _APP_STREAMS.values() or kind in {"web_usage", "media_usage"}:
                row["bundle_id"] = data.get("value_text") or ""
            elif kind == "app_intent":
                row["bundle_id"] = data.get("source_bundle_id") or ""
                row["intent_class"] = data.get("intent_class") or ""
                row["intent_verb"] = data.get("intent_verb") or ""
                # ZVALUESTRING of an intent names the app ("Messages"), not a bundle id.
                row["app_name"] = data.get("value_text") or ""
            elif kind == "notification":
                row["bundle_id"] = data.get("notification_bundle") or ""
            elif kind == "bluetooth_connection":
                row["bluetooth_name"] = data.get("bluetooth_name") or ""
                row["bluetooth_address"] = data.get("bluetooth_address") or ""
            if kind == "web_usage":
                row["url"] = data.get("web_url") or ""
                row["web_domain"] = data.get("web_domain") or ""
            elif kind == "media_usage":
                row["url"] = data.get("media_url") or ""
            row["message"] = _message(kind, row)
            rows.append(row)
    return rows
