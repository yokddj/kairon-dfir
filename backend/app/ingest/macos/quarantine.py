"""QuarantineEventsV2: files macOS marked as downloaded from the internet (Gatekeeper quarantine).

LaunchServices adds a row when an app that sets the quarantine attribute (browsers, mail, chat,
AirDrop, curl with -O does not) writes a downloaded file: which app, when, and -- when the app said
so -- the URL of the data and of the page it came from. The file name itself is not recorded here.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ingest.macos.common import cocoa_to_iso, open_sqlite_copy, table_columns, user_from_path

ARTIFACT_FAMILY = "macos_quarantine"
# LSQuarantineTypeNumber, from LSQuarantine.h.
_QUARANTINE_TYPES = {
    0: "web download",
    1: "other download",
    2: "email attachment",
    3: "instant message attachment",
    4: "calendar event attachment",
    5: "other attachment",
}


def parse_quarantine_events(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    username = user_from_path(source_path)
    rows: list[dict[str, Any]] = []
    with open_sqlite_copy(path) as connection:
        columns = table_columns(connection, "LSQuarantineEvent")
        if "LSQuarantineTimeStamp" not in columns:
            return []
        wanted = [
            column for column in (
                "LSQuarantineEventIdentifier", "LSQuarantineTimeStamp", "LSQuarantineAgentBundleIdentifier", "LSQuarantineAgentName",
                "LSQuarantineDataURLString", "LSQuarantineSenderName", "LSQuarantineSenderAddress", "LSQuarantineTypeNumber",
                "LSQuarantineOriginTitle", "LSQuarantineOriginURLString", "LSQuarantineOriginAlias",
            ) if column in columns
        ]
        select = ", ".join(f'"{column}"' for column in wanted if column != "LSQuarantineOriginAlias")
        for index, record in enumerate(connection.execute(f"SELECT {select} FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp"), start=1):
            data = dict(record)
            agent = str(data.get("LSQuarantineAgentName") or data.get("LSQuarantineAgentBundleIdentifier") or "an unknown app")
            data_url = str(data.get("LSQuarantineDataURLString") or "")
            origin_url = str(data.get("LSQuarantineOriginURLString") or "")
            kind = _QUARANTINE_TYPES.get(data.get("LSQuarantineTypeNumber"), "download")
            where = f" from {data_url}" if data_url else (f" (page {origin_url})" if origin_url else "")
            rows.append({
                "artifact_family": ARTIFACT_FAMILY,
                "artifact_type": "quarantine_event",
                "source_file": source_path,
                "line_number": index,
                "timestamp": cocoa_to_iso(data.get("LSQuarantineTimeStamp")),
                "event_action": "file_quarantined",
                "username": username,
                "quarantine_id": data.get("LSQuarantineEventIdentifier") or "",
                "agent_name": data.get("LSQuarantineAgentName") or "",
                "agent_bundle_id": data.get("LSQuarantineAgentBundleIdentifier") or "",
                "data_url": data_url,
                "origin_url": origin_url,
                "origin_title": data.get("LSQuarantineOriginTitle") or "",
                "sender_name": data.get("LSQuarantineSenderName") or "",
                "sender_address": data.get("LSQuarantineSenderAddress") or "",
                "quarantine_type": kind,
                "message": f"{agent} saved a quarantined {kind}{where}",
            })
    return rows
