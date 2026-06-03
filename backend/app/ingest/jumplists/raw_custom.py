from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ingest.jumplists.helpers import infer_jumplist_user, source_file_mtime_iso
from app.ingest.jumplists.raw_lnk import is_shell_link_bytes, parse_shell_link_bytes


SHELL_LINK_SIGNATURE = bytes.fromhex("4C0000000114020000000000C000000000000046")


def _find_shell_link_offsets(data: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while True:
        index = data.find(SHELL_LINK_SIGNATURE, cursor)
        if index == -1:
            break
        offsets.append(index)
        cursor = index + 4
    return offsets


def parse_custom_destinations_file(
    path: Path,
    *,
    source_path: str | None = None,
    app_id: str | None = None,
    user: str | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    source = source_path or str(path)
    inferred_user = user or infer_jumplist_user(source)
    warnings: list[str] = []
    audit: dict[str, Any] = {
        "raw_custom_files_read": 1,
        "lnk_streams_seen": 0,
        "lnk_streams_parsed": 0,
        "entries_parsed": 0,
        "skipped_low_value_records": 0,
        "parse_errors": 0,
    }
    try:
        data = path.read_bytes()
    except Exception as exc:  # noqa: BLE001
        return [], [f"Failed to read customDestinations file: {exc}"], {**audit, "parse_errors": 1}

    offsets = _find_shell_link_offsets(data)
    audit["lnk_streams_seen"] = len(offsets)
    if not offsets:
        warnings.append("No ShellLink signature found in customDestinations file.")
        return [], warnings, audit

    source_mtime = source_file_mtime_iso(path)
    rows: list[dict[str, Any]] = []
    for index, start in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        chunk = data[start:end]
        if not is_shell_link_bytes(chunk):
            continue
        parsed, chunk_warnings = parse_shell_link_bytes(chunk, stream_name=f"custom-{index}")
        warnings.extend(f"custom-{index}: {warning}" for warning in chunk_warnings)
        if not parsed:
            continue
        audit["lnk_streams_parsed"] += 1
        row = {
            "ArtifactType": "custom_destinations",
            "SourceFile": source,
            "SourceFileMtime": source_mtime,
            "AppId": app_id,
            "DestinationType": "custom",
            "EntryNumber": index,
            "StreamName": f"custom-{index}",
            "ParseMethod": "custom_lnk_scan",
            "ParseWarnings": " | ".join(chunk_warnings) if chunk_warnings else None,
            "UserName": inferred_user,
            **parsed,
        }
        useful = bool(
            row.get("LocalPath")
            or row.get("TargetPath")
            or row.get("NetworkPath")
            or row.get("TargetAccessed")
            or row.get("TargetModified")
            or row.get("TargetCreated")
            or row.get("Description")
        )
        if not useful:
            audit["skipped_low_value_records"] += 1
            continue
        rows.append(row)
    audit["entries_parsed"] = len(rows)
    if not rows:
        warnings.append("customDestinations parsing is partial and no high-value ShellLink entries were extracted from this file.")
    return rows, warnings, audit


__all__ = ["parse_custom_destinations_file"]
