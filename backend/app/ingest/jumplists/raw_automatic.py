from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

try:
    import olefile  # type: ignore
except Exception:  # noqa: BLE001
    olefile = None

from app.ingest.jumplists.helpers import infer_jumplist_user, source_file_mtime_iso
from app.ingest.jumplists.raw_lnk import is_shell_link_bytes, parse_shell_link_bytes


def _stream_name(parts: list[str] | tuple[str, ...]) -> str:
    return "/".join(str(part) for part in parts)


def _parse_destlist(data: bytes) -> tuple[dict[str, dict[str, Any]], list[str], dict[str, Any]]:
    warnings: list[str] = []
    if not data:
        return {}, ["DestList stream is empty"], {"destlist_streams_seen": 1, "destlist_entries_seen": 0}
    header = {
        "destlist_streams_seen": 1,
        "destlist_entries_seen": 0,
        "destlist_version": int.from_bytes(data[:4], "little", signed=False) if len(data) >= 4 else None,
    }
    # Best effort only for now. We keep the stream visible and parse LNK streams even if DestList is opaque.
    warnings.append("DestList stream detected but only partial header parsing is available; LNK streams were parsed directly.")
    return {}, warnings, header


def parse_automatic_destinations_file(
    path: Path,
    *,
    source_path: str | None = None,
    app_id: str | None = None,
    user: str | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    warnings: list[str] = []
    audit: dict[str, Any] = {
        "raw_automatic_files_read": 1,
        "ole_streams_seen": 0,
        "destlist_streams_seen": 0,
        "lnk_streams_seen": 0,
        "lnk_streams_parsed": 0,
        "entries_parsed": 0,
        "skipped_low_value_records": 0,
        "parse_errors": 0,
    }
    source = source_path or str(path)
    inferred_user = user or infer_jumplist_user(source)
    source_mtime = source_file_mtime_iso(path)

    if olefile is None:
        warnings.append("olefile dependency is not available; raw automaticDestinations parsing skipped.")
        audit["parse_errors"] = 1
        return [], warnings, audit
    try:
        if not olefile.isOleFile(str(path)):
            warnings.append("automaticDestinations file is not a valid OLE Compound File.")
            audit["parse_errors"] = 1
            return [], warnings, audit
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Failed to open automaticDestinations OLE file: {exc}")
        audit["parse_errors"] = 1
        return [], warnings, audit

    rows: list[dict[str, Any]] = []
    try:
        streams = ole.listdir(streams=True, storages=False)
        audit["ole_streams_seen"] = len(streams)
        destlist_map: dict[str, dict[str, Any]] = {}
        for stream_parts in streams:
            name = _stream_name(stream_parts)
            lower_name = name.lower()
            try:
                stream = ole.openstream(stream_parts)
                data = stream.read()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to read stream {name}: {exc}")
                continue
            if lower_name == "destlist":
                destlist_map, dest_warnings, dest_audit = _parse_destlist(data)
                warnings.extend(dest_warnings)
                for key, value in dest_audit.items():
                    audit[key] = value
                continue
            if not is_shell_link_bytes(data):
                continue
            audit["lnk_streams_seen"] += 1
            parsed, stream_warnings = parse_shell_link_bytes(data, stream_name=name)
            warnings.extend(f"{name}: {warning}" for warning in stream_warnings)
            if not parsed:
                continue
            audit["lnk_streams_parsed"] += 1
            meta = destlist_map.get(name) or {}
            row = {
                "ArtifactType": "automatic_destinations",
                "SourceFile": source,
                "SourceFileMtime": source_mtime,
                "AppId": app_id,
                "DestinationType": "automatic",
                "EntryNumber": name,
                "StreamName": name,
                "ParseMethod": "ole_lnk_stream",
                "ParseWarnings": " | ".join(stream_warnings) if stream_warnings else None,
                "UserName": inferred_user,
                **parsed,
            }
            row.update(meta)
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
    finally:
        try:
            ole.close()
        except Exception:  # noqa: BLE001
            pass
    return rows, warnings, audit


__all__ = ["parse_automatic_destinations_file"]
