from __future__ import annotations

import csv
import json
from pathlib import Path

from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.windows_ui.helpers import canonicalize_header, clean_value, is_windows_ui_raw_candidate


def _read_structured_rows(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        ensure_csv_field_limit()
        with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            if isinstance(payload.get("rows"), list):
                return [item for item in payload["rows"] if isinstance(item, dict)]
            return [payload]
    if suffix == ".jsonl":
        rows: list[dict] = []
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
        return rows
    return []


def _infer_parser_name(path: Path, headers: set[str], sample_row: dict | None = None) -> str:
    lower_name = path.name.lower()
    if "thumbnailcacheid" in headers or "cacheentryhash" in headers or "thumbnailpath" in headers or "thumbcache" in lower_name:
        return "windows_thumbcache"
    if lower_name == "thumbs.db" or ("thumbs" in lower_name and "thumbnail" in headers):
        return "windows_thumbsdb"
    if {"notificationid", "toast", "title", "bodypreview"} & headers or "wpndatabase" in lower_name or "notification" in lower_name:
        return "windows_notifications"
    if {"activityid", "displaytext", "activationuri"} & headers or "activitiescache" in lower_name:
        return "windows_activitiescache"
    if "indexedpath" in headers or ("windows" in lower_name and ".edb" in lower_name):
        return "windows_search_index"
    if ("eventtext" in headers or "provider" in headers) and "eventtranscript" in lower_name:
        return "windows_eventtranscript"
    if "alerttext" in headers or "oalerts" in lower_name or "protected view" in " ".join(str(v).lower() for v in (sample_row or {}).values()):
        return "office_oalerts_evtx"
    if "cacheid" in headers or "officefilecache" in lower_name or "office_filecache" in lower_name:
        return "office_filecache"
    if "backstage" in lower_name or ("documentpath" in headers and "officeapp" in headers):
        return "office_backstage"
    return "windows_ui_generic_raw"


def parse_windows_ui_artifact_file(path: Path, artifact_meta: dict) -> tuple[list[dict], dict]:
    parser_name = str(artifact_meta.get("parser") or "").lower()
    source_path = str(artifact_meta.get("source_path") or path)
    if parser_name == "windows_ui_generic_raw" or is_windows_ui_raw_candidate(path):
        row = {
            "EventType": "ui_artifact_observed",
            "WindowsUIParser": "windows_ui_generic_raw",
            "WindowsUISource": "raw",
            "FilePath": source_path,
            "FileName": path.name,
            "UnsupportedReason": "unsupported_windows_ui_raw_parsing_not_enabled",
            "ParserStatus": "detected_not_implemented",
            "TimestampSource": "source_file",
        }
        return [row], {
            "records_read": 1,
            "records_parsed": 1,
            "records_failed": 0,
            "warnings": ["raw_windows_ui_inventory_only"],
            "parser_errors": [],
        }

    rows = _read_structured_rows(path)
    if not rows:
        return [], {
            "records_read": 0,
            "records_parsed": 0,
            "records_failed": 0,
            "warnings": ["windows_ui_no_rows"],
            "parser_errors": [],
        }

    normalized_rows: list[dict] = []
    for row in rows:
        parser_for_row = parser_name if parser_name.startswith(("windows_", "office_")) and parser_name != "windows_ui_generic_raw" else _infer_parser_name(path, {canonicalize_header(header) for header in row.keys()}, row)
        normalized = dict(row)
        normalized["WindowsUIParser"] = parser_for_row
        normalized["WindowsUISource"] = parser_for_row.removeprefix("windows_").removeprefix("office_")
        if not clean_value(normalized.get("SourceFile")):
            normalized["SourceFile"] = source_path
        normalized_rows.append(normalized)
    return normalized_rows, {
        "records_read": len(rows),
        "records_parsed": len(normalized_rows),
        "records_failed": 0,
        "warnings": [],
        "parser_errors": [],
    }
