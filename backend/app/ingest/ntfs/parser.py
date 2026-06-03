from __future__ import annotations

import csv
import json
from pathlib import Path

from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.ntfs.helpers import canonicalize_header, clean_value, is_ntfs_raw_candidate


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
    if "zoneid" in headers or "hosturl" in headers or "referrerurl" in headers or "zone.identifier" in lower_name:
        return "ntfs_ads_zone_identifier"
    if "shadowid" in headers or "snapshottime" in headers or "shadowcopy" in lower_name or "vss" in lower_name:
        return "ntfs_shadowcopy"
    if "reason" in headers and ("usn" in headers or "filereference" in headers or "usnjrnl" in lower_name):
        return "ntfs_usnjrnl"
    if "oldname" in headers or "newname" in headers or "$logfile" in lower_name or "logfileparser" in lower_name:
        return "ntfs_logfile"
    if ("inuse" in headers or "isdeleted" in headers) and ("entrynumber" in headers or "sequencenumber" in headers):
        return "ntfs_i30"
    if {"entrynumber", "sequencenumber"} <= headers and (
        {"created0x10", "modified0x10", "created0x30", "modified0x30"} & headers
    ):
        return "ntfs_mft_enriched"
    if "mftecmd" in lower_name:
        return "ntfs_mft_enriched"
    if sample_row:
        blob = " ".join(str(value) for value in sample_row.values() if value).lower()
        if "zoneid=" in blob or "hosturl" in blob:
            return "ntfs_ads_zone_identifier"
    return "ntfs_generic_raw"


def parse_ntfs_artifact_file(path: Path, artifact_meta: dict) -> tuple[list[dict], dict]:
    parser_name = str(artifact_meta.get("parser") or "").lower()
    source_path = str(artifact_meta.get("source_path") or path)
    if parser_name == "ntfs_generic_raw" or is_ntfs_raw_candidate(path):
        row = {
            "EventType": "ntfs_metadata_observed",
            "NtfsParser": "ntfs_generic_raw",
            "NtfsSource": "raw",
            "FilePath": source_path,
            "FileName": path.name,
            "UnsupportedReason": "unsupported_ntfs_raw_parsing_not_enabled",
            "ParserStatus": "detected_not_implemented",
            "TimestampSource": "source_file",
        }
        return [row], {
            "records_read": 1,
            "records_parsed": 1,
            "records_failed": 0,
            "warnings": ["raw_ntfs_inventory_only"],
            "parser_errors": [],
        }

    rows = _read_structured_rows(path)
    if not rows:
        return [], {
            "records_read": 0,
            "records_parsed": 0,
            "records_failed": 0,
            "warnings": ["ntfs_no_rows"],
            "parser_errors": [],
        }

    normalized_rows: list[dict] = []
    for row in rows:
        parser_for_row = parser_name if parser_name.startswith("ntfs_") and parser_name != "ntfs_generic_raw" else _infer_parser_name(path, {canonicalize_header(header) for header in row.keys()}, row)
        normalized = dict(row)
        normalized["NtfsParser"] = parser_for_row
        normalized["NtfsSource"] = parser_for_row.removeprefix("ntfs_")
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
