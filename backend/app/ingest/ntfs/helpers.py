from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath


NTFS_RAW_NAMES = {"$usnjrnl", "$logfile", "$i30"}
NTFS_NAME_HINTS = (
    "usnjrnl",
    "$logfile",
    "$i30",
    "zone.identifier",
    "alternate datastream",
    "alternatedatastream",
    "shadowcopy",
    "shadow copy",
    "vss",
    "indexallocation",
    "indexcsv",
    "logfileparser",
)
NTFS_HEADER_HINTS = {
    "usn",
    "reason",
    "filereference",
    "parentfilereference",
    "zoneid",
    "hosturl",
    "referrerurl",
    "entrynumber",
    "sequencenumber",
    "created0x10",
    "created0x30",
    "shadowid",
    "snapshottime",
    "oldname",
    "newname",
    "inuse",
    "isdeleted",
}


def canonicalize_header(value: object | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def clean_value(value: object | None) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in {"-", "--", "n/a", "na", "none", "null", "unknown"}:
        return None
    return text


def normalize_windows_path(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    return cleaned.replace("/", "\\")


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def parent_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        parent = str(PureWindowsPath(normalized).parent)
        return parent if parent and parent != "." else None
    except Exception:  # noqa: BLE001
        parent = str(Path(normalized.replace("\\", "/")).parent)
        return parent if parent and parent != "." else None


def first_nonempty(row: dict, *names: str) -> str | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    canon = {canonicalize_header(key): value for key, value in row.items()}
    for name in names:
        for candidate in (name, name.lower(), canonicalize_header(name)):
            value = lowered.get(candidate) if candidate in lowered else canon.get(candidate)
            if value not in (None, ""):
                return str(value)
    return None


def is_ntfs_raw_candidate(path: Path) -> bool:
    lower_name = path.name.lower()
    return lower_name in NTFS_RAW_NAMES or lower_name.endswith("zone.identifier")


def looks_like_ntfs_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    normalized_path = str(path).replace("/", "\\").lower()
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    lower_suffix = path.suffix.lower()
    if is_ntfs_raw_candidate(path):
        return True
    if lower_suffix in {".pf", ".lnk", ".evtx"}:
        return False
    if any(token in lower_name for token in NTFS_NAME_HINTS) or any(token in normalized_path for token in NTFS_NAME_HINTS):
        return True
    if len(header_set & NTFS_HEADER_HINTS) >= 2:
        return True
    if {"entrynumber", "sequencenumber"} <= header_set and ("isdeleted" in header_set or "inuse" in header_set):
        return True
    return False
