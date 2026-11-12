"""The evidence's saved MemProcFS scan as the API and the other workers see it.

The memory worker scans a Windows image once (app.services.memory.memprocfs_engine.ensure_scan)
and records where on the evidence (``metadata_json["memprocfs_scan"]``, path relative to the data
directory, as runs record theirs). The API reads it from there to say how the scan was made, list
its files, hand them out, and let Source Tables index its CSVs (source paths ``memprocfs/<file>``).
"""

from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.config import get_settings
from app.models.evidence import Evidence

SOURCE_PREFIX = "memprocfs/"
_TABULAR = {".csv", ".tsv"}


def recorded(evidence: Evidence) -> dict[str, Any]:
    value = (evidence.metadata_json or {}).get("memprocfs_scan")
    return dict(value) if isinstance(value, dict) else {}


def scan_directory(evidence: Evidence) -> Path | None:
    """The saved scan's directory, from this process's view of the data directory."""
    relative = str(recorded(evidence).get("path") or "")
    if not relative:
        return None
    settings = get_settings()
    path = Path(relative)
    candidates = [path] if path.is_absolute() else [settings.backend_data_dir / path]
    if not path.is_absolute() and relative.startswith("memory-output/") and settings.memory_output_root:
        candidates.append(settings.memory_output_root / Path(relative[len("memory-output/"):]))
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def _files(directory: Path) -> list[dict[str, Any]]:
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            relative = path.relative_to(directory).as_posix()
            files.append({"path": relative, "size": path.stat().st_size, "tabular": path.suffix.lower() in _TABULAR, "source_path": SOURCE_PREFIX + relative})
    return files


def status(evidence: Evidence) -> dict[str, Any]:
    info = recorded(evidence)
    directory = scan_directory(evidence)
    files = _files(directory) if directory is not None else []
    notices = []
    if info and not info.get("legacy_inventory") and not info.get("yara_rules") and get_settings().memprocfs_yara_accept_elastic_license:
        notices.append("yara_rules_missing")
    if info.get("legacy_inventory"):
        notices.append("legacy_inventory")
    return {
        "evidence_id": evidence.id,
        "exists": directory is not None,
        "scanned_at": info.get("scanned_at"),
        "memprocfs_version": info.get("memprocfs_version"),
        "yara_rules": bool(info.get("yara_rules")),
        "findevil": info.get("findevil"),
        "notices": notices,
        "files": files,
        "total_bytes": sum(item["size"] for item in files),
    }


def resolve_file(evidence: Evidence, relative: str) -> Path | None:
    """A file of the saved scan by its relative path; None outside the scan or missing."""
    directory = scan_directory(evidence)
    if directory is None:
        return None
    parts = PurePosixPath(str(relative).replace("\\", "/")).parts
    if not parts or any(part in ("", ".", "..") for part in parts) or parts[0] == "/":
        return None
    candidate = directory.joinpath(*parts)
    try:
        candidate.resolve().relative_to(directory.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def resolve_source(evidence: Evidence, source_path: str) -> Path | None:
    """Source Tables' file for a ``memprocfs/<file>`` source path."""
    if not str(source_path).startswith(SOURCE_PREFIX):
        return None
    return resolve_file(evidence, str(source_path)[len(SOURCE_PREFIX):])


def build_archive(evidence: Evidence) -> Path | None:
    """A ZIP of the whole saved scan in the temp directory (the caller removes it)."""
    directory = scan_directory(evidence)
    if directory is None:
        return None
    temp_root = Path(get_settings().backend_temp_dir)
    temp_root.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix="memprocfs-scan-", suffix=".zip", dir=str(temp_root))
    os.close(handle)
    target = Path(name)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for item in _files(directory):
            archive.write(directory / item["path"], arcname=item["path"])
    return target
