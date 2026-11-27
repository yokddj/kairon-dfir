"""On-demand search of a macOS evidence's FSEvents (see app.ingest.macos.fsevents).

Nothing is indexed: each search reads the evidence's ``.fseventsd`` pages, skips those that do not
contain the searched text, and returns the matching records, latest event first.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from app.core.storage import evidence_extract_dir
from app.ingest.macos.fsevents import CHANGE_KINDS, iter_directory, page_files
from app.models.evidence import Evidence

MAX_RESULTS = 1000
_FSEVENTSD = ".fseventsd"
_MAX_WALK_DEPTH = 8


def fseventsd_directories(root: Path) -> list[Path]:
    """Every .fseventsd folder of a collected macOS file system (each volume has its own)."""
    found: list[Path] = []
    base_depth = len(root.parts)
    for dirpath, dirnames, _files in os.walk(root):
        current = Path(dirpath)
        if len(current.parts) - base_depth >= _MAX_WALK_DEPTH:
            dirnames[:] = []
            continue
        if _FSEVENTSD in dirnames:
            found.append(current / _FSEVENTSD)
            dirnames.remove(_FSEVENTSD)
    return sorted(found)


def _volume_label(directory: Path) -> str:
    parent = directory.parent
    text = str(parent).replace("\\", "/")
    marker = "[root]"
    index = text.find(marker)
    relative = text[index + len(marker):] if index >= 0 else parent.name
    return relative or "/"


def evidence_fsevents_directories(evidence: Evidence) -> list[Path]:
    roots = [evidence_extract_dir(evidence.case_id, evidence.id)]
    stored = Path(str(evidence.stored_path or ""))
    if str(evidence.stored_path or "") and stored.is_dir():
        roots.append(stored)
    directories: list[Path] = []
    for root in roots:
        directories.extend(fseventsd_directories(root))
    return directories


def summarize(evidence: Evidence) -> dict:
    volumes = []
    for directory in evidence_fsevents_directories(evidence):
        pages = page_files(directory)
        volumes.append({"volume": _volume_label(directory), "page_files": len(pages)})
    return {"evidence_id": evidence.id, "volumes": volumes, "available": bool(volumes)}


def search(evidence: Evidence, *, path_contains: str, changes: list[str] | None = None, item_type: str | None = None, limit: int = 200) -> dict:
    needle = path_contains.strip().lower()
    wanted = {change for change in (changes or []) if change in CHANGE_KINDS}
    limit = max(1, min(int(limit), MAX_RESULTS))
    started = time.monotonic()
    matches: list[dict] = []
    total_matches = 0
    scanned = 0
    for directory in evidence_fsevents_directories(evidence):
        volume = _volume_label(directory)
        for record in iter_directory(directory, needle=needle.encode("utf-8")):
            scanned += 1
            if needle not in record.path.lower():
                continue
            if wanted and not wanted.intersection(record.changes):
                continue
            if item_type and record.item_type != item_type:
                continue
            total_matches += 1
            matches.append({**record.as_dict(), "volume": volume})
            if len(matches) > limit * 4:
                # Keep memory bounded: only the newest records are returned.
                matches.sort(key=lambda item: item["event_id"], reverse=True)
                del matches[limit:]
    matches.sort(key=lambda item: item["event_id"], reverse=True)
    return {
        "evidence_id": evidence.id,
        "path_contains": path_contains,
        "changes": sorted(wanted),
        "item_type": item_type,
        "records": matches[:limit],
        "total_matches": total_matches,
        "truncated": total_matches > limit,
        "records_scanned_in_matching_pages": scanned,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
