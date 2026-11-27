"""On-demand search of a UAC collection's bodyfile (see app.ingest.uac.bodyfile)."""
from __future__ import annotations

import time
from pathlib import Path

from app.core.storage import evidence_extract_dir
from app.ingest.uac.bodyfile import TIME_FIELDS, iter_matches
from app.ingest.uac.collection import find_uac_root
from app.models.evidence import Evidence

MAX_RESULTS = 1000


def bodyfile_path(evidence: Evidence) -> Path | None:
    roots = [evidence_extract_dir(evidence.case_id, evidence.id)]
    stored = Path(str(evidence.stored_path or ""))
    if str(evidence.stored_path or "") and stored.is_dir():
        roots.append(stored)
    for root in roots:
        uac_root = find_uac_root(root)
        if uac_root is not None and (uac_root / "bodyfile" / "bodyfile.txt").is_file():
            return uac_root / "bodyfile" / "bodyfile.txt"
    return None


def summarize(evidence: Evidence) -> dict:
    path = bodyfile_path(evidence)
    return {"evidence_id": evidence.id, "available": path is not None, "size_bytes": path.stat().st_size if path else None}


def search(evidence: Evidence, *, path_contains: str, sort: str = "mtime", limit: int = 200) -> dict:
    path = bodyfile_path(evidence)
    sort = sort if sort in TIME_FIELDS else "mtime"
    limit = max(1, min(int(limit), MAX_RESULTS))
    started = time.monotonic()
    if path is None:
        return {"evidence_id": evidence.id, "available": False, "records": [], "total_matches": 0, "truncated": False, "elapsed_seconds": 0.0}
    matches: list[dict] = []
    total = 0
    for record in iter_matches(path, path_contains.strip()):
        total += 1
        matches.append(record)
        if len(matches) > limit * 4:
            matches.sort(key=lambda item: item.get(sort) or "", reverse=True)
            del matches[limit:]
    matches.sort(key=lambda item: item.get(sort) or "", reverse=True)
    return {
        "evidence_id": evidence.id,
        "available": True,
        "path_contains": path_contains,
        "sort": sort,
        "records": matches[:limit],
        "total_matches": total,
        "truncated": total > limit,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
