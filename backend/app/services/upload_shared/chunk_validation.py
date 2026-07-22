"""Generic classifier for chunked-upload staging integrity.

Extracted from Memory's ``check_memory_upload_staging_integrity``. Takes
plain paths and a chunk-index -> {size, sha256} metadata mapping instead
of an ORM model, so any chunked session backend can reuse it without a
shared table. The returned shape is unchanged from Memory's original
function so it is a drop-in for existing callers/tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from app.core.storage import sha256_file

STAGING_HEALTHY = "healthy"
STAGING_MISSING = "staging_missing"
MISSING_CHUNKS = "missing_chunks_on_disk"
EXTRA_CHUNKS = "extra_chunks_on_disk"
SIZE_MISMATCH = "size_mismatch"
HASH_MISMATCH = "hash_mismatch"


def classify_chunk_staging(
    *,
    session_root: Path,
    chunks_dir: Path,
    chunk_path_fn: Callable[[int], Path],
    expected_chunks: int,
    db_received_chunk_count: int,
    chunk_metadata: dict[str, dict[str, Any]],
    verify_hashes: bool = False,
) -> dict[str, Any]:
    db_indices = sorted(int(k) for k in chunk_metadata.keys())

    if not session_root.exists() or not session_root.is_dir():
        return {
            "integrity_status": STAGING_MISSING,
            "resumable": False,
            "repairable": False,
            "expected_chunks": int(expected_chunks or 0),
            "db_received_chunks": int(db_received_chunk_count or 0),
            "disk_chunks": 0,
            "missing_db_chunks_on_disk": [],
            "extra_disk_chunks": [],
            "size_mismatches": [],
            "hash_mismatches": [],
        }

    if not chunks_dir.exists() or not chunks_dir.is_dir():
        return {
            "integrity_status": STAGING_MISSING,
            "resumable": False,
            "repairable": False,
            "expected_chunks": int(expected_chunks or 0),
            "db_received_chunks": int(db_received_chunk_count or 0),
            "disk_chunks": 0,
            "missing_db_chunks_on_disk": db_indices,
            "extra_disk_chunks": [],
            "size_mismatches": [],
            "hash_mismatches": [],
        }

    disk_indices: list[int] = []
    for entry in sorted(chunks_dir.iterdir()):
        if not entry.is_file() or entry.is_symlink():
            continue
        if entry.name.endswith(".part"):
            continue
        name = entry.name
        if not name.endswith(".chunk"):
            continue
        try:
            index = int(name.split(".")[0])
        except (ValueError, IndexError):
            continue
        disk_indices.append(index)
    disk_indices.sort()

    missing_db_chunks_on_disk: list[int] = []
    size_mismatches: list[int] = []
    hash_mismatches: list[int] = []

    for index in db_indices:
        chunk_path = chunk_path_fn(index)
        if not chunk_path.exists() or not chunk_path.is_file():
            missing_db_chunks_on_disk.append(index)
            continue
        chunk_meta = chunk_metadata.get(str(index), {})
        expected_size = int(chunk_meta.get("size") or 0)
        actual_size = int(chunk_path.stat().st_size)
        if expected_size != 0 and actual_size != expected_size:
            size_mismatches.append(index)
            continue
        if verify_hashes:
            expected_sha = str(chunk_meta.get("sha256") or "")
            if expected_sha:
                actual_sha = sha256_file(chunk_path)
                if actual_sha != expected_sha:
                    hash_mismatches.append(index)

    extra_disk_chunks = sorted(set(disk_indices) - set(db_indices))
    disk_chunk_count = len(disk_indices)

    if missing_db_chunks_on_disk:
        status, resumable, repairable = MISSING_CHUNKS, False, False
    elif size_mismatches:
        status, resumable, repairable = SIZE_MISMATCH, False, False
    elif hash_mismatches:
        status, resumable, repairable = HASH_MISMATCH, False, False
    elif extra_disk_chunks:
        status, resumable, repairable = EXTRA_CHUNKS, True, True
    else:
        status, resumable, repairable = STAGING_HEALTHY, True, True

    return {
        "integrity_status": status,
        "resumable": resumable,
        "repairable": repairable,
        "expected_chunks": int(expected_chunks or 0),
        "db_received_chunks": int(db_received_chunk_count or 0),
        "disk_chunks": disk_chunk_count,
        "missing_db_chunks_on_disk": missing_db_chunks_on_disk,
        "extra_disk_chunks": extra_disk_chunks,
        "size_mismatches": size_mismatches,
        "hash_mismatches": hash_mismatches,
    }
