"""On-demand file recovery from a memory image.

Some artifacts in a case (a Sysmon FileCreate event, a JumpList entry, a
persistence hit) name a file that was never hashed at ingest time -- the
source log simply never captured file bytes. If the case also has a memory
image for the same host, taken close enough in time, Windows may still hold
that file's pages cached in memory. This module runs Volatility 3's
``windows.filescan`` (locate matching ``_FILE_OBJECT``s by path) followed by
``windows.dumpfiles --virtaddr <offsets>`` (recover whatever cached pages
Volatility can reconstruct for them) to try to pull the actual bytes back
out, so an analyst can hash/inspect a file the original evidence never
captured.

Deliberately isolated from the bulk "run a profile" scan machinery in
execution.py: this is a single, on-demand, evidence-scoped action (one
requested path in, zero or more recovered files out), not a plugin roster a
profile iterates over, so it does not touch PROFILE_PLUGINS, MemoryScanRun,
or the artifact-indexing/OpenSearch pipeline. Recovery is inherently best
effort -- the OS may no longer hold the pages -- hence the ``not_found``
terminal status distinct from ``failed``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.core.storage import sha256_file
from app.models.memory import MemoryFileExtraction
from app.services.memory import backend_readiness
from app.services.memory.artifact_normalizers import _rows
from app.services.memory.evidence_access import MemoryStorageAccessError, validate_current_process_output_access
from app.services.memory.storage import memory_extraction_dir, relative_to_data_dir
from app.services.memory.validation import MemoryExecutionValidationError, validate_memory_execution_request
from app.services.memory.volatility_runner import VolatilityRunnerError, run_plugin


logger = logging.getLogger(__name__)

TERMINAL_STATUSES = {"completed", "failed", "not_found", "cancelled"}

# Generous but bounded: filescan walks the whole image (a few minutes on a
# multi-GB dump, mostly one-time PDB/GAC symbol caching); dumpfiles only
# touches the offsets we hand it, so it is comparatively fast even for a
# handful of candidates.
FILESCAN_TIMEOUT_SECONDS = 240
DUMPFILES_TIMEOUT_SECONDS = 120
# Cap how many candidate _FILE_OBJECTs a single ambiguous request (e.g. a
# bare filename shared by several processes) fans out to in one dumpfiles
# invocation -- every match still shows up in filescan_matches even if it
# was not attempted.
MAX_DUMP_CANDIDATES = 10


def _normalize_windows_path(path: str) -> str:
    text = str(path or "").strip().replace("/", "\\")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return text.lstrip("\\").lower()


def _basename(path: str) -> str:
    text = str(path or "").strip().replace("/", "\\")
    return text.rsplit("\\", 1)[-1].lower()


def _match_filescan_rows(rows: list[dict[str, Any]], requested_path: str) -> list[dict[str, Any]]:
    requested_normalized = _normalize_windows_path(requested_path)
    requested_basename = _basename(requested_path)
    candidates = [row for row in rows if isinstance(row.get("Name"), str)]
    exact = [row for row in candidates if _normalize_windows_path(row["Name"]) == requested_normalized]
    if exact:
        return exact
    if not requested_basename:
        return []
    return [row for row in candidates if _basename(row["Name"]) == requested_basename]


def create_memory_file_extraction(db, evidence_id: str, path: str) -> MemoryFileExtraction:
    """Validate the request and create the queued job row. Does not enqueue
    -- the caller (the API route) does that once the row has an id, mirroring
    every other memory job's create-then-enqueue split."""
    requested_path = str(path or "").strip()
    if not requested_path:
        raise MemoryExecutionValidationError("PATH_REQUIRED", "A file path is required.")
    if len(requested_path) > 2000:
        raise MemoryExecutionValidationError("PATH_TOO_LONG", "The requested path is too long.")
    validated = validate_memory_execution_request(db, evidence_id)
    extraction = MemoryFileExtraction(
        case_id=validated.evidence.case_id,
        evidence_id=validated.evidence.id,
        requested_path=requested_path,
        status="queued",
    )
    db.add(extraction)
    db.commit()
    db.refresh(extraction)
    return extraction


def execute_memory_file_extraction(extraction_id: str) -> None:
    """The worker task body: runs on the memory-worker process, the only
    one with a writable evidence/output mount for Volatility to use."""
    with SessionLocal() as db:
        extraction = db.get(MemoryFileExtraction, extraction_id)
        if extraction is None or extraction.status in TERMINAL_STATUSES:
            return
        extraction.status = "running"
        extraction.started_at = utc_now_naive()
        db.commit()
        logger.info("memory file extraction started", extra={"extraction_id": extraction.id, "case_id": extraction.case_id, "evidence_id": extraction.evidence_id})

        def _fail(code: str, message: str) -> None:
            extraction.status = "failed"
            extraction.error_code = code
            extraction.error_message = message
            extraction.completed_at = utc_now_naive()
            if extraction.started_at:
                extraction.duration_ms = int((extraction.completed_at - extraction.started_at).total_seconds() * 1000)
            db.commit()

        try:
            validated = validate_memory_execution_request(db, extraction.evidence_id)
            readiness = backend_readiness.check_volatility3_backend()
            if not readiness.get("ready"):
                raise MemoryExecutionValidationError("BACKEND_UNAVAILABLE", "Volatility 3 backend is not ready for execution.")
            try:
                validate_current_process_output_access()
            except MemoryStorageAccessError as exc:
                raise MemoryExecutionValidationError(exc.code, exc.message) from None

            work_dir = memory_extraction_dir(extraction.case_id, extraction.evidence_id, extraction.id)

            filescan_result = run_plugin(
                "windows.filescan",
                validated.path,
                work_dir,
                timeout_seconds=FILESCAN_TIMEOUT_SECONDS,
            )
            filescan_rows = _rows(json.loads(filescan_result.stdout.decode("utf-8") or "[]"))
            matches = _match_filescan_rows(filescan_rows, extraction.requested_path)
            extraction.filescan_matches = [
                {"offset": row.get("Offset"), "name": row.get("Name")} for row in matches
            ]
            db.commit()

            if not matches:
                extraction.status = "not_found"
                extraction.completed_at = utc_now_naive()
                extraction.duration_ms = int((extraction.completed_at - extraction.started_at).total_seconds() * 1000)
                db.commit()
                logger.info("memory file extraction found no matching file objects", extra={"extraction_id": extraction.id})
                return

            offsets = [str(row.get("Offset")) for row in matches[:MAX_DUMP_CANDIDATES] if row.get("Offset") is not None]
            dumpfiles_result = run_plugin(
                "windows.dumpfiles",
                validated.path,
                work_dir,
                timeout_seconds=DUMPFILES_TIMEOUT_SECONDS,
                extra_args=["--virtaddr", *offsets, "--ignore-case"],
            )
            dumpfiles_rows = _rows(json.loads(dumpfiles_result.stdout.decode("utf-8") or "[]"))

            results: list[dict[str, Any]] = []
            for row in dumpfiles_rows:
                result_name = row.get("Result")
                if not isinstance(result_name, str) or not result_name:
                    continue
                output_path = work_dir / result_name
                if not output_path.is_file() or output_path.stat().st_size <= 0:
                    continue
                results.append(
                    {
                        "offset": row.get("FileObject"),
                        "cache_type": row.get("Cache"),
                        "original_filename": row.get("FileName"),
                        "output_filename": result_name,
                        "output_relative_path": relative_to_data_dir(output_path),
                        "sha256": sha256_file(output_path),
                        "size_bytes": output_path.stat().st_size,
                    }
                )

            extraction.results_json = results
            extraction.status = "completed" if results else "not_found"
            extraction.completed_at = utc_now_naive()
            extraction.duration_ms = int((extraction.completed_at - extraction.started_at).total_seconds() * 1000)
            db.commit()
            logger.info(
                "memory file extraction finished",
                extra={"extraction_id": extraction.id, "status": extraction.status, "recovered_count": len(results)},
            )
        except MemoryExecutionValidationError as exc:
            _fail(exc.code, exc.message)
        except VolatilityRunnerError as exc:
            _fail(exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001
            logger.exception("memory file extraction failed unexpectedly", extra={"extraction_id": extraction.id})
            _fail("UNEXPECTED_ERROR", str(exc)[:512])


def get_memory_file_extraction(db, extraction_id: str) -> MemoryFileExtraction | None:
    return db.get(MemoryFileExtraction, extraction_id)


def list_memory_file_extractions(db, evidence_id: str) -> list[MemoryFileExtraction]:
    return (
        db.query(MemoryFileExtraction)
        .filter(MemoryFileExtraction.evidence_id == evidence_id)
        .order_by(MemoryFileExtraction.created_at.desc())
        .all()
    )


def resolve_extraction_result_file(extraction: MemoryFileExtraction, result_index: int) -> Path:
    """Resolve a completed extraction's recovered-file path for download.

    The file was written by the memory-worker process, whose
    ``memory_output_root`` (``MEMORY_OUTPUT_DIR``) may not be configured the
    same way in whichever process serves this download (the backend API
    container mounts the same host directory but does not necessarily set
    that env var) -- re-deriving the path via memory_extraction_dir() here
    would silently point at the wrong container-local root. Instead resolve
    it the same way app.services.memory.execution._resolve_raw_output_path
    already does for plugin JSON output: try backend_data_dir first (works
    whenever the caller's data dir bind-mounts the same host tree memory-
    output lives under, which it does today), then memory_output_root if
    configured, and require the winning candidate to still be a real file
    directly inside the expected extraction directory (never trusting the
    stored filename as a path on its own).
    """
    results = extraction.results_json or []
    if result_index < 0 or result_index >= len(results):
        raise MemoryExecutionValidationError("RESULT_NOT_FOUND", "No recovered file at that index.")
    result = results[result_index]
    output_filename = result.get("output_filename")
    relative_path = result.get("output_relative_path")
    if not output_filename or not relative_path:
        raise MemoryExecutionValidationError("RESULT_NOT_FOUND", "No recovered file at that index.")

    settings = get_settings()
    relative = Path(str(relative_path))
    candidates = [settings.backend_data_dir / relative]
    prefix = "memory-output/"
    if str(relative).startswith(prefix) and settings.memory_output_root:
        candidates.append(settings.memory_output_root / Path(str(relative)[len(prefix):]))

    expected_dir_suffix = Path("evidence") / extraction.case_id / extraction.evidence_id / "memory" / "extractions" / extraction.id
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.name != str(output_filename):
            continue
        if resolved.parent.parts[-len(expected_dir_suffix.parts):] != expected_dir_suffix.parts:
            continue
        if resolved.is_file():
            return resolved
    raise MemoryExecutionValidationError("RESULT_FILE_MISSING", "The recovered file is no longer available on disk.")
