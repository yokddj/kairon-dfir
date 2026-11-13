"""Memory-image tools for the assistant and the MCP server.

A memory image is often the only evidence a case has: no disk, no MFT, just
what was in RAM. These tools expose what Kairon already recovers from it --
file objects, files recovered on request, Find Evil records, processes that
had exited -- in the same shape as the rest of app.services.ai.tools: an
aggregate first, a bounded sample of rows after, and an explicit note when an
empty answer means "not analysed" rather than "not there".

Everything here only reads. Starting an extraction is a write (it queues a
job), so it stays in the app; these tools read the jobs and the bytes they
recovered.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

MEMORY_ID_PREFIX = "memory:"
MEMORY_TIMELINE_ID_PREFIX = "memory-timeline:"

# What one read of a recovered file may return. A text or strings answer is
# also clipped by the tools layer's overall result cap.
READ_MAX_BYTES = 4096
READ_DEFAULT_BYTES = 2048
STRINGS_MIN_LENGTH = 4
STRINGS_MAX_COUNT = 200

# Fields of a memory artifact that say *which process* and *which endpoints*:
# a connection without them cannot be attributed, which is what an analyst
# asks first.
MEMORY_ROW_FIELDS = (
    "pid", "ppid", "process_name", "evidence_id",
    "protocol", "local_address", "local_port", "remote_address", "remote_port", "state",
    "create_time", "exit_time", "source_plugins",
)


class MemoryToolError(RuntimeError):
    """Raised for an argument the model can fix; the message is shown to it."""


# --------------------------------------------------------------------------
# Rows and ids
# --------------------------------------------------------------------------

def memory_row(item: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """One memory search row with its process and endpoint fields.

    memory_search_results keeps those in ``raw``; projecting only the top-level
    keys lost the PID and owning process of every connection.
    """
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    row = {key: item.get(key) for key in keys if item.get(key) not in (None, "", [], {})}
    process = raw.get("process") if isinstance(raw.get("process"), dict) else {}
    for key in MEMORY_ROW_FIELDS:
        value = item.get(key)
        if value in (None, "", [], {}):
            value = raw.get(key)
        if value in (None, "", [], {}) and key in ("ppid", "create_time", "exit_time"):
            value = process.get(key)
        if value in (None, "", [], {}) and key == "state":
            value = raw.get("connection_state")
        if value not in (None, "", [], {}):
            row[key] = value
    return row


def detail_id(item: dict[str, Any]) -> Any:
    """The id get_event_detail resolves, for a timeline or search row.

    A memory timeline row's own id is a hash of its parts; the document behind
    it is what can be read back, so hand out that document's id instead.
    """
    row_id = item.get("id")
    if not isinstance(row_id, str) or not row_id.startswith(MEMORY_TIMELINE_ID_PREFIX):
        return row_id
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    reference = raw.get("raw_reference") if isinstance(raw.get("raw_reference"), dict) else {}
    if reference.get("document_id"):
        return f"{MEMORY_ID_PREFIX}{reference['document_id']}"
    if reference.get("opensearch_id"):
        return str(reference["opensearch_id"])
    return row_id


def is_memory_id(event_id: str) -> bool:
    return event_id.startswith(MEMORY_ID_PREFIX) or event_id.startswith(MEMORY_TIMELINE_ID_PREFIX)


def memory_event_detail(db: Session, case_id: str, event_id: str) -> dict[str, Any] | None:
    """Read one memory artifact back by the id a search or timeline handed out.

    Returns None when the id resolves to nothing; a ``memory-timeline:`` id
    that points at a disk event returns ``{"event_id": <id>}`` so the caller
    can read it from the events index.
    """
    if event_id.startswith(MEMORY_TIMELINE_ID_PREFIX):
        resolved = _resolve_timeline_id(db, case_id, event_id)
        if resolved is None:
            return None
        if not resolved.startswith(MEMORY_ID_PREFIX):
            return {"event_id": resolved}
        event_id = resolved
    document_id = event_id[len(MEMORY_ID_PREFIX):]
    if not document_id:
        return None

    from app.core.opensearch import get_memory_index, get_opensearch_client
    from app.models.evidence import Evidence
    from app.services.memory.search import _result_from_hit

    try:
        hit = get_opensearch_client().get(index=get_memory_index(case_id), id=document_id)
    except Exception:  # noqa: BLE001 - a missing document is an answer, not a crash
        logger.debug("Memory document %s not found", document_id, exc_info=True)
        return None
    source = (hit or {}).get("_source") or {}
    if not hit or source.get("case_id") != case_id:
        return None
    evidence = db.get(Evidence, source.get("evidence_id")) if source.get("evidence_id") else None
    result = _result_from_hit(hit, evidence_name=_evidence_name(evidence) if evidence else str(source.get("evidence_id") or ""), families=[])
    raw = result.get("raw") or {}
    fields = {
        key: value for key, value in raw.items()
        if value not in (None, "", [], {}) and key not in ("provenance", "case_id", "normalization_version", "document_id")
    }
    return {
        "found": True,
        "event_id": f"{MEMORY_ID_PREFIX}{document_id}",
        "source": "memory",
        "timestamp": result.get("timestamp"),
        "evidence_id": result.get("evidence_id"),
        "evidence_name": result.get("evidence_name"),
        "artifact_type": result.get("artifact_type"),
        "artifact_family": result.get("artifact_family"),
        "source_plugin": result.get("source_plugin"),
        "title": (
            " ".join(str(source.get(key)) for key in ("indicator_type", "process_name") if source.get(key))
            if result.get("title") == result.get("artifact_type") else result.get("title")
        ),
        "summary": result.get("summary") or source.get("description"),
        "fields": fields,
    }


def _resolve_timeline_id(db: Session, case_id: str, event_id: str) -> str | None:
    """The document behind a ``memory-timeline:`` id (a hash of its parts, not reversible), by
    walking each image's memory timeline until the row turns up."""
    from app.services.investigation_memory import _memory_timeline_row, memory_evidences
    from app.services.memory.timeline import get_memory_timeline

    for evidence in memory_evidences(db, case_id):
        page = 1
        while page <= 200:
            payload = get_memory_timeline(db, case_id=case_id, evidence_id=str(evidence.id), include_undated=True, page=page, page_size=500)
            items = payload.get("items") or []
            for row in items:
                item = _memory_timeline_row(case_id, row)
                if item.get("id") == event_id:
                    resolved = detail_id(item)
                    return None if resolved == event_id else resolved
            if page >= int(payload.get("total_pages") or 0):
                break
            page += 1
    return None


# --------------------------------------------------------------------------
# Defender detections that name the download URL
# --------------------------------------------------------------------------

def parse_webfile(text: str | None) -> list[dict[str, Any]]:
    from app.ingest.defender.helpers import parse_defender_webfile

    return parse_defender_webfile(text)


def defender_downloads(db: Session, case_id: str, host: Any, limit: int) -> dict[str, Any]:
    """Downloads named by Defender detections: in memory (Find Evil) and in its logs on disk."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        rows.extend(_memory_defender_downloads(db, case_id, host))
    except Exception as exc:  # noqa: BLE001 - one source failing must not hide the others
        logger.info("Memory Defender download lookup failed: %s", exc)
        _rollback(db)
        warnings.append(f"Memory Defender lookup failed: {exc}")
    try:
        rows.extend(_disk_defender_downloads(case_id, host))
    except Exception as exc:  # noqa: BLE001
        logger.info("Disk Defender download lookup failed: %s", exc)
        warnings.append(f"Defender log lookup failed: {exc}")
    rows.sort(key=lambda row: str(row.get("timestamp") or ""))
    return {"total": len(rows), "rows": rows[:limit], "warnings": warnings}


def _memory_defender_downloads(db: Session, case_id: str, host: Any) -> list[dict[str, Any]]:
    from app.core.opensearch import get_memory_index, get_opensearch_client
    from app.services.memory.antivirus_detections import MAX_RECORDS, parse_av_detect

    evidences = _memory_evidences_for_host(db, case_id, host)
    if not evidences:
        return []
    body = {
        "size": MAX_RECORDS,
        "timeout": "10s",
        "_source": ["description", "evidence_id"],
        "query": {"bool": {"filter": [
            {"term": {"document_type": "memory_findevil"}},
            {"terms": {"evidence_id": [str(e.id) for e in evidences]}},
            {"match": {"indicator_type": "AV_DETECT"}},
        ]}},
    }
    response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for hit in ((response.get("hits") or {}).get("hits")) or []:
        source = hit.get("_source") or {}
        description = str(source.get("description") or "")
        parsed = parse_av_detect(description) or {}
        for item in parse_webfile(description):
            key = (str(source.get("evidence_id")), str(item["file_path"] or "").lower(), item["url"])
            row = rows.setdefault(key, {
                "timestamp": parsed.get("time"),
                "file_path": item["file_path"],
                "url": item["url"],
                "downloading_pid": item["downloading_pid"],
                "threat": parsed.get("threat"),
                "source": "defender_in_memory",
                "evidence_id": source.get("evidence_id"),
            })
            if parsed.get("time") and (not row["timestamp"] or parsed["time"] < row["timestamp"]):
                row["timestamp"] = parsed["time"]
    return list(rows.values())


def _disk_defender_downloads(case_id: str, host: Any) -> list[dict[str, Any]]:
    from app.core.opensearch import get_events_index, get_opensearch_client

    wildcard = {"value": "*webfile:*", "case_insensitive": True}
    filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}]
    if host is not None:
        filters.append({"term": {"host_id": str(host.id)}})
    body = {
        "size": 200,
        "timeout": "10s",
        "_source": ["@timestamp", "defender.resource", "detection.resource", "defender.threat_name", "host.name", "event_id"],
        "query": {"bool": {
            "filter": filters,
            "should": [
                {"wildcard": {"defender.resource.keyword": wildcard}},
                {"wildcard": {"detection.resource.keyword": wildcard}},
                {"wildcard": {"defender.resource": wildcard}},
            ],
            "minimum_should_match": 1,
        }},
    }
    response = get_opensearch_client().search(index=get_events_index(case_id), body=body, params={"ignore_unavailable": "true"})
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for hit in ((response.get("hits") or {}).get("hits")) or []:
        source = hit.get("_source") or {}
        defender = source.get("defender") if isinstance(source.get("defender"), dict) else {}
        detection = source.get("detection") if isinstance(source.get("detection"), dict) else {}
        resource = defender.get("resource") or detection.get("resource")
        for item in parse_webfile(resource):
            key = (str(item["file_path"] or "").lower(), item["url"])
            rows.setdefault(key, {
                "id": hit.get("_id"),
                "timestamp": source.get("@timestamp"),
                "host": (source.get("host") or {}).get("name") if isinstance(source.get("host"), dict) else None,
                "file_path": item["file_path"],
                "url": item["url"],
                "downloading_pid": item["downloading_pid"],
                "threat": defender.get("threat_name"),
                "source": "defender_log",
            })
    return list(rows.values())


# --------------------------------------------------------------------------
# File objects and recovered files
# --------------------------------------------------------------------------

FILE_OBJECT_KEYS = ("name", "offset", "evidence_id", "source_plugin")


def tool_list_memory_files(db: Session, case_id: str, args: dict) -> dict:
    """Files whose objects were still in memory (windows.filescan, linux pagecache)."""
    from app.services.memory.artifact_indexing import search_artifact_documents

    limit = _limit(args.get("limit"))
    name = str(args.get("name") or args.get("query") or "").strip() or None
    images = []
    total = 0
    rows: list[dict[str, Any]] = []
    not_analysed: list[str] = []
    for evidence in _memory_evidences(db, case_id, args.get("evidence_id")):
        run_id = _active_run_id(db, case_id, str(evidence.id), "files")
        if not run_id:
            not_analysed.append(_evidence_name(evidence))
            continue
        payload = search_artifact_documents(
            case_id,
            document_type="memory_file_object",
            run_id=run_id,
            evidence_id=str(evidence.id),
            page=1,
            page_size=limit,
            filters={"name": name},
            sort=[{"name.keyword": {"order": "asc", "unmapped_type": "keyword"}}],
        )
        count = int(payload.get("total") or 0)
        total += count
        images.append({"evidence_id": str(evidence.id), "image": _evidence_name(evidence), "matches": count})
        for item in payload.get("items") or []:
            row = {key: item.get(key) for key in FILE_OBJECT_KEYS if item.get(key) not in (None, "")}
            row["evidence_id"] = str(evidence.id)
            rows.append(row)
    notes = []
    if not_analysed:
        notes.append(
            "No file-object scan (windows.filescan / linux pagecache) has run on: " + ", ".join(not_analysed)
            + ". Zero here means not analysed, not absent; run the Files profile in the app."
        )
    if images and total == 0 and name:
        notes.append("No file object matched. A file that was not open or cached at capture time has no object in memory.")
    return {
        "total_matches": total,
        "memory_images": images,
        "files": rows[:limit],
        "note": " ".join(notes) or None,
        "hint": "To recover a file's bytes, start an extraction for its path in the app (Memory > Files); "
        "then read it with list_memory_file_extractions and read_memory_extracted_file.",
    }


def tool_list_memory_file_extractions(db: Session, case_id: str, args: dict) -> dict:
    """Files recovered from memory on request, with their status and the files they produced."""
    from app.services.memory.file_extraction import list_memory_file_extractions

    limit = _limit(args.get("limit"))
    query = str(args.get("query") or "").strip().lower()
    jobs = []
    for evidence in _memory_evidences(db, case_id, args.get("evidence_id")):
        for extraction in list_memory_file_extractions(db, str(evidence.id)):
            if query and query not in str(extraction.requested_path or "").lower():
                continue
            jobs.append({
                "extraction_id": extraction.id,
                "evidence_id": extraction.evidence_id,
                "requested_path": extraction.requested_path,
                "status": extraction.status,
                "error": extraction.error_message,
                "created_at": extraction.created_at.isoformat() if extraction.created_at else None,
                "recovered_files": [
                    {
                        "result_index": index,
                        "file_name": result.get("output_filename"),
                        "size_bytes": result.get("size_bytes"),
                        "sha256": result.get("sha256"),
                        "file_object": result.get("file_object") or result.get("name") or result.get("path"),
                    }
                    for index, result in enumerate(extraction.results_json or [])
                ],
            })
    return {
        "total": len(jobs),
        "extractions": jobs[:limit],
        "note": None if jobs else "No file has been recovered from memory in this case yet. Extractions are started in the app (Memory > Files).",
    }


def tool_read_memory_extracted_file(db: Session, case_id: str, args: dict) -> dict:
    """Read the bytes of a file recovered from memory: as text, hex or strings."""
    from app.models.evidence import Evidence
    from app.services.memory.file_extraction import get_memory_file_extraction, resolve_extraction_result_file
    from app.services.memory.validation import MemoryExecutionValidationError

    extraction_id = str(args.get("extraction_id") or "").strip()
    if not extraction_id:
        raise MemoryToolError("extraction_id is required; list_memory_file_extractions gives it.")
    extraction = get_memory_file_extraction(db, extraction_id)
    evidence = db.get(Evidence, extraction.evidence_id) if extraction else None
    if extraction is None or extraction.case_id != case_id or evidence is None or evidence.case_id != case_id:
        raise MemoryToolError(f"No extraction '{extraction_id}' in this case. Call list_memory_file_extractions.")
    try:
        result_index = int(args.get("result_index") or 0)
    except (TypeError, ValueError) as exc:
        raise MemoryToolError("result_index must be an integer.") from exc
    try:
        path = resolve_extraction_result_file(extraction, result_index)
    except MemoryExecutionValidationError as exc:
        raise MemoryToolError(exc.message) from exc

    mode = str(args.get("mode") or "text").strip().lower()
    if mode not in ("text", "hex", "strings"):
        raise MemoryToolError("mode must be text, hex or strings.")
    size = path.stat().st_size
    offset = max(_int(args.get("offset"), 0), 0)
    length = min(max(_int(args.get("length"), READ_DEFAULT_BYTES), 1), READ_MAX_BYTES)
    meta = {
        "extraction_id": extraction.id,
        "requested_path": extraction.requested_path,
        "result_index": result_index,
        "size_bytes": size,
        "mode": mode,
    }
    if mode == "strings":
        # Strings scan the whole file (bounded): the point is to find what is in it.
        with path.open("rb") as handle:
            data = handle.read(min(size, 8 * 1024 * 1024))
        found = extract_strings(data, int(args.get("min_length") or STRINGS_MIN_LENGTH))
        needle = str(args.get("query") or "").strip().lower()
        if needle:
            found = [item for item in found if needle in item["text"].lower()]
        return {**meta, "total_strings": len(found), "strings": found[:STRINGS_MAX_COUNT],
                "truncated": len(found) > STRINGS_MAX_COUNT or size > 8 * 1024 * 1024}
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    meta.update({"offset": offset, "length": len(data), "more": offset + len(data) < size})
    if data and not data.strip(b"\x00"):
        # Pages that were not resident come back zero-filled: say so, and where content starts.
        meta["zero_filled"] = True
        meta["next_content_offset"] = _next_nonzero(path, offset + len(data))
        meta["note"] = "This window is zero-filled: pages not in memory at capture time, not file content."
    if mode == "hex":
        return {**meta, "hex": hexdump(data, offset)}
    return {**meta, "encoding": _guess_encoding(data), "text": decode_text(data)}


def extract_strings(data: bytes, min_length: int = STRINGS_MIN_LENGTH) -> list[dict[str, Any]]:
    """ASCII and UTF-16LE runs of printable characters, with their offsets."""
    min_length = max(min_length, 3)
    out = []
    for match in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_length, data):
        out.append({"offset": match.start(), "encoding": "ascii", "text": match.group().decode("ascii")[:300]})
    for match in re.finditer(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_length, data):
        out.append({"offset": match.start(), "encoding": "utf-16le", "text": match.group().decode("utf-16le")[:300]})
    out.sort(key=lambda item: item["offset"])
    return out


def hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for start in range(0, len(data), 16):
        chunk = data[start:start + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{base + start:08x}  {hex_part:<47}  {text}")
    return "\n".join(lines)


def _guess_encoding(data: bytes) -> str:
    sample = data[:64]
    if data.startswith(b"\xff\xfe"):
        return "utf-16le"
    if len(sample) >= 8 and sample[1::2].count(0) >= len(sample[1::2]) * 0.9 and sample[0::2].count(0) <= len(sample[0::2]) * 0.1:
        return "utf-16le"
    return "utf-8"


def _next_nonzero(path: Any, start: int, limit: int = 64 * 1024 * 1024) -> int | None:
    """Offset of the first non-zero byte at or after start, within a bounded scan."""
    with path.open("rb") as handle:
        handle.seek(start)
        position = start
        while position - start < limit:
            chunk = handle.read(65536)
            if not chunk:
                return None
            stripped = chunk.lstrip(b"\x00")
            if stripped:
                return position + len(chunk) - len(stripped)
            position += len(chunk)
    return None


def decode_text(data: bytes) -> str:
    if _guess_encoding(data) == "utf-16le":
        text = data.decode("utf-16le", errors="replace")
    else:
        text = data.decode("utf-8", errors="replace")
    # Control characters other than whitespace would only confuse the reader.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", ".", text.lstrip("﻿"))


# --------------------------------------------------------------------------
# Find Evil (YARA, injections, AV detections ...)
# --------------------------------------------------------------------------

FIND_EVIL_KEYS = (
    "indicator_type", "indicator_category", "review_priority", "pid", "process_name",
    "explanation", "address", "description", "evidence_id",
)


def tool_list_find_evil(db: Session, case_id: str, args: dict) -> dict:
    """Find Evil records of a memory image: YARA matches, injected code, AV detections, beacons."""
    from app.services.memory.artifact_indexing import search_artifact_documents

    limit = _limit(args.get("limit"))
    indicator = str(args.get("indicator_type") or "").strip() or None
    process_name = str(args.get("process_name") or "").strip() or None
    query = str(args.get("query") or "").strip().lower()
    total = 0
    by_type: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    not_run: list[str] = []
    for evidence in _memory_evidences(db, case_id, args.get("evidence_id")):
        run_id = _active_run_id(db, case_id, str(evidence.id), "find_evil")
        if not run_id:
            not_run.append(_evidence_name(evidence))
            continue
        page = 1
        while page <= 10:
            payload = search_artifact_documents(
                case_id,
                document_type="memory_findevil",
                run_id=run_id,
                evidence_id=str(evidence.id),
                page=page,
                page_size=200,
                filters={"process_name": process_name},
                sort=[{"review_rank": {"order": "asc", "unmapped_type": "long"}}, {"sequence": {"order": "asc", "unmapped_type": "long"}}],
            )
            items = payload.get("items") or []
            for item in items:
                kind = str(item.get("indicator_type") or "")
                if indicator and not kind.upper().startswith(indicator.upper()):
                    continue
                if query and query not in " ".join(str(item.get(k) or "") for k in ("description", "explanation", "process_name")).lower():
                    continue
                total += 1
                by_type[kind] = by_type.get(kind, 0) + 1
                row = {key: item.get(key) for key in FIND_EVIL_KEYS if item.get(key) not in (None, "")}
                row["id"] = f"{MEMORY_ID_PREFIX}{item.get('document_id')}" if item.get("document_id") else None
                rows.append(row)
            if len(items) < 200:
                break
            page += 1
    return {
        "total": total,
        "by_indicator_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "records": rows[:limit],
        "note": ("Find Evil has not run on: " + ", ".join(not_run) + ". Zero here means not analysed.") if not_run else None,
        "hint": "indicator_type is matched as a prefix: YR_ for YARA matches, AV_DETECT for antivirus, PE_INJECT for injected code.",
    }


# --------------------------------------------------------------------------
# Program executions from every source
# --------------------------------------------------------------------------

# Event artifacts that record a program running. Prefetch and Amcache come
# from disk or from MemProcFS (the memprocfs_ variants, read from memory);
# ShimCache, UserAssist and BAM from hives on disk; from memory they come from the registry
# values MemProcFS reads (registry_in_memory).
EXECUTION_ARTIFACT_TYPES = (
    "prefetch", "memprocfs_prefetch", "amcache", "memprocfs_amcache",
    "shimcache", "userassist", "bam", "registry_bam",
)
# A Prefetch file created in an MFT still in memory: the first run of a program.
EXECUTION_EVENT_TYPES = ("prefetch_file_created",)
EXECUTION_EVENT_KEYS = ("id", "timestamp", "host", "user", "artifact_type", "event_type", "title", "summary")


def tool_list_executions(db: Session, case_id: str, args: dict) -> dict:
    """Programs that ran, from memory processes (live and exited) and execution artifacts."""
    limit = _limit(args.get("limit"))
    name = str(args.get("process_name") or args.get("query") or "").strip()
    host = args.get("_host")
    sources: dict[str, int] = {}
    warnings: list[str] = []

    memory = _memory_process_executions(db, case_id, host, name, limit)
    sources["memory_processes"] = memory["total"]
    warnings.extend(memory["warnings"])

    events = _event_executions(db, case_id, host, name, limit)
    for key, value in events["by_artifact"].items():
        sources[key] = value
    warnings.extend(events["warnings"])

    registry_runs = [
        run_id for e in _memory_evidences_for_host(db, case_id, host)
        if (run_id := _registry_run_id(str(e.id), case_id, db))
    ]
    registry = _registry_executions(case_id, registry_runs, name, limit)
    sources.update(registry["by_category"])
    if registry.get("warning"):
        warnings.append(registry["warning"])

    notes = list(memory["notes"])
    if not any(sources.values()):
        notes.append(
            "No execution evidence found. Check describe_case and search_memory_artifacts: without a memory "
            "image, Prefetch, Amcache, ShimCache or UserAssist there is nothing that could show it."
        )
    return {
        "by_source": sources,
        "memory_processes": memory["rows"],
        "execution_artifacts": events["rows"],
        "registry_in_memory": registry["rows"],
        "note": " ".join(notes) or None,
        "warnings": warnings,
    }


def _memory_process_executions(db: Session, case_id: str, host: Any, name: str, limit: int) -> dict[str, Any]:
    from app.core.opensearch import get_memory_index, get_opensearch_client

    rows: list[dict[str, Any]] = []
    total = 0
    notes: list[str] = []
    warnings: list[str] = []
    for evidence in _memory_evidences_for_host(db, case_id, host):
        evidence_id = str(evidence.id)
        run_id = _active_run_id(db, case_id, evidence_id, "processes")
        if not run_id:
            continue
        filters: list[dict[str, Any]] = [
            {"term": {"document_type": "memory_process_entity"}},
            {"term": {"evidence_id": evidence_id}},
            {"term": {"scan_run_id.keyword": run_id}},
        ]
        if name:
            needle = name.replace("*", "").replace("?", "")
            filters.append({"wildcard": {"process.name": {"value": f"*{needle}*", "case_insensitive": True}}})
        body = {
            "size": min(limit, 200),
            "timeout": "8s",
            "track_total_hits": True,
            "_source": {"excludes": ["observations"]},
            "query": {"bool": {"filter": filters}},
            "sort": [{"process.create_time": {"order": "asc", "missing": "_last", "unmapped_type": "date"}}],
        }
        try:
            response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Memory process lookup failed: {exc}")
            continue
        hits = response.get("hits") or {}
        count = hits.get("total") or {}
        total += int(count.get("value", 0) if isinstance(count, dict) else count or 0)
        for hit in hits.get("hits") or []:
            item = hit.get("_source") or {}
            process = item.get("process") if isinstance(item.get("process"), dict) else {}
            visibility = item.get("visibility") if isinstance(item.get("visibility"), dict) else {}
            document_id = item.get("document_id") or hit.get("_id")
            row = {
                "id": f"{MEMORY_ID_PREFIX}{document_id}" if document_id else None,
                "evidence_id": evidence_id,
                "pid": process.get("pid"),
                "ppid": process.get("ppid"),
                "process_name": process.get("name"),
                "command_line": _clip(process.get("command_line")),
                "user": process.get("user"),
                "create_time": process.get("create_time"),
                "exit_time": process.get("exit_time"),
                "source_plugins": item.get("source_plugins") or [],
                # Exited, or found only by a pool scan (not in the live process list).
                "terminated": bool(visibility.get("terminated")) or None,
                "scan_only": bool(visibility.get("scan_only")) or None,
                "hidden_candidate": bool(visibility.get("hidden_candidate")) or None,
            }
            rows.append({k: v for k, v in row.items() if v not in (None, "", [])})
        if not _scan_ran(case_id, evidence_id):
            notes.append(
                f"No process pool scan (psscan) on {_evidence_name(evidence)}: processes that had already "
                "exited cannot appear. Run the extended processes profile in the app to look for them."
            )
    return {"total": total, "rows": rows[:limit], "notes": notes, "warnings": warnings}


def _scan_ran(case_id: str, evidence_id: str) -> bool:
    """Whether a process scan that finds exited processes contributed to this image's processes."""
    from app.core.opensearch import get_memory_index, get_opensearch_client

    plugins = ["windows.psscan", "linux.psscan", "memprocfs.processes"]
    body = {"size": 0, "query": {"bool": {"filter": [
        {"term": {"evidence_id": evidence_id}},
        {"term": {"document_type": "memory_process_entity"}},
        {"bool": {"should": [
            {"terms": {"source_plugins": plugins}},
            {"terms": {"source_plugins.keyword": plugins}},
        ], "minimum_should_match": 1}},
    ]}}}
    try:
        response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001 - unknown is reported as not run, which only adds a note
        return False
    total = ((response.get("hits") or {}).get("total")) or {}
    return int(total.get("value", 0) if isinstance(total, dict) else total or 0) > 0


def _event_executions(db: Session, case_id: str, host: Any, name: str, limit: int) -> dict[str, Any]:
    from app.services.search_service import build_search_v2_params, search_events_v2

    by_artifact: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for filters in ({"artifact_type": list(EXECUTION_ARTIFACT_TYPES)}, {"event_type": list(EXECUTION_EVENT_TYPES)}):
        params = build_search_v2_params(
            q=name,
            host_id=host.id if host else None,
            page_size=limit,
            page=1,
            include_highlights=False,
            include_facets=True,
            **filters,
        )
        try:
            total, items, search_warnings, facets = search_events_v2(case_id, params, db=db)
        except Exception as exc:  # noqa: BLE001
            _rollback(db)
            warnings.append(f"Execution artifact lookup failed: {getattr(exc, 'detail', None) or exc}")
            continue
        warnings.extend(search_warnings or [])
        counts = (facets or {}).get("artifact_type") or {}
        if "event_type" in filters:
            if total:
                by_artifact["prefetch_created_in_memory_mft"] = int(total)
        elif counts:
            for key, value in counts.items():
                by_artifact[key] = by_artifact.get(key, 0) + int(value)
        elif total:
            by_artifact["execution_artifacts"] = int(total)
        for item in items:
            row = {key: _clip(item.get(key)) for key in EXECUTION_EVENT_KEYS if item.get(key) not in (None, "", [], {})}
            if row:
                rows.append(row)
    rows.sort(key=lambda row: str(row.get("timestamp") or ""))
    return {"by_artifact": by_artifact, "rows": rows[:limit], "warnings": warnings}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _memory_evidences(db: Session, case_id: str, evidence_id: Any) -> list[Any]:
    from app.services.investigation_memory import memory_evidences

    try:
        return memory_evidences(db, case_id, str(evidence_id).strip() or None if evidence_id else None)
    except Exception as exc:  # HTTPException for an evidence of another case
        raise MemoryToolError(f"No memory evidence '{evidence_id}' in this case.") from exc


def _memory_evidences_for_host(db: Session, case_id: str, host: Any) -> list[Any]:
    evidences = _memory_evidences(db, case_id, None)
    if host is None:
        return evidences
    names = {str(name).lower() for name in (getattr(host, "display_name", None), getattr(host, "canonical_name", None)) if name}
    return [
        e for e in evidences
        if str(getattr(e, "host_id", "") or "") == str(host.id) or str(e.detected_host or "").lower() in names
    ]


def _active_run_id(db: Session, case_id: str, evidence_id: str, family: str) -> str | None:
    from app.services.memory.active_result import resolve_active_memory_result

    try:
        resolved = resolve_active_memory_result(db, case_id=case_id, evidence_id=evidence_id, family=family, page_size=1)
    except Exception:  # noqa: BLE001 - no run is the same answer as no data
        logger.debug("No active %s run for %s", family, evidence_id, exc_info=True)
        _rollback(db)
        return None
    run = resolved.get("active_run") if isinstance(resolved, dict) else None
    return str(run["id"]) if isinstance(run, dict) and run.get("id") else None


def _evidence_name(evidence: Any) -> str:
    return str(getattr(evidence, "original_filename", None) or getattr(evidence, "filename", None) or evidence.id)


def _limit(value: Any) -> int:
    from app.services.ai.tools import _limit as tools_limit

    return tools_limit(value)


def _clip(value: Any) -> Any:
    from app.services.ai.tools import _clip as tools_clip

    return tools_clip(value)


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _rollback(db: Session) -> None:
    try:
        db.rollback()
    except Exception:  # noqa: BLE001
        logger.exception("Could not roll back the session")


# --------------------------------------------------------------------------
# Registry values read from memory
# --------------------------------------------------------------------------

REGISTRY_ROW_KEYS = (
    "category", "key_path", "value_name", "value_data", "decoded", "timestamp", "key_last_write",
    "user_sid", "hive", "evidence_id",
)
REGISTRY_CATEGORIES = (
    "computer_name", "time_zone", "network_interface", "os_version", "profile", "winlogon", "autorun",
    "service", "bam", "userassist", "shimcache", "run_mru", "typed_paths",
)


def tool_get_memory_registry(db: Session, case_id: str, args: dict) -> dict:
    """Registry values read from the hives loaded in a memory image, decoded where known."""
    from app.core.opensearch import get_memory_index, get_opensearch_client

    limit = _limit(args.get("limit"))
    category = str(args.get("category") or "").strip().lower() or None
    if category and category not in REGISTRY_CATEGORIES:
        raise MemoryToolError(f"Unknown category '{category}'. Use one of: {', '.join(REGISTRY_CATEGORIES)}.")
    query = str(args.get("query") or "").strip()
    user_sid = str(args.get("user_sid") or "").strip() or None
    images = []
    rows: list[dict[str, Any]] = []
    total = 0
    not_read: list[str] = []
    for evidence in _memory_evidences(db, case_id, args.get("evidence_id")):
        evidence_id = str(evidence.id)
        run_id = _registry_run_id(evidence_id, case_id, db)
        if not run_id:
            not_read.append(_evidence_name(evidence))
            continue
        filters: list[dict[str, Any]] = [
            _term_any("document_type", "memory_registry_value"),
            {"term": {"evidence_id": evidence_id}},
            {"term": {"scan_run_id.keyword": run_id}},
        ]
        if category:
            filters.append(_term_any("category", category))
        if user_sid:
            filters.append(_term_any("user_sid", user_sid))
        must = []
        if query:
            needle = query.replace("*", "").replace("?", "")
            must.append({"bool": {"should": [
                {"wildcard": {f"{field}.keyword": {"value": f"*{needle}*", "case_insensitive": True}}}
                for field in ("key_path", "value_name", "value_data", "summary", "decoded.program", "decoded.path")
            ], "minimum_should_match": 1}})
        body = {
            "size": limit,
            "timeout": "8s",
            "track_total_hits": True,
            "query": {"bool": {"filter": filters, "must": must}},
            "sort": [{"timestamp": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}],
            "aggs": {"categories": {"terms": {"field": "category.keyword", "size": 30}}},
        }
        response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
        hits = response.get("hits") or {}
        count = hits.get("total") or {}
        count = int(count.get("value", 0) if isinstance(count, dict) else count or 0)
        total += count
        buckets = ((response.get("aggregations") or {}).get("categories") or {}).get("buckets") or []
        images.append({
            "evidence_id": evidence_id,
            "image": _evidence_name(evidence),
            "matches": count,
            "by_category": {bucket["key"]: bucket["doc_count"] for bucket in buckets},
            # The host summary once, on the overview call, not on every filtered lookup.
            **({} if (category or query or user_sid) else {"host": _registry_host_summary(evidence_id, case_id, run_id)}),
        })
        for hit in hits.get("hits") or []:
            source = hit.get("_source") or {}
            row = {key: _clip(source.get(key)) for key in REGISTRY_ROW_KEYS if source.get(key) not in (None, "", [], {})}
            if source.get("status") == "not_in_memory":
                row["status"] = "not_in_memory"
                row["note"] = source.get("summary")
            row["id"] = f"{MEMORY_ID_PREFIX}{source.get('document_id') or hit.get('_id')}"
            rows.append(row)
    notes = []
    if not_read:
        notes.append(
            "The registry has not been read from: " + ", ".join(not_read)
            + ". Run the System information analysis with MemProcFS in the app; zero here means not read, not absent."
        )
    return {
        "total_matches": total,
        "memory_images": images,
        "values": rows[:limit],
        "note": " ".join(notes) or None,
        "hint": "category narrows to one kind: " + ", ".join(REGISTRY_CATEGORIES)
        + ". BAM and UserAssist time when a user ran a program; ShimCache is as loaded at boot and dates the file, not its execution.",
    }


def _registry_run_id(evidence_id: str, case_id: str, db: Session | None = None) -> str | None:
    """The newest analysis run that indexed registry values for this image."""
    from app.core.opensearch import get_memory_index, get_opensearch_client

    body = {
        "size": 0,
        "query": {"bool": {"filter": [_term_any("document_type", "memory_registry_value"), {"term": {"evidence_id": evidence_id}}]}},
        "aggs": {"runs": {"terms": {"field": "scan_run_id.keyword", "size": 50}}},
    }
    try:
        response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001
        return None
    run_ids = [str(bucket["key"]) for bucket in ((response.get("aggregations") or {}).get("runs") or {}).get("buckets") or []]
    if len(run_ids) <= 1 or db is None:
        return run_ids[0] if run_ids else None
    from app.models.memory import MemoryScanRun

    try:
        newest = (
            db.query(MemoryScanRun.id)
            .filter(MemoryScanRun.id.in_(run_ids))
            .order_by(MemoryScanRun.created_at.desc())
            .first()
        )
    except Exception:  # noqa: BLE001
        _rollback(db)
        newest = None
    return str(newest[0]) if newest else run_ids[0]


def _registry_host_summary(evidence_id: str, case_id: str, run_id: str) -> dict[str, Any]:
    """Computer name, time zone, addresses, users and OS that the registry in memory records."""
    from app.core.opensearch import get_memory_index, get_opensearch_client

    body = {
        "size": 200,
        "_source": ["category", "value_name", "value_data", "user_sid", "key_path"],
        "query": {"bool": {"filter": [
            _term_any("document_type", "memory_registry_value"),
            {"term": {"evidence_id": evidence_id}},
            {"term": {"scan_run_id.keyword": run_id}},
            {"bool": {"should": [_term_any("category", c) for c in ("computer_name", "time_zone", "network_interface", "profile", "os_version")], "minimum_should_match": 1}},
        ]}},
    }
    try:
        hits = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"}).get("hits", {}).get("hits", [])
    except Exception:  # noqa: BLE001
        return {}
    summary: dict[str, Any] = {"addresses": [], "user_profiles": []}
    for hit in hits:
        source = hit.get("_source") or {}
        name = str(source.get("value_name") or "").lower()
        value = str(source.get("value_data") or "").strip()
        if not value:
            continue
        category = source.get("category")
        if category == "computer_name" and name == "computername":
            summary["computer_name"] = value
        elif category == "computer_name" and name in ("domain", "nv domain") and value:
            summary["domain"] = value
        elif category == "time_zone" and name == "timezonekeyname":
            summary["time_zone"] = value
        elif category == "network_interface" and name in ("dhcpipaddress", "ipaddress"):
            for address in value.split("|"):
                address = address.strip()
                if address and address not in ("0.0.0.0",) and address not in summary["addresses"]:
                    summary["addresses"].append(address)
        elif category == "profile" and name == "profileimagepath":
            summary["user_profiles"].append({"sid": source.get("user_sid"), "profile": value})
        elif category == "os_version" and name in ("productname", "displayversion", "currentbuild"):
            summary[name] = value
    return {key: value for key, value in summary.items() if value not in (None, "", [])}


def _registry_executions(case_id: str, run_ids: list[str], name: str, limit: int) -> dict[str, Any]:
    """BAM, UserAssist and ShimCache values decoded from the registry in memory, from the newest
    run of each image."""
    from app.core.opensearch import get_memory_index, get_opensearch_client

    if not run_ids:
        return {"by_category": {}, "rows": []}
    filters: list[dict[str, Any]] = [
        _term_any("document_type", "memory_registry_value"),
        {"terms": {"scan_run_id.keyword": run_ids}},
        {"bool": {"should": [_term_any("category", c) for c in ("bam", "userassist", "shimcache")], "minimum_should_match": 1}},
        {"exists": {"field": "decoded"}},
    ]
    if name:
        needle = name.replace("*", "").replace("?", "")
        filters.append({"bool": {"should": [
            {"wildcard": {f"{field}.keyword": {"value": f"*{needle}*", "case_insensitive": True}}}
            for field in ("decoded.program", "decoded.path")
        ], "minimum_should_match": 1}})
    body = {
        "size": limit,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "sort": [{"timestamp": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}],
        "aggs": {"categories": {"terms": {"field": "category.keyword", "size": 5}}},
    }
    try:
        response = get_opensearch_client().search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        return {"by_category": {}, "rows": [], "warning": f"Registry execution lookup failed: {exc}"}
    buckets = ((response.get("aggregations") or {}).get("categories") or {}).get("buckets") or []
    rows = []
    for hit in (response.get("hits") or {}).get("hits") or []:
        source = hit.get("_source") or {}
        rows.append({k: v for k, v in {
            "id": f"{MEMORY_ID_PREFIX}{source.get('document_id') or hit.get('_id')}",
            "source": f"memory_registry_{source.get('category')}",
            "timestamp": source.get("timestamp"),
            "user_sid": source.get("user_sid"),
            "program": (source.get("decoded") or {}).get("program") or (source.get("decoded") or {}).get("path"),
            "detail": _clip(source.get("summary")),
            "evidence_id": source.get("evidence_id"),
        }.items() if v not in (None, "")})
    return {"by_category": {f"memory_registry_{b['key']}": b["doc_count"] for b in buckets}, "rows": rows}


def _term_any(field: str, value: str) -> dict[str, Any]:
    return {"bool": {"should": [{"term": {field: value}}, {"term": {f"{field}.keyword": value}}], "minimum_should_match": 1}}
