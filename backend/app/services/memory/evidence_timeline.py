"""One memory image's own timeline, for the Timeline tab of a memory evidence.

Two producers, merged in time order:

- Volatility, from the active run of each family: process start and exit (Processes), network
  connection creation (Network), suspicious memory with its process's start time (Suspicious
  Memory) and shell commands that carry their own time (bash on Linux). A few hundred events,
  built in memory from the memory index.
- MemProcFS's forensic timelines (app.services.memory.memprocfs_timeline): NTFS, registry, event
  logs, web, scheduled tasks, Amcache, Prefetch and kernel objects, read page by page from the
  case's events index -- hundreds of thousands of events on a busy system.

Pages are keyed by a cursor (time and id of the last row shown), not by offset, so the next page
of the merge only needs the next rows of each producer, however deep the analyst scrolls.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from dateutil import parser as date_parser
from sqlalchemy.orm import Session

from app.services.memory.memprocfs_timeline import PARSER as MEMPROCFS_PARSER
from app.services.memory.memprocfs_timeline import TIMELINES as MEMPROCFS_TIMELINES

# Event kinds the tab filters on: key -> (producer, label).
VOLATILITY_KINDS: dict[str, str] = {
    "processes": "Process",
    "network": "Network connection",
    "suspicious": "Suspicious memory",
    "shell": "Shell command",
}
# artifact_type of these events in the case Timeline (timeline_service merges them into its view).
VOLATILITY_ARTIFACT_TYPES: dict[str, str] = {
    "processes": "memory_process",
    "network": "memory_network",
    "suspicious": "memory_suspicious",
    "shell": "memory_shell",
}
KINDS: dict[str, tuple[str, str]] = {
    **{key: ("volatility", label) for key, label in VOLATILITY_KINDS.items()},
    **{key: ("memprocfs", label) for key, label in MEMPROCFS_TIMELINES.items()},
}
# Hundreds of thousands of rows: off until the analyst asks for them, as in the case Timeline.
DEFAULT_OFF = ("ntfs", "registry")
DEFAULT_KINDS = tuple(key for key in KINDS if key not in DEFAULT_OFF)
PAGE_SIZES = (50, 100, 250, 500)

# Volatility families -> (active-result family, memory document type, timeline artifact_family).
_VOLATILITY_SOURCES = {
    "processes": ("processes", "memory_process_entity", "processes"),
    "network": ("network", "memory_network_connection", "network"),
    "suspicious": ("suspicious_regions", "memory_suspicious_region", "suspicious"),
    "shell": ("shell_history", "memory_shell_history", "shell_history"),
}


def encode_cursor(timestamp: str, item_id: str) -> str:
    return base64.urlsafe_b64encode(json.dumps([timestamp, item_id]).encode()).decode()


def decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        timestamp, item_id = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return str(timestamp), str(item_id)
    except (ValueError, TypeError):
        return None


def _moment(value: str) -> datetime:
    return date_parser.parse(value)


def _sort_key(item: dict[str, Any]) -> tuple[datetime, str]:
    return _moment(item["timestamp"]), item["id"]


def _after(item: dict[str, Any], cursor: tuple[str, str] | None, descending: bool) -> bool:
    if cursor is None:
        return True
    key, mark = _sort_key(item), (_moment(cursor[0]), cursor[1])
    return key < mark if descending else key > mark


def _matches(item: dict[str, Any], query: str) -> bool:
    if not query:
        return True
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "process_name", "pid")).lower()
    return query.lower() in text


def _volatility_items(db: Session, case_id: str, evidence_id: str, kinds: set[str]) -> list[dict[str, Any]]:
    """Dated Volatility events of the active run of each selected family."""
    from app.core.opensearch import get_memory_index, get_opensearch_client
    from app.services.memory import timeline as memory_timeline
    from app.services.memory.active_result import resolve_active_memory_result
    from app.services.memory.artifact_indexing import _prepare_artifact_document_for_response

    client = get_opensearch_client()
    items: list[dict[str, Any]] = []
    for kind, (family, doc_type, artifact_family) in _VOLATILITY_SOURCES.items():
        if kind not in kinds:
            continue
        resolved = resolve_active_memory_result(db, case_id=case_id, evidence_id=evidence_id, family=family, page_size=1)
        run = resolved.get("active_run") if isinstance(resolved, dict) else None
        run_id = run.get("id") if isinstance(run, dict) else None
        if not run_id:
            continue
        body = {
            "query": {"bool": {"filter": [{"term": {"evidence_id": evidence_id}}, {"term": {"document_type": doc_type}}, {"term": {"scan_run_id.keyword": run_id}}]}},
            "size": 10000,
        }
        response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
        docs = [_prepare_artifact_document_for_response(hit.get("_source", {}) | {"document_id": hit.get("_id")}) for hit in response.get("hits", {}).get("hits", [])]
        events, _undated = memory_timeline._memory_events(case_id, evidence_id, run_id, docs)
        for event in events:
            if event.get("artifact_family") != artifact_family or not event.get("occurred_at"):
                continue
            items.append({
                "id": f"vol-{event['event_id']}",
                "timestamp": event["occurred_at"],
                "producer": "volatility",
                "kind": kind,
                "kind_label": VOLATILITY_KINDS[kind],
                "event_type": event.get("event_kind"),
                "title": event.get("title") or event.get("event_kind"),
                "summary": event.get("summary"),
                "pid": event.get("pid"),
                "process_name": event.get("process_name"),
                "source": event.get("source_plugin"),
                "run_id": run_id,
            })
    return items


def _memprocfs_query(case_id: str, evidence_id: str, kinds: list[str], query: str) -> list[dict[str, Any]]:
    from app.core.opensearch import search_text_substring_clause

    filters: list[dict[str, Any]] = [
        {"term": {"case_id": case_id}},
        {"term": {"evidence_id": evidence_id}},
        {"term": {"artifact.parser": MEMPROCFS_PARSER}},
        {"terms": {"artifact.type": [f"memprocfs_{kind}" for kind in kinds]}},
    ]
    if query:
        filters.append(search_text_substring_clause(f"*{query}*"))
    return filters


def _memprocfs_item(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    artifact = source.get("artifact") or {}
    event = source.get("event") or {}
    kind = str(artifact.get("type") or "").removeprefix("memprocfs_")
    process = source.get("process") or {}
    return {
        "id": source.get("event_id") or hit.get("_id"),
        "timestamp": source.get("@timestamp"),
        "producer": "memprocfs",
        "kind": kind,
        "kind_label": MEMPROCFS_TIMELINES.get(kind, kind),
        "event_type": event.get("type"),
        "title": event.get("message") or source.get("raw_summary"),
        "summary": source.get("raw_summary"),
        "pid": int(process["pid"]) if str(process.get("pid") or "").isdigit() else None,
        "process_name": None,
        "source": "memprocfs.timeline",
        "run_id": (source.get("memprocfs") or {}).get("scan_run_id"),
    }


def _memprocfs_page(case_id: str, evidence_id: str, kinds: list[str], query: str, cursor: tuple[str, str] | None, descending: bool, size: int) -> tuple[list[dict[str, Any]], int]:
    """The next ``size`` MemProcFS events after the cursor, and how many follow it in all."""
    from app.core.opensearch import get_events_index, get_opensearch_client

    if not kinds:
        return [], 0
    filters = _memprocfs_query(case_id, evidence_id, kinds, query)
    if cursor:
        comparison = "lt" if descending else "gt"
        filters.append({"bool": {"should": [
            {"range": {"@timestamp": {comparison: cursor[0]}}},
            {"bool": {"filter": [{"term": {"@timestamp": cursor[0]}}, {"range": {"event_id": {comparison: cursor[1]}}}]}},
        ], "minimum_should_match": 1}})
    order = "desc" if descending else "asc"
    body = {"query": {"bool": {"filter": filters}}, "size": size, "track_total_hits": True, "sort": [{"@timestamp": {"order": order}}, {"event_id": {"order": order}}]}
    try:
        response = get_opensearch_client().search(index=get_events_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001 -- no events index yet: no MemProcFS timeline
        return [], 0
    hits = response.get("hits", {})
    return [_memprocfs_item(hit) for hit in hits.get("hits", [])], int((hits.get("total") or {}).get("value") or 0)


def _memprocfs_counts(case_id: str, evidence_id: str, query: str) -> dict[str, int]:
    from app.core.opensearch import get_events_index, get_opensearch_client

    body = {"query": {"bool": {"filter": _memprocfs_query(case_id, evidence_id, list(MEMPROCFS_TIMELINES), query)}}, "size": 0, "aggs": {"types": {"terms": {"field": "artifact.type", "size": 50}}}}
    try:
        response = get_opensearch_client().search(index=get_events_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001
        return {}
    buckets = (response.get("aggregations") or {}).get("types", {}).get("buckets", [])
    return {str(bucket["key"]).removeprefix("memprocfs_"): int(bucket["doc_count"]) for bucket in buckets}


def memory_evidence_timeline(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    kinds: list[str] | None = None,
    q: str | None = None,
    order: str = "asc",
    cursor: str | None = None,
    page_size: int = 100,
) -> dict[str, Any]:
    selected = [kind for kind in (kinds if kinds is not None else DEFAULT_KINDS) if kind in KINDS]
    descending = order == "desc"
    size = page_size if page_size in PAGE_SIZES else 100
    query = (q or "").strip()
    position = decode_cursor(cursor)

    volatility_all = [item for item in _volatility_items(db, case_id, evidence_id, set(VOLATILITY_KINDS)) if _matches(item, query)]
    counts = {kind: 0 for kind in KINDS}
    for item in volatility_all:
        counts[item["kind"]] += 1
    counts.update(_memprocfs_counts(case_id, evidence_id, query))

    volatility = sorted((item for item in volatility_all if item["kind"] in selected and _after(item, position, descending)), key=_sort_key, reverse=descending)
    memprocfs, memprocfs_remaining = _memprocfs_page(case_id, evidence_id, [kind for kind in selected if KINDS[kind][0] == "memprocfs"], query, position, descending, size)
    merged = sorted([*volatility[:size], *memprocfs], key=_sort_key, reverse=descending)
    page = merged[:size]
    has_more = len(volatility) + memprocfs_remaining > len(page)
    next_cursor = encode_cursor(page[-1]["timestamp"], page[-1]["id"]) if page and has_more else None
    return {
        "items": page,
        "next_cursor": next_cursor,
        "page_size": size,
        "order": "desc" if descending else "asc",
        "selected_kinds": selected,
        "total": sum(counts[kind] for kind in selected),
        "counts": counts,
        "kinds": [{"key": key, "producer": producer, "label": label, "default": key in DEFAULT_KINDS} for key, (producer, label) in KINDS.items()],
    }


def memory_powershell_log(case_id: str, evidence_id: str, *, q: str | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    """PowerShell's own event log records MemProcFS found in this memory image (script blocks,
    command invocations, engine starts), oldest first. Unlike console history they carry the time
    PowerShell logged them."""
    from app.core.opensearch import get_events_index, get_opensearch_client

    page = max(1, int(page))
    size = max(1, min(int(page_size), 200))
    filters: list[dict[str, Any]] = [
        {"term": {"case_id": case_id}},
        {"term": {"evidence_id": evidence_id}},
        {"term": {"artifact.parser": MEMPROCFS_PARSER}},
        {"exists": {"field": "powershell.command"}},
    ]
    query = (q or "").strip()
    if query:
        from app.core.opensearch import search_text_substring_clause

        filters.append(search_text_substring_clause(f"*{query}*"))
    body = {
        "query": {"bool": {"filter": filters}},
        "from": (page - 1) * size,
        "size": size,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "asc"}}, {"event_id": {"order": "asc"}}],
    }
    try:
        response = get_opensearch_client().search(index=get_events_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001 -- no events index yet: nothing recovered
        return {"items": [], "total": 0, "page": page, "page_size": size}
    items = []
    for hit in response.get("hits", {}).get("hits", []):
        source = hit.get("_source") or {}
        powershell = source.get("powershell") or {}
        windows = source.get("windows") or {}
        process = source.get("process") or {}
        number, total = powershell.get("message_number"), powershell.get("message_total")
        items.append({
            "id": source.get("event_id") or hit.get("_id"),
            "timestamp": source.get("@timestamp"),
            "event_id": windows.get("event_id"),
            "channel": windows.get("channel"),
            "pid": int(process["pid"]) if str(process.get("pid") or "").isdigit() else None,
            "command": powershell.get("command"),
            "host_application": powershell.get("host_application"),
            "script_block_id": powershell.get("script_block_id"),
            "part": f"{number}/{total}" if number and total and str(total) != "1" else None,
        })
    return {"items": items, "total": int((response.get("hits", {}).get("total") or {}).get("value") or 0), "page": page, "page_size": size}
