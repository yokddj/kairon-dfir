"""MemProcFS's forensic timelines as case Timeline events.

The forensic scan that memprocfs.findevil already runs also builds timelines from what it finds in
memory. The child (memprocfs_findevil) saves the ones Volatility has no equivalent for -- NTFS
(MFT records still in memory), registry key writes, event log records, browser history, scheduled
tasks, Amcache, Prefetch and kernel objects -- as CSV files under the run's output directory, and
this module indexes them into the case's events index. There the Timeline pages, filters and
searches them like any disk artifact, at any volume; process, network and thread timelines are
left out because pslist/psscan and netscan already give them.

Every row becomes one event: artifact.parser "memprocfs", artifact.type "memprocfs_<timeline>".
Ids are derived from the row, so indexing the same scan again replaces the same events; the
evidence's previous MemProcFS events are removed first, so a new scan never mixes with an old one.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PARSER = "memprocfs"
MEMORY_PLUGIN = "memprocfs.timeline"
# Indexed in this order, so the row cap falls on the bulkiest timelines (registry, NTFS) last.
TIMELINES: dict[str, str] = {
    "eventlog": "Event log",
    "task": "Scheduled task",
    "web": "Web",
    "amcache": "Amcache",
    "prefetch": "Prefetch",
    "kernelobject": "Kernel object",
    "registry": "Registry",
    "ntfs": "NTFS",
}
ARTIFACT_TYPES = tuple(f"memprocfs_{name}" for name in TIMELINES)
# Hundreds of thousands of rows on a busy system: kept out of the default Timeline like MFT, shown
# when filtered by type or searched for.
BULK_ARTIFACT_TYPES = ("memprocfs_ntfs", "memprocfs_registry")
MAX_EVENTS = 1_000_000
BATCH_SIZE = 5000

_ACTIONS = {"CRE": "created", "MOD": "modified", "RD": "read", "DEL": "deleted"}
_VOLUME_PREFIX = re.compile(r"^\\\d+(?=\\)")
_EVTX = re.compile(r"log:\[(?P<log>[^\]]*)\]\s*provider:\[(?P<provider>[^\]]*)\]\s*channel:\[(?P<channel>[^\]]*)\]\s*event:(?P<event>\d+)\s*level:(?P<level>\d+)\s*record:(?P<record>\d+)\s*(?:data:\[(?P<data>.*)\])?", re.S)
_WEB = re.compile(r"browser:\[(?P<browser>[^\]]*)\]\s*type:\[(?P<type>[^\]]*)\]\s*url:\[(?P<url>.*?)\](?:\s*info:\[(?P<info>.*)\])?$", re.S)
# "Name - [command :: arguments] (user)"
_TASK = re.compile(r"^(?P<name>.*?) - \[(?P<command>.*?) :: (?P<arguments>.*?)\] \((?P<user>[^()]*)\)$", re.S)
_AMCACHE_PATH = re.compile(r":\s+(?P<path>[a-z]:\\.+)$", re.I)
_MAX_TEXT = 4096


def _timestamp(value: str) -> str | None:
    try:
        moment = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if moment.year < 1980:
        return None
    return moment.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def _event_id(evidence_id: str, timeline: str, row: dict[str, str]) -> str:
    seed = "|".join([evidence_id, timeline, *(row.get(key) or "" for key in ("Time", "Action", "PID", "Value32", "Value64", "Text"))])
    return "memprocfs-" + hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:40]


def _file_fields(path: str) -> dict[str, Any]:
    name = path.rsplit("\\", 1)[-1]
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else None
    return {"path": path, "name": name or None, "extension": extension, "parent_path": path.rsplit("\\", 1)[0] or None}


def _details(timeline: str, action: str, text: str) -> tuple[str, str, str, dict[str, Any]]:
    """(event.category, event.type, message, extra fields) for one timeline row."""
    verb = _ACTIONS.get(action, action.lower() or "seen")
    if timeline == "ntfs":
        path = _VOLUME_PREFIX.sub("", text)
        file_verb = {"read": "accessed"}.get(verb, verb)
        return "file", f"file_{file_verb}", f"File {file_verb} (MFT in memory): {path}", {"file": _file_fields(path)}
    if timeline == "registry":
        return "registry", "registry_key_modified", f"Registry key written: {text}", {"registry": {"key_path": text, "path": text}}
    if timeline == "eventlog":
        match = _EVTX.search(text)
        if match:
            event_id = int(match["event"])
            data = (match["data"] or "").strip()
            windows = {"event_id": event_id, "provider": match["provider"], "channel": match["channel"], "record_id": match["record"], "level": match["level"], "event_data_summary": data[:_MAX_TEXT]}
            message = f"{match['channel'] or match['log']} event {event_id}" + (f": {data}" if data else "")
            return "windows_event", f"event_id_{event_id}", message, {"windows": windows, "event": {"provider": match["provider"], "channel": match["channel"]}}
        return "windows_event", "windows_event", f"Event log record: {text}", {}
    if timeline == "web":
        match = _WEB.search(text)
        if match:
            kind = match["type"].strip().lower() or "visit"
            url = match["url"].strip()
            info = (match["info"] or "").strip()
            browser = {"browser": match["browser"].strip().lower() or None, "url": url, "title": info or None}
            message = f"{match['browser']} {kind}: {url}" + (f" ({info})" if info else "")
            return "web", f"browser_{kind}", message, {"browser": browser, "url": {"full": url}}
        return "web", "browser_generic", f"Browser history: {text}", {}
    if timeline == "task":
        task_verb = {"read": "last run", "deleted": "run completed"}.get(verb, verb)
        match = _TASK.match(text)
        task: dict[str, Any] = {"name": text}
        if match:
            task = {"name": match["name"].strip(), "command": match["command"].strip(), "arguments": match["arguments"].strip(), "run_as": match["user"].strip()}
            task = {key: value for key, value in task.items() if value and value != "---"}
        return "persistence", "scheduled_task", f"Scheduled task {task_verb}: {text}", {"task": task}
    if timeline == "amcache":
        match = _AMCACHE_PATH.search(text)
        extra = {"amcache": {"file_path": match["path"]}, "file": _file_fields(match["path"])} if match else {}
        return "file", "amcache_entry", text, extra
    if timeline == "kernelobject":
        return "system", f"kernel_object_{verb}", f"Kernel object {verb}: {text}", {"object": {"name": text, "type": "kernel_object"}}
    if timeline == "prefetch":
        return "execution", "prefetch_execution", f"Prefetch: {text}", {}
    return "unknown", f"memprocfs_{timeline}", text, {}


def timeline_event(row: dict[str, str], *, timeline: str, case_id: str, evidence_id: str, scan_run_id: str) -> dict[str, Any] | None:
    """One indexed event for a row of MemProcFS's timeline_<timeline>.csv, or None for a row
    without a usable time."""
    timestamp = _timestamp(row.get("Time") or "")
    text = (row.get("Text") or "").strip()[:_MAX_TEXT]
    if not timestamp or not text:
        return None
    action = (row.get("Action") or "").strip().upper()
    category, event_type, message, extra = _details(timeline, action, text)
    label = TIMELINES.get(timeline, timeline)
    source = f"\\forensic\\csv\\timeline_{timeline}.csv"
    event: dict[str, Any] = {"category": category, "type": event_type, "action": _ACTIONS.get(action, action.lower() or None), "severity": "info", "message": message[:_MAX_TEXT]}
    event.update(extra.pop("event", {}))
    document: dict[str, Any] = {
        "event_id": _event_id(evidence_id, timeline, row),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_file": source,
        "source_tool": PARSER,
        "source_format": "csv",
        "@timestamp": timestamp,
        "timestamp_precision": "second",
        "timezone": "UTC",
        "os": {"type": "windows", "version": None},
        "host": {},
        "artifact": {"type": f"memprocfs_{timeline}", "name": f"MemProcFS {label} timeline", "parser": PARSER, "source_path": source},
        "event": event,
        "memory": {"plugin": MEMORY_PLUGIN},
        "memprocfs": {"scan_run_id": scan_run_id, "timeline": timeline, "action": action, "value32": row.get("Value32"), "value64": row.get("Value64")},
        "raw_summary": text,
        "search_text": message[:_MAX_TEXT],
        "risk_score": 0,
        "tags": ["memory", "memprocfs"],
        **extra,
    }
    pid = (row.get("PID") or "").strip()
    if pid.isdigit() and int(pid) > 0:
        document["process"] = {"pid": pid}
    return document


def timeline_events(directory: Path, *, case_id: str, evidence_id: str, scan_run_id: str, limit: int = MAX_EVENTS) -> Iterator[tuple[str, dict[str, Any]]]:
    """(timeline, event) for every usable row of the saved CSVs, at most ``limit`` in all."""
    emitted = 0
    for timeline in TIMELINES:
        path = directory / f"timeline_{timeline}.csv"
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                if emitted >= limit:
                    return
                document = timeline_event(row, timeline=timeline, case_id=case_id, evidence_id=evidence_id, scan_run_id=scan_run_id)
                if document is None:
                    continue
                emitted += 1
                yield timeline, document


def _delete_previous(case_id: str, evidence_id: str) -> int:
    from app.core.opensearch import get_events_index, get_opensearch_client, index_exists

    client = get_opensearch_client(timeout_seconds=300)
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return 0
    response = client.delete_by_query(
        index=index,
        body={"query": {"bool": {"filter": [{"term": {"evidence_id": evidence_id}}, {"term": {"artifact.parser": PARSER}}]}}},
        params={"refresh": "true", "conflicts": "proceed", "ignore_unavailable": "true"},
    )
    return int(response.get("deleted") or 0)


def index_memprocfs_timeline(directory: Path, *, case_id: str, evidence_id: str, scan_run_id: str) -> dict[str, Any]:
    """Replace the evidence's MemProcFS timeline events with the ones saved in ``directory``."""
    from app.core.opensearch import bulk_index_events_with_report, ensure_case_index, get_events_index, refresh_index

    counts: dict[str, int] = {}
    report: dict[str, Any] = {"indexed": 0, "by_timeline": counts, "truncated": False, "replaced": 0}
    if not directory.is_dir() or not any(directory.glob("timeline_*.csv")):
        return report
    index = ensure_case_index(case_id)
    report["replaced"] = _delete_previous(case_id, evidence_id)
    batch: list[dict[str, Any]] = []

    def flush() -> None:
        if not batch:
            return
        result = bulk_index_events_with_report(case_id, batch, index=index, refresh=False)
        if not result.get("success"):
            raise RuntimeError("MemProcFS timeline events could not be indexed: " + "; ".join((result.get("failed_items") or [])[:5]))
        report["indexed"] += int(result.get("documents_indexed") or 0)
        batch.clear()

    for timeline, document in timeline_events(directory, case_id=case_id, evidence_id=evidence_id, scan_run_id=scan_run_id):
        counts[timeline] = counts.get(timeline, 0) + 1
        batch.append(document)
        if len(batch) >= BATCH_SIZE:
            flush()
    flush()
    report["truncated"] = sum(counts.values()) >= MAX_EVENTS
    refresh_index(get_events_index(case_id), raise_on_error=False)
    logger.info("memprocfs timeline indexed", extra={"case_id": case_id, "evidence_id": evidence_id, "indexed": report["indexed"], "by_timeline": counts})
    return report
