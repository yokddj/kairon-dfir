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

Event log records and Amcache entries are the same records the disk parsers read, so they also go
through the disk normalizer: they get the tags, risk score, user, process and detection fields an
EVTX or Amcache file gives, and the built-in detections disk evidence gets (see
detection_candidates). The type and provenance stay MemProcFS's. NTFS records are not: the MFT
normalizer flags every program and script under AppData, which on a memory image is hundreds of
browser and application files.
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
# Event log rows carry whole PowerShell script blocks.
_MAX_EVENTLOG_TEXT = 32768
# PowerShell's own event log records with a command in them: 4104 script block text, 4103 command
# invocation (Operational log); 400/403/600/800 engine and pipeline records (Windows PowerShell log),
# which name the host's command line.
POWERSHELL_EVENT_IDS = (4104, 4103, 400, 403, 600, 800)
# "Key=Value; Key=Value": a value can itself contain "; ", so split only where a key follows.
_EVENT_DATA_FIELD = re.compile(r";\s+(?=[A-Za-z][A-Za-z0-9_]*=)")
# Inside a field's text: "HostApplication=..." (400/403/600/800) or "Host Application = ..." (4103's
# ContextInfo), and "CommandLine=..." (800), one per line.
# MemProcFS writes the record's level as its number.
_EVENT_LEVELS = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
# What the disk normalizer reads each timeline as.
_DISK_ARTIFACT_META: dict[str, dict[str, str]] = {
    "eventlog": {"artifact_type": "evtx", "parser": "evtxecmd_csv"},
    "amcache": {"artifact_type": "amcache", "parser": "amcache_csv"},
}
# Fields of the disk normalizer's document that describe the record; the rest (ids, host, time,
# artifact, source) stay the memory event's own.
_NORMALIZED_FIELDS = (
    "event", "windows", "user", "process", "parent", "detection", "file", "service", "task", "network", "source",
    "destination", "powershell", "execution", "amcache", "registry", "suspicious_reasons", "risk_score", "data_quality",
)
# A record the disk normalizer does not recognise gets a placeholder message; the memory event's
# own message carries the record's data.
_GENERIC_EVENT_ACTIONS = {"windows_event_observed"}
_PREFETCH = re.compile(r"\\Windows\\Prefetch\\(?P<program>[^\\]+?)-[0-9A-F]{8}\.pf$", re.I)
_HOST_APPLICATION = re.compile(r"Host ?Application\s*=\s*(?P<value>[^\r\n]*)")
_COMMAND_LINE = re.compile(r"CommandLine\s*=\s*(?P<value>[^\r\n]*)")


def _line_value(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text or "")
    if not match:
        return None
    # A flattened record continues with "; NextKey=..." on the same line.
    value = _EVENT_DATA_FIELD.split(match["value"])[0].strip()
    return value or None


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


def event_data_fields(data: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in _EVENT_DATA_FIELD.split(data):
        key, separator, value = part.partition("=")
        if separator and key.strip():
            fields[key.strip()] = value.strip()
    return fields


def powershell_fields(provider: str, channel: str, event_id: int, data: str) -> dict[str, Any] | None:
    """The command a PowerShell event log record names, as the case's powershell.* fields, or None
    when the record is not PowerShell's or names no command."""
    if event_id not in POWERSHELL_EVENT_IDS or "powershell" not in f"{provider} {channel}".lower():
        return None
    fields = event_data_fields(data)
    result: dict[str, Any] = {}
    if event_id == 4104:
        command = fields.get("ScriptBlockText")
        result = {"script_block_text": command, "script_block_id": fields.get("ScriptBlockId"), "path": fields.get("Path") or None, "message_number": fields.get("MessageNumber"), "message_total": fields.get("MessageTotal")}
    elif event_id == 4103:
        command = fields.get("Payload")
        result = {"payload": command, "context_info": fields.get("ContextInfo")}
        result["host_application"] = _line_value(_HOST_APPLICATION, fields.get("ContextInfo") or "")
    else:
        host = _line_value(_HOST_APPLICATION, data)
        command = (_line_value(_COMMAND_LINE, data) if event_id == 800 else None) or host
        result = {"host_application": host}
    if not command:
        return None
    result["command"] = command
    return {key: value for key, value in result.items() if value not in (None, "")}


def _details(timeline: str, action: str, text: str) -> tuple[str, str, str, dict[str, Any]]:
    """(event.category, event.type, message, extra fields) for one timeline row."""
    verb = _ACTIONS.get(action, action.lower() or "seen")
    if timeline == "ntfs":
        path = _VOLUME_PREFIX.sub("", text)
        file_verb = {"read": "accessed"}.get(verb, verb)
        prefetch = _PREFETCH.search(path)
        if prefetch and verb == "created":
            # Windows creates a program's Prefetch file the first time it runs it.
            program = prefetch["program"]
            extra = {"file": _file_fields(path), "process": {"name": program}, "execution": {"source": "prefetch_file_created", "program": program}}
            return "execution", "prefetch_file_created", f"Program run (Prefetch file created, MFT in memory): {program}", extra
        return "file", f"file_{file_verb}", f"File {file_verb} (MFT in memory): {path}", {"file": _file_fields(path)}
    if timeline == "registry":
        return "registry", "registry_key_modified", f"Registry key written: {text}", {"registry": {"key_path": text, "path": text}}
    if timeline == "eventlog":
        match = _EVTX.search(text)
        if match:
            event_id = int(match["event"])
            data = (match["data"] or "").strip()
            windows = {"event_id": event_id, "provider": match["provider"], "channel": match["channel"], "record_id": match["record"], "level": match["level"], "event_data_summary": data[:_MAX_EVENTLOG_TEXT]}
            message = f"{match['channel'] or match['log']} event {event_id}" + (f": {data}" if data else "")
            extra: dict[str, Any] = {"windows": windows, "event": {"provider": match["provider"], "channel": match["channel"]}}
            powershell = powershell_fields(match["provider"], match["channel"], event_id, data)
            if powershell:
                extra["powershell"] = powershell
                extra["process"] = {"name": "powershell.exe"}
                message = f"PowerShell event {event_id}: {powershell['command']}"
            return "windows_event", f"event_id_{event_id}", message, extra
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


def _has_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_has_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_value(item) for item in value)
    return value not in (None, "")


def _disk_row(timeline: str, text: str, timestamp: str) -> dict[str, Any] | None:
    """The row a disk parser would have produced for this record, or None."""
    if timeline == "eventlog":
        match = _EVTX.search(text)
        if not match:
            return None
        data = (match["data"] or "").strip()
        fields = event_data_fields(data)
        return {
            **fields,
            "EventData": fields,
            "EventDataSummary": data,
            "EventId": match["event"],
            "Channel": match["channel"],
            "Provider": match["provider"],
            "RecordNumber": match["record"],
            "Level": _EVENT_LEVELS.get(match["level"], match["level"]),
            "TimeCreated": timestamp,
        }
    if timeline == "amcache":
        match = _AMCACHE_PATH.search(text)
        if not match:
            return None
        return {"FullPath": match["path"], "Name": match["path"].rsplit("\\", 1)[-1], "KeyLastWriteTimestamp": timestamp}
    return None


def _normalize_like_disk(document: dict[str, Any], timeline: str, text: str) -> None:
    """Fill ``document`` with what the disk normalizer reads from the same record."""
    from app.ingest.normalizer import normalize_row

    row = _disk_row(timeline, text, document["@timestamp"])
    if row is None:
        return
    meta = {**_DISK_ARTIFACT_META[timeline], "source_tool": PARSER, "source_format": "csv", "source_path": document["source_file"], "os_type": "windows"}
    try:
        normalized = normalize_row(document["case_id"], document["evidence_id"], "", row, meta)
    except Exception:  # noqa: BLE001 -- the memory event stands on its own
        logger.debug("memprocfs record not normalized", exc_info=True)
        return
    own_message = document["event"]["message"]
    own_powershell = document.get("powershell")
    for field in _NORMALIZED_FIELDS:
        # powershell_fields already decided whether the record names a command; the disk
        # normalizer falls back to "powershell.exe" for an empty script block.
        if field == "powershell" and not own_powershell:
            continue
        value = normalized.get(field)
        # The disk document carries every block, most of them empty for a given record.
        if not _has_value(value):
            continue
        current = document.get(field)
        if isinstance(current, dict) and isinstance(value, dict):
            document[field] = {**current, **{key: item for key, item in value.items() if _has_value(item)}}
        else:
            document[field] = value
    if normalized["event"].get("action") in _GENERIC_EVENT_ACTIONS or not normalized["event"].get("message"):
        document["event"]["message"] = own_message
    if own_powershell:
        document["powershell"] = {**(document.get("powershell") or {}), **own_powershell}
        document.setdefault("process", {})["name"] = document["process"].get("name") or "powershell.exe"
    if timeline == "eventlog" and row.get("EventData"):
        # Where an EVTX record's named fields are kept.
        document["windows"].setdefault("event_data", row["EventData"])
    document["tags"] = sorted({*document.get("tags", []), *normalized.get("tags", [])})
    document["search_text"] = f"{normalized.get('search_text') or ''} {own_message}"[:_MAX_EVENTLOG_TEXT]


def detection_candidates(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The events the disk normalizer flagged, for the built-in detections disk evidence gets."""
    return [document for document in documents if document.get("suspicious_reasons") or int(document.get("risk_score") or 0) > 0]


def timeline_event(row: dict[str, str], *, timeline: str, case_id: str, evidence_id: str, scan_run_id: str) -> dict[str, Any] | None:
    """One indexed event for a row of MemProcFS's timeline_<timeline>.csv, or None for a row
    without a usable time."""
    timestamp = _timestamp(row.get("Time") or "")
    text = (row.get("Text") or "").strip()[: _MAX_EVENTLOG_TEXT if timeline == "eventlog" else _MAX_TEXT]
    if not timestamp or not text:
        return None
    action = (row.get("Action") or "").strip().upper()
    category, event_type, message, extra = _details(timeline, action, text)
    label = TIMELINES.get(timeline, timeline)
    source = f"\\forensic\\csv\\timeline_{timeline}.csv"
    event: dict[str, Any] = {"category": category, "type": event_type, "action": _ACTIONS.get(action, action.lower() or None), "severity": "info", "message": message[:_MAX_EVENTLOG_TEXT]}
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
        "search_text": message[:_MAX_EVENTLOG_TEXT],
        "risk_score": 0,
        "tags": ["memory", "memprocfs"],
        **extra,
    }
    if timeline in _DISK_ARTIFACT_META:
        _normalize_like_disk(document, timeline, text)
    pid = (row.get("PID") or "").strip()
    if pid.isdigit() and int(pid) > 0:
        document.setdefault("process", {})["pid"] = pid
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
    from app.core.opensearch import delete_by_query_and_wait, get_events_index, get_opensearch_client, index_exists

    client = get_opensearch_client(timeout_seconds=300)
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return 0
    return delete_by_query_and_wait(client, index, {"bool": {"filter": [{"term": {"evidence_id": evidence_id}}, {"term": {"artifact.parser": PARSER}}]}})


def create_timeline_detections(db: Any, *, case_id: str, evidence_id: str, candidates: list[dict[str, Any]]) -> dict[str, int]:
    """The built-in detections of the indexed memory events: per event, as disk ingest creates
    them, and the mass-encryption check over the evidence's file events. Indexing again finds the
    same events and adds nothing."""
    from app.services.mass_encryption import detect_mass_file_encryption
    from app.workers.tasks import _create_builtin_detections_for_ids

    created = {"builtin": 0, "mass_encryption": 0}
    try:
        created["builtin"] = _create_builtin_detections_for_ids(db, case_id=case_id, evidence_id=evidence_id, artifact_id=None, documents=candidates)
    except Exception:  # noqa: BLE001 -- the events are indexed either way
        db.rollback()
        logger.warning("memprocfs timeline: built-in detections failed", exc_info=True)
    try:
        created["mass_encryption"] = detect_mass_file_encryption(db, case_id=case_id, evidence_id=evidence_id)
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.warning("memprocfs timeline: mass-encryption check failed", exc_info=True)
    return created


def index_memprocfs_timeline(directory: Path, *, case_id: str, evidence_id: str, scan_run_id: str, db: Any = None) -> dict[str, Any]:
    """Replace the evidence's MemProcFS timeline events with the ones saved in ``directory``, and
    with ``db``, create their detections."""
    from app.core.opensearch import bulk_index_events_with_report, ensure_case_index, get_events_index, refresh_index

    counts: dict[str, int] = {}
    report: dict[str, Any] = {"indexed": 0, "by_timeline": counts, "truncated": False, "replaced": 0}
    if not directory.is_dir() or not any(directory.glob("timeline_*.csv")):
        return report
    index = ensure_case_index(case_id)
    report["replaced"] = _delete_previous(case_id, evidence_id)
    batch: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    def flush() -> None:
        if not batch:
            return
        candidates.extend(detection_candidates(batch))
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
    if db is not None:
        report["detections"] = create_timeline_detections(db, case_id=case_id, evidence_id=evidence_id, candidates=candidates)
    logger.info("memprocfs timeline indexed", extra={"case_id": case_id, "evidence_id": evidence_id, "indexed": report["indexed"], "by_timeline": counts})
    return report
