from __future__ import annotations

import copy
import hashlib
import time
from collections import Counter
from collections.abc import Iterable
from typing import Any

from app.core.opensearch import search_documents
from app.ingest.defender.normalizer import normalize_defender_row


DEFENDER_EVTX_BACKEND = "defender_evtx"
DEFENDER_EVENT_IDS = {1006, 1007, 1008, 1011, 1116, 1117, 1118, 1119, 1120, 5007, 5013}


def defender_source_query(case_id: str, evidence_id: str) -> dict[str, Any]:
    return {
        "bool": {
            "filter": [
                {"term": {"case_id": case_id}},
                {"term": {"evidence_id": evidence_id}},
            ],
            "must_not": [{"term": {"artifact.type": "defender"}}],
            "should": [
                {"term": {"artifact.parser": "defender_evtx"}},
                {"wildcard": {"windows.provider": {"value": "*Defender*", "case_insensitive": True}}},
                {"wildcard": {"windows.channel": {"value": "*Defender*", "case_insensitive": True}}},
                {"wildcard": {"event.provider": {"value": "*Defender*", "case_insensitive": True}}},
                {"wildcard": {"event.channel": {"value": "*Defender*", "case_insensitive": True}}},
                {
                    "bool": {
                        "filter": [
                            {"wildcard": {"source_file": {"value": "*Defender*", "case_insensitive": True}}},
                            {"wildcard": {"source_file": {"value": "*.evtx*", "case_insensitive": True}}},
                        ]
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def iter_defender_evtx_source_docs(index: str, case_id: str, evidence_id: str, *, page_size: int = 1000, max_docs: int = 20000) -> Iterable[tuple[str, dict[str, Any]]]:
    query = defender_source_query(case_id, evidence_id)
    offset = 0
    while offset < max_docs:
        result = search_documents(
            index,
            {
                "from": offset,
                "size": min(page_size, max_docs - offset),
                "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}, {"event_id": {"order": "asc", "missing": "_last"}}],
                "query": query,
            },
        )
        hits = list((result.get("hits") or {}).get("hits") or [])
        if not hits:
            break
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            source = dict(hit.get("_source") or {})
            if source:
                yield str(hit.get("_id") or source.get("event_id") or ""), source
        if len(hits) < page_size:
            break
        offset += len(hits)


def _event_id(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _source_event_id(source_id: str, source: dict[str, Any]) -> str:
    return str(source.get("event_id") or source.get("stable_event_id") or source_id or "")


def _stable_defender_event_id(case_id: str, evidence_id: str, source_event_id: str, event_id: int | None, timestamp: str | None) -> str:
    blob = "|".join([case_id, evidence_id, source_event_id, str(event_id or ""), str(timestamp or "")])
    return f"defender:{hashlib.sha1(blob.encode('utf-8', errors='ignore')).hexdigest()}"


def _row_from_source(source: dict[str, Any]) -> dict[str, Any]:
    windows = dict(source.get("windows") or {})
    event = dict(source.get("event") or {})
    row: dict[str, Any] = {}
    event_data = windows.get("event_data")
    if isinstance(event_data, dict):
        row.update(event_data)
    detection = dict(source.get("detection") or {})
    defender = dict(source.get("defender") or {})
    row.update(
        {
            "EventID": windows.get("event_id"),
            "Channel": windows.get("channel") or event.get("channel"),
            "Provider": windows.get("provider") or event.get("provider"),
            "TimeCreated": source.get("@timestamp"),
            "Message": event.get("message"),
            "ThreatName": defender.get("threat_name") or detection.get("threat_name") or row.get("ThreatName"),
            "ThreatID": defender.get("threat_id") or detection.get("threat_id") or row.get("ThreatID") or row.get("ThreatId"),
            "Severity": defender.get("severity") or detection.get("severity") or row.get("Severity"),
            "Category": defender.get("category") or detection.get("category") or row.get("Category"),
            "Action": defender.get("action") or detection.get("action") or row.get("Action"),
            "Status": defender.get("status") or detection.get("status") or row.get("Status"),
            "DetectionSource": defender.get("detection_source") or detection.get("detection_source") or row.get("DetectionSource"),
            "Path": defender.get("path") or detection.get("path") or (source.get("file") or {}).get("path") or row.get("Path"),
            "Resource": defender.get("resource") or detection.get("resource") or row.get("Resource"),
            "ProcessName": (source.get("process") or {}).get("path") or (source.get("process") or {}).get("name") or row.get("ProcessName"),
            "User": (source.get("user") or {}).get("name") or detection.get("user") or row.get("User"),
            "SID": (source.get("user") or {}).get("sid") or detection.get("user_sid") or row.get("SID"),
            "SourceFile": source.get("source_file") or detection.get("source_file") or row.get("SourceFile"),
        }
    )
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}


def _build_search_text(document: dict[str, Any]) -> str:
    values: list[str] = []
    for container, keys in [
        (document.get("event") or {}, ["message", "type", "action", "severity"]),
        (document.get("defender") or {}, ["threat_name", "threat_id", "severity", "category", "status", "action", "action_result", "detection_source", "path", "resource"]),
        (document.get("threat") or {}, ["name", "id", "severity", "category", "status"]),
        (document.get("detection") or {}, ["threat_name", "threat_id", "severity", "category", "status", "action", "path", "resource"]),
        (document.get("file") or {}, ["path", "name", "extension", "sha1", "sha256", "md5"]),
        (document.get("process") or {}, ["name", "path", "executable", "command_line"]),
        (document.get("host") or {}, ["name", "hostname"]),
        (document.get("user") or {}, ["name", "sid"]),
        (document.get("windows") or {}, ["event_id", "provider", "channel"]),
    ]:
        for key in keys:
            value = container.get(key) if isinstance(container, dict) else None
            if value not in (None, "", [], {}):
                values.append(str(value))
    values.extend(str(item) for item in document.get("suspicious_reasons") or [] if item)
    values.extend(str(item) for item in document.get("tags") or [] if item)
    return " | ".join(values)[:32768]


def build_defender_document(source_id: str, source: dict[str, Any]) -> dict[str, Any] | None:
    source_event_id = _source_event_id(source_id, source)
    event_id = _event_id((source.get("windows") or {}).get("event_id"))
    source_provider = str((source.get("windows") or {}).get("provider") or (source.get("event") or {}).get("provider") or "")
    source_channel = str((source.get("windows") or {}).get("channel") or (source.get("event") or {}).get("channel") or "")
    source_file = str(source.get("source_file") or "")
    source_file_is_defender_evtx = "defender" in source_file.lower() and ".evtx" in source_file.lower()
    if event_id not in DEFENDER_EVENT_IDS and not any("defender" in value.lower() for value in [source_provider, source_channel]) and not source_file_is_defender_evtx:
        return None
    document = copy.deepcopy(source)
    row = _row_from_source(source)
    artifact_meta = {
        "artifact_type": "defender",
        "parser": DEFENDER_EVTX_BACKEND,
        "defender_artifact_type": DEFENDER_EVTX_BACKEND,
        "source_tool": DEFENDER_EVTX_BACKEND,
        "source_format": "evtx",
        "source_path": source_file,
        "name": "Microsoft Defender EVTX",
    }
    document = normalize_defender_row(document, row, artifact_meta)
    document["event_id"] = _stable_defender_event_id(str(source.get("case_id") or ""), str(source.get("evidence_id") or ""), source_event_id, event_id, document.get("@timestamp"))
    document["stable_event_id"] = document["event_id"]
    document["artifact"]["type"] = "defender"
    document["artifact"]["parser"] = DEFENDER_EVTX_BACKEND
    document["artifact"]["name"] = "Microsoft Defender EVTX"
    document["source_tool"] = DEFENDER_EVTX_BACKEND
    document["source_format"] = "evtx"
    document["source_file"] = source_file
    document.setdefault("related", {})["source_event_id"] = source_event_id
    document.setdefault("defender", {})["source_event_id"] = source_event_id
    document.setdefault("defender", {})["event_id"] = event_id
    document.setdefault("threat", {}).setdefault("name", (document.get("detection") or {}).get("threat_name"))
    document.setdefault("threat", {}).setdefault("id", (document.get("detection") or {}).get("threat_id"))
    raw = dict(document.get("raw") or {})
    winlog = raw.get("winlog")
    if not isinstance(winlog, dict):
        winlog = {}
    winlog["event_data"] = (source.get("windows") or {}).get("event_data") or row
    raw["winlog"] = winlog
    raw["source_event"] = {
        "event_id": source_event_id,
        "artifact_type": (source.get("artifact") or {}).get("type"),
        "parser": (source.get("artifact") or {}).get("parser"),
    }
    document["raw"] = raw
    key_entity = (document.get("threat") or {}).get("name") or (document.get("file") or {}).get("path") or (document.get("defender") or {}).get("path")
    if key_entity:
        document["key_entity"] = key_entity
    document["search_text"] = _build_search_text(document)
    return document


def build_defender_documents_from_sources(sources: Iterable[tuple[str, dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    started = time.perf_counter()
    docs: list[dict[str, Any]] = []
    event_ids: Counter[str] = Counter()
    threats: Counter[str] = Counter()
    for source_id, source in sources:
        doc = build_defender_document(source_id, source)
        if not doc:
            continue
        docs.append(doc)
        event_id = (doc.get("windows") or {}).get("event_id")
        if event_id is not None:
            event_ids[str(event_id)] += 1
        threat = (doc.get("threat") or {}).get("name") or (doc.get("detection") or {}).get("threat_name")
        if threat:
            threats[str(threat)] += 1
    return docs, {
        "records_read": len(docs),
        "records_parsed": len(docs),
        "by_event_id": dict(event_ids),
        "by_threat": dict(threats),
        "elapsed_seconds": round(time.perf_counter() - started, 2),
    }
