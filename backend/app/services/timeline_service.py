from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from dateutil import parser as date_parser
from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.config import get_settings
from app.core.opensearch import fetch_event_by_id
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence
from app.models.event_marking import EventMarking
from app.models.finding import Finding
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.models.timeline_bookmark import TimelineBookmark, TimelineBookmarkCategory, TimelineBookmarkImportance
from app.services.command_history import get_command_history
from app.services.host_identity import normalize_host_alias, resolve_canonical_host
from app.services.investigation_memory import (
    add_event_source_provenance,
    memory_timeline_items,
    normalize_source_category,
    wants_memory_source,
    wants_non_memory_source,
)
from app.services.indicator_resolution import extract_and_resolve_indicators
from app.services.search_service import (
    _dedupe,
    _format_event_result,
    _format_finding_result,
    _parse_time,
    _parse_window,
    _risk_bucket,
    _sort_mixed_items,
    search_events_v2,
    search_findings_v2,
    search_related_to_finding as search_related_to_finding_v2,
)
from app.services.validation_matrix import should_show_validation_matrix


INCIDENT_PHASES = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
    "cleanup",
    "unknown",
]
_INCIDENT_DRAFT_CACHE: dict[str, tuple[datetime, dict[str, Any]]] = {}
_INCIDENT_DRAFT_CACHE_SECONDS = 300
INCIDENT_TIMELINE_BUILDER_VERSION = "v2"

DEFAULT_INCIDENT_TIMELINE_SOURCES = [
    "marked_events",
    "findings",
    "command_history",
    "defender",
    "memory",
]
VALIDATION_SEED_QUERIES: list[dict[str, Any]] = []
TIMELINE_QUICK_FILTERS = [
    {"id": "high_risk", "label": "High risk", "params": {"risk_min": 70}},
    {"id": "findings_only", "label": "Findings only", "params": {"include_findings": True, "kind": "finding"}},
    {"id": "process_executions", "label": "Process executions", "params": {"event_type": ["process_start"]}},
    {"id": "downloads", "label": "Downloads", "params": {"event_type": ["file_downloaded"]}},
    {"id": "defender_detections", "label": "Defender detections", "params": {"artifact_type": ["defender", "detection"]}},
    {"id": "persistence", "label": "Persistence", "params": {"event_category": ["persistence"]}},
    {"id": "network", "label": "Network", "params": {"event_category": ["network"]}},
    {"id": "cloud_usb", "label": "Cloud / USB", "params": {"artifact_type": ["cloud", "cloud_sync", "usb"]}},
    {"id": "deleted_files", "label": "Deleted files", "params": {"event_type": ["file_deleted"]}},
    {"id": "key_events", "label": "Key events", "params": {"key_events_only": True}},
]


def _encode_cursor(offset: int) -> str | None:
    if offset < 0:
        return None
    return base64.urlsafe_b64encode(str(offset).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        return max(0, int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc


def _normalize_iso(value: str | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = date_parser.parse(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _compact_event_row(row: dict[str, Any], *, related_finding_ids: list[str] | None = None, bookmark: TimelineBookmark | None = None) -> dict[str, Any]:
    raw = dict(row.get("raw") or {})
    return {
        "id": row.get("id"),
        "kind": "event",
        "timestamp": row.get("timestamp"),
        "time_bucket": None,
        "title": row.get("title"),
        "summary": row.get("summary"),
        "artifact_type": row.get("artifact_type"),
        "parser": row.get("parser"),
        "event_type": row.get("event_type"),
        "event_category": ((raw.get("event") or {}) if isinstance(raw.get("event"), dict) else {}).get("category"),
        "risk_score": int(row.get("risk_score") or 0),
        "severity": row.get("severity"),
        "host": row.get("host"),
        "user": row.get("user"),
        "evidence_id": raw.get("evidence_id"),
        "source_file": row.get("source_file"),
        "key_entity": _event_key_entity(raw),
        "related_finding_ids": related_finding_ids or [],
        "related_process_node_ids": _event_process_nodes(raw),
        "is_key_event": bool(bookmark),
        "bookmark": _serialize_bookmark(bookmark) if bookmark else None,
        "data_quality": list(raw.get("data_quality") or []),
        "raw": raw,
    }


def _compact_event_row_lightweight(row: dict[str, Any], *, related_finding_ids: list[str] | None = None) -> dict[str, Any]:
    raw = dict(row.get("raw") or {})
    compact_raw: dict[str, Any] = {}
    for key in ("id", "event_id", "stable_event_id", "evidence_id", "case_id", "source_file", "risk_score", "timestamp_precision"):
        if raw.get(key) is not None:
            compact_raw[key] = raw.get(key)
    for key in ("artifact", "event", "process", "file", "url", "browser", "network", "windows", "user", "host", "powershell", "amcache", "shimcache", "jumplist", "scheduled_task"):
        value = raw.get(key)
        if isinstance(value, dict) and value:
            compact_raw[key] = value
    return {
        "id": row.get("id"),
        "kind": "event",
        "timestamp": row.get("timestamp"),
        "time_bucket": None,
        "title": row.get("title"),
        "summary": row.get("summary"),
        "artifact_type": row.get("artifact_type"),
        "parser": row.get("parser"),
        "event_type": row.get("event_type"),
        "event_category": ((compact_raw.get("event") or {}) if isinstance(compact_raw.get("event"), dict) else {}).get("category"),
        "risk_score": int(row.get("risk_score") or 0),
        "severity": row.get("severity"),
        "host": row.get("host"),
        "user": row.get("user"),
        "evidence_id": compact_raw.get("evidence_id"),
        "source_file": row.get("source_file"),
        "key_entity": _event_key_entity(compact_raw),
        "related_finding_ids": related_finding_ids or [],
        "related_process_node_ids": _event_process_nodes(compact_raw),
        "is_key_event": False,
        "bookmark": None,
        "data_quality": list(compact_raw.get("data_quality") or []),
        "raw": compact_raw,
    }


def _compact_finding_row(row: dict[str, Any], *, bookmark: TimelineBookmark | None = None) -> dict[str, Any]:
    raw = dict(row.get("raw") or {})
    return {
        "id": row.get("id"),
        "kind": "finding",
        "timestamp": row.get("timestamp"),
        "time_bucket": None,
        "title": row.get("title"),
        "summary": row.get("summary"),
        "artifact_type": row.get("artifact_type"),
        "event_type": row.get("event_type"),
        "event_category": "finding",
        "risk_score": int(row.get("risk_score") or 0),
        "severity": row.get("severity"),
        "host": row.get("host"),
        "user": row.get("user"),
        "evidence_id": raw.get("evidence_id"),
        "source_file": None,
        "key_entity": _finding_key_entity(raw),
        "related_finding_ids": [str(row.get("id"))],
        "related_process_node_ids": list(raw.get("related_process_node_ids") or []),
        "is_key_event": bool(bookmark),
        "bookmark": _serialize_bookmark(bookmark) if bookmark else None,
        "data_quality": list(raw.get("data_quality") or []),
        "raw": raw,
    }


def _compact_bookmark_row(bookmark: TimelineBookmark, *, event: dict[str, Any] | None = None, case_id: str | None = None, db: Session | None = None) -> dict[str, Any]:
    raw = event or {}
    source_event = _compact_event_row(_format_event_result({"_id": raw.get("id"), "_source": raw}, case_id=case_id, db=db), bookmark=bookmark) if raw else None
    return {
        "id": bookmark.id,
        "kind": "bookmark",
        "timestamp": _normalize_iso(bookmark.timestamp),
        "time_bucket": None,
        "title": bookmark.title,
        "summary": bookmark.summary or bookmark.note or "",
        "artifact_type": source_event.get("artifact_type") if source_event else "bookmark",
        "event_type": source_event.get("event_type") if source_event else bookmark.category.value,
        "event_category": "bookmark",
        "risk_score": source_event.get("risk_score") if source_event else 0,
        "severity": bookmark.importance.value,
        "host": source_event.get("host") if source_event else None,
        "user": source_event.get("user") if source_event else None,
        "evidence_id": (source_event.get("evidence_id") if source_event else None),
        "source_file": source_event.get("source_file") if source_event else None,
        "key_entity": source_event.get("key_entity") if source_event else None,
        "related_finding_ids": [bookmark.finding_id] if bookmark.finding_id else [],
        "related_process_node_ids": source_event.get("related_process_node_ids") if source_event else [],
        "is_key_event": True,
        "bookmark": _serialize_bookmark(bookmark),
        "data_quality": [],
        "raw": raw,
    }


def _event_process_nodes(raw: dict[str, Any]) -> list[str]:
    process = raw.get("process") or {}
    if not isinstance(process, dict):
        return []
    values = [process.get("entity_id"), process.get("guid")]
    return [str(value) for value in values if value]


def _event_key_entity(raw: dict[str, Any]) -> str | None:
    for value in (
        ((raw.get("file") or {}) if isinstance(raw.get("file"), dict) else {}).get("path"),
        ((raw.get("process") or {}) if isinstance(raw.get("process"), dict) else {}).get("command_line"),
        ((raw.get("process") or {}) if isinstance(raw.get("process"), dict) else {}).get("path"),
        ((raw.get("download") or {}) if isinstance(raw.get("download"), dict) else {}).get("target_path"),
        ((raw.get("dns") or {}) if isinstance(raw.get("dns"), dict) else {}).get("domain"),
        ((raw.get("url") or {}) if isinstance(raw.get("url"), dict) else {}).get("full"),
        ((raw.get("network") or {}) if isinstance(raw.get("network"), dict) else {}).get("destination_ip"),
    ):
        if value:
            return str(value)
    return None


def _finding_key_entity(raw: dict[str, Any]) -> str | None:
    for collection_name in ("related_files", "related_domains", "related_ips", "related_hosts", "related_users"):
        values = raw.get(collection_name) or []
        if values:
            return str(values[0])
    return None


def _serialize_bookmark(bookmark: TimelineBookmark) -> dict[str, Any]:
    return {
        "id": bookmark.id,
        "case_id": bookmark.case_id,
        "event_id": bookmark.event_id,
        "stable_event_id": bookmark.stable_event_id,
        "finding_id": bookmark.finding_id,
        "timestamp": _normalize_iso(bookmark.timestamp),
        "title": bookmark.title,
        "summary": bookmark.summary,
        "note": bookmark.note,
        "category": bookmark.category.value,
        "importance": bookmark.importance.value,
        "created_at": _normalize_iso(bookmark.created_at),
        "updated_at": _normalize_iso(bookmark.updated_at),
        "created_by": bookmark.created_by,
        "order_index": bookmark.order_index,
        "include_in_report": bookmark.include_in_report,
        "remap_status": bookmark.remap_status,
    }


def _matches_timeline_filters(item: dict[str, Any], params: dict[str, Any]) -> bool:
    kind = str(params.get("kind") or "").strip().lower()
    if kind and str(item.get("kind") or "").lower() != kind:
        return False

    artifact_types = {str(value).strip().lower() for value in params.get("artifact_type") or [] if str(value).strip()}
    if artifact_types and str(item.get("artifact_type") or "").strip().lower() not in artifact_types:
        return False

    event_types = {str(value).strip().lower() for value in params.get("event_type") or [] if str(value).strip()}
    if event_types and str(item.get("event_type") or "").strip().lower() not in event_types:
        return False

    event_categories = {str(value).strip().lower() for value in params.get("event_category") or [] if str(value).strip()}
    if event_categories and str(item.get("event_category") or "").strip().lower() not in event_categories:
        return False

    risk_score = int(item.get("risk_score") or 0)
    risk_min = params.get("risk_min")
    risk_max = params.get("risk_max")
    if risk_min is not None and risk_score < int(risk_min):
        return False
    if risk_max is not None and risk_score > int(risk_max):
        return False

    host = str(params.get("host") or "").strip().lower()
    if host and str(item.get("host") or "").strip().lower() != host:
        return False

    user = str(params.get("user") or "").strip().lower()
    if user and str(item.get("user") or "").strip().lower() != user:
        return False

    evidence_id = str(params.get("evidence_id") or "").strip()
    if evidence_id and str(item.get("evidence_id") or "").strip() != evidence_id:
        return False

    return True


def _event_map_for_ids(case_id: str, event_ids: list[str]) -> dict[str, dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    for event_id in _dedupe(event_ids):
        event = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
        if event:
            items[event_id] = {"id": event_id, **event}
    return items


def _timeline_groups(items: list[dict[str, Any]], group_by: str) -> list[dict[str, Any]]:
    if group_by not in {"hour", "day"}:
        return []
    buckets: dict[str, dict[str, Any]] = {}
    for item in items:
        timestamp = item.get("timestamp")
        if not timestamp:
            continue
        parsed = _parse_time(str(timestamp))
        if not parsed:
            continue
        bucket = parsed.replace(minute=0, second=0, microsecond=0) if group_by == "hour" else parsed.replace(hour=0, minute=0, second=0, microsecond=0)
        bucket_key = bucket.isoformat().replace("+00:00", "Z")
        entry = buckets.setdefault(
            bucket_key,
            {
                "key": bucket_key,
                "label": bucket.strftime("%d %b %Y %H:00") if group_by == "hour" else bucket.strftime("%d %b %Y"),
                "count": 0,
                "high_risk_count": 0,
            },
        )
        entry["count"] += 1
        if int(item.get("risk_score") or 0) >= 70 or str(item.get("severity") or "") in {"high", "critical"}:
            entry["high_risk_count"] += 1
        item["time_bucket"] = bucket_key
    return [buckets[key] for key in sorted(buckets.keys())]


def _timeline_facets(items: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    facets = {
        "artifact_type": Counter(),
        "event_type": Counter(),
        "risk_bucket": Counter(),
        "host": Counter(),
        "user": Counter(),
        "evidence": Counter(),
        "kind": Counter(),
    }
    for item in items:
        if item.get("artifact_type"):
            facets["artifact_type"][str(item["artifact_type"])] += 1
        if item.get("event_type"):
            facets["event_type"][str(item["event_type"])] += 1
        facets["risk_bucket"][_risk_bucket(int(item.get("risk_score") or 0))] += 1
        if item.get("host"):
            facets["host"][str(item["host"])] += 1
        if item.get("user"):
            facets["user"][str(item["user"])] += 1
        if item.get("evidence_id"):
            facets["evidence"][str(item["evidence_id"])] += 1
        facets["kind"][str(item.get("kind") or "event")] += 1
    return {key: dict(value) for key, value in facets.items()}


def _incident_search_url(case_id: str, item: dict[str, Any]) -> str:
    params: list[str] = []
    if item.get("event_id"):
        params.append(f"event_id={item['event_id']}")
    if item.get("evidence_id"):
        params.append(f"evidence_id={item['evidence_id']}")
    if item.get("host"):
        params.append(f"host={item['host']}")
    if item.get("query"):
        from urllib.parse import quote_plus

        params.append(f"q={quote_plus(str(item['query']))}")
    return f"/cases/{case_id}/search" + (f"?{'&'.join(params)}" if params else "")


def _incident_search_around_url(case_id: str, item: dict[str, Any], *, query: str | None = None, minutes: int = 5) -> str:
    from urllib.parse import quote_plus

    params = ["view=timeline"]
    if item.get("host"):
        params.append(f"host={quote_plus(str(item['host']))}")
    if query:
        params.append(f"q={quote_plus(query)}")
    timestamp = _parse_time(str(item.get("timestamp") or ""))
    if timestamp:
        delta = timedelta(minutes=minutes)
        params.append(f"time_from={(timestamp - delta).isoformat()}")
        params.append(f"time_to={(timestamp + delta).isoformat()}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _incident_execution_story_url(case_id: str, event_id: str | None, evidence_id: str | None, host: str | None) -> str | None:
    if not event_id:
        return None
    from urllib.parse import quote_plus

    params = [f"story_event_id={quote_plus(str(event_id))}", "mode=execution_story"]
    if evidence_id:
        params.append(f"evidence_id={quote_plus(str(evidence_id))}")
    if host:
        params.append(f"host={quote_plus(str(host))}")
    return f"/cases/{case_id}/process-graph?{'&'.join(params)}"


def _fallback_display_host(host: str | None) -> str | None:
    normalized = normalize_host_alias(host)
    if not normalized:
        return None
    short = normalized.split(".", 1)[0]
    if short and short not in {"localhost", "unknown", "-"}:
        return short.upper()
    return normalized.upper()


def _canonical_incident_host(
    db: Session,
    case_id: str,
    host: Any,
    cache: dict[str, dict[str, Any] | None],
) -> tuple[str | None, str | None]:
    raw = str(host or "").strip()
    if not raw:
        return None, None
    key = raw.lower()
    if key not in cache:
        try:
            cache[key] = resolve_canonical_host(db, case_id, raw)
        except Exception:  # noqa: BLE001
            cache[key] = None
    resolved = cache.get(key) or {}
    resolved_name = resolved.get("display_name") or resolved.get("canonical_name")
    display = _fallback_display_host(str(resolved_name or raw)) or str(resolved_name or raw)
    alias = raw if raw and raw.lower() != display.lower() else None
    return display, alias


def _canonicalize_incident_item_hosts(db: Session, case_id: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cache: dict[str, dict[str, Any] | None] = {}
    output: list[dict[str, Any]] = []
    for item in items:
        row = dict(item)
        host, alias = _canonical_incident_host(db, case_id, row.get("host"), cache)
        if host:
            row["host"] = host
            if alias:
                row["host_alias"] = alias
            row["search_url"] = _incident_search_url(case_id, row)
            row["execution_story_url"] = _incident_execution_story_url(case_id, row.get("event_id"), row.get("evidence_id"), host)
        output.append(row)
    return output


def _infer_incident_phase(text: str, *, fallback: str = "unknown") -> tuple[str, str]:
    lower = text.lower()
    if any(token in lower for token in ("psexec", "psexesvc", "\\\\ws", "winrs", "wmic ")):
        return "lateral_movement", "medium"
    if any(token in lower for token in ("rubeus", "kerberoast", "dcsync", "mimikatz", "lsass", "sekurlsa")):
        return "credential_access", "medium"
    if any(token in lower for token in ("whoami", "nltest", "ipconfig", "net view", "net group", "net user", "hostname")):
        return "discovery", "medium"
    if any(token in lower for token in ("-ep bypass", "executionpolicy bypass", "-nop", "-w hidden", "powershell", "cmd.exe /c")):
        return "execution", "medium"
    if any(token in lower for token in ("schtasks", "startup", "runonce", "check-updates", "onedrive")):
        return "persistence", "medium"
    if any(token in lower for token in ("disablerealtimemonitoring", "defender", "tamper", "wevtutil", "clear-eventlog")):
        return "defense_evasion", "medium"
    if any(token in lower for token in ("filezilla", "ftp", "200.234.235.200", "exfil")):
        return "exfiltration", "medium"
    if any(token in lower for token in ("management-passwords", "collection", "desktop", "downloads")):
        return "collection", "low"
    if any(token in lower for token in (".encrypted", ".locked", "readme.txt", "ransom", "encryptor")):
        return "impact", "medium"
    if fallback in INCIDENT_PHASES:
        return fallback, "high" if fallback != "unknown" else "low"
    return "unknown", "low"


def _incident_item(
    case_id: str,
    *,
    source: str,
    title: str,
    summary: str = "",
    timestamp: Any = None,
    host: str | None = None,
    phase: str = "unknown",
    phase_confidence: str = "low",
    artifact_type: str | None = None,
    severity: str | None = None,
    risk_score: int | None = None,
    event_id: str | None = None,
    evidence_id: str | None = None,
    finding_id: str | None = None,
    command_id: str | None = None,
    query: str | None = None,
    notes: str = "",
    status: str | None = None,
    confidence: str | None = None,
    source_type: str | None = None,
) -> dict[str, Any]:
    phase = phase if phase in INCIDENT_PHASES else "unknown"
    source_type = source_type or _timeline_source_type(source)
    item = {
        "id": f"{source}:{event_id or finding_id or command_id or title}:{host or ''}:{phase}",
        "timestamp": _normalize_iso(timestamp) if timestamp else None,
        "host": host,
        "phase": phase,
        "phase_confidence": phase_confidence,
        "confidence": confidence,
        "title": title,
        "summary": summary,
        "source": source,
        "source_type": source_type,
        "artifact_type": artifact_type,
        "severity": severity,
        "risk_score": int(risk_score or 0),
        "event_id": event_id,
        "evidence_id": evidence_id,
        "finding_id": finding_id,
        "command_id": command_id,
        "query": query,
        "notes": notes,
        "included": True,
    }
    if status:
        item["status"] = status
    if confidence:
        item["confidence"] = confidence
    item["provenance_badge"] = _timeline_provenance_badge(item)
    item["search_url"] = _incident_search_url(case_id, item)
    item["execution_story_url"] = _incident_execution_story_url(case_id, event_id, evidence_id, host)
    return item


def _timeline_source_type(source: str | None) -> str:
    normalized = str(source or "").strip().lower()
    mapping = {
        "ground_truth": "validation_matrix",
        "ground_truth_seed": "validation_matrix",
        "finding": "finding",
        "marked_event": "marked_event",
        "defender": "defender_detection",
        "command_history": "command_history",
        "sigma": "sigma_detection",
        "sigma_detection": "sigma_detection",
        "execution_story": "execution_story",
        "heuristic": "heuristic_candidate",
        "heuristic_candidate": "heuristic_candidate",
    }
    return mapping.get(normalized, normalized or "unknown")


def _timeline_provenance_badge(item: dict[str, Any]) -> str:
    confidence = str(item.get("confidence") or "").lower()
    source_type = str(item.get("source_type") or item.get("source") or "").lower()
    if confidence == "ground_truth" or source_type == "validation_matrix":
        return "Ground truth seed"
    if confidence == "analyst_verified":
        return "Analyst verified"
    if source_type == "finding":
        return "Finding"
    if source_type == "marked_event":
        return "Marked event"
    if source_type == "defender_detection":
        return "Defender"
    if source_type == "command_history":
        return "Command History"
    if source_type == "heuristic_candidate":
        return "Suggested"
    return source_type.replace("_", " ").title() or "Unknown"


def _classify_story_target(item: dict[str, Any]) -> dict[str, str]:
    source_type = str(item.get("source_type") or item.get("source") or "").lower()
    artifact_type = str(item.get("artifact_type") or "").lower()
    phase = str(item.get("phase") or "").lower()
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "query", "notes")).lower()
    has_event = bool(item.get("event_id"))
    has_story = bool(item.get("execution_story_url"))
    has_command = bool(item.get("command_id")) or source_type == "command_history"

    if source_type == "defender_detection" or artifact_type == "defender":
        return {
            "story_target_type": "defender_detection",
            "story_target_confidence": "high" if has_event else "medium",
            "story_target_reason": "defender event present",
            "story_primary_action": "Open Defender bundle",
        }
    if phase == "lateral_movement" or any(token in text for token in ("psexec", "psexesvc", "lateral", " -> ", "\\\\ws", "\\\\srv", "\\\\dc")):
        return {
            "story_target_type": "lateral_movement",
            "story_target_confidence": "high" if has_command or has_event else "medium",
            "story_target_reason": "multi-host movement or remote execution indicator",
            "story_primary_action": "Open Movement Story",
        }
    processish_artifacts = {"process", "windows_event", "command_history", "powershell", "sysmon", "security"}
    command_tokens = ("powershell", "cmd", ".ps1", ".exe", "-ep", "-nop", "noexit", "rundll32")
    if has_story and has_event and (artifact_type in processish_artifacts or has_command or phase == "execution") and any(token in text for token in command_tokens):
        return {
            "story_target_type": "exact_process",
            "story_target_confidence": "high",
            "story_target_reason": "source event has process identity",
            "story_primary_action": "Open Execution Story",
        }
    if has_command:
        return {
            "story_target_type": "command",
            "story_target_confidence": "medium",
            "story_target_reason": "command history item present",
            "story_primary_action": "Open Command Bundle",
        }
    file_artifacts = {"mft", "filesystem", "recentdocs", "opensavemru", "userassist", "lnk", "jumplist", "amcache", "shimcache"}
    file_tokens = (".iso", ".lnk", ".encrypted", ".locked", "readme.txt", "\\users\\", "/users/", "content.outlook")
    if artifact_type in file_artifacts or any(token in text for token in file_tokens):
        return {
            "story_target_type": "file_artifact",
            "story_target_confidence": "high" if artifact_type in file_artifacts else "medium",
            "story_target_reason": "artifact/file evidence only",
            "story_primary_action": "Open File Story",
        }
    if has_story and has_event:
        return {
            "story_target_type": "candidate_process",
            "story_target_confidence": "medium",
            "story_target_reason": "event link exists but exact process identity is uncertain",
            "story_primary_action": "Choose related process",
        }
    if source_type == "validation_matrix":
        return {
            "story_target_type": "validation_item",
            "story_target_confidence": "medium",
            "story_target_reason": "validation-only summary",
            "story_primary_action": "Open Validation Detail",
        }
    if item.get("search_url"):
        return {
            "story_target_type": "evidence_bundle",
            "story_target_confidence": "low",
            "story_target_reason": "insufficient process identity; use linked evidence context",
            "story_primary_action": "Open Evidence Bundle",
        }
    return {
        "story_target_type": "none",
        "story_target_confidence": "low",
        "story_target_reason": "insufficient process identity",
        "story_primary_action": "No exact story available",
    }


def _curation_defaults(source: str, *, case_mode: str = "investigation") -> dict[str, str]:
    source_type = _timeline_source_type(source)
    if source_type == "validation_matrix":
        return {"source_type": source_type, "status": "accepted", "confidence": "ground_truth"}
    if source_type in {"finding", "marked_event"}:
        return {"source_type": source_type, "status": "accepted", "confidence": "analyst_verified"}
    if case_mode in {"validation", "demo", "training"}:
        return {"source_type": source_type, "status": "accepted", "confidence": "high"}
    if source_type in {"command_history", "defender_detection", "sigma_detection", "execution_story"}:
        return {"source_type": source_type, "status": "candidate", "confidence": "medium"}
    return {"source_type": source_type, "status": "candidate", "confidence": "low"}


def _event_to_incident_item(case_id: str, row: dict[str, Any], *, source: str, phase: str | None = None, query: str | None = None, title: str | None = None, summary: str | None = None) -> dict[str, Any]:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    event_id = str(row.get("id") or raw.get("id") or raw.get("event_id") or "")
    text = " ".join(str(value or "") for value in (title, summary, row.get("title"), row.get("summary"), row.get("key_entity"), query))
    inferred_phase, confidence = _infer_incident_phase(text, fallback=phase or "unknown")
    return _incident_item(
        case_id,
        source=source,
        title=title or str(row.get("title") or row.get("summary") or query or "Timeline event"),
        summary=summary or str(row.get("summary") or row.get("key_entity") or ""),
        timestamp=row.get("timestamp") or raw.get("@timestamp"),
        host=str(row.get("host") or (((raw.get("host") or {}) if isinstance(raw.get("host"), dict) else {}).get("name") or "")) or None,
        phase=inferred_phase,
        phase_confidence=confidence,
        artifact_type=str(row.get("artifact_type") or (((raw.get("artifact") or {}) if isinstance(raw.get("artifact"), dict) else {}).get("type") or "")) or None,
        severity=str(row.get("severity") or raw.get("severity") or "") or None,
        risk_score=int(row.get("risk_score") or raw.get("risk_score") or 0),
        event_id=event_id or None,
        evidence_id=str(raw.get("evidence_id") or "") or None,
        query=query,
    )


def _dedupe_incident_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(
            str(part or "").strip().lower()
            for part in (
                item.get("event_id"),
                item.get("finding_id"),
                item.get("command_id"),
                item.get("host"),
                item.get("phase"),
                item.get("title"),
            )
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _apply_curation_metadata(items: list[dict[str, Any]], *, case_mode: str = "investigation") -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        row = dict(item)
        defaults = _curation_defaults(str(row.get("source") or ""), case_mode=case_mode)
        row["source_type"] = str(row.get("source_type") or defaults["source_type"])
        row["status"] = str(row.get("status") or defaults["status"])
        row["confidence"] = str(row.get("confidence") or defaults["confidence"])
        row["provenance_badge"] = _timeline_provenance_badge(row)
        output.append(row)
    return output


def _apply_story_target_metadata(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        row = dict(item)
        row.update(_classify_story_target(row))
        output.append(row)
    return output


def _incident_groups(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_phase = Counter(str(item.get("phase") or "unknown") for item in items)
    by_host = Counter(str(item.get("host") or "unknown") for item in items)
    return {
        "phase": [{"key": key, "count": count} for key, count in sorted(by_phase.items())],
        "host": [{"key": key, "count": count} for key, count in sorted(by_host.items())],
    }


def _incident_curation_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(str(item.get("status") or "candidate") for item in items)
    by_source_type = Counter(str(item.get("source_type") or item.get("source") or "unknown") for item in items)
    by_confidence = Counter(str(item.get("confidence") or "low") for item in items)
    return {
        "official_count": int(by_status.get("accepted", 0)),
        "candidate_count": int(by_status.get("candidate", 0)),
        "needs_review_count": int(by_status.get("needs_review", 0)),
        "dismissed_count": int(by_status.get("dismissed", 0)),
        "by_status": dict(sorted(by_status.items())),
        "by_source_type": dict(sorted(by_source_type.items())),
        "by_confidence": dict(sorted(by_confidence.items())),
    }


def _bookmark_query(db: Session, case_id: str, params: dict[str, Any]) -> list[TimelineBookmark]:
    query = db.query(TimelineBookmark).filter(TimelineBookmark.case_id == case_id)
    if params.get("evidence_id") or params.get("host"):
        bookmarks = query.order_by(TimelineBookmark.timestamp.asc(), TimelineBookmark.created_at.asc()).all()
        event_map = _event_map_for_ids(case_id, [bookmark.event_id for bookmark in bookmarks])
        filtered: list[TimelineBookmark] = []
        evidence_filter = str(params.get("evidence_id") or "").strip()
        host_filter = str(params.get("host") or "").strip().lower()
        for bookmark in bookmarks:
            event = event_map.get(bookmark.event_id) or {}
            if evidence_filter and str(event.get("evidence_id") or "") != evidence_filter:
                continue
            if host_filter:
                host_name = str(((event.get("host") or {}) if isinstance(event.get("host"), dict) else {}).get("name") or "").strip().lower()
                if host_name != host_filter:
                    continue
            filtered.append(bookmark)
        return filtered
    return query.order_by(TimelineBookmark.timestamp.asc(), TimelineBookmark.created_at.asc()).all()


def timeline_quick_filters() -> list[dict[str, Any]]:
    return TIMELINE_QUICK_FILTERS


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_default)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _row_count_and_max(db: Session, model: Any, case_id: str, column: Any) -> dict[str, Any]:
    count, max_value = db.query(func.count(model.id), func.max(column)).filter(model.case_id == case_id).one()
    return {"count": int(count or 0), "max": max_value.isoformat() if isinstance(max_value, datetime) else str(max_value or "")}


def _incident_data_fingerprint(db: Session, case_id: str) -> tuple[str, dict[str, Any]]:
    evidence_count, evidence_processed_max = (
        db.query(func.count(Evidence.id), func.max(Evidence.processed_at))
        .filter(Evidence.case_id == case_id)
        .one()
    )
    artifact_count, artifact_created_max, artifact_record_sum = (
        db.query(func.count(Artifact.id), func.max(Artifact.created_at), func.coalesce(func.sum(Artifact.record_count), 0))
        .filter(Artifact.case_id == case_id)
        .one()
    )
    parts = {
        "builder_version": INCIDENT_TIMELINE_BUILDER_VERSION,
        "event_markings": _row_count_and_max(db, EventMarking, case_id, EventMarking.updated_at),
        "findings": _row_count_and_max(db, Finding, case_id, Finding.updated_at),
        "timeline_bookmarks": _row_count_and_max(db, TimelineBookmark, case_id, TimelineBookmark.updated_at),
        "detections": _row_count_and_max(db, DetectionResult, case_id, DetectionResult.created_at),
        "evidence": {
            "count": int(evidence_count or 0),
            "processed_max": evidence_processed_max.isoformat() if isinstance(evidence_processed_max, datetime) else str(evidence_processed_max or ""),
            "statuses": [
                {"id": row.id, "status": str(row.ingest_status.value if hasattr(row.ingest_status, "value") else row.ingest_status), "processed_at": row.processed_at.isoformat() if isinstance(row.processed_at, datetime) else str(row.processed_at or "")}
                for row in db.query(Evidence.id, Evidence.ingest_status, Evidence.processed_at).filter(Evidence.case_id == case_id).order_by(Evidence.id.asc()).all()
            ],
        },
        "artifacts": {
            "count": int(artifact_count or 0),
            "created_max": artifact_created_max.isoformat() if isinstance(artifact_created_max, datetime) else str(artifact_created_max or ""),
            "record_sum": int(artifact_record_sum or 0),
            "by_type": [
                {"artifact_type": str(row[0] or "unknown"), "count": int(row[1] or 0), "records": int(row[2] or 0)}
                for row in db.query(Artifact.artifact_type, func.count(Artifact.id), func.coalesce(func.sum(Artifact.record_count), 0))
                .filter(Artifact.case_id == case_id)
                .group_by(Artifact.artifact_type)
                .order_by(Artifact.artifact_type.asc())
                .all()
            ],
        },
    }
    return _stable_hash(parts), parts


def _incident_options(
    case_id: str,
    sources: list[str],
    host_filter: set[str],
    phase_filter: set[str],
    max_items: int,
    include_low_signal: bool,
) -> tuple[dict[str, Any], str]:
    options = {
        "case_id": case_id,
        "sources": sorted(sources),
        "host": sorted(host_filter),
        "phase": sorted(phase_filter),
        "max_items": max_items,
        "include_low_signal": include_low_signal,
        "builder_version": INCIDENT_TIMELINE_BUILDER_VERSION,
        "no_mft_flood_default": True,
    }
    return options, _stable_hash(options)


def _draft_to_payload(draft: IncidentTimelineDraft, *, hit: bool, stale: bool, reason: str | None = None) -> dict[str, Any]:
    payload = dict(draft.payload or {})
    case_mode = str(payload.get("case_mode") or "investigation")
    items = _apply_curation_metadata([dict(item) for item in (payload.get("items") or []) if isinstance(item, dict)], case_mode=case_mode)
    items = _apply_story_target_metadata(items)
    payload["items"] = items
    payload["curation"] = _incident_curation_summary(items)
    warnings = list(payload.get("warnings") or [])
    if stale:
        warning = "Timeline may be outdated. Use existing draft or regenerate it."
        if reason:
            warning = f"{warning} Reason: {reason}"
        warnings = _dedupe([warning, *warnings])
    payload["warnings"] = warnings
    payload["cache"] = {
        "hit": hit,
        "persistent": True,
        "status": "stale" if stale else "fresh",
        "draft_id": draft.id,
        "timeline_id": draft.id,
        "created_at": draft.created_at.isoformat() if isinstance(draft.created_at, datetime) else str(draft.created_at or ""),
        "updated_at": draft.updated_at.isoformat() if isinstance(draft.updated_at, datetime) else str(draft.updated_at or ""),
        "generated_at": draft.generated_at.isoformat() if isinstance(draft.generated_at, datetime) else str(draft.generated_at or ""),
        "generation_seconds": draft.generation_seconds,
        "builder_version": draft.builder_version,
        "data_fingerprint": draft.data_fingerprint,
        "stale": stale,
        "reason": reason,
    }
    payload["timeline_id"] = draft.id
    payload["status"] = "stale" if stale else "fresh"
    return payload


def _persist_incident_draft(
    db: Session,
    *,
    case_id: str,
    option_key: str,
    cache_key: str,
    sources: list[str],
    filters: dict[str, Any],
    data_fingerprint: str,
    fingerprint_metadata: dict[str, Any],
    payload: dict[str, Any],
    generation_seconds: float,
    generated_by: str,
) -> IncidentTimelineDraft:
    existing = db.query(IncidentTimelineDraft).filter(IncidentTimelineDraft.cache_key == cache_key).one_or_none()
    if existing is None:
        existing = IncidentTimelineDraft(case_id=case_id, option_key=option_key, cache_key=cache_key)
        db.add(existing)
    existing.builder_version = INCIDENT_TIMELINE_BUILDER_VERSION
    existing.data_fingerprint = data_fingerprint
    existing.status = "fresh"
    existing.generated_by = generated_by
    existing.sources = sorted(sources)
    existing.filters = filters
    existing.payload = payload
    existing.item_count = int(payload.get("total") or len(payload.get("items") or []))
    existing.hosts = list(payload.get("hosts") or [])
    existing.phases = list(payload.get("phases") or [])
    existing.generation_seconds = generation_seconds
    existing.generated_at = datetime.now(tz=UTC)
    existing.error_message = None
    existing.summary_metadata = {
        "fingerprint": fingerprint_metadata,
        "item_count": existing.item_count,
        "hosts": existing.hosts,
        "phases": existing.phases,
    }
    stale_rows = (
        db.query(IncidentTimelineDraft)
        .filter(
            IncidentTimelineDraft.case_id == case_id,
            IncidentTimelineDraft.option_key == option_key,
            IncidentTimelineDraft.cache_key != cache_key,
            IncidentTimelineDraft.status == "fresh",
        )
        .all()
    )
    for row in stale_rows:
        row.status = "stale"
    db.commit()
    db.refresh(existing)
    return existing


def build_incident_timeline_draft(db: Session, case_id: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = dict(params or {})
    case = db.get(Case, case_id)
    raw_case_mode = getattr(case, "mode", "") if case is not None else ""
    case_mode = str(getattr(raw_case_mode, "value", raw_case_mode) or "investigation")
    force_regenerate = bool(params.get("regenerate") or params.get("force"))
    generated_by = str(params.get("generated_by") or ("manual" if force_regenerate else "auto")).strip() or "manual"
    sources = [str(item).strip() for item in (params.get("sources") or DEFAULT_INCIDENT_TIMELINE_SOURCES) if str(item).strip()]
    source_set = set(sources)
    raw_host_filter = [str(item).strip() for item in (params.get("host") or params.get("hosts") or []) if str(item).strip()]
    host_filter = {
        (_fallback_display_host(item) or item).strip().lower()
        for item in raw_host_filter
        if str(item).strip()
    }
    phase_filter = {str(item).strip().lower() for item in (params.get("phase") or params.get("phases") or []) if str(item).strip()}
    max_items = min(max(int(params.get("max_items") or 60), 1), 200)
    include_low_signal = bool(params.get("include_low_signal"))
    option_filters, option_key = _incident_options(case_id, sources, host_filter, phase_filter, max_items, include_low_signal)
    persistent_enabled = True
    try:
        data_fingerprint, fingerprint_metadata = _incident_data_fingerprint(db, case_id)
    except Exception:  # noqa: BLE001 - unit-test fakes and non-SQL stores fall back to process cache.
        persistent_enabled = False
        fingerprint_metadata = {"fallback": "memory_only"}
        data_fingerprint = _stable_hash({"case_id": case_id, "builder_version": INCIDENT_TIMELINE_BUILDER_VERSION, "fallback": "memory_only"})
    cache_key = _stable_hash({"option_key": option_key, "data_fingerprint": data_fingerprint})
    now = datetime.now(tz=UTC)
    cached = _INCIDENT_DRAFT_CACHE.get(cache_key)
    if not force_regenerate and cached and (now - cached[0]).total_seconds() <= _INCIDENT_DRAFT_CACHE_SECONDS:
        cached_payload = dict(cached[1])
        cached_payload["cache"] = {
            **dict(cached_payload.get("cache") or {}),
            "hit": True,
            "memory": True,
            "ttl_seconds": _INCIDENT_DRAFT_CACHE_SECONDS,
            "persistent": bool((cached_payload.get("cache") or {}).get("persistent")),
        }
        return cached_payload
    if persistent_enabled and not force_regenerate:
        try:
            fresh_draft = db.query(IncidentTimelineDraft).filter(IncidentTimelineDraft.cache_key == cache_key, IncidentTimelineDraft.status == "fresh").order_by(IncidentTimelineDraft.updated_at.desc()).first()
            if fresh_draft is not None:
                payload = _draft_to_payload(fresh_draft, hit=True, stale=False)
                _INCIDENT_DRAFT_CACHE[cache_key] = (now, payload)
                return payload
            stale_draft = db.query(IncidentTimelineDraft).filter(IncidentTimelineDraft.case_id == case_id, IncidentTimelineDraft.option_key == option_key).order_by(IncidentTimelineDraft.updated_at.desc()).first()
            if stale_draft is not None:
                stale_draft.status = "stale"
                db.commit()
                payload = _draft_to_payload(stale_draft, hit=True, stale=True, reason="Relevant case data changed.")
                _INCIDENT_DRAFT_CACHE[cache_key] = (now, payload)
                return payload
        except Exception:  # noqa: BLE001
            persistent_enabled = False
    warnings: list[str] = []
    items: list[dict[str, Any]] = []
    generation_started = time.perf_counter()

    if "findings" in source_set:
        rows = (
            db.query(Finding)
            .filter(Finding.case_id == case_id)
            .order_by(Finding.time_start.asc().nullslast(), Finding.created_at.asc())
            .limit(100)
            .all()
        )
        for finding in rows:
            text = " ".join(
                str(value or "")
                for value in (
                    finding.title,
                    finding.description,
                    " ".join(str(item) for item in (finding.reasons or [])),
                    " ".join(str(item) for item in (finding.tags or [])),
                )
            )
            phase, confidence = _infer_incident_phase(text, fallback=str(finding.finding_type or "unknown"))
            host = str((finding.related_hosts or [None])[0] or "")
            items.append(
                _incident_item(
                    case_id,
                    source="finding",
                    title=finding.title,
                    summary=finding.description or "; ".join(str(reason) for reason in (finding.reasons or [])[:3]),
                    timestamp=finding.time_start or finding.created_at,
                    host=host or None,
                    phase=phase,
                    phase_confidence=confidence,
                    severity=str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
                    risk_score=int(finding.risk_score or 0),
                    finding_id=finding.id,
                    evidence_id=finding.evidence_id,
                    notes="Finding-linked timeline seed.",
                )
            )

    if "marked_events" in source_set:
        markings = (
            db.query(EventMarking)
            .filter(EventMarking.case_id == case_id, EventMarking.status.in_(["suspicious", "important"]))
            .order_by(EventMarking.timestamp.asc().nullslast(), EventMarking.created_at.asc())
            .limit(100)
            .all()
        )
        event_map = _event_map_for_ids(case_id, [marking.event_id for marking in markings])
        for marking in markings:
            event = event_map.get(marking.event_id) or {}
            if event:
                row = _format_event_result({"_id": marking.event_id, "_source": event}, case_id=case_id, db=db)
                item = _event_to_incident_item(case_id, row, source="marked_event", summary=marking.note or None)
            else:
                phase, confidence = _infer_incident_phase(f"{marking.artifact_type or ''} {marking.note or ''}")
                item = _incident_item(
                    case_id,
                    source="marked_event",
                    title=f"Marked {marking.status} event",
                    summary=marking.note or "",
                    timestamp=marking.timestamp,
                    host=marking.host,
                    phase=phase,
                    phase_confidence=confidence,
                    artifact_type=marking.artifact_type,
                    severity=marking.status,
                    risk_score=80 if marking.status == "suspicious" else 60,
                    event_id=marking.event_id,
                    evidence_id=marking.evidence_id,
                    finding_id=marking.finding_id,
                )
            item["notes"] = marking.note or item.get("notes") or ""
            items.append(item)

    if "command_history" in source_set:
        try:
            commands = get_command_history(
                case_id,
                {
                    "page": 1,
                    "page_size": min(max_items, 100),
                    "only_suspicious": True,
                    "sort": "timestamp_asc",
                },
            ).get("items", [])
            for command in commands:
                text = str(command.get("command") or "")
                phase, confidence = _infer_incident_phase(text)
                parent = command.get("parent_process") if isinstance(command.get("parent_process"), dict) else {}
                summary = "; ".join(str(reason) for reason in (command.get("risk_reasons") or [])[:4])
                if parent.get("name") or parent.get("pid"):
                    summary = f"Parent {parent.get('name') or 'unknown'} PID {parent.get('pid') or '-'}" + (f"; {summary}" if summary else "")
                supporting = [item for item in (command.get("supporting_events") or []) if isinstance(item, dict)]
                source_event = supporting[0] if supporting else {}
                event_id = str(source_event.get("event_doc_id") or source_event.get("event_id") or command.get("source_event_id") or "") or None
                items.append(
                    _incident_item(
                        case_id,
                        source="command_history",
                        title=str(command.get("launcher") or command.get("shell_family") or "Command") + " command",
                        summary=summary or text,
                        timestamp=command.get("timestamp"),
                        host=command.get("host"),
                        phase=phase,
                        phase_confidence=confidence,
                        artifact_type="command_history",
                        severity=_risk_bucket(int(command.get("risk_score") or 0)),
                        risk_score=int(command.get("risk_score") or 0),
                        event_id=event_id,
                        evidence_id=command.get("evidence_id"),
                        command_id=command.get("id"),
                        query=text,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Command History source could not be loaded: {exc}")

    if "defender" in source_set:
        try:
            _total, rows, defender_warnings, _facets = search_events_v2(
                case_id,
                {"artifact_type": ["defender"], "page": 1, "page_size": 50, "sort": "risk_desc", "include_facets": False},
                db=db,
            )
            warnings.extend(defender_warnings)
            for row in rows:
                items.append(_event_to_incident_item(case_id, row, source="defender", phase="defense_evasion"))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Defender source could not be loaded: {exc}")

    if "memory" in source_set:
        try:
            memory_payload = memory_timeline_items(db, case_id, {"page": 1, "page_size": min(max_items, 100), "sort": "timestamp_asc"})
            for row in memory_payload.get("items") or []:
                raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
                phase = "execution" if row.get("event_type") in {"process_start", "process_exit"} else "discovery"
                item = _incident_item(
                    case_id,
                    source="memory",
                    title=str(row.get("title") or "Memory event"),
                    summary=str(row.get("summary") or ""),
                    timestamp=row.get("timestamp"),
                    host=row.get("host"),
                    phase=phase,
                    phase_confidence="medium",
                    artifact_type=str(row.get("artifact_type") or "memory_timeline_event"),
                    severity="info",
                    risk_score=int(row.get("risk_score") or 0),
                    event_id=str(row.get("id") or ""),
                    evidence_id=row.get("evidence_id") or raw.get("evidence_id"),
                )
                item["source_type"] = "memory"
                item["source_category"] = "Memory"
                item["source_plugin_or_parser"] = row.get("source_plugin_or_parser")
                item["search_url"] = f"/cases/{case_id}/search?source_category=Memory&evidence_id={row.get('evidence_id') or raw.get('evidence_id') or ''}"
                item["timeline_url"] = f"/cases/{case_id}/timeline?source_category=Memory&evidence_id={row.get('evidence_id') or raw.get('evidence_id') or ''}"
                item["raw"] = raw
                items.append(item)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Memory source could not be loaded: {exc}")

    ground_truth_enabled = should_show_validation_matrix(case_id, case_mode, validation_mode_enabled=get_settings().validation_features_enabled)
    if "ground_truth" in source_set and ground_truth_enabled:
        for seed in VALIDATION_SEED_QUERIES:
            try:
                search_params = {
                    "q": seed["query"],
                    "host": seed["host"],
                    "artifact_type": seed.get("artifact_type"),
                    "page": 1,
                    "page_size": 1,
                    "sort": "timestamp_asc",
                    "include_facets": False,
                }
                _total, rows, seed_warnings, _facets = search_events_v2(case_id, search_params, db=db)
                warnings.extend(seed_warnings[:1])
                if rows:
                    item = _event_to_incident_item(
                        case_id,
                        rows[0],
                        source="ground_truth_seed",
                        phase=str(seed["phase"]),
                        query=str(seed["query"]),
                        title=str(seed["title"]),
                        summary=str(seed["summary"]),
                    )
                    item["phase"] = str(seed["phase"])
                    item["phase_confidence"] = "high"
                    items.append(item)
                elif include_low_signal:
                    items.append(
                        _incident_item(
                            case_id,
                            source="ground_truth_seed",
                            title=str(seed["title"]),
                            summary=f"No direct indexed event matched `{seed['query']}`. Keep as a validation gap or search manually.",
                            host=str(seed["host"]),
                            phase=str(seed["phase"]),
                            phase_confidence="high",
                            query=str(seed["query"]),
                            notes="No direct match in draft builder.",
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Ground truth seed `{seed['query']}` could not be searched: {exc}")

    items = _apply_curation_metadata(items, case_mode=case_mode)
    items = _canonicalize_incident_item_hosts(db, case_id, items)
    items = _apply_story_target_metadata(items)
    items = _dedupe_incident_items(items)
    if host_filter:
        items = [item for item in items if str(item.get("host") or "").strip().lower() in host_filter]
    if phase_filter:
        items = [item for item in items if str(item.get("phase") or "").strip().lower() in phase_filter]
    items.sort(key=lambda item: (_parse_time(str(item.get("timestamp") or "")) or datetime.max.replace(tzinfo=UTC), str(item.get("host") or ""), str(item.get("phase") or "")))
    items = items[:max_items]
    payload = {
        "case_id": case_id,
        "case_mode": case_mode,
        "query": {
            "sources": sources,
            "host": sorted(host_filter),
            "phase": sorted(phase_filter),
            "max_items": max_items,
            "include_low_signal": include_low_signal,
            "builder_version": INCIDENT_TIMELINE_BUILDER_VERSION,
        },
        "total": len(items),
        "items": items,
        "hosts": sorted({str(item.get("host") or "unknown") for item in items}),
        "phases": [phase for phase in INCIDENT_PHASES if any(item.get("phase") == phase for item in items)],
        "groups": _incident_groups(items),
        "curation": _incident_curation_summary(items),
        "warnings": _dedupe([str(warning) for warning in warnings if str(warning).strip()])[:20],
        "no_mft_flood_default": True,
        "available_sources": DEFAULT_INCIDENT_TIMELINE_SOURCES
        + (["ground_truth"] if ground_truth_enabled else [])
        + ["sigma_detections", "selected_search", "mft_user_activity"],
        "phase_options": INCIDENT_PHASES,
        "cache": {
            "hit": False,
            "persistent": True,
            "status": "fresh",
            "builder_version": INCIDENT_TIMELINE_BUILDER_VERSION,
            "data_fingerprint": data_fingerprint,
            "ttl_seconds": _INCIDENT_DRAFT_CACHE_SECONDS,
        },
    }
    generation_seconds = round(time.perf_counter() - generation_started, 3)
    if persistent_enabled:
        try:
            draft = _persist_incident_draft(
                db,
                case_id=case_id,
                option_key=option_key,
                cache_key=cache_key,
                sources=sources,
                filters=option_filters,
                data_fingerprint=data_fingerprint,
                fingerprint_metadata=fingerprint_metadata,
                payload=payload,
                generation_seconds=generation_seconds,
                generated_by=generated_by,
            )
            payload = _draft_to_payload(draft, hit=False, stale=False)
        except Exception as exc:  # noqa: BLE001
            payload["warnings"] = _dedupe([*list(payload.get("warnings") or []), f"Persistent timeline draft cache could not be updated: {exc}"])[:20]
            payload["cache"] = {**dict(payload.get("cache") or {}), "persistent": False, "status": "fresh", "generation_seconds": generation_seconds}
    else:
        payload["cache"] = {**dict(payload.get("cache") or {}), "persistent": False, "status": "fresh", "generation_seconds": generation_seconds}
    _INCIDENT_DRAFT_CACHE[cache_key] = (now, payload)
    return payload


def export_incident_timeline_markdown(case_id: str, payload: dict[str, Any]) -> str:
    items = [dict(item) for item in (payload.get("items") or []) if isinstance(item, dict)]
    include_candidates = bool(payload.get("include_candidates"))
    if not include_candidates:
        items = [item for item in items if str(item.get("status") or "accepted") == "accepted"]
    title = str(payload.get("title") or "Incident Timeline").strip() or "Incident Timeline"
    if not items:
        return f"## {title}\n\nNo incident timeline items selected.\n"
    group_by = str(payload.get("group_by") or "phase").strip().lower()
    items.sort(key=lambda item: (_parse_time(str(item.get("timestamp") or "")) or datetime.max.replace(tzinfo=UTC), str(item.get("host") or ""), str(item.get("phase") or "")))
    lines = [f"## {title}", "", "| Time | Host | Phase | Event | Evidence | Provenance |", "|---|---|---|---|---|---|"]
    for item in items:
        evidence = ", ".join(
            part
            for part in (
                str(item.get("source") or ""),
                str(item.get("artifact_type") or ""),
                f"event `{item.get('event_id')}`" if item.get("event_id") else "",
                f"finding `{item.get('finding_id')}`" if item.get("finding_id") else "",
            )
            if part
        )
        lines.append(
            "| "
            + " | ".join(
                _escape_markdown_cell(str(value or "-"))
                for value in (
                    _normalize_iso(item.get("timestamp")) or "unknown",
                    item.get("host"),
                    item.get("phase"),
                    f"{item.get('title') or 'Timeline item'} - {item.get('summary') or ''}".strip(" -"),
                    evidence,
                    item.get("provenance_badge") or item.get("source_type") or item.get("source"),
                )
            )
            + " |"
        )
    if group_by in {"phase", "host"}:
        lines.extend(["", f"Grouped by `{group_by}` in the UI."])
    return "\n".join(lines).strip() + "\n"


def update_incident_timeline_item_status(db: Session, case_id: str, timeline_id: str, item_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    draft = db.query(IncidentTimelineDraft).filter(IncidentTimelineDraft.id == timeline_id, IncidentTimelineDraft.case_id == case_id).one_or_none()
    if draft is None:
        raise HTTPException(status_code=404, detail="Incident timeline draft not found")
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"candidate", "accepted", "dismissed", "needs_review"}:
        raise HTTPException(status_code=400, detail="Invalid timeline item status")
    note = str(payload.get("note") or "").strip()
    draft_payload = dict(draft.payload or {})
    items = [dict(item) for item in (draft_payload.get("items") or []) if isinstance(item, dict)]
    updated_item: dict[str, Any] | None = None
    previous_status = "candidate"
    for item in items:
        if str(item.get("id") or "") != item_id:
            continue
        previous_status = str(item.get("status") or "candidate")
        item["status"] = status
        if note:
            item["notes"] = note
        item["provenance_badge"] = _timeline_provenance_badge(item)
        updated_item = item
        break
    if updated_item is None:
        raise HTTPException(status_code=404, detail="Incident timeline item not found")
    draft_payload["items"] = items
    draft_payload["curation"] = _incident_curation_summary(items)
    draft_payload["total"] = len(items)
    draft.payload = draft_payload
    draft.item_count = len(items)
    draft.summary_metadata = {**dict(draft.summary_metadata or {}), "curation": draft_payload["curation"]}
    try:
        log_activity(
            db,
            activity_type="incident_timeline_item_status_updated",
            title="Incident timeline item updated",
            message=f"Timeline item status changed from {previous_status} to {status}",
            case_id=case_id,
            metadata={"timeline_id": timeline_id, "item_id": item_id, "previous_status": previous_status, "new_status": status},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(draft)
    _INCIDENT_DRAFT_CACHE.clear()
    return {"timeline_id": draft.id, "item": updated_item, "curation": draft_payload["curation"]}


def build_incident_timeline_story_bundle(db: Session, case_id: str, item_id: str) -> dict[str, Any]:
    draft = build_incident_timeline_draft(db, case_id, {"max_items": 80})
    items = [dict(item) for item in draft.get("items") or [] if isinstance(item, dict)]
    item = next((row for row in items if str(row.get("id") or "") == item_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Incident timeline item not found")
    target_type = str(item.get("story_target_type") or "evidence_bundle")
    host = str(item.get("host") or "").strip()
    query = str(item.get("query") or "").strip()
    file_reference = _select_file_reference(item)
    file_basename = _extract_file_basename(file_reference) if file_reference else None
    exact_reference_query = file_reference or query or str(item.get("title") or "").strip()
    pivots = {
        "find_this_file": _incident_search_url(case_id, {**item, "query": file_basename or file_reference or query}) if (file_basename or file_reference or query) else item.get("search_url"),
        "view_activity_around_time": _incident_search_around_url(case_id, item, query=file_basename or file_reference or query),
        "search_exact_command_reference": _incident_search_url(case_id, {**item, "query": exact_reference_query}) if exact_reference_query else None,
        "execution_story": item.get("execution_story_url") if target_type == "exact_process" else None,
        "validation_matrix": f"/cases/{case_id}/validation-matrix" if item.get("source_type") == "validation_matrix" else None,
        "open_artifact_evidence": f"/cases/{case_id}/artifacts" + (f"?host={host}" if host else ""),
    }
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "query"))
    movement = None
    if target_type == "lateral_movement":
        movement = {
            "source_host": host or None,
            "destination_host": _extract_destination_host(text),
            "window": "around timeline item timestamp",
            "evidence": [part for part in (item.get("source_type"), item.get("artifact_type"), item.get("event_id"), item.get("command_id")) if part],
        }
    file_story = None
    if target_type == "file_artifact":
        resolution = _referenced_file_resolution(item, file_reference=file_reference, basename=file_basename)
        file_story = {
            "file_name": file_basename,
            "path_or_query": file_reference or query,
            "artifact_type": item.get("artifact_type"),
            "host": host or None,
            "timestamp": item.get("timestamp"),
            "resolution_status": resolution["status"],
            "found_in_mft": resolution["found_in_mft"],
            "found_in_user_activity": resolution["found_in_user_activity"],
            "found_in_defender": resolution["found_in_defender"],
            "found_in_browser": resolution["found_in_browser"],
            "found_only_in_command": resolution["found_only_in_command"],
            "likely_container_or_mounted_media": resolution["likely_container_or_mounted_media"],
            "explanation": resolution["explanation"],
            "suggested_pivots": resolution["suggested_pivots"],
        }
    indicator_resolution = extract_and_resolve_indicators(
        db,
        case_id,
        {
            "source": {
                "title": item.get("title"),
                "summary": item.get("summary"),
                "query": item.get("query"),
                "file_story": file_story,
                "movement": movement,
            },
            "context": {
                "host": host or None,
                "evidence_id": item.get("evidence_id"),
                "timestamp": item.get("timestamp"),
            },
        },
    )
    return {
        "case_id": case_id,
        "item": item,
        "target": {
            "type": target_type,
            "confidence": item.get("story_target_confidence"),
            "reason": item.get("story_target_reason"),
            "primary_action": item.get("story_primary_action"),
        },
        "pivots": pivots,
        "movement": movement,
        "file_story": file_story,
        "indicator_resolution": indicator_resolution,
        "linked_evidence": {
            "event_id": item.get("event_id"),
            "evidence_id": item.get("evidence_id"),
            "finding_id": item.get("finding_id"),
            "command_id": item.get("command_id"),
            "source_type": item.get("source_type"),
            "provenance": item.get("provenance_badge"),
        },
    }


def _extract_destination_host(text: str) -> str | None:
    lowered = str(text or "")
    import re

    match = re.search(r"\\\\([A-Za-z0-9_.-]+)", lowered)
    if match:
        return _fallback_display_host(match.group(1))
    arrow = re.search(r"\b([A-Z]{2,}\d{1,3})\s*[-\u2192>]+\s*([A-Z]{2,}\d{1,3})\b", lowered, flags=re.IGNORECASE)
    if arrow:
        return _fallback_display_host(arrow.group(2))
    return None


def _extract_file_basename(text: str) -> str | None:
    matches = re.findall(r"(?<![A-Za-z0-9_])([.~A-Za-z0-9_:$%{}()\\/\-]+?\.(?:iso|lnk|ps1|exe|dll|txt|encrypted|locked|zip|7z|rar|docx?|xlsx?|bat|cmd|vbs|js|hta))(?![A-Za-z0-9_])", str(text or ""), flags=re.IGNORECASE)
    if not matches:
        return None
    return _clean_file_reference(matches[0]).split("\\")[-1].split("/")[-1]


def _clean_file_reference(value: object | None) -> str:
    return str(value or "").strip().strip("\"'`,;:()[]{}<>")


def _artifact_values(item: dict[str, Any]) -> set[str]:
    raw = item.get("artifact_type")
    if isinstance(raw, list):
        return {str(value).lower() for value in raw if value}
    if raw:
        return {str(raw).lower()}
    return set()


def _select_file_reference(item: dict[str, Any]) -> str | None:
    for key in ("file_path", "file.path", "path", "query"):
        value = item.get(key)
        if value and _extract_file_basename(str(value)):
            return _clean_file_reference(value)
    for key in ("file_name", "file.name", "basename"):
        value = item.get(key)
        if value and _extract_file_basename(str(value)):
            return _clean_file_reference(value)
    indicators = item.get("expected_indicators") or item.get("indicators")
    if isinstance(indicators, list):
        for value in indicators:
            if value and _extract_file_basename(str(value)):
                return _clean_file_reference(value)
    for key in ("summary", "title"):
        basename = _extract_file_basename(str(item.get(key) or ""))
        if basename:
            return basename
    return None


def _referenced_file_resolution(item: dict[str, Any], *, file_reference: str | None, basename: str | None) -> dict[str, Any]:
    artifacts = _artifact_values(item)
    source_type = str(item.get("source_type") or item.get("source") or "").lower()
    found_in_mft = "mft" in artifacts
    found_in_user_activity = bool(artifacts.intersection({"recentdocs", "opensavemru", "userassist", "runmru", "jumplist", "lnk"}) or source_type in {"recentdocs", "opensavemru", "userassist", "user_activity"})
    found_in_defender = "defender" in artifacts or source_type == "defender_detection"
    found_in_browser = "browser" in artifacts or source_type == "browser"
    command_like = source_type in {"command_history", "execution_story"} or bool(item.get("command_id"))
    found_any = found_in_mft or found_in_user_activity or found_in_defender or found_in_browser
    likely_mounted = bool(file_reference and (re.match(r"^[A-Z]:\\", file_reference, flags=re.IGNORECASE) or "\\f\\" in file_reference.lower() or "/f/" in file_reference.lower()))
    return {
        "status": "found_in_artifacts" if found_any else "found_only_in_command" if command_like or basename else "not_resolved",
        "found_in_mft": found_in_mft,
        "found_in_user_activity": found_in_user_activity,
        "found_in_defender": found_in_defender,
        "found_in_browser": found_in_browser,
        "found_only_in_command": not found_any and (command_like or bool(basename)),
        "likely_container_or_mounted_media": likely_mounted,
        "explanation": (
            "The reference is linked to indexed artifact evidence. Use the pivots to inspect the filename/path and nearby host activity."
            if found_any
            else "Referenced by command, but no matching filesystem record was found in indexed MFT/User Activity. Possible reasons: file inside mounted ISO/container, temporary extraction, deleted/unallocated beyond parser visibility, relative path unresolved, or evidence gap."
        ),
        "suggested_pivots": [
            "Find this file",
            "View activity around this time",
            *(["Search exact command/reference", "Command History", "PowerShell logs", "Execution Story"] if command_like else []),
            *(["possible ISO/mounted media"] if not found_any else []),
        ],
    }


def _escape_markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def list_key_events(db: Session, case_id: str) -> list[dict[str, Any]]:
    rows = db.query(TimelineBookmark).filter(TimelineBookmark.case_id == case_id).order_by(TimelineBookmark.order_index.asc(), TimelineBookmark.timestamp.asc(), TimelineBookmark.created_at.asc()).all()
    return [_serialize_bookmark(row) for row in rows]


def create_key_event(db: Session, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    event_id = str(payload.get("event_id") or "").strip()
    if not event_id:
        raise HTTPException(status_code=400, detail="event_id is required")
    event = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    try:
        category = TimelineBookmarkCategory(str(payload.get("category") or "other"))
        importance = TimelineBookmarkImportance(str(payload.get("importance") or "medium"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid bookmark category or importance") from exc
    bookmark = TimelineBookmark(
        case_id=case_id,
        event_id=event_id,
        stable_event_id=str(event.get("stable_event_id") or event.get("event_fingerprint") or "").strip() or None,
        finding_id=str(payload.get("finding_id") or "").strip() or None,
        timestamp=_parse_time(str(event.get("@timestamp") or "")),
        title=str(payload.get("title") or ((event.get("event") or {}) if isinstance(event.get("event"), dict) else {}).get("message") or event.get("raw_summary") or event_id),
        summary=str(payload.get("summary") or event.get("raw_summary") or "") or None,
        note=str(payload.get("note") or "").strip() or None,
        category=category,
        importance=importance,
        created_by=str(payload.get("created_by") or "").strip() or None,
        order_index=int(payload.get("order_index") or 0),
        include_in_report=bool(payload.get("include_in_report", True)),
        remap_status="current",
    )
    db.add(bookmark)
    db.commit()
    db.refresh(bookmark)
    return _serialize_bookmark(bookmark)


def update_key_event(db: Session, case_id: str, bookmark_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    bookmark = db.get(TimelineBookmark, bookmark_id)
    if not bookmark or bookmark.case_id != case_id:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    if "note" in payload:
        bookmark.note = str(payload.get("note") or "").strip() or None
    if "category" in payload and payload.get("category"):
        try:
            bookmark.category = TimelineBookmarkCategory(str(payload["category"]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid bookmark category") from exc
    if "importance" in payload and payload.get("importance"):
        try:
            bookmark.importance = TimelineBookmarkImportance(str(payload["importance"]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid bookmark importance") from exc
    if "order_index" in payload and payload.get("order_index") is not None:
        bookmark.order_index = int(payload["order_index"])
    if "include_in_report" in payload:
        bookmark.include_in_report = bool(payload["include_in_report"])
    db.add(bookmark)
    db.commit()
    db.refresh(bookmark)
    return _serialize_bookmark(bookmark)


def delete_key_event(db: Session, case_id: str, bookmark_id: str) -> None:
    bookmark = db.get(TimelineBookmark, bookmark_id)
    if not bookmark or bookmark.case_id != case_id:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    db.delete(bookmark)
    db.commit()


def export_key_events_markdown(db: Session, case_id: str, filters: dict[str, Any] | None = None) -> str:
    filters = filters or {}
    rows = db.query(TimelineBookmark).filter(TimelineBookmark.case_id == case_id, TimelineBookmark.include_in_report.is_(True)).order_by(TimelineBookmark.order_index.asc(), TimelineBookmark.timestamp.asc(), TimelineBookmark.created_at.asc()).all()
    lines = [
        f"# Case Timeline Export",
        "",
        f"- Case ID: `{case_id}`",
        f"- Generated at: `{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}`",
    ]
    if filters.get("host"):
        lines.append(f"- Host filter: `{filters['host']}`")
    if filters.get("evidence_id"):
        lines.append(f"- Evidence filter: `{filters['evidence_id']}`")
    lines.append("")
    for bookmark in rows:
        lines.extend(
            [
                f"## {bookmark.title}",
                "",
                f"- Timestamp: `{_normalize_iso(bookmark.timestamp) or 'unknown'}`",
                f"- Event ID: `{bookmark.event_id}`",
                f"- Category: `{bookmark.category.value}`",
                f"- Importance: `{bookmark.importance.value}`",
            ]
        )
        if bookmark.finding_id:
            lines.append(f"- Related finding: `{bookmark.finding_id}`")
        if bookmark.note:
            lines.append(f"- Note: {bookmark.note}")
        if bookmark.summary:
            lines.extend(["", bookmark.summary])
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def build_timeline_response(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    mode = str(params.get("mode") or "full")
    sort = str(params.get("sort") or "timestamp_desc")
    page_size = max(1, min(int(params.get("page_size") or 100), 250))
    offset = _decode_cursor(params.get("cursor")) if params.get("cursor") else max(0, (int(params.get("page") or 1) - 1) * page_size)
    include_findings = bool(params.get("include_findings", True))
    include_bookmarks = bool(params.get("include_bookmarks", True))
    params = {**params}
    params.setdefault("scope", "events")
    params.setdefault("include_facets", True)
    params.setdefault("include_highlights", False)
    params.setdefault("page", 1)
    params.setdefault("cursor", None)
    fetch_limit = min(offset + page_size + 50, 500)
    params["page_size"] = fetch_limit

    warnings: list[str] = []
    if wants_memory_source(params):
        return memory_timeline_items(db, case_id, {**params, "page_size": page_size})
    event_params = dict(params)
    if mode == "investigation" and event_params.get("risk_min") is None:
        event_params["risk_min"] = 40
    event_total, event_rows, event_warnings, _ = search_events_v2(case_id, event_params, db=db)
    warnings.extend(event_warnings)

    finding_rows: list[dict[str, Any]] = []
    finding_models: list[Finding] = []
    if include_findings:
        finding_total, finding_rows, finding_models, finding_warnings = search_findings_v2(
            db,
            case_id,
            {
                **params,
                "page_size": fetch_limit,
                "severity": params.get("severity"),
                "evidence_id": params.get("evidence_id"),
                "host": params.get("host"),
            },
            limit_override=fetch_limit,
        )
        warnings.extend(finding_warnings)
    else:
        finding_total = 0

    related_finding_map: dict[str, list[str]] = {}
    if mode == "investigation":
        related_ids = _dedupe([event_id for finding in finding_models for event_id in (finding.related_event_ids or [])])
        related_event_map = _event_map_for_ids(case_id, related_ids)
        existing_ids = {str(item.get("id")) for item in event_rows}
        for finding in finding_models:
            for event_id in _dedupe(finding.related_event_ids or []):
                related_finding_map.setdefault(event_id, []).append(finding.id)
                if event_id not in existing_ids and event_id in related_event_map:
                    hit = {"_id": event_id, "_source": related_event_map[event_id]}
                    event_rows.append(_format_event_result(hit, case_id=case_id, db=db))
                    existing_ids.add(event_id)

    bookmarks = _bookmark_query(db, case_id, params) if include_bookmarks else []
    bookmark_map = {bookmark.event_id: bookmark for bookmark in bookmarks}

    compact_items = [add_event_source_provenance(_compact_event_row(row, related_finding_ids=related_finding_map.get(str(row.get("id")), []), bookmark=bookmark_map.get(str(row.get("id"))))) for row in event_rows]
    compact_findings = [_compact_finding_row(row) for row in finding_rows]
    compact_bookmarks = []
    if include_bookmarks:
        event_map = _event_map_for_ids(case_id, [bookmark.event_id for bookmark in bookmarks])
        compact_bookmarks = [_compact_bookmark_row(bookmark, event=event_map.get(bookmark.event_id), case_id=case_id, db=db) for bookmark in bookmarks]

    memory_payload = None if wants_non_memory_source(params) else memory_timeline_items(db, case_id, {**params, "page": 1, "page_size": fetch_limit})
    memory_items = (memory_payload or {}).get("items") or []
    warnings.extend((memory_payload or {}).get("warnings") or [])
    merged = [item for item in [*compact_items, *compact_findings, *compact_bookmarks, *memory_items] if _matches_timeline_filters(item, params)]
    merged = _filter_timeline_source_category(merged, params)
    merged = _sort_mixed_items(merged, sort)

    if params.get("finding_id"):
        finding_filter = str(params.get("finding_id"))
        merged = [item for item in merged if finding_filter in [str(value) for value in (item.get("related_finding_ids") or [])] or item.get("id") == finding_filter]
    if params.get("process_node_id"):
        process_filter = str(params.get("process_node_id"))
        merged = [item for item in merged if process_filter in [str(value) for value in (item.get("related_process_node_ids") or [])]]
    if params.get("key_events_only"):
        merged = [item for item in merged if item.get("is_key_event")]

    total = len(merged)
    page_items = merged[offset : offset + page_size]
    groups = _timeline_groups(page_items, str(params.get("group_by") or "hour"))
    next_cursor = _encode_cursor(offset + page_size) if offset + page_size < total else None
    return {
        "case_id": case_id,
        "query": params,
        "mode": mode,
        "total": total,
        "page_size": page_size,
        "next_cursor": next_cursor,
        "items": page_items,
        "groups": groups,
        "facets": _timeline_facets(merged) if params.get("include_facets", False) else {},
        "undated_count": int((memory_payload or {}).get("undated_count") or 0),
        "warnings": warnings,
    }


def _filter_timeline_source_category(rows: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    category = normalize_source_category(params.get("source_category") or params.get("source"))
    if not category:
        return rows
    return [row for row in rows if str(row.get("source_category") or (row.get("raw") or {}).get("source_category") or "") == category]


def build_lightweight_timeline_response(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    mode = str(params.get("mode") or "full")
    sort = str(params.get("sort") or "timestamp_desc")
    page_size = max(1, min(int(params.get("page_size") or 100), 500))
    offset = _decode_cursor(params.get("cursor")) if params.get("cursor") else max(0, (int(params.get("page") or 1) - 1) * page_size)
    event_params = {
        **params,
        "scope": "events",
        "page_size": page_size,
        "include_facets": False,
        "include_highlights": False,
        "include_findings": False,
        "include_bookmarks": False,
        "has_timestamp": True,
        "timeline_only": True,
        "include_low_value": False,
        "include_low_confidence_timestamps": False,
        "sort": sort,
    }
    total, event_rows, warnings, _ = search_events_v2(case_id, event_params, db=db)
    page_items = [_compact_event_row_lightweight(row) for row in event_rows if row.get("timestamp")]
    groups = _timeline_groups(page_items, str(params.get("group_by") or "hour"))
    next_cursor = _encode_cursor(offset + page_size) if offset + page_size < total else None
    return {
        "case_id": case_id,
        "query": {**event_params, "lightweight": True},
        "mode": mode,
        "total": total,
        "page_size": page_size,
        "next_cursor": next_cursor,
        "items": page_items,
        "groups": groups,
        "facets": {},
        "warnings": warnings,
        "timeline_status": "lightweight",
        "timestamped_docs_count": total,
        "documents_without_timestamp_count": 0,
    }


def timeline_around_event(db: Session, case_id: str, event_id: str, *, window: str = "30m", page_size: int = 100) -> dict[str, Any]:
    source = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
    if not source:
        raise HTTPException(status_code=404, detail="Event not found")
    timestamp = _parse_time(str(source.get("@timestamp") or ""))
    if not timestamp:
        raise HTTPException(status_code=400, detail="Event does not have a searchable timestamp")
    delta = _parse_window(window)
    return build_timeline_response(
        db,
        case_id,
        {
            "mode": "full",
            "time_from": (timestamp - delta).isoformat(),
            "time_to": (timestamp + delta).isoformat(),
            "evidence_id": source.get("evidence_id"),
            "sort": "timestamp_asc",
            "page_size": page_size,
            "include_findings": True,
            "include_bookmarks": True,
            "group_by": "hour",
        },
    )


def timeline_around_finding(db: Session, case_id: str, finding_id: str, *, window: str = "30m", page_size: int = 100) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if not finding or finding.case_id != case_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    delta = _parse_window(window)
    start = finding.time_start or finding.created_at
    end = finding.time_end or finding.time_start or finding.created_at
    response = build_timeline_response(
        db,
        case_id,
        {
            "mode": "investigation",
            "time_from": (start.astimezone(UTC) - delta).isoformat() if start else None,
            "time_to": (end.astimezone(UTC) + delta).isoformat() if end else None,
            "evidence_id": finding.evidence_id,
            "host": (finding.related_hosts or [None])[0],
            "finding_id": finding_id,
            "sort": "timestamp_asc",
            "page_size": page_size,
            "include_findings": True,
            "include_bookmarks": True,
            "group_by": "hour",
        },
    )
    response["finding"] = _format_finding_result(finding)
    response["related_events"] = search_related_to_finding_v2(db, case_id, finding_id, page_size=page_size)
    return response
