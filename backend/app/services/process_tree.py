from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import PureWindowsPath
import time
from typing import Any

from dateutil import parser as date_parser

from app.api.routes_search import build_search_query
from app.core.opensearch import fetch_event_by_id, get_events_index, search_documents
from app.models.case import Case
from app.models.evidence import Evidence
from app.schemas.event import SearchRequest
from app.services.host_identity import normalize_host_alias
from app.analysis.suspicious import normalize_windows_path_for_classification


@dataclass
class _ProcessTreeContext:
    case: Case
    evidences: list[Evidence]
    export_timestamp: datetime
    scope: str = "case"
    evidence_id: str | None = None
    event_ids: list[str] = field(default_factory=list)
    artifact_types: list[str] = field(default_factory=list)
    include_raw_samples: bool = False
    include_raw_xml: bool = False
    max_events_per_type: int = 250
    search_request: SearchRequest | None = None


def _build_scope_search_request(context: _ProcessTreeContext, *, page_size: int) -> SearchRequest:
    case_id = context.case.id
    page_size = min(int(page_size), 200)
    if context.scope == "selected_events":
        return SearchRequest(case_id=case_id, query="*", page=1, page_size=page_size)

    search_request = context.search_request
    if search_request is None:
        search_request = SearchRequest(case_id=case_id, query="*", page=1, page_size=page_size)
        if context.evidence_id:
            search_request.filters.evidence_id = [context.evidence_id]
        if context.artifact_types:
            search_request.filters.artifact_type = context.artifact_types
    else:
        search_request = search_request.model_copy(deep=True)
        search_request.case_id = case_id
        search_request.page = 1
        search_request.page_size = page_size
        if context.evidence_id and context.evidence_id not in search_request.filters.evidence_id:
            search_request.filters.evidence_id = [context.evidence_id]
        if context.artifact_types:
            search_request.filters.artifact_type = context.artifact_types
    return search_request


def _search_scope_events(
    context: _ProcessTreeContext,
    *,
    size: int,
    extra_filters: list[dict] | None = None,
    timeline: bool = False,
) -> tuple[list[dict], int, dict[str, Any] | None]:
    if context.scope == "selected_events":
        events = []
        for event_id in context.event_ids:
            event = fetch_event_by_id(context.case.id, event_id)
            if event:
                events.append(event)
        return events[:size], len(events), None

    page_size = min(max(context.max_events_per_type * 30, 300), 200)
    search_request = _build_scope_search_request(context, page_size=page_size)
    body = build_search_query(search_request, timeline=timeline)
    body["size"] = size
    body["track_total_hits"] = True
    body["_source"] = _process_tree_source_fields(
        include_raw_samples=context.include_raw_samples,
        include_raw_xml=context.include_raw_xml,
    )
    if extra_filters:
        filters = (((body.get("query") or {}).get("bool") or {}).get("filter") or [])
        filters.extend(extra_filters)
    response = search_documents(get_events_index(context.case.id), body)
    hits = response.get("hits", {}).get("hits", [])
    total = int((((response.get("hits") or {}).get("total") or {}).get("value")) or 0)
    events = [{"opensearch_id": hit.get("_id"), "search_doc_id": hit.get("_id"), "id": hit.get("_id"), **(hit.get("_source") or {})} for hit in hits]
    return events, total, body.get("query")


def _process_tree_source_fields(*, include_raw_samples: bool, include_raw_xml: bool) -> list[str]:
    fields = [
        "id",
        "event_id",
        "stable_event_id",
        "event_fingerprint",
        "event_fingerprint_version",
        "case_id",
        "evidence_id",
        "artifact_id",
        "source_file",
        "source_tool",
        "source_format",
        "@timestamp",
        "timestamp_precision",
        "host",
        "user",
        "artifact",
        "event",
        "windows",
        "process",
        "file",
        "url",
        "download",
        "execution",
        "persistence",
        "service",
        "usb",
        "volume",
        "prefetch",
        "shimcache",
        "appcompat",
        "registry",
        "lnk",
        "browser",
        "powershell",
        "detection",
        "wmi",
        "bits",
        "cloud",
        "network",
        "dns",
        "wlan",
        "srum",
        "recycle",
        "tags",
        "data_quality",
        "risk_score",
        "suspicious_reasons",
        "raw_summary",
    ]
    if include_raw_samples:
        fields.append("raw")
        if include_raw_xml:
            fields.append("raw.RawXml")
            fields.append("raw.raw_xml")
    return fields


def _nested_get(data: dict, dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _is_process_start_event(event: dict) -> bool:
    event_type = str(_nested_get(event, "event.type") or "")
    artifact_type = str(_nested_get(event, "artifact.type") or "")
    return event_type in {"process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"} or artifact_type == "process"


def _safe_parse_dt(value: object | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = date_parser.parse(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:  # noqa: BLE001
        return None


def _safe_intish(value: object | None) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except Exception:  # noqa: BLE001
        return None


def _safe_name_from_path(value: object | None) -> str | None:
    text = normalize_windows_path_for_classification(str(value or "").strip())
    if not text:
        return None
    try:
        return PureWindowsPath(text).name or text
    except Exception:  # noqa: BLE001
        return text.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or text


def _path_is_user_writable(path: str | None) -> bool:
    lowered = str(path or "").lower()
    return any(token in lowered for token in ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\startup\\", "\\public\\"))


def _path_bucket_reason(path: str | None) -> list[str]:
    lowered = str(path or "").lower()
    reasons: list[str] = []
    if _path_is_user_writable(path):
        reasons.append("Process from user-writable path")
    if "\\temp\\" in lowered:
        reasons.append("Process from Temp")
    if "\\downloads\\" in lowered:
        reasons.append("Process from Downloads")
    return reasons


def _double_extension(path: str | None) -> bool:
    name = _safe_name_from_path(path)
    if not name:
        return False
    parts = name.lower().split(".")
    return len(parts) >= 3 and parts[-1] in {"exe", "scr", "ps1", "bat", "cmd", "js", "vbs", "hta"} and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"}


def _is_program_files_path(path: str | None) -> bool:
    lowered = str(path or "").lower()
    return lowered.startswith("c:\\program files\\") or lowered.startswith("c:\\program files (x86)\\")


def _is_browser_internal_child(parent_name: str | None, child_name: str | None, child_path: str | None) -> bool:
    normalized_parent = str(parent_name or "").lower().strip()
    normalized_child = str(child_name or "").lower().strip()
    if not normalized_parent:
        return False
    browser_process_names = {"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe"}
    browser_internal_child_names = browser_process_names | {"identity_helper.exe"}
    if normalized_parent not in browser_process_names:
        return False
    if normalized_child not in browser_internal_child_names:
        return False
    if normalized_child not in {normalized_parent, "identity_helper.exe"}:
        return False
    return _is_program_files_path(child_path)


def _process_badges_and_risk(node: dict) -> tuple[int, list[str], list[str]]:
    process_name = str(node.get("name") or "").lower()
    command_line = str(node.get("command_line") or "").lower()
    process_path = str(node.get("path") or "")
    reasons: list[str] = []
    badges: list[str] = []
    score = int(node.get("risk_score") or 0)

    if "powershell" in process_name:
        badges.append("powershell")
    if any(name in process_name for name in ("powershell.exe", "pwsh.exe")) and "-encodedcommand" in command_line or " -enc " in command_line:
        badges.append("encoded_command")
        reasons.append("Process uses encoded PowerShell")
        score = max(score, 95)
    if "executionpolicy bypass" in command_line or " -ep bypass" in command_line:
        reasons.append("Process uses execution policy bypass")
        score = max(score, 90)
    if "windowstyle hidden" in command_line or " -w hidden" in command_line:
        reasons.append("Process hidden window")
        score = max(score, 90)
    if any(name in process_name for name in ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")):
        badges.append("lolbin")
    reasons.extend(_path_bucket_reason(process_path))
    if "\\startup\\" in process_path.lower():
        reasons.append("MFT file in Startup folder")
    if _double_extension(process_path):
        reasons.append("Process has double extension")
        score = max(score, 80)
    if any(reason in {"Process from user-writable path", "Process from Temp", "Process from Downloads"} for reason in reasons):
        score = max(score, 70 if process_name.endswith((".exe", ".ps1", ".bat", ".cmd")) else 50)
    return min(score, 100), list(dict.fromkeys(reasons)), list(dict.fromkeys(badges))


def _event_path_candidates(event: dict) -> list[str]:
    values = [
        _nested_get(event, "process.path"),
        _nested_get(event, "file.path"),
        _nested_get(event, "download.target_path"),
        _nested_get(event, "bits.local_path"),
        _nested_get(event, "detection.path"),
        _nested_get(event, "detection.resource"),
        _nested_get(event, "persistence.path"),
        _nested_get(event, "autoruns.image_path"),
    ]
    paths: list[str] = []
    for value in values:
        normalized = normalize_windows_path_for_classification(str(value or "").strip())
        if normalized:
            paths.append(normalized.lower())
    return list(dict.fromkeys(paths))


def _node_matches_event_path(node: dict, event: dict) -> bool:
    node_entity_id = str(node.get("id") or node.get("entity_id") or "").strip()
    event_entity_id = str(_nested_get(event, "process.entity_id") or _nested_get(event, "process.guid") or "").strip()
    if node_entity_id and event_entity_id and node_entity_id == event_entity_id:
        return True
    node_pid = _safe_intish(node.get("pid"))
    event_pid = _safe_intish(_nested_get(event, "process.pid"))
    node_host = str(node.get("host") or "").strip().lower()
    event_host = str(_nested_get(event, "host.name") or "").strip().lower()
    if node_pid is not None and event_pid is not None and node_pid == event_pid and (not node_host or not event_host or node_host == event_host):
        return True
    node_path = normalize_windows_path_for_classification(str(node.get("path") or "").strip())
    if node_path and node_path.lower() in _event_path_candidates(event):
        return True
    node_name = str(node.get("name") or "").lower()
    event_process_name = str(_nested_get(event, "process.name") or "").lower()
    return bool(node_name and event_process_name and node_name == event_process_name)


def _activity_node_payload(event: dict) -> dict | None:
    event_type = str(_nested_get(event, "event.type") or "")
    event_id = str(event.get("id") or event.get("event_id") or "")
    if not event_id:
        return None
    if event_type in {"sysmon_network_connection"}:
        label = f"{_nested_get(event, 'destination.ip') or _nested_get(event, 'destination.hostname') or '?'}:{_nested_get(event, 'destination.port') or '?'}"
        badge = "network_activity"
    elif event_type in {"sysmon_dns_query"}:
        label = str(_nested_get(event, "dns.question.name") or _nested_get(event, "dns.query") or "DNS query")
        badge = "dns_activity"
    elif event_type in {"sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted"}:
        label = str(_nested_get(event, "file.path") or _nested_get(event, "target.filename") or "File activity")
        badge = "file_activity"
    elif event_type in {"sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed"}:
        label = str(_nested_get(event, "registry.path") or _nested_get(event, "registry.key_path") or "Registry activity")
        badge = "registry_activity"
    else:
        return None
    return {
        "id": f"activity:{event_id}",
        "pid": _safe_intish(_nested_get(event, "process.pid")),
        "name": label,
        "path": None,
        "command_line": str(_nested_get(event, "event.message") or label),
        "user": _nested_get(event, "user.name"),
        "sid": _nested_get(event, "user.sid"),
        "host": _nested_get(event, "host.name"),
        "first_seen": event.get("@timestamp"),
        "last_seen": event.get("@timestamp"),
        "source_events": [event_id],
        "risk_score": int(event.get("risk_score") or 0),
        "risk_reasons": list(event.get("suspicious_reasons") or []),
        "badges": [badge],
        "data_quality": list(event.get("data_quality") or []),
        "confidence": "high",
        "node_type": "activity",
    }


def _activity_edge_type(event: dict) -> str:
    event_type = str(_nested_get(event, "event.type") or "")
    if event_type == "sysmon_network_connection":
        return "network_activity"
    if event_type == "sysmon_dns_query":
        return "dns_activity"
    if event_type in {"sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted"}:
        return "file_activity"
    if event_type in {"sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed"}:
        return "registry_activity"
    if event_type in {"sysmon_image_loaded"}:
        return "image_load"
    if event_type in {"sysmon_process_access"}:
        return "process_access"
    if event_type in {"sysmon_create_remote_thread"}:
        return "remote_thread"
    return "activity"


def _activity_group_from_edge(edge_type: str) -> str:
    return {
        "network_activity": "network",
        "dns_activity": "dns",
        "file_activity": "file",
        "registry_activity": "registry",
        "image_load": "image_load",
        "process_access": "process_access",
        "remote_thread": "remote_thread",
    }.get(edge_type, "other")


def _build_process_graph(events: list[dict], case_id: str, evidence_id: str | None, scope: str) -> dict:
    process_events = [event for event in events if _is_process_start_event(event)]
    nodes_by_id: dict[str, dict] = {}
    edges: list[dict] = []
    host_pid_index: dict[tuple[str, int], list[dict]] = defaultdict(list)
    warning_samples: list[str] = []
    warning_counts: Counter[str] = Counter()

    def _record_warning(kind: str, message: str) -> None:
        warning_counts[kind] += 1
        if len(warning_samples) < 10:
            warning_samples.append(message)

    def _parent_fields(node: dict) -> dict:
        return {
            "parent_entity_id": node.get("parent_entity_id"),
            "parent_pid": node.get("parent_pid"),
            "parent_name": node.get("parent_name"),
            "host": node.get("host"),
            "first_seen": node.get("first_seen"),
        }

    def _set_parent_status(node: dict, status: str, reason: str, *, confidence: str = "none") -> None:
        node["parent_link_status"] = status
        node["parent_link_reason"] = reason
        node["parent_link_confidence"] = confidence
        node["parent_fields"] = _parent_fields(node)

    for event in process_events:
        process = event.get("process") or {}
        node_id = str(process.get("entity_id") or event.get("event_id") or event.get("id") or "")
        if not node_id:
            continue
        timestamp = event.get("@timestamp")
        host = str(_nested_get(event, "host.name") or _nested_get(event, "windows.computer") or "")
        event_refs = list(
            dict.fromkeys(
                str(event.get(key) or "").strip()
                for key in ("search_doc_id", "opensearch_id", "id", "event_id", "stable_event_id")
                if str(event.get(key) or "").strip()
            )
        )
        event_ref = event_refs[0] if event_refs else ""
        node = nodes_by_id.setdefault(
            node_id,
            {
                "id": node_id,
                "pid": _safe_intish(process.get("pid")),
                "name": process.get("name"),
                "path": process.get("path"),
                "command_line": process.get("command_line"),
                "user": _nested_get(event, "user.name"),
                "sid": _nested_get(event, "user.sid"),
                "host": host or None,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "source_type": _nested_get(event, "event.type") or _nested_get(event, "artifact.parser") or None,
                "source_event_id": event_ref or None,
                "source_events": [],
                "risk_score": 0,
                "risk_reasons": [],
                "badges": [],
                "data_quality": list(event.get("data_quality") or []),
                "confidence": "high" if process.get("entity_id") else "medium",
                "parent_entity_id": process.get("parent_entity_id"),
                "parent_pid": _safe_intish(process.get("parent_pid") or process.get("ppid")),
                "parent_name": process.get("parent_name"),
                "parent_link_status": "pending",
                "parent_link_reason": "Parent link has not been evaluated yet.",
                "parent_link_confidence": "none",
                "parent_fields": {},
            },
        )
        node["pid"] = node.get("pid") or _safe_intish(process.get("pid"))
        node["path"] = node.get("path") or process.get("path")
        node["command_line"] = node.get("command_line") or process.get("command_line")
        node["user"] = node.get("user") or _nested_get(event, "user.name")
        node["sid"] = node.get("sid") or _nested_get(event, "user.sid")
        node["host"] = node.get("host") or (host or None)
        node["parent_entity_id"] = node.get("parent_entity_id") or process.get("parent_entity_id")
        node["parent_pid"] = node.get("parent_pid") or _safe_intish(process.get("parent_pid") or process.get("ppid"))
        node["parent_name"] = node.get("parent_name") or process.get("parent_name")
        node["parent_fields"] = _parent_fields(node)
        if timestamp and (not node.get("first_seen") or str(timestamp) < str(node.get("first_seen"))):
            node["first_seen"] = timestamp
        if timestamp and (not node.get("last_seen") or str(timestamp) > str(node.get("last_seen"))):
            node["last_seen"] = timestamp
        for event_ref in event_refs:
            if event_ref and event_ref not in node["source_events"]:
                node["source_events"].append(event_ref)
        node["source_event_id"] = node.get("source_event_id") or event_ref or None
        node["source_type"] = node.get("source_type") or _nested_get(event, "event.type") or _nested_get(event, "artifact.parser") or None
        if node.get("host") and node.get("pid") is not None:
            host_pid_index[(str(node["host"]).lower(), int(node["pid"]))].append({"id": node_id, "ts": _safe_parse_dt(timestamp), "event": event})

    def _refine_pid_candidates(
        candidates: list[dict],
        *,
        parent_name: str | None,
    ) -> list[dict]:
        if len(candidates) <= 1:
            return candidates
        normalized_parent_name = str(parent_name or "").strip().lower()
        if not normalized_parent_name:
            return candidates
        name_matched = [
            candidate
            for candidate in candidates
            if str((nodes_by_id.get(str(candidate.get("id"))) or {}).get("name") or "").strip().lower() == normalized_parent_name
        ]
        return name_matched or candidates

    for node_id, node in nodes_by_id.items():
        parent_id = str(node.get("parent_entity_id") or "")
        if parent_id and parent_id in nodes_by_id and parent_id != node_id:
            child_ts = _safe_parse_dt(node.get("first_seen"))
            parent_ts = _safe_parse_dt(nodes_by_id[parent_id].get("first_seen"))
            if child_ts and parent_ts and child_ts < parent_ts:
                _set_parent_status(
                    node,
                    "parent_link_temporal_conflict",
                    "ParentProcessGuid matched exactly, but this process was observed before the claimed parent started; likely PID/GUID reuse.",
                    confidence="low",
                )
                node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_before_child_conflict", "process_graph_orphan"})
                _record_warning("parent_before_child_conflict", f"Node {node_id} observed before claimed parent {parent_id}; edge omitted.")
                continue
            _set_parent_status(node, "linked", "Linked exactly by Sysmon ProcessGuid / ParentProcessGuid.", confidence="high")
            edges.append(
                {
                    "source": parent_id,
                    "target": node_id,
                    "type": "spawned",
                    "confidence": "high",
                    "source_event_id": node.get("source_events", [None])[0],
                    "reason": "sysmon_parent_process_guid",
                }
            )
            continue
        parent_pid = node.get("parent_pid")
        host = str(node.get("host") or "").lower()
        child_ts = _safe_parse_dt(node.get("first_seen"))
        parent_name = str(node.get("parent_name") or "").strip().lower() or None
        if not parent_pid or not host or not child_ts:
            missing_parts = []
            if not parent_id and not parent_pid:
                missing_parts.append("parent PID/GUID")
            if not host:
                missing_parts.append("host")
            if not child_ts:
                missing_parts.append("timestamp")
            if missing_parts:
                reason = f"Parent fields missing: {', '.join(missing_parts)}."
                status = "parent_fields_missing"
                quality = "parent_fields_missing"
            else:
                reason = "Parent event could not be searched because required context is unavailable."
                status = "parent_not_found"
                quality = "parent_not_found"
            _set_parent_status(node, status, reason)
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {quality, "process_graph_orphan"})
            continue
        candidates = []
        for candidate_ref in host_pid_index.get((host, int(parent_pid)), []):
            if candidate_ref.get("id") == node_id:
                continue
            candidate_ts = candidate_ref.get("ts")
            if not candidate_ts or candidate_ts >= child_ts:
                continue
            if (child_ts - candidate_ts).total_seconds() > 86400:
                continue
            candidates.append({"id": candidate_ref.get("id"), "ts": candidate_ts})
        candidates = _refine_pid_candidates(candidates, parent_name=parent_name)
        if not candidates and parent_name:
            for candidate_node in nodes_by_id.values():
                if candidate_node.get("id") == node_id:
                    continue
                candidate_host = str(candidate_node.get("host") or "").lower()
                if host and candidate_host and candidate_host != host:
                    continue
                if str(candidate_node.get("name") or "").strip().lower() != parent_name:
                    continue
                candidate_ts = _safe_parse_dt(candidate_node.get("first_seen"))
                if not candidate_ts or candidate_ts >= child_ts:
                    continue
                if (child_ts - candidate_ts).total_seconds() > 86400:
                    continue
                candidates.append({"id": candidate_node.get("id"), "ts": candidate_ts})
        if not candidates:
            relaxed_candidates = []
            for candidate_ref in host_pid_index.get((host, int(parent_pid)), []):
                if candidate_ref.get("id") == node_id:
                    continue
                relaxed_candidates.append({"id": candidate_ref.get("id"), "ts": candidate_ref.get("ts")})
            relaxed_candidates = _refine_pid_candidates(relaxed_candidates, parent_name=parent_name)
            if len(relaxed_candidates) == 1:
                candidates = relaxed_candidates
            elif len(relaxed_candidates) > 1:
                _set_parent_status(node, "parent_pid_reused_ambiguous", "Multiple parent candidates matched the same PID; edge omitted to avoid a false parent.", confidence="low")
                node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"possible_pid_reuse", "process_graph_orphan"})
                _record_warning("ambiguous_relaxed_parent_candidates", f"Ambiguous relaxed parent candidates for node {node_id}")
                continue
        if len(candidates) == 1:
            candidate = candidates[0]
            candidate_ts = candidate.get("ts")
            child_delta_seconds = None
            if child_ts and candidate_ts:
                child_delta_seconds = abs((child_ts - candidate_ts).total_seconds())
            reason = "Linked by parent PID and timestamp proximity."
            confidence = "medium"
            if child_delta_seconds is None or child_delta_seconds > 86400:
                reason = "Linked by relaxed parent PID/name inference; parent may be outside the selected time window."
                confidence = "low"
                node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_outside_time_window"})
            _set_parent_status(node, "linked", reason, confidence=confidence)
            edges.append(
                {
                    "source": candidate["id"],
                    "target": node_id,
                    "type": "spawned",
                    "confidence": confidence,
                    "source_event_id": node.get("source_events", [None])[0],
                    "reason": "security_4688_parent_pid_inferred",
                }
            )
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_inferred_by_pid"})
            node["confidence"] = confidence
        elif len(candidates) > 1:
            _set_parent_status(node, "parent_pid_reused_ambiguous", "Multiple parent candidates matched PID/time constraints; edge omitted to avoid a false parent.", confidence="low")
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"possible_pid_reuse", "process_graph_orphan"})
            _record_warning("ambiguous_parent_candidates", f"Ambiguous parent candidates for node {node_id}")
        else:
            _set_parent_status(node, "parent_not_found", "Parent PID/name was present, but no earlier matching parent event was found in the graph context.")
            node["data_quality"] = sorted(set(node.get("data_quality") or []) | {"parent_not_found", "process_graph_orphan"})

    edge_targets = {edge["target"] for edge in edges}
    for node_id, node in nodes_by_id.items():
        score, reasons, badges = _process_badges_and_risk(node)
        node["risk_score"] = max(int(node.get("risk_score") or 0), score)
        node["risk_reasons"] = list(dict.fromkeys(list(node.get("risk_reasons") or []) + reasons))
        node["badges"] = list(dict.fromkeys(list(node.get("badges") or []) + badges))
        parent_name = str(node.get("parent_name") or "").lower()
        child_name = str(node.get("name") or "").lower()
        if parent_name in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} and child_name in {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            node["risk_score"] = max(int(node["risk_score"]), 90)
            node["risk_reasons"] = list(dict.fromkeys(list(node["risk_reasons"]) + ["Office spawned script interpreter"]))
            node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["office_child", "suspicious_chain"]))
        if parent_name in {"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe"} and child_name.endswith((".exe", ".ps1", ".bat", ".cmd")):
            if _is_browser_internal_child(parent_name, child_name, node.get("path")):
                node["risk_score"] = min(int(node.get("risk_score") or 0), 20)
                node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["browser_internal_child", "low_noise_process"]))
                node["data_quality"] = list(dict.fromkeys(list(node.get("data_quality") or []) + ["noisy_browser_child"]))
            else:
                node["risk_score"] = max(int(node["risk_score"]), 85)
                node["risk_reasons"] = list(dict.fromkeys(list(node["risk_reasons"]) + ["Browser spawned executable"]))
                node["badges"] = list(dict.fromkeys(list(node["badges"]) + ["browser_child", "suspicious_chain"]))
        if node_id not in edge_targets:
            continue

    activity_counts_by_node: Counter[str] = Counter()
    for event in events:
        if _is_process_start_event(event):
            continue
        artifact_type = str(_nested_get(event, "artifact.type") or "")
        event_type = str(_nested_get(event, "event.type") or "")
        for node in list(nodes_by_id.values()):
            if not _node_matches_event_path(node, event):
                continue
            activity_payload = _activity_node_payload(event)
            if activity_payload and activity_counts_by_node[str(node.get("id"))] < 25:
                activity_id = str(activity_payload["id"])
                if activity_id not in nodes_by_id:
                    nodes_by_id[activity_id] = activity_payload
                edge_id = f"activity:{node.get('id')}->{activity_id}"
                if not any(edge.get("id") == edge_id for edge in edges):
                    activity_type = _activity_edge_type(event)
                    edges.append(
                        {
                            "id": edge_id,
                            "source": str(node.get("id")),
                            "target": activity_id,
                            "type": activity_type,
                            "confidence": "high",
                            "source_event_id": str(event.get("id") or event.get("event_id") or ""),
                            "timestamp": event.get("@timestamp"),
                            "reason": event_type or "process_activity",
                            "summary": str(_nested_get(event, "event.message") or activity_payload.get("name") or event_type or activity_type),
                            "weight": 1,
                            "risk": int(event.get("risk_score") or activity_payload.get("risk_score") or 0),
                        }
                    )
                activity_counts_by_node[str(node.get("id"))] += 1
            reasons = list(node.get("risk_reasons") or [])
            badges = list(node.get("badges") or [])
            score = int(node.get("risk_score") or 0)
            if artifact_type == "browser" and event_type == "file_downloaded":
                reasons.append("Process associated with browser download")
                badges.append("browser_download")
                score = max(score, 85)
            elif artifact_type == "bits":
                reasons.append("Process associated with BITS download")
                badges.append("bits_download")
                score = max(score, 80)
            elif artifact_type == "detection":
                reasons.append("Process associated with Defender detection")
                badges.append("defender_detection")
                score = max(score, 85)
            elif artifact_type == "dns" and event.get("suspicious_reasons"):
                reasons.append("Process has suspicious DNS activity")
                badges.append("dns_activity")
                score = max(score, 70)
            elif artifact_type == "srum" and int(_nested_get(event, "srum.bytes_sent") or 0) >= 50_000_000:
                reasons.append("Process has high SRUM outbound bytes")
                badges.append("network_activity")
                score = max(score, 75)
            elif artifact_type == "autorun":
                reasons.append("Autorun process observed")
                badges.append("autorun")
                score = max(score, 75)
            node["risk_reasons"] = list(dict.fromkeys(reasons))
            node["badges"] = list(dict.fromkeys(badges))
            node["risk_score"] = min(score, 100)

    root_nodes_count = sum(1 for node in nodes_by_id.values() if all(edge["target"] != node["id"] for edge in edges))
    high_risk_nodes_count = sum(1 for node in nodes_by_id.values() if int(node.get("risk_score") or 0) >= 70)
    suspicious_chains_count = sum(1 for edge in edges if "suspicious_chain" in (nodes_by_id.get(edge["target"], {}).get("badges") or []))
    orphan_nodes_count = sum(1 for node in nodes_by_id.values() if "process_graph_orphan" in (node.get("data_quality") or []))
    data_quality_counts: Counter[str] = Counter()
    for node in nodes_by_id.values():
        for quality in node.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1

    orphan_diagnostics = [
        {
            "id": node.get("id"),
            "process_name": node.get("name"),
            "pid": node.get("pid"),
            "timestamp": node.get("first_seen"),
            "command_line": node.get("command_line"),
            "parent_fields": node.get("parent_fields") or _parent_fields(node),
            "parent_link_status": node.get("parent_link_status") or "parent_not_found",
            "parent_link_reason": node.get("parent_link_reason") or "Parent could not be linked.",
            "parent_link_confidence": node.get("parent_link_confidence") or "none",
        }
        for node in nodes_by_id.values()
        if "process_graph_orphan" in (node.get("data_quality") or [])
    ]
    orphan_status_counts = Counter(str(item.get("parent_link_status") or "parent_not_found") for item in orphan_diagnostics)

    warnings_summary = {
        "ambiguous_parent_candidates": int(warning_counts.get("ambiguous_parent_candidates") or 0),
        "ambiguous_relaxed_parent_candidates": int(warning_counts.get("ambiguous_relaxed_parent_candidates") or 0),
        "parent_not_found": int(data_quality_counts.get("parent_not_found") or 0),
        "parent_fields_missing": int(data_quality_counts.get("parent_fields_missing") or 0),
        "possible_pid_reuse": int(data_quality_counts.get("possible_pid_reuse") or 0),
        "process_graph_orphan": int(data_quality_counts.get("process_graph_orphan") or 0),
    }
    warnings: list[str] = []
    if warnings_summary["ambiguous_parent_candidates"]:
        warnings.append(
            f"{warnings_summary['ambiguous_parent_candidates']} ambiguous parent candidates. Some edges were omitted to avoid incorrect parent-child links."
        )
    if warnings_summary["ambiguous_relaxed_parent_candidates"]:
        warnings.append(
            f"{warnings_summary['ambiguous_relaxed_parent_candidates']} relaxed parent candidates remained ambiguous after inference."
        )
    if warnings_summary["parent_not_found"]:
        warnings.append(f"{warnings_summary['parent_not_found']} nodes could not be linked to a parent.")
    if warnings_summary["possible_pid_reuse"]:
        warnings.append(f"{warnings_summary['possible_pid_reuse']} nodes were marked with possible PID reuse.")
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scope": scope,
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "summary": {
            "nodes_count": len(nodes_by_id),
            "edges_count": len(edges),
            "root_nodes_count": root_nodes_count,
            "high_risk_nodes_count": high_risk_nodes_count,
            "suspicious_chains_count": suspicious_chains_count,
            "orphan_nodes_count": orphan_nodes_count,
            "warnings": warnings,
            "warnings_summary": warnings_summary,
            "warnings_samples": warning_samples,
            "orphan_diagnostics": orphan_diagnostics[:50],
            "orphan_status_counts": dict(orphan_status_counts),
        },
    }


def _build_process_tree_report(graph: dict, events: list[dict], *, selected_scope: str) -> dict:
    process_events = [event for event in events if _is_process_start_event(event)]
    nodes = {str(node.get("id")): node for node in graph.get("nodes", [])}
    node_counter = Counter(str(node.get("name") or "unknown").lower() for node in nodes.values())
    pair_counter = Counter(
        f"{str((nodes.get(str(edge.get('source'))) or {}).get('name') or 'unknown')} -> {str((nodes.get(str(edge.get('target'))) or {}).get('name') or 'unknown')}"
        for edge in graph.get("edges", [])
    )
    badge_counter = Counter(badge for node in graph.get("nodes", []) for badge in (node.get("badges") or []))
    user_counter = Counter(str(node.get("user") or "unknown") for node in graph.get("nodes", []))
    host_counter = Counter(str(node.get("host") or "unknown") for node in graph.get("nodes", []))
    warnings = list(graph.get("summary", {}).get("warnings") or [])
    sample_chains = _build_process_tree_sample_chains(graph)
    return {
        "selected_scope": selected_scope,
        "process_events_found": len(process_events),
        "sysmon_process_create_count": sum(1 for event in process_events if str(_nested_get(event, "artifact.parser") or "") == "sysmon_evtx"),
        "security_4688_count": sum(1 for event in process_events if str(_nested_get(event, "artifact.parser") or "") == "security_4688" or int(_nested_get(event, "windows.event_id") or 0) == 4688),
        "powershell_enriched_count": sum(1 for node in graph.get("nodes", []) if "powershell" in (node.get("badges") or [])),
        "nodes_count": graph.get("summary", {}).get("nodes_count", 0),
        "edges_count": graph.get("summary", {}).get("edges_count", 0),
        "orphan_nodes_count": graph.get("summary", {}).get("orphan_nodes_count", 0),
        "high_risk_nodes_count": graph.get("summary", {}).get("high_risk_nodes_count", 0),
        "suspicious_chain_count": graph.get("summary", {}).get("suspicious_chains_count", 0),
        "by_process_name": dict(node_counter.most_common(20)),
        "by_parent_child_pair": dict(pair_counter.most_common(20)),
        "by_user": dict(user_counter.most_common(20)),
        "by_host": dict(host_counter.most_common(20)),
        "by_badge": dict(badge_counter.most_common(20)),
        "parser_errors": [],
        "warnings": warnings,
        "sample_chains": sample_chains[:10],
    }


def _build_process_tree_sample_chains(graph: dict) -> list[dict]:
    nodes = {str(node.get("id")): node for node in graph.get("nodes", [])}
    chains: list[dict] = []
    for edge in graph.get("edges", []):
        parent = nodes.get(str(edge.get("source")))
        child = nodes.get(str(edge.get("target")))
        if not parent or not child:
            continue
        if "browser_internal_child" in (child.get("badges") or []) and int(child.get("risk_score") or 0) < 70:
            continue
        if not child.get("risk_reasons") and not child.get("badges"):
            continue
        chains.append(
            {
                "chain": [
                    {
                        "id": parent.get("id"),
                        "name": parent.get("name"),
                        "path": parent.get("path"),
                        "command_line": parent.get("command_line"),
                        "risk_score": parent.get("risk_score"),
                        "badges": parent.get("badges") or [],
                    },
                    {
                        "id": child.get("id"),
                        "name": child.get("name"),
                        "path": child.get("path"),
                        "command_line": child.get("command_line"),
                        "risk_score": child.get("risk_score"),
                        "badges": child.get("badges") or [],
                    },
                ],
                "edge": edge,
                "reasons": child.get("risk_reasons") or [],
            }
        )
    chains.sort(key=lambda item: int(item["chain"][-1].get("risk_score") or 0), reverse=True)
    return chains[:10]


def _filter_process_graph(graph: dict, *, pid: int | None = None, process_name: str | None = None, entity_id: str | None = None) -> dict:
    if pid is None and not process_name and not entity_id:
        return graph

    # Compared the same way everywhere: a pasted full path, a name with or
    # without .exe, and any casing all have to select the same node, or the
    # graph goes empty for a process that is plainly in it.
    wanted_name = normalize_process_name(process_name)
    focus_ids = {
        str(node.get("id"))
        for node in graph.get("nodes", [])
        if (
            (entity_id and str(node.get("id") or "") == entity_id)
            or (pid is not None and _safe_intish(node.get("pid")) == int(pid))
            or (wanted_name and _node_matches_name(node, wanted_name))
        )
    }
    if not focus_ids:
        return {
            **graph,
            "nodes": [],
            "edges": [],
            "summary": {
                **(graph.get("summary") or {}),
                "nodes_count": 0,
                "edges_count": 0,
                "root_nodes_count": 0,
                "high_risk_nodes_count": 0,
                "suspicious_chains_count": 0,
                "orphan_nodes_count": 0,
                "warnings": sorted(set(list((graph.get("summary") or {}).get("warnings") or []) + ["No process graph nodes matched the selected focus filter."])),
                "warnings_summary": dict((graph.get("summary") or {}).get("warnings_summary") or {}),
                "warnings_samples": list((graph.get("summary") or {}).get("warnings_samples") or []),
            },
        }

    related_ids = set(focus_ids)
    pending = list(focus_ids)
    edges = graph.get("edges", [])
    while pending:
        current = pending.pop()
        for edge in edges:
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source == current and target and target not in related_ids:
                related_ids.add(target)
                pending.append(target)
            if target == current and source and source not in related_ids:
                related_ids.add(source)
                pending.append(source)

    filtered_nodes = [node for node in graph.get("nodes", []) if str(node.get("id") or "") in related_ids]
    filtered_edges = [
        edge
        for edge in edges
        if str(edge.get("source") or "") in related_ids and str(edge.get("target") or "") in related_ids
    ]
    node_map = {str(node.get("id") or ""): node for node in filtered_nodes}
    edge_targets = {str(edge.get("target") or "") for edge in filtered_edges}
    summary = {
        **(graph.get("summary") or {}),
        "nodes_count": len(filtered_nodes),
        "edges_count": len(filtered_edges),
        "root_nodes_count": sum(1 for node in filtered_nodes if str(node.get("id") or "") not in edge_targets),
        "high_risk_nodes_count": sum(1 for node in filtered_nodes if int(node.get("risk_score") or 0) >= 70),
        "suspicious_chains_count": sum(1 for edge in filtered_edges if "suspicious_chain" in ((node_map.get(str(edge.get("target") or ""), {}) or {}).get("badges") or [])),
        "orphan_nodes_count": sum(1 for node in filtered_nodes if "process_graph_orphan" in (node.get("data_quality") or [])),
        "focus_node_ids": sorted(focus_ids),
    }
    filtered_ids = {str(node.get("id") or "") for node in filtered_nodes}
    summary["orphan_diagnostics"] = [
        item
        for item in list((graph.get("summary") or {}).get("orphan_diagnostics") or [])
        if str(item.get("id") or "") in filtered_ids
    ][:50]
    summary["orphan_status_counts"] = dict(Counter(str(item.get("parent_link_status") or "parent_not_found") for item in summary["orphan_diagnostics"]))
    return {
        **graph,
        "nodes": filtered_nodes,
        "edges": filtered_edges,
        "summary": summary,
    }


def _compact_process_graph(
    graph: dict,
    *,
    include_activity: bool = False,
    aggregate_activity: bool = True,
    edge_types: list[str] | None = None,
    max_nodes: int = 50,
    max_activity_per_process: int = 10,
    only_suspicious: bool = False,
    only_marked: bool = False,
) -> dict:
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    node_map = {str(node.get("id") or ""): node for node in nodes}
    activity_types = {"network_activity", "dns_activity", "file_activity", "registry_activity", "image_load", "process_access", "remote_thread", "activity"}
    requested_types = {str(item).strip() for item in (edge_types or []) if str(item).strip()}
    show_activity = include_activity or bool(requested_types & activity_types)
    process_edge_types = {"spawned", "parent_child"}
    omitted_counts: Counter[str] = Counter()
    groups_by_key: dict[tuple[str, str], dict] = {}
    activity_seen_by_source: Counter[str] = Counter()
    kept_edges: list[dict] = []

    for edge in edges:
        edge_type = str(edge.get("type") or "")
        if edge_type == "spawned":
            edge = {**edge, "type": "parent_child", "summary": edge.get("summary") or edge.get("reason") or "Parent-child process relationship", "weight": edge.get("weight") or 1}
            edge_type = "parent_child"
        if requested_types and edge_type not in requested_types:
            if edge_type in activity_types:
                omitted_counts[_activity_group_from_edge(edge_type)] += 1
            continue
        if edge_type in activity_types:
            group = _activity_group_from_edge(edge_type)
            if not show_activity:
                omitted_counts[group] += 1
                key = (str(edge.get("source") or ""), group)
                source_node = node_map.get(key[0]) or {}
                current = groups_by_key.setdefault(
                    key,
                    {
                        "id": f"activity-group:{key[0]}:{group}",
                        "source": key[0],
                        "type": f"{group}_activity_group",
                        "group": group,
                        "count": 0,
                        "samples": [],
                        "source_process": source_node.get("name") or source_node.get("path") or key[0],
                    },
                )
                current["count"] += 1
                if len(current["samples"]) < 5:
                    current["samples"].append(
                        {
                            "target": edge.get("target"),
                            "timestamp": edge.get("timestamp"),
                            "summary": edge.get("summary") or edge.get("reason"),
                            "source_event_id": edge.get("source_event_id"),
                        }
                    )
                continue
            source = str(edge.get("source") or "")
            activity_seen_by_source[source] += 1
            if activity_seen_by_source[source] > max_activity_per_process:
                omitted_counts[group] += 1
                continue
        elif edge_type not in process_edge_types and requested_types:
            continue
        kept_edges.append(edge)

    kept_ids = {str(edge.get("source") or "") for edge in kept_edges} | {str(edge.get("target") or "") for edge in kept_edges}
    if not kept_ids and not show_activity:
        kept_ids = {str(node.get("id") or "") for node in nodes if str(node.get("node_type") or "") != "activity"}
    kept_nodes = [node for node in nodes if str(node.get("id") or "") in kept_ids and (show_activity or str(node.get("node_type") or "") != "activity")]
    if only_suspicious:
        suspicious_ids = {str(node.get("id") or "") for node in kept_nodes if int(node.get("risk_score") or 0) >= 40 or node.get("risk_reasons") or node.get("badges")}
        suspicious_ids |= {str(edge.get("source") or "") for edge in kept_edges if str(edge.get("target") or "") in suspicious_ids}
        suspicious_ids |= {str(edge.get("target") or "") for edge in kept_edges if str(edge.get("source") or "") in suspicious_ids}
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in suspicious_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in suspicious_ids and str(edge.get("target") or "") in suspicious_ids]
    if only_marked:
        marked_ids = {str(node.get("id") or "") for node in kept_nodes if "marked" in (node.get("badges") or [])}
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in marked_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in marked_ids and str(edge.get("target") or "") in marked_ids]

    truncated = False
    if max_nodes > 0 and len(kept_nodes) > max_nodes:
        truncated = True
        priority = {
            str(node.get("id") or ""): (
                int(node.get("risk_score") or 0),
                len(node.get("source_events") or []),
                0 if str(node.get("node_type") or "") == "activity" else 1,
            )
            for node in kept_nodes
        }
        selected_ids = {
            node_id
            for node_id, _score in sorted(priority.items(), key=lambda item: item[1], reverse=True)[:max_nodes]
        }
        for node in kept_nodes:
            node_id = str(node.get("id") or "")
            if node_id not in selected_ids and str(node.get("node_type") or "") == "activity":
                omitted_counts["activity"] += 1
        kept_nodes = [node for node in kept_nodes if str(node.get("id") or "") in selected_ids]
        kept_edges = [edge for edge in kept_edges if str(edge.get("source") or "") in selected_ids and str(edge.get("target") or "") in selected_ids]

    edge_targets = {str(edge.get("target") or "") for edge in kept_edges}
    kept_node_ids = {str(node.get("id") or "") for node in kept_nodes}
    orphan_diagnostics = [
        item
        for item in list((graph.get("summary") or {}).get("orphan_diagnostics") or [])
        if str(item.get("id") or "") in kept_node_ids
    ][:50]
    summary = {
        **(graph.get("summary") or {}),
        "nodes_count": len(kept_nodes),
        "edges_count": len(kept_edges),
        "root_nodes_count": sum(1 for node in kept_nodes if str(node.get("id") or "") not in edge_targets),
        "high_risk_nodes_count": sum(1 for node in kept_nodes if int(node.get("risk_score") or 0) >= 70),
        "orphan_nodes_count": sum(1 for node in kept_nodes if "process_graph_orphan" in (node.get("data_quality") or [])),
        "truncated": truncated,
        "node_cap": max_nodes,
        "activity_collapsed": not show_activity and aggregate_activity,
        "omitted_counts": dict(omitted_counts),
        "activity_groups_count": len(groups_by_key),
        "orphan_diagnostics": orphan_diagnostics,
        "orphan_status_counts": dict(Counter(str(item.get("parent_link_status") or "parent_not_found") for item in orphan_diagnostics)),
    }
    warnings = list(summary.get("warnings") or [])
    if truncated:
        warnings.append(f"Graph limited to {max_nodes} nodes. Increase Max nodes or narrow the focus.")
    summary["warnings"] = sorted(set(warnings))
    return {
        **graph,
        "nodes": kept_nodes,
        "edges": kept_edges,
        "groups": list(groups_by_key.values()),
        "omitted_counts": dict(omitted_counts),
        "truncated": truncated,
        "summary": summary,
    }


def _process_focus_filter(*, pid: int | None = None, process_name: str | None = None, entity_id: str | None = None) -> dict | None:
    should: list[dict] = []
    if entity_id:
        should.extend(
            [
                {"term": {"process.entity_id": entity_id}},
                {"term": {"process.guid": entity_id}},
                {"term": {"process.parent.entity_id": entity_id}},
                {"term": {"process.parent.guid": entity_id}},
                {"term": {"parent.process.entity_id": entity_id}},
                {"term": {"parent.process.guid": entity_id}},
            ]
        )
    if pid is not None:
        pid_value = str(pid)
        should.extend(
            [
                {"term": {"process.pid": pid_value}},
                {"term": {"process.parent_pid": pid_value}},
                {"term": {"process.parent.pid": pid_value}},
                {"term": {"parent.process.pid": pid_value}},
            ]
        )
    process_name_value = str(process_name or "").strip()
    if process_name_value:
        # Search for what the analyst typed and, if they pasted a full path,
        # for the executable name inside it too. Otherwise pasting
        # "C:\\Windows\\System32\\cmd.exe" matches nothing, because
        # process.name only ever holds "cmd.exe".
        terms = {process_name_value}
        basename = normalize_process_name(process_name_value)
        if basename:
            terms.add(basename)
        for term in sorted(terms):
            _extend_process_name_should(should, term)
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


PROCESS_NAME_SEARCH_FIELDS = (
    "process.name",
    "process.executable",
    "process.path",
    "process.command_line",
    "process.parent.name",
    "process.parent.executable",
    "process.parent.path",
    "process.parent.command_line",
    "parent.process.name",
    "parent.process.executable",
    "parent.process.path",
    "parent.process.command_line",
)


def _extend_process_name_should(should: list[dict], term: str) -> None:
    """Add case-insensitive substring clauses for one search term."""
    wildcard_value = f"*{term.replace('*', '').replace('?', '')}*"
    for field in PROCESS_NAME_SEARCH_FIELDS:
        should.append({"wildcard": {field: {"value": wildcard_value, "case_insensitive": True}}})


def _process_start_filter() -> dict:
    return {
        "bool": {
            "should": [
                {"terms": {"event.type": ["process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"]}},
                {"term": {"artifact.type": "process"}},
            ],
            "minimum_should_match": 1,
        }
    }


def _process_activity_filter() -> dict:
    return {
        "bool": {
            "should": [
                {"terms": {"artifact.type": ["browser", "bits", "dns", "srum", "detection", "autorun"]}},
                {
                    "terms": {
                        "event.type": [
                            "sysmon_network_connection",
                            "sysmon_file_created",
                            "sysmon_file_create_stream_hash",
                            "sysmon_file_deleted",
                            "sysmon_registry_key_event",
                            "sysmon_registry_value_set",
                            "sysmon_registry_key_renamed",
                            "sysmon_dns_query",
                            "sysmon_image_loaded",
                            "sysmon_process_access",
                            "sysmon_create_remote_thread",
                            "object_access",
                            "object_access_attempted",
                            "file_access",
                        ]
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def _time_window_filter(timestamp: str | None, before_seconds: int | None, after_seconds: int | None) -> dict | None:
    anchor = _safe_parse_dt(timestamp)
    if not anchor:
        return None
    before = max(int(before_seconds or 0), 0)
    after = max(int(after_seconds or 0), 0)
    if before <= 0 and after <= 0:
        return None
    start = anchor - timedelta(seconds=before)
    end = anchor + timedelta(seconds=after)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}


def _identity_filter(*, entity_ids: set[str] | None = None, pids: set[int] | None = None, process_name: str | None = None) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in (entity_ids or set()) if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.entity_id": clean_entity_ids}},
                {"terms": {"process.guid": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in (pids or set()) if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.pid": pid_values}},
                {"terms": {"process.pid": clean_pids}},
            ]
        )
    name = str(process_name or "").strip()
    if name:
        wildcard_value = f"*{name.replace('*', '').replace('?', '')}*"
        should.extend(
            [
                {"wildcard": {"process.name": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.executable": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.path": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.command_line": {"value": wildcard_value, "case_insensitive": True}}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _source_event_filter(source_event_id: str | None) -> dict | None:
    value = str(source_event_id or "").strip()
    if not value:
        return None
    return {
        "bool": {
            "should": [
                {"ids": {"values": [value]}},
                {"term": {"id": value}},
                {"term": {"event_id": value}},
                {"term": {"stable_event_id": value}},
                {"term": {"search_doc_id": value}},
                {"term": {"opensearch_id": value}},
            ],
            "minimum_should_match": 1,
        }
    }


_EXECUTION_STORY_LIGHT_CACHE: dict[str, tuple[datetime, dict[str, Any]]] = {}
_EXECUTION_STORY_LIGHT_CACHE_SECONDS = 300


def _execution_story_cache_key(
    case_id: str,
    *,
    source_event_id: str | None,
    scope: str,
    evidence_id: str | None,
    origin: str | None = None,
    command_history_row_id: str | None = None,
) -> str:
    return "|".join([case_id, scope, str(evidence_id or ""), str(source_event_id or ""), str(origin or ""), str(command_history_row_id or "")])


def _execution_story_cache_get(key: str) -> dict[str, Any] | None:
    cached = _EXECUTION_STORY_LIGHT_CACHE.get(key)
    if not cached:
        return None
    created, payload = cached
    if (datetime.now(UTC) - created).total_seconds() > _EXECUTION_STORY_LIGHT_CACHE_SECONDS:
        _EXECUTION_STORY_LIGHT_CACHE.pop(key, None)
        return None
    response = dict(payload)
    quality = dict(response.get("quality") or {})
    quality["cache"] = {"hit": True, "ttl_seconds": _EXECUTION_STORY_LIGHT_CACHE_SECONDS}
    response["quality"] = quality
    return response


def _execution_story_cache_put(key: str, payload: dict[str, Any]) -> dict[str, Any]:
    quality = dict(payload.get("quality") or {})
    quality["cache"] = {"hit": False, "ttl_seconds": _EXECUTION_STORY_LIGHT_CACHE_SECONDS}
    payload = {**payload, "quality": quality}
    _EXECUTION_STORY_LIGHT_CACHE[key] = (datetime.now(UTC), payload)
    return payload


def _child_process_filter(*, parent_entity_ids: set[str], parent_pids: set[int]) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in parent_entity_ids if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.parent_entity_id": clean_entity_ids}},
                {"terms": {"process.parent.guid": clean_entity_ids}},
                {"terms": {"process.parent.entity_id": clean_entity_ids}},
                {"terms": {"parent.process.guid": clean_entity_ids}},
                {"terms": {"parent.process.entity_id": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in parent_pids if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.parent_pid": pid_values}},
                {"terms": {"process.parent.pid": pid_values}},
                {"terms": {"parent.process.pid": pid_values}},
                {"terms": {"process.parent_pid": clean_pids}},
                {"terms": {"process.parent.pid": clean_pids}},
                {"terms": {"parent.process.pid": clean_pids}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _activity_identity_filter(*, entity_ids: set[str], pids: set[int], process_name: str | None = None) -> dict | None:
    should: list[dict] = []
    clean_entity_ids = sorted({str(item).strip() for item in entity_ids if str(item).strip()})
    if clean_entity_ids:
        should.extend(
            [
                {"terms": {"process.entity_id": clean_entity_ids}},
                {"terms": {"process.guid": clean_entity_ids}},
                {"terms": {"process.parent_entity_id": clean_entity_ids}},
                {"terms": {"process.parent.guid": clean_entity_ids}},
            ]
        )
    clean_pids = sorted({int(pid) for pid in pids if pid is not None})
    if clean_pids:
        pid_values = [str(pid) for pid in clean_pids]
        should.extend(
            [
                {"terms": {"process.pid": pid_values}},
                {"terms": {"process.pid": clean_pids}},
            ]
        )
    name = str(process_name or "").strip()
    if name:
        wildcard_value = f"*{name.replace('*', '').replace('?', '')}*"
        should.extend(
            [
                {"wildcard": {"process.name": {"value": wildcard_value, "case_insensitive": True}}},
                {"wildcard": {"process.executable": {"value": wildcard_value, "case_insensitive": True}}},
            ]
        )
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _dedupe_events(events: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[str] = set()
    for event in events:
        event_id = str(event.get("id") or event.get("event_id") or "")
        if event_id and event_id in seen:
            continue
        if event_id:
            seen.add(event_id)
        deduped.append(event)
    return deduped


def _host_focus_filter(host: str | None) -> dict | None:
    normalized = normalize_host_alias(host)
    if not normalized:
        return None
    aliases = {normalized}
    if "." in normalized:
        aliases.add(normalized.split(".", 1)[0])
    should: list[dict] = []
    for alias in sorted(aliases):
        should.extend(
            [
                {"term": {"host.name": alias}},
                {"term": {"host.canonical": alias}},
                {"wildcard": {"host.name": {"value": f"{alias}.*", "case_insensitive": True}}},
                {"wildcard": {"host.canonical": {"value": f"{alias}.*", "case_insensitive": True}}},
            ]
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def build_process_tree_bundle(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    pid: int | None = None,
    process_name: str | None = None,
    entity_id: str | None = None,
    host: str | None = None,
    include_activity: bool = False,
    aggregate_activity: bool = True,
    edge_types: list[str] | None = None,
    max_nodes: int = 50,
    max_activity_per_process: int = 10,
    only_suspicious: bool = False,
    only_marked: bool = False,
) -> dict:
    context = _ProcessTreeContext(
        case=case,
        evidences=evidences,
        export_timestamp=datetime.now(UTC),
        scope=scope,
        evidence_id=evidence_id,
        max_events_per_type=250,
    )
    base_process_filters = [
        {
            "bool": {
                "should": [
                    {"terms": {"event.type": ["process_start", "process_creation", "sysmon_process_creation", "sysmon_process_created"]}},
                    {"term": {"artifact.type": "process"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    host_filter = _host_focus_filter(host)
    if host_filter:
        base_process_filters.append(host_filter)
    process_filters = list(base_process_filters)
    focus_filter = _process_focus_filter(pid=pid, process_name=process_name, entity_id=entity_id)
    if focus_filter:
        process_filters.append(focus_filter)
    focused_query = bool(focus_filter)
    process_events, _, _ = _search_scope_events(context, size=500 if focused_query else 2000, extra_filters=process_filters)
    if focused_query:
        parent_entity_ids = sorted(
            {
                str((event.get("process") or {}).get("parent_entity_id") or "").strip()
                for event in process_events
                if str((event.get("process") or {}).get("parent_entity_id") or "").strip()
            }
        )
        if parent_entity_ids:
            parent_guid_filter = {
                "bool": {
                    "should": [
                        {"terms": {"process.entity_id": parent_entity_ids}},
                        {"terms": {"process.guid": parent_entity_ids}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            parent_guid_events, _, _ = _search_scope_events(context, size=min(max(len(parent_entity_ids) * 4, 50), 500), extra_filters=[*base_process_filters, parent_guid_filter])
            process_events = [*process_events, *parent_guid_events]
        parent_context_events, _, _ = _search_scope_events(context, size=1500, extra_filters=base_process_filters)
        process_events = [*process_events, *parent_context_events]
    enrichment_filters = [
        {
            "bool": {
                "should": [
                    {"terms": {"artifact.type": ["browser", "bits", "dns", "srum", "detection", "autorun"]}},
                    {"terms": {"event.type": ["sysmon_network_connection", "sysmon_file_created", "sysmon_file_create_stream_hash", "sysmon_file_deleted", "sysmon_registry_key_event", "sysmon_registry_value_set", "sysmon_registry_key_renamed", "sysmon_dns_query"]}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if host_filter:
        enrichment_filters.append(host_filter)
    if focus_filter:
        enrichment_filters.append(focus_filter)
    enrichment_events, _, _ = _search_scope_events(
        context,
        size=500 if focused_query else 1000,
        extra_filters=enrichment_filters,
    )

    deduped_events: list[dict] = []
    seen_event_ids: set[str] = set()
    for event in [*process_events, *enrichment_events]:
        event_id_value = str(event.get("id") or event.get("event_id") or "")
        if event_id_value and event_id_value in seen_event_ids:
            continue
        if event_id_value:
            seen_event_ids.add(event_id_value)
        deduped_events.append(event)

    graph = _build_process_graph(deduped_events, case.id, evidence_id, scope)
    filtered_graph = _filter_process_graph(graph, pid=pid, process_name=process_name, entity_id=entity_id)
    compact_graph = _compact_process_graph(
        filtered_graph,
        include_activity=include_activity,
        aggregate_activity=aggregate_activity,
        edge_types=edge_types,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity_per_process,
        only_suspicious=only_suspicious,
        only_marked=only_marked,
    )
    report = _build_process_tree_report(compact_graph, deduped_events, selected_scope=scope)
    sample_chains = _build_process_tree_sample_chains(compact_graph)
    compact_graph.setdefault("summary", {})
    compact_graph["summary"]["suspicious_chains_count"] = len(sample_chains)
    return {
        "graph": compact_graph,
        "report": report,
        "sample_chains": sample_chains,
    }


def _process_identity_from_events(events: list[dict], *, entity_id: str | None, pid: int | None, process_name: str | None) -> tuple[set[str], set[int], set[str], set[int], dict | None]:
    entity_ids = {str(entity_id or "").strip()} if str(entity_id or "").strip() else set()
    pids = {int(pid)} if pid is not None else set()
    parent_entity_ids: set[str] = set()
    parent_pids: set[int] = set()
    base_event: dict | None = events[0] if events else None
    name_value = str(process_name or "").strip().lower()
    for event in events:
        process = event.get("process") or {}
        event_entity_id = str(process.get("entity_id") or process.get("guid") or "").strip()
        event_pid = _safe_intish(process.get("pid"))
        event_name = str(process.get("name") or process.get("executable") or "").strip().lower()
        if entity_id and event_entity_id and event_entity_id != str(entity_id).strip():
            continue
        if pid is not None and event_pid is not None and event_pid != int(pid):
            continue
        if name_value and event_name and name_value not in event_name and name_value not in str(process.get("command_line") or "").lower():
            continue
        if event_entity_id:
            entity_ids.add(event_entity_id)
        if event_pid is not None:
            pids.add(event_pid)
        parent_entity_id = str(process.get("parent_entity_id") or _nested_get(event, "process.parent.entity_id") or _nested_get(event, "parent.process.entity_id") or "").strip()
        if parent_entity_id:
            parent_entity_ids.add(parent_entity_id)
        parent_pid = _safe_intish(process.get("parent_pid") or process.get("ppid") or _nested_get(event, "process.parent.pid") or _nested_get(event, "parent.process.pid"))
        if parent_pid is not None:
            parent_pids.add(parent_pid)
        if base_event is None:
            base_event = event
    return entity_ids, pids, parent_entity_ids, parent_pids, base_event


def build_process_tree_expansion(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    node_id: str | None = None,
    process_guid: str | None = None,
    process_pid: int | None = None,
    process_name: str | None = None,
    timestamp: str | None = None,
    expansion_type: str = "children",
    depth: int = 1,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 50,
    max_activity: int = 25,
    edge_types: list[str] | None = None,
) -> dict:
    expansion = str(expansion_type or "children").strip().lower()
    if expansion not in {"children", "parents", "siblings", "activity", "commands"}:
        raise ValueError("expansion_type must be children, parents, siblings, activity, or commands")
    context = _ProcessTreeContext(
        case=case,
        evidences=evidences,
        export_timestamp=datetime.now(UTC),
        scope=scope,
        evidence_id=evidence_id,
        max_events_per_type=250,
    )
    host_filter = _host_focus_filter(host)
    time_filter = _time_window_filter(timestamp, time_window_before, time_window_after)
    base_process_filters = [_process_start_filter()]
    if host_filter:
        base_process_filters.append(host_filter)
    if time_filter:
        base_process_filters.append(time_filter)

    identity_entity_id = process_guid or node_id
    identity_name_fallback = process_name if not identity_entity_id and process_pid is None else None
    base_identity_filter = _identity_filter(
        entity_ids={identity_entity_id} if identity_entity_id else set(),
        pids={process_pid} if process_pid is not None else set(),
        process_name=identity_name_fallback,
    )
    selected_filters = list(base_process_filters)
    if base_identity_filter:
        selected_filters.append(base_identity_filter)
    selected_events, _, _ = _search_scope_events(context, size=300, extra_filters=selected_filters)
    entity_ids, pids, parent_entity_ids, parent_pids, base_event = _process_identity_from_events(
        selected_events,
        entity_id=identity_entity_id,
        pid=process_pid,
        process_name=process_name,
    )
    if identity_entity_id:
        entity_ids.add(str(identity_entity_id).strip())
    if process_pid is not None:
        pids.add(int(process_pid))

    expansion_events: list[dict] = []
    warnings: list[str] = []
    omitted_counts: Counter[str] = Counter()
    max_nodes = min(max(int(max_nodes or 50), 1), 500)
    max_activity = min(max(int(max_activity or 25), 1), 500)
    depth = min(max(int(depth or 1), 1), 5)

    if expansion == "commands":
        return {
            "base_node": None,
            "added_nodes": [],
            "added_edges": [],
            "activity_groups": [],
            "omitted_counts": {},
            "warnings": ["Use the Command History endpoint for command expansion."],
            "command_history": {
                "process_guid": sorted(entity_ids)[0] if entity_ids else None,
                "process_pid": sorted(pids)[0] if pids else None,
                "process_name": process_name,
            },
        }

    frontier_entity_ids = set(entity_ids)
    frontier_pids = set(pids)
    collected_process_events = list(selected_events)
    if expansion == "children":
        for _ in range(depth):
            child_filter = _child_process_filter(parent_entity_ids=frontier_entity_ids, parent_pids=frontier_pids)
            if not child_filter:
                break
            child_events, _, _ = _search_scope_events(context, size=max_nodes * 4, extra_filters=[*base_process_filters, child_filter])
            child_events = _dedupe_events(child_events)
            if not child_events:
                break
            expansion_events.extend(child_events)
            next_entity_ids, next_pids, _, _, _ = _process_identity_from_events(child_events, entity_id=None, pid=None, process_name=None)
            next_entity_ids -= frontier_entity_ids
            next_pids -= frontier_pids
            frontier_entity_ids = next_entity_ids
            frontier_pids = next_pids
            if not frontier_entity_ids and not frontier_pids:
                break
        if not expansion_events:
            warnings.append("No additional children found for the selected process within the current scope.")
    elif expansion == "parents":
        frontier_parent_entity_ids = set(parent_entity_ids)
        frontier_parent_pids = set(parent_pids)
        for _ in range(depth):
            parent_filter = _identity_filter(entity_ids=frontier_parent_entity_ids, pids=frontier_parent_pids)
            if not parent_filter:
                break
            parent_events, _, _ = _search_scope_events(context, size=max_nodes * 2, extra_filters=[*base_process_filters, parent_filter])
            parent_events = _dedupe_events(parent_events)
            if not parent_events:
                break
            expansion_events.extend(parent_events)
            _, _, next_parent_entity_ids, next_parent_pids, _ = _process_identity_from_events(parent_events, entity_id=None, pid=None, process_name=None)
            frontier_parent_entity_ids = next_parent_entity_ids - frontier_parent_entity_ids
            frontier_parent_pids = next_parent_pids - frontier_parent_pids
            if not frontier_parent_entity_ids and not frontier_parent_pids:
                break
        if not expansion_events:
            warnings.append("No parent process events were found for the selected process.")
    elif expansion == "siblings":
        sibling_filter = _child_process_filter(parent_entity_ids=parent_entity_ids, parent_pids=parent_pids)
        if sibling_filter:
            sibling_events, _, _ = _search_scope_events(context, size=max_nodes * 4, extra_filters=[*base_process_filters, sibling_filter])
            selected_event_ids = {str(event.get("id") or event.get("event_id") or "") for event in selected_events}
            expansion_events = [
                event
                for event in _dedupe_events(sibling_events)
                if str(event.get("id") or event.get("event_id") or "") not in selected_event_ids
            ]
        if not expansion_events:
            warnings.append("No sibling processes found for the selected process within the current scope.")
    elif expansion == "activity":
        activity_filters = [_process_activity_filter()]
        if host_filter:
            activity_filters.append(host_filter)
        if time_filter:
            activity_filters.append(time_filter)
        activity_identity = _activity_identity_filter(entity_ids=entity_ids, pids=pids, process_name=process_name if not entity_ids and not pids else None)
        if activity_identity:
            activity_filters.append(activity_identity)
        activity_events, _, _ = _search_scope_events(context, size=max_activity * 8, extra_filters=activity_filters)
        expansion_events = _dedupe_events(activity_events)
        if not expansion_events:
            warnings.append("No process activity found for the selected process within the current scope.")

    graph_events = _dedupe_events([*collected_process_events, *expansion_events])
    if expansion in {"children", "parents", "siblings"} and expansion_events:
        # Pull a little adjacent context so the returned subgraph can connect via existing edges.
        related_entity_ids, related_pids, related_parent_entity_ids, related_parent_pids, _ = _process_identity_from_events(expansion_events, entity_id=None, pid=None, process_name=None)
        context_filter = _identity_filter(entity_ids=entity_ids | related_entity_ids | parent_entity_ids | related_parent_entity_ids, pids=pids | related_pids | parent_pids | related_parent_pids)
        if context_filter:
            context_events, _, _ = _search_scope_events(context, size=min(max_nodes * 6, 1000), extra_filters=[*base_process_filters, context_filter])
            graph_events = _dedupe_events([*graph_events, *context_events])

    graph = _build_process_graph(graph_events, case.id, evidence_id, scope)
    compact_graph = _compact_process_graph(
        graph,
        include_activity=expansion == "activity" and bool(edge_types),
        aggregate_activity=True,
        edge_types=edge_types,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity,
    )
    summary = compact_graph.get("summary") or {}
    omitted_counts.update({str(key): int(value or 0) for key, value in (compact_graph.get("omitted_counts") or {}).items()})
    warnings.extend(str(item) for item in summary.get("warnings") or [])
    base_graph_node = None
    if base_event:
        base_graph = _build_process_graph([base_event], case.id, evidence_id, scope)
        base_graph_node = (base_graph.get("nodes") or [None])[0]
    return {
        "base_node": base_graph_node,
        "added_nodes": compact_graph.get("nodes") or [],
        "added_edges": compact_graph.get("edges") or [],
        "activity_groups": compact_graph.get("groups") or [],
        "omitted_counts": dict(omitted_counts),
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
        "summary": {
            **summary,
            "expansion_type": expansion,
            "selected_events": len(selected_events),
            "expansion_events": len(expansion_events),
        },
    }


def _merge_graph_parts(parts: list[dict]) -> dict:
    nodes_by_id: dict[str, dict] = {}
    edges_by_id: dict[str, dict] = {}
    groups_by_id: dict[str, dict] = {}
    omitted_counts: Counter[str] = Counter()
    warnings: list[str] = []
    for part in parts:
        for node in part.get("nodes") or part.get("added_nodes") or []:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            if node_id in nodes_by_id:
                merged = dict(nodes_by_id[node_id])
                for key, value in node.items():
                    if value not in (None, "", [], {}):
                        merged[key] = value
                nodes_by_id[node_id] = merged
            else:
                nodes_by_id[node_id] = dict(node)
        for edge in part.get("edges") or part.get("added_edges") or []:
            edge_id = str(edge.get("id") or f"{edge.get('source')}->{edge.get('target')}:{edge.get('type') or ''}")
            if edge_id:
                edges_by_id[edge_id] = dict(edge)
        for group in part.get("groups") or part.get("activity_groups") or []:
            group_id = str(group.get("id") or f"{group.get('source') or ''}:{group.get('group') or ''}")
            if group_id:
                groups_by_id[group_id] = dict(group)
        omitted_counts.update({str(key): int(value or 0) for key, value in (part.get("omitted_counts") or {}).items()})
        warnings.extend(str(item) for item in part.get("warnings") or [])
    return {
        "nodes": list(nodes_by_id.values()),
        "edges": list(edges_by_id.values()),
        "groups": list(groups_by_id.values()),
        "omitted_counts": dict(omitted_counts),
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
    }


def _node_identity_matches(node: dict, *, process_guid: str | None, pid: int | None, source_event_id: str | None, process_name: str | None) -> bool:
    source_events = {str(item) for item in (node.get("source_events") or []) if item}
    if source_event_id and (str(node.get("source_event_id") or "") == str(source_event_id) or str(source_event_id) in source_events):
        return True
    if source_event_id:
        return False
    if process_guid and str(node.get("id") or "").strip() == str(process_guid).strip():
        return True
    if pid is not None and _safe_intish(node.get("pid")) == int(pid):
        name = str(process_name or "").strip().lower()
        if not name:
            return True
        haystack = f"{node.get('name') or ''} {node.get('path') or ''} {node.get('command_line') or ''}".lower()
        return name in haystack
    return False


def normalize_process_name(value: str | None) -> str:
    """Reduce a process reference to something comparable.

    Analysts and events refer to the same process in several ways: a bare name,
    a full path, with or without the extension, in any case. Comparing those
    literally is what makes a search for "powershell" miss
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".
    """
    text = str(value or "").strip().strip('"').lower()
    if not text:
        return ""
    # Take the basename of either path flavour, then drop a trailing extension.
    for separator in ("\\", "/"):
        if separator in text:
            text = text.rsplit(separator, 1)[-1]
    if text.endswith(".exe"):
        text = text[: -len(".exe")]
    return text.strip()


def _node_name_haystack(node: dict) -> str:
    return " ".join(
        str(node.get(field) or "")
        for field in ("name", "path", "command_line")
    ).lower()


def _node_matches_name(node: dict, wanted: str) -> bool:
    """True when a node plausibly is the process the analyst named."""
    if not wanted:
        return False
    if normalize_process_name(node.get("name")) == wanted:
        return True
    if normalize_process_name(node.get("path")) == wanted:
        return True
    return wanted in _node_name_haystack(node)


# Ordered from "this is certainly the process you clicked" to "this is a
# process with the right name". Every step after the first is a guess, so the
# strategy that matched is reported and shown to the analyst -- silently
# resolving a different process than the one clicked would be far worse than
# finding nothing.
FOCUS_MATCH_EXPLANATIONS = {
    "source_event": "Matched the exact event you opened.",
    "process_guid": "Matched the exact process by its ProcessGuid.",
    "pid_and_name": "No node carried that exact event, so this was matched by PID and process name.",
    "pid": "No node carried that exact event, so this was matched by PID alone. Confirm it is the right process before relying on it.",
    "name": "No node matched that PID or event, so this was matched by process name alone. It may be a different execution of the same program.",
}


def _resolve_focus_node(
    nodes: list[dict],
    *,
    process_guid: str | None,
    pid: int | None,
    source_event_id: str | None,
    process_name: str | None,
) -> tuple[dict | None, str | None, list[dict]]:
    """Find the process to focus on, relaxing the criteria step by step.

    Returns the chosen node, the strategy that found it, and any other nodes
    that also fit -- so the caller can offer them rather than leaving the
    analyst with an empty graph and no way forward.
    """
    wanted_name = normalize_process_name(process_name)

    def pick(candidates: list[dict], strategy: str) -> tuple[dict, str, list[dict]]:
        chosen = min(candidates, key=_focus_candidate_rank)
        others = [node for node in candidates if node is not chosen]
        return chosen, strategy, others

    if source_event_id:
        wanted = str(source_event_id)
        matches = [
            node for node in nodes
            if str(node.get("source_event_id") or "") == wanted
            or wanted in {str(item) for item in (node.get("source_events") or []) if item}
        ]
        if matches:
            return pick(matches, "source_event")

    if process_guid:
        wanted = str(process_guid).strip()
        matches = [node for node in nodes if str(node.get("id") or "").strip() == wanted]
        if matches:
            return pick(matches, "process_guid")

    if pid is not None:
        same_pid = [node for node in nodes if _safe_intish(node.get("pid")) == int(pid)]
        if same_pid and wanted_name:
            named = [node for node in same_pid if _node_matches_name(node, wanted_name)]
            if named:
                return pick(named, "pid_and_name")
        if same_pid:
            return pick(same_pid, "pid")

    if wanted_name:
        matches = [node for node in nodes if _node_matches_name(node, wanted_name)]
        if matches:
            return pick(matches, "name")

    return None, None, []


def _nearest_named_nodes(nodes: list[dict], wanted_name: str | None, limit: int = 10) -> list[dict]:
    """Processes whose name is closest to what was asked for.

    Exists so a failed lookup ends with "did you mean one of these?" rather
    than an empty graph. Falls back to the busiest processes when no name was
    given at all, since those are the ones an analyst is most likely after.
    """
    wanted = normalize_process_name(wanted_name)
    if wanted:
        matches = [node for node in nodes if _node_matches_name(node, wanted)]
        if matches:
            return sorted(matches, key=_focus_candidate_rank)[:limit]
        # Nothing contains the whole term; offer names sharing its start, which
        # catches a truncated or misremembered name.
        prefix = wanted[:4]
        if len(prefix) >= 3:
            near = [node for node in nodes if normalize_process_name(node.get("name")).startswith(prefix)]
            if near:
                return sorted(near, key=_focus_candidate_rank)[:limit]
        return []
    return sorted(nodes, key=_focus_candidate_rank)[:limit]


def _focus_candidate_summary(node: dict) -> dict:
    """The minimum an analyst needs to choose between similar processes."""
    return {
        "id": node.get("id"),
        "pid": node.get("pid"),
        "name": node.get("name"),
        "path": node.get("path"),
        "command_line": node.get("command_line"),
        "user": node.get("user"),
        "host": node.get("host"),
        "first_seen": node.get("first_seen"),
        "last_seen": node.get("last_seen"),
    }


def _focus_candidate_rank(node: dict) -> tuple[bool, bool]:
    node_id = str(node.get("id") or "")
    is_synthetic = node_id.startswith("security:")
    has_command_line = bool(str(node.get("command_line") or "").strip())
    return (is_synthetic, not has_command_line)


def _parent_explanation_for_node(node: dict | None) -> str:
    if not node:
        return "Focused process could not be resolved."
    process_name = str(node.get("name") or "This process")
    pid_text = f" PID {node.get('pid')}" if node.get("pid") is not None else ""
    parent_name = str(node.get("parent_name") or "").strip()
    parent_pid = node.get("parent_pid")
    if str(node.get("parent_link_status") or "") == "linked" and (parent_name or parent_pid is not None):
        parent_text = parent_name or "its parent process"
        if parent_pid is not None:
            parent_text = f"{parent_text} PID {parent_pid}"
        return f"This {process_name}{pid_text} was launched by {parent_text}."
    reason = str(node.get("parent_link_reason") or "Parent process could not be found.")
    return f"Parent process could not be linked for {process_name}{pid_text}. Reason: {reason}"


def build_process_tree_focused(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    pid: int | None = None,
    process_guid: str | None = None,
    source_event_id: str | None = None,
    process_name: str | None = None,
    timestamp: str | None = None,
    parent_depth: int = 2,
    child_depth: int = 2,
    include_siblings: bool = True,
    include_activity: bool = False,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 100,
    max_activity: int = 25,
) -> dict:
    parent_depth = min(max(int(parent_depth or 0), 0), 5)
    child_depth = min(max(int(child_depth or 0), 0), 5)
    max_nodes = min(max(int(max_nodes or 100), 1), 500)
    max_activity = min(max(int(max_activity or 25), 1), 500)

    resolved_guid = str(process_guid or "").strip() or None
    resolved_pid = pid
    resolved_name = str(process_name or "").strip() or None
    resolved_timestamp = timestamp
    selected_source_events: list[dict] = []
    if source_event_id:
        context = _ProcessTreeContext(
            case=case,
            evidences=evidences,
            export_timestamp=datetime.now(UTC),
            scope=scope,
            evidence_id=evidence_id,
            max_events_per_type=250,
        )
        source_filters = [_process_start_filter()]
        source_filter = _source_event_filter(source_event_id)
        if source_filter:
            source_filters.append(source_filter)
        selected_source_events, _, _ = _search_scope_events(context, size=25, extra_filters=source_filters)
        if selected_source_events:
            source_process = selected_source_events[0].get("process") or {}
            resolved_guid = resolved_guid or str(source_process.get("entity_id") or source_process.get("guid") or "").strip() or None
            resolved_pid = resolved_pid if resolved_pid is not None else _safe_intish(source_process.get("pid"))
            resolved_name = resolved_name or str(source_process.get("name") or source_process.get("executable") or "").strip() or None
            resolved_timestamp = resolved_timestamp or selected_source_events[0].get("@timestamp")

    base_bundle = build_process_tree_bundle(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        pid=resolved_pid,
        process_name=resolved_name,
        entity_id=resolved_guid,
        include_activity=False,
        aggregate_activity=True,
        max_nodes=max_nodes,
        max_activity_per_process=max_activity,
    )
    base_graph = base_bundle.get("graph") or {}
    base_nodes = list(base_graph.get("nodes") or [])
    # Resolve by exact identity first, then progressively relax. A node built
    # from a different source than the event clicked (Security 4688 vs Sysmon)
    # carries neither the same event id nor the same ProcessGuid, and refusing
    # to look any further is what leaves the analyst with an empty graph for a
    # process that is plainly in the tree.
    focus_node, focus_match, focus_alternatives = _resolve_focus_node(
        base_nodes,
        process_guid=resolved_guid,
        pid=resolved_pid,
        source_event_id=source_event_id,
        process_name=resolved_name,
    )
    if focus_node:
        resolved_guid = resolved_guid or str(focus_node.get("id") or "").strip() or None
        resolved_pid = resolved_pid if resolved_pid is not None else _safe_intish(focus_node.get("pid"))
        resolved_name = resolved_name or str(focus_node.get("name") or "").strip() or None
        resolved_timestamp = resolved_timestamp or focus_node.get("first_seen") or focus_node.get("last_seen")

    parts = [base_graph]
    warnings: list[str] = []
    if not focus_node:
        # Even with nothing matched, hand back what the case does contain for
        # this name so the analyst has somewhere to go next.
        focus_alternatives = _nearest_named_nodes(base_nodes, resolved_name)
        if focus_alternatives:
            warnings.append(
                "No process matched that PID, ProcessGuid or event. The closest processes "
                "by name are offered as candidates below."
            )
        elif source_event_id:
            warnings.append("Could not build exact story for selected process event. No process node matched the requested source_event_id.")
        elif process_guid:
            warnings.append("Could not build exact story for selected process. No process node matched the requested ProcessGuid.")
        else:
            warnings.append("No process node matched the requested PID, ProcessGuid, or source event.")
    else:
        if focus_match and focus_match not in ("source_event", "process_guid"):
            # A relaxed match must never pass as the exact one: the analyst has
            # to know they may be looking at a different execution. The tree is
            # still built -- a warning is the point, not a dead end.
            warnings.append(FOCUS_MATCH_EXPLANATIONS[focus_match])
        expansion_kwargs = {
            "scope": scope,
            "evidence_id": evidence_id,
            "host": host or focus_node.get("host"),
            "node_id": str(focus_node.get("id") or resolved_guid or ""),
            "process_guid": str(focus_node.get("id") or resolved_guid or ""),
            "process_pid": resolved_pid,
            "process_name": resolved_name,
            "timestamp": resolved_timestamp,
            "time_window_before": time_window_before,
            "time_window_after": time_window_after,
            "max_nodes": max_nodes,
            "max_activity": max_activity,
        }
        if parent_depth:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="parents",
                    depth=parent_depth,
                    **expansion_kwargs,
                )
            )
        if child_depth:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="children",
                    depth=child_depth,
                    **expansion_kwargs,
                )
            )
        if include_siblings:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="siblings",
                    depth=1,
                    **expansion_kwargs,
                )
            )
        if include_activity:
            parts.append(
                build_process_tree_expansion(
                    case,
                    evidences,
                    expansion_type="activity",
                    depth=1,
                    **expansion_kwargs,
                )
            )

    merged = _merge_graph_parts(parts)
    warnings.extend(merged["warnings"])
    nodes = merged["nodes"]
    edges = merged["edges"]
    focus_id = str((focus_node or {}).get("id") or resolved_guid or "")
    parent_ids = {edge.get("source") for edge in edges if edge.get("target") == focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}}
    child_ids = {edge.get("target") for edge in edges if edge.get("source") == focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}}
    sibling_ids: set[str] = set()
    if parent_ids:
        for edge in edges:
            if edge.get("source") in parent_ids and edge.get("target") != focus_id and str(edge.get("type") or "") in {"spawned", "parent_child"}:
                sibling_ids.add(str(edge.get("target")))
    node_by_id = {str(node.get("id")): node for node in nodes}
    ambiguous_candidates = []
    if pid is not None and not process_guid and not source_event_id:
        pid_candidates = [node for node in nodes if _safe_intish(node.get("pid")) == int(pid)]
        if not (timestamp or host or evidence_id) and len(pid_candidates) > 1:
            ambiguous_candidates = pid_candidates
            warnings.append("PID-only focus matched multiple candidates. Add host, evidence, timestamp, or ProcessGuid to disambiguate.")
    method = "source_event_id" if source_event_id else "process_guid" if process_guid else "pid_timestamp_host" if timestamp or host or evidence_id else "pid_only" if pid is not None else "process_name"
    confidence = "high" if process_guid or source_event_id or (pid is not None and (timestamp or host or evidence_id)) else "low" if ambiguous_candidates else "medium"
    target_identity_matches = not bool(source_event_id or process_guid) or bool(focus_node)
    if focus_node and source_event_id:
        target_identity_matches = _node_identity_matches(
            focus_node,
            process_guid=None,
            pid=None,
            source_event_id=source_event_id,
            process_name=None,
        )
        if not target_identity_matches:
            warnings.append("Exact source_event_id did not round-trip to the selected target.")
    elif focus_node and process_guid:
        target_identity_matches = str(focus_node.get("id") or "").strip() == str(process_guid).strip()
        if not target_identity_matches:
            warnings.append("Exact ProcessGuid did not round-trip to the selected target.")
    return {
        "focus_node": node_by_id.get(focus_id) or focus_node,
        "parents": [node_by_id[item] for item in parent_ids if item in node_by_id],
        "children": [node_by_id[item] for item in child_ids if item in node_by_id],
        "siblings": [node_by_id[item] for item in sibling_ids if item in node_by_id],
        "activity_groups": merged["groups"],
        "nodes": nodes,
        "edges": edges,
        "omitted_counts": merged["omitted_counts"],
        "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
        "identity_resolution": {
            "method": method,
            "confidence": confidence,
            "ambiguous_candidates": ambiguous_candidates[:10],
            "parent_explanation": _parent_explanation_for_node(node_by_id.get(focus_id) or focus_node),
            "target_identity_matches": target_identity_matches,
            "requested_source_event_id": source_event_id,
            "requested_process_guid": process_guid,
            # How the focus was found, and what else it could have been. An
            # empty graph with no way forward is the failure mode this avoids.
            "focus_match": focus_match,
            "focus_match_explanation": FOCUS_MATCH_EXPLANATIONS.get(focus_match or "", ""),
            "is_exact_match": focus_match in ("source_event", "process_guid"),
            "candidates": [_focus_candidate_summary(node) for node in focus_alternatives[:10]],
        },
    }


def _node_short_label(node: dict | None) -> str:
    if not node:
        return "unknown process"
    label = str(node.get("name") or node.get("path") or "process")
    if node.get("pid") is not None:
        label = f"{label} PID {node.get('pid')}"
    return label


def _children_sentence(target: dict | None, children: list[dict]) -> str:
    if not target:
        return "No execution target was resolved."
    if not children:
        return f"{_node_short_label(target)} did not launch any direct child processes in the selected scope."
    labels = [_node_short_label(child) for child in children[:5]]
    suffix = f" and {len(children) - 5} more" if len(children) > 5 else ""
    return f"It launched {', '.join(labels)}{suffix}."


def _parent_sentence_for_story(target: dict | None, parents: list[dict], fallback: str) -> str:
    if not target:
        return fallback
    if fallback and not fallback.startswith("Parent process could not be linked"):
        return fallback
    candidates = [parent for parent in parents if parent and parent.get("id") != target.get("id")]
    if not candidates:
        return fallback
    target_parent_pid = target.get("parent_pid")
    target_parent_name = str(target.get("parent_name") or "").lower()
    parent = None
    for candidate in candidates:
        candidate_name = str(candidate.get("name") or candidate.get("path") or "").lower()
        if target_parent_pid is not None and candidate.get("pid") == target_parent_pid:
            parent = candidate
            break
        if target_parent_name and target_parent_name in candidate_name:
            parent = candidate
            break
    parent = parent or candidates[-1]
    return f"This {_node_short_label(target)} was launched by {_node_short_label(parent)}."


def _activity_sentence(groups: list[dict], omitted_counts: dict) -> str:
    counts: Counter[str] = Counter()
    for group in groups:
        counts[str(group.get("group") or "activity")] += int(group.get("count") or 0)
    for key, value in (omitted_counts or {}).items():
        counts[str(key)] += int(value or 0)
    interesting = [(name, count) for name, count in counts.items() if count]
    if not interesting:
        return "No grouped file, registry, network or DNS activity was observed for the target process."
    labels = []
    for name, count in sorted(interesting):
        label = {
            "dns": "DNS queries",
            "file": "file events",
            "network": "network connections",
            "registry": "registry events",
        }.get(name, f"{name} events")
        labels.append(f"{count} {label}")
    if len(labels) == 1:
        return f"{labels[0]} were observed."
    return f"{', '.join(labels[:-1])} and {labels[-1]} were observed."


def _risk_sentence(target: dict | None, children: list[dict]) -> str:
    reasons = list((target or {}).get("risk_reasons") or [])
    for child in children:
        reasons.extend(str(item) for item in (child.get("risk_reasons") or []) if item)
    reasons = list(dict.fromkeys([reason for reason in reasons if reason]))[:4]
    if not reasons:
        return "No explicit suspicious reasons were attached to this story."
    return "Suspicious because " + "; ".join(reason[0].lower() + reason[1:] if reason else reason for reason in reasons) + "."


def _event_host(event: dict) -> str | None:
    return str(_nested_get(event, "host.name") or _nested_get(event, "host.hostname") or _nested_get(event, "windows.computer") or "").strip() or None


def _event_source_label(event: dict) -> str:
    provider = str(_nested_get(event, "event.provider") or _nested_get(event, "winlog.provider_name") or "").strip()
    channel = str(_nested_get(event, "event.channel") or _nested_get(event, "winlog.channel") or "").strip()
    event_id = str(_nested_get(event, "windows.event_id") or _nested_get(event, "event.code") or "").strip()
    artifact_type = str(_nested_get(event, "artifact.type") or "").strip()
    parts = [part for part in [provider, channel, f"EventID {event_id}" if event_id else "", artifact_type] if part]
    return " / ".join(parts) or "event"


def _classify_execution_story_source_event(event: dict | None) -> tuple[str, str, str]:
    if not event:
        return "generic", "source_event_id", "low"
    process = event.get("process") or {}
    has_identity = bool(
        str(process.get("entity_id") or process.get("guid") or "").strip()
        or _safe_intish(process.get("pid")) is not None
    )
    has_command = bool(str(process.get("command_line") or "").strip())
    event_id = _safe_intish(_nested_get(event, "windows.event_id") or _nested_get(event, "event.code"))
    provider = str(_nested_get(event, "event.provider") or _nested_get(event, "winlog.provider_name") or "").lower()
    event_type = str(_nested_get(event, "event.type") or "").lower()
    artifact_type = str(_nested_get(event, "artifact.type") or "").lower()
    if _is_process_start_event(event) and has_identity and has_command:
        return "exact", "source_event_id", "high"
    if event_id in {1, 4688} and has_identity and has_command:
        return "exact", "source_event_id", "high"
    if has_identity:
        if "powershell" in provider or "powershell" in event_type or artifact_type == "powershell":
            return "related", "source_event_id_process_context", "medium"
        return "related", "source_event_id_process_context", "medium"
    return "generic", "source_event_id_event_only", "low"


def _event_to_light_summary(event: dict | None, source_event_id: str | None) -> dict[str, Any]:
    if not event:
        return {
            "id": source_event_id,
            "timestamp": None,
            "host": None,
            "source": "event",
            "title": "Source event was not found",
            "summary": "The selected source_event_id was not found in indexed events.",
            "process": {},
        }
    process = event.get("process") or {}
    title = str(event.get("title") or _nested_get(event, "event.action") or _event_source_label(event))
    summary = str(event.get("summary") or _nested_get(event, "event.message") or title)
    if len(summary) > 600:
        summary = summary[:597].rstrip() + "..."
    return {
        "id": str(event.get("id") or event.get("event_id") or source_event_id or ""),
        "timestamp": event.get("@timestamp"),
        "host": _event_host(event),
        "source": _event_source_label(event),
        "title": title[:240],
        "summary": summary,
        "process": {
            "pid": _safe_intish(process.get("pid")),
            "name": process.get("name") or process.get("executable"),
            "command_line": process.get("command_line"),
            "entity_id": process.get("entity_id") or process.get("guid"),
            "user": _nested_get(event, "user.name"),
        },
    }


def _candidate_score_for_event(candidate: dict, source_event: dict | None) -> int:
    process = candidate.get("process") or {}
    source_process = (source_event or {}).get("process") or {}
    score = 0
    if _safe_intish(process.get("pid")) is not None and _safe_intish(process.get("pid")) == _safe_intish(source_process.get("pid")):
        score += 100
    if str(process.get("entity_id") or process.get("guid") or "") and str(process.get("entity_id") or process.get("guid")) == str(source_process.get("entity_id") or source_process.get("guid") or ""):
        score += 120
    candidate_user = str(_nested_get(candidate, "user.name") or "").lower()
    source_user = str(_nested_get(source_event or {}, "user.name") or "").lower()
    if candidate_user and source_user and candidate_user == source_user:
        score += 25
    name = str(process.get("name") or process.get("executable") or "").lower()
    command = str(process.get("command_line") or "").lower()
    if "powershell" in name:
        score += 20
    if any(token in command for token in (" -ep bypass", "executionpolicy bypass", " -nop", " -w hidden", "psexec", "rubeus", "mimikatz")):
        score += 30
    source_ts = _safe_parse_dt((source_event or {}).get("@timestamp"))
    candidate_ts = _safe_parse_dt(candidate.get("@timestamp"))
    if source_ts and candidate_ts:
        delta = abs((candidate_ts - source_ts).total_seconds())
        if delta <= 60:
            score += 25
        elif delta <= 300:
            score += 15
        elif delta <= 1800:
            score += 5
    return score


def _candidate_node_from_event(event: dict, score: int) -> dict:
    graph = _build_process_graph([event], str(event.get("case_id") or ""), str(event.get("evidence_id") or ""), "case")
    nodes = list(graph.get("nodes") or [])
    if nodes:
        node = dict(nodes[0])
    else:
        process = event.get("process") or {}
        event_id = str(event.get("id") or event.get("event_id") or "")
        node = {
            "id": str(process.get("entity_id") or process.get("guid") or event_id),
            "pid": _safe_intish(process.get("pid")),
            "name": process.get("name") or process.get("executable"),
            "path": process.get("path"),
            "command_line": process.get("command_line"),
            "user": _nested_get(event, "user.name"),
            "host": _event_host(event),
            "first_seen": event.get("@timestamp"),
            "source_event_id": event_id,
            "source_events": [event_id] if event_id else [],
        }
    node["candidate_score"] = score
    node["candidate_reason"] = "Ranked by PID, user, time proximity and suspicious command indicators."
    return node


def _related_process_candidates_for_event(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None,
    host: str | None,
    source_event: dict | None,
    limit: int = 8,
) -> list[dict]:
    context = _ProcessTreeContext(
        case=case,
        evidences=evidences,
        export_timestamp=datetime.now(UTC),
        scope=scope,
        evidence_id=evidence_id,
        max_events_per_type=100,
    )
    filters = [_process_start_filter()]
    candidate_host = host or _event_host(source_event or {})
    host_filter = _host_focus_filter(candidate_host)
    if host_filter:
        filters.append(host_filter)
    time_filter = _time_window_filter((source_event or {}).get("@timestamp"), 900, 900)
    if time_filter:
        filters.append(time_filter)
    events, _, _ = _search_scope_events(context, size=300, extra_filters=filters)
    scored = sorted(
        [(_candidate_score_for_event(event, source_event), event) for event in _dedupe_events(events)],
        key=lambda item: (item[0], str(item[1].get("@timestamp") or "")),
        reverse=True,
    )
    return [_candidate_node_from_event(event, score) for score, event in scored[:limit]]


def _light_execution_story_for_generic_event(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None,
    host: str | None,
    source_event_id: str,
    source_event: dict | None,
    target_quality: str,
    identity_method: str,
    confidence: str,
    requested_target: dict[str, Any] | None = None,
    auto_focus_reason: str = "manual",
    origin: str = "search_event",
) -> dict:
    event_summary = _event_to_light_summary(source_event, source_event_id)
    candidates = _related_process_candidates_for_event(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        source_event=source_event,
        limit=8,
    )
    query_text = str((event_summary.get("process") or {}).get("command_line") or (event_summary.get("process") or {}).get("name") or "")
    recommendations = [
        "Build exact story from a candidate process.",
        "Search around the event timestamp.",
        "Open Command History around this host and time.",
    ]
    if target_quality == "generic":
        recommendations.insert(0, "This event is too broad for an exact process story.")
    story_text = (
        "Opened from a generic PowerShell event. Select a candidate process to build an exact story."
        if target_quality == "generic"
        else "Opened from a process-related event, not a process creation event. Select a candidate process to build an exact story."
    )
    return {
        "target": None,
        "target_node_id": None,
        "default_selected_node_id": None,
        "story": {
            "summary": story_text,
            "parent_sentence": "Parent/child process relationships are not built automatically for this event type.",
            "children_sentence": "Choose a candidate process to load exact children.",
            "activity_sentence": "Activity details are loaded on demand after an exact process target is selected.",
            "risk_sentence": "No exact process risk sentence was generated for this generic event.",
        },
        "parents": [],
        "children": [],
        "siblings": [],
        "activity_groups": {"items": [], "omitted_counts": {}},
        "commands": [],
        "source_events": [source_event_id],
        "visual_tree": {"nodes": [], "edges": []},
        "event_summary": event_summary,
        "candidate_processes": candidates,
        "nearby": {
            "search_query": query_text[:160] if query_text else None,
            "time_window_seconds": 300,
            "host": event_summary.get("host") or host,
        },
        "recommended_action": "build_exact_story_from_candidate" if candidates else "search_around_event",
        "requested_target": requested_target or {},
        "resolved_target": None,
        "auto_focus_reason": auto_focus_reason,
        "quality": {
            "confidence": confidence,
            "missing_parent": False,
            "ambiguous_pid": False,
            "warnings": [
                "This is not an exact process creation event.",
                "Could not build exact story for selected source_event_id; choose a related process candidate.",
                "Heavy graph/activity expansion was skipped to keep the first response small.",
            ],
            "identity_resolution": {
                "method": identity_method,
                "confidence": confidence,
                "ambiguous_candidates": candidates,
                "parent_explanation": "Select a candidate process to resolve parent/child relationships.",
                "target_identity_matches": False,
                "requested_source_event_id": source_event_id,
                "requested_process_guid": None,
            },
            "exact_story": False,
            "origin": origin,
            "filter_scope": "candidate_search",
            "visual_tree_contains_target": False,
            "target_quality": target_quality,
            "identity_method": identity_method,
            "recommended_action": "build_exact_story_from_candidate" if candidates else "search_around_event",
            "recommendations": recommendations,
            "activity_lazy": True,
            "response_mode": "lightweight",
        },
    }


def _execution_story_requested_target(
    *,
    evidence_id: str | None,
    host: str | None,
    pid: int | None,
    process_guid: str | None,
    source_event_id: str | None,
    command_history_row_id: str | None,
    origin: str | None,
    q: str | None,
    timestamp: str | None,
) -> dict[str, Any]:
    return {
        "origin": origin or None,
        "command_history_row_id": command_history_row_id or None,
        "evidence_id": evidence_id or None,
        "host": host or None,
        "pid": pid,
        "process_guid": process_guid or None,
        "source_event_id": source_event_id or None,
        "process_name": q or None,
        "timestamp": timestamp or None,
    }


def _execution_story_focus_reason(
    *,
    origin: str | None,
    command_history_row_id: str | None,
    source_event_id: str | None,
    process_guid: str | None,
    pid: int | None,
    q: str | None,
) -> str:
    if str(origin or "").strip().lower() == "command_history" or command_history_row_id:
        return "explicit_command_history_row"
    if source_event_id or process_guid or pid is not None or q:
        return "manual"
    return "risk_based_fallback"


def _execution_story_origin(origin: str | None, *, source_event_id: str | None, q: str | None, pid: int | None, process_guid: str | None) -> str:
    normalized = str(origin or "").strip().lower()
    if normalized == "command_history":
        return "command_history"
    if source_event_id:
        return "search_event"
    if q or pid is not None or process_guid:
        return "direct_search"
    return "advanced_graph"


def _execution_story_resolved_target(target: dict | None) -> dict[str, Any] | None:
    if not target:
        return None
    source_events = [str(item) for item in (target.get("source_events") or []) if item]
    return {
        "id": target.get("id"),
        "source_event_id": target.get("source_event_id") or (source_events[0] if source_events else None),
        "source_events": source_events,
        "process_guid": target.get("id"),
        "pid": target.get("pid"),
        "host": target.get("host"),
        "process_name": target.get("name"),
        "command_line": target.get("command_line"),
        "first_seen": target.get("first_seen"),
    }


def build_execution_story(
    case: Case,
    evidences: list[Evidence],
    *,
    scope: str,
    evidence_id: str | None = None,
    host: str | None = None,
    pid: int | None = None,
    process_guid: str | None = None,
    source_event_id: str | None = None,
    command_history_row_id: str | None = None,
    origin: str | None = None,
    q: str | None = None,
    timestamp: str | None = None,
    parent_depth: int = 3,
    child_depth: int = 2,
    include_activity: bool = True,
    time_window_before: int = 1800,
    time_window_after: int = 1800,
    max_nodes: int = 100,
) -> dict:
    requested_target = _execution_story_requested_target(
        evidence_id=evidence_id,
        host=host,
        pid=pid,
        process_guid=process_guid,
        source_event_id=source_event_id,
        command_history_row_id=command_history_row_id,
        origin=origin,
        q=q,
        timestamp=timestamp,
    )
    auto_focus_reason = _execution_story_focus_reason(
        origin=origin,
        command_history_row_id=command_history_row_id,
        source_event_id=source_event_id,
        process_guid=process_guid,
        pid=pid,
        q=q,
    )
    story_origin = _execution_story_origin(origin, source_event_id=source_event_id, q=q, pid=pid, process_guid=process_guid)
    if source_event_id:
        cache_key = _execution_story_cache_key(
            case.id,
            source_event_id=source_event_id,
            scope=scope,
            evidence_id=evidence_id,
            origin=story_origin,
            command_history_row_id=command_history_row_id,
        )
        cached = _execution_story_cache_get(cache_key)
        if cached:
            return cached
        context = _ProcessTreeContext(
            case=case,
            evidences=evidences,
            export_timestamp=datetime.now(UTC),
            scope=scope,
            evidence_id=evidence_id,
            max_events_per_type=25,
        )
        source_filter = _source_event_filter(source_event_id)
        source_events: list[dict] = []
        if source_filter:
            source_events, _, _ = _search_scope_events(context, size=1, extra_filters=[source_filter])
        source_event = source_events[0] if source_events else None
        target_quality, identity_method, source_confidence = _classify_execution_story_source_event(source_event)
        if target_quality in {"related", "generic"}:
            return _execution_story_cache_put(
                cache_key,
                _light_execution_story_for_generic_event(
                    case,
                    evidences,
                    scope=scope,
                    evidence_id=evidence_id,
                    host=host,
                    source_event_id=source_event_id,
                    source_event=source_event,
                    target_quality=target_quality,
                    identity_method=identity_method,
                    confidence=source_confidence,
                    requested_target=requested_target,
                    auto_focus_reason=auto_focus_reason,
                    origin=story_origin,
                ),
            )
    focused = build_process_tree_focused(
        case,
        evidences,
        scope=scope,
        evidence_id=evidence_id,
        host=host,
        pid=pid,
        process_guid=process_guid,
        source_event_id=source_event_id,
        process_name=q,
        timestamp=timestamp,
        parent_depth=parent_depth,
        child_depth=child_depth,
        include_siblings=True,
        include_activity=include_activity,
        time_window_before=time_window_before,
        time_window_after=time_window_after,
        max_nodes=max_nodes,
    )
    target = focused.get("focus_node")
    parents = focused.get("parents") or []
    children = focused.get("children") or []
    groups = focused.get("activity_groups") or []
    omitted_counts = focused.get("omitted_counts") or {}
    parent_sentence = _parent_sentence_for_story(
        target,
        parents,
        str((focused.get("identity_resolution") or {}).get("parent_explanation") or _parent_explanation_for_node(target)),
    )
    children_sentence = _children_sentence(target, children)
    activity_sentence = _activity_sentence(groups, omitted_counts)
    risk_sentence = _risk_sentence(target, children)
    summary_parts = [parent_sentence, children_sentence, activity_sentence]
    if risk_sentence and not risk_sentence.startswith("No explicit"):
        summary_parts.append(risk_sentence)
    identity = focused.get("identity_resolution") or {}
    exact_story = str(identity.get("method") or "") in {"source_event_id", "process_guid"}
    target_node_id = str((target or {}).get("id") or "") or None
    visual_nodes = focused.get("nodes") or []
    visual_edges = focused.get("edges") or []
    visual_tree_contains_target = not bool(target_node_id) or any(str(node.get("id") or "") == target_node_id for node in visual_nodes)
    warnings = list(focused.get("warnings") or [])
    if exact_story and target_node_id and not visual_tree_contains_target:
        warnings.append("Exact story target missing from visual tree.")
    return {
        "target": target,
        "target_node_id": target_node_id,
        "default_selected_node_id": target_node_id,
        "story": {
            "summary": " ".join(part for part in summary_parts if part),
            "parent_sentence": parent_sentence,
            "children_sentence": children_sentence,
            "activity_sentence": activity_sentence,
            "risk_sentence": risk_sentence,
        },
        "parents": parents,
        "children": children,
        "siblings": focused.get("siblings") or [],
        "activity_groups": {
            "items": groups,
            "omitted_counts": omitted_counts,
        },
        "commands": [],
        "source_events": list(dict.fromkeys((target or {}).get("source_events") or [])),
        "visual_tree": {
            "nodes": visual_nodes,
            "edges": visual_edges,
        },
        "requested_target": requested_target,
        "resolved_target": _execution_story_resolved_target(target),
        "auto_focus_reason": auto_focus_reason,
        "quality": {
            "confidence": str(identity.get("confidence") or "unknown"),
            "missing_parent": bool(target and (target.get("parent_link_status") or "") != "linked"),
            "ambiguous_pid": bool(identity.get("ambiguous_candidates")),
            "warnings": list(dict.fromkeys([warning for warning in warnings if warning])),
            "identity_resolution": identity,
            "exact_story": exact_story,
            "origin": story_origin,
            "filter_scope": "exact_chain" if exact_story else "candidate_search",
            "visual_tree_contains_target": visual_tree_contains_target,
            "target_quality": "exact" if exact_story else "generic",
            "identity_method": str(identity.get("method") or ""),
            "recommended_action": "review_exact_story" if exact_story else "select_candidate",
            "activity_lazy": False,
            "response_mode": "full",
        },
    }
