from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any
from urllib.parse import quote_plus

from sqlalchemy.orm import Session

from app.services.command_history import get_command_history
from app.services.host_identity import normalize_host_alias
from app.services.indicator_resolution import extract_indicators
from app.services.search_service import search_events_v2


SCRIPT_EXT_RE = re.compile(r"\.(?:ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|pif)(?:\s|$|\"|')", re.IGNORECASE)
USER_WRITABLE_RE = re.compile(r"\\(?:users\\[^\\]+\\(?:downloads|desktop|appdata)|users\\public|programdata|temp|windows\\temp)\\", re.IGNORECASE)
STARTUP_FOLDER_RE = re.compile(r"\\start menu\\programs\\startup\\", re.IGNORECASE)
POWERSHELL_FLAG_RE = re.compile(r"(?:-|/)(?:enc|encodedcommand|ep|executionpolicy|nop|noprofile|w|windowstyle)\b|bypass|hidden", re.IGNORECASE)
LOLBIN_RE = re.compile(r"\b(?:rundll32|regsvr32|mshta|wmic|schtasks|powershell|pwsh|cmd|bitsadmin|certutil)\.exe\b", re.IGNORECASE)
DEFENDER_CONFIG_RE = re.compile(r"defender|exclusion|disablerealtimemonitoring|spynetreporting|tamper|realtime", re.IGNORECASE)
CREATE_PERSISTENCE_RE = re.compile(r"\b(?:schtasks\s+/create|sc(?:\.exe)?\s+create|new-service|set-itemproperty|reg(?:\.exe)?\s+add|wmic\s+.*(?:consumer|filter|binding))\b", re.IGNORECASE)
BENIGN_SYSTEM_RE = re.compile(r"\\(?:windows\\system32|windows\\syswow64|program files(?: \(x86\))?)\\", re.IGNORECASE)

SOURCE_QUERIES: list[dict[str, Any]] = [
    {"source": "scheduled_tasks", "artifact_types": ["scheduled_task", "scheduled_tasks", "windows_event"], "queries": ["schtasks", "scheduled task", "TaskCache"], "limit": 40},
    {"source": "services", "artifact_types": ["service", "services", "windows_event", "process"], "queries": ["PSEXESVC", "service control manager", "sc create", "New-Service"], "limit": 40},
    {"source": "autoruns", "artifact_types": ["autoruns", "autorun"], "queries": ["Run", "RunOnce", "Startup"], "limit": 40},
    {"source": "registry_autoruns", "artifact_types": ["registry", "registry_persistence", "windows_event"], "queries": ["RunOnce", "CurrentVersion Run", "Winlogon", "Userinit", "AppInit_DLLs", "IFEO Debugger", "Defender Exclusion"], "limit": 35},
    {"source": "startup_folders", "artifact_types": ["mft", "lnk", "jumplist"], "queries": ["Startup", "Start Menu Programs Startup"], "limit": 35},
    {"source": "wmi", "artifact_types": ["wmi", "windows_event"], "queries": ["EventConsumer", "EventFilter", "CommandLineEventConsumer", "__EventFilter"], "limit": 35},
    {"source": "defender_config", "artifact_types": ["defender", "windows_event"], "queries": ["DisableRealtimeMonitoring", "Exclusion", "SpyNetReporting", "Tamper Defender"], "limit": 35},
]
DEFAULT_SOURCE_NAMES = {"scheduled_tasks", "services"}
TYPE_SOURCE_HINTS = {
    "scheduled_task": {"scheduled_tasks"},
    "service": {"services"},
    "run_key": {"registry_autoruns", "autoruns"},
    "startup_folder": {"startup_folders"},
    "wmi": {"wmi"},
    "defender_config": {"defender_config"},
    "winlogon": {"registry_autoruns"},
    "ifeo": {"registry_autoruns"},
}


def list_startup_persistence_items(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(1, int(params.get("page") or 1))
    page_size = max(1, min(int(params.get("page_size") or 50), 200))
    host_filter = _as_list(params.get("host"))
    type_filter = {str(item).strip().lower() for item in _as_list(params.get("type")) if str(item).strip()}
    source_filter = {str(item).strip().lower() for item in _as_list(params.get("source")) if str(item).strip()}
    q = str(params.get("q") or "").strip()
    suspicious_only = bool(params.get("suspicious_only"))
    risk_min = params.get("risk_min")
    try:
        risk_min_int = int(risk_min) if risk_min is not None and risk_min != "" else None
    except Exception:
        risk_min_int = None
    enabled = params.get("enabled")
    if isinstance(enabled, str):
        enabled_filter: bool | None = enabled.lower() in {"true", "1", "yes"} if enabled.lower() not in {"", "all", "none"} else None
    else:
        enabled_filter = enabled if isinstance(enabled, bool) else None

    fetched: list[dict[str, Any]] = []
    source_errors: list[str] = []
    active_sources = _active_source_names(q, source_filter, type_filter)
    for source in SOURCE_QUERIES:
        source_name = str(source["source"]).lower()
        if source_filter and str(source["source"]).lower() not in source_filter:
            continue
        if source_name not in active_sources:
            continue
        queries = [q] if q else list(source.get("queries") or [])
        per_query_limit = max(10, int(source["limit"]) // max(1, len(queries)))
        for query in queries:
            try:
                total, rows, _warnings, _facets = search_events_v2(
                    case_id,
                    {
                        "q": query,
                        "artifact_type": source["artifact_types"],
                        "host": host_filter,
                        "page_size": per_query_limit,
                        "sort": "risk_desc",
                        "include_facets": False,
                        "include_highlights": False,
                    },
                    db=db,
                )
            except Exception as exc:  # noqa: BLE001
                source_errors.append(f"{source['source']}:{query}: {exc}")
                rows = []
                total = 0
            fetched.extend(_normalize_event_row(case_id, row, str(source["source"])) for row in rows)
            if total > len(rows):
                source_errors.append(f"{source['source']}:{query}: showing first {len(rows)} of {total} source matches")

    if "command_history" in active_sources:
        fetched.extend(_command_history_candidates(case_id, host_filter))

    deduped = _dedupe_items(fetched)
    filtered: list[dict[str, Any]] = []
    for item in deduped:
        if type_filter and str(item.get("type") or "").lower() not in type_filter:
            continue
        if enabled_filter is not None and item.get("enabled") is not enabled_filter:
            continue
        if suspicious_only and int(item.get("risk_score") or 0) < 40:
            continue
        if risk_min_int is not None and int(item.get("risk_score") or 0) < risk_min_int:
            continue
        filtered.append(item)

    filtered.sort(key=lambda item: (-(int(item.get("risk_score") or 0)), str(item.get("host") or ""), str(item.get("last_modified") or item.get("first_seen") or "")))
    start = (page - 1) * page_size
    page_items = filtered[start : start + page_size]
    summary = _summary(filtered)
    return {
        "case_id": case_id,
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "total_pages": (len(filtered) + page_size - 1) // page_size if filtered else 0,
        "items": page_items,
        "summary": summary,
        "warnings": source_errors,
        "wmi_status": "parsed" if summary["by_type"].get("wmi") else "not_present",
    }


def build_startup_persistence_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    result = list_startup_persistence_items(
        db,
        case_id,
        {
            "host": filters.get("host"),
            "evidence_id": filters.get("evidence_id"),
            "page_size": int(filters.get("max_persistence_items") or 25),
            "suspicious_only": True,
        },
    )
    return {"items": result["items"], "counts": result["summary"], "warnings": result.get("warnings") or []}


def render_startup_persistence_markdown(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No suspicious startup or persistence items matched the report filters."
    rows = [["Host", "Type", "Name", "Risk", "Command / Target", "Evidence"]]
    for item in items[:50]:
        rows.append(
            [
                str(item.get("host") or "-"),
                str(item.get("type") or "-"),
                str(item.get("name") or "-"),
                str(item.get("risk_score") or 0),
                _clip(str(item.get("command_or_target") or item.get("path") or "-"), 120),
                str(item.get("source_artifact") or "-"),
            ]
        )
    return _markdown_table(rows)


def _normalize_event_row(case_id: str, row: dict[str, Any], source: str) -> dict[str, Any]:
    artifact = _obj(row.get("artifact"))
    event = _obj(row.get("event"))
    task = _obj(row.get("task"))
    service = _obj(row.get("service"))
    persistence = _obj(row.get("persistence"))
    autoruns = _obj(row.get("autoruns"))
    wmi = _obj(row.get("wmi"))
    defender = _obj(row.get("defender") or row.get("detection"))
    file = _obj(row.get("file"))
    process = _obj(row.get("process"))
    user = _obj(row.get("user"))
    windows = _obj(row.get("windows"))
    registry = _obj(row.get("registry"))
    raw = _obj(row.get("raw"))
    source_doc = _obj(raw.get("raw"))
    if not registry:
        registry = _obj(source_doc.get("registry"))
    if not persistence:
        persistence = _obj(source_doc.get("persistence"))
    if not user:
        user = _obj(source_doc.get("user"))
    artifact_type = str(artifact.get("type") or row.get("artifact_type") or "").lower()
    text = " ".join(
        str(value or "")
        for value in (
            task.get("command"),
            task.get("arguments"),
            service.get("image_path"),
            service.get("path"),
            registry.get("value_data"),
            registry.get("value_data_summary"),
            registry.get("key_path"),
            persistence.get("command"),
            persistence.get("path"),
            autoruns.get("image_path"),
            autoruns.get("command_line"),
            wmi.get("command_line_template"),
            wmi.get("script_preview"),
            defender.get("path"),
            process.get("command_line"),
            file.get("path"),
            event.get("message"),
            row.get("summary"),
        )
    )
    item_type = _classify_type(source, artifact_type, row, text)
    name = _first(
        persistence.get("name"),
        registry.get("value_name"),
        registry.get("persistence_mechanism"),
        autoruns.get("entry"),
        task.get("name"),
        task.get("path"),
        service.get("name"),
        service.get("display_name"),
        wmi.get("consumer_name"),
        wmi.get("filter_name"),
        defender.get("threat_name"),
        windows.get("service_name"),
        file.get("name"),
        event.get("action"),
    )
    command = _first(
        persistence.get("command"),
        registry.get("value_data"),
        autoruns.get("command_line"),
        autoruns.get("launch_string"),
        task.get("command"),
        task.get("action"),
        service.get("image_path"),
        service.get("path"),
        wmi.get("command_line_template"),
        wmi.get("script_preview"),
        defender.get("path"),
        process.get("command_line"),
        file.get("path"),
    )
    path = _first(persistence.get("path"), registry.get("value_data"), autoruns.get("image_path"), task.get("path"), service.get("image_path"), service.get("path"), file.get("path"))
    enabled = _bool_or_none(_first(task.get("enabled"), autoruns.get("enabled"), persistence.get("enabled")))
    risk_score, risk_reasons = _score_item(item_type, text, path, name, source)
    host = normalize_host_alias(str(_obj(row.get("host")).get("name") or row.get("host") or ""))
    indicators = extract_indicators({"source": {"name": name, "command_or_target": command, "path": path}}).get("indicators") or []
    source_event_id = str(row.get("id") or raw.get("stable_event_id") or "")
    return {
        "id": _stable_id(case_id, source, source_event_id or name or command or path),
        "case_id": case_id,
        "evidence_id": row.get("evidence_id") or source_doc.get("evidence_id"),
        "host": host,
        "type": item_type,
        "name": name or "-",
        "command_or_target": command or "-",
        "path": path or "",
        "user": _first(user.get("name"), user.get("sid"), task.get("run_as"), task.get("user_id"), autoruns.get("user"), persistence.get("user")) or "",
        "enabled": enabled,
        "start_type": _first(service.get("start_type"), service.get("start_mode"), persistence.get("start_type")) or "",
        "trigger": _first(task.get("trigger_summary"), task.get("trigger"), persistence.get("trigger")) or "",
        "source_artifact": "registry_hive" if artifact_type == "registry_persistence" else source,
        "source_event_id": source_event_id,
        "first_seen": row.get("@timestamp") or row.get("timestamp"),
        "last_modified": _first(registry.get("last_write"), file.get("modified"), task.get("modified"), persistence.get("last_modified"), row.get("@timestamp")),
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "indicator_resolution": indicators[:10],
        "related_events": [source_event_id] if source_event_id else [],
        "confidence": "high" if source_event_id else "medium",
        "search_url": _search_url(case_id, host, command or path or name),
        "timeline_url": _timeline_url(case_id, host, row.get("@timestamp") or row.get("timestamp"), command or path or name),
        "raw": row,
    }


def _command_history_candidates(case_id: str, host_filter: list[str]) -> list[dict[str, Any]]:
    terms = ["schtasks /create", "sc create", "New-Service", "Set-ItemProperty", "reg add", "wmic eventconsumer", "DisableRealtimeMonitoring"]
    output: list[dict[str, Any]] = []
    for term in terms:
        try:
            result = get_command_history(case_id, {"q": term, "host": host_filter[0] if len(host_filter) == 1 else None, "page_size": 20, "sort": "risk_desc"})
        except Exception:
            continue
        for command in result.get("items") or []:
            output.append(_normalize_command(case_id, command, term))
    return output


def _normalize_command(case_id: str, command: dict[str, Any], term: str) -> dict[str, Any]:
    command_text = str(command.get("command") or command.get("command_line") or "")
    host = normalize_host_alias(str(command.get("host") or ""))
    risk_score, risk_reasons = _score_item("unknown", command_text, "", term, "command_history")
    source_event = _first(*[event.get("id") for event in command.get("supporting_events") or [] if isinstance(event, dict)])
    return {
        "id": _stable_id(case_id, "command_history", command.get("id") or command_text),
        "case_id": case_id,
        "evidence_id": command.get("evidence_id"),
        "host": host,
        "type": _classify_command_type(command_text),
        "name": term,
        "command_or_target": command_text,
        "path": "",
        "user": str(command.get("user") or ""),
        "enabled": None,
        "start_type": "",
        "trigger": "",
        "source_artifact": "command_history",
        "source_event_id": source_event or "",
        "first_seen": command.get("timestamp"),
        "last_modified": command.get("timestamp"),
        "risk_score": risk_score,
        "risk_reasons": ["creation_command", *[reason for reason in risk_reasons if reason != "creation_command"]],
        "indicator_resolution": (extract_indicators({"source": {"command": command_text}}).get("indicators") or [])[:10],
        "related_events": [source_event] if source_event else [],
        "confidence": "medium",
        "search_url": _search_url(case_id, host, command_text),
        "timeline_url": _timeline_url(case_id, host, command.get("timestamp"), command_text),
        "raw": command,
    }


def _classify_type(source: str, artifact_type: str, row: dict[str, Any], text: str) -> str:
    lowered = f"{source} {artifact_type} {text}".lower()
    if artifact_type == "registry_persistence":
        category = str(_obj(row.get("registry")).get("category") or "").lower()
        if category in {"autorun", "service", "winlogon", "ifeo", "defender_exclusion", "rdp", "task_cache", "active_setup"}:
            return "run_key" if category == "autorun" else "defender_config" if category == "defender_exclusion" else "scheduled_task" if category == "task_cache" else category
    if "defender" in lowered and DEFENDER_CONFIG_RE.search(lowered):
        return "defender_config"
    if "wmi" in lowered or "eventconsumer" in lowered or "__eventfilter" in lowered:
        return "wmi"
    if "winlogon" in lowered:
        return "winlogon"
    if "image file execution options" in lowered or "ifeo" in lowered or "\\debugger" in lowered:
        return "ifeo"
    if STARTUP_FOLDER_RE.search(text):
        return "startup_folder"
    if "runonce" in lowered or "\\run" in lowered or "currentversion\\\\run" in lowered:
        return "run_key"
    if artifact_type in {"scheduled_task", "scheduled_tasks"} or "scheduled" in lowered:
        return "scheduled_task"
    if artifact_type in {"service", "services"} or "service" in lowered:
        return "service"
    return "unknown"


def _classify_command_type(command: str) -> str:
    lowered = command.lower()
    if "schtasks" in lowered:
        return "scheduled_task"
    if "sc create" in lowered or "new-service" in lowered:
        return "service"
    if "wmic" in lowered and any(token in lowered for token in ("eventconsumer", "eventfilter", "binding")):
        return "wmi"
    if "reg add" in lowered or "set-itemproperty" in lowered:
        return "run_key"
    return "unknown"


def _score_item(item_type: str, text: str, path: str | None, name: str | None, source: str) -> tuple[int, list[str]]:
    haystack = " ".join(str(part or "") for part in (text, path, name, source))
    reasons: list[str] = []
    score = 10
    if item_type in {"scheduled_task", "service", "run_key", "startup_folder", "wmi", "winlogon", "ifeo", "powershell_profile"}:
        score += 15
        reasons.append(f"{item_type}_mechanism")
    if USER_WRITABLE_RE.search(haystack):
        score += 30
        reasons.append("user_writable_path")
    if STARTUP_FOLDER_RE.search(haystack):
        score += 25
        reasons.append("startup_folder")
    if SCRIPT_EXT_RE.search(haystack):
        score += 25
        reasons.append("script_or_suspicious_extension")
    if POWERSHELL_FLAG_RE.search(haystack):
        score += 30
        reasons.append("suspicious_powershell_flags")
    if LOLBIN_RE.search(haystack):
        score += 20
        reasons.append("lolbin_or_script_launcher")
    if DEFENDER_CONFIG_RE.search(haystack) and item_type == "defender_config":
        score += 35
        reasons.append("defender_configuration_change")
    if CREATE_PERSISTENCE_RE.search(haystack):
        score += 30
        reasons.append("creation_command")
    if BENIGN_SYSTEM_RE.search(haystack) and not any(reason in reasons for reason in {"suspicious_powershell_flags", "user_writable_path", "defender_configuration_change", "creation_command"}):
        score = min(score, 20)
        reasons.append("common_system_location")
    if not reasons:
        reasons.append("persistence_candidate")
    return min(score, 100), reasons


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(str(item.get(part) or "").lower() for part in ("host", "type", "name", "command_or_target", "source_event_id"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(items),
        "suspicious": sum(1 for item in items if int(item.get("risk_score") or 0) >= 40),
        "by_host": dict(Counter(str(item.get("host") or "unknown") for item in items)),
        "by_type": dict(Counter(str(item.get("type") or "unknown") for item in items)),
        "by_source": dict(Counter(str(item.get("source_artifact") or "unknown") for item in items)),
        "high_risk": sum(1 for item in items if int(item.get("risk_score") or 0) >= 70),
    }


def _active_source_names(q: str, source_filter: set[str], type_filter: set[str]) -> set[str]:
    if source_filter:
        return set(source_filter)
    if q:
        return {str(source["source"]).lower() for source in SOURCE_QUERIES} | {"command_history"}
    if type_filter:
        names: set[str] = set()
        for item_type in type_filter:
            names.update(TYPE_SOURCE_HINTS.get(item_type, set()))
        return names or set(DEFAULT_SOURCE_NAMES)
    return set(DEFAULT_SOURCE_NAMES)


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    lowered = str(value).strip().lower()
    if lowered in {"true", "1", "yes", "enabled"}:
        return True
    if lowered in {"false", "0", "no", "disabled"}:
        return False
    return None


def _stable_id(case_id: str, source: str, value: Any) -> str:
    material = f"{case_id}|{source}|{value}"
    return "persist-" + hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _search_url(case_id: str, host: str, query: str) -> str:
    params = []
    if host:
        params.append(f"host={quote_plus(host)}")
    if query:
        params.append(f"q={quote_plus(_clip(query, 180))}")
    return f"/cases/{case_id}/search" + (f"?{'&'.join(params)}" if params else "")


def _timeline_url(case_id: str, host: str, timestamp: Any, query: str) -> str:
    params = ["view=timeline"]
    if host:
        params.append(f"host={quote_plus(host)}")
    if query:
        params.append(f"q={quote_plus(_clip(str(query), 180))}")
    if timestamp:
        params.append(f"timestamp={quote_plus(str(timestamp))}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _markdown_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = rows[0]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for row in rows[1:]:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in row) + " |")
    return "\n".join(lines)
