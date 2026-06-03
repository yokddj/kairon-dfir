from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote_plus

from sqlalchemy.orm import Session

from app.core.opensearch import get_events_index, get_opensearch_client, index_exists
from app.services.command_history import get_command_history
from app.services.search_service import search_events_v2


FILE_EXTENSIONS = (
    "exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|iso|zip|7z|rar|cab|msi|scr|pif|txt|doc|docx|xls|xlsx|xlsm|pdf|kdbx|encrypted|ini|dat|xml|sys"
)
COMMON_WORDS = {
    "the",
    "and",
    "that",
    "this",
    "with",
    "from",
    "into",
    "story",
    "timeline",
    "evidence",
    "activity",
    "investigation",
}

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?!(?:exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|iso|zip|rar|txt|docx?|xlsx?|pdf)\b)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
REGISTRY_RE = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n\"']+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z]:\\[^\s\"'<>|]+|\\\\[^\s\"'<>|]+|\.{1,2}\\[^\s\"'<>|]+)",
    re.IGNORECASE,
)
FILE_NAME_RE = re.compile(rf"(?<![A-Za-z0-9_])([A-Za-z0-9_.$%{{}}()~@!#^+=,\-]+?\.(?:{FILE_EXTENSIONS})(?::Zone\.Identifier)?)(?![A-Za-z0-9_])", re.IGNORECASE)
USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.@$-]+\b")
SERVICE_RE = re.compile(r"\b[A-Za-z0-9_.-]*(?:svc|service|task)[A-Za-z0-9_.-]*\b", re.IGNORECASE)


def extract_indicators(payload: dict[str, Any]) -> dict[str, Any]:
    context = dict(payload.get("context") or {})
    fields = _collect_fields(payload.get("source") if "source" in payload else payload)
    indicators: list[dict[str, Any]] = []
    for source_field, value in fields:
        indicators.extend(_extract_from_field(source_field, str(value or "")))
    return {"indicators": _dedupe_indicators(indicators), "context": context}


def resolve_indicators(db: Session, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    context = dict(payload.get("context") or {})
    raw_indicators = payload.get("indicators")
    if raw_indicators is None:
        raw_indicators = extract_indicators(payload).get("indicators") or []
    indicators = [_normalize_indicator(item) for item in raw_indicators if item]
    results = [_resolve_indicator(db, case_id, item, context) for item in indicators]
    return {"case_id": case_id, "indicators": indicators, "results": results}


def extract_and_resolve_indicators(db: Session, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    extracted = extract_indicators(payload)
    return resolve_indicators(db, case_id, {**payload, "indicators": extracted["indicators"]})


def _collect_fields(source: Any, prefix: str = "") -> list[tuple[str, Any]]:
    fields: list[tuple[str, Any]] = []
    if isinstance(source, dict):
        for key, value in source.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                fields.extend(_collect_fields(value, name))
            elif value is not None:
                fields.append((name, value))
    elif isinstance(source, list):
        for idx, value in enumerate(source):
            fields.extend(_collect_fields(value, f"{prefix}[{idx}]"))
    elif source is not None:
        fields.append((prefix or "text", source))
    return fields


def _extract_from_field(source_field: str, text: str) -> list[dict[str, Any]]:
    if not text or len(text) > 20000:
        return []
    field_lower = source_field.lower()
    confidence = "high" if any(token in field_lower for token in ("command", "path", "name", "url", "domain", "indicator", "file", "process", "registry", "user", "service", "task")) else "medium"
    output: list[dict[str, Any]] = []
    for match in URL_RE.findall(text):
        output.append(_indicator(match.rstrip(".,);]"), "url", source_field, confidence))
    for match in EMAIL_RE.findall(text):
        output.append(_indicator(match, "email", source_field, confidence))
    for match in HASH_RE.findall(text):
        subtype = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(match), "hash")
        output.append(_indicator(match.lower(), "hash", source_field, confidence, subtype=subtype))
    for match in IP_RE.findall(text):
        try:
            ip_address(match)
            output.append(_indicator(match, "ip", source_field, confidence))
        except ValueError:
            pass
    for match in REGISTRY_RE.findall(text):
        output.append(_indicator(match.rstrip(".,);]"), "registry", source_field, confidence))
    for match in WINDOWS_PATH_RE.findall(text):
        cleaned = _clean_token(match)
        if _looks_like_file(cleaned):
            output.append(_indicator(cleaned, "path", source_field, confidence, subtype="windows_path"))
    for match in FILE_NAME_RE.findall(text):
        cleaned = _clean_token(match)
        if _valid_file_name(cleaned):
            output.append(_indicator(cleaned, "file", source_field, confidence))
    for match in DOMAIN_RE.findall(text):
        cleaned = match.lower().rstrip(".")
        if not _looks_like_file(cleaned):
            output.append(_indicator(cleaned, "domain", source_field, "medium"))
    for match in USER_RE.findall(text):
        output.append(_indicator(match, "user", source_field, confidence))
    for match in SERVICE_RE.findall(text):
        cleaned = _clean_token(match)
        if len(cleaned) >= 5 and "." not in cleaned.lower():
            output.append(_indicator(cleaned, "service", source_field, "medium"))
    if "command" in field_lower and len(text.strip()) > 8:
        output.append(_indicator(text.strip(), "command", source_field, "high"))
    return output


def _indicator(value: str, type_: str, source_field: str, confidence: str, *, subtype: str = "") -> dict[str, Any]:
    normalized = _normalize_value(value, type_)
    return {
        "indicator": value,
        "type": type_,
        "subtype": subtype,
        "source_field": source_field,
        "confidence": confidence,
        "normalized": normalized,
        "display": value,
    }


def _dedupe_indicators(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        normalized = str(item.get("normalized") or "").strip()
        type_ = str(item.get("type") or "unknown")
        if not normalized or (type_, normalized) in seen:
            continue
        seen.add((type_, normalized))
        output.append(item)
    return output[:100]


def _normalize_indicator(item: Any) -> dict[str, Any]:
    if isinstance(item, str):
        guessed = _extract_from_field("indicator", item)
        return guessed[0] if guessed else _indicator(item, "unknown", "indicator", "low")
    row = dict(item)
    row.setdefault("indicator", row.get("display") or row.get("normalized") or "")
    row.setdefault("type", "unknown")
    row.setdefault("source_field", "indicator")
    row.setdefault("confidence", "medium")
    row.setdefault("normalized", _normalize_value(str(row.get("indicator") or ""), str(row.get("type") or "unknown")))
    row.setdefault("display", row.get("indicator"))
    row.setdefault("subtype", "")
    return row


def _resolve_indicator(db: Session, case_id: str, indicator: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    value = str(indicator.get("indicator") or indicator.get("normalized") or "").strip()
    type_ = str(indicator.get("type") or "unknown")
    host = str(context.get("host") or "").strip() or None
    evidence_id = str(context.get("evidence_id") or "").strip() or None
    timestamp = str(context.get("timestamp") or "").strip() or None
    counts: dict[str, int] = {}

    if type_ in {"file", "path"}:
        counts["mft"] = _exact_file_count(case_id, value, evidence_id=evidence_id, host=host)
        counts["motw"] = _motw_count(db, case_id, value, evidence_id=evidence_id, host=host)
        counts["user_activity"] = _event_count(db, case_id, value, ["recentdocs", "opensavemru", "userassist", "lnk", "jumplist"], evidence_id, host)
        counts["browser"] = _event_count(db, case_id, value, ["browser", "browser_download"], evidence_id, host)
        counts["defender"] = _event_count(db, case_id, value, ["defender"], evidence_id, host)
        counts["windows_event"] = _event_count(db, case_id, value, ["windows_event"], evidence_id, host)
        counts["command_history"] = _command_count(case_id, value, evidence_id=evidence_id, host=host)
        status = "found" if any(counts.get(src, 0) > 0 for src in ("mft", "motw", "user_activity", "browser", "defender")) else "command_only" if counts.get("command_history", 0) or counts.get("windows_event", 0) else "referenced_not_found"
    elif type_ in {"url", "domain", "ip"}:
        counts["browser"] = _event_count(db, case_id, value, ["browser", "browser_download"], evidence_id, host)
        counts["dns_network"] = _event_count(db, case_id, value, ["dns", "network", "windows_event"], evidence_id, host)
        counts["defender"] = _event_count(db, case_id, value, ["defender"], evidence_id, host)
        counts["command_history"] = _command_count(case_id, value, evidence_id=evidence_id, host=host)
        status = "found" if sum(counts.values()) else "not_found"
    elif type_ == "command":
        counts["command_history"] = _command_count(case_id, value, evidence_id=evidence_id, host=host)
        counts["windows_event"] = _event_count(db, case_id, value, ["windows_event", "powershell"], evidence_id, host)
        status = "found" if sum(counts.values()) else "not_found"
    elif type_ in {"registry", "service", "task", "user", "email", "hash"}:
        counts["search"] = _event_count(db, case_id, value, None, evidence_id, host)
        counts["command_history"] = _command_count(case_id, value, evidence_id=evidence_id, host=host) if type_ in {"user", "service", "task"} else 0
        status = "found" if sum(counts.values()) else "not_found"
    else:
        counts["search"] = _event_count(db, case_id, value, None, evidence_id, host)
        status = "found" if counts["search"] else "not_supported"

    sources_found = [source for source, count in counts.items() if count > 0]
    first_seen, last_seen = _time_bounds(case_id, value, evidence_id=evidence_id, host=host)
    if status == "found" and len(sources_found) == 1 and sources_found[0] in {"command_history", "windows_event"} and type_ in {"file", "path"}:
        status = "command_only"
    return {
        "indicator": value,
        "type": type_,
        "status": status,
        "sources_found": sources_found,
        "counts_by_source": counts,
        "hosts": [host] if host else [],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "evidence_ids": [evidence_id] if evidence_id else [],
        "confidence": _resolution_confidence(status, counts),
        "explanation": _resolution_explanation(status, type_, value, counts),
        "suggested_pivots": _pivots(case_id, indicator, context, first_seen),
    }


def _event_count(db: Session, case_id: str, query: str, artifact_types: list[str] | None, evidence_id: str | None, host: str | None) -> int:
    params: dict[str, Any] = {
        "q": query,
        "scope": "events",
        "page_size": 25,
        "include_facets": False,
        "include_highlights": False,
    }
    if artifact_types:
        params["artifact_type"] = artifact_types
    if evidence_id:
        params["evidence_id"] = evidence_id
    if host:
        params["host"] = host
    try:
        total, rows, _warnings, _facets = search_events_v2(case_id, params, db=db)
    except Exception:
        return 0
    if artifact_types and len(rows) < total and query:
        # Keep broad totals for non-file sources, but avoid over-counting exact file
        # presence from tokenized text fields.
        return int(total or 0)
    return int(total or 0)


def _command_count(case_id: str, query: str, *, evidence_id: str | None, host: str | None) -> int:
    try:
        result = get_command_history(case_id, {"q": query, "evidence_id": evidence_id, "host": host, "page_size": 1})
        return int(result.get("total") or 0)
    except Exception:
        return 0


def _motw_count(db: Session, case_id: str, query: str, *, evidence_id: str | None, host: str | None) -> int:
    if ":zone.identifier" not in str(query or "").lower():
        return 0
    try:
        total, _rows, _warnings, _facets = search_events_v2(
            case_id,
            {
                "q": query,
                "scope": "events",
                "artifact_type": ["mft", "windows_event", "sysmon"],
                "evidence_id": evidence_id,
                "host": host,
                "page_size": 1,
                "include_facets": False,
                "include_highlights": False,
            },
            db=db,
        )
        return int(total or 0)
    except Exception:
        return 0


def _exact_file_count(case_id: str, value: str, *, evidence_id: str | None, host: str | None) -> int:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return 0
    basename = _basename(value)
    possible_paths = {value}
    if value.startswith(".\\"):
        possible_paths.add(value)
    filters: list[dict[str, Any]] = [{"term": {"artifact.type": "mft"}}]
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    if host:
        filters.append({"term": {"host.name": host}})
    should: list[dict[str, Any]] = []
    if basename:
        should.append({"term": {"file.name": basename}})
    for path in possible_paths:
        should.append({"term": {"file.path": path}})
    try:
        response = client.count(index=index, body={"query": {"bool": {"filter": filters, "should": should, "minimum_should_match": 1}}})
        return int(response.get("count") or 0)
    except Exception:
        return 0


def _time_bounds(case_id: str, query: str, *, evidence_id: str | None, host: str | None) -> tuple[str | None, str | None]:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return None, None
    filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}]
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    if host:
        filters.append({"term": {"host.name": host}})
    body = {
        "size": 0,
        "query": {"bool": {"filter": filters, "must": [{"simple_query_string": {"query": query, "fields": ["search_text", "summary", "message", "file.path", "process.command_line", "command"], "default_operator": "and"}}]}},
        "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}},
    }
    try:
        response = client.search(index=index, body=body)
        first = (response.get("aggregations") or {}).get("first", {}).get("value_as_string")
        last = (response.get("aggregations") or {}).get("last", {}).get("value_as_string")
        return first, last
    except Exception:
        return None, None


def _pivots(case_id: str, indicator: dict[str, Any], context: dict[str, Any], first_seen: str | None) -> list[dict[str, str]]:
    value = str(indicator.get("indicator") or "")
    type_ = str(indicator.get("type") or "unknown")
    host = str(context.get("host") or "").strip()
    base_params = []
    if host:
        base_params.append(f"host={quote_plus(host)}")
    if value:
        base_params.append(f"q={quote_plus(value)}")
    search_url = f"/cases/{case_id}/search" + (f"?{'&'.join(base_params)}" if base_params else "")
    pivots = [{"label": "Search exact indicator", "url": search_url, "type": "search"}]
    if type_ in {"file", "path"}:
        pivots = [
            {"label": "Find this file", "url": search_url, "type": "file"},
            {"label": "Open File Story", "url": search_url, "type": "file_story"},
            {"label": "Open Artifact View", "url": f"/cases/{case_id}/artifacts" + (f"?host={quote_plus(host)}" if host else ""), "type": "artifact"},
            {"label": "Search command references", "url": search_url, "type": "command"},
        ]
    elif type_ in {"url", "domain", "ip"}:
        pivots = [{"label": "Search network/DNS/browser", "url": search_url, "type": "network"}, {"label": "Add to finding", "url": search_url, "type": "finding"}]
    elif type_ == "command":
        pivots = [{"label": "Open Command History", "url": f"/cases/{case_id}/command-history?{('&'.join(base_params))}", "type": "command"}, {"label": "Search exact command", "url": search_url, "type": "search"}]
    elif type_ in {"registry", "service", "task", "user"}:
        pivots = [{"label": f"Search {type_} activity", "url": search_url, "type": type_}]
    if first_seen:
        around_params = ["view=timeline", *base_params]
        window = _around_window(first_seen)
        if window:
            around_params.extend(window)
        pivots.append({"label": "View activity around first seen", "url": f"/cases/{case_id}/search?{'&'.join(around_params)}", "type": "timeline"})
    return pivots


def _around_window(timestamp: str) -> list[str]:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        delta = timedelta(minutes=5)
        return [f"time_from={(parsed - delta).isoformat()}", f"time_to={(parsed + delta).isoformat()}"]
    except Exception:
        return []


def _resolution_confidence(status: str, counts: dict[str, int]) -> str:
    if status == "found" and sum(1 for count in counts.values() if count > 0) > 1:
        return "high"
    if status in {"found", "command_only"}:
        return "medium"
    return "low"


def _resolution_explanation(status: str, type_: str, value: str, counts: dict[str, int]) -> str:
    if status == "found":
        return f"{value} was found in indexed evidence sources: {', '.join(source for source, count in counts.items() if count > 0)}."
    if status == "command_only":
        return f"{value} is referenced by commands/logs, but no exact filesystem artifact was confirmed. It may be relative, inside mounted media/container, temporary, deleted, or outside indexed evidence."
    if status == "referenced_not_found":
        return f"{value} was extracted as an indicator, but no matching indexed evidence was found. Absence is reported without claiming the artifact exists."
    if status == "not_supported":
        return f"{type_} indicators are extracted, but this resolver has limited source-specific support for this type."
    return f"{value} was not found in indexed evidence for the current scope."


def _normalize_value(value: str, type_: str) -> str:
    value = _clean_token(value)
    if type_ in {"domain", "email", "hash"}:
        return value.lower()
    return value


def _clean_token(value: str) -> str:
    return str(value or "").strip().strip("\"'`,;()[]{}<>")


def _looks_like_file(value: str) -> bool:
    return bool(re.search(rf"\.(?:{FILE_EXTENSIONS})(?::Zone\.Identifier)?$", value, re.IGNORECASE))


def _valid_file_name(value: str) -> bool:
    stem = value.split(":", 1)[0].rsplit(".", 1)[0].lower()
    return bool(stem and stem not in COMMON_WORDS and len(value) <= 260)


def _basename(value: str) -> str:
    return _clean_token(value).split("\\")[-1].split("/")[-1]
