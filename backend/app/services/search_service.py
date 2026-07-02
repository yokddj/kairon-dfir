from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from dateutil import parser as date_parser
from fastapi import HTTPException
from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.opensearch import fetch_event_by_id, get_events_index, get_opensearch_client, index_exists
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.event_markings import event_marking_filter_ids, marking_map_for_events, serialize_marking
from app.services.host_identity import expand_host_filter, is_invalid_host_value, normalize_host_alias, resolve_canonical_host
from app.services.investigation_memory import (
    add_event_source_provenance,
    memory_search_results,
    normalize_source_category,
    wants_memory_source,
    wants_non_memory_source,
)
from app.search.query_syntax import QuerySyntaxError, SEARCH_SYNTAX_EXAMPLES, analyze_query_syntax, evaluate_query_syntax


IOC_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
IOC_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IOC_SID_RE = re.compile(r"^S-\d-\d+(?:-\d+)+$", re.IGNORECASE)
IOC_GUID_RE = re.compile(r"^\{?[0-9a-fA-F]{8}\-(?:[0-9a-fA-F]{4}\-){3}[0-9a-fA-F]{12}\}?$")
IOC_FILENAME_RE = re.compile(r"^[^\\/:\n\r\t]+\.[A-Za-z0-9]{1,8}$")
IOC_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
IOC_REGISTRY_RE = re.compile(r"^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\", re.IGNORECASE)
IOC_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
IOC_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
WINDOW_RE = re.compile(r"^(?P<amount>\d+)\s*(?P<unit>[mhd])$", re.IGNORECASE)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+")
SEARCH_REQUEST_TIMEOUT_SECONDS = 8
MAX_REASONABLE_FUTURE_TIMESTAMP_SKEW = timedelta(days=366)
MIN_REASONABLE_TIMESTAMP = datetime(1990, 1, 1, tzinfo=UTC)

TEXT_FIELDS = [
    "search_text",
    "event.message",
    "raw_summary",
    "artifact.name",
    "source_file",
    "process.command_line",
    "object.name",
    "object.path",
    "access.mask",
    "access.reason",
    "file.path",
    "file.name",
    "browser.url",
    "browser.domain",
    "download.target_path",
    "download.file_name",
    "url.full",
    "url.domain",
    "dns.domain",
    "dns.query",
    "dns.question.name",
    "network.domain",
    "registry.key_path",
    "registry.path",
    "registry.value_name",
    "registry.value_data",
    "registry.data",
    "autoruns.command_line",
    "autoruns.entry_location",
    "suspicious_reasons",
    "tags",
    "detection.threat_name",
    "detection.path",
    "detection.action",
    "detection.status",
    "srum.app_name",
    "srum.application",
    "srum.app_id",
    "srum.user_sid",
    "srum.table",
    "network.application",
]
GENERIC_WILDCARD_TEXT_FIELDS = [
    "search_text.wildcard",
    "file.path",
    "file.name",
    "detection.threat_name",
    "detection.path",
    "detection.resource",
    "srum.app_name",
    "srum.application",
    "network.application",
]
COMMAND_QUERY_WILDCARD_FIELDS = [
    "search_text.wildcard",
    "process.command_line",
    "event.message",
    "raw_summary",
    "file.path",
    "file.name",
    "object.name",
    "defender.path",
    "detection.path",
    "powershell.command",
    "powershell.command_preview",
    "task.command",
]
FILTER_BUILDER_TEXT_FIELDS = {
    "message": ["event.message", "raw_summary", "search_text"],
    "content": ["event.message", "raw_summary", "search_text", "process.command_line", "file.path", "source_file"],
    "title": ["event.message", "raw_summary", "artifact.name"],
    "summary": ["event.message", "raw_summary", "search_text"],
}
FILTER_BUILDER_FIELD_MAP = {
    "artifact.type": {"field": "artifact.type", "kind": "term", "expand": "artifact_type"},
    "artifact.parser": {"field": "artifact.parser", "kind": "term"},
    "source_file": {"field": "source_file", "kind": "wildcard"},
    "host.name": {"field": "host.name", "kind": "host"},
    "user.name": {"field": "user.name", "kind": "term"},
    "event.type": {"field": "event.type", "kind": "term"},
    "event.action": {"field": "event.action", "kind": "term"},
    "event.id": {"field": "event_id", "kind": "term"},
    "windows.event_id": {"field": "windows.event_id", "kind": "number"},
    "process.name": {"field": "process.name", "kind": "wildcard"},
    "process.pid": {"field": "process.pid", "kind": "number"},
    "process.entity_id": {"fields": ["process.entity_id", "process.guid"], "kind": "wildcard_multi"},
    "process.command_line": {"field": "process.command_line", "kind": "wildcard"},
    "parent.process.name": {"fields": ["process.parent_name", "process.parent.name"], "kind": "wildcard_multi"},
    "parent.process.pid": {"fields": ["process.parent_pid", "process.parent.pid"], "kind": "wildcard_multi"},
    "parent.process.command_line": {"fields": ["process.parent_command_line", "process.parent.command_line"], "kind": "wildcard_multi"},
    "event.provider": {"fields": ["event.provider", "windows.provider"], "kind": "wildcard_multi"},
    "event.channel": {"fields": ["event.channel", "windows.channel"], "kind": "wildcard_multi"},
    "source.ip": {"field": "source.ip", "kind": "term"},
    "destination.ip": {"field": "destination.ip", "kind": "term"},
    "source.port": {"field": "source.port", "kind": "number"},
    "destination.port": {"field": "destination.port", "kind": "number"},
    "object.name": {"fields": ["object.name", "object.path"], "kind": "wildcard_multi"},
    "object.path": {"fields": ["object.path", "object.name"], "kind": "wildcard_multi"},
    "access.mask": {"field": "access.mask", "kind": "term"},
    "access.list": {"fields": ["access.list", "access.accesses"], "kind": "wildcard_multi"},
    "file.path": {"field": "file.path", "kind": "wildcard"},
    "registry.key": {"fields": ["registry.key", "registry.key_path", "registry.path"], "kind": "wildcard_multi"},
    "registry.path": {"fields": ["registry.path", "registry.key_path"], "kind": "wildcard_multi"},
    "registry.data": {"fields": ["registry.data", "registry.value_data"], "kind": "wildcard_multi"},
    "dns.question.name": {"fields": ["dns.question.name", "dns.query", "dns.domain"], "kind": "wildcard_multi"},
    "url.full": {"fields": ["url.full", "browser.url", "download.url"], "kind": "wildcard_multi"},
    "url.domain": {"fields": ["url.domain", "browser.domain", "dns.domain", "dns.question.name", "dns.query"], "kind": "wildcard_multi"},
    "threat.name": {"fields": ["threat.name", "detection.threat_name", "defender.threat_name"], "kind": "wildcard_multi"},
    "threat.id": {"fields": ["threat.id", "detection.threat_id", "defender.threat_id"], "kind": "wildcard_multi"},
    "defender.action": {"fields": ["defender.action", "detection.action", "event.action"], "kind": "wildcard_multi"},
    "defender.severity": {"fields": ["defender.severity", "detection.severity", "event.severity"], "kind": "wildcard_multi"},
    "defender.path": {"fields": ["defender.path", "detection.path", "file.path"], "kind": "wildcard_multi"},
    "srum.app": {"fields": ["srum.app_name", "srum.application", "network.application", "process.name"], "kind": "wildcard_multi"},
    "srum.table": {"field": "srum.table", "kind": "wildcard"},
    "srum.user_sid": {"fields": ["srum.user_sid", "user.sid"], "kind": "wildcard_multi"},
    "network.bytes": {"field": "network.bytes_total", "kind": "number"},
}
FILTER_BUILDER_OPERATORS = {"is", "is not", "contains", "does not contain", "exists", "does not exist", "starts with"}
HIGHLIGHT_FIELDS = {
    "search_text": {},
    "event.message": {},
    "raw_summary": {},
    "file.path": {},
    "process.command_line": {},
    "download.target_path": {},
}
HASH_FIELDS = [
    "file.md5",
    "file.sha1",
    "file.sha256",
    "autoruns.hash_md5",
    "autoruns.hash_sha1",
    "autoruns.hash_sha256",
    "process.hashes.md5",
    "process.hashes.sha1",
    "process.hashes.sha256",
]
IP_FIELDS = [
    "network.source_ip",
    "network.destination_ip",
    "source.ip",
    "destination.ip",
    "dns.ip",
    "host.ip",
]
DOMAIN_FIELDS = [
    "dns.domain",
    "dns.query",
    "dns.question.name",
    "url.domain",
    "network.domain",
    "browser.domain",
    "destination.hostname",
]
URL_FIELDS = [
    "url.full",
    "download.url",
    "browser.url",
    "browser.final_url",
    "bits.remote_url",
]
PATH_FIELDS = [
    "file.path",
    "process.path",
    "process.command_line",
    "download.target_path",
    "cloud.local_path",
    "recycle.original_path",
    "lnk.effective_path",
    "mft.path",
    "autoruns.image_path",
    "autoruns.command_line",
]
FILENAME_FIELDS = [
    "file.name",
    "process.name",
    "download.file_name",
    "recycle.original_file_name",
    "mft.file_name",
]
REGISTRY_FIELDS = [
    "registry.key_path",
    "registry.path",
    "registry.value_name",
    "registry.value_data",
    "registry.data",
    "autoruns.entry_location",
]
SID_FIELDS = [
    "user.sid",
    "autoruns.sid",
    "recycle.sid",
]
RISK_BUCKETS = [
    ("critical", 90, 100),
    ("high", 70, 89),
    ("medium", 40, 69),
    ("low", 1, 39),
    ("none", 0, 0),
]
EVENT_EXACT_FILTERS = {
    "evidence_id": "evidence_id",
    "host": "host.name",
    "user": "user.name",
    "process_name": "process.name",
    "source_file": "source_file",
}
EVENT_TERMS_FILTERS = {
    "artifact_type": "artifact.type",
    "parser": "artifact.parser",
    "parser_backend": "artifact.parser_backend",
    "backend_variant": "artifact.backend_variant",
    "event_type": "event.type",
    "event_category": "event.category",
    "severity": "event.severity",
}
EVENT_SORTS = {
    "timestamp_desc": [{"@timestamp": {"order": "desc", "missing": "_last"}}, {"event_id": {"order": "desc", "missing": "_last"}}],
    "timestamp_asc": [{"@timestamp": {"order": "asc", "missing": "_last"}}, {"event_id": {"order": "asc", "missing": "_last"}}],
    "risk_desc": [{"risk_score": {"order": "desc", "missing": "_last"}}, {"@timestamp": {"order": "desc", "missing": "_last"}}, {"event_id": {"order": "desc", "missing": "_last"}}],
    "risk_asc": [{"risk_score": {"order": "asc", "missing": "_last"}}, {"@timestamp": {"order": "desc", "missing": "_last"}}, {"event_id": {"order": "asc", "missing": "_last"}}],
}
OPENSEARCH_RESULT_WINDOW_LIMIT = 10000
TIMELINE_LOW_VALUE_TYPES = {"file_observed", "generic_record", "process_observed"}
QUICK_FILTERS = [
    {"id": "high_risk", "label": "High risk events", "params": {"scope": "events", "risk_min": 70}},
    {"id": "critical_findings", "label": "Critical findings", "params": {"scope": "findings", "severity": ["critical"]}},
    {"id": "powershell_activity", "label": "PowerShell activity", "params": {"scope": "events", "process_name": "powershell.exe"}},
    {"id": "downloads", "label": "Downloads", "params": {"scope": "events", "event_type": ["file_downloaded"]}},
    {"id": "defender_detections", "label": "Defender detections", "params": {"scope": "events", "artifact_type": ["defender", "detection"]}},
    {"id": "persistence", "label": "Persistence", "params": {"scope": "events", "event_category": ["persistence"]}},
    {"id": "network_activity", "label": "Network activity", "params": {"scope": "events", "event_category": ["network"]}},
    {"id": "cloud_activity", "label": "Cloud activity", "params": {"scope": "events", "artifact_type": ["cloud", "cloud_sync"]}},
    {"id": "usb_activity", "label": "USB activity", "params": {"scope": "events", "artifact_type": ["usb"]}},
    {"id": "deleted_files", "label": "Deleted files", "params": {"scope": "events", "event_type": ["file_deleted"]}},
    {"id": "process_executions", "label": "Process executions", "params": {"scope": "events", "event_type": ["process_start"]}},
    {"id": "suspicious_dns", "label": "Suspicious DNS", "params": {"scope": "events", "artifact_type": ["dns"], "risk_min": 50}},
]


def _dedupe(values: list[str] | None) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def normalize_search_value(value: str | None, *, max_length: int = 512) -> tuple[str, list[str]]:
    warnings: list[str] = []
    text = CONTROL_CHARS_RE.sub(" ", str(value or "")).strip()
    if len(text) > max_length:
        text = text[:max_length].rstrip()
        warnings.append("query_truncated")
    if text.count("*") + text.count("?") > 8:
        text = text.replace("*", " ").replace("?", " ").strip()
        warnings.append("wildcards_sanitized")
    return text, warnings


def detect_ioc_type(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if IOC_HASH_RE.fullmatch(text):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(text)]
    if IOC_IPV4_RE.fullmatch(text):
        return "ipv4"
    if IOC_URL_RE.match(text):
        return "url"
    if IOC_WINDOWS_PATH_RE.match(text):
        return "windows_path"
    if IOC_REGISTRY_RE.match(text):
        return "registry_path"
    if IOC_SID_RE.fullmatch(text):
        return "sid"
    if IOC_GUID_RE.fullmatch(text):
        return "guid"
    if IOC_DOMAIN_RE.fullmatch(text.lower()):
        return "domain"
    if IOC_FILENAME_RE.fullmatch(text):
        return "filename"
    return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_window(value: str) -> timedelta:
    match = WINDOW_RE.fullmatch(value.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Invalid window format. Use 30m, 2h or 1d.")
    amount = int(match.group("amount"))
    unit = match.group("unit").lower()
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _max_reasonable_timestamp() -> str:
    return (datetime.now(UTC) + MAX_REASONABLE_FUTURE_TIMESTAMP_SKEW).isoformat()


def _timestamp_warning(value: Any) -> str | None:
    if not value:
        return None
    try:
        parsed = _parse_time(str(value))
    except Exception:  # noqa: BLE001
        return "invalid_timestamp"
    if parsed is None:
        return None
    if parsed > datetime.now(UTC) + MAX_REASONABLE_FUTURE_TIMESTAMP_SKEW:
        return "future_out_of_range"
    if parsed < MIN_REASONABLE_TIMESTAMP:
        return "past_out_of_range"
    return None


def _preserve_suspicious_timestamp(source: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    timestamp = source.get("@timestamp")
    warning = _timestamp_warning(timestamp)
    if not warning:
        return source, None

    sanitized = dict(source)
    original = str(timestamp)
    sanitized.setdefault("timestamp_original", original)
    sanitized.setdefault("raw_timestamp", original)
    sanitized.setdefault("original_timestamp", original)
    sanitized.setdefault("timestamp_status", "suspicious" if warning.endswith("_out_of_range") else "invalid")
    sanitized.setdefault("timestamp_warning", warning)
    sanitized.setdefault("timestamp_source", "@timestamp")
    sanitized.pop("@timestamp", None)
    return sanitized, warning


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


def _risk_bucket(score: int | None) -> str:
    value = int(score or 0)
    for name, low, high in RISK_BUCKETS:
        if low <= value <= high:
            return name
    return "none"


def _safe_wildcard(value: str) -> str:
    return re.sub(r"([*?\\\\])", r"\\\1", value)


def _build_should_terms(fields: list[str], value: str, *, wildcard: bool = False, case_insensitive: bool = True) -> list[dict[str, Any]]:
    if wildcard:
        escaped = _safe_wildcard(value)
        return [{"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": case_insensitive}}} for field in fields]
    return [{"term": {field: value}} for field in fields]


def _strip_balanced_quotes(value: str) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1].strip()
    return text


def _query_looks_command_like(value: str) -> bool:
    text = _strip_balanced_quotes(value)
    lower = text.lower()
    return bool(
        re.search(r"(?<!\w)-[a-z][\w-]*", text)
        or re.search(r"(^|\s)/[a-z](\s|$)", lower)
        or "\\" in text
        or re.search(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|lnk|iso|zip|7z|rar|msi|scr|pif)\b", lower)
    )


def _command_query_variants(value: str) -> list[str]:
    text = _strip_balanced_quotes(value)
    variants: list[str] = []
    for candidate in (
        text,
        text.lower(),
        text.replace("/", "\\"),
        text.replace("\\", "/"),
        text.replace("\\\\", "\\"),
    ):
        candidate = candidate.strip()
        if candidate and candidate not in variants:
            variants.append(candidate)
    basename = text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip()
    if basename and basename != text and basename not in variants:
        variants.append(basename)
        lowered = basename.lower()
        if lowered not in variants:
            variants.append(lowered)
    return variants[:12]


def _build_command_like_text_query(query: str) -> dict[str, Any]:
    value = _strip_balanced_quotes(query)
    should: list[dict[str, Any]] = [
        {"multi_match": {"query": value, "fields": TEXT_FIELDS, "operator": "and", "type": "best_fields"}},
        {"multi_match": {"query": value, "fields": TEXT_FIELDS, "type": "phrase", "slop": 3}},
    ]
    for variant in _command_query_variants(value):
        if len(variant) > 160:
            continue
        should.extend(_build_should_terms(COMMAND_QUERY_WILDCARD_FIELDS, variant.lower(), wildcard=True))
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _build_text_query(query: str) -> dict[str, Any]:
    if query and _query_looks_command_like(query):
        return _build_command_like_text_query(query)
    ioc_type = detect_ioc_type(query)
    if ioc_type in {"md5", "sha1", "sha256"}:
        return {"bool": {"should": _build_should_terms(HASH_FIELDS, query), "minimum_should_match": 1}}
    if ioc_type == "ipv4":
        return {"bool": {"should": _build_should_terms(IP_FIELDS, query), "minimum_should_match": 1}}
    if ioc_type == "url":
        should = _build_should_terms(URL_FIELDS, query, wildcard=True)
        should.extend(_build_should_terms(TEXT_FIELDS, query, wildcard=True))
        return {"bool": {"should": should, "minimum_should_match": 1}}
    if ioc_type == "domain":
        should = _build_should_terms(DOMAIN_FIELDS, query, wildcard=True)
        should.extend(_build_should_terms(TEXT_FIELDS, query, wildcard=True))
        return {"bool": {"should": should, "minimum_should_match": 1}}
    if ioc_type == "windows_path":
        return {"bool": {"should": _build_should_terms(PATH_FIELDS, query, wildcard=True), "minimum_should_match": 1}}
    if ioc_type == "filename":
        should = _build_should_terms(FILENAME_FIELDS, query, wildcard=True)
        should.extend(_build_should_terms(TEXT_FIELDS, query, wildcard=True))
        return {"bool": {"should": should, "minimum_should_match": 1}}
    if ioc_type == "registry_path":
        return {"bool": {"should": _build_should_terms(REGISTRY_FIELDS, query, wildcard=True), "minimum_should_match": 1}}
    if ioc_type == "sid":
        return {"bool": {"should": _build_should_terms(SID_FIELDS, query), "minimum_should_match": 1}}
    if ioc_type == "guid":
        should = _build_should_terms(["process.entity_id", "process.parent_entity_id", "process.guid", "event_id"], query)
        return {"bool": {"should": should, "minimum_should_match": 1}}
    if query:
        simple_query = {"simple_query_string": {"query": query, "fields": TEXT_FIELDS, "default_operator": "and"}}
        if re.fullmatch(r"[A-Za-z0-9_.:-]{3,128}", query):
            should = [simple_query]
            should.extend(_build_should_terms(GENERIC_WILDCARD_TEXT_FIELDS, query, wildcard=True))
            return {"bool": {"should": should, "minimum_should_match": 1}}
        return simple_query
    return {"match_all": {}}


def _parse_filter_builder_conditions(raw_filters: Any) -> list[dict[str, Any]]:
    if not raw_filters:
        return []
    if isinstance(raw_filters, str):
        try:
            parsed = json.loads(raw_filters)
        except json.JSONDecodeError:
            return []
    else:
        parsed = raw_filters
    if not isinstance(parsed, list):
        return []
    conditions: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        field = str(item.get("field") or "").strip()
        operator = str(item.get("operator") or "is").strip().lower()
        value = str(item.get("value") or "").strip()
        negate = bool(item.get("negate"))
        if field not in FILTER_BUILDER_FIELD_MAP and field not in FILTER_BUILDER_TEXT_FIELDS:
            continue
        if operator not in FILTER_BUILDER_OPERATORS:
            continue
        if operator in {"is not", "does not contain", "does not exist"}:
            negate = not negate
            operator = {"is not": "is", "does not contain": "contains", "does not exist": "exists"}[operator]
        if operator in {"is", "contains", "starts with"} and not value:
            continue
        conditions.append({"field": field, "operator": operator, "value": value, "negate": negate})
    return conditions


def _wildcard_clause(fields: list[str], value: str, *, starts_with: bool = False) -> dict[str, Any]:
    escaped = _safe_wildcard(value)
    pattern = f"{escaped}*" if starts_with else f"*{escaped}*"
    return {
        "bool": {
            "should": [{"wildcard": {field: {"value": pattern, "case_insensitive": True}}} for field in fields],
            "minimum_should_match": 1,
        }
    }


def _filter_builder_clause(case_id: str, condition: dict[str, Any], db: Session | None = None) -> dict[str, Any] | None:
    field = str(condition.get("field") or "")
    operator = str(condition.get("operator") or "is")
    value = str(condition.get("value") or "").strip()
    if field in FILTER_BUILDER_TEXT_FIELDS:
        fields = FILTER_BUILDER_TEXT_FIELDS[field]
        if operator == "exists":
            return {"bool": {"should": [{"exists": {"field": item}} for item in fields], "minimum_should_match": 1}}
        return _wildcard_clause(fields, value, starts_with=operator == "starts with")

    spec = FILTER_BUILDER_FIELD_MAP.get(field)
    if not spec:
        return None
    primary_field = str(spec.get("field") or "")
    fields = list(spec.get("fields") or [primary_field])
    kind = str(spec.get("kind") or "term")
    if operator == "exists":
        return {"bool": {"should": [{"exists": {"field": item}} for item in fields], "minimum_should_match": 1}}
    if kind == "host":
        return _host_filter(case_id, value, db)
    if kind == "number":
        try:
            return {"term": {primary_field: int(value)}}
        except ValueError:
            return {"term": {primary_field: value}}
    if kind == "wildcard":
        if operator == "is":
            return {"term": {primary_field: value}}
        return _wildcard_clause([primary_field], value, starts_with=operator == "starts with")
    if kind == "wildcard_multi":
        if operator == "is":
            return {"bool": {"should": [{"term": {item: value}} for item in fields], "minimum_should_match": 1}}
        return _wildcard_clause(fields, value, starts_with=operator == "starts with")
    values = _artifact_type_values([value]) if spec.get("expand") == "artifact_type" else [value]
    return {"terms": {primary_field: values}}


def _build_filter_builder_clauses(case_id: str, params: dict[str, Any], db: Session | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    filters: list[dict[str, Any]] = []
    must_not: list[dict[str, Any]] = []
    for condition in _parse_filter_builder_conditions(params.get("filters")):
        clause = _filter_builder_clause(case_id, condition, db)
        if not clause:
            continue
        if condition.get("negate"):
            must_not.append(clause)
        else:
            filters.append(clause)
    return filters, must_not


def _query_syntax_metadata(query_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": query_info.get("mode", "plain"),
        "parsed": bool(query_info.get("parsed", False)),
        "errors": list(query_info.get("errors") or []),
        "warnings": list(query_info.get("warnings") or []),
        "normalized_query": str(query_info.get("normalized_query") or ""),
        "applied_filters": list(query_info.get("applied_filters") or []),
    }


def _public_query_params(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if not str(key).startswith("_")}


def _artifact_type_values(values: list[str] | None) -> list[str]:
    expanded: list[str] = []
    for item in values or []:
        text = str(item).strip().lower()
        if not text:
            continue
        expanded.append(text)
        if text == "defender":
            expanded.append("detection")
        elif text == "detection":
            expanded.append("defender")
        elif text == "cloud":
            expanded.append("cloud_sync")
        elif text == "cloud_sync":
            expanded.append("cloud")
        elif text == "user_activity":
            expanded.extend(["shellbag", "userassist", "recentdocs", "runmru", "opensavemru"])
        elif text in {"shellbag", "userassist", "recentdocs", "runmru", "opensavemru"}:
            expanded.append("user_activity")
    return sorted(set(expanded))


def _build_event_filters(case_id: str, params: dict[str, Any], db: Session | None = None) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}]
    for param_name, field_name in EVENT_TERMS_FILTERS.items():
        values = _dedupe(params.get(param_name))
        if not values:
            continue
        if param_name == "backend_variant" and any(str(value).strip().lower() == "all" for value in values):
            continue
        if param_name == "artifact_type":
            values = _artifact_type_values(values)
        filters.append({"terms": {field_name: values}})
    if not _dedupe(params.get("backend_variant")) and not _dedupe(params.get("parser_backend")):
        filters.append({"bool": {"must_not": [{"term": {"artifact.backend_variant": "advanced"}}]}})
    for param_name, field_name in EVENT_EXACT_FILTERS.items():
        value = str(params.get(param_name) or "").strip()
        if value:
            if param_name == "host":
                filters.append(_host_filter(case_id, value, db))
            elif param_name == "source_file":
                filters.append(
                    {
                        "bool": {
                            "should": [
                                {"term": {field_name: value}},
                                {"wildcard": {field_name: {"value": f"*{_safe_wildcard(value)}*", "case_insensitive": True}}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                )
            else:
                filters.append({"term": {field_name: value}})
    risk_min = params.get("risk_min")
    risk_max = params.get("risk_max")
    if risk_min is not None or risk_max is not None:
        range_filter: dict[str, Any] = {}
        if risk_min is not None:
            range_filter["gte"] = int(risk_min)
        if risk_max is not None:
            range_filter["lte"] = int(risk_max)
        filters.append({"range": {"risk_score": range_filter}})
    time_from = _parse_time(params.get("time_from"))
    time_to = _parse_time(params.get("time_to"))
    if time_from or time_to:
        range_filter = {}
        if time_from:
            range_filter["gte"] = time_from.isoformat()
        if time_to:
            range_filter["lte"] = time_to.isoformat()
        filters.append({"range": {"@timestamp": range_filter}})
    has_timestamp = params.get("has_timestamp")
    if has_timestamp is True:
        filters.append({"exists": {"field": "@timestamp"}})
    elif has_timestamp is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "@timestamp"}}]}})
    if params.get("timeline_only"):
        if not params.get("include_suspicious_timestamps", False):
            filters.append({"range": {"@timestamp": {"lte": _max_reasonable_timestamp()}}})
            filters.append({"bool": {"must_not": [{"terms": {"timestamp_status": ["invalid", "suspicious"]}}]}})
        if not params.get("include_low_value", False):
            filters.append({"bool": {"must_not": [{"terms": {"event.type": list(TIMELINE_LOW_VALUE_TYPES)}}]}})
        filters.append(
            {
                "bool": {
                    "should": [
                        {"term": {"event.timeline_include": True}},
                        {"bool": {"must_not": [{"exists": {"field": "event.timeline_include"}}]}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
        selected_artifact_types = set(_artifact_type_values(_dedupe(params.get("artifact_type"))))
        if "mft" not in selected_artifact_types and "filesystem" not in selected_artifact_types and not params.get("include_filesystem_timeline", False):
            filters.append({"bool": {"must_not": [{"term": {"artifact.type": "mft"}}]}})
        if not params.get("include_low_confidence_timestamps", False):
            filters.append({"bool": {"must_not": [{"term": {"timestamp_precision": "unknown"}}]}})
    domain = str(params.get("domain") or "").strip()
    if domain:
        filters.append({"bool": {"should": _build_should_terms(DOMAIN_FIELDS, domain, wildcard=True), "minimum_should_match": 1}})
    ip = str(params.get("ip") or "").strip()
    if ip:
        filters.append({"bool": {"should": _build_should_terms(IP_FIELDS, ip), "minimum_should_match": 1}})
    hash_value = str(params.get("hash") or "").strip()
    if hash_value:
        filters.append({"bool": {"should": _build_should_terms(HASH_FIELDS, hash_value), "minimum_should_match": 1}})
    url_value = str(params.get("url") or "").strip()
    if url_value:
        filters.append({"bool": {"should": _build_should_terms(URL_FIELDS, url_value, wildcard=True), "minimum_should_match": 1}})
    file_name = str(params.get("file_name") or "").strip()
    if file_name:
        filters.append({"bool": {"should": _build_should_terms(FILENAME_FIELDS, file_name, wildcard=True), "minimum_should_match": 1}})
    file_path = str(params.get("file_path") or "").strip()
    if file_path:
        filters.append({"bool": {"should": _build_should_terms(PATH_FIELDS, file_path, wildcard=True), "minimum_should_match": 1}})
    suspicious_reason = str(params.get("suspicious_reason") or "").strip()
    if suspicious_reason:
        filters.append({"wildcard": {"suspicious_reasons": {"value": f"*{_safe_wildcard(suspicious_reason)}*", "case_insensitive": True}}})
    tag = str(params.get("tag") or "").strip()
    if tag:
        filters.append({"term": {"tags": tag}})
    builder_filters, _ = _build_filter_builder_clauses(case_id, params, db)
    filters.extend(builder_filters)
    if params.get("marked_only") or params.get("marking_status") or params.get("marked_has_note") or params.get("marked_in_finding"):
        if not db:
            filters.append({"term": {"event_id": "__no_marking_session__"}})
        else:
            event_ids, stable_ids = event_marking_filter_ids(
                db,
                case_id,
                status=str(params.get("marking_status") or "").strip() or None,
                has_note=True if params.get("marked_has_note") else None,
                in_finding=True if params.get("marked_in_finding") else None,
            )
            should = []
            if event_ids:
                should.append({"terms": {"event_id": event_ids}})
            if stable_ids:
                should.append({"terms": {"stable_event_id": stable_ids}})
            filters.append({"bool": {"should": should or [{"term": {"event_id": "__no_marked_events__"}}], "minimum_should_match": 1}})
    return filters


def _source_file_filter(field_name: str, value: str) -> dict[str, Any]:
    return {
        "bool": {
            "should": [
                {"term": {field_name: value}},
                {"wildcard": {field_name: {"value": f"*{_safe_wildcard(value)}*", "case_insensitive": True}}},
            ],
            "minimum_should_match": 1,
        }
    }


def _missing_host_value(value: Any) -> bool:
    return is_invalid_host_value(str(value or "").strip())


def _evidence_scope_host(evidence: Evidence | Any | None) -> tuple[str | None, str]:
    if not evidence:
        return None, "unknown"
    metadata = getattr(evidence, "metadata_json", None)
    provided = str((metadata or {}).get("provided_host") or "").strip() if isinstance(metadata, dict) else ""
    if provided and not is_invalid_host_value(provided):
        return provided, "provided_host"
    detected = str(getattr(evidence, "detected_host", None) or "").strip()
    if detected and not is_invalid_host_value(detected):
        return detected, "detected_host"
    return None, "unknown"


def _same_host_family(left: str | None, right: str | None) -> bool:
    left_norm = normalize_host_alias(left)
    right_norm = normalize_host_alias(right)
    if not left_norm or not right_norm:
        return False
    left_aliases = {left_norm, left_norm.split(".", 1)[0]}
    right_aliases = {right_norm, right_norm.split(".", 1)[0]}
    return bool(left_aliases & right_aliases)


def _host_query_variants(*values: str | None) -> list[str]:
    variants: list[str] = []
    seen: set[str] = set()
    for value in values:
        raw = str(value or "").strip()
        normalized = normalize_host_alias(raw)
        candidates = [raw] if raw else []
        if normalized:
            candidates.extend([normalized, normalized.upper()])
            if "." in normalized:
                short = normalized.split(".", 1)[0]
                candidates.extend([short, short.upper()])
        for candidate in candidates:
            text = str(candidate or "").strip()
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            variants.append(text)
    return variants


def _evidence_aliases_for_host_scope(db: Session | None, case_id: str, values: list[str]) -> tuple[list[str], list[str]]:
    if not db or not values:
        return [], []
    wanted = {normalize_host_alias(value) for value in values if normalize_host_alias(value)}
    wanted |= {item.split(".", 1)[0] for item in list(wanted) if "." in item}
    if not wanted:
        return [], []
    aliases: list[str] = []
    evidence_ids: list[str] = []
    for evidence in db.query(Evidence).filter(Evidence.case_id == case_id).all():
        metadata = dict(evidence.metadata_json or {})
        evidence_values = [
            metadata.get("provided_host"),
            metadata.get("detected_host"),
            getattr(evidence, "detected_host", None),
        ]
        normalized_values = {normalize_host_alias(value) for value in evidence_values if normalize_host_alias(value)}
        normalized_values |= {item.split(".", 1)[0] for item in list(normalized_values) if "." in item}
        if normalized_values & wanted:
            evidence_ids.append(str(evidence.id))
            aliases.extend(_host_query_variants(*evidence_values))
    return _dedupe(aliases), _dedupe(evidence_ids)


def _evidence_ids_for_host_scope(db: Session | None, case_id: str, values: list[str]) -> list[str]:
    if not db or not values:
        return []
    wanted = {str(value).strip().lower() for value in values if str(value).strip()}
    if not wanted:
        return []
    rows = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    matches: list[str] = []
    for evidence in rows:
        scoped_host, _ = _evidence_scope_host(evidence)
        if scoped_host and scoped_host.lower() in wanted:
            matches.append(str(evidence.id))
    return matches


def _host_filter(case_id: str, value: str, db: Session | None = None) -> dict[str, Any]:
    expanded = _host_query_variants(*(expand_host_filter(db, case_id, value) if db else [value]), value)
    evidence_aliases, evidence_ids = _evidence_aliases_for_host_scope(db, case_id, expanded)
    expanded = _dedupe([*expanded, *evidence_aliases])
    fallback_evidence_ids = _dedupe([*_evidence_ids_for_host_scope(db, case_id, expanded), *evidence_ids])
    fields = ["host.name", "host.hostname", "host.canonical", "host.aliases", "observed_host.name", "observed_host.hostname"]
    should: list[dict[str, Any]] = [
        {"terms": {"host.name": expanded}},
        {"terms": {"observed_host.name": expanded}},
        *[
            {"wildcard": {field: {"value": alias, "case_insensitive": True}}}
            for field in fields
            for alias in expanded
        ],
    ]
    if fallback_evidence_ids:
        evidence_scope = {"terms": {"evidence_id": fallback_evidence_ids}}
        missing_host_scope = {
            "bool": {
                "filter": [{"terms": {"evidence_id": fallback_evidence_ids}}],
                "must_not": [{"exists": {"field": "host.name"}}],
            }
        }
        dash_host_scope = {
            "bool": {
                "filter": [{"terms": {"evidence_id": fallback_evidence_ids}}, {"term": {"host.name": "-"}}],
            }
        }
        should.extend([evidence_scope, missing_host_scope, dash_host_scope])
    return {
        "bool": {
            "should": should,
            "minimum_should_match": 1,
        }
    }


def _build_event_exclusions(case_id: str, params: dict[str, Any], db: Session | None = None) -> list[dict[str, Any]]:
    must_not: list[dict[str, Any]] = []
    for param_name, field_name in (
        ("exclude_artifact_type", "artifact.type"),
        ("exclude_parser", "artifact.parser"),
    ):
        values = _dedupe(params.get(param_name))
        if not values:
            continue
        if param_name == "exclude_artifact_type":
            values = _artifact_type_values(values)
        must_not.append({"terms": {field_name: values}})
    for param_name, field_name in (
        ("exclude_host", "host.name"),
        ("exclude_user", "user.name"),
        ("exclude_source_file", "source_file"),
    ):
        value = str(params.get(param_name) or "").strip()
        if not value:
            continue
        if param_name == "exclude_host":
            must_not.append(_host_filter(case_id, value, db))
        elif param_name == "exclude_source_file":
            must_not.append(_source_file_filter(field_name, value))
        else:
            must_not.append({"term": {field_name: value}})
    exclude_query, _ = normalize_search_value(params.get("exclude_q"))
    if exclude_query:
        must_not.append(_build_text_query(exclude_query))
    _, builder_must_not = _build_filter_builder_clauses(case_id, params, db)
    must_not.extend(builder_must_not)
    return must_not


def _event_sort(sort: str, has_query: bool) -> list[dict[str, Any]]:
    if sort == "relevance" and has_query:
        return [{"_score": {"order": "desc"}}, {"@timestamp": {"order": "desc", "missing": "_last"}}, {"event_id": {"order": "desc", "missing": "_last"}}]
    return EVENT_SORTS.get(sort, EVENT_SORTS["timestamp_desc"])


def _hydrate_case_host_display_cached(db: Session, case_id: str, event: dict[str, Any], host_cache: dict[str, dict[str, Any] | None] | None = None) -> dict[str, Any]:
    item = dict(event)
    host = dict(item.get("host") or {})
    observed_host = dict(item.get("observed_host") or {})
    observed_name = str(observed_host.get("name") or host.get("name") or "").strip()
    if observed_name:
        observed_host.setdefault("name", observed_name)
        observed_host.setdefault("hostname", observed_name)
    cache_key = observed_name.strip().lower()
    resolved = None
    if cache_key:
        if host_cache is not None and cache_key in host_cache:
            resolved = host_cache[cache_key]
        else:
            resolved = resolve_canonical_host(db, case_id, observed_name or host.get("name"))
            if host_cache is not None:
                host_cache[cache_key] = resolved
    if resolved:
        host["name"] = resolved["canonical_name"]
        host["hostname"] = resolved["canonical_name"]
        host["aliases"] = list(resolved.get("aliases") or [])
        host["identity_id"] = resolved["case_host_id"]
        host["identity_confidence"] = resolved["confidence"]
    item["host"] = host
    item["observed_host"] = observed_host
    return item


def _evidence_scope_host_cached(db: Session, evidence_id: str, evidence_host_cache: dict[str, tuple[str | None, str]] | None = None) -> tuple[str | None, str]:
    if evidence_host_cache is not None and evidence_id in evidence_host_cache:
        return evidence_host_cache[evidence_id]
    result = _evidence_scope_host(db.get(Evidence, evidence_id))
    if evidence_host_cache is not None:
        evidence_host_cache[evidence_id] = result
    return result


def _format_event_result(
    hit: dict[str, Any],
    *,
    case_id: str | None = None,
    db: Session | None = None,
    host_cache: dict[str, dict[str, Any] | None] | None = None,
    evidence_host_cache: dict[str, tuple[str | None, str]] | None = None,
) -> dict[str, Any]:
    source = dict(hit.get("_source") or {})
    if case_id and db:
        source = _hydrate_case_host_display_cached(db, case_id, source, host_cache)
    source, timestamp_warning = _preserve_suspicious_timestamp(source)
    event = dict(source.get("event") or {})
    artifact = dict(source.get("artifact") or {})
    host = dict(source.get("host") or {})
    evidence_id = str(source.get("evidence_id") or "").strip()
    if db and evidence_id:
        current_host = host.get("name") or host.get("hostname")
        scoped_host, scoped_source = _evidence_scope_host_cached(db, evidence_id, evidence_host_cache)
        if _missing_host_value(current_host) and scoped_host:
            original_value = current_host if current_host is not None else None
            host["name"] = scoped_host
            host["hostname"] = scoped_host
            host["source"] = scoped_source
            host["confidence"] = "evidence_scope"
            if original_value is not None:
                host["original_value"] = original_value
            source["host"] = host
        elif scoped_host and _same_host_family(current_host, scoped_host):
            original_value = current_host if current_host != scoped_host else None
            host["name"] = scoped_host
            host["hostname"] = scoped_host
            host["canonical"] = scoped_host
            host["source"] = "provided_host"
            host["confidence"] = "evidence_scope"
            if original_value:
                host["original_value"] = original_value
            source["host"] = host
        elif not _missing_host_value(current_host):
            host.setdefault("source", "artifact")
            host.setdefault("confidence", "artifact")
            source["host"] = host
    user = dict(source.get("user") or {})
    matched_fields = sorted((hit.get("highlight") or {}).keys())
    title = str(event.get("message") or source.get("raw_summary") or event.get("type") or artifact.get("name") or "Event")
    summary = str(source.get("raw_summary") or event.get("message") or title)
    return {
        "kind": "event",
        "id": hit.get("_id") or source.get("event_id"),
        "timestamp": source.get("@timestamp"),
        "title": title,
        "summary": summary,
        "artifact_type": artifact.get("type"),
        "parser": artifact.get("parser"),
        "event_type": event.get("type"),
        "severity": event.get("severity"),
        "risk_score": source.get("risk_score", 0),
        "host": host.get("name"),
        "user": user.get("name"),
        "source_file": source.get("source_file"),
        "matched_fields": matched_fields,
        "highlights": hit.get("highlight") or {},
        "raw": {
            "id": hit.get("_id"),
            "search_doc_id": hit.get("_id"),
            "opensearch_id": hit.get("_id"),
            **source,
            **({"timestamp_warning": timestamp_warning} if timestamp_warning and not source.get("timestamp_warning") else {}),
        },
    }


def _finding_text_haystack(finding: Finding) -> str:
    values: list[str] = [
        finding.title or "",
        finding.description or "",
        finding.finding_type or "",
        finding.confidence or "",
        finding.source or "",
        *(finding.reasons or []),
        *(finding.tags or []),
        *(finding.related_files or []),
        *(finding.related_domains or []),
        *(finding.related_ips or []),
        *(finding.related_users or []),
        *(finding.related_hosts or []),
    ]
    return "\n".join(item for item in values if item).lower()


def _match_finding(finding: Finding, params: dict[str, Any], normalized_query: str, *, case_id: str, db: Session | None = None) -> tuple[bool, int]:
    if "finding" in _artifact_type_values(_dedupe(params.get("exclude_artifact_type"))):
        return False, 0
    if params.get("evidence_id") and finding.evidence_id != params.get("evidence_id"):
        return False, 0
    if params.get("severity") and str(finding.severity.value) not in _dedupe(params.get("severity")):
        return False, 0
    if params.get("status") and str(finding.status.value) not in _dedupe(params.get("status")):
        return False, 0
    if params.get("confidence") and str(finding.confidence or "") not in _dedupe(params.get("confidence")):
        return False, 0
    if params.get("finding_type") and str(finding.finding_type or "") not in _dedupe(params.get("finding_type")):
        return False, 0
    risk_min = params.get("risk_min")
    risk_max = params.get("risk_max")
    if risk_min is not None and (finding.risk_score or 0) < int(risk_min):
        return False, 0
    if risk_max is not None and (finding.risk_score or 0) > int(risk_max):
        return False, 0
    time_from = _parse_time(params.get("time_from"))
    time_to = _parse_time(params.get("time_to"))
    candidate_time = finding.time_start or finding.created_at
    if time_from and candidate_time and candidate_time.astimezone(UTC) < time_from:
        return False, 0
    if time_to and candidate_time and candidate_time.astimezone(UTC) > time_to:
        return False, 0
    expanded_host_filter = set(expand_host_filter(db, case_id, params.get("host")) if params.get("host") and db else [])
    for key, values in (
        ("host", finding.related_hosts or []),
        ("user", finding.related_users or []),
        ("domain", finding.related_domains or []),
        ("ip", finding.related_ips or []),
        ("file_name", finding.related_files or []),
        ("file_path", finding.related_files or []),
    ):
        filter_value = str(params.get(key) or "").strip().lower()
        if not filter_value:
            continue
        if key == "host" and expanded_host_filter:
            finding_hosts = {str(item).strip().lower() for item in values if str(item).strip()}
            if not finding_hosts.intersection(expanded_host_filter):
                return False, 0
            continue
        if not any(filter_value in str(item).lower() for item in values):
            return False, 0
    haystack = _finding_text_haystack(finding)
    exclude_query, _ = normalize_search_value(params.get("exclude_q"))
    if exclude_query and exclude_query.lower() in haystack:
        return False, 0
    expanded_exclude_host = set(expand_host_filter(db, case_id, params.get("exclude_host")) if params.get("exclude_host") and db else [])
    for key, values in (
        ("exclude_host", finding.related_hosts or []),
        ("exclude_user", finding.related_users or []),
        ("exclude_source_file", finding.related_files or []),
    ):
        filter_value = str(params.get(key) or "").strip().lower()
        if not filter_value:
            continue
        if key == "exclude_host" and expanded_exclude_host:
            finding_hosts = {str(item).strip().lower() for item in values if str(item).strip()}
            if finding_hosts.intersection(expanded_exclude_host):
                return False, 0
            continue
        if any(filter_value in str(item).lower() for item in values):
            return False, 0
    query_info = params.get("_query_syntax")
    if query_info and not evaluate_query_syntax(
        query_info,
        {
            "artifact": {"type": "finding"},
            "event": {"type": finding.finding_type},
            "finding": {
                "type": finding.finding_type,
                "status": finding.status.value,
                "severity": finding.severity.value,
            },
            "status": finding.status.value,
            "severity": finding.severity.value,
            "risk_score": finding.risk_score,
            "host": {"name": (finding.related_hosts or [None])[0]},
            "user": {"name": (finding.related_users or [None])[0]},
            "file": {
                "path": finding.related_files or [],
                "name": [str(item).split("\\")[-1].split("/")[-1] for item in (finding.related_files or [])],
            },
            "rule": {"name": finding.title, "title": finding.title},
            "detection": {"source": finding.source},
        },
        haystack,
    ):
        return False, 0
    relevance = 0
    if normalized_query and (not query_info or query_info.get("mode") == "plain"):
        if normalized_query.lower() not in haystack:
            return False, 0
        relevance += 50
        relevance += haystack.count(normalized_query.lower())
    relevance += int(finding.risk_score or 0)
    return True, relevance


def _format_finding_result(finding: Finding, *, relevance: int = 0, case_id: str | None = None, db: Session | None = None) -> dict[str, Any]:
    related_hosts = getattr(finding, "related_hosts", None) or []
    canonical_host = None
    if case_id and db and related_hosts:
        resolved = resolve_canonical_host(db, case_id, related_hosts[0])
        canonical_host = resolved["canonical_name"] if resolved else None
    related_users = getattr(finding, "related_users", None) or []
    related_event_ids = getattr(finding, "related_event_ids", None) or []
    related_process_node_ids = getattr(finding, "related_process_node_ids", None) or []
    related_files = getattr(finding, "related_files", None) or []
    related_domains = getattr(finding, "related_domains", None) or []
    related_ips = getattr(finding, "related_ips", None) or []
    reasons = getattr(finding, "reasons", None) or []
    tags = getattr(finding, "tags", None) or []
    recommended_triage = getattr(finding, "recommended_triage", None) or []
    data_quality = getattr(finding, "data_quality", None) or []
    timestamp = finding.time_start.isoformat() if finding.time_start else (finding.created_at.isoformat() if finding.created_at else None)
    return {
        "kind": "finding",
        "id": finding.id,
        "timestamp": timestamp,
        "title": finding.title,
        "summary": finding.description or "",
        "artifact_type": "finding",
        "parser": None,
        "event_type": finding.finding_type,
        "severity": finding.severity.value,
        "risk_score": finding.risk_score,
        "host": canonical_host or (related_hosts or [None])[0],
        "user": (related_users or [None])[0],
        "source_file": None,
        "matched_fields": ["finding"] if relevance else [],
        "highlights": {},
        "raw": {
            "id": finding.id,
            "case_id": finding.case_id,
            "evidence_id": finding.evidence_id,
            "finding_type": finding.finding_type,
            "status": finding.status.value,
            "confidence": finding.confidence,
            "time_start": finding.time_start.isoformat() if finding.time_start else None,
            "time_end": finding.time_end.isoformat() if finding.time_end else None,
            "reasons": reasons,
            "tags": tags,
            "related_event_ids": related_event_ids,
            "related_process_node_ids": related_process_node_ids,
            "related_files": related_files,
            "related_domains": related_domains,
            "related_ips": related_ips,
            "related_users": related_users,
            "related_hosts": related_hosts,
            "recommended_triage": recommended_triage,
            "data_quality": data_quality,
        },
    }


def _sort_mixed_items(items: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, None: 0}
    if sort == "risk_asc":
        return sorted(items, key=lambda item: (int(item.get("risk_score") or 0), str(item.get("timestamp") or "")))
    if sort == "risk_desc":
        return sorted(items, key=lambda item: (-int(item.get("risk_score") or 0), str(item.get("timestamp") or "")), reverse=False)
    if sort == "timestamp_asc":
        return sorted(items, key=lambda item: str(item.get("timestamp") or ""))
    if sort == "relevance":
        return sorted(items, key=lambda item: (-len(item.get("matched_fields") or []), -int(item.get("risk_score") or 0), -severity_rank.get(item.get("severity"), 0), str(item.get("timestamp") or "")))
    return sorted(items, key=lambda item: (str(item.get("timestamp") or ""), int(item.get("risk_score") or 0)), reverse=True)


def _facet_counts(results: list[dict[str, Any]], *, finding_rows: list[Finding] | None = None) -> dict[str, dict[str, int]]:
    facets = {
        "artifact_type": Counter(),
        "parser": Counter(),
        "source_file": Counter(),
        "event_type": Counter(),
        "severity": Counter(),
        "risk_bucket": Counter(),
        "host": Counter(),
        "user": Counter(),
        "finding_type": Counter(),
        "status": Counter(),
    }
    for item in results:
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        artifact = raw.get("artifact") if isinstance(raw.get("artifact"), dict) else {}
        if item.get("artifact_type"):
            facets["artifact_type"][str(item["artifact_type"])] += 1
        parser_value = artifact.get("parser")
        if parser_value:
            facets["parser"][str(parser_value)] += 1
        if item.get("source_file"):
            facets["source_file"][str(item["source_file"])] += 1
        if item.get("event_type"):
            facets["event_type"][str(item["event_type"])] += 1
        if item.get("severity"):
            facets["severity"][str(item["severity"])] += 1
        facets["risk_bucket"][_risk_bucket(int(item.get("risk_score") or 0))] += 1
        if item.get("host"):
            facets["host"][str(item["host"])] += 1
        if item.get("user"):
            facets["user"][str(item["user"])] += 1
    for item in finding_rows or []:
        if item.finding_type:
            facets["finding_type"][str(item.finding_type)] += 1
        facets["status"][item.status.value] += 1
    return {key: dict(value) for key, value in facets.items()}


def search_events_v2(case_id: str, params: dict[str, Any], *, db: Session | None = None) -> tuple[int, list[dict[str, Any]], list[str], dict[str, dict[str, int]]]:
    warnings: list[str] = []
    query, query_warnings = normalize_search_value(params.get("q"))
    warnings.extend(query_warnings)
    try:
        query_info = analyze_query_syntax(query, _build_text_query)
    except QuerySyntaxError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid search query",
                "message": exc.message,
                "examples": SEARCH_SYNTAX_EXAMPLES,
            },
        ) from exc
    page_size_limit = int(params.get("_page_size_limit") or 500)
    page_size = max(1, min(int(params.get("page_size") or 50), page_size_limit, OPENSEARCH_RESULT_WINDOW_LIMIT))
    offset = _decode_cursor(params.get("cursor")) if params.get("cursor") else max(0, (int(params.get("page") or 1) - 1) * page_size)
    if offset + page_size > OPENSEARCH_RESULT_WINDOW_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"Search pagination is limited to the first {OPENSEARCH_RESULT_WINDOW_LIMIT} matching events for stable sorting. Narrow the query or time range.",
        )
    index = get_events_index(case_id)
    client = get_opensearch_client()
    params["_query_syntax"] = query_info
    if not index_exists(client, index):
        return 0, [], warnings, _facet_counts([])
    sort = str(params.get("sort") or "timestamp_desc")
    session = db if db else SessionLocal()
    close_session = db is None
    host_cache: dict[str, dict[str, Any] | None] = {}
    evidence_host_cache: dict[str, tuple[str | None, str]] = {}
    bool_query: dict[str, Any] = {
        "must": [query_info["query"]],
        "filter": _build_event_filters(case_id, params, session),
    }
    must_not = _build_event_exclusions(case_id, params, session)
    if must_not:
        bool_query["must_not"] = must_not
    body: dict[str, Any] = {
        "from": offset,
        "size": page_size,
        "query": {"bool": bool_query},
        "track_total_hits": True,
        "sort": _event_sort(sort, bool(query)),
    }
    if params.get("include_highlights", True):
        body["highlight"] = {"fields": HIGHLIGHT_FIELDS, "fragment_size": 160, "number_of_fragments": 2}
    try:
        try:
            result = client.search(index=index, body=body, params={"ignore_unavailable": "true"}, request_timeout=SEARCH_REQUEST_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {exc}") from exc
        total_meta = result.get("hits", {}).get("total", 0)
        total = int(total_meta.get("value", 0) if isinstance(total_meta, dict) else total_meta)
        rows = [_format_event_result(hit, case_id=case_id, db=session, host_cache=host_cache, evidence_host_cache=evidence_host_cache) for hit in result.get("hits", {}).get("hits", [])]
        markings = marking_map_for_events(session, case_id, rows)
        for row in rows:
            raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
            marking = markings.get(str(row.get("id"))) or markings.get(str(raw.get("stable_event_id") or ""))
            if marking:
                serialized = serialize_marking(marking)
                row["marking"] = serialized
                if isinstance(raw, dict):
                    raw["marking"] = serialized
        facets = _facet_counts(rows)
        return total, rows, warnings, facets
    finally:
        if close_session:
            session.close()


def search_findings_v2(db: Session, case_id: str, params: dict[str, Any], *, limit_override: int | None = None) -> tuple[int, list[dict[str, Any]], list[Finding], list[str]]:
    query_text, warnings = normalize_search_value(params.get("q"))
    query_info = params.get("_query_syntax")
    if query_info is None:
        try:
            query_info = analyze_query_syntax(query_text, _build_text_query)
        except QuerySyntaxError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid search query",
                    "message": exc.message,
                    "examples": SEARCH_SYNTAX_EXAMPLES,
                },
            ) from exc
        params["_query_syntax"] = query_info
    all_rows = db.query(Finding).filter(Finding.case_id == case_id).all()
    matched: list[tuple[Finding, int]] = []
    for row in all_rows:
        ok, relevance = _match_finding(row, params, query_text, case_id=case_id, db=db)
        if ok:
            matched.append((row, relevance))
    sort = str(params.get("sort") or "timestamp_desc")
    if sort == "risk_desc":
        matched.sort(key=lambda item: (-(item[0].risk_score or 0), str(item[0].time_start or item[0].created_at or "")))
    elif sort == "risk_asc":
        matched.sort(key=lambda item: ((item[0].risk_score or 0), str(item[0].time_start or item[0].created_at or "")))
    elif sort == "timestamp_asc":
        matched.sort(key=lambda item: str(item[0].time_start or item[0].created_at or ""))
    elif sort == "relevance":
        matched.sort(key=lambda item: (-item[1], -(item[0].risk_score or 0), str(item[0].time_start or item[0].created_at or "")))
    else:
        matched.sort(key=lambda item: str(item[0].time_start or item[0].created_at or ""), reverse=True)
    page_size_limit = int(params.get("_page_size_limit") or 500)
    page_size = max(1, min(int(params.get("page_size") or 50), page_size_limit, OPENSEARCH_RESULT_WINDOW_LIMIT))
    offset = _decode_cursor(params.get("cursor")) if params.get("cursor") else max(0, (int(params.get("page") or 1) - 1) * page_size)
    limit = limit_override if limit_override is not None else page_size
    page_rows = matched[offset : offset + limit]
    return len(matched), [_format_finding_result(row, relevance=relevance, case_id=case_id, db=db) for row, relevance in page_rows], [row for row, _ in matched], warnings


def search_case_v2(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    scope = str(params.get("scope") or "all")
    page_size = max(1, min(int(params.get("page_size") or 100), 500))
    offset = _decode_cursor(params.get("cursor")) if params.get("cursor") else max(0, (int(params.get("page") or 1) - 1) * page_size)
    warnings: list[str] = []
    if wants_memory_source(params):
        memory = memory_search_results(db, case_id, {**params, "page_size": page_size})
        memory.setdefault("query_syntax", _query_syntax_metadata(params.get("_query_syntax") or {}))
        memory.setdefault("has_previous", offset > 0)
        memory.setdefault("pagination_mode", "offset")
        memory.setdefault("debug_pagination", {"from": offset, "size": page_size, "sort": str(params.get("sort") or "timestamp_desc"), "search_after_used": False})
        return memory
    if scope == "events":
        total, results, event_warnings, facets = search_events_v2(case_id, params, db=db)
        warnings.extend(event_warnings)
        results = [add_event_source_provenance(row) for row in results]
        results = _filter_source_category(results, params)
        if wants_non_memory_source(params):
            total = len(results)
        next_cursor = _encode_cursor(offset + page_size) if offset + page_size < total else None
        return {
            "query": _public_query_params(params),
            "query_syntax": _query_syntax_metadata(params.get("_query_syntax") or {}),
            "total": total,
            "page": int(params.get("page") or 1),
            "page_size": page_size,
            "items_count": len(results),
            "has_previous": offset > 0,
            "has_next": offset + len(results) < total,
            "pagination_mode": "offset" if not params.get("cursor") else "cursor",
            "debug_pagination": {"from": offset, "size": page_size, "sort": _event_sort(str(params.get("sort") or "timestamp_desc"), bool(params.get("q"))), "search_after_used": False},
            "next_cursor": next_cursor,
            "results": results,
            "facets": facets if params.get("include_facets", True) else {},
            "warnings": warnings,
        }
    if scope == "findings":
        total, results, finding_rows, finding_warnings = search_findings_v2(db, case_id, params)
        warnings.extend(finding_warnings)
        next_cursor = _encode_cursor(offset + page_size) if offset + page_size < total else None
        return {
            "query": _public_query_params(params),
            "query_syntax": _query_syntax_metadata(params.get("_query_syntax") or {}),
            "total": total,
            "page": int(params.get("page") or 1),
            "page_size": page_size,
            "items_count": len(results),
            "has_previous": offset > 0,
            "has_next": offset + len(results) < total,
            "pagination_mode": "offset" if not params.get("cursor") else "cursor",
            "debug_pagination": {"from": offset, "size": page_size, "sort": str(params.get("sort") or "timestamp_desc"), "search_after_used": False},
            "next_cursor": next_cursor,
            "results": results,
            "facets": _facet_counts(results, finding_rows=finding_rows) if params.get("include_facets", True) else {},
            "warnings": warnings,
        }
    if offset + page_size > OPENSEARCH_RESULT_WINDOW_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"Search pagination is limited to the first {OPENSEARCH_RESULT_WINDOW_LIMIT} matching items for stable sorting. Narrow the query or time range.",
        )
    fetch_limit = min(offset + page_size, OPENSEARCH_RESULT_WINDOW_LIMIT)
    if wants_non_memory_source(params):
        params = {**params}
    event_total, event_rows, event_warnings, _ = search_events_v2(case_id, {**params, "page": 1, "cursor": None, "page_size": fetch_limit, "_page_size_limit": fetch_limit}, db=db)
    finding_total, finding_rows, finding_full_rows, finding_warnings = search_findings_v2(db, case_id, {**params, "page": 1, "cursor": None, "page_size": fetch_limit, "_page_size_limit": fetch_limit}, limit_override=fetch_limit)
    warnings.extend(event_warnings)
    warnings.extend(finding_warnings)
    event_rows = [add_event_source_provenance(row) for row in event_rows]
    event_rows = _filter_source_category(event_rows, params)
    disk_rows = [*event_rows, *finding_rows]
    if not wants_non_memory_source(params):
        memory = memory_search_results(db, case_id, {**params, "page": 1, "page_size": fetch_limit})
        memory_rows = memory.get("results") or []
        warnings.extend(memory.get("warnings") or [])
    else:
        memory_rows = []
    merged = _sort_mixed_items([*disk_rows, *memory_rows], str(params.get("sort") or "timestamp_desc"))
    total = (len(disk_rows) if wants_non_memory_source(params) else event_total + finding_total) + len(memory_rows)
    page_results = merged[offset : offset + page_size]
    next_cursor = _encode_cursor(offset + page_size) if offset + page_size < total else None
    return {
        "query": _public_query_params(params),
        "query_syntax": _query_syntax_metadata(params.get("_query_syntax") or {}),
        "total": total,
        "page": int(params.get("page") or 1),
        "page_size": page_size,
        "items_count": len(page_results),
        "has_previous": offset > 0,
        "has_next": offset + len(page_results) < total,
        "pagination_mode": "offset" if not params.get("cursor") else "cursor",
        "debug_pagination": {"from": offset, "size": page_size, "sort": str(params.get("sort") or "timestamp_desc"), "search_after_used": False},
        "next_cursor": next_cursor,
        "results": page_results,
            "facets": _merged_facets(_facet_counts(merged, finding_rows=finding_full_rows), memory_rows) if params.get("include_facets", True) else {},
            "warnings": warnings,
        }


def _merged_facets(facets: dict[str, dict[str, int]], rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    merged = {key: dict(value) for key, value in facets.items()}
    for row in rows:
        for key in ("source_category", "artifact_family", "artifact_type"):
            value = row.get(key) or (row.get("raw") or {}).get(key)
            if value:
                bucket = merged.setdefault(key, {})
                bucket[str(value)] = int(bucket.get(str(value), 0)) + 1
        parser = row.get("source_plugin_or_parser") or row.get("parser")
        if parser:
            bucket = merged.setdefault("source_plugin_or_parser", {})
            bucket[str(parser)] = int(bucket.get(str(parser), 0)) + 1
    return merged


def _filter_source_category(rows: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    category = normalize_source_category(params.get("source_category") or params.get("source"))
    if not category or category == "Memory":
        return rows
    return [row for row in rows if str(row.get("source_category") or (row.get("raw") or {}).get("source_category") or "") == category]


def search_around_event(case_id: str, event_id: str, *, window: str = "30m", page_size: int = 100) -> dict[str, Any]:
    source = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None)
    if not source:
        raise HTTPException(status_code=404, detail="Event not found")
    timestamp = _parse_time(str(source.get("@timestamp") or ""))
    if not timestamp:
        raise HTTPException(status_code=400, detail="Event does not have a searchable timestamp")
    delta = _parse_window(window)
    params = {
        "scope": "events",
        "time_from": (timestamp - delta).isoformat(),
        "time_to": (timestamp + delta).isoformat(),
        "evidence_id": source.get("evidence_id"),
        "sort": "timestamp_asc",
        "page_size": page_size,
        "include_facets": False,
        "include_highlights": False,
    }
    response = search_case_v2(None, case_id, params) if False else None
    total, results, warnings, _ = search_events_v2(case_id, params)
    return {"query": {"around_event_id": event_id, "window": window}, "total": total, "page_size": page_size, "next_cursor": None, "results": results, "facets": {}, "warnings": warnings}


def search_related_to_finding(db: Session, case_id: str, finding_id: str, *, page_size: int = 100) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if not finding or finding.case_id != case_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    should: list[dict[str, Any]] = []
    direct_ids = _dedupe((finding.related_event_ids or []) + (finding.event_ids or []))
    if direct_ids:
        should.append({"terms": {"event_id": direct_ids}})
    for path in _dedupe(finding.related_files or [])[:5]:
        should.extend(_build_should_terms(PATH_FIELDS + FILENAME_FIELDS, path, wildcard=True))
    for domain in _dedupe(finding.related_domains or [])[:5]:
        should.extend(_build_should_terms(DOMAIN_FIELDS, domain, wildcard=True))
    for ip in _dedupe(finding.related_ips or [])[:5]:
        should.extend(_build_should_terms(IP_FIELDS, ip))
    for host in _dedupe(finding.related_hosts or [])[:5]:
        should.append({"term": {"host.name": host}})
    for user in _dedupe(finding.related_users or [])[:5]:
        should.append({"term": {"user.name": user}})
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return {"query": {"finding_id": finding_id}, "total": 0, "page_size": page_size, "next_cursor": None, "results": [], "facets": {}, "warnings": []}
    body = {
        "size": max(25, min(page_size, 200)),
        "query": {
            "bool": {
                "filter": [{"term": {"case_id": case_id}}],
                "should": should or [{"terms": {"event_id": direct_ids}}],
                "minimum_should_match": 1,
            }
        },
        "sort": EVENT_SORTS["timestamp_desc"],
        "track_total_hits": min(10000, max(page_size * 10, 500)),
    }
    result = client.search(index=index, body=body, params={"ignore_unavailable": "true"}, request_timeout=SEARCH_REQUEST_TIMEOUT_SECONDS)
    rows = [_format_event_result(hit) for hit in result.get("hits", {}).get("hits", [])]
    total_meta = result.get("hits", {}).get("total", 0)
    total = int(total_meta.get("value", 0) if isinstance(total_meta, dict) else total_meta)
    return {"query": {"finding_id": finding_id}, "total": total, "page_size": page_size, "next_cursor": None, "results": rows, "facets": _facet_counts(rows), "warnings": []}


def _json_list_contains(column: Any, value: str) -> Any:
    escaped = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace('"', '\\"')
    return cast(column, String).like(f'%"{escaped}"%', escape="\\")


def _serialize_context_detection(item: DetectionResult) -> dict[str, Any]:
    return {
        "id": item.id,
        "rule_name": item.rule_name,
        "rule_title": item.rule_title,
        "severity": item.severity,
        "status": item.status,
        "engine": item.source_engine or item.engine,
        "event_id": item.event_id,
    }


def _serialize_context_finding(item: Finding) -> dict[str, Any]:
    return {
        "id": item.id,
        "title": item.title,
        "severity": item.severity.value if hasattr(item.severity, "value") else str(item.severity or ""),
        "status": item.status.value if hasattr(item.status, "value") else str(item.status or ""),
        "finding_type": item.finding_type,
        "risk_score": item.risk_score,
    }


def event_context(db: Session, case_id: str, event_id: str) -> dict[str, Any]:
    source = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=None) or {}
    source, _ = _preserve_suspicious_timestamp(dict(source))
    event = dict(source.get("event") or {})
    artifact = dict(source.get("artifact") or {})
    host = dict(source.get("host") or {})
    user = dict(source.get("user") or {})
    process = dict(source.get("process") or {})
    parent = dict(process.get("parent") or {})
    windows = dict(source.get("windows") or {})
    evidence_id = str(source.get("evidence_id") or "").strip() or None
    stable_event_id = str(source.get("stable_event_id") or source.get("event_fingerprint") or "").strip()
    event_ids = _dedupe([event_id, str(source.get("event_id") or ""), stable_event_id])

    detection_matchers: list[Any] = [DetectionResult.event_id.in_(event_ids), DetectionResult.opensearch_id.in_(event_ids)]
    for value in event_ids:
        detection_matchers.append(_json_list_contains(DetectionResult.related_event_ids, value))
    detection_query = (
        db.query(DetectionResult)
        .filter(DetectionResult.case_id == case_id, DetectionResult.deleted_at.is_(None), DetectionResult.status.notin_(["stale", "stale_event_link"]))
        .filter(or_(*detection_matchers))
    )
    detections = detection_query.order_by(DetectionResult.created_at.desc()).limit(5).all()

    finding_matchers: list[Any] = []
    for value in event_ids:
        finding_matchers.append(_json_list_contains(Finding.event_ids, value))
        finding_matchers.append(_json_list_contains(Finding.related_event_ids, value))
        if stable_event_id:
            finding_matchers.append(_json_list_contains(Finding.related_stable_event_ids, stable_event_id))
    finding_query = db.query(Finding).filter(Finding.case_id == case_id)
    if finding_matchers:
        finding_query = finding_query.filter(or_(*finding_matchers))
    else:
        finding_query = finding_query.filter(False)
    findings = finding_query.order_by(Finding.created_at.desc()).limit(5).all()

    timestamp_valid = bool(source.get("@timestamp"))
    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "available_context": {
            "timestamp": timestamp_valid,
            "host": host.get("name") or host.get("hostname"),
            "user": user.get("name"),
            "process": process.get("name"),
            "process_pid": process.get("pid"),
            "process_entity_id": process.get("entity_id") or process.get("guid"),
            "command_line": process.get("command_line"),
            "parent_process": process.get("parent_name") or parent.get("name"),
            "parent_pid": process.get("parent_pid") or parent.get("pid"),
            "parent_command_line": process.get("parent_command_line") or parent.get("command_line"),
            "source_file": source.get("source_file"),
            "artifact_type": artifact.get("type"),
            "parser": artifact.get("parser"),
            "event_id": source.get("event_id") or event.get("id"),
            "windows_event_id": windows.get("event_id") or event.get("id"),
        },
        "counts": {
            "related_detections": detection_query.count(),
            "related_findings": finding_query.count(),
        },
        "related_detections": [_serialize_context_detection(item) for item in detections],
        "related_findings": [_serialize_context_finding(item) for item in findings],
    }


def quick_filters() -> list[dict[str, Any]]:
    return QUICK_FILTERS


def build_search_v2_params(**kwargs: Any) -> dict[str, Any]:
    params = dict(kwargs)
    params["artifact_type"] = _dedupe(kwargs.get("artifact_type"))
    params["parser"] = _dedupe(kwargs.get("parser"))
    params["exclude_artifact_type"] = _dedupe(kwargs.get("exclude_artifact_type"))
    params["exclude_parser"] = _dedupe(kwargs.get("exclude_parser"))
    params["event_type"] = _dedupe(kwargs.get("event_type"))
    params["event_category"] = _dedupe(kwargs.get("event_category"))
    params["severity"] = _dedupe(kwargs.get("severity"))
    params["status"] = _dedupe(kwargs.get("status"))
    params["confidence"] = _dedupe(kwargs.get("confidence"))
    params["finding_type"] = _dedupe(kwargs.get("finding_type"))
    params["include_highlights"] = kwargs.get("include_highlights", True)
    params["include_facets"] = kwargs.get("include_facets", True)
    params["include_filesystem_timeline"] = bool(kwargs.get("include_filesystem_timeline", False))
    params["marked_only"] = bool(kwargs.get("marked_only", False))
    params["marked_has_note"] = bool(kwargs.get("marked_has_note", False))
    params["marked_in_finding"] = bool(kwargs.get("marked_in_finding", False))
    params["marking_status"] = str(kwargs.get("marking_status") or "").strip()
    return params
