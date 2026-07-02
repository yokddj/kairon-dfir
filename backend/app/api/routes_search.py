from copy import deepcopy
from datetime import UTC
from ipaddress import ip_address
import logging
import re
import time
from urllib.error import URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request as FastAPIRequest
from sqlalchemy.orm import Session

from dateutil import parser as date_parser

from app.core.app_settings import get_setting, set_setting
from app.core.app_settings import load_runtime_settings
from app.core.config import get_settings
from app.core.database import SessionLocal, get_db
from app.core.opensearch import count_documents, get_events_index, get_index_health, get_opensearch_client, index_exists, is_index_queryable, resolve_aggregatable_field
from app.models.evidence import Evidence
from app.schemas.event import SearchRequest, SearchResponse, SiemRequest
from app.ingest.normalization.field_quality import normalize_event_fields
from app.ingest.normalization.registry_modifications import enrich_registry_command_document, normalize_registry_modification_event
from app.ingest.powershell.entity_normalization import normalize_powershell_entities
from app.ingest.powershell.semantic_evtx import normalize_powershell_evtx_semantics
from app.services.host_identity import expand_host_filter, normalize_host_alias, resolve_canonical_host
from app.services.search_service import build_search_v2_params, event_context as event_context_v2, quick_filters as search_quick_filters, search_around_event as search_around_event_v2, search_case_v2, search_related_to_finding as search_related_to_finding_v2


router = APIRouter(tags=["search"])
logger = logging.getLogger(__name__)
settings = get_settings()
_FACETS_CACHE_TTL = 10.0
_FACETS_CACHE: dict[str, tuple[float, dict]] = {}
OPENSEARCH_DASHBOARDS_PUBLIC_URL_KEY = "OPENSEARCH_DASHBOARDS_PUBLIC_URL"

SORT_FIELD_MAP = {
    "@timestamp": "@timestamp",
    "timestamp": "@timestamp",
    "event.severity": "event.severity",
    "severity": "event.severity",
    "host.name": "host.name",
    "host": "host.name",
    "user.name": "user.name",
    "user": "user.name",
    "event.category": "event.category",
    "category": "event.category",
    "event.type": "event.type",
    "artifact.type": "artifact.type",
    "artifact.name": "artifact.name",
    "artifact": "artifact.type",
    "windows.event_id": "windows.event_id",
    "file.created": "file.created",
    "file.modified": "file.modified",
    "file.accessed": "file.accessed",
    "file.changed": "file.changed",
    "file.size": "file.size",
    "mft.entry_number": "mft.entry_number",
    "process.name": "process.name",
    "network.source_ip": "network.source_ip",
    "network.destination_ip": "network.destination_ip",
    "risk_score": "risk_score",
}
SIEM_FILTER_FIELDS = {
    "event.category",
    "event.type",
    "event.severity",
    "event.action",
    "artifact.type",
    "artifact.name",
    "artifact.parser",
    "host.name",
    "user.name",
    "process.name",
    "process.path",
    "process.command_line",
    "file.path",
    "file.name",
    "file.extension",
    "browser.domain",
    "browser.url",
    "browser.name",
    "browser.profile",
    "browser.artifact_type",
    "browser.search_terms",
    "execution.interpretation",
    "execution.confidence",
    "amcache.program_name",
    "amcache.publisher",
    "amcache.product_name",
    "shimcache.path",
    "appcompat.path",
    "srum.app_id",
    "srum.app_name",
    "srum.package_name",
    "srum.user_sid",
    "srum.interface_profile",
    "srum.network_profile",
    "powershell.command",
    "powershell.command_preview",
    "powershell.decoded_command_preview",
    "powershell.source_file",
    "powershell.urls",
    "powershell.domains",
    "powershell.paths",
    "powershell.indicators",
    "shellbag.path",
    "shellbag.absolute_path",
    "shellbag.bag_path",
    "shellbag.shell_type",
    "shellbag.hive_path",
    "shellbag.source_file",
    "jumplist.app_id",
    "jumplist.app_name",
    "jumplist.app_id_description",
    "jumplist.effective_path",
    "jumplist.target_path",
    "jumplist.local_path",
    "jumplist.common_path",
    "jumplist.relative_path",
    "jumplist.arguments",
    "jumplist.working_directory",
    "jumplist.source_file",
    "jumplist.stream_name",
    "jumplist.parse_method",
    "jumplist.drive_serial_number",
    "jumplist.machine_id",
    "usb.device_instance_id",
    "usb.raw_instance_id",
    "usb.vendor",
    "usb.product",
    "usb.revision",
    "usb.serial",
    "usb.vid",
    "usb.pid",
    "usb.friendly_name",
    "usb.container_id",
    "usb.parent_id_prefix",
    "usb.class_guid",
    "usb.class_name",
    "usb.service",
    "usb.driver",
    "usb.inf_path",
    "bits.job_id",
    "bits.job_guid",
    "bits.display_name",
    "bits.owner",
    "bits.owner_sid",
    "bits.state",
    "bits.type",
    "bits.priority",
    "bits.remote_name",
    "bits.remote_url",
    "bits.local_name",
    "bits.local_path",
    "bits.notify_cmd_line",
    "bits.error_code",
    "bits.error_description",
    "bits.source_file",
    "bits.raw_qmgr_path",
    "bits.parser_status",
    "cloud.provider",
    "cloud.account",
    "cloud.account_email",
    "cloud.sync_root",
    "cloud.local_path",
    "cloud.remote_path",
    "cloud.cloud_path",
    "cloud.status",
    "cloud.sync_status",
    "cloud.source_file",
    "autoruns.category",
    "autoruns.entry_location",
    "autoruns.entry",
    "autoruns.profile",
    "autoruns.publisher",
    "autoruns.company",
    "autoruns.signer",
    "autoruns.image_path",
    "autoruns.launch_string",
    "autoruns.command_line",
    "autoruns.hash_md5",
    "autoruns.hash_sha1",
    "autoruns.hash_sha256",
    "autoruns.vt_link",
    "autoruns.user",
    "autoruns.sid",
    "autoruns.source_file",
    "persistence.mechanism",
    "persistence.location",
    "persistence.name",
    "persistence.command",
    "persistence.path",
    "wmi.namespace",
    "wmi.class_name",
    "wmi.name",
    "wmi.filter_name",
    "wmi.consumer_name",
    "wmi.query",
    "wmi.command_line_template",
    "wmi.script_preview",
    "wmi.executable_path",
    "wmi.creator_sid",
    "wmi.source_file",
    "volume.guid",
    "volume.drive_letter",
    "volume.serial",
    "volume.mounted_device",
    "volume.dos_device",
    "network.share_name",
    "network.destination_hostname",
    "recycle.original_path",
    "recycle.original_file_name",
    "recycle.sid",
    "recycle.pair_id",
    "download.target_path",
    "download.file_name",
    "detection.threat_name",
    "detection.threat_id",
    "detection.path",
    "detection.resource",
    "detection.action",
    "detection.status",
    "detection.category",
    "detection.user_sid",
    "threat.name",
    "threat.id",
    "defender.action",
    "defender.severity",
    "defender.path",
    "url.domain",
    "url.full",
    "network.source_ip",
    "network.destination_ip",
    "windows.event_id",
    "windows.channel",
    "windows.provider",
    "windows.logon_type",
    "windows.service_name",
    "windows.task_name",
    "tags",
}
TEXT_SEARCH_FIELDS = [
    "process.command_line^5",
    "process.parent.command_line^4",
    "process.parent_command_line^4",
    "search_text^3",
    "key_entity^3",
    "file.path^3",
    "object.name^3",
    "defender.path^3",
    "threat.name^3",
    "event.message^2",
    "raw_summary^2",
    "registry.path^2",
    "dns.question.name^2",
    "url.full^2",
    "url.domain^2",
    "source_file",
]
COMMAND_KEYWORD_FIELDS = [
    "search_text.wildcard",
    "file.path",
    "file.name",
    "process.executable",
    "process.path",
    "process.name",
    "process.parent.executable",
    "process.parent.path",
    "process.parent.name",
    "object.name",
    "object.path",
    "registry.path",
    "dns.question.name",
    "dns.query",
    "dns.domain",
    "url.full",
    "url.domain",
    "network.domain",
    "browser.domain",
    "browser.url",
    "download.target_path",
    "download.file_name",
    "source_file",
    "key_entity",
    "threat.name",
    "defender.path",
    "detection.threat_name",
    "detection.path",
    "shortcut.target_path",
    "lnk.target_path",
    "jumplist.target_path",
    "amcache.file_path",
    "shimcache.path",
]
FACET_FIELDS = {
    "artifact.type": "artifact.type",
    "artifact.parser": "artifact.parser",
    "artifact.name": "artifact.name",
    "event.category": "event.category",
    "event.type": "event.type",
    "event.severity": "event.severity",
    "tags": "tags",
    "host.name": "host.name",
    "user.name": "user.name",
    "evidence_id": "evidence_id",
}
FACET_ALIASES = {
    "artifact.type": "artifact_type",
    "artifact.parser": "parser",
    "artifact.name": "artifact_name",
    "event.category": "event_category",
    "event.type": "event_type",
    "event.severity": "severity",
    "host.name": "host",
    "user.name": "user",
}
TIMELINE_LOW_VALUE_TYPES = {"file_observed", "generic_record", "process_observed"}
SIEM_HISTORY_KEY = "SIEM_QUERY_HISTORY"


def _empty_search_facets() -> dict:
    facets = {key: {} for key in FACET_FIELDS}
    for source_key, alias in FACET_ALIASES.items():
        facets[alias] = dict(facets.get(source_key) or {})
    return facets


def _same_host_family(left: str | None, right: str | None) -> bool:
    left_norm = normalize_host_alias(left)
    right_norm = normalize_host_alias(right)
    if not left_norm or not right_norm:
        return False
    left_aliases = {left_norm, left_norm.split(".", 1)[0]}
    right_aliases = {right_norm, right_norm.split(".", 1)[0]}
    return bool(left_aliases & right_aliases)


def _canonical_host_facet_key(db: Session, case_id: str | None, evidence_id: str | None, host: str) -> str:
    if not case_id:
        return host
    query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if evidence_id:
        query = query.filter(Evidence.id == evidence_id)
    for evidence in query.all():
        metadata = dict(evidence.metadata_json or {})
        provided = str(metadata.get("provided_host") or "").strip()
        detected = str(metadata.get("detected_host") or evidence.detected_host or "").strip()
        if provided and (_same_host_family(host, provided) or _same_host_family(host, detected)):
            return provided
    resolved = resolve_canonical_host(db, case_id, host)
    if resolved:
        return str(resolved.get("canonical_name") or host)
    return host


def _group_host_facet(db: Session, case_id: str | None, evidence_id: str | None, values: dict[str, int]) -> dict[str, int]:
    grouped: dict[str, int] = {}
    for host, count in values.items():
        key = _canonical_host_facet_key(db, case_id, evidence_id, host)
        grouped[key] = grouped.get(key, 0) + int(count or 0)
    return dict(sorted(grouped.items(), key=lambda item: item[1], reverse=True))
SIEM_SAVED_SEARCHES_KEY = "SIEM_SAVED_SEARCHES"


def _dedupe_text(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(text)
    return output


def _host_query_variants(*values: str | None) -> list[str]:
    variants: list[str | None] = []
    for value in values:
        normalized = normalize_host_alias(value)
        raw = str(value or "").strip()
        if raw:
            variants.append(raw)
        if normalized:
            variants.extend([normalized, normalized.upper()])
            short = normalized.split(".", 1)[0]
            if short:
                variants.extend([short, short.upper()])
    return _dedupe_text(variants)


def _evidence_aliases_for_host_filter(db: Session | None, case_id: str | None, values: list[str]) -> tuple[list[str], list[str]]:
    if not db or not case_id or not values:
        return [], []
    wanted = {normalize_host_alias(value) for value in values if normalize_host_alias(value)}
    wanted |= {item.split(".", 1)[0] for item in list(wanted) if item and "." in item}
    aliases: list[str] = []
    evidence_ids: list[str] = []
    if not wanted:
        return [], []
    for evidence in db.query(Evidence).filter(Evidence.case_id == case_id).all():
        metadata = dict(evidence.metadata_json or {})
        evidence_values = [
            metadata.get("provided_host"),
            metadata.get("detected_host"),
            evidence.detected_host,
        ]
        normalized_values = {normalize_host_alias(value) for value in evidence_values if normalize_host_alias(value)}
        normalized_values |= {item.split(".", 1)[0] for item in list(normalized_values) if item and "." in item}
        if normalized_values & wanted:
            evidence_ids.append(str(evidence.id))
            aliases.extend(_host_query_variants(*evidence_values))
    return _dedupe_text(aliases), _dedupe_text(evidence_ids)


def _build_host_filter(case_id: str | None, values: list[str], db: Session | None = None) -> dict:
    expanded: list[str] = []
    for value in values:
        resolved_values = expand_host_filter(db, case_id, value) if db and case_id else [value]
        expanded.extend(_host_query_variants(*resolved_values, value))
    evidence_aliases, evidence_ids = _evidence_aliases_for_host_filter(db, case_id, expanded)
    expanded = _dedupe_text([*expanded, *evidence_aliases])
    fields = ["host.name", "host.hostname", "host.canonical", "host.aliases", "observed_host.name", "observed_host.hostname"]
    should: list[dict] = [
        {"terms": {"host.name": expanded}},
        {"terms": {"observed_host.name": expanded}},
    ]
    wildcard_aliases = _dedupe_text([*expanded, *[f"{alias}.*" for alias in expanded if "." not in alias]])
    should.extend(
        {"wildcard": {field: {"value": f"{_escape_wildcard_term(alias[:-2])}.*" if alias.endswith(".*") else _escape_wildcard_term(alias), "case_insensitive": True}}}
        for field in fields
        for alias in wildcard_aliases
    )
    if evidence_ids:
        should.append({"bool": {"filter": [{"terms": {"evidence_id": evidence_ids}}], "must_not": [{"exists": {"field": "host.name"}}]}})
        should.append({"bool": {"filter": [{"terms": {"evidence_id": evidence_ids}}, {"term": {"host.name": "-"}}]}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _normalize_time_filter(value: str | None, timezone_name: str | None) -> str | None:
    if not value:
        return None
    parsed = date_parser.parse(value)
    if parsed.tzinfo is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name or "UTC"))
        except ZoneInfoNotFoundError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown timezone: {timezone_name}") from exc
    return parsed.astimezone(UTC).isoformat()


def _load_json_setting(key: str, default: list | dict) -> list | dict:
    db = SessionLocal()
    try:
        value = get_setting(db, key, default)
    finally:
        db.close()
    return value if isinstance(value, type(default)) else default


def _save_json_setting(key: str, value: list | dict) -> None:
    db = SessionLocal()
    try:
        set_setting(db, key, value)
    finally:
        db.close()


def _resolve_index(payload_case_id: str | None) -> str:
    return get_events_index(payload_case_id)


def _http_available(url: str) -> tuple[bool, str | None]:
    try:
        request = Request(url, headers={"User-Agent": "dfir-platform"})
        with urlopen(request, timeout=5) as response:  # noqa: S310
            if 200 <= getattr(response, "status", 200) < 500:
                return True, None
        return False, "Unexpected HTTP status"
    except URLError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _dashboards_status(case_id: str | None = None) -> dict:
    enabled = bool(settings.opensearch_dashboards_enabled)
    internal_url = settings.opensearch_dashboards_internal_url.rstrip("/")
    public_url = settings.opensearch_dashboards_public_url.rstrip("/")
    available, error = _http_available(internal_url) if enabled else (False, "OpenSearch Dashboards integration disabled")
    return {
        "enabled": enabled,
        "internal_url": internal_url,
        "public_url": public_url,
        "index_pattern": settings.opensearch_dashboards_index_pattern,
        "time_field": settings.opensearch_dashboards_time_field,
        "available": available if enabled else False,
        "error": error,
        "case_filter": f'case_id:"{case_id}"' if case_id else "",
    }


def _dashboard_host_needs_rewrite(hostname: str | None, request_hostname: str | None) -> bool:
    normalized = (hostname or "").strip().lower()
    request_normalized = (request_hostname or "").strip().lower()
    if not normalized:
        return False
    if normalized in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "opensearch-dashboards"}:
        return True
    if request_normalized and normalized == request_normalized:
        return False
    try:
        parsed_ip = ip_address(normalized)
    except ValueError:
        return "." not in normalized and normalized != request_normalized
    return bool((parsed_ip.is_loopback or parsed_ip.is_unspecified) or (parsed_ip.is_private and normalized != request_normalized))


def _configured_dashboards_public_url(db: Session | None = None) -> str:
    if db is None:
        return settings.opensearch_dashboards_public_url.rstrip("/")
    value = str(get_setting(db, OPENSEARCH_DASHBOARDS_PUBLIC_URL_KEY, settings.opensearch_dashboards_public_url) or "").strip()
    return value.rstrip("/")


def _resolve_dashboards_public_url(request: FastAPIRequest | None = None, db: Session | None = None) -> str:
    public_url = _configured_dashboards_public_url(db)
    if not public_url:
        if request is None:
            return ""
        request_hostname = request.url.hostname or ""
        default_port = urlsplit(settings.opensearch_dashboards_internal_url).port or 5601
        netloc = request_hostname if not default_port else f"{request_hostname}:{default_port}"
        return urlunsplit((request.url.scheme, netloc, "", "", "")).rstrip("/")
    if request is None:
        return public_url
    parsed = urlsplit(public_url)
    request_hostname = request.url.hostname or ""
    if not _dashboard_host_needs_rewrite(parsed.hostname, request_hostname):
        return public_url
    port = parsed.port
    netloc = request_hostname if not port else f"{request_hostname}:{port}"
    return urlunsplit((request.url.scheme, netloc, parsed.path.rstrip("/"), "", "")).rstrip("/")


def _dashboards_discover_url(
    *,
    request: FastAPIRequest | None = None,
    db: Session | None = None,
    case_id: str | None = None,
    query: str | None = None,
    artifact_type: str | None = None,
    event_id: str | None = None,
) -> str:
    public_url = _resolve_dashboards_public_url(request, db)
    clauses: list[str] = []
    if case_id:
        clauses.append(f'case_id:"{case_id}"')
    if artifact_type:
        clauses.append(f'artifact.type:"{artifact_type}"')
    if event_id:
        clauses.append(f'event_id:"{event_id}"')
    if query:
        clauses.append(f"({query})")
    query_string = " AND ".join(clauses) if clauses else "*"
    # Use a Discover deep link that is explicit about the DFIR data view and
    # hides the chart. This avoids malformed JSON `_a` state and works around
    # a Dashboards crash path where the top histogram request fails and the UI
    # still dereferences missing aggregations.
    query_rison = query_string.replace("!", "!!").replace("'", "!'")
    app_state = (
        "(columns:!(_source),"
        "hideChart:!t,"
        "index:'dfir-events',"
        "interval:auto,"
        f"query:(language:kuery,query:'{query_rison}'),"
        "sort:!(!('@timestamp',desc)))"
    )
    return f"{public_url}/app/discover#/?_a={quote(app_state, safe='')}"


def _escape_wildcard_term(value: str) -> str:
    return re.sub(r"([*?\\\\])", r"\\\1", value)


def _query_looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.strip()))


def _query_looks_like_hash(value: str) -> bool:
    value = value.strip()
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value))


def _query_looks_like_url(value: str) -> bool:
    value = value.strip().lower()
    return value.startswith(("http://", "https://")) or "/" in value or "." in value


def _query_looks_like_windows_path(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", value.strip()))


def _query_looks_like_event_id(value: str) -> bool:
    normalized = value.strip()
    return bool(re.fullmatch(r"\d{1,6}", normalized))


def _strip_balanced_quotes(value: str) -> str:
    text = value.strip()
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
        or "/" in text
        or re.search(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|lnk|iso|zip|7z|rar|msi|scr|pif)\b", lower)
        or re.search(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", lower)
    )


def _query_variants_for_command(value: str) -> list[str]:
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
    basename_source = text.replace("\\", "/").rstrip("/")
    basename = basename_source.rsplit("/", 1)[-1].strip()
    if basename and basename != text and basename not in variants:
        variants.append(basename)
        lowered = basename.lower()
        if lowered not in variants:
            variants.append(lowered)
    return variants[:10]


def _build_command_like_query(query: str) -> dict:
    value = _strip_balanced_quotes(query)
    should: list[dict] = [
        {"multi_match": {"query": value, "fields": TEXT_SEARCH_FIELDS, "operator": "and", "type": "best_fields"}},
        {"multi_match": {"query": value, "fields": TEXT_SEARCH_FIELDS, "type": "phrase", "slop": 3}},
    ]
    for variant in _query_variants_for_command(value):
        escaped = _escape_wildcard_term(variant.lower())
        if len(escaped) > 128:
            continue
        should.extend(
            {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}
            for field in COMMAND_KEYWORD_FIELDS
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _build_ioc_query(query: str) -> dict:
    value = query.strip()
    if not value:
        return {"match_all": {}}
    should: list[dict] = []
    if _query_looks_like_event_id(value):
        should.append({"term": {"windows.event_id": int(value)}})
    if _query_looks_like_hash(value):
        should.extend(
            [
                {"term": {"file.md5": value}},
                {"term": {"file.sha1": value}},
                {"term": {"file.sha256": value}},
            ]
        )
    if _query_looks_like_ip(value):
        should.extend(
            [
                {"term": {"network.source_ip": value}},
                {"term": {"network.destination_ip": value}},
                {"term": {"host.ip": value}},
            ]
        )
    if _query_looks_like_windows_path(value):
        should.extend(
            [
                {"wildcard": {"file.path": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
                {"wildcard": {"process.path": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
            ]
        )
    if "." in value:
        should.extend(
            [
                {"wildcard": {"file.name": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
                {"wildcard": {"browser.domain": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
                {"wildcard": {"network.domain": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
            ]
        )
    if _query_looks_like_url(value):
        should.extend(
            [
                {"wildcard": {"browser.url": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
                {"wildcard": {"network.url": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}},
                {"wildcard": {"search_text.wildcard": {"value": f"*{_escape_wildcard_term(value.lower())}*", "case_insensitive": True}}},
            ]
        )
    if not should:
        should.append({"simple_query_string": {"query": value, "fields": TEXT_SEARCH_FIELDS, "default_operator": "and"}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _build_text_query(payload: SearchRequest) -> dict:
    query = (payload.query or "").strip()
    if not query or query == "*":
        return {"match_all": {}}
    mode = payload.search_mode
    if mode == "ioc":
        return _build_ioc_query(query)
    if mode == "exact":
        if _query_looks_like_event_id(query):
            return _build_ioc_query(query)
        return {"multi_match": {"query": query, "type": "phrase", "fields": TEXT_SEARCH_FIELDS}}
    if mode == "contains":
        if _query_looks_like_event_id(query):
            return _build_ioc_query(query)
        if len(query) > 128:
            raise HTTPException(status_code=400, detail="Contains queries must be 128 characters or fewer.")
        escaped = _escape_wildcard_term(query.lower())
        return {
            "bool": {
                "should": [
                    {"wildcard": {"search_text.wildcard": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"file.name": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"file.path": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"artifact.name": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"process.name": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"browser.domain": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"browser.search_terms": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"download.file_name": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"download.target_path": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"url.domain": {"value": f"*{escaped}*", "case_insensitive": True}}},
                {"wildcard": {"network.domain": {"value": f"*{escaped}*", "case_insensitive": True}}},
            ],
                "minimum_should_match": 1,
            }
        }
    if any(char in query for char in "*?"):
        return {"query_string": {"query": query, "fields": TEXT_SEARCH_FIELDS, "default_operator": "AND"}}
    if _query_looks_command_like(query):
        return _build_command_like_query(query)
    if _query_looks_like_event_id(query) or _query_looks_like_hash(query) or _query_looks_like_ip(query) or _query_looks_like_windows_path(query):
        return _build_ioc_query(query)
    return {"multi_match": {"query": query, "fields": TEXT_SEARCH_FIELDS, "operator": "and", "type": "best_fields"}}


def _recommended_view(artifact_types: set[str], categories: set[str]) -> str:
    if len(artifact_types) == 1:
        artifact_type = next(iter(artifact_types))
        if artifact_type in {"mft", "usn"}:
            return "filesystem"
        if artifact_type == "evtx":
            return "evtx"
        if artifact_type in {"amcache", "shimcache", "appcompat"}:
            return "execution_artifacts"
        if artifact_type == "srum":
            return "srum"
        if artifact_type == "registry":
            return "registry"
        if artifact_type == "cloud_sync":
            return "cloud_sync"
        if artifact_type in {"autoruns", "autorun"}:
            return "autoruns"
        if artifact_type == "browser":
            return "browser"
        if artifact_type in {"defender", "detection"}:
            return "defender"
        if artifact_type == "powershell":
            return "powershell"
        if artifact_type == "recycle_bin":
            return "recycle_bin"
    if len(categories) == 1:
        category = next(iter(categories))
        if category == "registry":
            return "registry"
        if category == "persistence":
            if "cloud_sync" in artifact_types:
                return "cloud_sync"
            return "autoruns" if {"autoruns", "autorun"} & artifact_types else "persistence"
        if category == "execution":
            return "execution"
        if category == "detection":
            return "defender"
        if category == "powershell":
            return "powershell"
        if category == "browser":
            return "browser"
        if category in {"web", "file_transfer"}:
            return "browser"
        if category == "network":
            return "network"
        if category in {"persistence", "service", "scheduled_task"}:
            return "persistence"
        if category in {"file", "filesystem"}:
            return "filesystem"
        if category in {"windows_event", "logon", "authentication", "remote_access"}:
            return "evtx"
    return "generic"


def _build_result_profile(payload: SearchRequest, items: list[dict]) -> dict:
    artifact_types = {
        str(((item.get("artifact") or {}) if isinstance(item, dict) else {}).get("type") or "").lower()
        for item in items
        if str(((item.get("artifact") or {}) if isinstance(item, dict) else {}).get("type") or "").strip()
    }
    categories = {
        str(((item.get("event") or {}) if isinstance(item, dict) else {}).get("category") or "").lower()
        for item in items
        if str(((item.get("event") or {}) if isinstance(item, dict) else {}).get("category") or "").strip()
    }
    if len(payload.filters.artifact_type) == 1:
        artifact_types = {payload.filters.artifact_type[0].lower()}
    if len(payload.filters.event_category) == 1:
        categories = {payload.filters.event_category[0].lower()}
    recommended = _recommended_view(artifact_types, categories)
    return {
        "is_homogeneous": recommended != "generic",
        "artifact_types": sorted(artifact_types),
        "event_categories": sorted(categories),
        "recommended_view": recommended,
    }


def _index_available(index: str) -> bool:
    client = get_opensearch_client()
    return index_exists(client, index)


def _cache_get(cache: dict[str, tuple[float, dict]], key: str, ttl_seconds: float) -> dict | None:
    item = cache.get(key)
    if not item:
        return None
    expires_at, value = item
    if expires_at < time.monotonic():
        cache.pop(key, None)
        return None
    return deepcopy(value)


def _cache_put(cache: dict[str, tuple[float, dict]], key: str, ttl_seconds: float, value: dict) -> dict:
    cache[key] = (time.monotonic() + ttl_seconds, deepcopy(value))
    return value


def build_search_query(payload: SearchRequest, timeline: bool = False, db: Session | None = None) -> dict:
    filters = []
    registry_command_requested = any(str(value).lower() == "registry_command" for value in (payload.filters.artifact_type or []))
    registry_event_requested = any(str(value).lower() == "registry_event" for value in (payload.filters.artifact_type or []))
    def _expand_artifact_types(values: list[str] | None) -> list[str]:
        expanded: list[str] = []
        for value in values or []:
            lowered = str(value).lower()
            expanded.append(lowered)
            if lowered == "defender":
                expanded.append("detection")
            elif lowered == "detection":
                expanded.append("defender")
            elif lowered == "autorun":
                expanded.append("autoruns")
            elif lowered == "autoruns":
                expanded.append("autorun")
            elif lowered == "user_activity":
                expanded.extend(["shellbag", "userassist", "recentdocs", "runmru", "opensavemru"])
            elif lowered in {"shellbag", "userassist", "recentdocs", "runmru", "opensavemru"}:
                expanded.append("user_activity")
            elif lowered == "registry_command":
                expanded.extend(["windows_event", "powershell", "evtx"])
            elif lowered == "registry_event":
                expanded.extend(["windows_event", "evtx", "registry_event"])
        return sorted(set(expanded))
    if payload.case_id:
        filters.append({"term": {"case_id": payload.case_id}})
    if payload.filters.artifact_type:
        filters.append({"terms": {"artifact.type": _expand_artifact_types(payload.filters.artifact_type)}})
        if registry_command_requested:
            filters.append(
                {
                    "bool": {
                        "filter": [
                            {
                                "query_string": {
                                    "query": r'("reg add" OR "reg delete" OR "reg import" OR "reg load" OR "reg unload" OR Set-ItemProperty OR New-ItemProperty OR Remove-ItemProperty)',
                                    "fields": ["process.command_line", "powershell.command", "powershell.command_preview", "search_text"],
                                    "default_operator": "OR",
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {"wildcard": {field: {"value": pattern, "case_insensitive": True}}}
                                        for field in ["process.command_line", "powershell.command", "powershell.command_preview", "search_text"]
                                        for pattern in ["*HKLM\\\\*", "*HKCU\\\\*", "*HKU\\\\*", "*HKLM:\\\\*", "*HKCU:\\\\*", "*Registry::HKEY_LOCAL_MACHINE\\\\*", "*Registry::HKEY_CURRENT_USER\\\\*", "*HKEY_LOCAL_MACHINE\\\\*", "*HKEY_CURRENT_USER\\\\*", "*HKEY_USERS\\\\*"]
                                    ],
                                    "minimum_should_match": 1,
                                }
                            },
                        ]
                    }
                }
            )
        if registry_event_requested:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "filter": [
                                        {"terms": {"windows.event_id": [12, 13, 14]}},
                                        {
                                            "bool": {
                                                "should": [
                                                    {"wildcard": {"event.provider": {"value": "*sysmon*", "case_insensitive": True}}},
                                                    {"wildcard": {"windows.provider": {"value": "*sysmon*", "case_insensitive": True}}},
                                                    {"wildcard": {"event.channel": {"value": "*sysmon*", "case_insensitive": True}}},
                                                    {"wildcard": {"windows.channel": {"value": "*sysmon*", "case_insensitive": True}}},
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                            {"terms": {"windows.event_id": [4657]}},
                            {"term": {"artifact.type": "registry_event"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
    if payload.filters.artifact_name:
        filters.append({"terms": {"artifact.name": payload.filters.artifact_name}})
    if payload.filters.event_category:
        filters.append({"terms": {"event.category": payload.filters.event_category}})
    if payload.filters.tags:
        filters.append({"terms": {"tags": payload.filters.tags}})
    if payload.filters.host:
        filters.append(_build_host_filter(payload.case_id, payload.filters.host, db))
    if payload.filters.user:
        filters.append({"terms": {"user.name": payload.filters.user}})
    if payload.filters.parser:
        filters.append({"terms": {"artifact.parser": payload.filters.parser}})
    backend_variants = {str(value).strip().lower() for value in payload.filters.backend_variant if str(value).strip()}
    if payload.filters.parser_backend:
        filters.append({"terms": {"artifact.parser_backend": payload.filters.parser_backend}})
    if backend_variants and "all" not in backend_variants:
        filters.append({"terms": {"artifact.backend_variant": sorted(backend_variants)}})
    if payload.filters.source_file:
        filters.append(
            {
                "bool": {
                    "should": [
                        {"terms": {"source_file": payload.filters.source_file}},
                        *[
                            {"wildcard": {"source_file": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}}
                            for value in payload.filters.source_file
                        ],
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    if payload.filters.severity:
        filters.append({"terms": {"event.severity": payload.filters.severity}})
    if payload.filters.event_type:
        filters.append({"terms": {"event.type": payload.filters.event_type}})
    if payload.filters.evidence_id:
        filters.append({"terms": {"evidence_id": payload.filters.evidence_id}})
    if payload.filters.event_id:
        numeric_event_ids = [int(item) for item in payload.filters.event_id if _query_looks_like_event_id(str(item))]
        non_numeric_event_ids = [str(item) for item in payload.filters.event_id if not _query_looks_like_event_id(str(item))]
        event_id_should: list[dict] = []
        if numeric_event_ids:
            event_id_should.append({"terms": {"windows.event_id": numeric_event_ids}})
        if non_numeric_event_ids:
            event_id_should.append({"terms": {"event_id": non_numeric_event_ids}})
        if event_id_should:
            filters.append({"bool": {"should": event_id_should, "minimum_should_match": 1}})
    if payload.filters.activity:
        filters.append({"terms": {"event.action": payload.filters.activity}})
    if payload.filters.deleted_only:
        filters.append({"term": {"file.deleted": "true"}})
    if payload.filters.in_use_only:
        filters.append({"term": {"mft.in_use": True}})
    if payload.filters.has_path is True:
        filters.append({"exists": {"field": "file.path"}})
    if payload.filters.has_path is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "file.path"}}]}})
    if payload.filters.suspicious_paths_only:
        filters.append({"term": {"tags": "suspicious_path"}})
    if payload.filters.extension:
        filters.append({"terms": {"file.extension": payload.filters.extension}})
    if payload.filters.has_timestamp is True:
        filters.append({"exists": {"field": "@timestamp"}})
    if payload.filters.has_timestamp is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "@timestamp"}}]}})
    if payload.filters.time_from or payload.filters.time_to:
        range_filter = {}
        if payload.filters.time_from:
            range_filter["gte"] = _normalize_time_filter(payload.filters.time_from, payload.timezone)
        if payload.filters.time_to:
            range_filter["lte"] = _normalize_time_filter(payload.filters.time_to, payload.timezone)
        filters.append({"range": {"@timestamp": range_filter}})
    selected_timeline_artifact_types: set[str] = set()
    timeline_includes_filesystem = False
    if timeline:
        selected_timeline_artifact_types = set(_expand_artifact_types(payload.filters.artifact_type))
        timeline_includes_filesystem = (
            "mft" in selected_timeline_artifact_types
            or "filesystem" in selected_timeline_artifact_types
            or payload.include_filesystem_timeline
        )
    if timeline and not payload.include_undated:
        filters.append({"exists": {"field": "@timestamp"}})
    if timeline and not payload.include_low_value and not timeline_includes_filesystem:
        filters.append({"bool": {"must_not": [{"terms": {"event.type": list(TIMELINE_LOW_VALUE_TYPES)}}]}})
    if timeline:
        filters.append({"bool": {"should": [{"term": {"event.timeline_include": True}}, {"bool": {"must_not": [{"exists": {"field": "event.timeline_include"}}]}}], "minimum_should_match": 1}})
        if not timeline_includes_filesystem:
            filters.append({"bool": {"must_not": [{"term": {"artifact.type": "mft"}}]}})
    if timeline and not payload.include_low_confidence_timestamps:
        filters.append({"bool": {"must_not": [{"term": {"timestamp_precision": "unknown"}}]}})
    must = [_build_text_query(payload)]
    must_not = []
    if not backend_variants and not payload.filters.parser_backend:
        must_not.append({"term": {"artifact.backend_variant": "advanced"}})
    if payload.filters.exclude_artifact_type:
        must_not.append({"terms": {"artifact.type": _expand_artifact_types(payload.filters.exclude_artifact_type)}})
    if payload.filters.exclude_host:
        must_not.append(_build_host_filter(payload.case_id, payload.filters.exclude_host, db))
    if payload.filters.exclude_user:
        must_not.append({"terms": {"user.name": payload.filters.exclude_user}})
    if payload.filters.exclude_parser:
        must_not.append({"terms": {"artifact.parser": payload.filters.exclude_parser}})
    if payload.filters.exclude_source_file:
        must_not.append(
            {
                "bool": {
                    "should": [
                        {"terms": {"source_file": payload.filters.exclude_source_file}},
                        *[
                            {"wildcard": {"source_file": {"value": f"*{_escape_wildcard_term(value)}*", "case_insensitive": True}}}
                            for value in payload.filters.exclude_source_file
                        ],
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    if payload.filters.exclude_query.strip():
        must_not.append(_build_text_query(payload.model_copy(update={"query": payload.filters.exclude_query})))
    sort_field = SORT_FIELD_MAP.get(payload.sort_by)
    if not sort_field:
        raise HTTPException(status_code=400, detail=f"Unsupported sort field: {payload.sort_by}")
    sort_order = "asc" if payload.sort_order == "asc" else "desc"
    if timeline and payload.sort_by in {"@timestamp", "timestamp"}:
        sort_order = "asc"
    return {
        "from": (payload.page - 1) * payload.page_size,
        "size": payload.page_size,
        "query": {"bool": {"must": must, "filter": filters, **({"must_not": must_not} if must_not else {})}},
        "sort": [{sort_field: {"order": sort_order, "missing": "_last"}}],
    }


def run_search(payload: SearchRequest, timeline: bool = False) -> SearchResponse:
    client = get_opensearch_client()
    index = _resolve_index(payload.case_id)
    db = SessionLocal()
    try:
        runtime_settings = load_runtime_settings(db)
        max_page_size = min(int(runtime_settings.get("SEARCH_MAX_PAGE_SIZE", payload.page_size)), 200)
        if payload.page_size > max_page_size:
            raise HTTPException(status_code=400, detail=f"Requested page_size exceeds SEARCH_MAX_PAGE_SIZE ({max_page_size}).")
        if not _index_available(index):
            return SearchResponse(total=0, page=payload.page, page_size=payload.page_size, total_pages=0, items=[])
        if not is_index_queryable(client, index):
            raise HTTPException(status_code=503, detail=f"Index {index} is not queryable right now (health={get_index_health(client, index)}). Please retry shortly.")
        from_value = (payload.page - 1) * payload.page_size
        result_window_limit = 10000
        if from_value + payload.page_size > result_window_limit:
            raise HTTPException(status_code=400, detail="Deep pagination beyond 10,000 results is not supported yet. Narrow your filters or implement export/search_after.")
        body = build_search_query(payload, timeline=timeline, db=db)
        body["track_total_hits"] = True
        try:
            result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {exc}") from exc
    finally:
        db.close()
    hits = result["hits"]["hits"]
    total_meta = result["hits"]["total"]
    if isinstance(total_meta, dict):
        total = total_meta["value"]
        total_relation = total_meta.get("relation", "eq")
    else:
        total = total_meta
        total_relation = "eq"
    total_pages = (total + payload.page_size - 1) // payload.page_size if total else 0
    total_pages_visible = min(total_pages, result_window_limit // payload.page_size if payload.page_size else 0)
    items = [_normalize_search_item({"id": hit["_id"], **hit["_source"]}) for hit in hits]
    return SearchResponse(
        total=total,
        total_relation=total_relation,
        has_more=total_relation != "eq",
        page=payload.page,
        page_size=payload.page_size,
        total_pages=total_pages,
        total_pages_visible=total_pages_visible,
        deep_pagination_supported=False,
        result_window_limit=result_window_limit,
        has_more_beyond_window=total > result_window_limit,
        result_profile=_build_result_profile(payload, items),
        items=items,
    )


def _normalize_search_item(item: dict) -> dict:
    artifact = item.get("artifact") if isinstance(item.get("artifact"), dict) else {}
    if str(artifact.get("type") or "").lower() == "powershell":
        item = normalize_powershell_evtx_semantics(normalize_powershell_entities(item))
    item = normalize_registry_modification_event(item)
    item = enrich_registry_command_document(item)
    return normalize_event_fields(item)


def build_siem_query(payload: SiemRequest) -> dict:
    sort_field = SORT_FIELD_MAP.get(payload.sort_by)
    if not sort_field:
        raise HTTPException(status_code=400, detail=f"Unsupported sort field: {payload.sort_by}")
    sort_order = "asc" if payload.sort_order == "asc" else "desc"
    base = {"from": (payload.page - 1) * payload.page_size, "size": payload.page_size, "sort": [{sort_field: {"order": sort_order, "missing": "_last"}}]}
    if payload.mode == "dsl":
        body = deepcopy(payload.dsl or {})
        body.setdefault("from", base["from"])
        body.setdefault("size", base["size"])
        body.setdefault("sort", base["sort"])
        if payload.case_id:
            existing_query = body.get("query", {"match_all": {}})
            body["query"] = {"bool": {"filter": [{"term": {"case_id": payload.case_id}}], "must": [existing_query]}}
        return body
    filters = [{"term": {"case_id": payload.case_id}}] if payload.case_id else []
    if payload.time_from or payload.time_to:
        range_filter = {}
        if payload.time_from:
            range_filter["gte"] = _normalize_time_filter(payload.time_from, payload.timezone)
        if payload.time_to:
            range_filter["lte"] = _normalize_time_filter(payload.time_to, payload.timezone)
        filters.append({"range": {"@timestamp": range_filter}})
    for filter_item in payload.filters:
        if filter_item.field not in SIEM_FILTER_FIELDS:
            raise HTTPException(status_code=400, detail=f"Unsupported SIEM filter field: {filter_item.field}")
        operator = (filter_item.operator or "eq").lower()
        value = filter_item.value
        if operator == "eq":
            filters.append({"term": {filter_item.field: value}})
        elif operator == "neq":
            filters.append({"bool": {"must_not": [{"term": {filter_item.field: value}}]}})
        elif operator == "exists":
            filters.append({"exists": {"field": filter_item.field}})
        elif operator == "not_exists":
            filters.append({"bool": {"must_not": [{"exists": {"field": filter_item.field}}]}})
        elif operator in {"gte", "lte"}:
            filters.append({"range": {filter_item.field: {operator: value}}})
        elif operator == "contains":
            filters.append({"wildcard": {filter_item.field: {"value": f"*{_escape_wildcard_term(str(value))}*", "case_insensitive": True}}})
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported SIEM filter operator: {filter_item.operator}")
    must = [{"query_string": {"query": payload.query or "*", "default_operator": "AND"}}]
    if ":" not in (payload.query or "") and payload.query not in {"*", ""}:
        must = [{"simple_query_string": {"query": payload.query or "*", "default_operator": "and"}}]
    return {**base, "query": {"bool": {"must": must, "filter": filters}}}


def run_siem_query(payload: SiemRequest) -> SearchResponse:
    client = get_opensearch_client()
    index = _resolve_index(payload.case_id)
    db = SessionLocal()
    runtime_settings = load_runtime_settings(db)
    db.close()
    max_page_size = min(int(runtime_settings.get("SEARCH_MAX_PAGE_SIZE", payload.page_size)), 200)
    if payload.page_size > max_page_size:
        raise HTTPException(status_code=400, detail=f"Requested page_size exceeds SEARCH_MAX_PAGE_SIZE ({max_page_size}).")
    if not _index_available(index):
        return SearchResponse(total=0, page=payload.page, page_size=payload.page_size, total_pages=0, items=[])
    result_window_limit = 10000
    from_value = (payload.page - 1) * payload.page_size
    if from_value + payload.page_size > result_window_limit:
        raise HTTPException(status_code=400, detail="This query goes beyond the OpenSearch result window. Use narrower filters, export, or search_after deep pagination.")
    body = build_siem_query(payload)
    body["track_total_hits"] = True
    try:
        result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SIEM query failed: {exc}") from exc
    hits = result["hits"]["hits"]
    total_meta = result["hits"]["total"]
    if isinstance(total_meta, dict):
        total = total_meta["value"]
        total_relation = total_meta.get("relation", "eq")
    else:
        total = total_meta
        total_relation = "eq"
    total_pages = (total + payload.page_size - 1) // payload.page_size if total else 0
    total_pages_visible = min(total_pages, result_window_limit // payload.page_size if payload.page_size else 0)
    items = [{"id": hit["_id"], **hit["_source"]} for hit in hits]
    return SearchResponse(
        total=total,
        total_relation=total_relation,
        has_more=total_relation != "eq",
        page=payload.page,
        page_size=payload.page_size,
        total_pages=total_pages,
        total_pages_visible=total_pages_visible,
        deep_pagination_supported=False,
        result_window_limit=result_window_limit,
        has_more_beyond_window=total > result_window_limit,
        result_profile=_build_result_profile(SearchRequest(case_id=payload.case_id, query=payload.query, search_mode="smart"), items),
        items=items,
    )


@router.get("/api/search/facets")
def search_facets(case_id: str | None = None, evidence_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    client = get_opensearch_client()
    index = _resolve_index(case_id)
    if not _index_available(index):
        return _empty_search_facets()
    cache_key = f"{index}:{case_id or 'all'}:{evidence_id or 'all'}"
    cached = _cache_get(_FACETS_CACHE, cache_key, _FACETS_CACHE_TTL)
    if cached is not None:
        return cached
    if not is_index_queryable(client, index):
        logger.warning("Skipping facet computation for %s because index health is %s", index, get_index_health(client, index))
        return _empty_search_facets()
    scope_filters = []
    if case_id:
        scope_filters.append({"term": {"case_id": case_id}})
    if evidence_id:
        scope_filters.append({"term": {"evidence_id": evidence_id}})
    facets = {}
    for key, field in FACET_FIELDS.items():
        resolved_field = resolve_aggregatable_field(client, index, field)
        if not resolved_field:
            facets[key] = {}
            continue
        bucket_key = key.replace(".", "_")
        body = {"size": 0, "aggs": {bucket_key: {"terms": {"field": resolved_field, "size": 100}}}}
        if scope_filters:
            body["query"] = {"bool": {"filter": scope_filters}}
        try:
            result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
            facets[key] = {
                str(item.get("key") or "").strip(): int(item.get("doc_count") or 0)
                for item in result.get("aggregations", {}).get(bucket_key, {}).get("buckets", [])
                if str(item.get("key") or "").strip()
            }
            if key == "host.name":
                facets[key] = _group_host_facet(db, case_id, evidence_id, facets[key])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not compute facets for %s using %s: %s", key, resolved_field, exc)
            facets[key] = {}
    for source_key, alias in FACET_ALIASES.items():
        facets.setdefault(alias, dict(facets.get(source_key) or {}))
    return _cache_put(_FACETS_CACHE, cache_key, _FACETS_CACHE_TTL, facets)


@router.post("/api/search", response_model=SearchResponse)
def search_events(payload: SearchRequest) -> SearchResponse:
    return run_search(payload, timeline=False)


@router.get("/api/cases/{case_id}/search")
def search_case_events_and_findings(
    case_id: str,
    q: str = Query(default=""),
    exclude_q: str = Query(default=""),
    filters: str | None = Query(default=None),
    scope: str = Query(default="all"),
    evidence_id: str | None = Query(default=None),
    artifact_type: list[str] | None = Query(default=None),
    parser: list[str] | None = Query(default=None),
    exclude_artifact_type: list[str] | None = Query(default=None),
    exclude_parser: list[str] | None = Query(default=None),
    event_type: list[str] | None = Query(default=None),
    event_category: list[str] | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    risk_min: int | None = Query(default=None),
    risk_max: int | None = Query(default=None),
    status: list[str] | None = Query(default=None),
    confidence: list[str] | None = Query(default=None),
    finding_type: list[str] | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    exclude_host: str | None = Query(default=None),
    exclude_user: str | None = Query(default=None),
    process_name: str | None = Query(default=None),
    source_file: str | None = Query(default=None),
    source_category: str | None = Query(default=None),
    source: str | None = Query(default=None),
    exclude_source_file: str | None = Query(default=None),
    file_name: str | None = Query(default=None),
    file_path: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    hash: str | None = Query(default=None),
    url: str | None = Query(default=None),
    suspicious_reason: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    marked_only: bool = Query(default=False),
    marking_status: str | None = Query(default=None),
    marked_has_note: bool = Query(default=False),
    marked_in_finding: bool = Query(default=False),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    sort: str = Query(default="timestamp_desc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    include_highlights: bool = Query(default=True),
    include_facets: bool = Query(default=True),
    include_filesystem_timeline: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    params = build_search_v2_params(
        q=q,
        exclude_q=exclude_q,
        filters=filters,
        scope=scope,
        evidence_id=evidence_id,
        artifact_type=artifact_type,
        parser=parser,
        exclude_artifact_type=exclude_artifact_type,
        exclude_parser=exclude_parser,
        event_type=event_type,
        event_category=event_category,
        severity=severity,
        risk_min=risk_min,
        risk_max=risk_max,
        status=status,
        confidence=confidence,
        finding_type=finding_type,
        host=host,
        user=user,
        exclude_host=exclude_host,
        exclude_user=exclude_user,
        process_name=process_name,
        source_file=source_file,
        exclude_source_file=exclude_source_file,
        file_name=file_name,
        file_path=file_path,
        domain=domain,
        ip=ip,
        hash=hash,
        url=url,
        suspicious_reason=suspicious_reason,
        tag=tag,
        marked_only=marked_only,
        marking_status=marking_status,
        marked_has_note=marked_has_note,
        marked_in_finding=marked_in_finding,
        time_from=time_from,
        time_to=time_to,
        sort=sort,
        page=page,
        page_size=page_size,
        cursor=cursor,
        include_highlights=include_highlights,
        include_facets=include_facets,
        include_filesystem_timeline=include_filesystem_timeline,
    )
    params["source_category"] = source_category or source
    return search_case_v2(db, case_id, params)


@router.get("/api/cases/{case_id}/search/quick-filters")
def case_search_quick_filters(case_id: str) -> dict:
    return {"case_id": case_id, "items": search_quick_filters()}


@router.get("/api/cases/{case_id}/search/around-event/{event_id}")
def search_around_event(case_id: str, event_id: str, window: str = Query(default="30m"), page_size: int = Query(default=100, ge=1, le=200)) -> dict:
    return search_around_event_v2(case_id, event_id, window=window, page_size=page_size)


@router.get("/api/cases/{case_id}/search/related-to-finding/{finding_id}")
def search_related_to_finding(case_id: str, finding_id: str, page_size: int = Query(default=100, ge=1, le=200), db: Session = Depends(get_db)) -> dict:
    return search_related_to_finding_v2(db, case_id, finding_id, page_size=page_size)


@router.get("/api/cases/{case_id}/events/{event_id}/context")
def get_event_context(case_id: str, event_id: str, db: Session = Depends(get_db)) -> dict:
    return event_context_v2(db, case_id, event_id)


@router.get("/api/cases/{case_id}/search/entity")
def search_by_entity(
    case_id: str,
    type: str = Query(alias="type"),
    value: str = Query(alias="value"),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    params = build_search_v2_params(scope="events", page_size=page_size)
    normalized_type = type.strip().lower()
    if normalized_type == "file":
        params["file_path"] = value
    elif normalized_type == "domain":
        params["domain"] = value
    elif normalized_type == "ip":
        params["ip"] = value
    elif normalized_type == "user":
        params["user"] = value
    elif normalized_type == "host":
        params["host"] = value
    elif normalized_type == "process":
        params["process_name"] = value
    else:
        params["q"] = value
    return search_case_v2(db, case_id, params)


@router.post("/api/timeline", response_model=SearchResponse)
def timeline_events(payload: SearchRequest) -> SearchResponse:
    return run_search(payload, timeline=True)


@router.post("/api/siem", response_model=SearchResponse)
def siem_query(payload: SiemRequest) -> SearchResponse:
    return run_siem_query(payload)


@router.get("/api/siem/fields")
def siem_fields(case_id: str | None = None, sample_size: int = 25) -> dict:
    client = get_opensearch_client()
    index = _resolve_index(case_id)
    facets = search_facets(case_id)
    indexed_fields: list[dict] = []
    normalized_fields = [
        "event.category",
        "event.type",
        "event.action",
        "event.severity",
        "artifact.type",
        "artifact.name",
        "artifact.parser",
        "host.name",
        "user.name",
        "process.name",
        "process.command_line",
        "process.path",
        "file.path",
        "file.name",
        "file.extension",
        "windows.event_id",
        "windows.channel",
        "windows.provider",
        "windows.logon_type",
        "windows.service_name",
        "windows.task_name",
        "network.source_ip",
        "network.destination_ip",
        "tags",
    ]
    if _index_available(index):
        try:
            mapping = client.indices.get_mapping(index=index)
            properties = next(iter(mapping.values())).get("mappings", {}).get("properties", {})
            for field_name in normalized_fields:
                resolved = resolve_aggregatable_field(client, index, field_name)
                sample_values = facets.get(field_name, [])
                field_type = "unknown"
                cursor = properties
                for part in field_name.split("."):
                    cursor = (cursor.get(part) or {}).get("properties", {}) if isinstance(cursor, dict) and part in cursor and "properties" in cursor.get(part, {}) else (cursor.get(part) if isinstance(cursor, dict) else {})
                    if isinstance(cursor, dict) and cursor.get("type"):
                        field_type = str(cursor.get("type"))
                indexed_fields.append(
                    {
                        "name": field_name,
                        "type": field_type,
                        "searchable": True,
                        "aggregatable": resolved is not None,
                        "sample_values": sample_values[:5],
                    }
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not inspect SIEM fields for %s: %s", index, exc)
    raw_fields_sample: list[dict] = []
    if _index_available(index):
        try:
            result = client.search(index=index, body={"size": sample_size, "_source": ["raw"]}, params={"ignore_unavailable": "true"})
            counts: dict[str, int] = {}
            values: dict[str, list[str]] = {}
            for hit in result.get("hits", {}).get("hits", []):
                raw = (hit.get("_source") or {}).get("raw") or {}
                if isinstance(raw, dict):
                    for key, value in raw.items():
                        counts[key] = counts.get(key, 0) + 1
                        if len(values.setdefault(key, [])) < 3 and value is not None:
                            values[key].append(str(value)[:120])
            raw_fields_sample = [
                {"name": f"raw.{name}", "count": count, "sample_values": values.get(name, []), "searchable": False, "aggregatable": False}
                for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build raw SIEM sample fields for %s: %s", index, exc)
    return {
        "indexed_fields": indexed_fields,
        "normalized_fields": [
            {
                "name": field,
                "type": "known_normalized",
                "searchable": True,
                "aggregatable": resolve_aggregatable_field(client, index, field) is not None if _index_available(index) else False,
                "sample_values": facets.get(field, [])[:5],
            }
            for field in normalized_fields
        ],
        "raw_fields_sample": raw_fields_sample[:100],
        "unmapped_raw_fields": [],
        "missing_common_fields": [],
        "message": "Raw fields are visible in event details but are not indexed/searchable unless mapped into normalized fields.",
    }


@router.get("/api/siem/external/status")
def siem_external_status(request: FastAPIRequest, case_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    payload = _dashboards_status(case_id)
    payload["public_url"] = _resolve_dashboards_public_url(request, db)
    return payload


@router.post("/api/siem/external/setup")
def siem_external_setup(request: FastAPIRequest, db: Session = Depends(get_db)) -> dict:
    client = get_opensearch_client()
    index_pattern = settings.opensearch_dashboards_index_pattern
    matching_indices = []
    try:
        matching_indices = list((client.indices.get(index=index_pattern, params={"ignore_unavailable": "true"}) or {}).keys())
    except Exception:  # noqa: BLE001
        matching_indices = []
    dashboards = _dashboards_status()
    dashboards["public_url"] = _resolve_dashboards_public_url(request, db)
    manual_steps = [
        f"Open OpenSearch Dashboards at {dashboards['public_url']}",
        f"Create a Data View / Index Pattern with title {settings.opensearch_dashboards_index_pattern}",
        f"Set time field to {settings.opensearch_dashboards_time_field}",
    ]
    return {
        "dashboards_available": dashboards["available"],
        "opensearch_indices_found": bool(matching_indices),
        "indices": matching_indices,
        "data_view_created": False,
        "data_view_exists": False,
        "manual_steps_required": True,
        "manual_steps": manual_steps,
    }


@router.get("/api/siem/external/diagnostics")
def siem_external_diagnostics(request: FastAPIRequest, case_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    client = get_opensearch_client()
    index_pattern = settings.opensearch_dashboards_index_pattern
    opensearch_available = True
    try:
        matching_indices = list((client.indices.get(index=index_pattern, params={"ignore_unavailable": "true"}) or {}).keys())
    except Exception:
        matching_indices = []
        opensearch_available = False
    try:
        count_info = count_documents(get_events_index(case_id), {"term": {"case_id": case_id}} if case_id else None)
    except Exception:
        count_info = {"count": 0, "relation": "eq", "source": "count_api"}
        opensearch_available = False
    dashboards = _dashboards_status(case_id)
    dashboards["public_url"] = _resolve_dashboards_public_url(request, db)
    return {
        "opensearch": {
            "available": opensearch_available,
            "indices": matching_indices,
            "docs_count": count_info["count"],
        },
        "dashboards": {
            "available": dashboards["available"],
            "public_url": dashboards["public_url"],
            "internal_url": dashboards["internal_url"],
            "data_view": {
                "exists": False,
                "title": settings.opensearch_dashboards_index_pattern,
                "time_field": settings.opensearch_dashboards_time_field,
            },
            "error": dashboards["error"],
        },
        "case": {
            "case_id": case_id,
            "events_count": count_info["count"],
            "filter": f'case_id:"{case_id}"' if case_id else "",
        },
    }


@router.get("/api/siem/external/links")
def siem_external_links(
    request: FastAPIRequest,
    db: Session = Depends(get_db),
    case_id: str | None = None,
    query: str | None = None,
    artifact_type: str | None = None,
    event_id: str | None = None,
    detection_id: str | None = None,
) -> dict:
    detection_filter = ""
    if detection_id:
        detection_filter = f'detection_id:"{detection_id}"'
    query_string = " AND ".join([part for part in [detection_filter, query] if part]) or None
    case_filter = f'case_id:"{case_id}"' if case_id else ""
    artifact_filter = f'artifact.type:"{artifact_type}"' if artifact_type else ""
    event_filter = f'event_id:"{event_id}"' if event_id else ""
    dashboards_public_url = _resolve_dashboards_public_url(request, db)
    return {
        "dashboards_home": dashboards_public_url,
        "discover_url": _dashboards_discover_url(request=request, db=db, case_id=case_id, query=query_string, artifact_type=artifact_type, event_id=event_id),
        "case_filter": case_filter,
        "kql_or_lucene_query": " AND ".join([part for part in [case_filter, artifact_filter, event_filter, query_string] if part]) or "*",
        "copyable_filters": {
            "case_id": case_filter,
            "artifact_type": artifact_filter,
            "event_id": event_filter,
        },
    }


@router.get("/api/siem/query-history")
def siem_query_history() -> list[dict]:
    history = _load_json_setting(SIEM_HISTORY_KEY, [])
    return history if isinstance(history, list) else []


@router.post("/api/siem/query-history")
def save_siem_query_history(payload: dict) -> list[dict]:
    history = _load_json_setting(SIEM_HISTORY_KEY, [])
    entry = {
        "query": payload.get("query", "*"),
        "mode": payload.get("mode", "query_string"),
        "case_id": payload.get("case_id"),
        "time_from": payload.get("time_from"),
        "time_to": payload.get("time_to"),
        "saved_at": payload.get("saved_at"),
    }
    history = [entry, *history[:19]]
    _save_json_setting(SIEM_HISTORY_KEY, history)
    return history


@router.get("/api/siem/saved-searches")
def siem_saved_searches() -> list[dict]:
    searches = _load_json_setting(SIEM_SAVED_SEARCHES_KEY, [])
    return searches if isinstance(searches, list) else []


@router.post("/api/siem/saved-searches")
def create_siem_saved_search(payload: dict) -> dict:
    searches = _load_json_setting(SIEM_SAVED_SEARCHES_KEY, [])
    entry = {
        "id": payload.get("id"),
        "name": payload.get("name"),
        "query": payload.get("query", "*"),
        "mode": payload.get("mode", "query_string"),
        "case_id": payload.get("case_id"),
        "time_from": payload.get("time_from"),
        "time_to": payload.get("time_to"),
        "dsl": payload.get("dsl"),
    }
    searches = [entry, *[item for item in searches if item.get("id") != entry["id"]]]
    _save_json_setting(SIEM_SAVED_SEARCHES_KEY, searches[:50])
    return entry


@router.delete("/api/siem/saved-searches/{search_id}")
def delete_siem_saved_search(search_id: str) -> dict:
    searches = _load_json_setting(SIEM_SAVED_SEARCHES_KEY, [])
    searches = [item for item in searches if item.get("id") != search_id]
    _save_json_setting(SIEM_SAVED_SEARCHES_KEY, searches)
    return {"status": "deleted"}
