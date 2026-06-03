from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any


FINGERPRINT_VERSION = "v1"
_EXTRACTED_PATH_RE = re.compile(r"^.*?[/\\](?:extracted|staging)[/\\]", re.IGNORECASE)
_WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:[/\\]")


@dataclass
class FingerprintResult:
    stable_event_id: str
    event_fingerprint: str
    version: str
    components: dict[str, Any]
    best_effort: bool


def _nested_get(payload: dict[str, Any], dotted: str) -> Any:
    current: Any = payload
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def canonicalize_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except Exception:  # noqa: BLE001
        return text


def canonicalize_path(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("\\", "/")
    if "/extracted/" in normalized.lower() or "/staging/" in normalized.lower():
        normalized = _EXTRACTED_PATH_RE.sub("", normalized)
    if _WINDOWS_DRIVE_RE.match(normalized):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    normalized = re.sub(r"/{2,}", "/", normalized)
    return normalized.lower() or None


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()
    return value


def _first_non_empty(payload: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested_get(payload, path)
        if value not in (None, "", [], {}):
            return value
    return None


def _event_locator(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    artifact_type = str(_nested_get(payload, "artifact.type") or "").strip().lower()
    parser_name = str(_nested_get(payload, "artifact.parser") or "").strip().lower()

    if artifact_type in {"evtx_raw", "evtx", "windows_event", "sysmon"} or "evtx" in parser_name:
        provider = _first_non_empty(payload, "windows.provider_name", "windows.provider", "event.provider")
        event_id = _first_non_empty(payload, "windows.event_id", "windows.event.code", "event.code")
        record_id = _first_non_empty(payload, "windows.event_record_id", "windows.record_id", "event.record_id")
        if record_id not in (None, ""):
            return "evtx_record", "|".join(str(part) for part in [provider or "", event_id or "", record_id])

    message_id = _first_non_empty(payload, "email.message_id")
    if message_id:
        mailbox = _first_non_empty(payload, "email.mailbox_name", "source_file")
        message_index = _first_non_empty(payload, "email.message_index")
        return "email_message", "|".join(str(part) for part in [mailbox or "", message_id, message_index or ""])

    ntfs_usn = _first_non_empty(payload, "ntfs.usn", "usn.usn")
    ntfs_reference = _first_non_empty(payload, "file.mft_reference", "usn.file_reference", "mft.reference_number", "mft.entry_number")
    if ntfs_usn or ntfs_reference:
        reason = _first_non_empty(payload, "ntfs.reason", "usn.reason", "event.type")
        return "ntfs_locator", "|".join(str(part) for part in [ntfs_usn or "", ntfs_reference or "", reason or ""])

    zone_host = _first_non_empty(payload, "ntfs.host_url", "url.full", "download.url")
    zone_id = _first_non_empty(payload, "ntfs.zone_id")
    zone_path = _first_non_empty(payload, "file.path")
    if zone_path and zone_id not in (None, ""):
        return "zone_identifier", "|".join(str(part) for part in [canonicalize_path(zone_path) or "", zone_id, zone_host or ""])

    registry_key = _first_non_empty(payload, "registry.key_path")
    registry_value = _first_non_empty(payload, "registry.value_name")
    if registry_key:
        return "registry_value", "|".join(str(part) for part in [registry_key, registry_value or "", _first_non_empty(payload, "user.sid", "user.name") or ""])

    process_guid = _first_non_empty(payload, "process.guid", "process.entity_id")
    if process_guid:
        return "process_guid", str(process_guid)

    process_path = _first_non_empty(payload, "process.path")
    process_cmd = _first_non_empty(payload, "process.command_line")
    process_pid = _first_non_empty(payload, "process.pid")
    if process_path or process_cmd:
        return "process_start", "|".join(
            str(part)
            for part in [
                canonicalize_path(process_path) or "",
                process_pid or "",
                process_cmd or "",
                canonicalize_timestamp(_first_non_empty(payload, "@timestamp")) or "",
            ]
        )

    browser_url = _first_non_empty(payload, "browser.url", "url.full", "download.url")
    browser_time = _first_non_empty(payload, "browser.visit_time", "download.start_time", "@timestamp")
    if browser_url:
        return "url_time", "|".join(str(part) for part in [browser_url, canonicalize_timestamp(browser_time) or ""])

    file_path = _first_non_empty(payload, "file.path", "download.target_path", "windows_search.indexed_path", "office.document_path")
    if file_path:
        return "file_path_time", "|".join(
            str(part)
            for part in [
                canonicalize_path(file_path) or "",
                _first_non_empty(payload, "event.type") or "",
                canonicalize_timestamp(_first_non_empty(payload, "@timestamp", "file.modified", "registry.last_write_time")) or "",
            ]
        )

    return None, None


def compute_event_fingerprint(event: dict[str, Any]) -> FingerprintResult:
    case_id = str(event.get("case_id") or "").strip()
    evidence_id = str(event.get("evidence_id") or "").strip()
    artifact_type = str(_nested_get(event, "artifact.type") or "").strip()
    parser_name = str(_nested_get(event, "artifact.parser") or "").strip()
    source_file = canonicalize_path(event.get("source_file") or _nested_get(event, "artifact.source_path"))
    timestamp = canonicalize_timestamp(event.get("@timestamp"))
    event_type = str(_nested_get(event, "event.type") or "").strip()
    host_name = str(_nested_get(event, "observed_host.name") or _nested_get(event, "host.name") or "").strip()

    locator_type, locator_value = _event_locator(event)
    primary_entity = _first_non_empty(
        event,
        "file.path",
        "process.path",
        "process.command_line",
        "registry.key_path",
        "email.message_id",
        "url.full",
        "dns.domain",
        "notification.title",
        "activity.activity_id",
    )
    secondary_entity = _first_non_empty(
        event,
        "file.name",
        "process.name",
        "registry.value_name",
        "email.subject",
        "ntfs.reason",
        "event.action",
    )
    components = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_type": artifact_type,
        "parser": parser_name,
        "source_file": source_file,
        "timestamp": timestamp,
        "event_type": event_type,
        "host_name": host_name or None,
        "locator_type": locator_type,
        "locator_value": _normalize_scalar(locator_value),
        "primary_entity": canonicalize_path(primary_entity) if isinstance(primary_entity, str) and ("/" in primary_entity or "\\" in primary_entity) else _normalize_scalar(primary_entity),
        "secondary_entity": canonicalize_path(secondary_entity) if isinstance(secondary_entity, str) and ("/" in secondary_entity or "\\" in secondary_entity) else _normalize_scalar(secondary_entity),
    }
    best_effort = not bool(locator_value)
    if best_effort:
        components["best_effort"] = True
    material = json.dumps(components, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()
    return FingerprintResult(
        stable_event_id=digest,
        event_fingerprint=digest,
        version=FINGERPRINT_VERSION,
        components=components,
        best_effort=best_effort,
    )


def apply_event_fingerprint(event: dict[str, Any]) -> dict[str, Any]:
    result = compute_event_fingerprint(event)
    event["stable_event_id"] = result.stable_event_id
    event["event_fingerprint"] = result.event_fingerprint
    event["event_fingerprint_version"] = result.version
    data_quality = list(event.get("data_quality") or [])
    if result.best_effort and "fingerprint_best_effort" not in data_quality:
        data_quality.append("fingerprint_best_effort")
    event["data_quality"] = data_quality
    return event
