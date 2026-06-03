from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import PureWindowsPath
import re
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.app_settings import get_setting
from app.core.opensearch import iter_case_events
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.debug_export import build_process_tree_bundle
from app.services.host_identity import expand_host_filter, normalize_host_alias, resolve_canonical_host


SUSPICIOUS_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"}
OFFICE_PROCESS_NAMES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SENSITIVE_KEYWORDS = {"password", "passwd", "secret", "credential", "token", "private", "backup", "wallet", "key", "dump", "database", "payroll", "invoice"}
SUSPICIOUS_FILENAME_KEYWORDS = {"payload", "invoice", "update", "installer", "setup", "crack", "keygen", "loader", "beacon"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".scr"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img", ".pst", ".ost", ".kdbx"}
USER_WRITABLE_MARKERS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\startup\\", "\\public\\")
CRITICAL_PERSISTENCE = {"ifeo_debugger", "winlogon_shell", "winlogon_userinit", "appinit_dll", "lsa_package", "wmi", "scheduled_task"}


def _nested_get(item: dict, dotted: str) -> Any:
    current: Any = item
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _parse_ts(value: object | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:  # noqa: BLE001
        return None


def _as_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _normalize_text(value: object | None) -> str:
    return str(value or "").strip()


def _normalize_path(value: object | None) -> str:
    text = _normalize_text(value).replace("/", "\\")
    return text.lower()


def _file_name(value: object | None) -> str:
    text = _normalize_text(value).replace("/", "\\")
    if not text:
        return ""
    try:
        return PureWindowsPath(text).name.lower()
    except Exception:  # noqa: BLE001
        return text.split("\\")[-1].lower()


def _extension(value: object | None) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    try:
        return PureWindowsPath(text).suffix.lower()
    except Exception:  # noqa: BLE001
        return ""


def _looks_sensitive_path(path: str | None) -> bool:
    lowered = _normalize_path(path)
    filename = _file_name(path)
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS) or any(keyword in filename for keyword in SENSITIVE_KEYWORDS)


def _is_user_writable(path: str | None) -> bool:
    lowered = _normalize_path(path)
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS)


def _is_suspicious_domain(domain: str | None) -> tuple[bool, list[str]]:
    lowered = _normalize_text(domain).lower().rstrip(".")
    if not lowered:
        return False, []
    reasons: list[str] = []
    if lowered.startswith("xn--"):
        reasons.append("Punycode domain observed")
    if any(token in lowered for token in ["duckdns", "no-ip", "ddns", "dyn", "ngrok", "pastebin", "raw", "payload", "invoice", "update", "installer", "crack", "keygen"]):
        reasons.append("Suspicious domain keyword or dynamic DNS provider")
    first_label = lowered.split(".", 1)[0]
    if len(lowered) >= 30:
        reasons.append("Long domain observed")
    if len(first_label) >= 20 and sum(ch.isdigit() for ch in first_label) >= 4:
        reasons.append("DGA-like domain observed")
    return bool(reasons), reasons


def _domain_from_url_text(value: str | None) -> str | None:
    text = _normalize_text(value)
    if not text:
        return None
    try:
        return urlparse(text).hostname
    except Exception:  # noqa: BLE001
        return None


def _match_paths(left: str | None, right: str | None) -> tuple[bool, bool]:
    left_norm = _normalize_path(left)
    right_norm = _normalize_path(right)
    if left_norm and right_norm and left_norm == right_norm:
        return True, False
    left_name = _file_name(left)
    right_name = _file_name(right)
    if left_name and right_name and left_name == right_name:
        return False, True
    return False, False


def _event_summary(event: dict) -> str:
    return _normalize_text(_nested_get(event, "event.message") or _nested_get(event, "event.type") or event.get("id"))


def _extract_event_path(event: dict) -> str | None:
    for dotted in [
        "process.path",
        "file.path",
        "download.target_path",
        "detection.path",
        "detection.resource",
        "cloud.local_path",
        "cloud.remote_path",
        "bits.local_path",
        "bits.remote_url",
        "persistence.path",
        "persistence.command",
    ]:
        value = _nested_get(event, dotted)
        if value not in (None, ""):
            return str(value)
    return None


def _extract_persistence_command(event: dict) -> str | None:
    for dotted in ["persistence.command", "persistence.path", "autoruns.command_line", "autoruns.image_path", "service.image_path", "task.action_path", "wmi.executable_path"]:
        value = _nested_get(event, dotted)
        if value not in (None, ""):
            return str(value)
    return None


def _extract_related_artifact_id(event: dict) -> str | None:
    value = event.get("artifact_id")
    return str(value) if value not in (None, "") else None


def _process_event(event: dict) -> bool:
    return str(_nested_get(event, "event.type") or "") == "process_start" and bool(_nested_get(event, "execution.is_execution_confirmed"))


def _prefetch_or_inventory_execution(event: dict) -> bool:
    artifact_type = str(_nested_get(event, "artifact.type") or "")
    if artifact_type not in {"prefetch", "amcache", "shimcache", "appcompat"}:
        return False
    return bool(_extract_event_path(event))


def _build_timeline(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda item: (_parse_ts(item.get("@timestamp")) or datetime.min.replace(tzinfo=UTC), str(item.get("id") or "")))
    timeline = []
    for event in ordered:
        timeline.append(
            {
                "timestamp": event.get("@timestamp"),
                "event_id": str(event.get("id") or event.get("event_id") or ""),
                "artifact_type": str(_nested_get(event, "artifact.type") or ""),
                "event_type": str(_nested_get(event, "event.type") or ""),
                "summary": _event_summary(event),
            }
        )
    return timeline


def _severity_from_score(score: int) -> FindingSeverity:
    if score >= 90:
        return FindingSeverity.critical
    if score >= 70:
        return FindingSeverity.high
    if score >= 40:
        return FindingSeverity.medium
    if score >= 20:
        return FindingSeverity.low
    return FindingSeverity.info


def _downgrade_confidence_level(value: str) -> str:
    normalized = str(value or "").lower()
    if normalized == "high":
        return "medium"
    if normalized == "medium":
        return "low"
    return normalized or "low"


def _make_fingerprint(case_id: str, finding_type: str, related_stable_event_ids: list[str], key_parts: list[str]) -> str:
    material = "|".join([case_id, finding_type, ",".join(sorted(set(related_stable_event_ids))), ",".join(sorted(set(part for part in key_parts if part)))])
    return hashlib.sha1(material.encode("utf-8", "ignore")).hexdigest()


def _base_finding(case_id: str, *, evidence_id: str | None, finding_type: str, title: str, summary: str, confidence: str, events: list[dict], reasons: list[str], tags: list[str], risk_score: int, related_process_node_ids: list[str] | None = None, related_files: list[str] | None = None, related_domains: list[str] | None = None, related_users: list[str] | None = None, related_hosts: list[str] | None = None, related_ips: list[str] | None = None, related_artifact_ids: list[str] | None = None, recommended_triage: list[str] | None = None, data_quality: list[str] | None = None, mitre: list[str] | None = None, key_parts: list[str] | None = None) -> dict:
    related_event_ids = [str(event.get("id") or event.get("event_id") or "") for event in events if event.get("id") or event.get("event_id")]
    related_stable_event_ids = [
        str(event.get("stable_event_id") or event.get("event_fingerprint") or event.get("event_id") or event.get("id") or "")
        for event in events
        if event.get("stable_event_id") or event.get("event_fingerprint") or event.get("event_id") or event.get("id")
    ]
    event_artifact_ids = [_extract_related_artifact_id(event) for event in events]
    time_values = [_parse_ts(event.get("@timestamp")) for event in events]
    parsed_times = [value for value in time_values if value is not None]
    timeline = _build_timeline(events)
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "finding_type": finding_type,
        "title": title,
        "description": summary,
        "severity": _severity_from_score(risk_score),
        "confidence": confidence,
        "status": FindingStatus.new,
        "query": None,
        "event_ids": related_event_ids,
        "detection_ids": [],
        "time_start": min(parsed_times) if parsed_times else None,
        "time_end": max(parsed_times) if parsed_times else None,
        "timeline": timeline,
        "related_event_ids": related_event_ids,
        "related_stable_event_ids": related_stable_event_ids,
        "related_artifact_ids": sorted({value for value in (related_artifact_ids or []) + [item for item in event_artifact_ids if item] if value}),
        "related_evidence_ids": sorted({str(event.get("evidence_id")) for event in events if event.get("evidence_id")} | ({evidence_id} if evidence_id else set())),
        "related_process_node_ids": sorted(set(related_process_node_ids or [])),
        "related_files": sorted(set(related_files or [])),
        "related_domains": sorted(set(related_domains or [])),
        "related_ips": sorted(set(related_ips or [])),
        "related_users": sorted(set(related_users or [str(_nested_get(event, "user.name") or "") for event in events if _nested_get(event, "user.name")])),
        "related_hosts": sorted(set(related_hosts or [str(_nested_get(event, "host.name") or "") for event in events if _nested_get(event, "host.name")])),
        "risk_score": risk_score,
        "reasons": list(dict.fromkeys(reason for reason in reasons if reason)),
        "tags": sorted(set(tags)),
        "mitre": list(dict.fromkeys(mitre or [])),
        "recommended_triage": list(dict.fromkeys(recommended_triage or [])),
        "source": "correlation_engine",
        "correlation_version": "v1",
        "data_quality": list(dict.fromkeys(data_quality or [])),
        "fingerprint": _make_fingerprint(case_id, finding_type, related_stable_event_ids, key_parts or []),
        "last_seen_at": max(parsed_times) if parsed_times else None,
        "occurrence_count": max(len(set(related_stable_event_ids)), 1),
    }


def _persist_findings(db: Session, findings: list[dict], *, preserve_status: bool = True, force_reset_status: bool = False) -> tuple[list[Finding], int]:
    if not findings:
        return [], 0
    existing = {
        item.fingerprint: item
        for item in db.query(Finding).filter(Finding.case_id == findings[0]["case_id"]).all()
        if item.fingerprint and item.source == "correlation_engine"
    }
    deduplicated = 0
    saved: list[Finding] = []
    preserve_states = {FindingStatus.reviewed, FindingStatus.confirmed, FindingStatus.dismissed, FindingStatus.false_positive, FindingStatus.closed}
    for payload in findings:
        current = existing.get(payload["fingerprint"])
        if current:
            deduplicated += 1
            current_status = getattr(current.status, "value", current.status)
            preserved_status = current.status if preserve_status and not force_reset_status and current_status in {
                status.value if hasattr(status, "value") else status for status in preserve_states
            } else payload["status"]
            for key, value in payload.items():
                if key == "status":
                    setattr(current, key, preserved_status)
                elif hasattr(current, key):
                    setattr(current, key, value)
            current.last_seen_at = payload.get("last_seen_at")
            current.occurrence_count = max(int(current.occurrence_count or 0), int(payload.get("occurrence_count") or 1))
            saved.append(current)
            continue
        item = Finding(**payload)
        db.add(item)
        saved.append(item)
    db.commit()
    for item in saved:
        db.refresh(item)
    return saved, deduplicated


def _remove_stale_correlation_findings(
    db: Session,
    *,
    case_id: str,
    evidence_id: str | None,
    case_evidence_ids: set[str] | None,
    active_fingerprints: set[str],
) -> int:
    query = db.query(Finding).filter(Finding.case_id == case_id, Finding.source == "correlation_engine")

    def _matches_scope(item: Finding) -> bool:
        if not evidence_id:
            return True
        if item.evidence_id == evidence_id:
            return True
        related_evidence_ids = {str(value) for value in (item.related_evidence_ids or []) if value}
        if evidence_id in related_evidence_ids:
            return True
        if not item.evidence_id and not related_evidence_ids and case_evidence_ids and len(case_evidence_ids) == 1 and evidence_id in case_evidence_ids:
            return True
        return False

    stale_items = [
        item
        for item in query.all()
        if _matches_scope(item) and item.fingerprint and item.fingerprint not in active_fingerprints
    ]
    for item in stale_items:
        db.delete(item)
    if stale_items:
        db.commit()
    return len(stale_items)


def _dedupe_text(values: list[str | None]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = normalize_host_alias(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _host_query_variants(*values: str | None) -> list[str]:
    variants: list[str | None] = []
    for value in values:
        normalized = normalize_host_alias(value)
        if not normalized:
            continue
        variants.extend([normalized, normalized.upper()])
        if "." in normalized:
            short = normalized.split(".", 1)[0]
            variants.extend([short, short.upper()])
        else:
            variants.append(f"{normalized}.*")
    return _dedupe_text(variants)


def _evidence_host_values(evidence: Evidence) -> list[str]:
    metadata = dict(evidence.metadata_json or {})
    return [
        str(value)
        for value in [
            metadata.get("provided_host"),
            metadata.get("detected_host"),
            evidence.detected_host,
            evidence.original_filename,
        ]
        if value
    ]


def _evidence_matches_host(evidence: Evidence, host_aliases: set[str]) -> bool:
    if not host_aliases:
        return True
    values = set(_host_query_variants(*_evidence_host_values(evidence)))
    return bool(values.intersection(host_aliases))


def _host_filter_query(evidence_id: str | None, host_aliases: list[str], evidence_ids: list[str]) -> dict | None:
    filters: list[dict] = []
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    elif evidence_ids:
        filters.append({"terms": {"evidence_id": evidence_ids}})
    if host_aliases:
        fields = ["host.name", "host.hostname", "host.canonical", "host.aliases", "observed_host.name", "observed_host.hostname"]
        should: list[dict] = [
            {"terms": {"host.name": host_aliases}},
            {"terms": {"observed_host.name": host_aliases}},
        ]
        should.extend(
            {"wildcard": {field: {"value": alias, "case_insensitive": True}}}
            for field in fields
            for alias in host_aliases
        )
        filters.append({"bool": {"should": should, "minimum_should_match": 1}})
    if not filters:
        return None
    return {"bool": {"filter": filters}}


def _event_matches_host(event: dict, host_aliases: set[str]) -> bool:
    if not host_aliases:
        return True
    values = _host_query_variants(
        str(_nested_get(event, "host.name") or ""),
        str(_nested_get(event, "host.hostname") or ""),
        str(_nested_get(event, "host.canonical") or ""),
        str(_nested_get(event, "observed_host.name") or ""),
        str(_nested_get(event, "observed_host.hostname") or ""),
    )
    return bool(set(values).intersection(host_aliases))


def _iter_events_for_case(
    case_id: str,
    evidence_id: str | None = None,
    *,
    host_aliases: list[str] | None = None,
    host_evidence_ids: list[str] | None = None,
    max_docs: int = 100000,
) -> list[dict]:
    aliases = _dedupe_text(host_aliases or [])
    query = _host_filter_query(evidence_id, aliases, host_evidence_ids or [])
    events = list(iter_case_events(case_id, query=query, max_docs=max_docs))
    if aliases:
        alias_set = set(aliases)
        events = [event for event in events if _event_matches_host(event, alias_set) or (str(event.get("evidence_id") or "") in set(host_evidence_ids or []) and not _event_host(event))]
    return events


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(value or "unknown" for value in values).items()))


def _event_artifact_type(event: dict) -> str:
    return str(_nested_get(event, "artifact.type") or event.get("artifact_type") or "unknown")


def _event_host(event: dict) -> str:
    return str(_nested_get(event, "host.name") or event.get("host") or "unknown")


def _display_host(value: object | None) -> str:
    normalized = normalize_host_alias(str(value or ""))
    if not normalized:
        return "unknown"
    return normalized.split(".", 1)[0].upper()


def _resolve_effective_host_scope(db: Session, case_id: str, host: str | None) -> dict[str, Any]:
    raw_host = str(host or "").strip()
    if not raw_host:
        return {"raw_host": None, "canonical_host": None, "host_aliases": [], "resolved": None}
    resolved = resolve_canonical_host(db, case_id, raw_host)
    canonical_host = str((resolved or {}).get("canonical_name") or normalize_host_alias(raw_host) or raw_host).strip()
    expanded = expand_host_filter(db, case_id, raw_host)
    aliases = _host_query_variants(*expanded, raw_host, canonical_host)
    return {
        "raw_host": raw_host,
        "canonical_host": canonical_host,
        "host_aliases": aliases,
        "resolved": resolved,
    }


def _correlation_cache_key(case_id: str, *, evidence_id: str | None, canonical_host: str | None, page: int, page_size: int, finding_types: list[str] | None) -> str:
    material = {
        "case_id": case_id,
        "evidence_id": evidence_id or "",
        "canonical_host": normalize_host_alias(canonical_host) or "",
        "page": page,
        "page_size": page_size,
        "finding_types": sorted(finding_types or []),
        "version": "correlation-host-scope-v1",
    }
    return hashlib.sha256(repr(sorted(material.items())).encode("utf-8")).hexdigest()[:24]


def _correlation_max_events(db: Session) -> int:
    try:
        return max(1, int(get_setting(db, "CORRELATION_MAX_EVENTS", 20000) or 20000))
    except Exception:  # noqa: BLE001
        return 20000


def _paginate_findings(findings: list[Finding], *, page: int, page_size: int) -> list[Finding]:
    start = max(page - 1, 0) * page_size
    return findings[start : start + page_size]


def _finding_recommended_triage(finding_type: str) -> list[str]:
    mapping = {
        "download_execute_detect": ["review process tree for the executed file", "review DNS/SRUM around execution", "review persistence related to the file", "review cleanup/deletion artifacts"],
        "office_powershell": ["review full Office child process chain", "review PowerShell script block or command line", "review DNS/SRUM around PowerShell execution"],
        "powershell_network": ["review PowerShell command line and script blocks", "review DNS domains and SRUM outbound bytes", "review downloaded or detected files around the same window"],
        "persistence_execution": ["review the persistence mechanism source", "review process tree for matching binary", "review author and signer of the persisted binary"],
        "cloud_exfil_candidate": ["review cloud item path and sync root", "review suspicious process activity before upload", "review whether the item was shared externally"],
        "usb_exfil_candidate": ["review USB device metadata and mount time", "review file creation/modification near connection", "review cloud or recycle activity in the same window"],
        "execution_cleanup": ["review executed file lineage", "review Defender alerts around execution", "review MFT/Recycle deletion timing"],
        "suspicious_process_chain": ["review the full process tree chain", "review source events for parent and child nodes", "review adjacent network and detection signals"],
        "user_executed_suspicious_command": ["review full Run dialog command", "pivot to Timeline and Search around the same user", "review process graph for matching PowerShell or LOLBin execution"],
        "trusted_office_macro_document": ["review the Office document path and source", "review whether macros or trusted content were enabled", "pivot to Search and Timeline for matching execution or download activity"],
        "user_activity_suspicious_program": ["review the user activity artifact source", "review whether the binary lives in a user-writable path", "pivot to Search and Process Graph for matching execution evidence"],
        "downloaded_executable_origin": ["review Search and Timeline for matching download, browser, BITS or Defender activity", "pivot to the file path and host URL", "confirm whether the file later executed or was quarantined"],
        "suspicious_file_deleted_or_renamed": ["pivot to Timeline around the file path", "review recycle bin, process execution and Defender activity", "confirm whether the file was staged and then deleted or renamed"],
        "office_security_alert_document": ["review the Office alert text and referenced document", "pivot to Timeline and Search for the same document path", "check whether Zone.Identifier, email or execution evidence also exists"],
        "suspicious_ui_observed_file": ["review Search, Timeline and NTFS for the same file path", "confirm whether the artifact represents visual presence, activity history or index metadata only", "pivot to related execution or download evidence if present"],
        "security_notification_observed": ["review the notification text and source app", "pivot to Defender, Search and Timeline around the same time", "confirm whether the warning corresponds to a real detection or suspicious download"],
    }
    return mapping.get(finding_type, ["review related events and corroborating artifacts"])


def _generate_findings(case: Case, evidences: list[Evidence], events: list[dict], process_bundle: dict, *, evidence_id: str | None = None) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    by_type = Counter()
    warnings: list[str] = []
    process_graph = process_bundle.get("graph") or {"nodes": [], "edges": [], "summary": {}}
    nodes = process_graph.get("nodes", [])
    edges = process_graph.get("edges", [])
    node_map = {str(node.get("id")): node for node in nodes}
    events_by_type: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        events_by_type[str(_nested_get(event, "event.type") or "")].append(event)

    downloads = [event for event in events if str(_nested_get(event, "event.type") or "") == "file_downloaded" and str(_nested_get(event, "artifact.type") or "") in {"browser", "bits"}]
    processes = [event for event in events if _process_event(event)]
    defender = [event for event in events if str(_nested_get(event, "artifact.type") or "") in {"defender", "detection"} or "detection" in str(_nested_get(event, "event.category") or "")]
    dns_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "dns"]
    srum_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "srum"]
    persistence_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") in {"autorun", "scheduled_task", "service", "wmi"}]
    cloud_uploads = [event for event in events if str(_nested_get(event, "event.type") or "") == "cloud_upload"]
    usb_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "usb" and "mass_storage" in str(_nested_get(event, "usb.device_type") or "")]
    deletion_events = [event for event in events if str(_nested_get(event, "event.type") or "") == "file_deleted" and str(_nested_get(event, "artifact.type") or "") in {"recycle_bin", "mft"}]
    inventory_exec = [event for event in events if _prefetch_or_inventory_execution(event)]
    user_activity_events = [event for event in events if str(_nested_get(event, "artifact.type") or "") == "user_activity"]

    for download in downloads:
        download_ts = _parse_ts(download.get("@timestamp"))
        download_path = _extract_event_path(download)
        filename = _file_name(download_path)
        candidate_processes: list[tuple[dict, bool, bool]] = []
        for process_event in processes:
            process_ts = _parse_ts(process_event.get("@timestamp"))
            if not download_ts or not process_ts or process_ts < download_ts or process_ts > download_ts + timedelta(hours=48):
                continue
            exact, filename_only = _match_paths(download_path, _extract_event_path(process_event))
            if not exact and not filename_only:
                continue
            candidate_processes.append((process_event, exact, filename_only))
        for process_event, exact_match, filename_only in candidate_processes[:2]:
            process_ts = _parse_ts(process_event.get("@timestamp"))
            matched_defender: list[tuple[dict, bool, bool]] = []
            for detection_event in defender:
                detection_ts = _parse_ts(detection_event.get("@timestamp"))
                if not process_ts or not detection_ts or detection_ts < process_ts - timedelta(hours=1) or detection_ts > process_ts + timedelta(hours=48):
                    continue
                det_exact, det_filename = _match_paths(_extract_event_path(process_event), _extract_event_path(detection_event))
                if not det_exact and not det_filename:
                    continue
                matched_defender.append((detection_event, det_exact, det_filename))
            if not matched_defender:
                continue
            finding_events = [download, process_event, matched_defender[0][0]]
            reasons = [
                "Downloaded file later executed",
                "Executed file later detected by Defender",
                "Download path matched process path" if exact_match else "Download filename matched process filename",
                "Defender detection matched executed file" if matched_defender[0][1] else "Defender detection matched executed filename",
            ]
            filename_only_match = bool(filename_only or matched_defender[0][2])
            data_quality = ["filename_only_match"] if filename_only_match else []
            risk = max(int(_nested_get(process_event, "risk_score") or 0), int(_nested_get(matched_defender[0][0], "risk_score") or 0), 75)
            if any(marker in _normalize_path(download_path) for marker in ("\\temp\\", "\\appdata\\", "\\startup\\")):
                risk = max(risk, 92)
            if str(_nested_get(matched_defender[0][0], "event.severity") or "").lower() in {"high", "critical"}:
                risk = max(risk, 95)
            if filename_only_match:
                risk = min(risk, 60)
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="download_execute_detect",
                    title=f"Downloaded file executed and detected: {filename or _extract_event_path(process_event) or 'unknown'}",
                    summary=f"A downloaded file was later executed and correlated with a Defender detection: {download_path or filename or 'unknown'}",
                    confidence="high" if exact_match and matched_defender[0][1] else "medium" if filename_only_match else "low",
                    events=finding_events,
                    reasons=reasons,
                    tags=["correlation_engine", "download", "execution", "defender"],
                    risk_score=min(risk, 100),
                    related_files=[value for value in [download_path, _extract_event_path(process_event), _extract_event_path(matched_defender[0][0])] if value],
                    related_process_node_ids=[
                        str(node.get("id"))
                        for node in nodes
                        if _match_paths(_extract_event_path(process_event), node.get("path"))[0] or (_file_name(_extract_event_path(process_event)) and _file_name(_extract_event_path(process_event)) == _file_name(node.get("path")))
                    ],
                    recommended_triage=_finding_recommended_triage("download_execute_detect"),
                    data_quality=data_quality,
                    key_parts=[download_path or "", filename],
                )
            )
            by_type["download_execute_detect"] += 1

    for edge in edges:
        parent = node_map.get(str(edge.get("source")) or "")
        child = node_map.get(str(edge.get("target")) or "")
        if not parent or not child:
            continue
        parent_name = _normalize_text(parent.get("name")).lower()
        child_name = _normalize_text(child.get("name")).lower()
        child_cmd = _normalize_text(child.get("command_line")).lower()
        if parent_name in OFFICE_PROCESS_NAMES and child_name in {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "mshta.exe"}:
            reasons = ["Office spawned script interpreter"]
            if "encoded" in child_cmd:
                reasons.append("Encoded PowerShell observed")
            if "executionpolicy bypass" in child_cmd or " -ep bypass" in child_cmd or " -executionpolicy bypass" in child_cmd:
                reasons.append("Execution policy bypass observed")
            if "windowstyle hidden" in child_cmd or "-w hidden" in child_cmd:
                reasons.append("Hidden PowerShell window observed")
            risk = max(int(child.get("risk_score") or 0), 80)
            if any("network" in badge or "dns" in badge for badge in (child.get("badges") or [])):
                risk = max(risk, 95)
            finding_events = [event for event in processes if str(event.get("id") or "") in (parent.get("source_events") or []) + (child.get("source_events") or [])]
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="office_powershell",
                    title=f"Office spawned suspicious interpreter: {parent_name} -> {child_name}",
                    summary=f"{parent_name} spawned {child_name} with suspicious command-line characteristics.",
                    confidence="high" if str(edge.get("confidence") or "").lower() == "high" else "medium",
                    events=finding_events,
                    reasons=reasons,
                    tags=["correlation_engine", "process_graph", "office", "powershell"],
                    risk_score=min(risk, 100),
                    related_process_node_ids=[str(parent.get("id")), str(child.get("id"))],
                    related_files=[value for value in [str(parent.get("path") or ""), str(child.get("path") or "")] if value],
                    recommended_triage=_finding_recommended_triage("office_powershell"),
                    key_parts=[str(parent.get("id")), str(child.get("id"))],
                )
            )
            by_type["office_powershell"] += 1

    suspicious_powershell_nodes = [node for node in nodes if _normalize_text(node.get("name")).lower() in {"powershell.exe", "pwsh.exe"} and int(node.get("risk_score") or 0) >= 70]
    for node in suspicious_powershell_nodes:
        node_time = _parse_ts(node.get("first_seen") or node.get("last_seen"))
        related_dns = []
        related_srum = []
        domains: list[str] = []
        if node_time:
            for event in dns_events:
                event_time = _parse_ts(event.get("@timestamp"))
                if not event_time or event_time < node_time - timedelta(minutes=30) or event_time > node_time + timedelta(minutes=30):
                    continue
                process_name = _normalize_text(_nested_get(event, "process.name")).lower()
                domain = _normalize_text(_nested_get(event, "dns.domain") or _nested_get(event, "dns.name")).lower()
                suspicious_domain, _ = _is_suspicious_domain(domain)
                if process_name in {"powershell.exe", "pwsh.exe"} or suspicious_domain:
                    related_dns.append(event)
                    if domain:
                        domains.append(domain)
            for event in srum_events:
                event_time = _parse_ts(event.get("@timestamp"))
                if not event_time or event_time < node_time - timedelta(hours=2) or event_time > node_time + timedelta(hours=2):
                    continue
                app = _normalize_text(_nested_get(event, "srum.application") or _nested_get(event, "process.name")).lower()
                outbound = int(_nested_get(event, "srum.bytes_sent") or _nested_get(event, "network.bytes_sent") or 0)
                if app in {"powershell.exe", "pwsh.exe"} and outbound >= 1000000:
                    related_srum.append(event)
        if not related_dns and not related_srum:
            continue
        reasons = ["Suspicious PowerShell with network activity"]
        if related_dns:
            reasons.append("PowerShell resolved suspicious domain")
        if related_srum:
            reasons.append("PowerShell high outbound bytes")
        node_events = [event for event in processes if str(event.get("id") or "") in (node.get("source_events") or [])]
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="powershell_network",
                title=f"Suspicious PowerShell with network activity: {_normalize_text(node.get('name')) or 'powershell.exe'}",
                summary="Suspicious PowerShell execution correlated with DNS and/or SRUM network activity.",
                confidence="high" if related_dns and related_srum else "medium",
                events=node_events + related_dns[:2] + related_srum[:2],
                reasons=reasons,
                tags=["correlation_engine", "powershell", "network"],
                risk_score=min(max(int(node.get("risk_score") or 0), 75 if related_dns else 65), 100),
                related_process_node_ids=[str(node.get("id"))],
                related_domains=domains,
                recommended_triage=_finding_recommended_triage("powershell_network"),
                key_parts=[str(node.get("id"))] + domains,
            )
        )
        by_type["powershell_network"] += 1

    for persistence_event in persistence_events:
        command = _extract_persistence_command(persistence_event)
        mechanism = _normalize_text(_nested_get(persistence_event, "persistence.mechanism")).lower() or str(_nested_get(persistence_event, "artifact.type") or "")
        persistence_ts = _parse_ts(persistence_event.get("@timestamp"))
        matches: list[dict] = []
        for process_event in processes:
            process_ts = _parse_ts(process_event.get("@timestamp"))
            if persistence_ts and process_ts and process_ts >= persistence_ts and process_ts <= persistence_ts + timedelta(days=7):
                if _match_paths(command, _extract_event_path(process_event))[0] or _match_paths(command, _extract_event_path(process_event))[1]:
                    matches.append(process_event)
        supporting_inventory = []
        for event in inventory_exec:
            if _match_paths(command, _extract_event_path(event))[0] or _match_paths(command, _extract_event_path(event))[1]:
                supporting_inventory.append(event)
        if not matches and not supporting_inventory:
            continue
        reasons = ["Persistence entry matched later process execution" if matches else "Persistence command matched execution artifact"]
        if mechanism in CRITICAL_PERSISTENCE:
            reasons.append("Critical persistence mechanism observed")
        inventory_only = not matches and bool(supporting_inventory)
        risk = 85 if mechanism in CRITICAL_PERSISTENCE and matches else 70 if mechanism in CRITICAL_PERSISTENCE else 65
        if inventory_only:
            risk = 70 if mechanism in CRITICAL_PERSISTENCE else 45
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="persistence_execution",
                title=f"Persistence matched execution: {mechanism or 'persistence'}",
                summary="A persistence mechanism was correlated with later execution evidence for the same binary or script.",
                confidence="high" if matches and _match_paths(command, _extract_event_path(matches[0]))[0] else "medium" if matches else "low" if supporting_inventory else "low",
                events=[persistence_event] + matches[:1] + supporting_inventory[:1],
                reasons=reasons,
                tags=["correlation_engine", "persistence", mechanism or "unknown"],
                risk_score=risk,
                related_files=[value for value in [command, _extract_event_path(matches[0]) if matches else None] if value],
                recommended_triage=_finding_recommended_triage("persistence_execution"),
                data_quality=["inventory_only_execution_artifact_used"] if inventory_only else [],
                key_parts=[mechanism, command or ""],
            )
        )
        by_type["persistence_execution"] += 1

    for event in user_activity_events:
        event_type = str(_nested_get(event, "event.type") or "")
        command_line = _normalize_text(_nested_get(event, "process.command_line"))
        process_path = _normalize_text(_nested_get(event, "process.path") or _nested_get(event, "file.path"))
        file_path = _normalize_text(_nested_get(event, "file.path"))
        reasons = list(dict.fromkeys(str(reason) for reason in (event.get("suspicious_reasons") or []) if reason))
        risk = int(_nested_get(event, "risk_score") or 0)

        if event_type == "user_run_command_observed" and risk >= 70 and command_line:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="user_executed_suspicious_command",
                    title=f"User executed suspicious command: {_file_name(process_path) or 'command'}",
                    summary="A RunMRU artifact recorded a suspicious command with strong execution or LOLBin indicators.",
                    confidence="high" if any(token in command_line.lower() for token in ["encodedcommand", "-enc", "mshta", "rundll32", "regsvr32", "certutil"]) else "medium",
                    events=[event],
                    reasons=reasons or ["Suspicious Run dialog command observed"],
                    tags=["correlation_engine", "user_activity", "run_mru", "suspicious_command"],
                    risk_score=min(max(risk, 75), 100),
                    related_files=[value for value in [process_path] if value],
                    recommended_triage=_finding_recommended_triage("user_executed_suspicious_command"),
                    key_parts=[command_line, process_path],
                )
            )
            by_type["user_executed_suspicious_command"] += 1
            continue

        if event_type == "office_document_trusted" and risk >= 70:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="trusted_office_macro_document",
                    title=f"Trusted Office document: {_file_name(file_path) or file_path or 'document'}",
                    summary="An Office TrustRecords artifact indicates a trusted document with suspicious path or macro-enabled characteristics.",
                    confidence="high" if _extension(file_path) in {".docm", ".xlsm", ".pptm", ".xlam"} else "medium",
                    events=[event],
                    reasons=reasons or ["Trusted Office document observed"],
                    tags=["correlation_engine", "user_activity", "office", "trusted_document"],
                    risk_score=min(max(risk, 75), 100),
                    related_files=[value for value in [file_path] if value],
                    recommended_triage=_finding_recommended_triage("trusted_office_macro_document"),
                    key_parts=[file_path, str(_nested_get(event, "office.app") or "")],
                )
            )
            by_type["trusted_office_macro_document"] += 1
            continue

        if event_type in {"user_program_execution_observed", "background_app_execution_observed"} and risk >= 70 and process_path:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="user_activity_suspicious_program",
                    title=f"Suspicious user activity program: {_file_name(process_path) or process_path}",
                    summary="A user activity registry artifact indicates suspicious program execution or background execution from a risky path.",
                    confidence="high" if bool(_nested_get(event, "execution.is_execution_confirmed")) else "medium",
                    events=[event],
                    reasons=reasons or ["Suspicious program observed in user activity artifact"],
                    tags=["correlation_engine", "user_activity", "execution_hint"],
                    risk_score=min(max(risk, 70), 100),
                    related_files=[value for value in [process_path] if value],
                    recommended_triage=_finding_recommended_triage("user_activity_suspicious_program"),
                    key_parts=[process_path, str(_nested_get(event, "user.sid") or ""), event_type],
                )
            )
            by_type["user_activity_suspicious_program"] += 1
            continue

    ntfs_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "ntfs"]
    for event in ntfs_events:
        event_type = str(_nested_get(event, "event.type") or "")
        file_path = _normalize_text(_nested_get(event, "file.path"))
        host_url = _normalize_text(_nested_get(event, "ntfs.host_url") or _nested_get(event, "url.full"))
        reasons = list(dict.fromkeys(str(reason) for reason in (event.get("suspicious_reasons") or []) if reason))
        risk = int(_nested_get(event, "risk_score") or 0)
        extension = _extension(file_path)

        if event_type == "file_zone_identifier_observed" and risk >= 70 and file_path:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="downloaded_executable_origin",
                    title=f"Downloaded file origin observed: {_file_name(file_path) or file_path}",
                    summary="A Zone.Identifier record shows a suspicious web-origin file with preserved source URL context.",
                    confidence="high" if extension in {".exe", ".ps1", ".cmd", ".bat", ".js", ".vbs"} or file_path.lower().endswith(".pdf.exe") else "medium",
                    events=[event],
                    reasons=reasons or ["Suspicious web-origin file observed"],
                    tags=["correlation_engine", "ntfs", "zone_identifier", "download_origin"],
                    risk_score=min(max(risk, 75), 100),
                    related_files=[value for value in [file_path] if value],
                    related_domains=[value for value in [_domain_from_url_text(host_url)] if value],
                    recommended_triage=_finding_recommended_triage("downloaded_executable_origin"),
                    key_parts=[file_path, host_url],
                )
            )
            by_type["downloaded_executable_origin"] += 1
            continue

        if event_type in {"file_deleted_observed", "file_renamed_observed", "directory_entry_observed"} and risk >= 60 and file_path:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="suspicious_file_deleted_or_renamed",
                    title=f"Suspicious file delete/rename trace: {_file_name(file_path) or file_path}",
                    summary="NTFS metadata indicates a suspicious file was deleted, renamed or only remains as a directory-entry trace.",
                    confidence="medium",
                    events=[event],
                    reasons=reasons or ["Suspicious NTFS delete/rename trace observed"],
                    tags=["correlation_engine", "ntfs", "delete_rename"],
                    risk_score=min(max(risk, 60), 90),
                    related_files=[value for value in [file_path, _normalize_text(_nested_get(event, "ntfs.old_name")), _normalize_text(_nested_get(event, "ntfs.new_name"))] if value],
                    recommended_triage=_finding_recommended_triage("suspicious_file_deleted_or_renamed"),
                    key_parts=[file_path, event_type],
                )
            )
            by_type["suspicious_file_deleted_or_renamed"] += 1
            continue

    windows_ui_events = [event for event in events if str(_nested_get(event, "artifact.type") or "").lower() == "windows_ui"]
    for event in windows_ui_events:
        event_type = str(_nested_get(event, "event.type") or "")
        file_path = _normalize_text(_nested_get(event, "file.path") or _nested_get(event, "windows_search.indexed_path") or _nested_get(event, "thumbnail.source_path") or _nested_get(event, "office.document_path"))
        notification_title = _normalize_text(_nested_get(event, "notification.title"))
        notification_body = _normalize_text(_nested_get(event, "notification.body_preview"))
        office_alert_text = _normalize_text(_nested_get(event, "office.alert_text"))
        reasons = list(dict.fromkeys(str(reason) for reason in (event.get("suspicious_reasons") or []) if reason))
        risk = int(_nested_get(event, "risk_score") or 0)
        extension = _extension(file_path)

        if event_type == "office_alert_observed" and risk >= 70 and (office_alert_text or file_path):
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="office_security_alert_document",
                    title=f"Office security alert: {_file_name(file_path) or 'document'}",
                    summary="An Office alert indicates Protected View, macro, security or content-warning context for a document.",
                    confidence="high" if extension in {".docm", ".xlsm", ".pptm", ".xlam"} else "medium",
                    events=[event],
                    reasons=reasons or ["Office security alert observed"],
                    tags=["correlation_engine", "windows_ui", "office_alert"],
                    risk_score=min(max(risk, 70), 95),
                    related_files=[value for value in [file_path] if value],
                    recommended_triage=_finding_recommended_triage("office_security_alert_document"),
                    key_parts=[file_path, office_alert_text],
                )
            )
            by_type["office_security_alert_document"] += 1
            continue

        if event_type in {"thumbnail_observed", "activity_history_observed", "search_index_entry_observed"} and risk >= 60 and file_path:
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="suspicious_ui_observed_file",
                    title=f"Suspicious UI/local DB file reference: {_file_name(file_path) or file_path}",
                    summary="A Windows UI or local database artifact references a suspicious file path, cached thumbnail, search entry or activity-history item.",
                    confidence="medium",
                    events=[event],
                    reasons=reasons or ["Suspicious file referenced by Windows UI artifact"],
                    tags=["correlation_engine", "windows_ui", "ui_reference"],
                    risk_score=min(max(risk, 60), 85),
                    related_files=[value for value in [file_path] if value],
                    recommended_triage=_finding_recommended_triage("suspicious_ui_observed_file"),
                    key_parts=[file_path, event_type],
                )
            )
            by_type["suspicious_ui_observed_file"] += 1
            continue

        if event_type == "notification_observed" and risk >= 70 and (notification_title or notification_body):
            findings.append(
                _base_finding(
                    case.id,
                    evidence_id=evidence_id,
                    finding_type="security_notification_observed",
                    title=f"Security notification observed: {notification_title or 'notification'}",
                    summary="A Windows notification indicates Defender, malware, phishing or other security-relevant user-facing warning.",
                    confidence="medium",
                    events=[event],
                    reasons=reasons or ["Security notification observed"],
                    tags=["correlation_engine", "windows_ui", "notification"],
                    risk_score=min(max(risk, 70), 95),
                    related_files=[value for value in [file_path] if value],
                    recommended_triage=_finding_recommended_triage("security_notification_observed"),
                    key_parts=[notification_title, file_path, notification_body],
                )
            )
            by_type["security_notification_observed"] += 1
            continue

    for cloud_event in cloud_uploads:
        local_path = _normalize_text(_nested_get(cloud_event, "cloud.local_path") or _nested_get(cloud_event, "file.path"))
        remote_path = _normalize_text(_nested_get(cloud_event, "cloud.remote_path"))
        shared = bool(_nested_get(cloud_event, "cloud.shared"))
        cloud_ts = _parse_ts(cloud_event.get("@timestamp"))
        filename = _file_name(local_path or remote_path)
        reasons = []
        if _extension(local_path or remote_path) in EXECUTABLE_EXTENSIONS:
            reasons.append("Cloud upload of executable")
        if _extension(local_path or remote_path) in ARCHIVE_EXTENSIONS:
            reasons.append("Cloud upload of archive")
        if _is_user_writable(local_path):
            reasons.append("Cloud upload from user-writable path")
        if any(keyword in filename for keyword in SENSITIVE_KEYWORDS):
            reasons.append("Cloud file name contains sensitive keyword")
        if shared and any(keyword in filename for keyword in SENSITIVE_KEYWORDS):
            reasons.append("Cloud shared sensitive item")
        nearby_suspicious = []
        if cloud_ts:
            for event in processes + defender:
                event_time = _parse_ts(event.get("@timestamp"))
                if not event_time or event_time < cloud_ts - timedelta(hours=24) or event_time > cloud_ts:
                    continue
                if int(_nested_get(event, "risk_score") or 0) >= 70:
                    nearby_suspicious.append(event)
        if nearby_suspicious:
            reasons.append("Cloud upload after suspicious activity")
        if not reasons:
            continue
        risk = 75 if "Cloud shared sensitive item" in reasons or nearby_suspicious else 60
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="cloud_exfil_candidate",
                title=f"Cloud exfiltration candidate: {filename or local_path or remote_path or 'cloud item'}",
                summary="A cloud upload was observed for a sensitive or suspicious item, optionally following suspicious local activity.",
                confidence="high" if shared and nearby_suspicious else "medium",
                events=[cloud_event] + nearby_suspicious[:2],
                reasons=reasons,
                tags=["correlation_engine", "cloud", "exfiltration_candidate"],
                risk_score=min(risk + (10 if shared else 0), 100),
                related_files=[value for value in [local_path, remote_path] if value],
                recommended_triage=_finding_recommended_triage("cloud_exfil_candidate"),
                key_parts=[local_path, remote_path, filename],
            )
        )
        by_type["cloud_exfil_candidate"] += 1

    for usb_event in usb_events:
        usb_ts = _parse_ts(usb_event.get("@timestamp"))
        if not usb_ts:
            continue
        nearby = []
        reasons = []
        for event in events:
            event_time = _parse_ts(event.get("@timestamp"))
            if not event_time or event_time < usb_ts - timedelta(hours=2) or event_time > usb_ts + timedelta(hours=2):
                continue
            if event is usb_event:
                continue
            artifact_type = str(_nested_get(event, "artifact.type") or "")
            path = _extract_event_path(event)
            ext = _extension(path)
            if artifact_type == "mft" and ext in ARCHIVE_EXTENSIONS and (str(_nested_get(event, "event.type") or "") in {"file_observed", "file_deleted"}):
                nearby.append(event)
                reasons.append("USB connected near archive creation")
            elif artifact_type in {"recycle_bin", "mft"} and str(_nested_get(event, "event.type") or "") == "file_deleted" and (_looks_sensitive_path(path) or ext in EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS):
                nearby.append(event)
                reasons.append("USB connected near suspicious deletion")
            elif artifact_type == "cloud" and any(keyword in _file_name(path) for keyword in SENSITIVE_KEYWORDS):
                nearby.append(event)
                reasons.append("USB mass storage connected near sensitive file activity")
        if not nearby:
            continue
        high_context = any(int(_nested_get(event, "risk_score") or 0) >= 70 for event in nearby + processes)
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="usb_exfil_candidate",
                title="USB exfiltration candidate",
                summary="USB mass storage activity was correlated with nearby sensitive archive, cloud or deletion activity.",
                confidence="medium" if high_context else "low",
                events=[usb_event] + nearby[:4],
                reasons=list(dict.fromkeys(reasons)),
                tags=["correlation_engine", "usb", "exfiltration_candidate"],
                risk_score=80 if high_context else 50,
                related_files=[value for value in (_extract_event_path(event) for event in nearby) if value],
                recommended_triage=_finding_recommended_triage("usb_exfil_candidate"),
                key_parts=[str(_nested_get(usb_event, "usb.serial") or ""), str(_nested_get(usb_event, "volume.drive_letter") or "")],
            )
        )
        by_type["usb_exfil_candidate"] += 1

    suspicious_exec_sources = [event for event in processes + inventory_exec if bool(_nested_get(event, "execution.is_execution_confirmed")) or str(_nested_get(event, "artifact.type") or "") == "prefetch"]
    for exec_event in suspicious_exec_sources:
        exec_ts = _parse_ts(exec_event.get("@timestamp"))
        exec_path = _extract_event_path(exec_event)
        if not exec_ts or not exec_path:
            continue
        matches = []
        for deletion in deletion_events:
            del_ts = _parse_ts(deletion.get("@timestamp"))
            if not del_ts or del_ts < exec_ts or del_ts > exec_ts + timedelta(hours=72):
                continue
            exact, filename_only = _match_paths(exec_path, _extract_event_path(deletion))
            if exact or filename_only:
                matches.append((deletion, filename_only))
        if not matches:
            continue
        reasons = ["Executed file later deleted"]
        if any((_match_paths(exec_path, _extract_event_path(event))[0] or _match_paths(exec_path, _extract_event_path(event))[1]) for event in defender):
            reasons.append("Suspicious file deleted after detection")
        if _extension(exec_path) in EXECUTABLE_EXTENSIONS:
            reasons.append("Executed file later deleted")
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="execution_cleanup",
                title=f"Execution cleanup candidate: {_file_name(exec_path) or exec_path}",
                summary="An executed or high-confidence execution artifact was later deleted in MFT or Recycle Bin.",
                confidence="high" if not matches[0][1] else "medium",
                events=[exec_event, matches[0][0]],
                reasons=list(dict.fromkeys(reasons)),
                tags=["correlation_engine", "cleanup", "execution"],
                risk_score=80 if _extension(exec_path) in EXECUTABLE_EXTENSIONS else 65,
                related_files=[exec_path, _extract_event_path(matches[0][0]) or ""],
                recommended_triage=_finding_recommended_triage("execution_cleanup"),
                data_quality=["filename_only_match"] if matches[0][1] else [],
                key_parts=[exec_path, _file_name(exec_path)],
            )
        )
        by_type["execution_cleanup"] += 1

    for edge in edges:
        parent = node_map.get(str(edge.get("source")) or "")
        child = node_map.get(str(edge.get("target")) or "")
        if not parent or not child:
            continue
        if int(child.get("risk_score") or 0) < 70:
            continue
        reasons = list(dict.fromkeys((child.get("risk_reasons") or []) + (["LOLBins process chain"] if _normalize_text(child.get("name")).lower() in SUSPICIOUS_PROCESS_NAMES else [])))
        parent_name = _normalize_text(parent.get("name")).lower()
        child_name = _normalize_text(child.get("name")).lower()
        if parent_name in {"chrome.exe", "msedge.exe", "firefox.exe"} and _extension(child.get("path")) in EXECUTABLE_EXTENSIONS:
            reasons.append("Browser spawned executable")
        node_events = [event for event in processes if str(event.get("id") or "") in (parent.get("source_events") or []) + (child.get("source_events") or [])]
        chain_confidence = str(edge.get("confidence") or "medium").lower()
        if not node_events:
            chain_confidence = _downgrade_confidence_level(chain_confidence)
        parent_command_line = _normalize_text(parent.get("command_line")) or "command line not available"
        child_command_line = _normalize_text(child.get("command_line")) or "command line not available"
        findings.append(
            _base_finding(
                case.id,
                evidence_id=evidence_id,
                finding_type="suspicious_process_chain",
                title=f"Suspicious process chain: {parent_name or 'parent'} -> {child_name or 'child'}",
                summary=f"A suspicious high-risk process chain was extracted from the process graph. Parent command line: {parent_command_line}. Child command line: {child_command_line}.",
                confidence=chain_confidence,
                events=node_events,
                reasons=list(dict.fromkeys(reasons or ["Suspicious process chain observed"])),
                tags=["correlation_engine", "process_graph", "suspicious_chain"],
                risk_score=min(max(int(parent.get("risk_score") or 0), int(child.get("risk_score") or 0), 70 if node_events else 55), 100),
                related_process_node_ids=[str(parent.get("id")), str(child.get("id"))],
                related_files=[value for value in [str(parent.get("path") or ""), str(child.get("path") or "")] if value],
                recommended_triage=_finding_recommended_triage("suspicious_process_chain"),
                data_quality=["process_chain_without_source_events"] if not node_events else [],
                key_parts=[str(parent.get("id")), str(child.get("id"))],
            )
        )
        by_type["suspicious_process_chain"] += 1

    report = {
        "case_id": case.id,
        "evidence_id": evidence_id,
        "findings_generated": len(findings),
        "findings_deduplicated": 0,
        "by_type": dict(by_type),
        "by_severity": dict(Counter(item["severity"].value for item in findings)),
        "by_confidence": dict(Counter(item["confidence"] for item in findings)),
        "by_status": dict(Counter(item["status"].value for item in findings)),
        "events_considered": len(events),
        "process_graph_available": bool(nodes),
        "process_nodes_considered": len(nodes),
        "correlation_windows": {
            "download_to_process_hours": 48,
            "process_to_defender_hours": 48,
            "powershell_dns_minutes": 30,
            "powershell_srum_hours": 2,
            "persistence_execution_days": 7,
            "usb_exfil_hours": 2,
            "execution_cleanup_hours": 72,
        },
        "warnings": warnings + list(process_graph.get("summary", {}).get("warnings") or []),
        "parser_errors": [],
    }
    return findings, report


def serialize_finding(item: Finding) -> dict:
    return {
        "id": item.id,
        "case_id": item.case_id,
        "evidence_id": item.evidence_id,
        "finding_type": item.finding_type,
        "title": item.title,
        "summary": item.description,
        "severity": item.severity.value if hasattr(item.severity, "value") else str(item.severity),
        "confidence": item.confidence,
        "status": item.status.value if hasattr(item.status, "value") else str(item.status),
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "time_start": _as_iso(item.time_start),
        "time_end": _as_iso(item.time_end),
        "timeline": item.timeline or [],
        "related_event_ids": item.related_event_ids or item.event_ids or [],
        "related_stable_event_ids": item.related_stable_event_ids or [],
        "related_artifact_ids": item.related_artifact_ids or [],
        "related_evidence_ids": item.related_evidence_ids or [],
        "related_process_node_ids": item.related_process_node_ids or [],
        "related_files": item.related_files or [],
        "related_domains": item.related_domains or [],
        "related_ips": item.related_ips or [],
        "related_users": item.related_users or [],
        "related_hosts": item.related_hosts or [],
        "risk_score": item.risk_score or 0,
        "reasons": item.reasons or [],
        "tags": item.tags or [],
        "mitre": item.mitre or [],
        "recommended_triage": item.recommended_triage or [],
        "source": item.source,
        "correlation_version": item.correlation_version,
        "data_quality": item.data_quality or [],
        "fingerprint": item.fingerprint,
        "last_seen_at": _as_iso(item.last_seen_at),
        "occurrence_count": item.occurrence_count or 1,
    }


def run_correlation_engine(
    db: Session,
    case_id: str,
    *,
    evidence_id: str | None = None,
    host: str | None = None,
    finding_types: list[str] | None = None,
    force: bool = False,
    force_reset_status: bool = False,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    case = db.get(Case, case_id)
    if not case:
        raise ValueError("Case not found")
    page = max(int(page or 1), 1)
    page_size = max(min(int(page_size or 25), 200), 1)
    host_scope = _resolve_effective_host_scope(db, case_id, host)
    host_aliases = host_scope["host_aliases"]
    host_alias_set = set(host_aliases)
    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if evidence_id:
        evidences_query = evidences_query.filter(Evidence.id == evidence_id)
    evidences = evidences_query.all()
    if host_alias_set:
        evidences = [evidence for evidence in evidences if _evidence_matches_host(evidence, host_alias_set)]
    host_evidence_ids = sorted({item.id for item in evidences if getattr(item, "id", None)})
    max_events = _correlation_max_events(db)
    try:
        events_with_probe = _iter_events_for_case(case_id, evidence_id, host_aliases=host_aliases, host_evidence_ids=host_evidence_ids, max_docs=max_events + 1)
    except TypeError:
        events_with_probe = _iter_events_for_case(case_id, evidence_id, max_docs=max_events + 1)
        if host_alias_set:
            events_with_probe = [event for event in events_with_probe if _event_matches_host(event, host_alias_set)]
    event_limit_reached = len(events_with_probe) > max_events
    events = events_with_probe[:max_events]
    process_bundle = build_process_tree_bundle(
        case,
        evidences,
        scope="evidence" if evidence_id else ("host" if host_aliases else "case"),
        evidence_id=evidence_id,
        host=host_scope["canonical_host"],
    )
    generated, report = _generate_findings(case, evidences, events, process_bundle, evidence_id=evidence_id)
    if finding_types:
        allowed = set(finding_types)
        generated = [item for item in generated if item.get("finding_type") in allowed]
        report["by_type"] = dict(Counter(item["finding_type"] for item in generated))
    active_fingerprints = {str(item.get("fingerprint") or "") for item in generated if item.get("fingerprint")}
    stale_removed = 0
    if not host_aliases:
        stale_removed = _remove_stale_correlation_findings(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            case_evidence_ids={item.id for item in evidences if getattr(item, "id", None)},
            active_fingerprints=active_fingerprints,
        )
    saved, deduplicated = _persist_findings(
        db,
        generated,
        preserve_status=True,
        force_reset_status=force_reset_status,
    )
    returned_findings = _paginate_findings(saved, page=page, page_size=page_size)
    total_matched = len(saved)
    returned_count = len(returned_findings)
    hidden_by_limit = max(total_matched - (page * page_size), 0)
    has_more = page * page_size < total_matched
    scanned_source_breakdown = _counter_dict([_event_artifact_type(event) for event in events])
    scanned_host_breakdown = _counter_dict([_display_host(_event_host(event)) for event in events])
    result_source_breakdown = _counter_dict(
        [
            str((item.finding_type or "unknown"))
            for item in saved
        ]
    )
    result_host_breakdown = _counter_dict(
        [
            _display_host(host)
            for item in saved
            for host in (item.related_hosts or [])
        ]
    )
    scope_reason = "host_and_evidence" if evidence_id and host_aliases else "evidence_id" if evidence_id else "host" if host_aliases else "all_case"
    effective_scope = {
        "case_id": case_id,
        "host": host_scope["raw_host"],
        "canonical_host": host_scope["canonical_host"],
        "evidence_id": evidence_id,
        "all_hosts": not bool(host_aliases) and not bool(evidence_id),
    }
    request_scope = {
        "host": host,
        "evidence_id": evidence_id,
    }
    scope = {
        **effective_scope,
        "hosts": sorted({host for host in scanned_host_breakdown if host != "unknown"}),
        "evidence_ids": sorted({item.id for item in evidences if getattr(item, "id", None)}),
        "time_range": {
            "from": _as_iso(min((_parse_ts(event.get("@timestamp")) for event in events if _parse_ts(event.get("@timestamp"))), default=None)),
            "to": _as_iso(max((_parse_ts(event.get("@timestamp")) for event in events if _parse_ts(event.get("@timestamp"))), default=None)),
        },
        "query_terms": [],
        "sources": sorted(scanned_source_breakdown),
        "scope_type": "selected_evidence" if evidence_id else ("selected_host" if host_aliases else "case_all_evidence"),
        "scope_reason": scope_reason,
    }
    counts = {
        "candidates_scanned": len(events),
        "matched": total_matched,
        "returned": returned_count,
        "deduplicated": deduplicated,
        "hidden_by_limit": hidden_by_limit,
        "has_more": has_more,
        "event_limit_reached": event_limit_reached,
    }
    limits = {
        "page": page,
        "page_size": page_size,
        "max_results": page_size,
        "max_candidates": max_events,
        "reason": "default_safety" if has_more or event_limit_reached else "none",
    }
    report["findings_generated"] = len(generated)
    report["findings_deduplicated"] = deduplicated
    report["stale_findings_removed"] = stale_removed
    report["by_severity"] = dict(Counter((item.severity.value if hasattr(item.severity, "value") else str(item.severity)) for item in saved))
    report["by_confidence"] = dict(Counter(str(item.confidence or "") for item in saved if item.confidence))
    report["by_status"] = dict(Counter((item.status.value if hasattr(item.status, "value") else str(item.status)) for item in saved))
    report["scope"] = scope
    report["effective_scope"] = effective_scope
    report["request_scope"] = request_scope
    report["scope_reason"] = scope_reason
    report["correlation_run_id"] = str(uuid4())
    report["cache_key"] = _correlation_cache_key(case_id, evidence_id=evidence_id, canonical_host=host_scope["canonical_host"], page=page, page_size=page_size, finding_types=finding_types)
    report["reused_previous_run"] = False
    report["counts"] = counts
    report["limits"] = limits
    report["source_breakdown"] = scanned_source_breakdown
    report["host_breakdown"] = scanned_host_breakdown
    report["result_source_breakdown"] = result_source_breakdown
    report["result_host_breakdown"] = result_host_breakdown
    report["pagination"] = {"page": page, "page_size": page_size, "has_more": has_more, "next_page": page + 1 if has_more else None}
    return {
        "report": report,
        "findings": [serialize_finding(item) for item in returned_findings],
        "process_graph": process_bundle.get("graph"),
    }
