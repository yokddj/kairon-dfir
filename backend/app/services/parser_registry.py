from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any


SEARCHABLE_CONTRACT_VERSION = "v1"
COMMON_SEARCH_FILTER_FIELDS = [
    "evidence_id",
    "case_id",
    "artifact.type",
    "artifact.parser",
    "source_file",
    "@timestamp",
    "host.name",
    "user.name",
]
SEARCHABLE_DOCUMENT_CONTRACT = {
    "version": SEARCHABLE_CONTRACT_VERSION,
    "required_fields": [
        "evidence_id",
        "case_id",
        "artifact.type",
        "artifact.parser",
        "source_file",
        "ingest_run_id",
    ],
    "optional_fields": [
        "@timestamp",
        "host.name",
        "user.name",
        "event.id",
        "windows.event_id",
        "title",
        "summary",
        "message",
        "description",
        "content",
    ],
    "filter_fields": list(COMMON_SEARCH_FILTER_FIELDS),
}

_REGISTRY: dict[str, dict[str, Any]] = {
    "windows_event": {
        "artifact_type": "windows_event",
        "parser_name": "evtxecmd_csv",
        "supported_extensions": [".evtx"],
        "source_patterns": ["*/winevt/Logs/*.evtx"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "stable",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["message", "summary", "windows.event_id", "event.message", "event.action", "event.category"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["windows.event_id", "event.provider", "event.channel", "host.name"],
        "notes": ["Indexes EVTX events into searchable documents. EvtxECmd CSV is preferred when available; the native Python parser remains fallback."],
    },
    "browser": {
        "artifact_type": "browser",
        "parser_name": "browser_chromium_history",
        "supported_extensions": ["History", ".sqlite", ".db"],
        "source_patterns": ["*/User Data/*/History", "*/places.sqlite"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "stable",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["browser.url", "url.full", "title", "summary", "message", "browser.domain"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["browser.url", "browser.domain", "title", "browser.profile"],
        "notes": ["Chromium/Edge history is normalized into browser timeline/search documents."],
    },
    "prefetch": {
        "artifact_type": "prefetch",
        "parser_name": "prefetch_raw",
        "supported_extensions": [".pf"],
        "source_patterns": ["*.pf"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "stable",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["process.path", "process.name", "prefetch.executable", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["process.path", "prefetch.executable", "execution.run_count"],
        "notes": ["Prefetch rows index execution metadata and executable paths."],
    },
    "scheduled_task": {
        "artifact_type": "scheduled_task",
        "parser_name": "scheduled_task_xml",
        "supported_extensions": [".job", ".xml", ".dat"],
        "source_patterns": ["*/Windows/Tasks/*", "*/Tasks/*.DAT"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "stable",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["task.command", "task.name", "task.arguments", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["task.name", "task.command", "task.arguments"],
        "notes": ["Scheduled tasks are indexed for command and task-name search."],
    },
    "jumplist": {
        "artifact_type": "jumplist",
        "parser_name": "raw_automatic_destinations",
        "supported_extensions": [".automaticDestinations-ms", ".customDestinations-ms"],
        "source_patterns": ["*.automaticDestinations-ms", "*.customDestinations-ms"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["lnk.target_path", "jumplist.app_id", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["lnk.target_path", "lnk.arguments", "jumplist.app_id"],
        "notes": ["Jump Lists are searchable by destination and app id."],
    },
    "registry": {
        "artifact_type": "registry",
        "parser_name": "registry_usb",
        "supported_extensions": ["SYSTEM", "SOFTWARE", "NTUSER.DAT", "UsrClass.dat"],
        "source_patterns": ["*/Windows/System32/config/*", "*/NTUSER.DAT", "*/UsrClass.dat"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["registry.key_path", "registry.value_name", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["registry.hive", "registry.key_path", "registry.value_name"],
        "notes": ["Registry artifacts are searchable when normalized rows are produced."],
    },
    "amcache": {
        "artifact_type": "amcache",
        "parser_name": "amcache_raw",
        "supported_extensions": ["Amcache.hve"],
        "source_patterns": ["*/Windows/appcompat/Programs/Amcache.hve"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["process.path", "file.path", "summary", "hash.sha256"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["process.path", "file.path", "hash.sha256"],
        "notes": ["Amcache rows are searchable for executable inventory and execution-candidate traces."],
    },
    "shimcache": {
        "artifact_type": "shimcache",
        "parser_name": "shimcache_raw",
        "supported_extensions": ["SYSTEM"],
        "source_patterns": ["*/Windows/System32/config/SYSTEM"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["file.path", "process.path", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["file.path", "process.path"],
        "notes": ["Shimcache rows are searchable for execution-candidate path pivots."],
    },
    "powershell": {
        "artifact_type": "powershell",
        "parser_name": "powershell_history",
        "supported_extensions": [".txt", ".ps1", ".log"],
        "source_patterns": ["*/PSReadLine/ConsoleHost_history.txt", "*.ps1", "*powershell*"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["powershell.command", "powershell.command_preview", "content", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["user.name", "powershell.command", "powershell.command_preview"],
        "notes": ["PowerShell history/transcript/script rows remain searchable without deep enrichment."],
    },
    "mft": {
        "artifact_type": "mft",
        "parser_name": "mft_raw",
        "supported_extensions": ["$MFT", "$UsnJrnl"],
        "source_patterns": ["*/$MFT", "*/$UsnJrnl*"],
        "enabled_for_usable_search": True,
        "searchable": True,
        "maturity": "beta",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": ["file.path", "file.name", "summary"],
        "filter_fields": COMMON_SEARCH_FILTER_FIELDS + ["file.path", "file.name"],
        "notes": ["Filesystem timeline artifacts remain searchable with partial coverage depending on parser output."],
    },
}

_ARTIFACT_TYPE_ALIASES: dict[str, str] = {
    "evtx_raw": "windows_event",
    "chromium_history": "browser",
    "prefetch_raw": "prefetch",
    "jumplist_automatic_destinations": "jumplist",
    "jumplist_custom_destinations": "jumplist",
    "psreadline_history": "powershell",
    "amcache_raw": "amcache",
    "shimcache_raw": "shimcache",
}

_PARSER_NAME_ALIASES: dict[str, str] = {
    "chromium_history": "browser_chromium_history",
    "jumplist_raw_automatic": "raw_automatic_destinations",
    "jumplist_raw_custom": "raw_custom_destinations",
    "psreadline_history": "powershell_history",
}


def get_searchable_document_contract() -> dict[str, Any]:
    return deepcopy(SEARCHABLE_DOCUMENT_CONTRACT)


def get_parser_registry() -> dict[str, dict[str, Any]]:
    return {key: deepcopy(value) for key, value in _REGISTRY.items()}


def _normalize_registry_keys(*, artifact_type: object | None = None, parser_name: object | None = None) -> tuple[str, str]:
    artifact_key = str(artifact_type or "").strip().lower()
    parser_key = str(parser_name or "").strip().lower()
    if artifact_key in _ARTIFACT_TYPE_ALIASES:
        artifact_key = _ARTIFACT_TYPE_ALIASES[artifact_key]
    if parser_key in _PARSER_NAME_ALIASES:
        parser_key = _PARSER_NAME_ALIASES[parser_key]
    return artifact_key, parser_key


def get_parser_registry_entry(*, artifact_type: object | None = None, parser_name: object | None = None) -> dict[str, Any]:
    artifact_key, parser_key = _normalize_registry_keys(artifact_type=artifact_type, parser_name=parser_name)
    if artifact_key and artifact_key in _REGISTRY:
        return deepcopy(_REGISTRY[artifact_key])
    for entry in _REGISTRY.values():
        if parser_key and str(entry.get("parser_name") or "").lower() == parser_key:
            return deepcopy(entry)
    return {
        "artifact_type": artifact_key or "unknown",
        "parser_name": parser_key or "unknown",
        "supported_extensions": [],
        "source_patterns": [],
        "enabled_for_usable_search": False,
        "searchable": False,
        "maturity": "experimental",
        "output_contract_version": SEARCHABLE_CONTRACT_VERSION,
        "primary_timestamp_field": "@timestamp",
        "searchable_fields": [],
        "filter_fields": list(COMMON_SEARCH_FILTER_FIELDS),
        "notes": ["No central parser registry entry defined yet."],
    }


def build_parser_registry_report(*, artifact_types: list[str] | None = None) -> dict[str, Any]:
    registry = get_parser_registry()
    if artifact_types:
        selected = [registry[key] for key in sorted(registry) if key in set(artifact_types)]
    else:
        selected = [registry[key] for key in sorted(registry)]
    return {
        "contract_version": SEARCHABLE_CONTRACT_VERSION,
        "artifact_types": [entry["artifact_type"] for entry in selected],
        "entries": selected,
    }


def _get_path(document: dict[str, Any], path: str) -> Any:
    current: Any = document
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current.get(segment)
    return current


def _present(document: dict[str, Any], path: str) -> bool:
    value = _get_path(document, path)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _event_artifact_type(document: dict[str, Any]) -> str:
    artifact_type, parser_name = _normalize_registry_keys(
        artifact_type=_get_path(document, "artifact.type") or document.get("artifact_type"),
        parser_name=_get_path(document, "artifact.parser") or document.get("parser"),
    )
    if artifact_type:
        return artifact_type
    entry = get_parser_registry_entry(parser_name=parser_name)
    return str(entry.get("artifact_type") or "unknown").strip().lower()


def _event_parser_name(document: dict[str, Any]) -> str:
    _, parser_name = _normalize_registry_keys(
        artifact_type=_get_path(document, "artifact.type") or document.get("artifact_type"),
        parser_name=_get_path(document, "artifact.parser") or document.get("parser"),
    )
    return parser_name or "unknown"


def _artifact_indexed_count(artifact: dict[str, Any]) -> int:
    ingest_audit = dict(artifact.get("ingest_audit") or {})
    return int(
        ingest_audit.get("events_indexed")
        or ingest_audit.get("records_indexed")
        or artifact.get("record_count")
        or 0
    )


def build_indexed_field_coverage_by_artifact_type(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_artifact_type: dict[str, dict[str, Any]] = {}
    for event in events:
        artifact_type = _event_artifact_type(event)
        entry = get_parser_registry_entry(artifact_type=artifact_type, parser_name=_event_parser_name(event))
        fields = list(dict.fromkeys(
            get_searchable_document_contract()["required_fields"]
            + get_searchable_document_contract()["optional_fields"]
            + list(entry.get("filter_fields") or [])
            + list(entry.get("searchable_fields") or [])
        ))
        bucket = by_artifact_type.setdefault(
            artifact_type,
            {
                "documents_indexed": 0,
                "field_presence": Counter(),
                "filter_fields": list(entry.get("filter_fields") or []),
                "searchable_fields": list(entry.get("searchable_fields") or []),
            },
        )
        bucket["documents_indexed"] += 1
        for field in fields:
            if _present(event, field):
                bucket["field_presence"][field] += 1
    serializable: dict[str, Any] = {}
    for artifact_type, bucket in sorted(by_artifact_type.items()):
        serializable[artifact_type] = {
            "documents_indexed": bucket["documents_indexed"],
            "field_presence": dict(sorted(bucket["field_presence"].items())),
            "filter_fields": bucket["filter_fields"],
            "searchable_fields": bucket["searchable_fields"],
        }
    return {
        "contract_version": SEARCHABLE_CONTRACT_VERSION,
        "by_artifact_type": serializable,
    }


def build_searchable_contract_report(*, artifacts: list[dict[str, Any]], sampled_events: list[dict[str, Any]]) -> dict[str, Any]:
    contract = get_searchable_document_contract()
    coverage = build_indexed_field_coverage_by_artifact_type(sampled_events)["by_artifact_type"]
    artifacts_by_type: Counter[str] = Counter()
    indexed_counts_by_type: Counter[str] = Counter()
    for item in artifacts:
        entry = get_parser_registry_entry(artifact_type=item.get("artifact_type"), parser_name=item.get("parser"))
        artifact_type = str(entry.get("artifact_type") or item.get("artifact_type") or "unknown").strip().lower()
        if artifact_type:
            artifacts_by_type[artifact_type] += 1
            indexed_counts_by_type[artifact_type] += _artifact_indexed_count(item)
    reports: list[dict[str, Any]] = []
    artifact_types = sorted(set(artifacts_by_type.keys()) | set(coverage.keys()))
    for artifact_type in artifact_types:
        entry = get_parser_registry_entry(artifact_type=artifact_type)
        sampled_docs_count = int((coverage.get(artifact_type) or {}).get("documents_indexed") or 0)
        fallback_docs_count = int(indexed_counts_by_type.get(artifact_type) or 0)
        docs_count = sampled_docs_count or fallback_docs_count
        field_presence = dict((coverage.get(artifact_type) or {}).get("field_presence") or {})
        missing_required = {
            field: max(docs_count - int(field_presence.get(field) or 0), 0)
            for field in contract["required_fields"]
        }
        filter_presence = {
            field: int(field_presence.get(field) or 0)
            for field in dict.fromkeys(list(entry.get("filter_fields") or []))
        }
        searchable_presence = {
            field: int(field_presence.get(field) or 0)
            for field in dict.fromkeys(list(entry.get("searchable_fields") or []))
        }
        if docs_count == 0 and artifacts_by_type.get(artifact_type, 0) > 0:
            status = "partial"
        elif docs_count == 0:
            status = "fail"
        elif any(count > 0 for count in missing_required.values()):
            status = "partial"
        else:
            status = "pass"
        reports.append(
            {
                "artifact_type": artifact_type,
                "parser": entry.get("parser_name"),
                "documents_indexed": docs_count,
                "documents_indexed_source": "sampled_events" if sampled_docs_count else "artifact_audit_fallback" if fallback_docs_count else "none",
                "artifacts_seen": int(artifacts_by_type.get(artifact_type, 0)),
                "missing_required_fields": missing_required,
                "searchable_fields": searchable_presence,
                "filter_fields": filter_presence,
                "contract_status": status,
                "notes": list(entry.get("notes") or []),
            }
        )
    summary = Counter(str(item.get("contract_status") or "unknown") for item in reports)
    return {
        "contract": contract,
        "summary": dict(sorted(summary.items())),
        "artifact_types": reports,
    }


def build_parser_coverage_matrix(*, artifacts: list[dict[str, Any]], sampled_events: list[dict[str, Any]]) -> dict[str, Any]:
    contract_report = build_searchable_contract_report(artifacts=artifacts, sampled_events=sampled_events)
    coverage = build_indexed_field_coverage_by_artifact_type(sampled_events)["by_artifact_type"]
    rows: list[dict[str, Any]] = []
    for item in contract_report["artifact_types"]:
        artifact_type = str(item.get("artifact_type") or "unknown")
        entry = get_parser_registry_entry(artifact_type=artifact_type, parser_name=item.get("parser"))
        field_presence = dict((coverage.get(artifact_type) or {}).get("field_presence") or {})
        docs_count = int(item.get("documents_indexed") or 0)
        timestamp_present = int(field_presence.get(str(entry.get("primary_timestamp_field") or "@timestamp")) or 0)
        host_present = int(field_presence.get("host.name") or 0)
        user_present = int(field_presence.get("user.name") or 0)
        source_file_present = int(field_presence.get("source_file") or 0)
        rows.append(
            {
                "artifact_type": artifact_type,
                "parser": item.get("parser"),
                "registry_status": entry.get("maturity"),
                "searchable": bool(entry.get("searchable")),
                "enabled_for_usable_search": bool(entry.get("enabled_for_usable_search")),
                "documents_indexed": docs_count,
                "documents_indexed_source": item.get("documents_indexed_source"),
                "artifacts_seen": int(item.get("artifacts_seen") or 0),
                "required_fields_missing": dict(item.get("missing_required_fields") or {}),
                "contract_status": item.get("contract_status"),
                "key_fields_present": dict(item.get("searchable_fields") or {}),
                "filter_fields_present": dict(item.get("filter_fields") or {}),
                "timestamp_field": entry.get("primary_timestamp_field"),
                "timestamp_coverage": {"present": timestamp_present, "missing": max(docs_count - timestamp_present, 0)},
                "host_coverage": {"present": host_present, "missing": max(docs_count - host_present, 0)},
                "user_coverage": {"present": user_present, "missing": max(docs_count - user_present, 0)},
                "source_file_coverage": {"present": source_file_present, "missing": max(docs_count - source_file_present, 0)},
                "notes": list(entry.get("notes") or []),
            }
        )
    summary = Counter(str(row.get("contract_status") or "unknown") for row in rows)
    return {
        "contract_version": SEARCHABLE_CONTRACT_VERSION,
        "summary": dict(sorted(summary.items())),
        "artifact_types": rows,
    }


def build_non_searchable_artifacts_report(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for artifact in artifacts:
        entry = get_parser_registry_entry(artifact_type=artifact.get("artifact_type"), parser_name=artifact.get("parser"))
        if entry.get("searchable"):
            continue
        items.append(
            {
                "artifact_type": artifact.get("artifact_type"),
                "parser": artifact.get("parser"),
                "source_file": artifact.get("source_path") or artifact.get("source_file") or artifact.get("name"),
                "status": artifact.get("status"),
                "searchable": False,
                "maturity": entry.get("maturity"),
                "notes": list(entry.get("notes") or []),
            }
        )
    return {
        "summary": {"non_searchable_count": len(items)},
        "items": items,
    }
