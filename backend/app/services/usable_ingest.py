from __future__ import annotations

from collections import Counter
from typing import Any

from app.services.parser_registry import get_parser_registry_entry

USABLE_INGEST_MODE = "usable_search"
FULL_FORENSIC_MODE = "full_forensic"

TIER_1_ARTIFACT_TYPES = {
    "windows_event",
    "evtx",
    "prefetch",
    "lnk",
    "scheduled_task",
    "powershell",
    "browser",
    "usb",
    "service",
    "amcache",
    "shimcache",
    "jumplist",
    "registry",
    "jsonl",
    "csv",
    "network",
    "dns",
    "wlan",
}

TIER_1_PARSERS = {
    "evtx_raw",
    "powershell_evtx",
    "prefetch_raw",
    "lnk_raw",
    "scheduled_task_xml",
    "psreadline",
    "powershell_history",
    "browser_chromium_history",
    "browser_firefox_places",
    "sqlite_chromium",
    "sqlite_firefox",
    "registry_usb",
    "windows_service_registry",
    "amcache_raw",
    "shimcache_raw",
    "jumplist_automatic",
    "jumplist_custom",
}

TIER_2_ARTIFACT_TYPES = {
    "autorun",
    "bits",
    "cloud",
    "cloud_sync",
    "email",
    "mft",
    "ntfs",
    "recycle_bin",
    "shellbags",
    "srum",
    "usn",
    "windows_ui",
    "wmi",
}

TIER_3_PARSERS = {
    "unsupported_sensitive_artifact",
}

COMMON_FILTER_FIELDS = [
    "case_id",
    "evidence_id",
    "artifact_type",
    "parser",
    "source_file",
    "timestamp",
    "host.name",
    "user.name",
]

ARTIFACT_FILTER_FIELDS: dict[str, list[str]] = {
    "windows_event": ["event_id", "provider", "channel", "computer"],
    "evtx": ["event_id", "provider", "channel", "computer"],
    "prefetch": ["executable", "run_count", "path"],
    "lnk": ["target_path", "arguments", "working_dir"],
    "browser": ["url", "domain", "title", "profile"],
    "registry": ["hive", "key_path", "value_name"],
    "scheduled_task": ["task_name", "command", "arguments"],
    "amcache": ["path", "program", "hash"],
    "shimcache": ["path", "program", "hash"],
    "powershell": ["command", "source_file", "artifact_type"],
    "jumplist": ["target_path", "arguments", "source_file", "app_id"],
    "service": ["service_name", "image_path", "display_name"],
    "usb": ["vendor", "product", "serial", "device_instance_id"],
}


def normalize_ingest_mode(value: object | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == USABLE_INGEST_MODE:
        return USABLE_INGEST_MODE
    return FULL_FORENSIC_MODE


def ingest_mode_metadata(mode: object | None) -> dict[str, Any]:
    normalized = normalize_ingest_mode(mode)
    if normalized == USABLE_INGEST_MODE:
        return {
            "ingest_mode": USABLE_INGEST_MODE,
            "skipped_features": ["rules", "detections", "heavy_enrichment", "benchmark", "advanced_reports"],
            "parser_tiers_enabled": ["tier1", "tier2_limited"],
            "automatic_task_categories": ["core"],
            "automatic_tasks": ["app.workers.tasks.ingest_evidence"],
            "host_identity_light": True,
            "skip_inline_detection_creation": True,
            "skip_heavy_debug_during_ingest": True,
            "metadata_updates_throttled": True,
            "skip_rules": True,
            "skip_detections": True,
            "skip_heavy_enrichment": True,
            "skip_benchmark": True,
            "on_demand_modules_available": ["rules", "reports", "host_enrichment", "deep_retry", "benchmark", "advanced_exports"],
        }
    return {
        "ingest_mode": FULL_FORENSIC_MODE,
        "skipped_features": [],
        "parser_tiers_enabled": ["tier1", "tier2", "tier3"],
        "automatic_task_categories": ["core"],
        "automatic_tasks": ["app.workers.tasks.ingest_evidence"],
        "host_identity_light": False,
        "skip_inline_detection_creation": False,
        "skip_heavy_debug_during_ingest": False,
        "metadata_updates_throttled": False,
        "skip_rules": False,
        "skip_detections": False,
        "skip_heavy_enrichment": False,
        "skip_benchmark": False,
        "on_demand_modules_available": ["rules", "reports", "host_enrichment", "deep_retry", "benchmark", "advanced_exports"],
    }


def build_mode_effective_plan(
    mode: object | None,
    *,
    selected_artifact_types: list[str] | None = None,
    available_artifact_types: list[str] | None = None,
) -> dict[str, Any]:
    normalized = normalize_ingest_mode(mode)
    metadata = ingest_mode_metadata(normalized)
    selected = sorted({str(item).strip() for item in selected_artifact_types or [] if str(item).strip()})
    available = sorted({str(item).strip() for item in available_artifact_types or [] if str(item).strip()})
    enabled = selected or available
    disabled: list[str] = []
    if normalized == USABLE_INGEST_MODE:
        disabled = ["rules", "detections", "heavy_enrichment", "benchmark", "advanced_reports"]
    return {
        "ingest_mode": normalized,
        "automatic_tasks": list(metadata.get("automatic_tasks") or []),
        "automatic_task_categories": list(metadata.get("automatic_task_categories") or []),
        "skipped_features": list(metadata.get("skipped_features") or []),
        "enabled_artifact_categories": enabled,
        "disabled_artifact_categories": [],
        "expensive_features_disabled": disabled,
        "parser_tiers_enabled": list(metadata.get("parser_tiers_enabled") or []),
    }


def parser_capability_profile(parser_name: object | None, artifact_type: object | None) -> dict[str, Any]:
    parser_key = str(parser_name or "").strip().lower()
    artifact_key = str(artifact_type or "").strip().lower()
    registry_entry = get_parser_registry_entry(artifact_type=artifact_key, parser_name=parser_key)
    if parser_key in TIER_3_PARSERS:
        tier = "tier3"
    elif parser_key in TIER_1_PARSERS or artifact_key in TIER_1_ARTIFACT_TYPES:
        tier = "tier1"
    elif artifact_key in TIER_2_ARTIFACT_TYPES:
        tier = "tier2"
    else:
        tier = "tier2"
    supports_usable_mode = tier in {"tier1", "tier2"}
    max_runtime_seconds = 1800 if tier == "tier1" else 3600 if tier == "tier2" else 900
    no_progress_timeout_seconds = 600 if tier == "tier1" else 900 if tier == "tier2" else 300
    filter_fields = list(
        dict.fromkeys(
            list(registry_entry.get("filter_fields") or [])
            + list(COMMON_FILTER_FIELDS)
            + list(ARTIFACT_FILTER_FIELDS.get(artifact_key, []))
        )
    )
    return {
        "parser_name": parser_key,
        "artifact_type": artifact_key,
        "tier": tier,
        "supports_usable_mode": supports_usable_mode,
        "expected_output_type": "searchable_document",
        "max_runtime_seconds": max_runtime_seconds,
        "no_progress_timeout_seconds": no_progress_timeout_seconds,
        "required_fields": ["case_id", "evidence_id", "artifact_id", "artifact_type", "parser", "source_file"],
        "optional_fields": ["timestamp", "host.name", "user.name", "event.category", "event.action", "event.type", "message"],
        "filter_fields": list(filter_fields),
        "failure_policy": "defer" if tier in {"tier2", "tier3"} else "fail_fast_artifact_only",
    }


def should_process_artifact_in_mode(artifact_info: dict[str, Any], ingest_mode: object | None) -> tuple[bool, str | None]:
    mode = normalize_ingest_mode(ingest_mode)
    profile = parser_capability_profile(artifact_info.get("parser"), artifact_info.get("artifact_type"))
    if mode != USABLE_INGEST_MODE:
        return True, None
    if profile["tier"] == "tier3":
        return False, "skipped_experimental"
    if not profile["supports_usable_mode"]:
        return False, "skipped_unsupported"
    return True, None


def deferred_retry_mode(parser_name: object | None, artifact_type: object | None) -> str | None:
    parser_key = str(parser_name or "").strip().lower()
    artifact_key = str(artifact_type or "").strip().lower()
    if parser_key in {"evtx_raw", "powershell_evtx"} or artifact_key in {"windows_event", "evtx"}:
        return "deep_safe_mode"
    return "default"


def build_parser_tier_report(*, artifacts: list[dict[str, Any]], ingest_mode: object | None) -> dict[str, Any]:
    by_tier: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        profile = parser_capability_profile(artifact.get("parser"), artifact.get("artifact_type"))
        tier = str(profile["tier"])
        bucket = by_tier.setdefault(
            tier,
            {
                "artifacts": 0,
                "completed": 0,
                "deferred": 0,
                "failed": 0,
                "skipped": 0,
                "artifact_types": Counter(),
                "parsers": Counter(),
            },
        )
        bucket["artifacts"] += 1
        bucket["artifact_types"][str(artifact.get("artifact_type") or "unknown")] += 1
        bucket["parsers"][str(artifact.get("parser") or "unknown")] += 1
        status = str(artifact.get("status") or "").lower()
        if status in {"completed", "parsed_with_warning", "partial"}:
            bucket["completed"] += 1
        elif "deferred" in status:
            bucket["deferred"] += 1
        elif status.startswith("failed"):
            bucket["failed"] += 1
        elif status.startswith("skipped"):
            bucket["skipped"] += 1
    serializable = {}
    for tier, payload in by_tier.items():
        serializable[tier] = {
            **payload,
            "artifact_types": dict(sorted(payload["artifact_types"].items())),
            "parsers": dict(sorted(payload["parsers"].items())),
        }
    return {
        "ingest_mode": normalize_ingest_mode(ingest_mode),
        "tiers_enabled": ingest_mode_metadata(ingest_mode).get("parser_tiers_enabled"),
        "by_tier": serializable,
    }


def build_indexed_document_counts_by_artifact_type(artifacts: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for artifact in artifacts:
        ingest_audit = dict(artifact.get("ingest_audit") or {})
        counts[str(artifact.get("artifact_type") or "unknown")] += int(
            ingest_audit.get("events_indexed")
            or ingest_audit.get("records_indexed")
            or artifact.get("record_count")
            or 0
        )
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_search_filter_coverage(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    artifact_types = sorted({str(item.get("artifact_type") or "unknown") for item in artifacts if item.get("artifact_type")})
    filters = {
        artifact_type: {
            "common_fields": list(COMMON_FILTER_FIELDS),
            "artifact_specific_fields": list(ARTIFACT_FILTER_FIELDS.get(artifact_type, [])),
        }
        for artifact_type in artifact_types
    }
    return {
        "common_fields": list(COMMON_FILTER_FIELDS),
        "artifact_types": artifact_types,
        "filters_by_artifact_type": filters,
    }
