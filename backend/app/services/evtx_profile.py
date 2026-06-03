from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.services.usable_ingest import FULL_FORENSIC_MODE, USABLE_INGEST_MODE, normalize_ingest_mode


EVTX_PROFILE_FAST_HIGH_VALUE = "fast_high_value"
EVTX_PROFILE_FULL = "full"
EVTX_PROFILE_CUSTOM = "custom"
EVTX_PROFILE_VALUES = {EVTX_PROFILE_FAST_HIGH_VALUE, EVTX_PROFILE_FULL, EVTX_PROFILE_CUSTOM}
MANY_EVTX_THRESHOLD = 20

DEFAULT_FAST_EVTX_LIMITS = {
    "max_records_per_file": 5000,
    "max_seconds_per_file": 120,
    "max_total_records": 25000,
    "max_total_seconds": 600,
    "on_limit": "defer_remaining",
}

HIGH_VALUE_EVTX_CHANNELS = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-SmbClient/Security",
    "Microsoft-Windows-SmbServer/Security",
]

HIGH_VALUE_EVTX_KEYWORDS = [
    "powershell",
    "sysmon",
    "defender",
    "terminalservices",
    "taskscheduler",
    "wmi",
    "security",
    "system",
    "application",
    "rdpcorets",
    "smbclient",
    "smbserver",
]


def _candidate_id(candidate: dict[str, Any]) -> str:
    return str(candidate.get("id") or candidate.get("candidate_id") or "")


def evtx_path(candidate: dict[str, Any]) -> str:
    return str(candidate.get("original_path") or candidate.get("source_path") or candidate.get("relative_path") or candidate.get("display_name") or "")


def normalize_evtx_path(value: object | None) -> str:
    text = str(value or "").replace("\\", "/").strip()
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = text.replace("%254", "/").replace("%252f", "/").replace("%2f", "/").replace("%5c", "/").replace("%4", "/")
    return text.lower()


def evtx_channel(candidate: dict[str, Any]) -> str:
    path = normalize_evtx_path(evtx_path(candidate))
    name = Path(path).name
    if name.endswith(".evtx"):
        name = name[:-5]
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and parts[-1].endswith(".evtx"):
        parent = parts[-2]
        if parent in {"operational", "security", "admin"}:
            return f"{parts[-3]}/{parent}" if len(parts) >= 3 else name
    return name


def is_evtx_candidate(candidate: dict[str, Any]) -> bool:
    artifact_type = str(candidate.get("artifact_type") or "").strip().lower()
    parser = str(candidate.get("parser") or candidate.get("planned_parser") or "").strip().lower()
    path = normalize_evtx_path(evtx_path(candidate))
    return artifact_type in {"windows_event", "evtx"} or parser == "evtx_raw" or path.endswith(".evtx")


def is_high_value_evtx_candidate(candidate: dict[str, Any]) -> bool:
    normalized_path = normalize_evtx_path(evtx_path(candidate))
    channel = evtx_channel(candidate)
    channel_no_ext = channel[:-5] if channel.endswith(".evtx") else channel
    filename = Path(normalized_path).name
    for configured in HIGH_VALUE_EVTX_CHANNELS:
        configured_norm = normalize_evtx_path(configured)
        configured_no_ext = configured_norm[:-5] if configured_norm.endswith(".evtx") else configured_norm
        if "/" not in configured_no_ext and configured_no_ext in {"security", "system", "application", "windows powershell"}:
            if configured_no_ext == channel_no_ext or filename == f"{configured_no_ext}.evtx":
                return True
            continue
        if configured_norm in normalized_path or configured_no_ext == channel_no_ext or configured_no_ext in normalized_path:
            return True
    for keyword in HIGH_VALUE_EVTX_KEYWORDS:
        if keyword in {"security", "system", "application"}:
            if channel_no_ext == keyword or filename == f"{keyword}.evtx":
                return True
            continue
        if keyword in normalized_path or keyword in channel_no_ext:
            return True
    return False


def normalize_evtx_profile(value: object | None, *, ingest_mode: str | None, evtx_count: int) -> tuple[str, str]:
    requested = str(value or "").strip().lower()
    if requested in EVTX_PROFILE_VALUES:
        return requested, "explicit_user_selection"
    mode = normalize_ingest_mode(ingest_mode)
    if mode == FULL_FORENSIC_MODE:
        return EVTX_PROFILE_FULL, "full_forensic_defaults_to_full_evtx"
    if mode == USABLE_INGEST_MODE and evtx_count >= MANY_EVTX_THRESHOLD:
        return EVTX_PROFILE_FULL, "usable_search_defaults_to_full_evtx_with_backend_auto"
    return EVTX_PROFILE_FULL, "small_evtx_set_defaults_to_full"


def normalize_evtx_fast_limits(value: object | None = None) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    limits = dict(DEFAULT_FAST_EVTX_LIMITS)
    for key in ("max_records_per_file", "max_seconds_per_file", "max_total_records", "max_total_seconds"):
        try:
            limits[key] = max(int(source.get(key, limits[key]) or 0), 0)
        except Exception:  # noqa: BLE001
            limits[key] = DEFAULT_FAST_EVTX_LIMITS[key]
    on_limit = str(source.get("on_limit") or limits["on_limit"]).strip().lower()
    limits["on_limit"] = on_limit if on_limit in {"defer_remaining"} else "defer_remaining"
    return limits


def apply_evtx_profile_to_selection(
    candidates: list[dict[str, Any]],
    selected_candidate_ids: list[str] | None,
    *,
    ingest_mode: str | None,
    requested_profile: object | None = None,
) -> dict[str, Any]:
    selected_ids = {str(item) for item in (selected_candidate_ids or []) if item}
    evtx_candidates = [candidate for candidate in candidates if _candidate_id(candidate) in selected_ids and is_evtx_candidate(candidate)]
    profile, reason = normalize_evtx_profile(requested_profile, ingest_mode=ingest_mode, evtx_count=len(evtx_candidates))
    if profile == EVTX_PROFILE_FULL:
        adjusted_ids = sorted(selected_ids)
        selected_evtx = evtx_candidates
        deferred_evtx: list[dict[str, Any]] = []
    else:
        selected_evtx = [candidate for candidate in evtx_candidates if is_high_value_evtx_candidate(candidate)]
        selected_evtx_ids = {_candidate_id(candidate) for candidate in selected_evtx}
        deferred_evtx = [candidate for candidate in evtx_candidates if _candidate_id(candidate) not in selected_evtx_ids]
        adjusted_ids = sorted((selected_ids - {_candidate_id(candidate) for candidate in deferred_evtx}) | selected_evtx_ids)

    selected_files = [evtx_path(candidate) for candidate in selected_evtx]
    deferred_files = [
        {
            "artifact_id": _candidate_id(candidate),
            "path": evtx_path(candidate),
            "artifact_type": "windows_event",
            "reason": "evtx_profile_deferred",
            "profile": EVTX_PROFILE_FAST_HIGH_VALUE,
            "can_run_later": True,
            "suggested_action": "Run Full EVTX indexing / Deep retry",
            "channel": evtx_channel(candidate),
        }
        for candidate in deferred_evtx
    ]
    return {
        "selected_candidate_ids": adjusted_ids,
        "evtx_profile": profile,
        "evtx_profile_reason": reason,
        "evtx_fast_limits": normalize_evtx_fast_limits() if profile == EVTX_PROFILE_FAST_HIGH_VALUE else {},
        "evtx_selected_files": selected_files,
        "evtx_deferred_files": deferred_files,
        "evtx_high_value_channels": HIGH_VALUE_EVTX_CHANNELS,
        "evtx_deferred_count": len(deferred_files),
        "evtx_partial_files": [],
        "evtx_partial_count": 0,
        "evtx_coverage_status": "deferred_fast_profile" if deferred_files and profile == EVTX_PROFILE_FAST_HIGH_VALUE else "full",
    }
