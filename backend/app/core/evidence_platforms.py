from __future__ import annotations

import enum
from typing import Any, Iterable

from app.core.artifact_registry import CAPABILITY_KEYS, artifact_registry_entries, artifact_registry_entry


class EvidencePlatform(str, enum.Enum):
    auto = "auto"
    windows = "windows"
    linux = "linux"
    macos = "macos"
    memory = "memory"
    mixed = "mixed"
    unknown = "unknown"


MEMORY_EVIDENCE_TYPES = {"memory_dump"}
MEMORY_EXTENSIONS = {".raw", ".mem", ".dmp", ".dump", ".bin", ".img", ".vmem", ".lime", ".aff4"}
_LEGACY_PLATFORM_ALIASES = {"other": EvidencePlatform.unknown.value}

_WINDOWS_MARKERS = (
    "windows/system32/",
    "windows/syswow64/",
    "windows/prefetch/",
    "windows/system32/winevt/logs/",
    "programdata/microsoft/",
    "documents and settings/",
    "ntuser.dat",
    "usrclass.dat",
)
_LINUX_MARKERS = (
    "/etc/passwd",
    "etc/passwd",
    "/etc/group",
    "etc/group",
    "/etc/shadow",
    "etc/shadow",
    "/etc/sudoers",
    "etc/sudoers",
    "/etc/crontab",
    "etc/crontab",
    "/etc/systemd/",
    "etc/systemd/",
    "/lib/systemd/",
    "lib/systemd/",
    "/var/log/",
    "var/log/",
    "/home/",
    "home/",
    "/root/",
    "root/",
    "/usr/bin/",
    "usr/bin/",
    "/proc/",
    "proc/",
    "/sys/",
    "sys/",
    "audit/audit.log",
    ".bash_history",
    ".zsh_history",
)
_MACOS_MARKERS = (
    "/library/",
    ".plist",
    "/system/library/",
    "/private/var/",
)

PLATFORM_REGISTRY: dict[str, dict[str, Any]] = {
    EvidencePlatform.windows.value: {
        "id": EvidencePlatform.windows.value,
        "label": "Windows",
        "upload_label": "Windows",
        "upload_description": "Use for Windows endpoint artifacts such as EVTX, registry hives, prefetch, and user profiles.",
    },
    EvidencePlatform.linux.value: {
        "id": EvidencePlatform.linux.value,
        "label": "Linux",
        "upload_label": "Linux",
        "upload_description": "Use for Linux triage artifacts, logs, inventory, persistence and memory-supporting collections.",
    },
    EvidencePlatform.macos.value: {
        "id": EvidencePlatform.macos.value,
        "label": "macOS",
        "upload_label": "macOS planned",
        "upload_description": "Visible for roadmap clarity. macOS artifacts are not supported yet.",
        "disabled": True,
    },
    EvidencePlatform.memory.value: {
        "id": EvidencePlatform.memory.value,
        "label": "Memory",
        "upload_label": "Memory",
        "upload_description": "Memory images are registered separately and expose memory-specific analysis capabilities.",
    },
    EvidencePlatform.mixed.value: {
        "id": EvidencePlatform.mixed.value,
        "label": "Mixed",
        "upload_label": "Mixed",
        "upload_description": "A single evidence source containing multiple platform families.",
    },
    EvidencePlatform.unknown.value: {
        "id": EvidencePlatform.unknown.value,
        "label": "Unknown",
        "upload_label": "Unknown / Other",
        "upload_description": "Use when the source platform is unclear or non-OS-specific.",
    },
}


def normalize_evidence_platform(value: EvidencePlatform | str | None) -> str:
    normalized = str(value.value if isinstance(value, EvidencePlatform) else value or EvidencePlatform.auto.value).strip().lower()
    normalized = _LEGACY_PLATFORM_ALIASES.get(normalized, normalized)
    if normalized in {item.value for item in EvidencePlatform}:
        return normalized
    return EvidencePlatform.auto.value


def _lowered_candidates(*, filename: str | None = None, paths: list[str] | None = None) -> list[str]:
    raw = [str(filename or ""), *[str(path or "") for path in (paths or [])]]
    return [item.replace("\\", "/").lower() for item in raw if item]


def _count_platform_hits(lowered: list[str]) -> dict[str, int]:
    hits = {
        EvidencePlatform.windows.value: 0,
        EvidencePlatform.linux.value: 0,
        EvidencePlatform.macos.value: 0,
    }
    for path in lowered:
        if any(marker in path for marker in _WINDOWS_MARKERS) or path.endswith((".evtx", ".pf", ".lnk")):
            hits[EvidencePlatform.windows.value] += 1
        if any(marker in path for marker in _LINUX_MARKERS):
            hits[EvidencePlatform.linux.value] += 1
        if any(marker in path for marker in _MACOS_MARKERS):
            hits[EvidencePlatform.macos.value] += 1
    return hits


def detect_memory_os_hint(*, filename: str | None = None, paths: list[str] | None = None) -> str | None:
    lowered = _lowered_candidates(filename=filename, paths=paths)
    if any(path.endswith(".lime") or "/lime" in path for path in lowered):
        return EvidencePlatform.linux.value
    hits = _count_platform_hits(lowered)
    ordered = [platform for platform, count in hits.items() if count > 0]
    return ordered[0] if len(ordered) == 1 else None


def detect_evidence_platform(
    *,
    filename: str | None = None,
    paths: list[str] | None = None,
    evidence_type: str | None = None,
) -> str:
    normalized_evidence_type = str(evidence_type or "").strip().lower()
    lowered = _lowered_candidates(filename=filename, paths=paths)
    if normalized_evidence_type in MEMORY_EVIDENCE_TYPES or any(path.endswith(tuple(MEMORY_EXTENSIONS)) for path in lowered):
        return EvidencePlatform.memory.value
    hits = _count_platform_hits(lowered)
    present = [platform for platform, count in hits.items() if count > 0]
    if len(present) > 1:
        return EvidencePlatform.mixed.value
    if len(present) == 1:
        return present[0]
    return EvidencePlatform.unknown.value


def resolve_evidence_platform(
    provided_platform: EvidencePlatform | str | None,
    detected_platform: EvidencePlatform | str | None,
    *,
    evidence_type: str | None = None,
) -> tuple[str, str, str]:
    provided = normalize_evidence_platform(provided_platform)
    detected = normalize_evidence_platform(detected_platform)
    if detected == EvidencePlatform.auto.value:
        detected = EvidencePlatform.unknown.value
    if str(evidence_type or "").strip().lower() in MEMORY_EVIDENCE_TYPES:
        return provided, EvidencePlatform.memory.value, EvidencePlatform.memory.value
    effective = detected if provided == EvidencePlatform.auto.value else provided
    if effective == EvidencePlatform.auto.value:
        effective = EvidencePlatform.unknown.value
    return provided, detected, effective


def category_platform(category: str | None) -> str:
    entry = artifact_registry_entry(category)
    platforms = list(entry.get("platforms") or [])
    if len(platforms) == 1:
        return str(platforms[0])
    return EvidencePlatform.unknown.value


def infer_platform_from_categories(categories: Iterable[str] | None) -> str:
    present = {category_platform(category) for category in (categories or [])}
    present.discard(EvidencePlatform.unknown.value)
    if not present:
        return EvidencePlatform.unknown.value
    if len(present) == 1:
        return next(iter(present))
    return EvidencePlatform.mixed.value


def build_platform_capabilities(platforms: Iterable[str] | None) -> dict[str, bool]:
    selected_platforms = {normalize_evidence_platform(item) for item in (platforms or []) if normalize_evidence_platform(item) not in {EvidencePlatform.auto.value, EvidencePlatform.unknown.value, EvidencePlatform.mixed.value}}
    flags = {key: False for key in CAPABILITY_KEYS}
    for entry in artifact_registry_entries(platforms=sorted(selected_platforms)):
        for key, enabled in dict(entry.get("capabilities") or {}).items():
            if enabled:
                flags[key] = True
    if EvidencePlatform.memory.value in selected_platforms:
        flags["supportsMemory"] = True
    return flags


def build_platform_groups(platforms: Iterable[str] | None, available_categories: set[str]) -> list[dict[str, Any]]:
    selected_platforms = {normalize_evidence_platform(item) for item in (platforms or []) if normalize_evidence_platform(item) not in {EvidencePlatform.auto.value, EvidencePlatform.unknown.value, EvidencePlatform.mixed.value}}
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in artifact_registry_entries(platforms=sorted(selected_platforms)):
        category_id = str(entry.get("id") or "")
        if available_categories and category_id not in available_categories and not any(alias in available_categories for alias in entry.get("aliases") or []):
            continue
        platform = str((entry.get("platforms") or [EvidencePlatform.unknown.value])[0])
        key = (platform, str(entry.get("group_id") or "other"))
        group = groups.setdefault(
            key,
            {
                "id": str(entry.get("group_id") or "other"),
                "label": str(entry.get("group_label") or "Other"),
                "platform": platform,
                "categories": [],
            },
        )
        group["categories"].append(
            {
                "id": category_id,
                "label": str(entry.get("label") or category_id),
                "group_id": group["id"],
                "group_label": group["label"],
                "platform": platform,
                "icon": entry.get("icon"),
                "view": entry.get("view"),
                "searchable": bool(entry.get("searchable")),
                "timeline_capable": bool(entry.get("timeline_capable")),
                "severity_support": bool(entry.get("severity_support")),
                "aliases": list(entry.get("aliases") or []),
            }
        )
    return [groups[key] for key in sorted(groups)]


def build_platform_quick_selects(platforms: Iterable[str] | None, available_categories: set[str]) -> list[dict[str, Any]]:
    selected_platforms = {normalize_evidence_platform(item) for item in (platforms or []) if normalize_evidence_platform(item) not in {EvidencePlatform.auto.value, EvidencePlatform.unknown.value, EvidencePlatform.mixed.value}}
    quick_selects: dict[tuple[str, str], dict[str, Any]] = {}
    labels = {
        "event_logs": "Event logs only",
        "execution": "Execution artifacts",
        "persistence": "Persistence artifacts",
        "core_logs": "Journal & logs",
        "memory_core": "Memory core",
    }
    for entry in artifact_registry_entries(platforms=sorted(selected_platforms)):
        category_id = str(entry.get("id") or "")
        aliases = [str(alias) for alias in entry.get("aliases") or []]
        if available_categories and category_id not in available_categories and not any(alias in available_categories for alias in aliases):
            continue
        platform = str((entry.get("platforms") or [EvidencePlatform.unknown.value])[0])
        for quick_select_id in entry.get("quick_selects") or []:
            key = (platform, str(quick_select_id))
            quick_select = quick_selects.setdefault(
                key,
                {
                    "id": str(quick_select_id),
                    "label": labels.get(str(quick_select_id), str(quick_select_id).replace("_", " ").title()),
                    "platform": platform,
                    "category_ids": [],
                },
            )
            for value in [category_id, *aliases]:
                if value not in quick_select["category_ids"]:
                    quick_select["category_ids"].append(value)
    return [quick_selects[key] for key in sorted(quick_selects)]


def build_evidence_platform_profile(
    platform: EvidencePlatform | str | None,
    *,
    evidence_type: str | None = None,
    available_categories: Iterable[str] | None = None,
) -> dict[str, Any]:
    available = {str(item).strip().lower() for item in (available_categories or []) if str(item).strip()}
    normalized = normalize_evidence_platform(platform)
    inferred = infer_platform_from_categories(available)
    if str(evidence_type or "").strip().lower() in MEMORY_EVIDENCE_TYPES:
        normalized = EvidencePlatform.memory.value
    elif normalized in {EvidencePlatform.auto.value, EvidencePlatform.unknown.value}:
        normalized = inferred
    selected_platforms = [normalized]
    if normalized == EvidencePlatform.mixed.value:
        preferred_order = [EvidencePlatform.windows.value, EvidencePlatform.linux.value, EvidencePlatform.memory.value, EvidencePlatform.macos.value]
        seen_platforms = {category_platform(category) for category in available}
        category_platforms = []
        for candidate in preferred_order:
            if candidate not in {EvidencePlatform.unknown.value, EvidencePlatform.mixed.value}:
                if candidate in seen_platforms:
                    category_platforms.append(candidate)
        selected_platforms = category_platforms or [EvidencePlatform.windows.value, EvidencePlatform.linux.value, EvidencePlatform.memory.value]
    elif normalized == EvidencePlatform.unknown.value:
        selected_platforms = []
    groups = build_platform_groups(selected_platforms, available)
    quick_selects = build_platform_quick_selects(selected_platforms, available)
    categories = [category for group in groups for category in group["categories"]]
    artifacts = artifact_registry_entries(platforms=selected_platforms)
    capabilities = build_platform_capabilities(selected_platforms)
    return {
        "platform": normalized if normalized != EvidencePlatform.auto.value else EvidencePlatform.unknown.value,
        "platforms": selected_platforms,
        "platform_meta": [PLATFORM_REGISTRY.get(item, {"id": item, "label": item.title()}) for item in selected_platforms],
        "capabilities": capabilities,
        "groups": groups,
        "quick_selects": quick_selects,
        "categories": categories,
        "artifacts": artifacts,
        "available_categories": sorted(available),
    }
