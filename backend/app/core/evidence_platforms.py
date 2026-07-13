from __future__ import annotations

import enum
from typing import Any, Iterable


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

_WINDOWS_CATEGORY_IDS = {
    "evtx",
    "windows_event",
    "powershell",
    "prefetch",
    "shimcache",
    "service",
    "scheduled_task",
    "browser",
    "defender",
    "lnk",
    "jumplist",
    "recycle_bin",
    "usb",
    "amcache",
    "registry",
    "bits",
    "shellbags",
    "autoruns",
    "wmi",
    "network",
    "mft",
    "srum",
    "startup_persistence",
}
_MEMORY_CATEGORY_IDS = {"process", "vad", "vads", "dll", "dlls", "handles", "network", "registry"}

PLATFORM_UI_GROUPS: dict[str, list[dict[str, Any]]] = {
    EvidencePlatform.windows.value: [
        {
            "id": "windows_core",
            "label": "Windows Core",
            "categories": [
                {"id": "evtx", "label": "Event Logs"},
                {"id": "powershell", "label": "PowerShell"},
                {"id": "prefetch", "label": "Prefetch"},
                {"id": "shimcache", "label": "Shimcache"},
                {"id": "amcache", "label": "Amcache"},
                {"id": "lnk", "label": "LNK"},
                {"id": "jumplist", "label": "Jump Lists"},
                {"id": "browser", "label": "Browser"},
            ],
        },
        {
            "id": "windows_persistence",
            "label": "Windows Persistence",
            "categories": [
                {"id": "service", "label": "Services"},
                {"id": "scheduled_task", "label": "Scheduled Tasks"},
                {"id": "registry", "label": "Registry"},
                {"id": "defender", "label": "Defender"},
                {"id": "usb", "label": "USB"},
                {"id": "recycle_bin", "label": "Recycle Bin"},
            ],
        },
    ],
    EvidencePlatform.linux.value: [
        {
            "id": "linux_logs",
            "label": "Linux Logs",
            "categories": [
                {"id": "linux_journal", "label": "Journal"},
                {"id": "linux_auth", "label": "Auth logs"},
                {"id": "linux_syslog", "label": "Syslog"},
                {"id": "linux_audit", "label": "Audit logs"},
                {"id": "linux_shell_history", "label": "Bash History"},
            ],
        },
        {
            "id": "linux_persistence",
            "label": "Linux Persistence",
            "categories": [
                {"id": "linux_cron", "label": "Cron"},
                {"id": "linux_systemd", "label": "Systemd Units"},
                {"id": "linux_sudoers", "label": "Sudoers"},
                {"id": "linux_ssh", "label": "SSH"},
            ],
        },
        {
            "id": "linux_inventory",
            "label": "Linux Inventory",
            "categories": [
                {"id": "linux_identity", "label": "Users / Groups"},
                {"id": "linux_packages", "label": "Packages"},
                {"id": "linux_network", "label": "Network"},
                {"id": "linux_os_info", "label": "OS Info"},
            ],
        },
    ],
    EvidencePlatform.memory.value: [
        {
            "id": "memory_core",
            "label": "Memory Core",
            "categories": [
                {"id": "process", "label": "Processes"},
                {"id": "vads", "label": "VADs"},
                {"id": "dlls", "label": "DLLs"},
                {"id": "handles", "label": "Handles"},
                {"id": "network", "label": "Network"},
                {"id": "registry", "label": "Registry"},
            ],
        }
    ],
}

PLATFORM_QUICK_SELECTS: dict[str, list[dict[str, Any]]] = {
    EvidencePlatform.windows.value: [
        {"id": "event_logs", "label": "Event logs only", "category_ids": ["evtx", "windows_event"]},
        {"id": "execution", "label": "Execution artifacts", "category_ids": ["evtx", "windows_event", "prefetch", "shimcache", "amcache", "lnk", "jumplist"]},
        {"id": "persistence", "label": "Persistence artifacts", "category_ids": ["scheduled_task", "service", "registry", "autoruns", "startup", "startup_folder", "wmi", "defender"]},
    ],
    EvidencePlatform.linux.value: [
        {"id": "core_logs", "label": "Journal & logs", "category_ids": ["linux_journal", "linux_auth", "linux_syslog", "linux_audit"]},
        {"id": "execution", "label": "Execution artifacts", "category_ids": ["linux_journal", "linux_auth", "linux_syslog", "linux_audit", "linux_shell_history"]},
        {"id": "persistence", "label": "Persistence & identity", "category_ids": ["linux_cron", "linux_systemd", "linux_identity", "linux_ssh", "linux_sudoers"]},
    ],
    EvidencePlatform.memory.value: [
        {"id": "memory_core", "label": "Memory core", "category_ids": ["process", "vads", "dlls", "handles", "network", "registry"]},
    ],
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
    normalized = str(category or "").strip().lower()
    if not normalized:
        return EvidencePlatform.unknown.value
    if normalized.startswith("linux_"):
        return EvidencePlatform.linux.value
    if normalized in _WINDOWS_CATEGORY_IDS:
        return EvidencePlatform.windows.value
    if normalized in _MEMORY_CATEGORY_IDS:
        return EvidencePlatform.memory.value
    return EvidencePlatform.unknown.value


def infer_platform_from_categories(categories: Iterable[str] | None) -> str:
    present = {category_platform(category) for category in (categories or [])}
    present.discard(EvidencePlatform.unknown.value)
    if not present:
        return EvidencePlatform.unknown.value
    if len(present) == 1:
        return next(iter(present))
    return EvidencePlatform.mixed.value


def _category_ids_for_platform(platform: str, available_categories: set[str]) -> list[str]:
    category_ids: list[str] = []
    for group in PLATFORM_UI_GROUPS.get(platform, []):
        for category in group.get("categories") or []:
            category_id = str(category.get("id") or "").strip().lower()
            if category_id and category_id not in category_ids:
                if not available_categories or category_id in available_categories:
                    category_ids.append(category_id)
    return category_ids


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
        selected_platforms = [platform for platform in (EvidencePlatform.windows.value, EvidencePlatform.linux.value, EvidencePlatform.memory.value) if _category_ids_for_platform(platform, available)]
        if not selected_platforms:
            selected_platforms = [EvidencePlatform.windows.value, EvidencePlatform.linux.value]
    elif normalized == EvidencePlatform.unknown.value:
        selected_platforms = []
    groups: list[dict[str, Any]] = []
    quick_selects: list[dict[str, Any]] = []
    categories: list[dict[str, Any]] = []
    for selected in selected_platforms:
        for group in PLATFORM_UI_GROUPS.get(selected, []):
            category_entries = []
            for category in group.get("categories") or []:
                category_id = str(category.get("id") or "").strip().lower()
                if not category_id:
                    continue
                entry = {
                    "id": category_id,
                    "label": str(category.get("label") or category_id.replace("_", " ").title()),
                    "group_id": group["id"],
                    "group_label": group["label"],
                    "platform": selected,
                }
                category_entries.append(entry)
                categories.append(entry)
            groups.append({
                "id": group["id"],
                "label": group["label"],
                "platform": selected,
                "categories": category_entries,
            })
        for quick_select in PLATFORM_QUICK_SELECTS.get(selected, []):
            quick_selects.append({
                "id": quick_select["id"],
                "label": quick_select["label"],
                "platform": selected,
                "category_ids": list(dict.fromkeys(str(item).strip().lower() for item in quick_select.get("category_ids") or [] if str(item).strip())),
            })
    return {
        "platform": normalized if normalized != EvidencePlatform.auto.value else EvidencePlatform.unknown.value,
        "platforms": selected_platforms,
        "groups": groups,
        "quick_selects": quick_selects,
        "categories": categories,
        "available_categories": sorted(available),
    }
