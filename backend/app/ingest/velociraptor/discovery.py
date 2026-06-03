from collections.abc import Callable
from collections import Counter
from datetime import UTC, datetime
import hashlib
import re
from pathlib import Path

from app.ingest.detector import classify_artifact
from app.ingest.defender.helpers import normalize_windows_path as normalize_defender_windows_path
from app.ingest.email.helpers import is_outlook_temp_attachment_path, is_thunderbird_profile_path, is_windows_mail_inventory_path, normalize_windows_path as normalize_email_windows_path
from app.ingest.host_detection import detect_host_from_velociraptor_collection
from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.autoruns.discovery import looks_like_startup_folder_path
from app.ingest.autoruns.helpers import looks_like_autoruns_artifact
from app.ingest.powershell.helpers import POWERSHELL_SCRIPT_EXTENSIONS
from app.ingest.raw_parsers.extraction import evtx_subcategory
from app.ingest.raw_parsers.router import describe_raw_candidate
from app.ingest.bits.helpers import looks_like_bits_artifact
from app.ingest.cloud_sync.helpers import basename_windows, classify_cloud_path_kind, detect_cloud_provider_from_path, looks_like_cloud_sync_artifact, normalize_windows_path as normalize_cloud_windows_path
from app.ingest.network.helpers import looks_like_network_artifact
from app.ingest.recycle_bin.discovery import classify_recycle_entry
from app.ingest.scheduled_tasks.helpers import infer_task_identity_from_filesystem_path, looks_like_scheduled_task_xml_path
from app.ingest.jumplists.helpers import looks_like_jumplist_artifact
from app.ingest.shellbags.helpers import infer_user_from_windows_path, looks_like_shellbags_artifact
from app.ingest.usb.helpers import infer_usb_user_from_path, looks_like_setupapi_log, looks_like_usb_artifact
from app.ingest.wmi.helpers import looks_like_wmi_artifact
from app.ingest.velociraptor.models import VelociraptorDiscoveryResult, VelociraptorEvidenceCandidate
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path, relative_display_path
from app.ingest.velociraptor.zip_inventory import ContainerEntry, EvidenceContainer, inventory_summary, open_evidence_container


RAW_UPLOAD_PATTERNS: list[tuple[str, str, str]] = [
    ("evtx_raw", "Hayabusa / Chainsaw / EvtxECmd", "*.evtx"),
    ("lnk_raw", "LECmd", "*.lnk"),
]

RAW_UPLOAD_NAME_MAP: dict[str, tuple[str, str]] = {
    "ntuser.dat": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "usrclass.dat": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "system": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "software": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "sam": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "security": ("registry_hive_raw", "RECmd / AmcacheParser / AppCompatCacheParser"),
    "amcache.hve": ("amcache", "native_amcache"),
    "recentfilecache.bcf": ("recentfilecache_bcf", "RecentFileCache parser"),
    "history": ("browser_history_raw", "custom sqlite parser / Hindsight"),
    "cookies": ("browser_raw", "custom sqlite parser / Hindsight"),
    "login data": ("browser_raw", "custom sqlite parser / Hindsight"),
    "web data": ("browser_raw", "custom sqlite parser / Hindsight"),
    "places.sqlite": ("browser_history_raw", "custom sqlite parser / Hindsight"),
    "cookies.sqlite": ("browser_raw", "custom sqlite parser / Hindsight"),
    "srudb.dat": ("srum_raw", "SrumECmd"),
    "$mft": ("ntfs_raw", "MFTECmd / UsnJrnl2Csv"),
    "$usnjrnl": ("ntfs_raw", "MFTECmd / UsnJrnl2Csv"),
    "$logfile": ("ntfs_raw", "MFTECmd / UsnJrnl2Csv"),
    "consolehost_history.txt": ("text_raw", "text parser"),
}

TEXT_SUFFIXES = {".ps1", ".bat", ".cmd", ".log", ".txt"}

CHROMIUM_PATTERNS: list[tuple[str, str]] = [
    (r"appdata\\local\\google\\chrome\\user data\\([^\\]+)\\history$", "Chrome"),
    (r"appdata\\local\\microsoft\\edge\\user data\\([^\\]+)\\history$", "Edge"),
    (r"appdata\\local\\bravesoftware\\brave-browser\\user data\\([^\\]+)\\history$", "Brave"),
    (r"appdata\\local\\chromium\\user data\\([^\\]+)\\history$", "Chromium"),
    (r"appdata\\roaming\\opera software\\opera stable\\history$", "Opera"),
]

FIREFOX_PATTERN = r"appdata\\roaming\\mozilla\\firefox\\profiles\\([^\\]+)\\places\.sqlite$"
DEFENDER_ROOT_TOKEN = "programdata\\microsoft\\windows defender\\"
DEFENDER_TOKENS = (
    "windows defender",
    "detectionhistory",
    "mplog",
    "quarantine",
    "scans\\history",
    "support",
)
POWERSHELL_TRANSCRIPT_PATTERNS = (
    r"users\\[^\\]+\\documents\\powershell_transcript.*\.txt$",
    r"users\\[^\\]+\\documents\\windowspowershell_transcript.*\.txt$",
    r"users\\[^\\]+\\desktop\\.*transcript.*\.txt$",
    r"users\\[^\\]+\\documents\\.*transcript.*\.txt$",
    r"programdata\\.*powershell.*\\.*transcript.*\.txt$",
)
PSREADLINE_PATTERNS = (
    r"users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\powershell\\psreadline\\consolehost_history\.txt$",
    r"users\\[^\\]+\\documents\\powershell\\psreadline\\consolehost_history\.txt$",
    r"users\\[^\\]+\\documents\\windowspowershell\\psreadline\\consolehost_history\.txt$",
)
SHELLBAGS_HIVE_PATTERNS = (
    r"users\\[^\\]+\\ntuser\.dat$",
    r"users\\[^\\]+\\appdata\\local\\microsoft\\windows\\usrclass\.dat$",
    r"users\\[^\\]+\\appdata\\local\\microsoft\\windows\\usrclass\.dat\.log[12]$",
    r"users\\[^\\]+\\ntuser\.dat\.log[12]$",
)
JUMPLIST_AUTOMATIC_PATTERN = r"users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\recent\\automaticdestinations\\(?P<appid>[^\\]+)\.automaticdestinations-ms$"
JUMPLIST_CUSTOM_PATTERN = r"users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\recent\\customdestinations\\(?P<appid>[^\\]+)\.customdestinations-ms$"
SETUPAPI_PATTERN = r"windows\\inf\\setupapi\.dev\.log$"
USB_SYSTEM_HIVE_PATTERN = r"windows\\system32\\config\\system$"
USB_SOFTWARE_HIVE_PATTERN = r"windows\\system32\\config\\software$"
BITS_SETUPAPI_EVTX_PATTERN = r"windows\\system32\\winevt\\logs\\microsoft-windows-bits-client%4operational\.evtx$"
BITS_QMGR_PATTERN = r"programdata\\microsoft\\network\\downloader\\(?P<name>qmgr0\.dat|qmgr1\.dat|qmgr\.db)$"
WMI_REPOSITORY_OBJECTS_PATTERN = r"windows\\system32\\wbem\\repository\\objects\.data$"
WMI_REPOSITORY_INDEX_PATTERN = r"windows\\system32\\wbem\\repository\\index\.btr$"
WMI_REPOSITORY_MAPPING_PATTERN = r"windows\\system32\\wbem\\repository\\mapping[^\\]*\.map$"
WMI_ACTIVITY_EVTX_PATTERN = r"windows\\system32\\winevt\\logs\\microsoft-windows-wmi-activity%4operational\.evtx$"
AUTORUNS_SOFTWARE_HIVE_PATTERN = r"windows\\system32\\config\\software$"
AUTORUNS_SYSTEM_HIVE_PATTERN = r"windows\\system32\\config\\system$"
AUTORUNS_NTUSER_PATTERN = r"users\\[^\\]+\\ntuser\.dat$"
AUTORUNS_USRCLASS_PATTERN = r"users\\[^\\]+\\appdata\\local\\microsoft\\windows\\usrclass\.dat$"
WLAN_PROFILE_XML_PATTERN = r"programdata\\microsoft\\wlansvc\\profiles\\interfaces\\[^\\]+\\[^\\]+\.xml$"
WLAN_AUTOCONFIG_EVTX_PATTERN = r"windows\\system32\\winevt\\logs\\microsoft-windows-wlan-autoconfig%4operational\.evtx$"
HOSTS_FILE_PATTERN = r"windows\\system32\\drivers\\etc\\hosts$"
NETWORK_SOFTWARE_HIVE_PATTERN = r"windows\\system32\\config\\software$"
NETWORK_SYSTEM_HIVE_PATTERN = r"windows\\system32\\config\\system$"
NETWORK_NTUSER_PATTERN = r"users\\[^\\]+\\ntuser\.dat$"
OUTLOOK_MAILBOX_PATTERN = r"users\\[^\\]+\\(?:appdata\\local|local settings\\application data)\\microsoft\\outlook\\[^\\]+\.(?:pst|ost)$"


def _candidate_id(category: str, path: str) -> str:
    digest = hashlib.sha1(f"{category}:{path}".encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"velo-{digest[:16]}"


def _classify_lnk_location(path: str | None) -> str:
    normalized = (normalize_velociraptor_path(path or "") or "").lower()
    if "\\microsoft\\office\\recent\\" in normalized:
        return "office_recent"
    if "\\microsoft\\windows\\recent\\" in normalized:
        return "recent"
    if looks_like_startup_folder_path(normalized):
        return "startup"
    if "\\desktop\\" in normalized:
        return "desktop"
    if "\\downloads\\" in normalized:
        return "downloads"
    if "\\microsoft\\windows\\start menu\\" in normalized:
        return "start_menu"
    return "other"


def _parse_prefetch_filename(filename: str | None) -> tuple[str | None, str | None]:
    cleaned = Path(str(filename or "")).name
    match = re.match(r"(?P<exe>.+?)(?:-(?P<hash>[0-9A-Fa-f]{8}))?\.pf$", cleaned, flags=re.IGNORECASE)
    if not match:
        return None, None
    executable = str(match.group("exe") or "").strip() or None
    pf_hash = str(match.group("hash") or "").upper() or None
    return executable, pf_hash


def _parse_browser_candidate(entry: ContainerEntry, entry_map: dict[str, ContainerEntry], *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel).lower()
    warnings: list[str] = []
    user = extract_user_from_path(normalized)
    browser: str | None = None
    profile: str | None = None
    artifact_type: str | None = None

    for pattern, browser_name in CHROMIUM_PATTERNS:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            browser = browser_name
            profile = match.group(1) if match.groups() else ("Opera Stable" if browser_name == "Opera" else None)
            artifact_type = "chromium_history"
            break
    if not artifact_type:
        match = re.search(FIREFOX_PATTERN, normalized, flags=re.IGNORECASE)
        if match:
            browser = "Firefox"
            profile = match.group(1)
            artifact_type = "firefox_places"

    if not artifact_type:
        return None

    companions = []
    for suffix in ("-wal", "-shm"):
        companion_path = f"{entry.path}{suffix}"
        if companion_path.lower() in entry_map:
            companions.append(companion_path)
    if artifact_type == "chromium_history" and not companions:
        warnings.append("History WAL/SHM not found; recent rows may be missing.")
    if artifact_type == "firefox_places" and not companions:
        warnings.append("places.sqlite WAL/SHM not found; recent rows may be missing.")

    display_name = f"{browser} History - {user or 'unknown-user'} - {profile or 'default'}"
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("browser", rel),
        category="browser",
        artifact_type=artifact_type,
        parser_status="ready",
        display_name=display_name,
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalize_velociraptor_path(rel),
        user=user,
        browser=browser,
        profile=profile,
        size=entry.size,
        mtime=entry.mtime,
        confidence="high",
        supported=True,
        reason=None,
        warnings=warnings,
        companion_files=companions,
        container_type=container_type,
        container_path=container_path,
    )


def _parse_scheduled_task_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    path_obj = Path(entry.path)
    normalized = normalize_velociraptor_path(entry.path)
    lower_normalized = normalized.lower()
    is_legacy_job = lower_normalized.startswith("c:\\windows\\tasks\\") and path_obj.suffix.lower() == ".job"
    if not looks_like_scheduled_task_xml_path(path_obj) and not is_legacy_job:
        return None
    if path_obj.name.lower() == "desktop.ini" or entry.size == 0:
        return None
    rel = entry.path
    task_path, task_name = infer_task_identity_from_filesystem_path(normalized)
    if not task_path or not task_name:
        return None
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("scheduled_task", rel),
        category="scheduled_task",
        artifact_type="scheduled_task",
        parser="scheduled_task_xml" if not is_legacy_job else None,
        parser_status="detected_not_implemented" if is_legacy_job else "ready",
        display_name=f"Scheduled Task - {task_path}",
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalized,
        user=None,
        task_name=task_name,
        task_path=task_path,
        size=entry.size,
        mtime=entry.mtime,
        confidence="high",
        supported=not is_legacy_job,
        reason="Legacy .job scheduled task detected. Native .job parser not implemented yet." if is_legacy_job else None,
        warnings=[],
        container_type=container_type,
        container_path=container_path,
    )


def _parse_defender_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    if not any(token in lower_normalized for token in DEFENDER_TOKENS):
        return None
    lower_name = Path(entry.path).name.lower()
    warnings: list[str] = []
    supported = False
    parser_status = "detected_not_implemented"
    artifact_type = "defender_generic"
    reason = "Detected raw Defender artifact. Parser not implemented yet."
    display_name = Path(entry.path).name

    if Path(entry.path).suffix.lower() == ".evtx":
        artifact_type = "defender_evtx"
        supported = False
        parser_status = "handled_by_evtx_parser"
        reason = "Defender EVTX found; handled by EVTX parser"
        display_name = f"Defender EVTX - {Path(entry.path).name}"
    elif "\\scans\\history\\service\\detectionhistory\\" in lower_normalized:
        artifact_type = "defender_detection_history"
        supported = True
        parser_status = "ready"
        reason = None
        display_name = f"Defender DetectionHistory - {Path(entry.path).name}"
    elif "\\support\\" in lower_normalized and lower_name.startswith("mplog"):
        artifact_type = "defender_mplog"
        supported = True
        parser_status = "ready"
        reason = None
        display_name = f"Defender MPLog - {Path(entry.path).name}"
    elif "\\support\\" in lower_normalized:
        artifact_type = "defender_support_log"
        supported = lower_name.endswith((".log", ".txt"))
        parser_status = "ready" if supported else "detected_not_implemented"
        reason = None if supported else "Detected Defender support artifact. Raw parser not implemented yet."
        display_name = f"Defender Support - {Path(entry.path).name}"
    elif "\\quarantine\\" in lower_normalized:
        artifact_type = "defender_quarantine"
        supported = False
        parser_status = "discovery_only"
        reason = "Quarantine found but raw parser not implemented"
        display_name = f"Defender Quarantine - {Path(entry.path).name}"
    elif "\\scans\\history\\results\\" in lower_normalized:
        artifact_type = "defender_support_log"
        supported = lower_name.endswith((".log", ".txt", ".json"))
        parser_status = "ready" if supported else "detected_not_implemented"
        reason = None if supported else "Detected Defender scan results artifact. Raw parser not implemented yet."
        display_name = f"Defender Results - {Path(entry.path).name}"
    elif any(token in lower_normalized for token in ["\\mpcache", "\\definition updates\\", "\\platform\\"]):
        artifact_type = "defender_generic"
        supported = False
        parser_status = "detected_not_implemented"
        reason = "Detected raw Defender platform/cache artifact. Parser not implemented yet."
        display_name = f"Defender Artifact - {Path(entry.path).name}"
    else:
        return None

    return VelociraptorEvidenceCandidate(
        id=_candidate_id("defender", rel),
        category="defender",
        artifact_type=artifact_type,
        parser_status=parser_status,
        display_name=display_name,
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalize_defender_windows_path(normalized),
        user=extract_user_from_path(normalized),
        size=entry.size,
        mtime=entry.mtime,
        confidence="high" if supported else "medium",
        supported=supported,
        reason=reason,
        warnings=warnings,
        container_type=container_type,
        container_path=container_path,
    )


def _build_defender_discovery_summary_candidate(
    *,
    container_path: str,
    defender_paths: list[ContainerEntry],
    has_detection_history: bool,
    has_mplog: bool,
    has_evtx: bool,
    has_quarantine: bool,
) -> VelociraptorEvidenceCandidate | None:
    if not defender_paths:
        return None
    if has_detection_history or has_mplog:
        return None
    first = sorted(defender_paths, key=lambda item: item.path)[0]
    rel = first.path
    normalized = normalize_velociraptor_path(rel)
    warnings: list[str] = []
    if not has_detection_history:
        warnings.append("Expected ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory was not found")
    if not has_mplog:
        warnings.append("Expected ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog*.log was not found")
    if has_evtx:
        reason = "Defender EVTX found; handled by EVTX parser"
    elif has_quarantine:
        reason = "Quarantine found but raw parser not implemented"
    else:
        reason = "Defender directory found but DetectionHistory/MPLog not collected"
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("defender", f"{rel}:directory-only"),
        category="defender",
        artifact_type="defender_directory_only",
        parser_status="detected_but_no_parseable_files",
        display_name="Defender directory only",
        original_path=rel,
        local_path=first.local_path or "",
        normalized_windows_path=normalize_defender_windows_path(normalized),
        user=extract_user_from_path(normalized),
        size=first.size,
        mtime=first.mtime,
        confidence="medium",
        supported=False,
        reason=reason,
        warnings=warnings,
        container_type=first.container_type,
        container_path=container_path,
    )


def _parse_powershell_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    if "\\$recycle.bin\\" in lower_normalized or "/$recycle.bin/" in lower_normalized:
        return None
    user = extract_user_from_path(normalized)
    artifact_type = None
    supported = False
    parser_status = "detected_not_implemented"
    reason = None
    display_name = Path(entry.path).name
    warnings: list[str] = []

    if any(re.search(pattern, lower_normalized, flags=re.IGNORECASE) for pattern in PSREADLINE_PATTERNS):
        artifact_type = "psreadline_history"
        supported = True
        parser_status = "ready"
        display_name = f"PSReadLine History - {user or 'unknown-user'}"
    elif any(re.search(pattern, lower_normalized, flags=re.IGNORECASE) for pattern in POWERSHELL_TRANSCRIPT_PATTERNS):
        artifact_type = "powershell_transcript"
        supported = True
        parser_status = "ready"
        display_name = f"PowerShell Transcript - {user or 'unknown-user'}"
    elif Path(entry.path).suffix.lower() in POWERSHELL_SCRIPT_EXTENSIONS:
        artifact_type = "powershell_script"
        supported = True
        parser_status = "partial"
        reason = "Script content can be observed, but script presence alone does not prove execution."
        display_name = f"PowerShell Script - {Path(entry.path).name}"
    else:
        return None

    return VelociraptorEvidenceCandidate(
        id=_candidate_id("powershell", rel),
        category="powershell",
        artifact_type=artifact_type,
        parser_status=parser_status,
        display_name=display_name,
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalized,
        user=user,
        size=entry.size,
        mtime=entry.mtime,
        confidence="high" if supported else "medium",
        supported=supported,
        reason=reason,
        warnings=warnings,
        container_type=container_type,
        container_path=container_path,
    )


def _parse_recycle_candidate(entry: ContainerEntry, entry_map: dict[str, ContainerEntry], *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    classification = classify_recycle_entry(entry.path)
    if not classification:
        return None
    pair_id = classification["pair_id"]
    sid = classification["sid"]
    kind = classification["kind"]
    original_i_path = entry.path if kind == "i" else None
    original_r_path = entry.path if kind == "r" else None
    if kind == "i":
        sibling_name = entry.path.replace("/$I", "/$R").replace("\\$I", "\\$R")
        if sibling_name == entry.path:
            path_name = Path(entry.path).name
            sibling_name = entry.path[: -len(path_name)] + "$R" + path_name[2:]
        r_entry = entry_map.get(sibling_name.lower())
        if r_entry:
            original_r_path = r_entry.path
        supported = True
        parser_status = "ready"
        artifact_type = "recycle_pair" if original_r_path else "recycle_i_file"
        reason = None
    else:
        supported = True
        parser_status = "partial"
        artifact_type = "recycle_r_file"
        reason = "Recycle content file found without matching $I metadata."
    warnings: list[str] = []
    if kind == "i" and not original_r_path:
        warnings.append("Recycle Bin metadata exists but content file is missing")
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("recycle_bin", f"{sid}:{pair_id}:{kind}"),
        category="recycle_bin",
        artifact_type=artifact_type,
        parser_status=parser_status,
        display_name=f"Recycle Bin - {pair_id}",
        original_path=entry.path,
        local_path=entry.local_path or "",
        normalized_windows_path=normalize_velociraptor_path(entry.path),
        sid=sid,
        original_i_path=original_i_path,
        original_r_path=original_r_path,
        local_i_path=entry.local_path if kind == "i" else None,
        local_r_path=(entry_map.get(original_r_path.lower()).local_path if original_r_path and entry_map.get(original_r_path.lower()) else entry.local_path if kind == "r" else None),
        normalized_windows_i_path=normalize_velociraptor_path(original_i_path) if original_i_path else None,
        normalized_windows_r_path=normalize_velociraptor_path(original_r_path) if original_r_path else None,
        has_metadata_file=kind == "i",
        has_content_file=bool(original_r_path) if kind == "i" else True,
        pair_id=pair_id,
        size=entry.size,
        mtime=entry.mtime,
        confidence="high" if kind == "i" else "low",
        supported=supported,
        reason=reason,
        warnings=warnings,
        companion_files=[original_r_path] if original_r_path and kind == "i" else [],
        container_type=container_type,
        container_path=container_path,
    )


def _parse_shellbags_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    lower_name = Path(entry.path).name.lower()
    user = infer_user_from_windows_path(normalized)
    warnings: list[str] = []

    if entry.size == 0:
        warnings.append("Shellbags candidate is empty.")

    if looks_like_shellbags_artifact(Path(entry.path), None):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("shellbags", rel),
            category="shellbags",
            artifact_type="shellbag_generic",
            parser_status="ready",
            display_name=f"Shellbags - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            user=user,
            hive_type=None,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=warnings,
            container_type=container_type,
            container_path=container_path,
        )

    if not any(re.search(pattern, lower_normalized, flags=re.IGNORECASE) for pattern in SHELLBAGS_HIVE_PATTERNS):
        return None

    if lower_name == "ntuser.dat":
        artifact_type = "shellbags_user_hive_ntuser"
        hive_type = "NTUSER.DAT"
    elif lower_name == "usrclass.dat":
        artifact_type = "shellbags_user_hive_usrclass"
        hive_type = "UsrClass.dat"
    else:
        artifact_type = "shellbags_registry_hive"
        hive_type = "Registry transaction log"

    return VelociraptorEvidenceCandidate(
        id=_candidate_id("shellbags", rel),
        category="shellbags",
        artifact_type=artifact_type,
        parser_status="detected_not_implemented",
        display_name=f"Shellbags raw hive - {Path(entry.path).name}",
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalized,
        user=user,
        hive_type=hive_type,
        size=entry.size,
        mtime=entry.mtime,
        confidence="medium",
        supported=False,
        reason="Shellbags raw hives detected. Raw hive parsing is not implemented yet. Use SBECmd parsed CSV for now.",
        warnings=warnings,
        container_type=container_type,
        container_path=container_path,
    )


def _parse_jumplist_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    user = extract_user_from_path(normalized)

    if looks_like_jumplist_artifact(Path(entry.path), None):
        lower_name = Path(entry.path).name.lower()
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("jumplist", rel),
            category="jumplist",
            artifact_type="automatic_destinations" if "automaticdestinations" in lower_name else "custom_destinations" if "customdestinations" in lower_name else "jumplist_entry",
            parser_status="ready",
            parser="jlecmd",
            display_name=f"JumpLists - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            user=user,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )

    automatic = re.search(JUMPLIST_AUTOMATIC_PATTERN, lower_normalized, flags=re.IGNORECASE)
    custom = re.search(JUMPLIST_CUSTOM_PATTERN, lower_normalized, flags=re.IGNORECASE)
    if not automatic and not custom:
        return None
    app_id = (automatic or custom).group("appid")
    destination_type = "automatic" if automatic else "custom"
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("jumplist", rel),
        category="jumplist",
        artifact_type="jumplist_automatic_destinations" if automatic else "jumplist_custom_destinations",
        parser_status="ready" if automatic else "partial",
        parser="jumplist_raw_automatic" if automatic else "jumplist_raw_custom",
        display_name=f"JumpList raw - {Path(rel).name}",
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalized,
        user=user,
        app_id=app_id,
        destination_type=destination_type,
        size=entry.size,
        mtime=entry.mtime,
        confidence="medium",
        supported=True,
        reason="Raw automaticDestinations files can be parsed directly. CustomDestinations support is partial." if automatic else "CustomDestinations support is partial. Some files may yield warnings or low-value records.",
        warnings=[],
        container_type=container_type,
        container_path=container_path,
    )


def _parse_usb_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    lower_name = Path(entry.path).name.lower()

    if re.search(SETUPAPI_PATTERN, lower_normalized, flags=re.IGNORECASE) or looks_like_setupapi_log(Path(entry.path)):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("usb", rel),
            category="usb",
            artifact_type="setupapi_dev_log",
            parser_status="ready",
            display_name="USB SetupAPI - setupapi.dev.log",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="usb_setupapi",
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )

    if lower_name.endswith((".csv", ".json", ".jsonl", ".txt")) and looks_like_usb_artifact(Path(entry.path), None):
        artifact_type = (
            "mounted_device" if "mounteddevices" in lower_name
            else "mountpoints2" if "mountpoints2" in lower_name
            else "portable_device" if "portabledevices" in lower_name
            else "usbstor_device" if "usbstor" in lower_name
            else "usb_registry_csv"
        )
        parser = (
            "usb_evtx" if lower_name.endswith((".json", ".jsonl")) and any(token in lower_name for token in ["userpnp", "kernel-pnp", "driverframeworks"])
            else "usb_mounteddevices" if "mounteddevices" in lower_name
            else "usb_mountpoints2" if "mountpoints2" in lower_name
            else "usb_jsonl" if lower_name.endswith(".jsonl")
            else "usb_json" if lower_name.endswith(".json")
            else "usb_raw" if lower_name.endswith(".txt")
            else "usb_registry"
        )
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("usb", rel),
            category="usb",
            artifact_type=artifact_type,
            parser_status="ready",
            display_name=f"USB CSV - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            user=infer_usb_user_from_path(normalized),
            parser=parser,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )

    if re.search(USB_SYSTEM_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("usb", rel),
            category="usb",
            artifact_type="registry_system_hive_usb_candidate",
            parser_status="detected_not_implemented",
            display_name="USB Registry candidate - SYSTEM hive",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="registry_hive",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="USB-relevant SYSTEM hive detected. Raw hive parsing is not implemented yet; use RECmd parsed CSV for now.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(USB_SOFTWARE_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("usb", rel),
            category="usb",
            artifact_type="registry_software_hive_usb_candidate",
            parser_status="detected_not_implemented",
            display_name="USB Registry candidate - SOFTWARE hive",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="registry_hive",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="USB-relevant SOFTWARE hive detected. Raw hive parsing is not implemented yet; use RECmd parsed CSV for now.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(SHELLBAGS_HIVE_PATTERNS[0], lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("usb", rel),
            category="usb",
            artifact_type="registry_user_hive_usb_candidate",
            parser_status="detected_not_implemented",
            display_name=f"USB Registry candidate - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            user=infer_usb_user_from_path(normalized),
            parser="registry_hive",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="USB-relevant user hive detected. Raw hive parsing is not implemented yet; use RECmd parsed CSV for now.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _parse_email_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_email_windows_path(normalize_velociraptor_path(rel) or rel) or rel.replace("/", "\\")
    lower_normalized = normalized.lower()
    path_obj = Path(entry.path)
    lower_name = path_obj.name.lower()

    parser: str | None = None
    artifact_type = "email_message"
    supported = True
    reason: str | None = None

    if path_obj.suffix.lower() == ".eml":
        parser = "email_eml"
        artifact_type = "email_message"
    elif path_obj.suffix.lower() == ".mbox" or (is_thunderbird_profile_path(normalized) and path_obj.suffix.lower() not in {".msf", ".sqlite"} and lower_name in {"inbox", "sent", "archives", "drafts", "trash", "junk", "templates"}):
        parser = "email_mbox"
        artifact_type = "email_message"
    elif path_obj.suffix.lower() == ".pst" and re.search(OUTLOOK_MAILBOX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        parser = "email_pst_inventory"
        artifact_type = "email_pst_inventory"
        reason = "PST detected. Email Artifacts v1 inventories mailbox files but does not parse PST contents."
    elif path_obj.suffix.lower() == ".ost" and re.search(OUTLOOK_MAILBOX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        parser = "email_ost_inventory"
        artifact_type = "email_ost_inventory"
        reason = "OST detected. Email Artifacts v1 inventories mailbox files but does not parse OST contents."
    elif is_outlook_temp_attachment_path(normalized):
        parser = "email_outlook_temp_attachment"
        artifact_type = "email_temp_attachment"
    elif is_windows_mail_inventory_path(normalized):
        parser = "email_windows_mail_inventory"
        artifact_type = "email_windows_mail_inventory"
        reason = "Windows Mail artifact detected. Email Artifacts v1 inventories store metadata only."
    else:
        return None

    user = extract_user_from_path(normalized)
    display_name = (
        f"Email message - {path_obj.name}" if parser in {"email_eml", "email_mbox"}
        else f"Outlook temp attachment - {path_obj.name}" if parser == "email_outlook_temp_attachment"
        else f"Mailbox inventory - {path_obj.name}" if parser in {"email_pst_inventory", "email_ost_inventory"}
        else f"Windows Mail inventory - {path_obj.name}"
    )
    return VelociraptorEvidenceCandidate(
        id=_candidate_id("email", rel),
        category="email",
        artifact_type=artifact_type,
        parser_status="ready" if supported else "detected_not_implemented",
        display_name=display_name,
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalized,
        user=user,
        parser=parser,
        size=entry.size,
        mtime=entry.mtime,
        confidence="high" if parser in {"email_eml", "email_mbox", "email_outlook_temp_attachment"} else "medium",
        supported=supported,
        reason=reason,
        warnings=[],
        container_type=container_type,
        container_path=container_path,
    )


def _parse_bits_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    lower_name = Path(entry.path).name.lower()

    qmgr_match = re.search(BITS_QMGR_PATTERN, lower_normalized, flags=re.IGNORECASE)
    if qmgr_match:
        artifact_type = "bits_qmgr_db" if lower_name == "qmgr.db" else "bits_qmgr_dat"
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("bits", rel),
            category="bits",
            artifact_type=artifact_type,
            parser_status="detected_not_implemented",
            display_name=f"BITS raw - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="bits_qmgr",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="BITS qmgr raw database detected. Raw qmgr parsing is not implemented yet.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )

    if re.search(BITS_SETUPAPI_EVTX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("bits", rel),
            category="bits",
            artifact_type="bits_evtx",
            parser_status="handled_by_evtx_parser",
            display_name="BITS EVTX - Microsoft-Windows-Bits-Client Operational",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="evtx",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="BITS EVTX found; handled by EVTX parser.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )

    if looks_like_bits_artifact(Path(entry.path), None):
        parser = "bits_jsonl" if lower_name.endswith(".jsonl") else "bits_json" if lower_name.endswith(".json") else "bits_raw" if lower_name.endswith(".txt") and "bitsadmin" in lower_name else "bits_csv"
        artifact_type = "bits_transfer"
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("bits", rel),
            category="bits",
            artifact_type=artifact_type,
            parser_status="ready",
            display_name=f"BITS Parsed - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser=parser,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _parse_wmi_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    lower_name = Path(entry.path).name.lower()

    if re.search(WMI_REPOSITORY_OBJECTS_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("wmi", rel),
            category="wmi",
            artifact_type="wmi_objects_data",
            parser_status="detected_not_implemented",
            display_name="WMI repository - OBJECTS.DATA",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="raw_discovery",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="WMI repository raw OBJECTS.DATA detected. Raw repository parsing is not implemented yet.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(WMI_REPOSITORY_INDEX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("wmi", rel),
            category="wmi",
            artifact_type="wmi_index_btr",
            parser_status="detected_not_implemented",
            display_name="WMI repository - INDEX.BTR",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="raw_discovery",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="WMI repository raw INDEX.BTR detected. Raw repository parsing is not implemented yet.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(WMI_REPOSITORY_MAPPING_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("wmi", rel),
            category="wmi",
            artifact_type="wmi_mapping_map",
            parser_status="detected_not_implemented",
            display_name=f"WMI repository - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="raw_discovery",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="WMI repository raw mapping file detected. Raw repository parsing is not implemented yet.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(WMI_ACTIVITY_EVTX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("wmi", rel),
            category="wmi",
            artifact_type="wmi_activity_evtx",
            parser_status="handled_by_evtx_parser",
            display_name="WMI Activity EVTX - Operational",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="evtx",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="WMI Activity EVTX found; handled by EVTX parser.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if looks_like_wmi_artifact(Path(entry.path), None):
        parser = "wmi_jsonl" if lower_name.endswith(".jsonl") else "wmi_json" if lower_name.endswith(".json") else "autoruns" if "autoruns" in lower_name else "wmi_csv"
        artifact_type = (
            "wmi_filter_to_consumer_binding" if "filtertoconsumerbinding" in lower_name
            else "wmi_command_line_consumer" if "commandlineeventconsumer" in lower_name
            else "wmi_active_script_consumer" if "activescripteventconsumer" in lower_name
            else "wmi_event_filter" if "eventfilter" in lower_name
            else "wmi_activity_event" if "wmi-activity" in lower_name
            else "wmi_parsed_json" if parser == "wmi_json"
            else "wmi_generic"
        )
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("wmi", rel),
            category="wmi",
            artifact_type=artifact_type,
            parser_status="ready",
            display_name=f"WMI Parsed - {Path(entry.path).name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser=parser,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _parse_autoruns_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    path_obj = Path(entry.path)
    lower_name = path_obj.name.lower()

    if looks_like_autoruns_artifact(path_obj, None):
        parser = "autoruns_xml" if lower_name.endswith(".xml") else "autoruns_tsv" if lower_name.endswith(".tsv") else "autoruns_csv"
        artifact_type = (
            "autoruns_xml" if parser == "autoruns_xml"
            else "autoruns_tsv" if parser == "autoruns_tsv"
            else "autorunsc_output" if "autorunsc" in lower_name
            else "autoruns_csv"
        )
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("autoruns", rel),
            category="autoruns",
            artifact_type=artifact_type,
            parser_status="ready",
            display_name=f"Autoruns Parsed - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser=parser,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if looks_like_startup_folder_path(normalized):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("autoruns", rel),
            category="autoruns",
            artifact_type="startup_folder_file",
            parser_status="ready",
            display_name=f"Startup folder file - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="startup_folder",
            user=extract_user_from_path(normalized),
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(AUTORUNS_SOFTWARE_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE) or re.search(AUTORUNS_SYSTEM_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE) or re.search(AUTORUNS_NTUSER_PATTERN, lower_normalized, flags=re.IGNORECASE) or re.search(AUTORUNS_USRCLASS_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("autoruns", rel),
            category="autoruns",
            artifact_type="registry_asep_candidate",
            parser_status="detected_not_implemented",
            display_name=f"ASEP registry candidate - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="registry_hive",
            user=extract_user_from_path(normalized),
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="ASEP-relevant raw registry hive detected. Raw hive parsing is not implemented yet; use RECmd parsed CSV for now.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _parse_cloud_candidate(
    entry: ContainerEntry,
    *,
    container_path: str,
    container_type: str,
    seen_cloud_roots: set[str],
) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    provider, sync_root, _ = detect_cloud_provider_from_path(normalized)
    path_obj = Path(entry.path)
    lower_name = path_obj.name.lower()
    artifact_type, parser_hint = classify_cloud_path_kind(normalized)
    parseable_cloud_suffixes = (".csv", ".json", ".log", ".txt", ".ini")

    if looks_like_cloud_sync_artifact(path_obj, None) or (
        provider
        and artifact_type in {"cloud_client_config", "cloud_client_log"}
        and lower_name.endswith(parseable_cloud_suffixes)
    ):
        parser = "cloud_json" if lower_name.endswith(".json") else "provider_log" if lower_name.endswith((".log", ".txt", ".ini")) else "cloud_csv"
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("cloud_sync", rel),
            category="cloud_sync",
            artifact_type=artifact_type or "cloud_generic",
            parser_status="ready",
            display_name=f"Cloud sync parsed/log artifact - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser=parser if parser_hint != "raw_discovery" else "path_inference",
            provider=provider,
            user=extract_user_from_path(normalized),
            sync_root=sync_root,
            size=entry.size,
            mtime=entry.mtime,
            confidence="high" if parser != "path_inference" else "medium",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if provider and sync_root:
        root_key = sync_root.lower()
        if root_key in seen_cloud_roots:
            return None
        seen_cloud_roots.add(root_key)
        artifact_type = f"{provider}_folder"
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("cloud_sync", rel),
            category="cloud_sync",
            artifact_type=artifact_type,
            parser_status="discovery_only",
            display_name=f"{provider.replace('_', ' ').title()} sync root - {basename_windows(sync_root) or sync_root}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=sync_root,
            parser="path_inference",
            provider=provider,
            user=extract_user_from_path(normalized),
            sync_root=sync_root,
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=True,
            reason="Cloud sync root observed via path inference. Folder contents are not extracted in bulk by default.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _parse_network_candidate(entry: ContainerEntry, *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    rel = entry.path
    normalized = normalize_velociraptor_path(rel)
    lower_normalized = normalized.lower()
    path_obj = Path(entry.path)
    lower_name = path_obj.name.lower()

    if re.search(WLAN_PROFILE_XML_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network", rel),
            category="network",
            artifact_type="wlan_profile_xml",
            parser_status="ready",
            display_name=f"WLAN profile - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="wlan_profile_xml",
            user=extract_user_from_path(normalized),
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(WLAN_AUTOCONFIG_EVTX_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network", rel),
            category="network",
            artifact_type="wlan_autoconfig_evtx",
            parser_status="handled_by_evtx_parser",
            display_name="WLAN AutoConfig EVTX - Operational",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="evtx",
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="WLAN AutoConfig EVTX found; handled by EVTX parser.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(HOSTS_FILE_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network", rel),
            category="network",
            artifact_type="hosts_file",
            parser_status="ready",
            display_name="Hosts file",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="hosts_file",
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if re.search(NETWORK_SOFTWARE_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE) or re.search(NETWORK_SYSTEM_HIVE_PATTERN, lower_normalized, flags=re.IGNORECASE) or re.search(NETWORK_NTUSER_PATTERN, lower_normalized, flags=re.IGNORECASE):
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network", rel),
            category="network",
            artifact_type="network_registry_hive_candidate",
            parser_status="detected_not_implemented",
            display_name=f"Network registry candidate - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser="registry_hive",
            user=extract_user_from_path(normalized),
            size=entry.size,
            mtime=entry.mtime,
            confidence="medium",
            supported=False,
            reason="Network-relevant raw registry hive detected. Raw hive parsing is not implemented yet; use RECmd parsed CSV for now.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if looks_like_network_artifact(path_obj, None):
        parser = (
            "wlan_profile_xml" if lower_name.endswith(".xml")
            else "hosts_file" if lower_name == "hosts"
            else "network_json" if lower_name.endswith(".json")
            else "dns_csv" if "dns" in lower_name and lower_name.endswith(".csv")
            else "ipconfig_txt" if "ipconfig" in lower_name
            else "netsh_txt" if "netsh" in lower_name or "wlan" in lower_name
            else "network_txt" if lower_name.endswith(".txt")
            else "network_csv"
        )
        artifact_type = (
            "dns_cache_output" if "dnscache" in lower_name
            else "dns_config_output" if any(token in lower_name for token in ["dnsclientserveraddress", "dnsserver"])
            else "ipconfig_output" if "ipconfig" in lower_name
            else "netsh_wlan_output" if "netsh" in lower_name or "wlan" in lower_name
            else "netadapter_output" if "netadapter" in lower_name
            else "netipconfiguration_output" if "netipconfiguration" in lower_name
            else "route_table_output" if "route" in lower_name
            else "netstat_output" if "netstat" in lower_name
            else "arp_output" if "arp" in lower_name
            else "networklist_registry" if "networklist" in lower_name
            else "tcpip_interfaces_registry" if "tcpip" in lower_name or "interfaces" in lower_name
            else "network_generic"
        )
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network", rel),
            category="network",
            artifact_type=artifact_type,
            parser_status="ready",
            display_name=f"Network artifact - {path_obj.name}",
            original_path=rel,
            local_path=entry.local_path or "",
            normalized_windows_path=normalized,
            parser=parser,
            user=extract_user_from_path(normalized),
            size=entry.size,
            mtime=entry.mtime,
            confidence="high",
            supported=True,
            reason=None,
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    return None


def _raw_candidate(entry: ContainerEntry, *, category: str, artifact_type: str, reason: str, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate:
    rel = entry.path
    return VelociraptorEvidenceCandidate(
        id=_candidate_id(category, rel),
        category=category,
        artifact_type=artifact_type,
        parser_status="detected_not_implemented",
        display_name=Path(entry.path).name,
        original_path=rel,
        local_path=entry.local_path or "",
        normalized_windows_path=normalize_velociraptor_path(rel),
        filename=Path(entry.path).name,
        user=extract_user_from_path(rel),
        size=entry.size,
        mtime=entry.mtime,
        confidence="medium",
        supported=False,
        reason=reason,
        warnings=[],
        container_type=container_type,
        container_path=container_path,
    )


def _find_amcache_companion_files(entry: ContainerEntry, entry_map: dict[str, ContainerEntry]) -> list[str]:
    lower_path = entry.path.lower()
    companions: list[str] = []
    for suffix in (".log1", ".log2", ".idx", ".log1.idx", ".log2.idx"):
        companion = entry_map.get(lower_path + suffix)
        if companion:
            companions.append(companion.path)
    return companions


def _find_system_companion_files(entry: ContainerEntry, entry_map: dict[str, ContainerEntry]) -> list[str]:
    lower_path = entry.path.lower()
    companions: list[str] = []
    for suffix in (".log1", ".log2"):
        companion = entry_map.get(lower_path + suffix)
        if companion:
            companions.append(companion.path)
    return companions


def _detect_raw_candidate(entry: ContainerEntry, entry_map: dict[str, ContainerEntry], *, container_path: str, container_type: str) -> VelociraptorEvidenceCandidate | None:
    lower_name = Path(entry.path).name.lower()
    lower_relative = entry.path.lower()

    if lower_relative.endswith(("amcache.hve.log1", "amcache.hve.log2", "amcache.hve.idx", "amcache.hve.log1.idx", "amcache.hve.log2.idx")):
        return None
    normalized_lower = normalize_velociraptor_path(lower_relative).lower()
    if normalized_lower.endswith("windows\\system32\\config\\system.log1") or normalized_lower.endswith("windows\\system32\\config\\system.log2"):
        return None

    if Path(entry.path).suffix.lower() == ".evtx":
        native = describe_raw_candidate(entry.path, "evtx_raw")
        if native:
            subcategory = evtx_subcategory(entry.path)
            return VelociraptorEvidenceCandidate(
                id=_candidate_id("evtx", entry.path),
                category="evtx",
                artifact_type="evtx_raw",
                parser_status=str(native["parser_status"]),
                display_name=f"EVTX raw - {Path(entry.path).name}",
                original_path=entry.path,
                local_path=entry.local_path or "",
                normalized_windows_path=normalize_velociraptor_path(entry.path),
                parser=str(native["parser"]),
                size=entry.size,
                mtime=entry.mtime,
                confidence="medium",
                supported=bool(native["supported"]),
                reason=f'{native["reason"]}{f" Subcategory: {subcategory}." if subcategory and native["supported"] else ""}',
                warnings=[],
                container_type=container_type,
                container_path=container_path,
            )
    if Path(entry.path).suffix.lower() == ".lnk":
        native = describe_raw_candidate(entry.path, "lnk_raw")
        if native:
            normalized_path = normalize_velociraptor_path(entry.path)
            lnk_location = _classify_lnk_location(normalized_path)
            return VelociraptorEvidenceCandidate(
                id=_candidate_id("lnk", entry.path),
                category="lnk",
                artifact_type="lnk_raw",
                parser_status=str(native["parser_status"]),
                display_name=f"LNK raw - {Path(entry.path).name}",
                original_path=entry.path,
                local_path=entry.local_path or "",
                normalized_windows_path=normalized_path,
                user=extract_user_from_path(normalized_path),
                lnk_location=lnk_location,
                parser=str(native["parser"]),
                size=entry.size,
                mtime=entry.mtime,
                confidence="medium",
                supported=bool(native["supported"]),
                reason=str(native["reason"]),
                warnings=[],
                container_type=container_type,
                container_path=container_path,
            )
    if Path(entry.path).suffix.lower() == ".pf":
        native = describe_raw_candidate(entry.path, "prefetch_raw")
        executable_name_guess, prefetch_hash_guess = _parse_prefetch_filename(Path(entry.path).name)
        if native:
            normalized_path = normalize_velociraptor_path(entry.path)
            return VelociraptorEvidenceCandidate(
                id=_candidate_id("prefetch", entry.path),
                category="prefetch",
                artifact_type="prefetch_raw",
                parser_status=str(native["parser_status"]),
                display_name=f"Prefetch raw - {Path(entry.path).name}",
                original_path=entry.path,
                local_path=entry.local_path or "",
                normalized_windows_path=normalized_path,
                filename=Path(entry.path).name,
                executable_name_guess=executable_name_guess,
                prefetch_hash_guess=prefetch_hash_guess,
                parser=str(native["parser"]),
                size=entry.size,
                mtime=entry.mtime,
                confidence="medium",
                supported=bool(native["supported"]),
                reason=str(native["reason"]),
                warnings=[],
                container_type=container_type,
                container_path=container_path,
            )
    if lower_name == "amcache.hve":
        native = describe_raw_candidate(entry.path, "amcache")
        if native:
            return VelociraptorEvidenceCandidate(
                id=_candidate_id("amcache", entry.path),
                category="amcache",
                artifact_type="amcache",
                parser_status=str(native["parser_status"]),
                display_name=f"Amcache raw - {Path(entry.path).name}",
                original_path=entry.path,
                local_path=entry.local_path or "",
                normalized_windows_path=normalize_velociraptor_path(entry.path),
                filename=Path(entry.path).name,
                parser=str(native["parser"]),
                size=entry.size,
                mtime=entry.mtime,
                confidence="medium",
                supported=bool(native["supported"]),
                reason=str(native["reason"]),
                warnings=[],
                companion_files=_find_amcache_companion_files(entry, entry_map),
                container_type=container_type,
                container_path=container_path,
            )
    if lower_name == "system" and normalized_lower.endswith("windows\\system32\\config\\system"):
        native = describe_raw_candidate(entry.path, "shimcache")
        if native:
            return VelociraptorEvidenceCandidate(
                id=_candidate_id("shimcache", entry.path),
                category="shimcache",
                artifact_type="shimcache",
                parser_status=str(native["parser_status"]),
                display_name=f"Shimcache raw - {Path(entry.path).name}",
                original_path=entry.path,
                local_path=entry.local_path or "",
                normalized_windows_path=normalize_velociraptor_path(entry.path),
                filename=Path(entry.path).name,
                parser=str(native["parser"]),
                size=entry.size,
                mtime=entry.mtime,
                confidence="medium",
                supported=bool(native["supported"]),
                reason=str(native["reason"]),
                warnings=[],
                companion_files=_find_system_companion_files(entry, entry_map),
                container_type=container_type,
                container_path=container_path,
            )

    for artifact_type, planned_parser, pattern in RAW_UPLOAD_PATTERNS:
        if Path(entry.path).match(pattern):
            category = artifact_type.split("_", 1)[0]
            return _raw_candidate(entry, category=category, artifact_type=artifact_type, reason=f"Detected raw artifact. Planned parser: {planned_parser}.", container_path=container_path, container_type=container_type)

    if lower_name in RAW_UPLOAD_NAME_MAP:
        artifact_type, planned_parser = RAW_UPLOAD_NAME_MAP[lower_name]
        category = (
            "network_activity"
            if artifact_type == "srum_raw"
            else "amcache"
            if artifact_type == "amcache"
            else "execution_artifact"
            if artifact_type == "recentfilecache_bcf"
            else "registry"
            if "registry" in artifact_type
            else "filesystem"
            if "ntfs" in artifact_type
            else "other"
        )
        return _raw_candidate(entry, category=category, artifact_type=artifact_type, reason=f"Detected raw artifact. Planned parser: {planned_parser}.", container_path=container_path, container_type=container_type)

    if lower_name.endswith(("automaticdestinations-ms", "customdestinations-ms")):
        return _raw_candidate(entry, category="jumplist", artifact_type="jumplist_raw", reason="Detected Jump List raw file. Use JLECmd/EZ output for now.", container_path=container_path, container_type=container_type)
    if Path(entry.path).suffix.lower() in TEXT_SUFFIXES:
        return _raw_candidate(entry, category="other", artifact_type="text_raw", reason="Detected text artifact candidate. Parser not implemented yet.", container_path=container_path, container_type=container_type)
    if any(token in lower_relative for token in ["$extend/$usnjrnl", "$mft", "$logfile"]):
        return _raw_candidate(entry, category="filesystem", artifact_type="ntfs_raw", reason="Detected NTFS raw file. Use MFTECmd output for now.", container_path=container_path, container_type=container_type)
    if any(token in lower_relative for token in ["appcompatcache", "shimcache", "recentfilecache"]):
        return _raw_candidate(entry, category="execution_artifact", artifact_type="shimcache_registry_hive", reason="Detected raw ShimCache/AppCompat artifact. Raw parser not implemented yet. Use AppCompatCacheParser/RECmd parsed CSV for now.", container_path=container_path, container_type=container_type)
    if "windows\\system32\\sru\\" in normalized_lower and lower_name == "srudb.dat":
        return _raw_candidate(entry, category="network_activity", artifact_type="srum_database", reason="Detected raw SRUM database. Use the scoped SRUM action to parse with SrumECmd.", container_path=container_path, container_type=container_type)
    if "windows\\system32\\sru\\" in normalized_lower and lower_name == "sru.chk":
        return VelociraptorEvidenceCandidate(
            id=_candidate_id("network_activity", entry.path),
            category="network_activity",
            artifact_type="srum_checkpoint",
            parser_status="auxiliary",
            display_name="SRUM checkpoint file",
            original_path=entry.path,
            local_path=entry.local_path or "",
            normalized_windows_path=normalize_velociraptor_path(entry.path),
            parser="srum_checkpoint",
            size=entry.size,
            mtime=entry.mtime,
            confidence="low",
            supported=False,
            reason="Detected SRUM checkpoint file. Requires SRUDB.dat and a SRUM parser; not independently parseable.",
            warnings=[],
            container_type=container_type,
            container_path=container_path,
        )
    if "windows\\system32\\sru\\" in normalized_lower and Path(entry.path).suffix.lower() == ".log":
        return _raw_candidate(entry, category="network_activity", artifact_type="srum_log", reason="Detected SRUM auxiliary log file. Raw parser not implemented yet; use SrumECmd parsed CSV for now.", container_path=container_path, container_type=container_type)
    if "windows\\system32\\tasks\\" in normalize_velociraptor_path(lower_relative).lower():
        return None
    if any(token in lower_relative for token in ["defender", "scheduledtasks", "amcache", "shimcache", "srum", "wmi", "rdp"]):
        return _raw_candidate(entry, category="other", artifact_type="other_raw", reason="Detected raw artifact candidate. Parser not implemented yet.", container_path=container_path, container_type=container_type)
    return None


def _detect_priority_registry_raw_candidate(
    entry: ContainerEntry,
    entry_map: dict[str, ContainerEntry],
    *,
    container_path: str,
    container_type: str,
) -> list[VelociraptorEvidenceCandidate]:
    lower_name = Path(entry.path).name.lower()
    normalized_lower = normalize_velociraptor_path(entry.path).lower()
    candidates: list[VelociraptorEvidenceCandidate] = []
    if lower_name == "amcache.hve":
        candidate = _detect_raw_candidate(entry, entry_map, container_path=container_path, container_type=container_type)
        if candidate:
            candidates.append(candidate)
        return candidates
    if lower_name == "system" and normalized_lower.endswith("windows\\system32\\config\\system"):
        native = describe_raw_candidate(entry.path, "service")
        if native:
            candidates.append(
                VelociraptorEvidenceCandidate(
                    id=_candidate_id("service", entry.path),
                    category="service",
                    artifact_type="service",
                    parser_status=str(native["parser_status"]),
                    display_name=f"Windows Service raw - {Path(entry.path).name}",
                    original_path=entry.path,
                    local_path=entry.local_path or "",
                    normalized_windows_path=normalize_velociraptor_path(entry.path),
                    filename=Path(entry.path).name,
                    parser=str(native["parser"]),
                    size=entry.size,
                    mtime=entry.mtime,
                    confidence="medium",
                    supported=bool(native["supported"]),
                    reason=str(native["reason"]),
                    warnings=[],
                    companion_files=_find_system_companion_files(entry, entry_map),
                    container_type=container_type,
                    container_path=container_path,
                )
            )
        shimcache_candidate = _detect_raw_candidate(entry, entry_map, container_path=container_path, container_type=container_type)
        if shimcache_candidate:
            candidates.append(shimcache_candidate)
        return candidates
    return candidates


def _parsed_results(root: Path) -> list[dict]:
    results_dir = root / "results"
    artifacts = []
    if not results_dir.exists():
        return artifacts
    for path in sorted(results_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".csv", ".json", ".jsonl", ".txt"}:
            classification = classify_artifact(path)
            artifacts.append(
                {
                    "name": path.name,
                    "source_path": str(path.relative_to(root)),
                    "artifact_type": classification["artifact_type"],
                    "parser": classification["parser"],
                    "profile": classification["profile"],
                    "path": path,
                    "status": "processing",
                    "planned_parser": None,
                    "reason": None,
                    "source_tool": "velociraptor",
                    "source_format": path.suffix.lower().lstrip("."),
                }
            )
    return artifacts


def list_velociraptor_upload_artifacts(root: Path, progress_cb: Callable[[dict], None] | None = None) -> list[dict]:
    discovery = discover_velociraptor_evidences(root, progress_cb=progress_cb)
    artifacts: list[dict] = []
    for candidate in discovery.candidates:
        if candidate.supported:
            continue
        artifacts.append(
            {
                "name": candidate.display_name,
                "source_path": candidate.original_path,
                "artifact_type": candidate.artifact_type,
                "parser": "not_implemented",
                "profile": "raw_upload",
                "path": Path(candidate.local_path),
                "status": "detected_not_parsed",
                "planned_parser": candidate.reason,
                "reason": candidate.reason,
            }
        )
    return artifacts


def discover_velociraptor_evidences(root_path: Path | EvidenceContainer, progress_cb: Callable[[dict], None] | None = None) -> VelociraptorDiscoveryResult:
    container = root_path if isinstance(root_path, EvidenceContainer) else open_evidence_container(Path(root_path))
    container_location = str(Path(container.archive_path if hasattr(container, "archive_path") else container.root))
    candidates: list[VelociraptorEvidenceCandidate] = []
    warnings: list[str] = []
    counters = Counter()
    entries = container.list_entries()
    all_files = [entry for entry in entries if not entry.is_dir]
    total_files = len(all_files)
    total_files_scanned = 0
    seen_paths: set[str] = set()
    entry_map = {entry.path.lower(): entry for entry in entries}
    defender_paths: list[ContainerEntry] = []
    has_defender_detection_history = False
    has_defender_mplog = False
    has_defender_quarantine = False
    has_defender_evtx = False
    seen_recycle_pairs: set[tuple[str, str]] = set()
    seen_cloud_roots: set[str] = set()

    for entry in entries:
        normalized_entry = normalize_velociraptor_path(entry.path).lower()
        if any(token in normalized_entry for token in DEFENDER_TOKENS):
            defender_paths.append(entry)

    for entry in all_files:
        total_files_scanned += 1
        if entry.ignored:
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        browser_candidate = _parse_browser_candidate(entry, entry_map, container_path=container_location, container_type=container.type)
        if browser_candidate:
            candidates.append(browser_candidate)
            counters["browser_candidates"] += 1
            counters[browser_candidate.artifact_type] += 1
            seen_paths.add(browser_candidate.original_path)
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        scheduled_task_candidate = _parse_scheduled_task_candidate(entry, container_path=container_location, container_type=container.type)
        if scheduled_task_candidate:
            candidates.append(scheduled_task_candidate)
            counters["scheduled_task_count"] += 1
            counters[scheduled_task_candidate.artifact_type] += 1
            seen_paths.add(scheduled_task_candidate.original_path)
            candidates.append(
                VelociraptorEvidenceCandidate(
                    id=_candidate_id("autoruns", scheduled_task_candidate.original_path),
                    category="autoruns",
                    artifact_type="scheduled_task_candidate",
                    parser_status="handled_by_scheduled_tasks_parser",
                    display_name=f"ASEP scheduled task - {scheduled_task_candidate.task_path or scheduled_task_candidate.display_name}",
                    original_path=scheduled_task_candidate.original_path,
                    local_path=scheduled_task_candidate.local_path,
                    normalized_windows_path=scheduled_task_candidate.normalized_windows_path,
                    parser="scheduled_task_xml",
                    size=scheduled_task_candidate.size,
                    mtime=scheduled_task_candidate.mtime,
                    confidence="medium",
                    supported=False,
                    reason="Scheduled Task XML found; handled by Scheduled Tasks parser.",
                    warnings=[],
                    container_type=container.type,
                    container_path=container_location,
                )
            )
            counters["autoruns_count"] += 1
            counters["scheduled_task_candidate"] += 1
            counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        defender_candidate = _parse_defender_candidate(entry, container_path=container_location, container_type=container.type)
        if defender_candidate:
            candidates.append(defender_candidate)
            counters["defender_count"] += 1
            counters[defender_candidate.artifact_type] += 1
            seen_paths.add(defender_candidate.original_path)
            if defender_candidate.artifact_type == "defender_detection_history":
                has_defender_detection_history = True
            elif defender_candidate.artifact_type == "defender_mplog":
                has_defender_mplog = True
            elif defender_candidate.artifact_type == "defender_quarantine":
                has_defender_quarantine = True
            elif defender_candidate.artifact_type == "defender_evtx":
                has_defender_evtx = True
            if not defender_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        powershell_candidate = _parse_powershell_candidate(entry, container_path=container_location, container_type=container.type)
        if powershell_candidate:
            candidates.append(powershell_candidate)
            counters["powershell_count"] += 1
            counters[powershell_candidate.artifact_type] += 1
            seen_paths.add(powershell_candidate.original_path)
            if not powershell_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        email_candidate = _parse_email_candidate(entry, container_path=container_location, container_type=container.type)
        if email_candidate:
            candidates.append(email_candidate)
            counters["email_count"] += 1
            counters[email_candidate.artifact_type] += 1
            seen_paths.add(email_candidate.original_path)
            if not email_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        recycle_candidate = _parse_recycle_candidate(entry, entry_map, container_path=container_location, container_type=container.type)
        if recycle_candidate:
            pair_key = (recycle_candidate.sid or "", recycle_candidate.pair_id or recycle_candidate.original_path)
            if recycle_candidate.artifact_type != "recycle_r_file" or pair_key not in seen_recycle_pairs:
                candidates.append(recycle_candidate)
                counters["recycle_bin_count"] += 1
                counters[recycle_candidate.artifact_type] += 1
                seen_paths.add(recycle_candidate.original_path)
                if recycle_candidate.pair_id and recycle_candidate.original_i_path:
                    seen_recycle_pairs.add((recycle_candidate.sid or "", recycle_candidate.pair_id))
                if not recycle_candidate.supported:
                    counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        shellbags_candidate = _parse_shellbags_candidate(entry, container_path=container_location, container_type=container.type)
        if shellbags_candidate:
            candidates.append(shellbags_candidate)
            counters["shellbags_count"] += 1
            counters[shellbags_candidate.artifact_type] += 1
            seen_paths.add(shellbags_candidate.original_path)
            if not shellbags_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        priority_registry_raw_candidates = _detect_priority_registry_raw_candidate(
            entry,
            entry_map,
            container_path=container_location,
            container_type=container.type,
        )
        if priority_registry_raw_candidates:
            for priority_registry_raw_candidate in priority_registry_raw_candidates:
                candidates.append(priority_registry_raw_candidate)
                counters[f"{priority_registry_raw_candidate.category}_count"] += 1
                counters[priority_registry_raw_candidate.artifact_type] += 1
                if not priority_registry_raw_candidate.supported:
                    counters["unsupported_count"] += 1
            seen_paths.add(entry.path)
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        usb_candidate = _parse_usb_candidate(entry, container_path=container_location, container_type=container.type)
        if usb_candidate:
            candidates.append(usb_candidate)
            counters["usb_count"] += 1
            counters[usb_candidate.artifact_type] += 1
            seen_paths.add(usb_candidate.original_path)
            if not usb_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        bits_candidate = _parse_bits_candidate(entry, container_path=container_location, container_type=container.type)
        if bits_candidate:
            candidates.append(bits_candidate)
            counters["bits_count"] += 1
            counters[bits_candidate.artifact_type] += 1
            seen_paths.add(bits_candidate.original_path)
            if not bits_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        cloud_candidate = _parse_cloud_candidate(entry, container_path=container_location, container_type=container.type, seen_cloud_roots=seen_cloud_roots)
        if cloud_candidate:
            candidates.append(cloud_candidate)
            counters["cloud_count"] += 1
            counters[cloud_candidate.artifact_type] += 1
            seen_paths.add(cloud_candidate.original_path)
            if not cloud_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        network_candidate = _parse_network_candidate(entry, container_path=container_location, container_type=container.type)
        if network_candidate:
            candidates.append(network_candidate)
            counters["network_count"] += 1
            counters[network_candidate.artifact_type] += 1
            seen_paths.add(network_candidate.original_path)
            if not network_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        autoruns_candidate = _parse_autoruns_candidate(entry, container_path=container_location, container_type=container.type)
        if autoruns_candidate:
            candidates.append(autoruns_candidate)
            counters["autoruns_count"] += 1
            counters[autoruns_candidate.artifact_type] += 1
            seen_paths.add(autoruns_candidate.original_path)
            if not autoruns_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        wmi_candidate = _parse_wmi_candidate(entry, container_path=container_location, container_type=container.type)
        if wmi_candidate:
            candidates.append(wmi_candidate)
            counters["wmi_count"] += 1
            counters[wmi_candidate.artifact_type] += 1
            seen_paths.add(wmi_candidate.original_path)
            if wmi_candidate.artifact_type in {"wmi_objects_data", "wmi_index_btr", "wmi_mapping_map"}:
                candidates.append(
                    VelociraptorEvidenceCandidate(
                        id=_candidate_id("autoruns", wmi_candidate.original_path),
                        category="autoruns",
                        artifact_type="wmi_repository_candidate",
                        parser_status="handled_by_wmi_parser",
                        display_name=f"ASEP WMI candidate - {Path(wmi_candidate.original_path).name}",
                        original_path=wmi_candidate.original_path,
                        local_path=wmi_candidate.local_path,
                        normalized_windows_path=wmi_candidate.normalized_windows_path,
                        parser="raw_discovery",
                        size=wmi_candidate.size,
                        mtime=wmi_candidate.mtime,
                        confidence="medium",
                        supported=False,
                        reason="WMI repository candidate found; handled by WMI parser or preserved as raw discovery.",
                        warnings=[],
                        container_type=container.type,
                        container_path=container_location,
                    )
                )
                counters["autoruns_count"] += 1
                counters["wmi_repository_candidate"] += 1
                counters["unsupported_count"] += 1
            if not wmi_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        jumplist_candidate = _parse_jumplist_candidate(entry, container_path=container_location, container_type=container.type)
        if jumplist_candidate:
            candidates.append(jumplist_candidate)
            counters["jumplist_count"] += 1
            counters[jumplist_candidate.artifact_type] += 1
            seen_paths.add(jumplist_candidate.original_path)
            if not jumplist_candidate.supported:
                counters["unsupported_count"] += 1
            if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
                progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})
            continue
        raw_candidate = _detect_raw_candidate(entry, entry_map, container_path=container_location, container_type=container.type)
        if raw_candidate and raw_candidate.original_path not in seen_paths:
            candidates.append(raw_candidate)
            counters[f"{raw_candidate.category}_count"] += 1
            if raw_candidate.artifact_type == "lnk_raw":
                counters["lnk_candidates_total"] += 1
                counters[f"lnk_{raw_candidate.lnk_location or 'other'}_candidates"] += 1
            if not raw_candidate.supported:
                counters["unsupported_count"] += 1
            seen_paths.add(raw_candidate.original_path)
        if progress_cb and (total_files_scanned == total_files or total_files_scanned % 200 == 0):
            progress_cb({"files_scanned": total_files_scanned, "total_files": total_files, "candidates": len(candidates), "current_path": entry.path})

    defender_summary_candidate = _build_defender_discovery_summary_candidate(
        container_path=container_location,
        defender_paths=defender_paths,
        has_detection_history=has_defender_detection_history,
        has_mplog=has_defender_mplog,
        has_evtx=has_defender_evtx,
        has_quarantine=has_defender_quarantine,
    )
    if defender_summary_candidate and defender_summary_candidate.original_path not in seen_paths:
        candidates.append(defender_summary_candidate)
        counters["defender_count"] += 1
        counters["defender_directory_only"] += 1
        counters["unsupported_count"] += 1
        warnings.extend(defender_summary_candidate.warnings)

    summary = {
        "total_candidates": len(candidates),
        "supported_candidates": sum(1 for candidate in candidates if candidate.supported),
        "unsupported_candidates": sum(1 for candidate in candidates if not candidate.supported),
        "browser_candidates": counters.get("browser_candidates", 0),
        "chromium_history_count": counters.get("chromium_history", 0),
        "firefox_places_count": counters.get("firefox_places", 0),
        "evtx_count": counters.get("evtx_count", 0),
        "prefetch_count": counters.get("prefetch_count", 0),
        "amcache_count": counters.get("amcache_count", 0),
        "lnk_count": counters.get("lnk_count", 0),
        "lnk_candidates_total": counters.get("lnk_candidates_total", 0),
        "lnk_recent_candidates": counters.get("lnk_recent_candidates", 0),
        "lnk_office_recent_candidates": counters.get("lnk_office_recent_candidates", 0),
        "lnk_desktop_candidates": counters.get("lnk_desktop_candidates", 0),
        "lnk_downloads_candidates": counters.get("lnk_downloads_candidates", 0),
        "lnk_start_menu_candidates": counters.get("lnk_start_menu_candidates", 0),
        "lnk_startup_candidates": counters.get("lnk_startup_candidates", 0),
        "registry_hive_count": counters.get("registry_count", 0),
        "mft_count": counters.get("filesystem_count", 0),
        "usn_count": counters.get("filesystem_count", 0),
        "srum_count": counters.get("network_activity_count", 0),
        "scheduled_task_count": counters.get("scheduled_task_count", 0),
        "service_count": counters.get("service_count", 0),
        "defender_count": counters.get("defender_count", 0),
        "defender_detection_history_count": counters.get("defender_detection_history", 0),
        "defender_mplog_count": counters.get("defender_mplog", 0),
        "defender_quarantine_count": counters.get("defender_quarantine", 0),
        "defender_evtx_count": counters.get("defender_evtx", 0),
        "defender_directory_only_count": counters.get("defender_directory_only", 0),
        "powershell_count": counters.get("powershell_count", 0),
        "email_count": counters.get("email_count", 0),
        "recycle_bin_count": counters.get("recycle_bin_count", 0),
        "shellbags_count": counters.get("shellbags_count", 0),
        "shellbags_ntuser_count": counters.get("shellbags_user_hive_ntuser", 0),
        "shellbags_usrclass_count": counters.get("shellbags_user_hive_usrclass", 0),
        "jumplist_count": counters.get("jumplist_count", 0),
        "jumplist_automatic_count": counters.get("jumplist_automatic_destinations", 0),
        "jumplist_custom_count": counters.get("jumplist_custom_destinations", 0),
        "usb_count": counters.get("usb_count", 0),
        "setupapi_candidates": counters.get("setupapi_dev_log", 0),
        "usb_registry_candidates": counters.get("registry_system_hive_usb_candidate", 0) + counters.get("registry_user_hive_usb_candidate", 0) + counters.get("registry_software_hive_usb_candidate", 0),
        "bits_count": counters.get("bits_count", 0),
        "network_candidates": counters.get("network_count", 0),
        "wlan_profile_candidates": counters.get("wlan_profile_xml", 0),
        "hosts_file_candidates": counters.get("hosts_file", 0),
        "dns_candidates": counters.get("dns_cache_output", 0) + counters.get("dns_config_output", 0),
        "network_registry_candidates": counters.get("networklist_registry", 0) + counters.get("tcpip_interfaces_registry", 0) + counters.get("network_registry_hive_candidate", 0),
        "evtx_network_candidates": counters.get("wlan_autoconfig_evtx", 0),
        "cloud_candidates": counters.get("cloud_count", 0),
        "providers_detected": sorted({candidate.provider for candidate in candidates if candidate.category == "cloud_sync" and candidate.provider}),
        "cloud_folders_detected": sum(1 for candidate in candidates if candidate.category == "cloud_sync" and str(candidate.artifact_type).endswith("_folder")),
        "config_candidates": sum(1 for candidate in candidates if candidate.category == "cloud_sync" and "config" in str(candidate.artifact_type)),
        "log_candidates": sum(1 for candidate in candidates if candidate.category == "cloud_sync" and "log" in str(candidate.artifact_type)),
        "large_cloud_folder_skipped": 0,
        "autoruns_count": counters.get("autoruns_count", 0),
        "autoruns_parseable_outputs": counters.get("autoruns_csv", 0) + counters.get("autoruns_tsv", 0) + counters.get("autoruns_xml", 0) + counters.get("autorunsc_output", 0),
        "startup_folder_candidates": counters.get("startup_folder_file", 0),
        "registry_asep_candidates": counters.get("registry_asep_candidate", 0),
        "scheduled_task_candidates": counters.get("scheduled_task_candidate", 0),
        "wmi_candidates": counters.get("wmi_repository_candidate", 0),
        "qmgr_raw_candidates": counters.get("bits_qmgr_dat", 0) + counters.get("bits_qmgr_db", 0),
        "parsed_bits_candidates": counters.get("bits_job", 0) + counters.get("bits_parsed_json", 0),
        "evtx_bits_candidates": counters.get("bits_evtx", 0),
        "recycle_i_candidates": counters.get("recycle_i_file", 0) + counters.get("recycle_pair", 0),
        "recycle_r_candidates": counters.get("recycle_r_file", 0) + counters.get("recycle_pair", 0),
        "recycle_pairs": counters.get("recycle_pair", 0),
        "orphan_i_files": counters.get("recycle_i_file", 0),
        "orphan_r_files": counters.get("recycle_r_file", 0),
        "unsupported_count": counters.get("unsupported_count", 0),
        **inventory_summary(entries),
    }
    hostname = detect_host_from_velociraptor_collection(Path(container_location))
    return VelociraptorDiscoveryResult(
        collection_root=container_location,
        hostname=hostname,
        candidates=candidates,
        summary=summary,
        total_files_scanned=total_files_scanned,
        warnings=warnings,
    )


def list_velociraptor_artifacts(root: Path, selected_candidates: list[dict] | None = None, progress_cb: Callable[[dict], None] | None = None) -> list[dict]:
    artifacts = _parsed_results(root)
    if selected_candidates is None:
        artifacts.extend(list_velociraptor_upload_artifacts(root, progress_cb=progress_cb))
        return artifacts
    if selected_candidates:
        for candidate in selected_candidates:
            if not candidate.get("supported"):
                continue
            source_path = str(candidate.get("original_path") or "")
            common = {
                "name": candidate.get("display_name") or Path(str(candidate.get("local_path") or "")).name,
                "source_path": source_path,
                "path": Path(str(candidate.get("local_path"))),
                "status": "processing",
                "planned_parser": None,
                "reason": None,
                "velociraptor_category": candidate.get("category"),
                "velociraptor_original_path": source_path,
                "velociraptor_normalized_windows_path": candidate.get("normalized_windows_path"),
                "velociraptor_parser_status": candidate.get("parser_status"),
            }
            if candidate.get("category") == "browser":
                parser = "browser_chromium_history" if candidate.get("artifact_type") == "chromium_history" else "browser_firefox_places"
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "browser",
                        "parser": parser,
                        "profile": "browser_usage",
                        "source_tool": "velociraptor_raw",
                        "source_format": "sqlite",
                        "browser_name": candidate.get("browser"),
                        "browser_profile": candidate.get("profile"),
                        "browser_user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "scheduled_task":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "scheduled_task",
                        "parser": "scheduled_task_xml",
                        "profile": "persistence",
                        "source_tool": "native_scheduled_task",
                        "source_format": "xml",
                        "task_name": candidate.get("task_name"),
                        "task_path": candidate.get("task_path"),
                    }
                )
            elif candidate.get("category") == "defender":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "defender",
                        "parser": "defender_raw" if str(candidate.get("artifact_type") or "").startswith("defender_detection_history") else "defender_raw",
                        "profile": "detection",
                        "source_tool": "defender_mplog" if candidate.get("artifact_type") == "defender_mplog" else "defender_detection_history" if candidate.get("artifact_type") == "defender_detection_history" else "generic_defender",
                        "source_format": "log" if candidate.get("artifact_type") in {"defender_mplog", "defender_support_log"} else "raw",
                        "defender_artifact_type": candidate.get("artifact_type"),
                    }
                )
            elif candidate.get("category") == "powershell":
                parser = (
                    "psreadline" if candidate.get("artifact_type") == "psreadline_history"
                    else "transcript" if candidate.get("artifact_type") == "powershell_transcript"
                    else "script" if candidate.get("artifact_type") == "powershell_script"
                    else "generic"
                )
                source_format = "ps1" if candidate.get("artifact_type") == "powershell_script" else "txt"
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "powershell",
                        "parser": parser,
                        "profile": "powershell",
                        "source_tool": "powershell_script" if parser == "script" else "powershell_transcript" if parser == "transcript" else "psreadline_history",
                        "source_format": source_format,
                        "powershell_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "email":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "email",
                        "parser": candidate.get("parser") or "email_generic_raw",
                        "profile": "email",
                        "source_tool": "email_artifact",
                        "source_format": Path(str(candidate.get("local_path") or candidate.get("original_path") or "")).suffix.lower().lstrip(".") or "raw",
                        "email_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "jumplist":
                parser = str(candidate.get("parser") or "").lower()
                source_format = (
                    "automaticDestinations-ms" if parser == "jumplist_raw_automatic"
                    else "customDestinations-ms" if parser == "jumplist_raw_custom"
                    else "csv"
                )
                source_tool = "velociraptor_raw" if parser in {"jumplist_raw_automatic", "jumplist_raw_custom"} else "jlecmd"
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "jumplist",
                        "parser": "raw_automatic_destinations" if parser == "jumplist_raw_automatic" else "raw_custom_destinations" if parser == "jumplist_raw_custom" else "jlecmd",
                        "profile": "file_folder_opening",
                        "source_tool": source_tool,
                        "source_format": source_format,
                        "jumplist_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                        "jumplist_app_id": candidate.get("app_id"),
                        "jumplist_destination_type": candidate.get("destination_type"),
                    }
                )
            elif candidate.get("category") == "recycle_bin":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "recycle_bin",
                        "parser": "raw_i_file" if candidate.get("original_i_path") else "raw_r_file" if candidate.get("original_r_path") else "csv",
                        "profile": "filesystem",
                        "source_tool": "recycle_bin_raw",
                        "source_format": "raw",
                        "recycle_artifact_type": candidate.get("artifact_type"),
                        "recycle_r_path": candidate.get("original_r_path"),
                        "user": candidate.get("user"),
                        "sid": candidate.get("sid"),
                    }
                )
            elif candidate.get("category") == "shellbags":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "shellbags",
                        "parser": "sbecmd",
                        "profile": "file_folder_opening",
                        "source_tool": "sbecmd",
                        "source_format": "csv",
                        "shellbag_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                        "hive_type": candidate.get("hive_type"),
                    }
                )
            elif candidate.get("category") == "usb":
                parser = str(candidate.get("parser") or "").lower()
                source_format = "log" if parser == "setupapi" else "csv" if Path(source_path).suffix.lower() == ".csv" else "raw"
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "usb",
                        "parser": "setupapi" if parser == "setupapi" else "registry_usb",
                        "profile": "device_activity",
                        "source_tool": "setupapi_dev_log" if parser == "setupapi" else "usb_registry_csv",
                        "source_format": source_format,
                        "usb_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "bits":
                parser = str(candidate.get("parser") or "").lower()
                suffix = Path(source_path).suffix.lower()
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "bits",
                        "parser": parser or "bits_csv",
                        "profile": "network_activity",
                        "source_tool": "velociraptor_raw" if parser == "bits_qmgr" else "bits" if parser == "bits_raw" else "native_bits",
                        "source_format": "raw_qmgr" if parser == "bits_qmgr" else "jsonl" if suffix == ".jsonl" else "json" if suffix == ".json" else "txt" if suffix == ".txt" else "csv",
                        "bits_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "cloud_sync":
                parser = str(candidate.get("parser") or "").lower()
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "cloud_sync",
                        "parser": parser or "path_inference",
                        "profile": "cloud",
                        "source_tool": candidate.get("provider") or "generic_cloud",
                        "source_format": "json" if Path(source_path).suffix.lower() == ".json" else "log" if Path(source_path).suffix.lower() in {".log", ".txt", ".ini"} else "csv" if Path(source_path).suffix.lower() == ".csv" else "path_inference",
                        "cloud_artifact_type": candidate.get("artifact_type"),
                        "cloud_provider": candidate.get("provider"),
                        "user": candidate.get("user"),
                        "cloud_sync_root": candidate.get("sync_root"),
                    }
                )
            elif candidate.get("category") == "evtx":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "windows_event",
                        "parser": "evtx_raw",
                        "profile": "account_usage",
                        "source_tool": "native_evtx",
                        "source_format": "evtx",
                        "evtx_artifact_type": candidate.get("artifact_type"),
                        "evtx_subcategory": evtx_subcategory(candidate.get("normalized_windows_path") or source_path),
                    }
                )
            elif candidate.get("category") == "lnk":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "lnk",
                        "parser": "lnk_raw",
                        "profile": "file_folder_opening",
                        "source_tool": "native_lnk",
                        "source_format": "lnk",
                        "lnk_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                        "lnk_location": candidate.get("lnk_location"),
                    }
                )
            elif candidate.get("category") == "prefetch":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "prefetch",
                        "parser": "prefetch_raw",
                        "profile": "program_execution",
                        "source_tool": "native_prefetch",
                        "source_format": "pf",
                        "prefetch_artifact_type": candidate.get("artifact_type"),
                        "prefetch_filename": candidate.get("filename"),
                        "prefetch_executable_name_guess": candidate.get("executable_name_guess"),
                        "prefetch_hash_guess": candidate.get("prefetch_hash_guess"),
                    }
                )
            elif candidate.get("category") == "amcache":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "amcache",
                        "parser": "amcache_raw",
                        "profile": "execution_artifact",
                        "source_tool": "native_amcache",
                        "source_format": "registry_hive",
                        "amcache_artifact_type": candidate.get("artifact_type") or "amcache_raw",
                    }
                )
            elif candidate.get("category") == "shimcache":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "shimcache",
                        "parser": "shimcache_raw",
                        "profile": "execution_artifact",
                        "source_tool": "native_shimcache",
                        "source_format": "registry_hive",
                        "shimcache_artifact_type": candidate.get("artifact_type") or "shimcache_raw",
                    }
                )
            elif candidate.get("category") == "service":
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "service",
                        "parser": "windows_service_registry",
                        "profile": "persistence",
                        "source_tool": "native_windows_service",
                        "source_format": "registry_hive",
                        "service_artifact_type": candidate.get("artifact_type") or "service",
                    }
                )
            elif candidate.get("category") == "wmi":
                parser = str(candidate.get("parser") or "").lower()
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "wmi",
                        "parser": parser or "wmi_csv",
                        "profile": "persistence",
                        "source_tool": "evtxecmd" if parser == "evtx" else "autoruns" if parser == "autoruns" else "velociraptor_wmi" if parser in {"wmi_json", "wmi_jsonl"} else "wmi_parser",
                        "source_format": "jsonl" if Path(source_path).suffix.lower() == ".jsonl" else "json" if Path(source_path).suffix.lower() == ".json" else "evtx_csv" if parser == "evtx" else "csv",
                        "wmi_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
            elif candidate.get("category") == "autoruns":
                parser = str(candidate.get("parser") or "").lower()
                source_format = "xml" if Path(source_path).suffix.lower() == ".xml" else "tsv" if Path(source_path).suffix.lower() == ".tsv" else "csv"
                artifacts.append(
                    {
                        **common,
                        "artifact_type": "autoruns",
                        "parser": parser or "autoruns_csv",
                        "profile": "persistence",
                        "source_tool": "autorunsc" if "autorunsc" in source_path.lower() else "autoruns" if parser != "startup_folder" else "generic_asep",
                        "source_format": "raw" if parser == "startup_folder" else source_format,
                        "autoruns_artifact_type": candidate.get("artifact_type"),
                        "user": candidate.get("user"),
                    }
                )
    return artifacts
