"""Which files of a macOS collection are parsed, and by which parser.

A macOS collection is read from a closed list of artifacts at known locations. UAC's ``full``
profile also copies every ``*.log``, ``*.csv``, ``*.json``... it finds under the user's home and the
system (documents, other tools' data, even other evidence on the disk); none of that is a macOS
artifact, and reading it with filename heuristics produced Windows and Linux events from files
that merely shared a name. So nothing outside the list below is parsed -- it stays in the evidence
and is counted, not indexed.

The list:

* macOS-specific: launchd jobs (LaunchAgents/LaunchDaemons outside the sealed system volume),
  QuarantineEventsV2, knowledgeC.db, TCC.db, dslocal users and groups, SystemVersion.plist,
  install.log, wifi.log, launchd.log and shared file lists (recent items, favourites).
* Unix formats macOS shares with Linux, at their macOS locations, read by the Linux parsers:
  shell histories and shell start-up files in home directories, sudoers, PAM, cron tabs, SSH
  configuration and keys lists, /etc/hosts, /etc/localtime and system.log.
* Browser history databases (Chromium-based browsers, Firefox, Safari), read by the browser parsers.
* UAC's own live-response output (see app.ingest.uac.live_response).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from app.ingest.macos.common import original_path
from app.ingest.macos.launchd import launchd_kind
from app.ingest.macos.logs import log_kind
from app.ingest.macos.shared_file_lists import is_shared_file_list
from app.ingest.uac.live_response import BODYFILE_CLASSIFICATION, is_ignored_uac_output, is_uac_bodyfile, looks_like_uac_output

MACOS_OS_TYPE = "macos"
_DSLOCAL_RE = re.compile(r"^/(?:private/)?var/db/dslocal/nodes/Default/(?P<kind>users|groups)/[^/]+\.plist$", re.IGNORECASE)
_SYSTEM_VERSION_RE = re.compile(r"^/System/Library/CoreServices/SystemVersion\.plist$", re.IGNORECASE)
_QUARANTINE_RE = re.compile(r"/Library/Preferences/com\.apple\.LaunchServices\.QuarantineEventsV2$", re.IGNORECASE)
_KNOWLEDGEC_RE = re.compile(r"^/(?:Users/[^/]+/Library/Application Support/Knowledge|(?:private/)?var/db/CoreDuet/Knowledge)/knowledgeC\.db$", re.IGNORECASE)
_TCC_RE = re.compile(r"^/(?:Users/[^/]+/)?Library/Application Support/com\.apple\.TCC/TCC\.db$", re.IGNORECASE)

_HOME = r"/(?:Users/[^/]+|(?:private/)?var/root)"
_ETC = r"/(?:private/)?etc"
# Unix artifacts at their macOS locations; each is then routed by app.ingest.linux.helpers.
_SHARED_UNIX_RES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rf"^{_HOME}/\.(?:zsh|bash|sh|ksh)_history$",
    rf"^{_HOME}/\.zsh_sessions/[^/]+\.history$",
    rf"^{_HOME}/\.(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile)$",
    rf"^{_HOME}/\.ssh/(?:known_hosts|authorized_keys2?|config)$",
    rf"^{_ETC}/(?:sudoers|sudoers\.d/[^/]+)$",
    rf"^{_ETC}/(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|profile)$",
    rf"^{_ETC}/pam\.d/[^/]+$",
    rf"^{_ETC}/ssh/(?:sshd_config|ssh_config|sshd_config\.d/[^/]+|ssh_config\.d/[^/]+)$",
    rf"^{_ETC}/(?:hosts|localtime|crontab)$",
    r"^/(?:private/)?var/at/tabs/[^/]+$",
    r"^/usr/lib/cron/tabs/[^/]+$",
    r"^/(?:private/)?var/log/system\.log(?:\.\d+)?(?:\.gz|\.bz2)?$",
))
_BROWSER_RES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rf"^{_HOME}/Library/Application Support/(?:Google/Chrome(?: Beta| Canary)?|BraveSoftware/Brave-Browser|Microsoft Edge|Chromium|Vivaldi|Arc/User Data|com\.operasoftware\.Opera)/(?:[^/]+/)?History$",
    rf"^{_HOME}/Library/Application Support/Firefox/Profiles/[^/]+/places\.sqlite$",
    rf"^{_HOME}/Library/(?:Containers/com\.apple\.Safari/Data/Library/)?Safari/History\.db$",
))
_PARSER_FOR_FAMILY = {
    "macos_launchd": "macos_launchd_raw",
    "macos_quarantine": "macos_quarantine_raw",
    "macos_knowledgec": "macos_knowledgec_raw",
    "macos_tcc": "macos_tcc_raw",
    "macos_accounts": "macos_accounts_raw",
    "macos_system_info": "macos_system_info_raw",
    "macos_logs": "macos_logs_raw",
    "macos_recent_items": "macos_recent_items_raw",
}


def looks_like_macos_artifact(source_path: str | Path) -> tuple[str, str, str] | None:
    """(family, artifact_type, parser) for a macOS-specific artifact, from its path."""
    original = original_path(str(source_path))
    name = original.rsplit("/", 1)[-1]
    result: tuple[str, str] | None = None
    if name.lower().endswith(".plist"):
        kind = launchd_kind(original)
        if kind:
            result = ("macos_launchd", kind[0])
        else:
            dslocal = _DSLOCAL_RE.search(original)
            if dslocal:
                result = ("macos_accounts", "local_user" if dslocal.group("kind").lower() == "users" else "local_group")
            elif _SYSTEM_VERSION_RE.search(original):
                result = ("macos_system_info", "system_version")
    elif _QUARANTINE_RE.search(original):
        result = ("macos_quarantine", "quarantine_event")
    elif _KNOWLEDGEC_RE.search(original):
        result = ("macos_knowledgec", "knowledgec")
    elif _TCC_RE.search(original):
        result = ("macos_tcc", "tcc_permission")
    elif is_shared_file_list(original):
        result = ("macos_recent_items", "recent_item")
    else:
        kind = log_kind(original)
        if kind:
            result = ("macos_logs", kind)
    if result is None:
        return None
    family, artifact_type = result
    return family, artifact_type, _PARSER_FOR_FAMILY[family]


def is_shared_unix_artifact(source_path: str | Path) -> bool:
    original = original_path(str(source_path))
    return any(pattern.search(original) for pattern in _SHARED_UNIX_RES)


def is_browser_history(source_path: str | Path) -> bool:
    original = original_path(str(source_path))
    return any(pattern.search(original) for pattern in _BROWSER_RES)


def _dedupe_key(source_path: str) -> str:
    """/etc is a link to /private/etc on macOS (and /var to /private/var): one file, two paths."""
    original = original_path(source_path).lower()
    for alias in ("/etc/", "/var/", "/tmp/"):
        if original.startswith(alias):
            return "/private" + original
    return original


def _artifact_entry(path: Path, root: Path, classification: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_path": str(path.relative_to(root)),
        "path": path,
        "os_type": MACOS_OS_TYPE,
        **classification,
        "name": classification.get("name") or path.name,
    }


def classify_macos_path(path: Path, root: Path) -> dict[str, Any] | None:
    """The classification of one collected file, or None when it is not on the list."""
    from app.ingest.browser.detector import classify_browser_artifact
    from app.ingest.linux.helpers import looks_like_linux_artifact

    relative = str(path.relative_to(root))
    if is_uac_bodyfile(relative):
        return dict(BODYFILE_CLASSIFICATION)
    uac_output = looks_like_uac_output(relative)
    if uac_output:
        family, artifact_type, parser = uac_output
        return {"artifact_type": family, "artifact_family": family, "uac_artifact_type": artifact_type, "parser": parser, "profile": "host_activity", "reason": "UAC live-response output"}
    macos = looks_like_macos_artifact(relative)
    if macos:
        family, artifact_type, parser = macos
        return {"artifact_type": family, "artifact_family": family, "macos_artifact_type": artifact_type, "parser": parser, "profile": "macos_activity", "reason": "Detected macOS artifact"}
    if is_browser_history(relative):
        classification = classify_browser_artifact(path)
        if original_path(relative).lower().endswith("/safari/history.db"):
            classification = {**classification, "parser": "browser_safari_history", "source_tool": "native_browser", "source_format": "sqlite", "browser_artifact_type": "history"}
        return {**classification, "reason": "Detected browser history database"}
    if is_shared_unix_artifact(relative):
        linux = looks_like_linux_artifact(relative)
        if linux:
            family, artifact_type, parser = linux
            return {"artifact_type": family, "artifact_family": family, "linux_artifact_type": artifact_type, "parser": parser, "profile": "macos_activity", "reason": "Unix artifact at its macOS location"}
    return None


def list_macos_artifacts(root: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The artifacts of a macOS collection, and how many collected files were left unparsed."""
    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    files_seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        current = Path(dirpath)
        if current.name in {"diagnostics", "uuidtext"} and current.parent.name == "db" and "[root]" in str(current):
            # Unified Logs: thousands of tracev3/uuidtext files read together by one parser run.
            dirnames[:] = []
            if current.name == "diagnostics" and (current.parent / "uuidtext").is_dir():
                marker = next((path for path in sorted(current.rglob("*.tracev3")) if path.is_file()), None)
                if marker is not None:
                    artifacts.append(_artifact_entry(marker, root, {
                        "artifact_type": "macos_unified_logs",
                        "artifact_family": "macos_unified_logs",
                        "macos_artifact_type": "unified_logs",
                        "parser": "macos_unified_logs_raw",
                        "profile": "macos_activity",
                        "name": "Unified Logs",
                        "reason": "macOS Unified Logs (diagnostics + uuidtext), decoded by unifiedlog_iterator.",
                    }))
            continue
        if current.name == ".fseventsd" and "[root]" in str(current):
            # FSEvents: millions of records, searched on demand, never indexed. One artifact row
            # stands for the volume's journal so the evidence shows it was collected.
            dirnames[:] = []
            marker = next((current / name for name in ("fseventsd-uuid", *sorted(filenames)) if (current / name).is_file()), None)
            if marker is not None:
                artifacts.append(_artifact_entry(marker, root, {
                    "artifact_type": "macos_fsevents",
                    "artifact_family": "macos_fsevents",
                    "parser": "not_implemented",
                    "profile": "macos_activity",
                    "status": "detected_not_parsed",
                    "reason": "FSEvents journal: searched on demand from the macOS workbench, not indexed.",
                }))
            continue
        for filename in sorted(filenames):
            path = current / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = str(path.relative_to(root))
            if is_ignored_uac_output(relative):
                continue
            files_seen += 1
            classification = classify_macos_path(path, root)
            if classification is None:
                continue
            key = _dedupe_key(relative)
            if key in seen:
                continue
            seen.add(key)
            artifacts.append(_artifact_entry(path, root, classification))
    return artifacts, {"files_seen": files_seen, "artifacts_listed": len(artifacts), "files_not_parsed": files_seen - len(artifacts)}
