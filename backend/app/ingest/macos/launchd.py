"""launchd property lists: LaunchAgents and LaunchDaemons, the main macOS persistence mechanism.

One row per plist with what launchd would run (``Program`` / ``ProgramArguments``), when
(``RunAtLoad``, ``KeepAlive``, ``StartInterval``, ``StartCalendarInterval``, ``WatchPaths``...) and as
whom. The row time is the plist's modification time, which on a collected copy is the time the job
was written (installed or last changed) -- not when it ran.

A few properties of the job are flagged as leads for review, never as detections: a program in a
world-writable or temporary location, a program in a hidden directory, and a shell or script
interpreter given its code inline on the command line.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.ingest.macos.common import file_mtime_iso, load_plist, original_path, user_from_path

ARTIFACT_FAMILY = "macos_launchd"
_SCOPES = (
    # (pattern on the original path, mechanism, scope)
    (re.compile(r"^/Users/[^/]+/Library/LaunchAgents/", re.IGNORECASE), "launch_agent", "user"),
    (re.compile(r"^/(?:private/)?var/root/Library/LaunchAgents/", re.IGNORECASE), "launch_agent", "user"),
    (re.compile(r"^/Library/LaunchAgents/", re.IGNORECASE), "launch_agent", "system"),
    (re.compile(r"^/Library/LaunchDaemons/", re.IGNORECASE), "launch_daemon", "system"),
)
_TEMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/users/shared/", "/var/folders/", "/private/var/folders/")
_HIDDEN_COMPONENT_RE = re.compile(r"/\.[^/]+/")
_INLINE_INTERPRETERS = {
    "sh": {"-c"}, "bash": {"-c"}, "zsh": {"-c"}, "dash": {"-c"},
    "osascript": {"-e"}, "python": {"-c"}, "python3": {"-c"}, "perl": {"-e"}, "ruby": {"-e"}, "node": {"-e"},
}


def launchd_kind(original: str) -> tuple[str, str] | None:
    for pattern, mechanism, scope in _SCOPES:
        if pattern.search(original):
            return mechanism, scope
    return None


def _schedule_summary(plist: dict[str, Any]) -> list[str]:
    triggers = []
    if plist.get("RunAtLoad"):
        triggers.append("at load")
    keep_alive = plist.get("KeepAlive")
    if keep_alive is True or (isinstance(keep_alive, dict) and keep_alive):
        triggers.append("kept alive")
    if plist.get("StartInterval"):
        triggers.append(f"every {plist['StartInterval']}s")
    if plist.get("StartCalendarInterval"):
        triggers.append("on a calendar schedule")
    if plist.get("WatchPaths"):
        triggers.append("when watched paths change")
    if plist.get("QueueDirectories"):
        triggers.append("when queue directories fill")
    if plist.get("StartOnMount"):
        triggers.append("on volume mount")
    return triggers


def suspicious_indicators(program: str, arguments: list[str]) -> list[str]:
    indicators = []
    lowered = program.lower()
    if lowered.startswith(_TEMP_PREFIXES):
        indicators.append("program_in_temporary_or_shared_location")
    if _HIDDEN_COMPONENT_RE.search(program):
        indicators.append("program_in_hidden_directory")
    interpreter = Path(program).name.lower()
    flags = _INLINE_INTERPRETERS.get(interpreter)
    if flags and any(argument in flags for argument in arguments[1:]):
        indicators.append("inline_interpreter_code")
    return indicators


def parse_launchd_plist(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    original = original_path(source_path)
    kind = launchd_kind(original) or ("launchd_job", "unknown")
    mechanism, scope = kind
    base = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": mechanism,
        "source_file": source_path,
        "file_path": original,
        "persistence_scope": scope,
        "timestamp": file_mtime_iso(path),
        "timestamp_status": "file_mtime",
    }
    try:
        plist = load_plist(path)
    except (OSError, ValueError) as exc:
        return [{**base, "event_action": "launchd_plist_unreadable", "parse_status": "invalid", "message": f"Unreadable launchd plist {original}: {exc}"}]
    if not isinstance(plist, dict):
        return [{**base, "event_action": "launchd_plist_unreadable", "parse_status": "invalid", "message": f"launchd plist {original} is not a dictionary"}]
    arguments = [str(item) for item in plist.get("ProgramArguments") or [] if isinstance(item, (str, int, float))]
    program = str(plist.get("Program") or (arguments[0] if arguments else "") or "")
    command_line = " ".join(arguments) if arguments else program
    label = str(plist.get("Label") or Path(original).stem)
    owner = str(plist.get("UserName") or "") or (user_from_path(source_path) if scope == "user" else "")
    triggers = _schedule_summary(plist)
    disabled = bool(plist.get("Disabled"))
    indicators = suspicious_indicators(program, arguments or [program])
    what = "LaunchDaemon" if mechanism == "launch_daemon" else "LaunchAgent"
    detail = f" {', '.join(triggers)}" if triggers else ""
    state = " (disabled in its plist)" if disabled else ""
    return [{
        **base,
        "event_action": f"persistence_{mechanism}",
        "launchd_label": label,
        "program": program,
        "command_line": command_line,
        "username": owner,
        "run_as_user": str(plist.get("UserName") or ""),
        "run_at_load": bool(plist.get("RunAtLoad")),
        "keep_alive": bool(plist.get("KeepAlive")),
        "triggers": triggers,
        "disabled": disabled,
        "session_type": str(plist.get("LimitLoadToSessionType") or "") if not isinstance(plist.get("LimitLoadToSessionType"), list) else ",".join(map(str, plist["LimitLoadToSessionType"])),
        "bundle_ids": [str(item) for item in plist.get("AssociatedBundleIdentifiers") or []] if isinstance(plist.get("AssociatedBundleIdentifiers"), list) else ([str(plist["AssociatedBundleIdentifiers"])] if plist.get("AssociatedBundleIdentifiers") else []),
        "suspicious_indicators": indicators,
        "parse_status": "valid",
        "message": f"{what} {label} ({scope}) runs {command_line[:300] or 'nothing'}{detail}{state}",
    }]
