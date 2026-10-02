"""Linux persistence and rootkit-hook configuration files.

These are plain config or shell files with no timestamps, but they are where a Linux intruder
keeps access or hides: a library preloaded into every process (``/etc/ld.so.preload``), a
command run at boot (``rc.local``), code run at every login (``/etc/profile.d``, ``~/.bashrc``,
``update-motd.d``), a PAM rule that weakens authentication, a queued ``at`` job.

Every active line becomes a row. Lines are *flagged*, never judged: ``suspicious_indicators``
lists generic, widely known markers (download-and-run, reverse-shell syntax, obfuscation,
execution from world-writable or hidden paths) for an analyst to review, and the row keeps the
original text. Nothing here is executed.
"""
from __future__ import annotations

import re
from typing import Any

ARTIFACT_FAMILY = "linux_persistence"

_ETC = r"(^|/)etc/"
_USER_HOME = r"(?:^|/)(?:home/[^/]+|root)/"
_SHELL_INIT_NAMES = r"(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|zlogout|xprofile|xinitrc)"

# (artifact_type, regex) in priority order. First match wins.
_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ld_so_preload", re.compile(_ETC + r"ld\.so\.preload$", re.I)),
    ("ld_so_conf", re.compile(_ETC + r"ld\.so\.conf(?:\.d/[^/]+\.conf)?$", re.I)),
    ("rc_local", re.compile(_ETC + r"(?:rc\.d/)?rc\.local$", re.I)),
    ("pam_config", re.compile(_ETC + r"pam\.d/[^/]+$", re.I)),
    ("at_job", re.compile(r"(?:^|/)var/spool/(?:cron/)?(?:atjobs|at)/[^/.][^/]*$", re.I)),
    (
        "shell_init",
        re.compile(
            _ETC + r"(?:profile|bash\.bashrc|bashrc|zsh/zshrc|zsh/zprofile|zsh/zshenv|zshrc|zprofile|zshenv)$"
            r"|" + _ETC + r"(?:profile\.d|update-motd\.d)/[^/]+$"
            r"|" + _USER_HOME + r"\." + _SHELL_INIT_NAMES + r"$",
            re.I,
        ),
    ),
)
_EXCLUDED_DIR_RE = re.compile(r"(^|/)(?:usr/share|usr/lib|usr/local/share)/", re.I)
_COMMENT_RE = re.compile(r"^\s*#")

# Generic indicator vocabulary; matched against the active text of a line.
_INDICATORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("download_and_run", re.compile(r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b.*\b(?:chmod\s+\+x|-O\s*\S+\s*;|&&\s*(?:sh|bash|\./))", re.I)),
    ("reverse_shell", re.compile(r"/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^|;&]*\s-[a-z]*e\b|\bbash\s+-i\b|\bsocat\b[^|;&]*exec|\bmkfifo\b[^|;&]*\bnc\b|\bpython[0-9.]*\s+-c\b[^|;&]*socket", re.I)),
    ("obfuscation", re.compile(r"\bbase64\s+(?:-d|--decode)\b|\beval\s*[\"'(`$]|\bxxd\s+-r\b|\bopenssl\s+enc\b.*-d\b|\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.I)),
    ("inline_interpreter", re.compile(r"\b(?:python[0-9.]*|perl|ruby|php|node)\s+-[a-z]*[ceEr]\s", re.I)),
    ("world_writable_path", re.compile(r"(?:^|[\s=:\"'])(?:/tmp|/var/tmp|/dev/shm|/run/shm)/", re.I)),
    ("hidden_path", re.compile(r"(?:^|[\s=:\"'/])/[^\s\"']*/\.[A-Za-z0-9_][^\s\"']*", re.I)),
    ("ld_preload_set", re.compile(r"\bLD_(?:PRELOAD|LIBRARY_PATH)\s*=", re.I)),
    ("prompt_command_hook", re.compile(r"\bPROMPT_COMMAND\s*=|\btrap\b[^|;&]*\bDEBUG\b", re.I)),
    ("shadowed_command_alias", re.compile(r"^\s*alias\s+(?:sudo|su|ssh|scp|passwd|login|ls|ps|netstat|ss|lsof|top)\s*=", re.I)),
)
_WORLD_WRITABLE_OR_HIDDEN = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/run/shm)/|/\.[^/]|^\.|^[^/]+$", re.I)
_STANDARD_LIB_DIRS = ("/lib/", "/lib32/", "/lib64/", "/libx32/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/local/lib/")


def persistence_kind(source_path: str) -> str | None:
    path = str(source_path or "").replace("\\", "/").lower()
    if _EXCLUDED_DIR_RE.search(path):
        return None
    for kind, pattern in _KINDS:
        if pattern.search(path):
            return kind
    return None


def _owner(source_path: str) -> str | None:
    path = str(source_path or "").replace("\\", "/")
    match = re.search(r"(?:^|/)home/([^/]+)/", path)
    if match:
        return match.group(1)
    if re.search(r"(?:^|/)root/\.", path):
        return "root"
    return None


def _indicators(text: str) -> list[str]:
    return [name for name, pattern in _INDICATORS if pattern.search(text)]


def _row(kind: str, source_path: str, line_number: int, raw: str, text: str, owner: str | None, extra: dict[str, Any]) -> dict[str, Any]:
    row = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": kind,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": None,
        "timestamp_status": "missing",
        "username": owner,
        "command": text[:2000],
        "message": text[:2000],
        "raw_excerpt": raw[:2000],
        "suspicious_indicators": _indicators(text),
    }
    row.update(extra)
    return row


def _parse_pam(text: str) -> dict[str, Any]:
    # "<type> <control> <module> [args...]", control may be "[success=1 default=ignore]".
    match = re.match(r"^(?:-)?(?P<type>account|auth|password|session)\s+(?P<control>\[[^\]]*\]|\S+)\s+(?P<module>\S+)\s*(?P<args>.*)$", text)
    if match:
        return {
            "pam_type": match.group("type"),
            "pam_control": match.group("control"),
            "pam_module": match.group("module"),
            "pam_args": match.group("args")[:500],
        }
    include = re.match(r"^@include\s+(\S+)", text)
    return {"pam_module": f"@include {include.group(1)}"} if include else {}


def _pam_indicators(extra: dict[str, Any]) -> list[str]:
    module = str(extra.get("pam_module") or "")
    flags: list[str] = []
    if module.endswith("pam_exec.so") or "pam_exec.so" in module:
        flags.append("pam_exec")
    if "pam_permit.so" in module and extra.get("pam_type") == "auth" and "sufficient" in str(extra.get("pam_control")):
        flags.append("auth_always_permit")
    if module.startswith("/") and not module.startswith(_STANDARD_LIB_DIRS):
        flags.append("nonstandard_pam_module")
    return flags


def parse_persistence(content: str, *, source_path: str = "") -> list[dict[str, Any]]:
    kind = persistence_kind(source_path)
    if kind is None:
        return []
    owner = _owner(source_path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        extra: dict[str, Any] = {}
        if kind == "ld_so_preload":
            # Entries are libraries separated by whitespace or colons.
            for library in re.split(r"[\s:]+", stripped):
                if not library:
                    continue
                flags = ["preload_library"]
                if _WORLD_WRITABLE_OR_HIDDEN.search(library) or not library.startswith(_STANDARD_LIB_DIRS):
                    flags.append("unusual_preload_path")
                row = _row(kind, source_path, line_number, line, library, owner, {"library_path": library[:1000]})
                row["suspicious_indicators"] = sorted(set(flags + row["suspicious_indicators"]))
                rows.append(row)
            continue
        if kind == "pam_config":
            extra = _parse_pam(stripped)
        row = _row(kind, source_path, line_number, line, stripped, owner, extra)
        if kind == "pam_config":
            row["suspicious_indicators"] = sorted(set(row["suspicious_indicators"] + _pam_indicators(extra)))
        rows.append(row)
    return rows
