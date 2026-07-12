"""Sudoers parser for /etc/sudoers and /etc/sudoers.d/*."""
from __future__ import annotations
import re
from pathlib import Path

_COMMENT_RE = re.compile(r"^\s*#")
_EMPTY_RE = re.compile(r"^\s*$")
_DEFAULTS_RE = re.compile(r"^\s*Defaults([:@!>]\S+)?\s+(.+)$", re.IGNORECASE)
_PRINCIPAL_RE = re.compile(
    r"^\s*(%?[a-zA-Z_][a-zA-Z0-9_-]*)\s+(ALL|[a-zA-Z_][a-zA-Z0-9_.-]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_.-]*)*)\s*=\s*(?:\(\s*(\S.*?)\s*\)\s*)?(.*)$"
)
_INCLUDE_RE = re.compile(r"^\s*@includedir\s", re.IGNORECASE)
_INCLUDE_FILE_RE = re.compile(r"^\s*#includedir\s", re.IGNORECASE)


def _extract_options(command_spec: str) -> tuple[list[str], str]:
    ops = {"NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT"}
    options: list[str] = []
    parts = command_spec.split(":")
    remaining = []
    for part in parts:
        part_upper = part.strip().upper()
        if part_upper in ops or any(part.strip().upper().startswith(o + "=") for o in ops):
            options.append(part.strip())
        else:
            remaining.append(part)
    return options, ":".join(remaining)


def parse_sudoers(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped) or _EMPTY_RE.match(stripped):
            continue
        if _INCLUDE_RE.match(stripped) or _INCLUDE_FILE_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]

        defaults_match = _DEFAULTS_RE.match(stripped)
        if defaults_match:
            param_spec = defaults_match.group(1)
            value = defaults_match.group(2).strip()
            results.append({
                "artifact_family": "linux_sudoers",
                "artifact_type": "sudoers",
                "source_file": source_path,
                "line_number": line_number,
                "principal": None,
                "host_spec": None,
                "run_as": None,
                "command_spec": None,
                "options": [],
                "is_defaults": True,
                "defaults_param": param_spec.strip() if param_spec else None,
                "defaults_value": value,
                "message": f"Defaults{param_spec or ''} {value}",
                "raw_excerpt": raw_excerpt,
            })
            continue

        principal_match = _PRINCIPAL_RE.match(stripped)
        if principal_match:
            principal = principal_match.group(1).strip()
            host_spec = principal_match.group(2).strip()
            run_as = principal_match.group(3).strip() if principal_match.group(3) else "ALL"
            command_spec = principal_match.group(4).strip()
            options, clean_command = _extract_options(command_spec)
            results.append({
                "artifact_family": "linux_sudoers",
                "artifact_type": "sudoers",
                "source_file": source_path,
                "line_number": line_number,
                "principal": principal,
                "host_spec": host_spec,
                "run_as": run_as,
                "command_spec": clean_command[:2000],
                "options": options,
                "is_defaults": False,
                "defaults_param": None,
                "defaults_value": None,
                "message": f"{principal} {host_spec}=({run_as}) {clean_command[:500]}",
                "raw_excerpt": raw_excerpt,
            })
            continue

        results.append({
            "artifact_family": "linux_sudoers",
            "artifact_type": "sudoers",
            "source_file": source_path,
            "line_number": line_number,
            "principal": None,
            "host_spec": None,
            "run_as": None,
            "command_spec": None,
            "options": [],
            "is_defaults": False,
            "defaults_param": None,
            "defaults_value": None,
            "message": stripped[:2000],
            "raw_excerpt": raw_excerpt,
        })
    return results
