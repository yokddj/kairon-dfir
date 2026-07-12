"""Systemd service/timer parser."""
from __future__ import annotations
import re
from pathlib import Path

_SECTION_RE = re.compile(r"^\s*\[(\w+)\]\s*$")
_KEY_VALUE_RE = re.compile(r"^\s*(\w+)\s*=\s*(.*)$")
_COMMENT_RE = re.compile(r"^\s*[#;]")


def _infer_enabled(source_path: str, unit_name: str) -> str | None:
    path_str = str(source_path).replace("\\", "/").lower()
    if "multi-user.target.wants" in path_str or "graphical.target.wants" in path_str:
        return "likely_enabled"
    if any(d in path_str for d in ("/wants/", "/requires/", "/depends/")):
        return "likely_enabled"
    return None


def parse_systemd(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    file_name = Path(source_path).name if source_path else ""
    unit_name = file_name
    unit_type = None
    if file_name.endswith(".service"):
        unit_type = "service"
    elif file_name.endswith(".timer"):
        unit_type = "timer"
    else:
        for suffix in (".service", ".timer", ".socket", ".mount", ".slice", ".target"):
            if file_name.endswith(suffix):
                unit_type = suffix.lstrip(".")
                break
        if unit_type is None:
            unit_type = "unknown"

    current_section: str | None = None
    section_data: dict[str, dict[str, str]] = {}
    description = None
    exec_start = None
    exec_start_pre = None
    exec_start_post = None
    wanted_by = None
    enabled_hint = _infer_enabled(source_path, unit_name)

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        section_match = _SECTION_RE.match(stripped)
        if section_match:
            current_section = section_match.group(1).lower()
            if current_section not in section_data:
                section_data[current_section] = {}
            continue
        kv_match = _KEY_VALUE_RE.match(stripped)
        if kv_match:
            key = kv_match.group(1).strip().lower()
            value = kv_match.group(2).strip()
            if current_section is None:
                current_section = "_global"
                section_data[current_section] = {}
            section_data[current_section][key] = value
            if key == "description":
                description = value
            elif key == "execstart":
                exec_start = value
            elif key in ("execstartpre", "execstartpre"):
                exec_start_pre = value
            elif key in ("execstartpost", "execstartpost"):
                exec_start_post = value
            elif key == "wantedby":
                wanted_by = value

    if not section_data:
        return []

    message_parts = []
    if description:
        message_parts.append(description)
    if exec_start:
        message_parts.append(f"ExecStart={exec_start}")
    message = "; ".join(message_parts) or unit_name

    raw_excerpt = content.strip()[:2000]

    results: list[dict] = [{
        "artifact_family": "linux_systemd",
        "artifact_type": unit_type + "_unit",
        "source_file": source_path,
        "unit_name": unit_name,
        "unit_type": unit_type,
        "description": description,
        "exec_start": exec_start,
        "exec_start_pre": exec_start_pre,
        "exec_start_post": exec_start_post,
        "wanted_by": wanted_by,
        "enabled_hint": enabled_hint,
        "message": message[:2000],
        "raw_excerpt": raw_excerpt,
    }]

    return results
