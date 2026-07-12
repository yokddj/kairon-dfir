"""Bash/ZSH history parser."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path

_ZSH_EXTENDED_RE = re.compile(r"^:\s*(\d+):\d+;(.*)$")


def _infer_username(source_path: str) -> str | None:
    path_str = str(source_path).replace("\\", "/")
    match = re.search(r"/home/([^/]+)/", path_str)
    if match:
        return match.group(1)
    match = re.search(r"/root/", path_str)
    if match:
        return "root"
    return None


def _detect_shell_type(source_path: str) -> str:
    lower = str(source_path).lower()
    if "zsh_history" in lower or ".zsh" in lower:
        return "zsh"
    return "bash"


def parse_shell_history(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    inferred_user = username or _infer_username(source_path)
    shell_type = _detect_shell_type(source_path)
    current_timestamp = None

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            current_timestamp = None
            continue

        if shell_type == "zsh":
            zsh_match = _ZSH_EXTENDED_RE.match(stripped)
            if zsh_match:
                epoch_str = zsh_match.group(1)
                command = zsh_match.group(2).strip()
                try:
                    epoch = int(epoch_str)
                    current_timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                except (ValueError, OverflowError, OSError):
                    current_timestamp = None
            else:
                if stripped.startswith(":"):
                    current_timestamp = None
                    continue
                command = stripped
        else:
            command = stripped

        if not command:
            continue

        truncated = command[:4000] if len(command) > 4000 else command
        raw_excerpt = truncated[:2000]

        results.append({
            "artifact_family": "linux_shell_history",
            "artifact_type": f"{shell_type}_history",
            "source_file": source_path,
            "line_number": line_number,
            "username": inferred_user,
            "shell_type": shell_type,
            "command": truncated,
            "timestamp": current_timestamp,
            "message": truncated[:2000],
            "raw_excerpt": raw_excerpt,
        })

    return results
