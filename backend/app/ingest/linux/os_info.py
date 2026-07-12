"""OS info parser: /etc/os-release, /etc/hostname, /proc/version."""
from __future__ import annotations
import re
from pathlib import Path

_OS_RELEASE_RE = re.compile(r"^\s*(\w+)\s*=\s*\"?([^\"]*?)\"?\s*$")
_COMMENT_RE = re.compile(r"^\s*#")
_EMPTY_RE = re.compile(r"^\s*$")


def parse_os_info(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    path_lower = str(source_path).replace("\\", "/").lower()
    file_name = Path(source_path).name.lower() if source_path else ""

    if "hostname" in path_lower or file_name == "hostname":
        hostname_val = content.strip().split("\n")[0].strip()
        return [{
            "artifact_family": "linux_os_info",
            "artifact_type": "hostname",
            "source_file": source_path,
            "hostname": hostname_val,
            "os_name": None,
            "os_version": None,
            "kernel_version": None,
            "architecture": None,
            "detected_host": hostname_val,
            "message": f"Hostname: {hostname_val}",
            "raw_excerpt": content.strip()[:2000],
        }]

    if "os-release" in path_lower or file_name == "os-release":
        info: dict[str, str] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or _COMMENT_RE.match(stripped):
                continue
            match = _OS_RELEASE_RE.match(stripped)
            if match:
                key = match.group(1).upper()
                value = match.group(2).strip().strip('"')
                info[key] = value
        os_name = info.get("NAME") or info.get("PRETTY_NAME") or info.get("ID")
        os_version = info.get("VERSION_ID") or info.get("VERSION") or info.get("BUILD_ID")
        message = f"OS: {os_name or 'unknown'} {os_version or ''}".strip()
        return [{
            "artifact_family": "linux_os_info",
            "artifact_type": "os_release",
            "source_file": source_path,
            "hostname": None,
            "os_name": os_name,
            "os_version": os_version,
            "kernel_version": None,
            "architecture": None,
            "detected_host": None,
            "message": message,
            "raw_excerpt": content.strip()[:2000],
        }]

    if "version" in path_lower or "proc" in path_lower:
        kernel_version = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and "version" in stripped.lower():
                ver_match = re.search(r"version\s+(\S+)", stripped, re.IGNORECASE)
                if ver_match:
                    kernel_version = ver_match.group(1)
                break
        arch_match = re.search(r"(x86_64|aarch64|armv7l|i686|amd64)", content, re.IGNORECASE)
        architecture = arch_match.group(1) if arch_match else None
        return [{
            "artifact_family": "linux_os_info",
            "artifact_type": "kernel_version",
            "source_file": source_path,
            "hostname": None,
            "os_name": None,
            "os_version": None,
            "kernel_version": content.strip().split("\n")[0][:500],
            "architecture": architecture,
            "detected_host": None,
            "message": f"Kernel: {content.strip().split(chr(10))[0][:500]}",
            "raw_excerpt": content.strip()[:2000],
        }]

    return [{
        "artifact_family": "linux_os_info",
        "artifact_type": "os_info",
        "source_file": source_path,
        "hostname": None,
        "os_name": None,
        "os_version": None,
        "kernel_version": None,
        "architecture": None,
        "detected_host": None,
        "message": content.strip()[:2000],
        "raw_excerpt": content.strip()[:2000],
    }]
