"""Linux collection auto-discovery and inventory generation."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.os_detection import detect_linux_release


SUPPORTED_ARTIFACTS: dict[str, dict[str, str]] = {
    "journal": {"label": "journal", "family": "linux_journal"},
    "auth_log": {"label": "auth.log", "family": "linux_auth"},
    "wtmp": {"label": "wtmp", "family": "linux_auth"},
    "btmp": {"label": "btmp", "family": "linux_auth"},
    "lastlog": {"label": "lastlog", "family": "linux_lastlog"},
    "syslog": {"label": "syslog", "family": "linux_syslog"},
    "audit_log": {"label": "audit.log", "family": "linux_audit"},
    "apache": {"label": "Apache logs", "family": "linux_apache"},
    "exim": {"label": "Exim logs", "family": "linux_exim"},
    "shell_history": {"label": "shell history", "family": "linux_shell_history"},
    "cron": {"label": "cron", "family": "linux_cron"},
    "systemd": {"label": "systemd", "family": "linux_systemd"},
    "ssh": {"label": "ssh", "family": "linux_ssh"},
    "identity": {"label": "passwd/group/shadow", "family": "linux_identity"},
    "sudoers": {"label": "sudoers", "family": "linux_sudoers"},
    "packages": {"label": "packages", "family": "linux_packages"},
    "network": {"label": "network", "family": "linux_network"},
    "os_info": {"label": "os-release", "family": "linux_os_info"},
}

OPTIONAL_NOT_FOUND = {
    "auditd": "auditd unavailable",
    "journal_export": "journal export not found",
    "firewalld": "firewalld not found",
}

UNSUPPORTED_PATTERNS = (
    (re.compile(r"(^|/)etc/selinux/", re.I), "SELinux database", "SELinux policy databases are detected but not parsed."),
    (re.compile(r"(^|/)var/log/journal/", re.I), "systemd journal binary", "Binary journal parsing is not supported yet; export text logs instead."),
    (re.compile(r"(^|/)boot/(vmlinuz|initrd|initramfs)", re.I), "boot image", "Kernel/initrd images are preserved but not parsed."),
)


def _normalize_rel(path: str | Path) -> str:
    return str(path).replace("\\", "/").lstrip("/")


def _read_text(root: Path, rel_path: str, *, limit: int = 256_000) -> str:
    path = root / rel_path
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _artifact_key(family: str, artifact_type: str, path: str) -> str:
    lower = path.lower()
    if family == "linux_shell_history":
        return "shell_history"
    if family == "linux_journal":
        return "journal"
    if family == "linux_identity":
        return "identity"
    if family == "linux_packages":
        return "packages"
    if family == "linux_network":
        return "network"
    if family == "linux_os_info":
        return "os_info"
    if family == "linux_auth":
        if artifact_type in {"wtmp", "btmp"}:
            return artifact_type
        return "auth_log"
    if family == "linux_lastlog":
        return "lastlog"
    if family == "linux_syslog":
        return "syslog"
    if family == "linux_audit":
        return "audit_log"
    if family == "linux_apache":
        return "apache"
    if family == "linux_exim":
        return "exim"
    if family == "linux_cron" or "/cron" in lower or "crontab" in lower:
        return "cron"
    if family == "linux_systemd":
        return "systemd"
    if family == "linux_ssh":
        return "ssh"
    if family == "linux_sudoers":
        return "sudoers"
    return artifact_type or family


def _parse_linux_release(root: Path, paths: list[str]) -> tuple[str | None, list[str]]:
    markers: dict[str, str] = {}
    for marker in ("/etc/os-release", "/usr/lib/os-release", "/etc/lsb-release", "/etc/issue", "/etc/debian_version"):
        rel = marker.lstrip("/")
        source = next((path for path in paths if path.lower().endswith(rel.lower())), None)
        markers[marker] = _read_text(root, source) if source else ""
    detection = detect_linux_release(markers)
    return detection.distribution, detection.reasons


def _parse_kernel(content: str, paths: list[str]) -> str | None:
    match = re.search(r"Linux version\s+([^\s]+)", content)
    if match:
        return match.group(1)
    for path in paths:
        name = Path(path).name
        if name.startswith("vmlinuz-"):
            return name.removeprefix("vmlinuz-")
    return None


def _parse_hostnamectl(content: str) -> tuple[str | None, str | None, str | None]:
    hostname = None
    distribution = None
    kernel = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("static hostname:"):
            hostname = line.split(":", 1)[1].strip() or None
        elif line.lower().startswith("operating system:"):
            distribution = line.split(":", 1)[1].strip() or None
        elif line.lower().startswith("kernel:"):
            kernel_value = line.split(":", 1)[1].strip()
            kernel = kernel_value.removeprefix("Linux ").strip() or None
    return hostname, distribution, kernel


def _parse_users(root: Path, paths: list[str]) -> list[str]:
    passwd_path = next((path for path in paths if path.lower().endswith("/etc/passwd") or path.lower() == "etc/passwd" or path.lower().endswith("/passwd")), None)
    if not passwd_path:
        return []
    users: list[str] = []
    for line in _read_text(root, passwd_path).splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        name = line.split(":", 1)[0].strip()
        if name:
            users.append(name)
    return users[:100]


def build_linux_inventory(root: Path, extracted_files: list[str]) -> dict[str, Any] | None:
    paths = sorted({_normalize_rel(path) for path in extracted_files if str(path).strip()})
    detected_by_key: dict[str, dict[str, Any]] = {}
    unsupported: list[dict[str, Any]] = []
    linux_path_hits = 0

    for rel_path in paths:
        lower = rel_path.lower()
        if any(marker in f"/{lower}" for marker in ("/etc/", "/var/log/", "/home/", "/root/", "/usr/", "/boot/")):
            linux_path_hits += 1
        linux_match = looks_like_linux_artifact(rel_path)
        if linux_match:
            family, artifact_type, parser = linux_match
            key = _artifact_key(family, artifact_type, rel_path)
            spec = SUPPORTED_ARTIFACTS.get(key, {"label": Path(rel_path).name, "family": family})
            item = detected_by_key.setdefault(
                key,
                {
                    "key": key,
                    "label": spec["label"],
                    "family": family,
                    "artifact_type": artifact_type,
                    "parser": parser,
                    "status": "detected",
                    "supported": True,
                    "paths": [],
                },
            )
            item["paths"].append(rel_path)
        for pattern, label, reason in UNSUPPORTED_PATTERNS:
            if pattern.search(rel_path):
                unsupported.append({"key": label.lower().replace(" ", "_"), "label": label, "source_path": rel_path, "status": "unsupported", "supported": False, "reason": reason})

    hostname_path = next((path for path in paths if path.lower().endswith("/etc/hostname") or path.lower() == "etc/hostname" or path.lower().endswith("/hostname")), None)
    hostnamectl_path = next((path for path in paths if "hostnamectl" in Path(path).name.lower()), None)
    proc_version_path = next((path for path in paths if path.lower().endswith("/proc/version") or path.lower() == "proc/version"), None)

    distribution, distribution_reasons = _parse_linux_release(root, paths)
    hostname = None
    if hostname_path:
        hostname = next((line.strip() for line in _read_text(root, hostname_path, limit=4096).splitlines() if line.strip() and not line.strip().startswith("#")), None)
    kernel = _parse_kernel(_read_text(root, proc_version_path) if proc_version_path else "", paths)
    if hostnamectl_path:
        hostnamectl_hostname, hostnamectl_distribution, hostnamectl_kernel = _parse_hostnamectl(_read_text(root, hostnamectl_path, limit=32_000))
        hostname = hostname or hostnamectl_hostname
        distribution = distribution or hostnamectl_distribution
        kernel = kernel or hostnamectl_kernel
    users = _parse_users(root, paths)

    if not detected_by_key and not unsupported and not distribution and not hostname and not kernel and linux_path_hits < 2:
        return None

    not_detected = [
        {"key": key, "label": spec["label"], "family": spec["family"], "status": "not_inspected", "supported": True}
        for key, spec in SUPPORTED_ARTIFACTS.items()
        if key not in detected_by_key
    ]
    warnings = [message for key, message in OPTIONAL_NOT_FOUND.items() if key == "auditd" and "audit_log" not in detected_by_key]
    warnings.extend(message for key, message in OPTIONAL_NOT_FOUND.items() if key not in {"auditd", "journal_export"})
    if "journal" not in detected_by_key:
        warnings.append(OPTIONAL_NOT_FOUND["journal_export"])

    detected = list(detected_by_key.values())
    total_detected = len(detected) + len(unsupported)
    supported_detected = len(detected)
    coverage_percent = round((supported_detected / total_detected) * 100) if total_detected else 0
    return {
        "platform": "linux",
        "distribution": distribution,
        "distribution_reasons": distribution_reasons,
        "hostname": hostname,
        "kernel": kernel,
        "users": users,
        "detected_artifacts": detected,
        "not_detected": not_detected,
        "unsupported": unsupported,
        "warnings": warnings,
        "coverage": {
            "detected": total_detected,
            "total_detected": total_detected,
            "supported": supported_detected,
            "unsupported": len(unsupported),
            "coverage_percent": coverage_percent,
        },
        "processing": [
            {"name": item["label"], "family": item["family"], "status": "Detected", "paths": item.get("paths", []), "source_count": len(item.get("paths", []))}
            for item in detected
        ]
        + [{"name": item["label"], "family": item["key"], "status": "Unsupported", "paths": [item.get("source_path")], "source_count": 1} for item in unsupported]
        + [{"name": item["label"], "family": item["key"], "status": "Not inspected", "paths": [], "source_count": 0} for item in not_detected],
    }
