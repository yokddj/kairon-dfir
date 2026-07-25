"""Linux artifact detection helpers."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

_LINUX_ARTIFACT_MAP: dict[str, tuple[str, str, str]] = {
    "journal.export": ("linux_journal", "journal_export", "linux_journal_raw"),
    "journal.json": ("linux_journal", "journal_json", "linux_journal_raw"),
    "journal.ndjson": ("linux_journal", "journal_json", "linux_journal_raw"),
    "journalctl.json": ("linux_journal", "journal_json", "linux_journal_raw"),
    "auth.log": ("linux_auth", "auth_log", "linux_auth_raw"),
    "secure": ("linux_auth", "auth_log", "linux_auth_raw"),
    "syslog": ("linux_syslog", "syslog", "linux_syslog_raw"),
    "messages": ("linux_syslog", "syslog", "linux_syslog_raw"),
    "kern.log": ("linux_syslog", "kern_log", "linux_syslog_raw"),
    "audit.log": ("linux_audit", "audit_log", "linux_audit_raw"),
    ".bash_history": ("linux_shell_history", "bash_history", "linux_shell_raw"),
    ".zsh_history": ("linux_shell_history", "zsh_history", "linux_shell_raw"),
    "bash_history": ("linux_shell_history", "bash_history", "linux_shell_raw"),
    "zsh_history": ("linux_shell_history", "zsh_history", "linux_shell_raw"),
    "crontab": ("linux_cron", "crontab", "linux_cron_raw"),
    "/cron.d/": ("linux_cron", "cron_file", "linux_cron_raw"),
    "/cron.daily/": ("linux_cron", "cron_file", "linux_cron_raw"),
    "/cron.hourly/": ("linux_cron", "cron_file", "linux_cron_raw"),
    "/cron.weekly/": ("linux_cron", "cron_file", "linux_cron_raw"),
    "/cron.monthly/": ("linux_cron", "cron_file", "linux_cron_raw"),
    "anacrontab": ("linux_cron", "anacrontab", "linux_cron_raw"),
    ".service": ("linux_systemd", "service_unit", "linux_systemd_raw"),
    ".timer": ("linux_systemd", "timer_unit", "linux_systemd_raw"),
    "authorized_keys": ("linux_ssh", "authorized_keys", "linux_ssh_raw"),
    "known_hosts": ("linux_ssh", "known_hosts", "linux_ssh_raw"),
    "ssh_config": ("linux_ssh", "ssh_config", "linux_ssh_raw"),
    "sshd_config": ("linux_ssh", "sshd_config", "linux_ssh_raw"),
    "passwd": ("linux_identity", "passwd", "linux_identity_raw"),
    "group": ("linux_identity", "group", "linux_identity_raw"),
    "shadow": ("linux_identity", "shadow", "linux_identity_raw"),
    "sudoers": ("linux_sudoers", "sudoers", "linux_sudoers_raw"),
    "dpkg.log": ("linux_packages", "dpkg_log", "linux_packages_raw"),
    "yum.log": ("linux_packages", "yum_log", "linux_packages_raw"),
    "dnf.log": ("linux_packages", "dnf_log", "linux_packages_raw"),
    "apt/history.log": ("linux_packages", "apt_history", "linux_packages_raw"),
    "apt/term.log": ("linux_packages", "apt_term", "linux_packages_raw"),
    "var/lib/dpkg/status": ("linux_packages", "dpkg_status", "linux_packages_raw"),
    "os-release": ("linux_os_info", "os_release", "linux_os_info_raw"),
    "lsb-release": ("linux_os_info", "lsb_release", "linux_os_info_raw"),
    "debian_version": ("linux_os_info", "debian_version", "linux_os_info_raw"),
    "issue": ("linux_os_info", "issue", "linux_os_info_raw"),
    "hostname": ("linux_os_info", "hostname", "linux_os_info_raw"),
    "hosts": ("linux_network", "etc_hosts", "linux_network_raw"),
    "resolv.conf": ("linux_network", "resolv_conf", "linux_network_raw"),
    "/netplan/": ("linux_network", "netplan", "linux_network_raw"),
    "interfaces": ("linux_network", "interfaces", "linux_network_raw"),
}

_AUTH_PATTERNS = [
    re.compile(r"(accepted|Accepted)\s+(password|publickey)\s+for\s+(\S+)", re.IGNORECASE),
    re.compile(r"(Failed|failed)\s+password\s+for\s+(\S+)", re.IGNORECASE),
    re.compile(r"(Invalid|invalid)\s+user\s+(\S+)", re.IGNORECASE),
    re.compile(r"(sudo|su)\s*:\s+(\S+)\s*:\s*TTY=", re.IGNORECASE),
    re.compile(r"pam_unix\([^)]+\):\s*session\s+(opened|closed)", re.IGNORECASE),
    re.compile(r"(authentication|Authentication)\s+failure", re.IGNORECASE),
]


def looks_like_linux_artifact(path: str | Path) -> tuple[str, str, str] | None:
    """Detect Linux artifact family, type, and parser from a path."""
    path_str = str(path).replace("\\", "/").lower()
    name = path_str.rsplit("/", 1)[-1]
    for marker, (family, artifact_type, parser) in _LINUX_ARTIFACT_MAP.items():
        if "/" in marker:
            # Directory-scoped marker: full relative-path context is required,
            # so a plain substring match is safe (low collision risk).
            if marker in path_str:
                return (family, artifact_type, parser)
        else:
            # Filename-scoped marker: match the basename only (optionally with a
            # log-rotation suffix like ".1" or "-20230101"), never a raw
            # substring of the full path — otherwise unrelated files that merely
            # contain the marker word (e.g. "more_messages_pb2.py" containing
            # "messages", or "group_utils.py" containing "group") get
            # misclassified as forensic log artifacts.
            if name == marker or name.startswith(marker + ".") or name.startswith(marker + "-"):
                return (family, artifact_type, parser)
    return None


def is_linux_artifact_path(path: str | Path) -> bool:
    """Check if a path likely belongs to a Linux artifact."""
    path_str = str(path).replace("\\", "/").lower()
    common_linux_markers = [
        "/var/log/", "/etc/", "/home/", "/root/",
        ".bash_history", ".zsh_history", "/proc/", "/usr/",
        "/lib/systemd/", "/etc/systemd/", "/var/spool/cron/",
    ]
    return any(marker in path_str for marker in common_linux_markers)
