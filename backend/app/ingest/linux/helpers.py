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
    "wtmp": ("linux_auth", "wtmp", "linux_auth_raw"),
    "btmp": ("linux_auth", "btmp", "linux_auth_raw"),
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
    "hosts": ("linux_network", "etc_hosts", "linux_network_raw"),
    "resolv.conf": ("linux_network", "resolv_conf", "linux_network_raw"),
    "/netplan/": ("linux_network", "netplan", "linux_network_raw"),
    "interfaces": ("linux_network", "interfaces", "linux_network_raw"),
}

_APACHE_LOG_RE = re.compile(
    r"(^|/)var/log/(apache2|httpd)/(?P<name>[^/]*(?:access|error)(?:[._-]log|\.log)[^/]*)$",
    re.IGNORECASE,
)
_EXIM_LOG_RE = re.compile(
    r"(^|/)var/log/exim4?/(?P<name>(?:mainlog|rejectlog|paniclog)(?:[._-].*)?)$",
    re.IGNORECASE,
)
_LASTLOG_RE = re.compile(r"(^|/)var/log/lastlog$", re.IGNORECASE)
_ETC_TIMEZONE_RE = re.compile(r"(^|/)etc/timezone$", re.IGNORECASE)
_ETC_LOCALTIME_RE = re.compile(r"(^|/)etc/localtime$", re.IGNORECASE)
_SYSCONFIG_CLOCK_RE = re.compile(r"(^|/)etc/sysconfig/clock$", re.IGNORECASE)
_CONF_D_CLOCK_RE = re.compile(r"(^|/)etc/conf\.d/clock$", re.IGNORECASE)
_TIMEDATECTL_RE = re.compile(r"(^|/)timedatectl(?:[._-][a-z0-9_-]*)?$", re.IGNORECASE)
_HOSTNAMECTL_RE = re.compile(r"(^|/)hostnamectl(?:[._-][a-z0-9_-]*)?$", re.IGNORECASE)
# /etc/hostname is dedicated (not a bare "hostname" marker) because real
# disk-image evidence ships unrelated files with that exact basename
# outside /etc -- e.g. usr/lib/byobu/hostname (a shell script) and
# usr/lib/perl*/auto/Sys/Hostname.
_ETC_HOSTNAME_RE = re.compile(r"(^|/)etc/hostname$", re.IGNORECASE)
# os-release is checked by exact basename anywhere (both /etc/os-release
# and /usr/lib/os-release are legitimate per the spec, and this basename
# has not shown false positives against real evidence).
_OS_RELEASE_RE = re.compile(r"(^|/)os-release$", re.IGNORECASE)
# lsb-release is restricted to /etc/lsb-release and the installer-time
# snapshot at /var/log/installer/lsb-release (both confirmed present on
# real evidence). A bare "lsb-release" marker also matched dpkg's own
# package-metadata files for the lsb-release package itself --
# var/lib/dpkg/info/lsb-release.list/.md5sums/.postinst/.postrm/.prerm --
# which are not the file's content, just bookkeeping that shares its name.
_LSB_RELEASE_RE = re.compile(r"(^|/)(etc|var/log/installer)/lsb-release$", re.IGNORECASE)
# /etc/debian_version only -- dedicated for the same reason as the others,
# and so the internal "version" substring can never collide with kernel
# routing (see app.ingest.linux.os_info).
_DEBIAN_VERSION_RE = re.compile(r"(^|/)etc/debian_version$", re.IGNORECASE)
# uname output capture (e.g. "uname.txt", "uname_a.log"); excluded from
# bin/sbin like timedatectl/hostnamectl since /usr/bin/uname is a real
# binary, not captured command output.
_UNAME_RE = re.compile(r"(^|/)uname(?:[._-][a-z0-9_-]*)?$", re.IGNORECASE)
# timedatectl/hostnamectl/uname are also real systemd/coreutils binary
# names (under bin/sbin/) and, confirmed against real disk-image evidence,
# real systemd packages ship a file named exactly "timedatectl"/
# "hostnamectl" under usr/share/bash-completion/completions/ (a
# shell-completion *script*, sourced from a live shell -- never captured
# command output). Only the captured text output of actually running the
# command is a fact source; the executable and any package-shipped file
# living under a system share/bin directory is excluded rather than
# misread as that output.
_BIN_OR_SHARE_DIR_RE = re.compile(r"(^|/)(s?bin|share)/", re.IGNORECASE)

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
    apache_match = _APACHE_LOG_RE.search(path_str)
    if apache_match:
        apache_name = apache_match.group("name")
        artifact_type = "apache_error" if "error" in apache_name else "apache_access"
        return ("linux_apache", artifact_type, "linux_apache_raw")
    exim_match = _EXIM_LOG_RE.search(path_str)
    if exim_match:
        exim_name = exim_match.group("name")
        if exim_name.startswith("rejectlog"):
            artifact_type = "exim_reject"
        elif exim_name.startswith("paniclog"):
            artifact_type = "exim_panic"
        else:
            artifact_type = "exim_main"
        return ("linux_exim", artifact_type, "linux_exim_raw")
    if _LASTLOG_RE.search(path_str):
        return ("linux_lastlog", "lastlog", "linux_lastlog_raw")
    if _OS_RELEASE_RE.search(path_str):
        return ("linux_os_info", "os_release", "linux_os_info_raw")
    if _LSB_RELEASE_RE.search(path_str):
        return ("linux_os_info", "lsb_release", "linux_os_info_raw")
    if _DEBIAN_VERSION_RE.search(path_str):
        return ("linux_os_info", "debian_version", "linux_os_info_raw")
    if _ETC_TIMEZONE_RE.search(path_str):
        return ("linux_timezone", "etc_timezone", "linux_timezone_raw")
    if _ETC_LOCALTIME_RE.search(path_str):
        return ("linux_timezone", "etc_localtime", "linux_timezone_raw")
    if _SYSCONFIG_CLOCK_RE.search(path_str):
        return ("linux_timezone", "sysconfig_clock", "linux_timezone_raw")
    if _CONF_D_CLOCK_RE.search(path_str):
        return ("linux_timezone", "conf_d_clock", "linux_timezone_raw")
    if _TIMEDATECTL_RE.search(path_str) and not _BIN_OR_SHARE_DIR_RE.search(path_str):
        return ("linux_timezone", "timedatectl", "linux_timezone_raw")
    if _ETC_HOSTNAME_RE.search(path_str):
        return ("linux_os_info", "hostname", "linux_os_info_raw")
    if _HOSTNAMECTL_RE.search(path_str) and not _BIN_OR_SHARE_DIR_RE.search(path_str):
        # Host-identity command output (hostname, distribution, kernel,
        # architecture) first and foremost; app.ingest.linux.os_info also
        # extracts the "Time zone:" line it carries, reusing
        # app.ingest.linux.timezone's own validation for that one field.
        return ("linux_os_info", "hostnamectl", "linux_os_info_raw")
    if _UNAME_RE.search(path_str) and not _BIN_OR_SHARE_DIR_RE.search(path_str):
        return ("linux_os_info", "uname", "linux_os_info_raw")
    for marker, (family, artifact_type, parser) in _LINUX_ARTIFACT_MAP.items():
        if "/" in marker:
            # Directory-scoped marker: full relative-path context is required,
            # so a plain substring match is safe (low collision risk).
            if marker in path_str:
                return (family, artifact_type, parser)
        elif not _BIN_OR_SHARE_DIR_RE.search(path_str):
            # Filename-scoped marker: match the basename only (optionally with a
            # log-rotation suffix like ".1" or "-20230101", or the bare trailing
            # dash of the standard vipw/pwck backup convention: passwd-,
            # group-, shadow-), never a raw substring of the full path —
            # otherwise unrelated files that merely contain the marker word
            # (e.g. "more_messages_pb2.py" containing "messages", or
            # "group_utils.py" containing "group") get misclassified as
            # forensic log artifacts. A rotation/date suffix always starts
            # with a digit; requiring that (rather than accepting any
            # suffix) is what excludes a genuinely different file that just
            # happens to share the marker as a prefix -- confirmed against
            # real evidence: /usr/share/base-passwd/passwd.master is a
            # Debian package *template* listing default system accounts,
            # not a rotated copy of the host's actual /etc/passwd, and was
            # silently inflating the Host User Inventory with accounts that
            # never existed on the host. The digit check alone still isn't
            # enough though -- man page section files (passwd.5.gz, a real
            # man(7) naming convention, section "5") also start with a
            # digit after the dot; excluding usr/share (and usr/bin,
            # /sbin) the same way the hostnamectl/uname/timedatectl
            # false-positive fix already does is what actually rules those
            # out, since no real /etc/passwd, /etc/group or /etc/shadow
            # ever lives under a share/bin directory.
            if name == marker or name == f"{marker}-":
                return (family, artifact_type, parser)
            for separator in (".", "-"):
                prefix = f"{marker}{separator}"
                if name.startswith(prefix) and name[len(prefix):][:1].isdigit():
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
