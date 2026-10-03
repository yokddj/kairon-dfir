"""Linux artifact detection helpers."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

from app.ingest.linux.container_logs import container_kind
from app.ingest.linux.persistence import persistence_kind

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
    "fail2ban.log": ("linux_fail2ban", "fail2ban_log", "linux_fail2ban_raw"),
    "ufw.log": ("linux_syslog", "ufw_log", "linux_syslog_raw"),
    "mail.log": ("linux_syslog", "mail_log", "linux_syslog_raw"),
    "maillog": ("linux_syslog", "mail_log", "linux_syslog_raw"),
    "mail.info": ("linux_syslog", "mail_log", "linux_syslog_raw"),
    "mail.warn": ("linux_syslog", "mail_log", "linux_syslog_raw"),
    "mail.err": ("linux_syslog", "mail_log", "linux_syslog_raw"),
    "iptables.log": ("linux_syslog", "iptables_log", "linux_syslog_raw"),
    "audit.log": ("linux_audit", "audit_log", "linux_audit_raw"),
    ".bash_history": ("linux_shell_history", "bash_history", "linux_shell_raw"),
    ".zsh_history": ("linux_shell_history", "zsh_history", "linux_shell_raw"),
    "bash_history": ("linux_shell_history", "bash_history", "linux_shell_raw"),
    "zsh_history": ("linux_shell_history", "zsh_history", "linux_shell_raw"),
    # BSD shell-command audit logging (seen on a FreeBSD-based appliance):
    # every interactive command is syslogged to its own file instead of
    # (or alongside) the shell's ~/.bash_history -- see
    # app.ingest.linux.shell_history.parse_bsd_shell_audit_log for the
    # "<user> on <tty> shell_command=\"...\"" message shape this routes to.
    "bash.log": ("linux_shell_history", "bsd_shell_audit", "linux_shell_raw_bsd_audit"),
    "sh.log": ("linux_shell_history", "bsd_shell_audit", "linux_shell_raw_bsd_audit"),
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
    r"(^|/)var/log/(apache2|httpd|nginx)/(?P<name>[^/]*(?:access|error)(?:[._-]log|\.log)[^/]*)$",
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


# Generic text logs -- the last-resort tier, consulted only after every specific
# detector above has declined the file. ``.log``/``.out``/``.err`` files (optionally
# rotated: ``.1``, ``-20240101``, ``.2.gz``) qualify under the places Linux software
# writes logs; ``.txt`` and a short list of well-known extensionless logs only qualify
# under /var/log itself, where a plain-text file is overwhelmingly a log.
_GENERIC_LOG_NAME_RE = re.compile(r"\.(?:log|out|err)(?:[.-][\w]+)*$", re.IGNORECASE)
_GENERIC_TXT_NAME_RE = re.compile(r"\.txt(?:[.-][\w]+)*$", re.IGNORECASE)
_VAR_LOG_RE = re.compile(r"(^|/)var/log/")
_LOG_ROOTS_RE = re.compile(r"(^|/)(?:var/log|var/lib/docker/containers|var/www|var/tmp|var/lib|opt|srv|usr/local|home|root|tmp)/")
_BINARY_OR_UNSUPPORTED_RE = re.compile(r"(^|/)var/log/journal/|\.(?:journal|db|sqlite3?|rrd|pcap|gz\.sig)(?:$|\.)", re.IGNORECASE)
_ROTATION_TAIL_RE = re.compile(r"(?:[.-]\d+)*(?:\.(?:gz|bz2|xz))?$")
_KNOWN_EXTENSIONLESS_LOGS = frozenset({
    "dmesg", "debug", "daemon", "user", "mail", "mail.info", "mail.warn", "mail.err",
    "boot", "ufw", "yum", "dnf", "pacman",
})


def _looks_like_generic_linux_log(path_str: str, name: str) -> bool:
    if _BIN_OR_SHARE_DIR_RE.search(path_str) or _BINARY_OR_UNSUPPORTED_RE.search(path_str):
        return False
    if not _LOG_ROOTS_RE.search(path_str):
        return False
    if _GENERIC_LOG_NAME_RE.search(name):
        return True
    if not _VAR_LOG_RE.search(path_str):
        return False
    if _GENERIC_TXT_NAME_RE.search(name):
        return True
    return _ROTATION_TAIL_RE.sub("", name) in _KNOWN_EXTENSIONLESS_LOGS


# Kubernetes API-server audit logs: /var/log/kubernetes/audit.log, /var/log/kube-apiserver/audit-*.log,
# or a file named like kube-apiserver-audit.log. Claimed before the filename table because the
# plain "audit.log" there means auditd.
_K8S_AUDIT_RE = re.compile(
    r"(?:(^|/)(?:kubernetes|kube-apiserver|k8s)[^/]*/(?:[^/]+/)*[^/]*audit[^/]*\.log(?:[.-]\w+)*$)"
    r"|(?:(^|/)[^/]*(?:kube|k8s)[^/]*audit[^/]*\.log(?:[.-]\w+)*$)",
    re.IGNORECASE,
)

# Binary systemd journals: /var/log/journal/<machine-id>/system.journal, user-<uid>.journal,
# rotated system@<id>.journal, and the .journal~ left by an unclean shutdown. /run/log/journal
# is the volatile (non-persistent) copy.
_JOURNAL_BINARY_RE = re.compile(r"(^|/)(?:var|run)/log/journal/(?:[^/]+/)?[^/]+\.journal~?$", re.IGNORECASE)


def looks_like_linux_artifact(path: str | Path) -> tuple[str, str, str] | None:
    """Detect Linux artifact family, type, and parser from a path."""
    path_str = str(path).replace("\\", "/").lower()
    name = path_str.rsplit("/", 1)[-1]
    if _JOURNAL_BINARY_RE.search(path_str):
        return ("linux_journal", "journal_binary", "linux_journal_raw")
    if _K8S_AUDIT_RE.search(path_str):
        return ("linux_k8s_audit", "k8s_audit", "linux_k8s_audit_raw")
    container_type = container_kind(path_str)
    if container_type:
        return ("linux_container", container_type, "linux_container_raw")
    # Persistence/rootkit-hook config is claimed before the filename table below: files such as
    # /etc/pam.d/passwd or /etc/pam.d/group must not be mistaken for /etc/passwd and /etc/group.
    persistence_type = persistence_kind(path_str)
    if persistence_type:
        return ("linux_persistence", persistence_type, "linux_persistence_raw")
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
    if _looks_like_generic_linux_log(path_str, name):
        return ("linux_generic_log", "generic_log", "linux_generic_raw")
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
