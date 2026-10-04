"""Linux parser dispatch helpers."""
from __future__ import annotations

import importlib
import re
import gzip
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ingest.linux.local_time import ASSUMED_YEAR, ASSUMED_ZONE, file_reference_time, host_clock_for, resolve_local_times


class LinuxParserDispatchError(RuntimeError):
    """Raised when a recognized Linux artifact cannot be routed."""


class LinuxParserExecutionError(RuntimeError):
    """Raised when a Linux parser fails after dispatch."""


@dataclass(frozen=True)
class LinuxParserTarget:
    parser: str
    module: str
    function: str
    binary_artifact_types: frozenset[str] = frozenset()


LINUX_PARSER_TARGETS: dict[str, LinuxParserTarget] = {
    "linux_journal_raw": LinuxParserTarget("linux_journal_raw", "journal", "parse_journal"),
    "linux_auth_raw": LinuxParserTarget("linux_auth_raw", "auth", "parse_auth", frozenset({"wtmp", "btmp"})),
    "linux_lastlog_raw": LinuxParserTarget("linux_lastlog_raw", "lastlog", "parse_lastlog", frozenset({"lastlog"})),
    "linux_timezone_raw": LinuxParserTarget("linux_timezone_raw", "timezone", "parse_timezone", frozenset({"etc_localtime"})),
    "linux_syslog_raw": LinuxParserTarget("linux_syslog_raw", "syslog", "parse_syslog"),
    "linux_generic_raw": LinuxParserTarget("linux_generic_raw", "generic_log", "parse_generic_log"),
    "linux_fail2ban_raw": LinuxParserTarget("linux_fail2ban_raw", "fail2ban", "parse_fail2ban"),
    "linux_persistence_raw": LinuxParserTarget("linux_persistence_raw", "persistence", "parse_persistence"),
    "linux_k8s_audit_raw": LinuxParserTarget("linux_k8s_audit_raw", "k8s_audit", "parse_k8s_audit"),
    "linux_container_raw": LinuxParserTarget("linux_container_raw", "container_logs", "parse_container_artifact"),
    "linux_database_raw": LinuxParserTarget("linux_database_raw", "database_logs", "parse_database_log"),
    "linux_vpn_raw": LinuxParserTarget("linux_vpn_raw", "vpn_logs", "parse_vpn_log"),
    "linux_audit_raw": LinuxParserTarget("linux_audit_raw", "audit", "parse_audit"),
    "linux_apache_raw": LinuxParserTarget("linux_apache_raw", "apache", "parse_apache"),
    "linux_exim_raw": LinuxParserTarget("linux_exim_raw", "exim", "parse_exim"),
    "linux_shell_raw": LinuxParserTarget("linux_shell_raw", "shell_history", "parse_shell_history"),
    "linux_shell_raw_bsd_audit": LinuxParserTarget("linux_shell_raw_bsd_audit", "shell_history", "parse_bsd_shell_audit_log"),
    "linux_cron_raw": LinuxParserTarget("linux_cron_raw", "cron", "parse_cron"),
    "linux_systemd_raw": LinuxParserTarget("linux_systemd_raw", "systemd", "parse_systemd"),
    "linux_ssh_raw": LinuxParserTarget("linux_ssh_raw", "ssh_artifacts", "parse_ssh_artifacts"),
    "linux_identity_raw": LinuxParserTarget("linux_identity_raw", "identity", "parse_identity"),
    "linux_sudoers_raw": LinuxParserTarget("linux_sudoers_raw", "sudoers", "parse_sudoers"),
    "linux_packages_raw": LinuxParserTarget("linux_packages_raw", "packages", "parse_packages"),
    "linux_network_raw": LinuxParserTarget("linux_network_raw", "network", "parse_network"),
    "linux_os_info_raw": LinuxParserTarget("linux_os_info_raw", "os_info", "parse_os_info"),
}


def resolve_linux_parser(parser: str | None) -> tuple[LinuxParserTarget, Callable[..., list[dict[str, Any]]]]:
    parser_key = str(parser or "").strip().lower()
    target = LINUX_PARSER_TARGETS.get(parser_key)
    if target is None:
        raise LinuxParserDispatchError(f"No Linux parser dispatch target configured for parser '{parser_key or 'unknown'}'.")
    module = importlib.import_module(f"app.ingest.linux.{target.module}")
    parse_func = getattr(module, target.function, None)
    if not callable(parse_func):
        raise LinuxParserDispatchError(
            f"Linux parser target app.ingest.linux.{target.module}.{target.function} for '{parser_key}' is not callable."
        )
    return target, parse_func


_UTMP_NAME_RE = re.compile(r"^[bw]tmp(?:\.\d+)?$", re.IGNORECASE)


def parse_linux_artifact_file(path: Path, *, parser: str | None, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    rows = _parse_linux_artifact_file(path, parser=parser, artifact_type=artifact_type, source_path=source_path)
    if any(row.get("timestamp_status") in {ASSUMED_YEAR, ASSUMED_ZONE} for row in rows):
        # Local, zone-less (and year-less) times become UTC using the host's own timezone, boot
        # records and the file's modification time; see app.ingest.linux.local_time.
        resolve_local_times(rows, reference=file_reference_time(path), clock=host_clock_for(path))
    return rows


def _parse_linux_artifact_file(path: Path, *, parser: str | None, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    target, parse_func = resolve_linux_parser(parser)
    try:
        if target.parser == "linux_lastlog_raw":
            passwd_content = _read_linux_passwd_for_artifact(path, source_path)
            return parse_func(path.read_bytes(), source_path=source_path, passwd_content=passwd_content)
        if target.parser == "linux_timezone_raw":
            # classify_artifact() reports the coarse family ("linux_timezone")
            # as artifact_type for disk-image-sourced candidates, reserving
            # the real sub-type for its separate linux_artifact_type field --
            # so the generic binary_artifact_types check below never fires
            # for /etc/localtime from that path (confirmed against real
            # evidence: it silently fell back to text-decoding a TZif
            # binary). Matching on the source filename directly is
            # unambiguous and correct for every calling convention.
            if Path(str(source_path or path.name)).name.lower() == "localtime":
                return parse_func(path.read_bytes(), source_path=source_path)
        if str(artifact_type or "").lower() in target.binary_artifact_types:
            return parse_func(path.read_bytes(), source_path=source_path)
        if target.parser == "linux_auth_raw" and _UTMP_NAME_RE.match(Path(str(source_path or path.name)).name):
            # Same disk-image case as localtime above: the coarse family arrives as artifact_type,
            # so the binary login records (wtmp, btmp and rotated copies) were text-decoded.
            return parse_func(path.read_bytes(), source_path=source_path)
        if target.parser == "linux_journal_raw":
            from app.ingest.linux.journal import parse_journal_binary_file
            from app.ingest.linux.journal_binary import is_journal_file

            # Binary journals are recognised by their magic bytes, so a renamed or
            # extensionless copy still parses; text exports fall through unchanged.
            if is_journal_file(path):
                return parse_journal_binary_file(path, source_path=source_path)
        if target.parser in {"linux_generic_raw", "linux_container_raw", "linux_database_raw", "linux_vpn_raw"}:
            # Capped, magic-byte-sniffed read (gzip/bzip2/xz): an unrecognised log can be
            # arbitrarily large or a compression bomb, unlike the fixed-name artifacts.
            from app.ingest.linux.generic_log import read_log_text

            text, truncated = read_log_text(path)
            return parse_func(text, source_path=source_path, truncated=truncated)
        if path.suffix.lower() == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                return parse_func(handle.read(), source_path=source_path)
        return parse_func(path.read_text(encoding="utf-8", errors="replace"), source_path=source_path)
    except LinuxParserDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LinuxParserExecutionError(f"Linux parser '{target.parser}' failed for '{source_path}': {exc}") from exc


def _read_linux_passwd_for_artifact(path: Path, source_path: str) -> str | None:
    try:
        for root in (path.parent, *path.parents):
            passwd = root / "etc" / "passwd"
            if passwd.is_file():
                return passwd.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    normalized_source = str(source_path or "").replace("\\", "/").lstrip("/")
    suffix = Path(*normalized_source.split("/")) if normalized_source else Path(path.name)
    try:
        root = path
        for _ in suffix.parts:
            root = root.parent
        passwd = root / "etc" / "passwd"
        if passwd.is_file():
            return passwd.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return None
