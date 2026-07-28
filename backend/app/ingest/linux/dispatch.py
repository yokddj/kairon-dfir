"""Linux parser dispatch helpers."""
from __future__ import annotations

import importlib
import gzip
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
    "linux_auth_raw": LinuxParserTarget("linux_auth_raw", "auth", "parse_auth", frozenset({"wtmp", "btmp", "lastlog"})),
    "linux_syslog_raw": LinuxParserTarget("linux_syslog_raw", "syslog", "parse_syslog"),
    "linux_audit_raw": LinuxParserTarget("linux_audit_raw", "audit", "parse_audit"),
    "linux_apache_raw": LinuxParserTarget("linux_apache_raw", "apache", "parse_apache"),
    "linux_shell_raw": LinuxParserTarget("linux_shell_raw", "shell_history", "parse_shell_history"),
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


def parse_linux_artifact_file(path: Path, *, parser: str | None, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    target, parse_func = resolve_linux_parser(parser)
    try:
        if str(artifact_type or "").lower() in target.binary_artifact_types:
            return parse_func(path.read_bytes(), source_path=source_path)
        if path.suffix.lower() == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                return parse_func(handle.read(), source_path=source_path)
        return parse_func(path.read_text(encoding="utf-8", errors="replace"), source_path=source_path)
    except LinuxParserDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LinuxParserExecutionError(f"Linux parser '{target.parser}' failed for '{source_path}': {exc}") from exc
