"""Route a macOS (or UAC live-response) artifact to its parser."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


class MacosParserDispatchError(RuntimeError):
    """Raised when a recognised macOS artifact has no parser configured."""


class MacosParserExecutionError(RuntimeError):
    """Raised when a macOS parser fails on its input."""


def _parsers() -> dict[str, Callable[..., list[dict[str, Any]]]]:
    from app.ingest.macos.accounts import parse_dslocal_group, parse_dslocal_user
    from app.ingest.macos.knowledgec import parse_knowledgec
    from app.ingest.macos.launchd import parse_launchd_plist
    from app.ingest.macos.logs import parse_install_log, parse_launchd_log, parse_wifi_log
    from app.ingest.macos.quarantine import parse_quarantine_events
    from app.ingest.macos.shared_file_lists import parse_shared_file_list
    from app.ingest.macos.system_info import parse_system_version
    from app.ingest.macos.tcc import parse_tcc

    def accounts(path: Path, *, source_path: str, artifact_type: str) -> list[dict[str, Any]]:
        if artifact_type == "local_group":
            return parse_dslocal_group(path, source_path=source_path)
        return parse_dslocal_user(path, source_path=source_path)

    def logs(path: Path, *, source_path: str, artifact_type: str) -> list[dict[str, Any]]:
        if artifact_type == "wifi_log":
            return parse_wifi_log(path, source_path=source_path)
        if artifact_type == "launchd_log":
            return parse_launchd_log(path, source_path=source_path)
        return parse_install_log(path, source_path=source_path)

    def simple(function: Callable[..., list[dict[str, Any]]]) -> Callable[..., list[dict[str, Any]]]:
        return lambda path, *, source_path, artifact_type: function(path, source_path=source_path)

    return {
        "macos_launchd_raw": simple(parse_launchd_plist),
        "macos_quarantine_raw": simple(parse_quarantine_events),
        "macos_knowledgec_raw": simple(parse_knowledgec),
        "macos_tcc_raw": simple(parse_tcc),
        "macos_accounts_raw": accounts,
        "macos_system_info_raw": simple(parse_system_version),
        "macos_logs_raw": logs,
        "macos_recent_items_raw": simple(parse_shared_file_list),
    }


MACOS_PARSERS = frozenset({
    "macos_launchd_raw", "macos_quarantine_raw", "macos_knowledgec_raw", "macos_tcc_raw",
    "macos_accounts_raw", "macos_system_info_raw", "macos_logs_raw", "macos_recent_items_raw",
})


def _subtype_for(source_path: str, artifact_type: str | None) -> str:
    from app.ingest.macos.helpers import looks_like_macos_artifact

    detected = looks_like_macos_artifact(source_path)
    if detected:
        return detected[1]
    return str(artifact_type or "")


def parse_macos_artifact_file(path: Path, *, parser: str | None, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    key = str(parser or "").strip().lower()
    parsers = _parsers()
    function = parsers.get(key)
    if function is None:
        raise MacosParserDispatchError(f"No macOS parser configured for parser '{key or 'unknown'}'.")
    try:
        return function(path, source_path=source_path, artifact_type=_subtype_for(source_path, artifact_type))
    except Exception as exc:  # noqa: BLE001
        raise MacosParserExecutionError(f"macOS parser '{key}' failed for '{source_path}': {exc}") from exc


def parse_uac_artifact_file(path: Path, *, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    from app.ingest.uac.live_response import looks_like_uac_output, parse_uac_output

    detected = looks_like_uac_output(source_path)
    subtype = detected[1] if detected else artifact_type
    try:
        return parse_uac_output(path, artifact_type=subtype, source_path=source_path)
    except Exception as exc:  # noqa: BLE001
        raise MacosParserExecutionError(f"UAC live-response parser failed for '{source_path}': {exc}") from exc
