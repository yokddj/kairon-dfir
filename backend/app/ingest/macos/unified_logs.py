"""macOS Unified Logs (``/private/var/db/diagnostics`` + ``/private/var/db/uuidtext``).

The Unified Log is the main log of a modern Mac. Its binary ``.tracev3`` files are decoded by
Mandiant's ``unifiedlog_iterator`` (macos-UnifiedLogs, Apache-2.0; pinned in
tooling/tooling.lock.yaml), which reads a *logarchive* layout: ``Persist/``, ``Special/``,
``Signpost/`` and ``timesync/`` from diagnostics next to the ``00``..``FF`` and ``dsc`` folders of
uuidtext, all in one directory. It does not follow symbolic links to directories, so that
directory is rebuilt with hard links (a copy when the temporary directory is on another file
system).

A Mac writes tens of millions of entries (a test Mac's output passed 12 GB in 11 minutes), so the
tool's JSONL is read from its standard output and filtered as it streams -- never written out
whole. By default only the subsystems and processes of forensic value are kept (logins and
authorisation, local accounts, Gatekeeper, XProtect, volume mounts, installations, sudo/su, SSH,
screen sharing, kernel extension loading), named after Apple's own subsystem identifiers and
process names. ``MACOS_UNIFIED_LOGS_MODE=all`` keeps every entry. Repeated lines are folded (see
app.ingest.macos.logs.collapse_repeats).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.ingest.macos.logs import collapse_repeats

ARTIFACT_FAMILY = "macos_unified_logs"
DIAGNOSTICS_PARTS = ("Persist", "Special", "Signpost", "timesync", "HighVolume")
FORENSIC_SUBSYSTEM_PREFIXES = (
    "com.apple.loginwindow",
    "com.apple.authd",
    "com.apple.Authorization",
    "com.apple.opendirectoryd",
    "com.apple.syspolicy",
    "com.apple.xprotect",
    "com.apple.XProtectFramework",
    "com.apple.MRT",
    "com.apple.DiskArbitration",
    "com.apple.install",
    "com.apple.packagekit",
    "com.apple.screensharing",
    "com.apple.kext",
)
FORENSIC_PROCESSES = {
    "sudo", "su", "sshd", "sshd-session", "sshd-keygen-wrapper", "screensharingd", "loginwindow", "authd",
    "opendirectoryd", "installer", "installd", "system_installd", "syspolicyd", "XProtect", "XprotectService",
    "MRT", "kextload", "kmutil", "diskarbitrationd",
}
_MAX_MESSAGE = 4000
_DEFAULT_TIMEOUT_SECONDS = 4 * 3600


def iterator_binary() -> str | None:
    configured = os.environ.get("UNIFIEDLOG_ITERATOR") or "/opt/unifiedlog/unifiedlog_iterator"
    if Path(configured).is_file() and os.access(configured, os.X_OK):
        return configured
    return shutil.which("unifiedlog_iterator")


def collection_mode() -> str:
    return "all" if str(os.environ.get("MACOS_UNIFIED_LOGS_MODE", "")).strip().lower() == "all" else "forensic"


def diagnostics_and_uuidtext(marker: Path) -> tuple[Path, Path] | None:
    """The diagnostics folder an artifact marker sits in, and the uuidtext folder beside it."""
    for candidate in [marker, *marker.parents][:6]:
        if candidate.name == "diagnostics" and candidate.is_dir():
            uuidtext = candidate.parent / "uuidtext"
            return (candidate, uuidtext) if uuidtext.is_dir() else None
    return None


def _link_tree(source: Path, target: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(source):
        relative = Path(dirpath).relative_to(source)
        (target / relative).mkdir(parents=True, exist_ok=True)
        for name in filenames:
            origin = Path(dirpath) / name
            if origin.is_symlink() or not origin.is_file():
                continue
            destination = target / relative / name
            try:
                os.link(origin, destination)
            except OSError:
                shutil.copy2(origin, destination)


def build_logarchive(diagnostics: Path, uuidtext: Path, work_dir: Path) -> Path:
    archive = work_dir / "system.logarchive"
    archive.mkdir(parents=True, exist_ok=True)
    for part in DIAGNOSTICS_PARTS:
        if (diagnostics / part).is_dir():
            _link_tree(diagnostics / part, archive / part)
    for child in uuidtext.iterdir():
        if child.is_dir() and not child.is_symlink():
            _link_tree(child, archive / child.name)
    return archive


def is_forensic(entry: dict[str, Any]) -> bool:
    """A forensic subsystem, or a forensic process writing without a subsystem (sudo, sshd...).

    A process's lines under some other subsystem are its libraries talking (syspolicyd's
    networking, loginwindow's wallpaper and drawing): on a test Mac they were most of what a
    process-only rule kept.
    """
    subsystem = str(entry.get("subsystem") or "")
    if subsystem in {"", "Unknown subsystem"}:
        process = str(entry.get("process") or "").rsplit("/", 1)[-1]
        return process in FORENSIC_PROCESSES
    return subsystem.startswith(FORENSIC_SUBSYSTEM_PREFIXES)


def entry_row(entry: dict[str, Any], *, source_path: str) -> dict[str, Any]:
    process_path = str(entry.get("process") or "")
    message = str(entry.get("message") or "")[:_MAX_MESSAGE]
    subsystem = str(entry.get("subsystem") or "")
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": "unified_log_entry",
        "source_file": source_path,
        "timestamp": entry.get("timestamp") or None,
        "timestamp_status": "ok" if entry.get("timestamp") else "missing",
        "subsystem": subsystem if subsystem not in {"Unknown subsystem"} else "",
        "category": str(entry.get("category") or ""),
        "process": process_path.rsplit("/", 1)[-1],
        "process_path": process_path,
        "pid": entry.get("pid"),
        "euid": entry.get("euid"),
        "log_type": str(entry.get("log_type") or ""),
        "unified_event_type": str(entry.get("event_type") or ""),
        "library": str(entry.get("library") or ""),
        "boot_uuid": str(entry.get("boot_uuid") or ""),
        "tracev3_file": str(entry.get("evidence") or "").rsplit("/", 1)[-1],
        "event_action": "unified_log_entry",
        "message": message,
    }


def iter_entries(archive: Path, *, binary: str, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS) -> Iterator[dict[str, Any]]:
    """The tool's JSONL entries as they stream out (its warnings go to a capped stderr buffer)."""
    process = subprocess.Popen(
        [binary, "--mode", "log-archive", "--input", str(archive), "--format", "jsonl"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1024 * 1024,
    )
    try:
        assert process.stdout is not None
        for line in process.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                yield entry
        process.wait(timeout=timeout_seconds)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def parse_unified_logs(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    from app.core.config import get_settings

    located = diagnostics_and_uuidtext(path)
    if located is None:
        raise ValueError("diagnostics folder with a uuidtext folder beside it not found")
    binary = iterator_binary()
    if binary is None:
        raise RuntimeError("unifiedlog_iterator is not installed")
    keep_all = collection_mode() == "all"
    temp_root = Path(get_settings().backend_temp_dir)
    temp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="unifiedlogs-", dir=str(temp_root)))
    try:
        archive = build_logarchive(*located, work_dir)
        rows = [entry_row(entry, source_path=source_path) for entry in iter_entries(archive, binary=binary) if keep_all or is_forensic(entry)]
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    rows.sort(key=lambda row: str(row.get("timestamp") or ""))
    return collapse_repeats(rows)
