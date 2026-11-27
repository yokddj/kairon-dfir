"""macOS Unified Logs (``/private/var/db/diagnostics`` + ``/private/var/db/uuidtext``).

The Unified Log is the main log of a modern Mac. Its binary ``.tracev3`` files are decoded by
Mandiant's ``unifiedlog_iterator`` (macos-UnifiedLogs, Apache-2.0; pinned in
tooling/tooling.lock.yaml), which reads a *logarchive* layout: ``Persist/``, ``Special/``,
``Signpost/`` and ``timesync/`` from diagnostics next to the ``00``..``FF`` and ``dsc`` folders of
uuidtext, all in one directory. It does not follow symbolic links to directories, so that
directory is rebuilt with hard links (a copy when the temporary directory is on another file
system).

Kept entries are split by topic into their own families (macos_ul_sessions, macos_ul_app_execution,
macos_ul_installs, macos_ul_disks, macos_ul_accounts, macos_ul_remote_access,
macos_ul_kernel_extensions; anything else in mode "all" goes to macos_ul_other), so each is its own
view instead of one mixed log.

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
from collections.abc import Sequence, Iterator
from pathlib import Path
from typing import Any

from app.ingest.macos.row_store import collapse_to_disk

ARTIFACT_FAMILY = "macos_unified_logs"
DIAGNOSTICS_PARTS = ("Persist", "Special", "Signpost", "timesync", "HighVolume")
# Each kept entry goes to the view of its topic, by Apple subsystem prefix or, for lines without a
# subsystem, by process. Order matters only where prefixes overlap (none do today).
TOPICS: tuple[tuple[str, str, tuple[str, ...], frozenset[str]], ...] = (
    ("macos_ul_sessions", "Sessions & screen", ("com.apple.loginwindow",), frozenset({"loginwindow"})),
    ("macos_ul_app_execution", "App execution (Gatekeeper, XProtect)", ("com.apple.syspolicy", "com.apple.xprotect", "com.apple.XProtectFramework", "com.apple.MRT"), frozenset({"syspolicyd", "XProtect", "XprotectService", "MRT"})),
    ("macos_ul_installs", "Installations", ("com.apple.install", "com.apple.packagekit"), frozenset({"installer", "installd", "system_installd"})),
    ("macos_ul_disks", "Disks & USB", ("com.apple.DiskArbitration",), frozenset({"diskarbitrationd"})),
    ("macos_ul_accounts", "Accounts & authorization", ("com.apple.authd", "com.apple.Authorization", "com.apple.opendirectoryd"), frozenset({"authd", "opendirectoryd"})),
    ("macos_ul_remote_access", "sudo, SSH & screen sharing", ("com.apple.screensharing",), frozenset({"sudo", "su", "sshd", "sshd-session", "sshd-keygen-wrapper", "screensharingd"})),
    ("macos_ul_kernel_extensions", "Kernel extensions", ("com.apple.kext",), frozenset({"kextload", "kmutil"})),
)
TOPIC_FAMILIES = frozenset(topic[0] for topic in TOPICS)
# What is kept by default: every topic's subsystems, and its processes for lines without one.
FORENSIC_SUBSYSTEM_PREFIXES = tuple(prefix for topic in TOPICS for prefix in topic[2])
FORENSIC_PROCESSES = frozenset(process for topic in TOPICS for process in topic[3])
_OTHER_FAMILY = "macos_ul_other"
_MAX_MESSAGE = 4000


def topic_family(subsystem: str, process: str) -> str:
    for family, _label, prefixes, processes in TOPICS:
        if subsystem and subsystem.startswith(prefixes):
            return family
        if not subsystem and process in processes:
            return family
    return _OTHER_FAMILY
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
    clean_subsystem = subsystem if subsystem not in {"Unknown subsystem"} else ""
    return {
        "artifact_family": topic_family(clean_subsystem, process_path.rsplit("/", 1)[-1]),
        "artifact_type": "unified_log_entry",
        "source_file": source_path,
        "timestamp": entry.get("timestamp") or None,
        "timestamp_status": "ok" if entry.get("timestamp") else "missing",
        "subsystem": clean_subsystem,
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


def parse_unified_logs(path: Path, *, source_path: str) -> "Sequence[dict[str, Any]]":
    """The kept entries, folded and in time order. Returned as a sequence backed by a temporary
    SQLite file (app.ingest.macos.row_store): a Mac's logs do not fit in the worker's memory."""
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
        kept = (entry_row(entry, source_path=source_path) for entry in iter_entries(archive, binary=binary) if keep_all or is_forensic(entry))
        return collapse_to_disk(kept, temp_dir=temp_root)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
