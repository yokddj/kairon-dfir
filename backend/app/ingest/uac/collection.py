"""Recognise a UAC collection and read what its own ``uac.log`` says about the run.

The first lines of ``uac.log`` are written by UAC itself before it collects anything::

    2026-01-02 10:00:00 +0100 INF Unix-like Artifacts Collector 3.4.0
    2026-01-02 10:00:00 +0100 INF Command line: ./uac -p full /tmp/out
    2026-01-02 10:00:00 +0100 INF Operating system: macos
    2026-01-02 10:00:00 +0100 INF System architecture: arm64
    2026-01-02 10:00:00 +0100 INF Hostname: host.local
    2026-01-02 10:00:00 +0100 INF Time zone: Europe/Madrid

Only those header facts are read. The command line itself is not kept: it carries the output path
of the machine that ran the collection.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.ingest.linux.local_time import HostClock

UAC_LOG_NAME = "uac.log"
UAC_ROOT_DIRNAME = "[root]"
# Directories UAC writes next to uac.log; at least one must be present beside it.
UAC_OUTPUT_DIRS = (UAC_ROOT_DIRNAME, "live_response", "bodyfile", "hash_executables")
# UAC's names for the operating systems it runs on (see uac's lib/get_operating_system.sh).
UAC_OPERATING_SYSTEMS = {"aix", "esxi", "freebsd", "linux", "macos", "netbsd", "netscaler", "openbsd", "solaris"}
_HEADER_LINES = 80
_LINE_RE = re.compile(r"^(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<offset>[+-]\d{4}) [A-Z]{3} (?P<text>.*)$")
_VERSION_RE = re.compile(r"^Unix-like Artifacts Collector\s+(?P<version>\S+)")
_PROFILE_RE = re.compile(r"(?:^|\s)(?:-p|--profile)\s+(?P<profile>[A-Za-z0-9_.-]+)")
_MAX_ROOT_SEARCH_DEPTH = 3


@dataclass(frozen=True)
class UacCollection:
    root: str
    version: str | None = None
    operating_system: str | None = None
    architecture: str | None = None
    hostname: str | None = None
    timezone: str | None = None
    profile: str | None = None
    started_at: str | None = None

    def as_metadata(self) -> dict:
        data = asdict(self)
        data.pop("root", None)
        return {key: value for key, value in data.items() if value}


def _is_uac_root(directory: Path) -> bool:
    try:
        return (directory / UAC_LOG_NAME).is_file() and any((directory / name).is_dir() for name in UAC_OUTPUT_DIRS)
    except OSError:
        return False


def _parse_started_at(stamp: str, offset: str) -> str | None:
    try:
        return datetime.strptime(f"{stamp} {offset}", "%Y-%m-%d %H:%M:%S %z").isoformat()
    except ValueError:
        return None


def read_uac_log(path: Path) -> dict[str, str]:
    """The header facts of one uac.log, keyed by field name. Missing facts are left out."""
    facts: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, raw in enumerate(handle):
                if index >= _HEADER_LINES:
                    break
                match = _LINE_RE.match(raw.rstrip("\n"))
                if not match:
                    continue
                text = match.group("text").strip()
                if "started_at" not in facts:
                    started = _parse_started_at(match.group("stamp"), match.group("offset"))
                    if started:
                        facts["started_at"] = started
                version = _VERSION_RE.match(text)
                if version:
                    facts["version"] = version.group("version")
                    continue
                key, separator, value = text.partition(":")
                if not separator:
                    continue
                key = key.strip().lower()
                value = value.strip()
                if not value:
                    continue
                if key == "operating system":
                    facts["operating_system"] = value.lower()
                elif key == "system architecture":
                    facts["architecture"] = value
                elif key == "hostname":
                    facts["hostname"] = value
                elif key == "time zone":
                    facts["timezone"] = value
                elif key == "command line":
                    profile = _PROFILE_RE.search(value)
                    if profile:
                        facts["profile"] = profile.group("profile")
    except OSError:
        return {}
    return facts


def find_uac_root(start: Path) -> Path | None:
    """The UAC output directory at ``start`` or a few levels below it (a tar wrapped in a folder)."""
    if _is_uac_root(start):
        return start
    frontier = [start]
    for _ in range(_MAX_ROOT_SEARCH_DEPTH):
        next_frontier: list[Path] = []
        for directory in frontier:
            try:
                children = [child for child in directory.iterdir() if child.is_dir()]
            except OSError:
                continue
            for child in children:
                if _is_uac_root(child):
                    return child
                next_frontier.append(child)
        frontier = next_frontier[:200]
    return None


def detect_uac_collection(start: Path) -> UacCollection | None:
    root = find_uac_root(start)
    if root is None:
        return None
    facts = read_uac_log(root / UAC_LOG_NAME)
    if facts.get("operating_system") not in UAC_OPERATING_SYSTEMS:
        # A uac.log that names no operating system UAC knows is not trusted to decide the platform.
        facts.pop("operating_system", None)
    return UacCollection(root=str(root), **facts)


@lru_cache(maxsize=64)
def _collection_for_root(root: str) -> UacCollection:
    base = Path(root)
    facts = read_uac_log(base / UAC_LOG_NAME)
    return UacCollection(root=root, **facts)


def uac_collection_for(path: Path) -> UacCollection | None:
    """The UAC collection a collected file belongs to, found by walking up from it."""
    try:
        for candidate in list(path.parents)[:12]:
            if _is_uac_root(candidate):
                return _collection_for_root(str(candidate))
    except OSError:
        return None
    return None


def uac_host_clock(path: Path) -> HostClock:
    """The collected host's time zone as UAC recorded it, for times written without a zone."""
    collection = uac_collection_for(path)
    if collection is None or not collection.timezone:
        return HostClock()
    try:
        return HostClock(zone=ZoneInfo(collection.timezone), zone_name=collection.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return HostClock()


def collection_reference_time(path: Path) -> datetime | None:
    """When the collection ran: the reference for live-response output that prints no year."""
    collection = uac_collection_for(path)
    if collection is None or not collection.started_at:
        return None
    try:
        return datetime.fromisoformat(collection.started_at)
    except ValueError:
        return None


def relative_to_collected_root(source_path: str) -> str | None:
    """The original absolute path of a file under ``[root]/`` ("[root]/etc/hosts" -> "/etc/hosts")."""
    normalized = str(source_path or "").replace("\\", "/")
    marker = f"{UAC_ROOT_DIRNAME}/"
    index = normalized.find(marker)
    if index < 0:
        return None
    return "/" + normalized[index + len(marker):]
