"""Cobalt Strike beacon configurations in the memory regions MemProcFS's FindEvil flags.

A running beacon keeps its configuration -- C2 servers, port, sleep and jitter, user agent,
named pipe, the process it spawns to inject into, the licence watermark -- in its own memory,
XOR-encoded with one byte (0x2e since Cobalt Strike 4, 0x69 before). FindEvil marks the regions
that hold injected or unbacked executable code (PRIVATE_RWX, NOIMAGE_RX, PE_INJECT...) and, with
its YARA rules enabled, the matches of known tooling (YR_*). Those regions are where a beacon
lives, so only they are searched: a bounded window of each, read through MemProcFS, is handed to
dissect.cobaltstrike (Fox-IT, MIT), which finds and decodes the configuration block.

Each beacon found becomes one more FindEvil row of type CS_BEACON, with the configuration in its
description, so it reaches the Find Evil view, search and the finding suggestions like any other
indicator. A beacon whose configuration is no longer readable in memory (a sleep mask encrypting
it, pages swapped out) is not found this way; FindEvil's own rows still flag its region.

Runs inside the MemProcFS child (app.services.memory.memprocfs_findevil), never in the worker.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

BEACON_TYPE = "CS_BEACON"
# FindEvil indicators of code that does not come from a file on disk, and YARA matches.
CANDIDATE_TYPES = frozenset({
    "PRIVATE_RWX", "PRIVATE_RX", "NOIMAGE_RWX", "NOIMAGE_RX", "PE_INJECT", "PE_NOLINK", "PE_PATCHED",
})
MAX_REGIONS = 512
# A beacon's image is a few hundred KiB; its configuration sits inside it.
WINDOW_BYTES = 4 * 1024 * 1024
# Searched first: YARA matches, then writable-executable and injected code, then the rest (JIT
# compilers fill many images with PRIVATE_RX regions).
_TYPE_RANK = {"PE_INJECT": 1, "PRIVATE_RWX": 1, "NOIMAGE_RWX": 1, "PE_PATCHED": 2, "PE_NOLINK": 2, "NOIMAGE_RX": 3, "PRIVATE_RX": 3}
# A YARA match can sit after the configuration inside the beacon's image.
YARA_LOOKBEHIND_BYTES = 1024 * 1024
TIME_BUDGET_SECONDS = 180
_PAGE = 0x1000
_MAX_TEXT = 300
# Every configuration carries the beacon's RSA public key, whose DER encoding holds the
# rsaEncryption OID; found XOR-encoded with the keys beacons use, it marks where a configuration
# may be, so the parser (pure Python, about 20 s per MiB) only reads a few KiB around each hit.
_RSA_OID = bytes.fromhex("06092a864886f70d010101")
_XOR_KEYS = (0x2E, 0x69, 0x00)
_BEFORE_OID = 0x400
_AFTER_OID = 0x1C00
_MAX_HITS_PER_REGION = 32


def _candidate_slices(data: bytes):
    hits = 0
    for key in _XOR_KEYS:
        needle = bytes(byte ^ key for byte in _RSA_OID)
        position = data.find(needle)
        while position != -1 and hits < _MAX_HITS_PER_REGION:
            hits += 1
            yield data[max(0, position - _BEFORE_OID): position + _AFTER_OID]
            position = data.find(needle, position + 1)


def _is_candidate(indicator_type: str) -> bool:
    return indicator_type in CANDIDATE_TYPES or indicator_type.startswith("YR_")


def _address(value: str) -> int | None:
    try:
        return int(str(value).strip(), 16)
    except (TypeError, ValueError):
        return None


def candidate_regions(rows: list[dict[str, str]], *, limit: int = MAX_REGIONS) -> list[dict[str, Any]]:
    """The memory windows to search: one per process and flagged address, YARA matches widened
    backwards, overlapping windows of one process merged."""
    windows: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        indicator_type = (row.get("Type") or "").strip()
        address = _address(row.get("Address") or "")
        try:
            pid = int(str(row.get("PID") or "").strip())
        except ValueError:
            continue
        if not _is_candidate(indicator_type) or address is None or address <= 0:
            continue
        start = address & ~(_PAGE - 1)
        if indicator_type.startswith("YR_"):
            start = max(0, start - YARA_LOOKBEHIND_BYTES)
        end = start + WINDOW_BYTES
        rank = 0 if indicator_type.startswith("YR_") else _TYPE_RANK.get(indicator_type, 3)
        process_windows = windows.setdefault(pid, [])
        for window in process_windows:
            if start < window["end"] and end > window["start"]:
                window["start"], window["end"] = min(start, window["start"]), max(end, window["end"])
                window["rank"] = min(rank, window["rank"])
                break
        else:
            process_windows.append({"pid": pid, "process": (row.get("Process") or "").strip(), "start": start, "end": end, "rank": rank})
    regions = [window for process_windows in windows.values() for window in process_windows]
    regions.sort(key=lambda window: window["rank"])
    return regions[:limit]


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.split(b"\0", 1)[0].decode("utf-8", "replace")
    return " ".join(str(value or "").split())[:_MAX_TEXT]


def describe(config: Any) -> dict[str, Any]:
    """The fields an analyst acts on, from a dissect.cobaltstrike BeaconConfig."""
    settings = config.settings
    domains = [_text(item) for item in (config.domains or [])]
    uris = [_text(item) for item in (config.uris or [])]
    spawnto = [_text(settings.get(key)) for key in ("SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64") if settings.get(key)]
    return {
        "protocol": _text(config.protocol),
        "domains": domains,
        "port": config.port,
        "uris": uris,
        "sleep_ms": config.sleeptime,
        "jitter_percent": config.jitter,
        "user_agent": _text(settings.get("SETTING_USERAGENT")),
        "pipe": _text(settings.get("SETTING_PIPENAME")),
        "spawnto": spawnto,
        "watermark": config.watermark,
    }


def description(fields: dict[str, Any]) -> str:
    parts = []
    servers = ", ".join(fields["domains"]) or "?"
    target = f"{fields['protocol'] or '?'}://{servers}"
    if fields.get("port"):
        target += f" port {fields['port']}"
    if fields["uris"]:
        target += f" {', '.join(fields['uris'])}"
    parts.append(f"C2 {target}")
    if fields.get("sleep_ms") is not None:
        sleep = f"sleep {int(fields['sleep_ms']) / 1000:g} s"
        if fields.get("jitter_percent"):
            sleep += f", jitter {fields['jitter_percent']}%"
        parts.append(sleep)
    if fields["user_agent"]:
        parts.append(f"user agent {fields['user_agent']}")
    if fields["pipe"]:
        parts.append(f"pipe {fields['pipe']}")
    if fields["spawnto"]:
        parts.append(f"spawns to {' / '.join(fields['spawnto'])}")
    if fields.get("watermark") is not None:
        parts.append(f"watermark {fields['watermark']}")
    return "Cobalt Strike beacon configuration: " + "; ".join(parts) + "."


def beacon_rows(
    regions: list[dict[str, Any]],
    read: Callable[[int, int, int], bytes | None],
    *,
    progress: Callable[[str], None] | None = None,
    time_budget: float = TIME_BUDGET_SECONDS,
) -> list[dict[str, str]]:
    """Search each region for a beacon configuration; one CS_BEACON row per configuration and
    process. ``read(pid, address, size)`` returns the bytes (unreadable pages as zeros)."""
    try:
        from dissect.cobaltstrike.beacon import BeaconConfig
    except ImportError:
        return []
    deadline = time.monotonic() + time_budget
    rows: list[dict[str, str]] = []
    seen: set[tuple[int, str]] = set()
    for index, region in enumerate(regions, start=1):
        if time.monotonic() > deadline:
            break
        if progress:
            progress(f"beacon search {index}/{len(regions)}")
        data = read(region["pid"], region["start"], region["end"] - region["start"])
        if not data or not any(data):
            continue
        for candidate in _candidate_slices(data):
            try:
                config = BeaconConfig.from_bytes(candidate)
            except Exception:  # noqa: BLE001 - not a configuration, or one too damaged to decode
                continue
            text = description(describe(config))
            key = (region["pid"], text)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "PID": str(region["pid"]),
                "Process": region["process"],
                "Type": BEACON_TYPE,
                "Address": f"{region['start']:x}",
                "Description": text,
            })
    return rows
