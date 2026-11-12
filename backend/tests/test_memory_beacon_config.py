"""Cobalt Strike beacon configurations are decoded from the memory regions FindEvil flags.

The configurations here are synthetic: built from the documented settings layout (type, kind,
length, value; XOR-encoded with one byte), never taken from a real sample.
"""

from __future__ import annotations

import os
import struct

import pytest

from app.services.memory import beacon_config, memprocfs_findevil
from app.services.memory.artifact_normalizers import normalize_memprocfs_findevil

# DER prefix of an RSA public key (rsaEncryption OID): what the parser keys on to find a config.
_RSA_PREFIX = bytes.fromhex("30819f300d06092a864886f70d010101050003818d00")


def _setting(index: int, kind: int, value) -> bytes:
    if kind == 1:
        return struct.pack(">HHHH", index, 1, 2, value)
    if kind == 2:
        return struct.pack(">HHHI", index, 2, 4, value)
    return struct.pack(">HHH", index, 3, len(value)) + value


def synthetic_config(xor: int = 0x2E, server: bytes = b"c2.example.test,/api/v1") -> bytes:
    config = b"".join([
        _setting(1, 1, 8),  # protocol: https
        _setting(2, 1, 443),
        _setting(3, 2, 60000),
        _setting(5, 1, 25),
        _setting(7, 3, (_RSA_PREFIX + bytes(range(141))).ljust(256, b"\0")),
        _setting(8, 3, server.ljust(256, b"\0")),
        _setting(9, 3, b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestAgent".ljust(128, b"\0")),
        _setting(15, 3, b"\\\\.\\pipe\\test_pipe".ljust(128, b"\0")),
        _setting(30, 3, b"%windir%\\sysnative\\rundll32.exe".ljust(64, b"\0")),
        _setting(37, 2, 123456789),
    ]) + b"\0\0"
    return bytes(byte ^ xor for byte in config.ljust(0x1000, b"\0"))


def _memory(regions: dict[tuple[int, int], bytes]):
    """read(pid, address, size) over a sparse address space; unmapped bytes read as zeros."""
    def read(pid: int, address: int, size: int) -> bytes:
        out = bytearray(size)
        for (region_pid, base), data in regions.items():
            if region_pid != pid:
                continue
            lo, hi = max(address, base), min(address + size, base + len(data))
            if lo < hi:
                out[lo - address:hi - address] = data[lo - base:hi - base]
        return bytes(out)
    return read


def test_only_flagged_code_regions_are_searched_and_overlaps_merge():
    rows = [
        {"PID": "100", "Process": "rundll32.exe", "Type": "PRIVATE_RWX", "Address": "1a0000", "Description": ""},
        {"PID": "100", "Process": "rundll32.exe", "Type": "NOIMAGE_RX", "Address": "1a5000", "Description": ""},
        {"PID": "100", "Process": "rundll32.exe", "Type": "YR_HACKTOOL", "Address": "3000000", "Description": ""},
        {"PID": "200", "Process": "svchost.exe", "Type": "PROC_PARENT", "Address": "", "Description": ""},
        {"PID": "x", "Process": "?", "Type": "PRIVATE_RWX", "Address": "1000", "Description": ""},
    ]
    regions = beacon_config.candidate_regions(rows)
    # The YARA match first, then the writable-executable region (merged with the RX one next to it).
    assert [(r["pid"], hex(r["start"])) for r in regions] == [(100, hex(0x3000000 - beacon_config.YARA_LOOKBEHIND_BYTES)), (100, "0x1a0000")]
    assert regions[1]["end"] == 0x1A5000 + beacon_config.WINDOW_BYTES and regions[1]["rank"] == 1


@pytest.mark.parametrize("xor", [0x2E, 0x69])
def test_a_configuration_in_a_flagged_region_becomes_a_cs_beacon_row(xor):
    region = os.urandom(70_000) + synthetic_config(xor) + os.urandom(5_000)
    read = _memory({(100, 0x1A0000): region})
    regions = [{"pid": 100, "process": "rundll32.exe", "start": 0x1A0000, "end": 0x1A0000 + beacon_config.WINDOW_BYTES}]
    rows = beacon_config.beacon_rows(regions, read)
    assert len(rows) == 1
    row = rows[0]
    assert row["Type"] == "CS_BEACON" and row["PID"] == "100" and row["Process"] == "rundll32.exe" and row["Address"] == "1a0000"
    text = row["Description"]
    for expected in ("https://c2.example.test port 443 /api/v1", "sleep 60 s, jitter 25%", "TestAgent", "\\\\.\\pipe\\test_pipe", "sysnative\\rundll32.exe", "watermark 123456789"):
        assert expected in text


def test_regions_without_a_configuration_give_nothing():
    read = _memory({(100, 0x1A0000): os.urandom(200_000)})
    regions = [{"pid": 100, "process": "a.exe", "start": 0x1A0000, "end": 0x1A0000 + 0x40000}, {"pid": 7, "process": "b.exe", "start": 0x5000, "end": 0x9000}]
    assert beacon_config.beacon_rows(regions, read) == []


def test_the_same_beacon_seen_twice_in_a_process_is_one_row():
    config = synthetic_config()
    read = _memory({(100, 0x100000): config, (100, 0x900000): config})
    regions = [{"pid": 100, "process": "a.exe", "start": base, "end": base + 0x2000} for base in (0x100000, 0x900000)]
    assert len(beacon_config.beacon_rows(regions, read)) == 1


def test_the_search_stops_at_its_time_budget():
    read = _memory({(100, 0x100000): synthetic_config()})
    regions = [{"pid": 100, "process": "a.exe", "start": 0x100000, "end": 0x102000}]
    assert beacon_config.beacon_rows(regions, read, time_budget=-1) == []


def test_a_failing_search_keeps_the_findevil_rows(monkeypatch):
    rows = [{"PID": "100", "Process": "a.exe", "Type": "PRIVATE_RWX", "Address": "1a0000", "Description": "x"}]

    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(beacon_config, "beacon_rows", broken)
    watchdog = type("W", (), {"update": lambda self, _p: None})()
    assert memprocfs_findevil._with_beacons(object(), 0, rows, watchdog) == rows


def test_a_beacon_row_is_a_high_priority_indicator():
    payload = [{"PID": "100", "Process": "rundll32.exe", "Type": "CS_BEACON", "Address": "1a0000", "Description": "Cobalt Strike beacon configuration: C2 https://c2.example.test port 443."}]
    result = normalize_memprocfs_findevil(payload, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    item = result["items"][0]
    flat = str(item)
    assert "'high'" in flat and "c2.example.test" in flat and "Cobalt Strike" in flat
