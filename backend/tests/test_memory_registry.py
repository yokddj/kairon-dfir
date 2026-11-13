"""Registry values read from a memory image with MemProcFS: reading through the registry API,
decoding (BAM, UserAssist, ShimCache, strings), host facts, users and addresses.

All data here is synthetic.
"""

from __future__ import annotations

import base64
import codecs
import ctypes
import struct
from datetime import UTC, datetime

from app.services.memory import memprocfs_registry as registry

SID = "S-1-5-21-1000-2000-3000-1001"


def _filetime(text: str) -> int:
    moment = datetime.fromisoformat(text).replace(tzinfo=UTC)
    return int((moment - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000)


def _sz(text: str) -> bytes:
    return (text + "\x00").encode("utf-16le")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _userassist(run_count: int, last_run: str) -> bytes:
    data = bytearray(72)
    struct.pack_into("<IIII", data, 0, 0, run_count, run_count + 1, 61000)
    struct.pack_into("<Q", data, 60, _filetime(last_run))
    return bytes(data)


# --------------------------------------------------------------------------
# A fake MemProcFS exposing the registry API over a dict of keys
# --------------------------------------------------------------------------

class _Fn:
    def __init__(self, fn):
        self.fn = fn
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        return self.fn(*args)


def _put(buffer, size_ptr, data: bytes) -> None:
    ctypes.memmove(buffer, data, len(data))
    size_ptr._obj.value = len(data)


class FakeMemProcFS:
    """keys: {path: {"written": filetime, "subkeys": [...], "values": [(name, type, bytes), ...]}}"""

    def __init__(self, keys: dict, hives: list[tuple[int, str, str]]):
        self.keys = {path.lower(): value for path, value in keys.items()}
        self.hives = hives
        self.VMMDLL_WinReg_HiveList = _Fn(self._hive_list)
        self.VMMDLL_WinReg_EnumKeyExU = _Fn(self._enum_key)
        self.VMMDLL_WinReg_EnumValueU = _Fn(self._enum_value)
        self.VMMDLL_WinReg_QueryNameOriginalU = _Fn(self._original)

    def _key(self, path: bytes):
        return self.keys.get(path.decode().lower())

    def _hive_list(self, handle, array, count, count_ptr):
        count_ptr._obj.value = len(self.hives)
        if array:
            items = ctypes.cast(array, ctypes.POINTER(registry._HiveInfo))
            for index, (address, name, path) in enumerate(self.hives):
                items[index].vaCMHIVE = address
                items[index].uszName = name.encode()
                items[index].uszNameShort = path.encode()[-32:]
        return 1

    def _enum_key(self, handle, path, index, name, name_size, written):
        key = self._key(path)
        if key is None:
            return 0
        if index == 0xFFFFFFFF:
            written._obj.value = key.get("written", 0)
            return 1
        subkeys = key.get("subkeys") or []
        if index >= len(subkeys):
            return 0
        _put(name, name_size, subkeys[index].encode() + b"\x00")
        child = self._key(path + b"\\" + subkeys[index].encode()) or {}
        written._obj.value = child.get("written", 0)
        return 1

    def _enum_value(self, handle, path, index, name, name_size, value_type, data, data_size):
        key = self._key(path)
        values = (key or {}).get("values") or []
        if index >= len(values):
            return 0
        value_name, kind, raw = values[index]
        # MemProcFS lists "\\" in a name as "_".
        _put(name, name_size, value_name.replace("\\", "_").encode() + b"\x00")
        value_type._obj.value = kind
        _put(data, data_size, raw)
        return 1

    def _original(self, handle, full_path, is_value, out, size_ptr):
        key_path, _, listed = full_path.decode().rpartition("\\")
        for value_name, _kind, _raw in (self._key(key_path.encode()) or {}).get("values") or []:
            if value_name.replace("\\", "_") == listed:
                _put(out, size_ptr, value_name.encode() + b"\x00")
                return 1
        return 0


def _machine() -> FakeMemProcFS:
    ccs = "HKLM\\SYSTEM\\ControlSet002"
    ua = "0x1000\\ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    keys = {
        "HKLM\\SYSTEM": {},
        "HKLM\\SOFTWARE": {},
        "HKLM\\SYSTEM\\Select": {"values": [("Current", 4, struct.pack("<I", 2))]},
        f"{ccs}\\Control\\ComputerName\\ComputerName": {"written": _filetime("2024-01-01T00:00:00"), "values": [("ComputerName", 1, _sz("WS-TEST01"))]},
        f"{ccs}\\Control\\TimeZoneInformation": {"values": [("TimeZoneKeyName", 1, _sz("W. Europe Standard Time")), ("Bias", 4, struct.pack("<i", -60))]},
        f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces": {"subkeys": ["{iface-1}"]},
        f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces\\{{iface-1}}": {"written": _filetime("2024-01-02T08:00:00"), "values": [
            ("DhcpIPAddress", 1, _sz("192.0.2.25")), ("DhcpDefaultGateway", 7, _sz("192.0.2.1") + b"\x00\x00"), ("EnableDHCP", 4, struct.pack("<I", 1)),
        ]},
        f"{ccs}\\Services\\bam\\State\\UserSettings": {"subkeys": [SID]},
        f"{ccs}\\Services\\bam\\State\\UserSettings\\{SID}": {"values": [
            ("Version", 4, struct.pack("<I", 1)),
            ("\\Device\\HarddiskVolume3\\Users\\analyst\\Downloads\\tool.exe", 3, struct.pack("<Q", _filetime("2024-01-02T09:30:00")) + b"\x00" * 16),
        ]},
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList": {"subkeys": [SID]},
        f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{SID}": {"values": [("ProfileImagePath", 2, _sz("C:\\Users\\analyst")), ("State", 4, struct.pack("<I", 0))]},
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run": {"values": [("Updater", 1, _sz("C:\\ProgramData\\upd.exe -q"))]},
        ua: {"subkeys": ["{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"]},
        f"{ua}\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count": {"values": [
            (codecs.encode("C:\\Tools\\scanner.exe", "rot_13"), 3, _userassist(3, "2024-01-02T10:00:00")),
        ]},
        "0x1000\\ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU": {"values": [("a", 1, _sz("cmd /c whoami\\1"))]},
    }
    return FakeMemProcFS(keys, hives=[(0x1000, "0x1000-ntuserdat-unknown", "Users\\analyst\\ntuser.dat"), (0x2000, "0x2000-SYSTEM-unknown", "SYSTEM")])


def _snapshot() -> dict:
    return registry.read_registry(_machine(), handle=1)


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

def test_the_current_control_set_is_followed():
    snapshot = _snapshot()
    assert snapshot["control_set"] == "ControlSet002"
    paths = {key["path"] for key in snapshot["keys"]}
    assert "HKLM\\SYSTEM\\ControlSet002\\Control\\ComputerName\\ComputerName" in paths


def test_a_user_hive_is_shown_under_its_sid():
    snapshot = _snapshot()
    user_keys = [key for key in snapshot["keys"] if key.get("hive") == "NTUSER.DAT"]
    assert user_keys and all(key["user_sid"] == SID for key in user_keys)
    assert any(key["path"].startswith(f"HKU\\{SID}\\Software") for key in user_keys)


def test_value_names_keep_their_backslashes():
    snapshot = _snapshot()
    bam = next(key for key in snapshot["keys"] if key["category"] == "bam")
    assert "\\Device\\HarddiskVolume3\\Users\\analyst\\Downloads\\tool.exe" in {value["name"] for value in bam["values"]}


def test_keys_this_system_does_not_have_are_not_reported_as_missing_evidence():
    result = registry.normalize_memprocfs_registry([_snapshot()], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert not [doc for doc in result["items"] if doc["status"] == "not_in_memory"]


def test_an_unreadable_hive_is_reported_as_unknown():
    machine = _machine()
    del machine.keys["hklm\\software"]
    result = registry.normalize_memprocfs_registry([registry.read_registry(machine, handle=1)], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    missing = [doc for doc in result["items"] if doc["status"] == "not_in_memory"]
    assert [doc["key_path"] for doc in missing] == ["HKLM\\SOFTWARE"]
    assert "unknown, not absent" in missing[0]["summary"]


def test_a_memprocfs_without_the_registry_api_says_so():
    class Old:
        pass

    snapshot = registry.read_registry(Old(), handle=1)
    assert snapshot["available"] is False
    result = registry.normalize_memprocfs_registry([snapshot], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["items"] == [] and result["warnings"]


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------

def _documents() -> list[dict]:
    return registry.normalize_memprocfs_registry([_snapshot()], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")["items"]


def _one(documents, category, value_name=None):
    return next(d for d in documents if d["category"] == category and (value_name is None or d["value_name"] == value_name))


def test_strings_numbers_and_multi_strings_are_readable():
    documents = _documents()
    assert _one(documents, "computer_name", "ComputerName")["value_data"] == "WS-TEST01"
    assert _one(documents, "network_interface", "DhcpIPAddress")["value_data"] == "192.0.2.25"
    assert _one(documents, "network_interface", "DhcpDefaultGateway")["value_data"] == "192.0.2.1"
    assert _one(documents, "autorun", "Updater")["value_data"] == "C:\\ProgramData\\upd.exe -q"
    assert _one(documents, "computer_name", "ComputerName")["key_path"].startswith("HKLM\\SYSTEM\\ControlSet002\\")


def test_bam_gives_the_program_and_its_last_execution():
    bam_documents = [d for d in _documents() if d["category"] == "bam"]
    # The key's own Version / SequenceNumber counters are not programs.
    assert [d["value_name"] for d in bam_documents] == ["\\Device\\HarddiskVolume3\\Users\\analyst\\Downloads\\tool.exe"]
    bam = bam_documents[0]
    assert bam["decoded"] == {"program": "\\Device\\HarddiskVolume3\\Users\\analyst\\Downloads\\tool.exe", "last_execution": "2024-01-02T09:30:00+00:00"}
    assert bam["user_sid"] == SID
    assert bam["timestamp"] == "2024-01-02T09:30:00+00:00"


def test_userassist_is_rot13_decoded_with_counts():
    entry = _one(_documents(), "userassist")
    assert entry["decoded"]["program"] == "C:\\Tools\\scanner.exe"
    assert entry["decoded"]["run_count"] == 3
    assert entry["decoded"]["focus_seconds"] == 61
    assert entry["decoded"]["last_run"] == "2024-01-02T10:00:00+00:00"
    assert entry["user_sid"] == SID


def _shimcache_win10(entries: list[tuple[str, str | None]], gap_after: int | None = None) -> bytes:
    header = bytearray(0x34)
    struct.pack_into("<I", header, 0, 0x34)
    body = bytearray()
    for index, (path, modified) in enumerate(entries):
        encoded = path.encode("utf-16le")
        entry = struct.pack("<H", len(encoded)) + encoded + struct.pack("<Q", _filetime(modified) if modified else 0) + struct.pack("<I", 0)
        record = b"10ts" + struct.pack("<II", 0, len(entry)) + entry
        if gap_after is not None and index == gap_after:
            record = b"\x00" * len(record)  # a page that was not in memory
        body += record
    return bytes(header) + bytes(body)


def test_shimcache_read_from_memory_survives_zero_filled_gaps():
    from app.ingest.raw_parsers.shimcache_parser import _get_shimcache_entries

    raw = _shimcache_win10([
        ("C:\\Windows\\a.exe", "2024-01-01T00:00:00"),
        ("C:\\Windows\\b.exe", "2024-01-01T01:00:00"),
        ("C:\\Tools\\c.exe", "2024-01-01T02:00:00"),
    ], gap_after=1)
    paths = [entry["path"] for entry in _get_shimcache_entries(raw, partial=True)]
    assert paths == ["C:\\Windows\\a.exe", "C:\\Tools\\c.exe"]


def test_shimcache_from_disk_still_fails_loudly_on_damage():
    import pytest

    from app.ingest.raw_parsers.shimcache_parser import _get_shimcache_entries

    raw = _shimcache_win10([("C:\\a.exe", "2024-01-01T00:00:00"), ("C:\\b.exe", "2024-01-01T01:00:00")], gap_after=0)
    with pytest.raises(ValueError):
        _get_shimcache_entries(raw)


def test_appcompatcache_becomes_one_document_per_entry():
    raw = _shimcache_win10([("C:\\Windows\\a.exe", "2024-01-01T00:00:00"), ("C:\\Tools\\c.exe", None)])
    snapshot = {"available": True, "keys": [{
        "path": "HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache", "category": "shimcache",
        "hive": "SYSTEM", "values": [{"name": "AppCompatCache", "type": 3, "size": len(raw), "data": _b64(raw)}],
    }], "missing": []}
    documents = registry.normalize_memprocfs_registry([snapshot], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")["items"]
    assert [d["decoded"]["path"] for d in documents] == ["C:\\Windows\\a.exe", "C:\\Tools\\c.exe"]
    assert documents[0]["timestamp_source"] == "file_last_modified"
    assert documents[1]["timestamp"] is None
    assert "ShimCache" in documents[0]["summary"]


# --------------------------------------------------------------------------
# Host facts, users, addresses, timeline
# --------------------------------------------------------------------------

def test_host_facts_from_the_registry():
    facts = registry.host_fact_inputs(_documents(), run_id="r", plugin_run_id="p")
    from app.ingest.host_facts_extraction import extract_host_fact_documents

    assert extract_host_fact_documents(facts) == facts
    by_type = {doc["host_fact"]["fact_type"]: doc["host_fact"] for doc in facts}
    assert by_type["host.hostname"]["normalized_value"] == "WS-TEST01"
    assert by_type["host.hostname"]["artifact_type"] == "memory_registry_computername"
    assert by_type["host.timezone"]["normalized_value"] == "W. Europe Standard Time"


def test_the_registry_hostname_ranks_below_the_hive_file_and_above_the_event_logs():
    from app.services.host_facts import _SOURCE_PRIORITY

    rank = {kind: _SOURCE_PRIORITY[("host.hostname", kind)] for kind in ("system_hive_computername", "memory_registry_computername", "evtx_computer_field")}
    assert rank["system_hive_computername"] > rank["memory_registry_computername"] > rank["evtx_computer_field"]


def test_profile_list_becomes_host_user_facts():
    users = registry.host_user_documents(_documents())
    assert users == [{"host_user_fact": {
        "source_kind": "profile_list", "username": None, "home": "C:\\Users\\analyst",
        "attributes": {"sid": SID, "profile_state": "0"}, "parser": "memprocfs.registry", "source_file": "memory:memprocfs.registry",
    }}]


def test_interface_addresses_are_host_network_observations(monkeypatch):
    from app.services import host_network

    documents = _documents()
    hits = [{"_source": {**d, "key_last_write": d["key_last_write"]}} for d in documents if d["category"] == "network_interface"]

    class Client:
        def search(self, index, body):
            return {"hits": {"hits": hits}}

    monkeypatch.setattr(host_network, "index_exists", lambda client, index: True)
    monkeypatch.setattr(host_network, "is_index_queryable", lambda client, index: True)
    observations = host_network._query_memory_registry_interfaces(Client(), "idx", evidence_map={"e": object()})
    # The machine's own address, not its gateway.
    assert [o["raw_value"] for o in observations] == ["192.0.2.25"]
    assert observations[0]["source_kind"] == "memory_registry_tcpip_interface"


def test_bam_and_userassist_are_timeline_executions():
    from app.services.memory.timeline import _memory_events

    documents = [d for d in _documents() if d["category"] in ("bam", "userassist", "service", "autorun")]
    events, _undated = _memory_events("c", "e", "r", documents)
    kinds = {(event["event_kind"], event["occurred_at"][:19]) for event in events}
    assert ("program_execution", "2024-01-02T09:30:00") in kinds
    assert ("program_execution", "2024-01-02T10:00:00") in kinds
    # Configuration values are not timeline events.
    assert len(events) == 2


def test_the_registry_plugin_is_part_of_the_system_information_analysis():
    from app.core.config import Settings
    from app.services.memory import memprocfs_engine
    from app.services.memory.execution import ARTIFACT_PLUGIN_NORMALIZER, _normalize_artifact_payload

    assert "memprocfs.registry" in memprocfs_engine.PROFILE_PLUGINS["metadata_only"]
    assert ARTIFACT_PLUGIN_NORMALIZER["memprocfs.registry"] == "memory_registry_value"
    assert "memprocfs.registry" in Settings().allowed_memory_plugins
    result = _normalize_artifact_payload("memprocfs.registry", [_snapshot()], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["accepted_count"] > 0
    assert {doc["document_type"] for doc in result["items"]} == {"memory_registry_value"}


def test_the_engine_reads_the_saved_snapshot(tmp_path):
    import json

    from app.services.memory import memprocfs_engine

    assert memprocfs_engine.rows("memprocfs.registry", tmp_path) == []
    (tmp_path / "registry.json").write_text(json.dumps({"available": True, "keys": [], "missing": []}))
    assert memprocfs_engine.rows("memprocfs.registry", tmp_path) == [{"available": True, "keys": [], "missing": []}]


def test_an_old_scan_gets_its_registry_read_without_a_new_scan(tmp_path, monkeypatch):
    from app.services.memory import memprocfs_engine, memprocfs_runner

    calls = []

    def fake_run_registry(evidence_path, work_dir, destination, **kw):
        calls.append(destination)
        destination.write_text("{}")

    monkeypatch.setattr(memprocfs_runner, "run_registry", fake_run_registry)
    memprocfs_engine.ensure_registry(tmp_path, tmp_path / "image.raw", tmp_path, timeout_seconds=60)
    memprocfs_engine.ensure_registry(tmp_path, tmp_path / "image.raw", tmp_path, timeout_seconds=60)
    assert calls == [tmp_path / "registry.json"]


def test_an_image_analysed_twice_gives_one_timeline_event_per_value():
    from app.services.memory.timeline import _memory_events

    first = [d for d in _documents() if d["category"] == "bam"]
    again = [{**d, "scan_run_id": "r2", "document_id": d["document_id"] + "-2"} for d in first]
    events, _ = _memory_events("c", "e", "r", first + again)
    assert len(events) == len(first)
