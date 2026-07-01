"""Tests for observation normalizers: envars, getsids, privileges, vadinfo."""

from __future__ import annotations

from app.services.memory.artifact_normalizers import (
    normalize_windows_envars,
    normalize_windows_getsids,
    normalize_windows_malfind,
    normalize_windows_privileges,
    normalize_windows_vadinfo,
)


def _args():
    return {
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "scan_run_id": "run-1",
        "plugin_run_id": "plugin-1",
    }


def test_envars_normalizes_standard_output():
    payload = [
        {"PID": 4, "Process": "System", "Variable": "NUMBER_OF_PROCESSORS", "Value": "4"},
        {"PID": 4, "Process": "System", "Variable": "OS", "Value": "Windows_NT"},
        {"PID": 1234, "Process": "cmd.exe", "Variable": "PATH", "Value": "C:\\Windows\\system32"},
    ]
    result = normalize_windows_envars(payload, **_args())
    assert result["accepted_count"] == 3
    assert result["dropped_count"] == 0
    assert result["raw_count"] == 3
    items = result["items"]
    assert items[0]["variable"] == "NUMBER_OF_PROCESSORS"
    assert items[0]["value"] == "4"
    assert items[0]["pid"] == 4
    assert items[0]["memory_artifact_type"] == "memory_environment_variable"
    assert items[2]["variable"] == "PATH"


def test_envars_drops_rows_without_variable():
    payload = [
        {"PID": 4, "Process": "System", "Value": "some value"},
    ]
    result = normalize_windows_envars(payload, **_args())
    assert result["accepted_count"] == 0
    assert result["dropped_count"] == 1


def test_envars_handles_alternative_field_names():
    payload = [
        {"Pid": 8, "Name": "lsass.exe", "Key": "TEMP", "Data": "/tmp"},
    ]
    result = normalize_windows_envars(payload, **_args())
    assert result["accepted_count"] == 1
    assert result["items"][0]["variable"] == "TEMP"
    assert result["items"][0]["process_name"] == "lsass.exe"


def test_getsids_normalizes_standard_output():
    payload = [
        {"PID": 4, "Process": "System", "SID": "S-1-5-18", "Name": "NT AUTHORITY\\SYSTEM"},
        {"PID": 1234, "Process": "cmd.exe", "SID": "S-1-5-21-1234", "Name": "DOMAIN\\user"},
    ]
    result = normalize_windows_getsids(payload, **_args())
    assert result["accepted_count"] == 2
    assert result["dropped_count"] == 0
    items = result["items"]
    assert items[0]["sid"] == "S-1-5-18"
    assert items[0]["resolved_name"] == "NT AUTHORITY\\SYSTEM"
    assert items[0]["memory_artifact_type"] == "memory_sid"
    assert items[1]["pid"] == 1234


def test_getsids_drops_rows_without_sid():
    payload = [
        {"PID": 4, "Process": "System", "Name": "SYSTEM"},
    ]
    result = normalize_windows_getsids(payload, **_args())
    assert result["accepted_count"] == 0


def test_privileges_normalizes_standard_output():
    payload = [
        {"PID": 4, "Process": "System", "Value": "SeDebugPrivilege", "Present": True, "Enabled": True, "Default": True, "Description": "Debug programs"},
        {"PID": 4, "Process": "System", "Value": "SeShutdownPrivilege", "Present": True, "Enabled": False, "Default": False},
    ]
    result = normalize_windows_privileges(payload, **_args())
    assert result["accepted_count"] == 2
    items = result["items"]
    assert items[0]["privilege"] == "SeDebugPrivilege"
    assert items[0]["enabled"] is True
    assert items[0]["description"] == "Debug programs"
    assert items[0]["memory_artifact_type"] == "memory_privilege"
    assert items[1]["enabled"] is False


def test_privileges_drops_rows_without_privilege_name():
    payload = [
        {"PID": 4, "Process": "System", "Present": True},
    ]
    result = normalize_windows_privileges(payload, **_args())
    assert result["accepted_count"] == 0


def test_privileges_handles_alternative_field_names():
    payload = [
        {"PID": 8, "Name": "svchost.exe", "Privilege": "SeAuditPrivilege", "Enabled": True},
    ]
    result = normalize_windows_privileges(payload, **_args())
    assert result["accepted_count"] == 1
    assert result["items"][0]["privilege"] == "SeAuditPrivilege"


def test_normalizers_respect_max_records():
    payload = [{"PID": i, "Process": f"proc{i}", "Variable": f"VAR{i}", "Value": f"val{i}"} for i in range(10)]
    result = normalize_windows_envars(payload, max_records=5, **_args())
    assert result["accepted_count"] == 5
    assert result["dropped_count"] == 5
    assert len(result["warnings"]) == 1


def test_normalizers_return_provenance_fields():
    payload = [{"PID": 100, "Process": "test.exe", "SID": "S-1-5-99", "Name": "TEST"}]
    result = normalize_windows_getsids(payload, **_args())
    item = result["items"][0]
    assert item["source_plugin"] == "windows.getsids"
    assert item["source_record_index"] == 0
    assert item["document_id"] == "run-1:plugin-1:0"
    assert item["normalization_version"] == "memory_artifact_canonical_v1"


def test_normalizers_handle_empty_payload():
    result = normalize_windows_envars([], **_args())
    assert result["accepted_count"] == 0
    assert result["raw_count"] == 0

    result = normalize_windows_getsids(None, **_args())
    assert result["accepted_count"] == 0

    result = normalize_windows_privileges([], **_args())
    assert result["accepted_count"] == 0


def test_normalizers_are_idempotent():
    payload = [
        {"PID": 4, "Process": "System", "SID": "S-1-5-18", "Name": "SYSTEM"},
    ]
    r1 = normalize_windows_getsids(payload, **_args())
    r2 = normalize_windows_getsids(payload, **_args())
    assert r1["accepted_count"] == r2["accepted_count"]
    assert r1["items"][0]["document_id"] == r2["items"][0]["document_id"]


# ---------------------------------------------------------------------------
# VAD normalizer tests
# ---------------------------------------------------------------------------


def test_vadinfo_normalizes_to_memory_vad():
    payload = [
        {"PID": 1234, "Process": "cmd.exe", "Start": "0x7ffe0000", "End": "0x7ffeffff", "Protection": "PAGE_READONLY", "Tag": "VadS", "CommitCharge": 1, "PrivateMemory": True, "FileObject": "\\Windows\\System32\\kernel32.dll"},
        {"PID": 5678, "Process": "svchost.exe", "Start": "0x10000", "End": "0x1ffff", "Protection": "PAGE_EXECUTE_READ", "Tag": "Vad ", "CommitCharge": 2, "PrivateMemory": False},
    ]
    result = normalize_windows_vadinfo(payload, **_args())
    assert result["accepted_count"] == 2
    assert result["dropped_count"] == 0
    items = result["items"]
    assert items[0]["memory_artifact_type"] == "memory_vad"
    assert items[0]["document_type"] == "memory_vad"
    assert items[0]["pid"] == 1234
    assert items[0]["start_address"] == "0x7ffe0000"
    assert items[0]["protection"] == "PAGE_READONLY"
    assert items[0]["tag"] == "VadS"
    assert items[0]["private_memory"] is True
    assert items[0]["file_object"] == "\\Windows\\System32\\kernel32.dll"
    assert items[0]["review_status"] == "needs_review"


def test_vadinfo_extracts_vad_specific_fields():
    payload = [
        {"PID": 100, "Process": "test.exe", "Start": "0x400000", "End": "0x401000", "Protection": "PAGE_EXECUTE_WRITECOPY", "Tag": "VadS", "CommitCharge": 3, "PrivateMemory": True, "FileObject": "\\Device\\HarddiskVolume1\\test.exe", "Parent": 50},
    ]
    result = normalize_windows_vadinfo(payload, **_args())
    item = result["items"][0]
    assert item["commit_charge"] == 3
    assert item["file_object"] == "\\Device\\HarddiskVolume1\\test.exe"
    assert item["parent_pid"] == 50


def test_vadinfo_drops_rows_without_pid_and_address():
    payload = [
        {"Process": "orphan.exe"},
    ]
    result = normalize_windows_vadinfo(payload, **_args())
    assert result["accepted_count"] == 0
    assert result["dropped_count"] == 1


def test_vadinfo_is_idempotent():
    payload = [
        {"PID": 4, "Process": "System", "Start": "0x0", "End": "0xfff", "Protection": "PAGE_READONLY", "Tag": "Vad "},
    ]
    r1 = normalize_windows_vadinfo(payload, **_args())
    r2 = normalize_windows_vadinfo(payload, **_args())
    assert r1["accepted_count"] == r2["accepted_count"]
    assert r1["items"][0]["document_id"] == r2["items"][0]["document_id"]


def test_vadinfo_and_malfind_are_distinct():
    payload = [{"PID": 100, "Process": "test.exe", "Start": "0x400000", "End": "0x4fffff", "Protection": "PAGE_EXECUTE_READ"}]
    vad_result = normalize_windows_vadinfo(payload, **_args())
    malfind_result = normalize_windows_malfind(payload, source_plugin="windows.malfind", **_args())
    assert vad_result["items"][0]["document_type"] == "memory_vad"
    assert malfind_result["items"][0]["document_type"] == "memory_suspicious_region"
    assert vad_result["items"][0]["document_id"] != malfind_result["items"][0]["document_id"]
