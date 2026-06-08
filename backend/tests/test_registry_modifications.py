from __future__ import annotations

from app.ingest.normalization.registry_modifications import (
    correlate_registry_commands,
    detect_registry_command,
    normalize_registry_modification_event,
)


def _sysmon_event(event_id: int, event_type: str, target: str, details: str = "") -> dict:
    return {
        "id": f"sysmon-{event_id}",
        "@timestamp": "2026-06-06T18:23:00Z",
        "host": {"name": "KAIRON-LAB01"},
        "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
        "event": {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"},
        "windows": {
            "event_id": event_id,
            "event_data": {
                "EventType": event_type,
                "TargetObject": target,
                "Details": details,
                "Image": "C:\\Windows\\System32\\reg.exe",
                "ProcessGuid": "{PROC-1}",
            },
        },
        "process": {"guid": "{PROC-1}", "name": "reg.exe", "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v KaironLab01Run /d test"},
    }


def test_sysmon_13_normalizes_registry_value_set():
    doc = normalize_registry_modification_event(_sysmon_event(13, "SetValue", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KaironLab01Run", "powershell.exe -File run_key_payload.ps1"))

    assert doc["artifact"]["type"] == "registry_event"
    assert doc["event"]["type"] == "registry_value_set"
    assert doc["event"]["confidence"] == "observed_event"
    assert doc["registry"]["action"] == "set"
    assert doc["registry"]["target_object"].endswith("KaironLab01Run")
    assert doc["registry"]["value_data"].startswith("powershell.exe")


def test_sysmon_12_create_and_delete_are_distinct():
    created = normalize_registry_modification_event(_sysmon_event(12, "CreateKey", "HKLM\\Software\\Example"))
    deleted = normalize_registry_modification_event(_sysmon_event(12, "DeleteKey", "HKLM\\Software\\Example"))

    assert created["event"]["type"] == "registry_key_created"
    assert created["registry"]["action"] == "created"
    assert deleted["event"]["type"] == "registry_key_deleted"
    assert deleted["registry"]["action"] == "deleted"


def test_sysmon_14_normalizes_registry_rename():
    doc = normalize_registry_modification_event(_sysmon_event(14, "RenameKey", "HKLM\\Software\\OldName", "HKLM\\Software\\NewName"))

    assert doc["artifact"]["type"] == "registry_event"
    assert doc["event"]["type"] == "registry_object_renamed"
    assert doc["registry"]["action"] == "renamed"


def test_security_4657_normalizes_registry_value_modified():
    doc = normalize_registry_modification_event(
        {
            "id": "sec-4657",
            "@timestamp": "2026-06-06T18:24:00Z",
            "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
            "event": {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"},
            "windows": {
                "event_id": 4657,
                "event_data": {
                    "ObjectName": "\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "ObjectValueName": "KaironLab01Run",
                    "OldValue": "",
                    "NewValue": "powershell.exe -File run_key_payload.ps1",
                    "SubjectUserName": "analyst",
                    "ProcessName": "C:\\Windows\\System32\\reg.exe",
                },
            },
        }
    )

    assert doc["artifact"]["type"] == "registry_event"
    assert doc["event"]["type"] == "registry_value_modified"
    assert doc["registry"]["action"] == "modified"
    assert doc["registry"]["new_value"].startswith("powershell.exe")


def test_registry_commands_are_command_evidence_not_confirmed_events():
    reg = detect_registry_command("cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v KaironLab01Run /d test")
    ps = detect_registry_command("powershell.exe Set-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name KaironLab01Run -Value test")

    assert reg and reg["operation"] == "add"
    assert reg["confidence"] == "command_evidence"
    assert reg["confirmed_by_registry_event"] is False
    assert ps and ps["operation"] == "set"
    assert ps["registry_path"].startswith("HKCU")


def test_command_event_correlation_confirms_matching_registry_command():
    commands = [
        {
            "id": "cmd-1",
            "timestamp": "2026-06-06T18:23:05Z",
            "host": "KAIRON-LAB01",
            "process": {"guid": "{PROC-1}"},
            "registry_command": detect_registry_command("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KaironLab01Run /d test"),
        }
    ]
    events = [normalize_registry_modification_event(_sysmon_event(13, "SetValue", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KaironLab01Run", "test"))]

    result = correlate_registry_commands(commands, events)

    assert result[0]["registry_command"]["confirmed_by_registry_event"] is True
    assert result[0]["registry_command"]["linked_registry_event_ids"] == ["sysmon-13"]


def test_registry_persistence_lastwrite_is_not_converted_to_registry_event():
    doc = normalize_registry_modification_event(
        {
            "artifact": {"type": "registry_persistence", "parser": "registry_persistence_summary"},
            "event": {"type": "registry_persistence_value_observed", "action": "registry_persistence_value_observed"},
            "timestamp_semantics": "registry_key_last_write",
            "registry": {"timestamp_semantics": "registry_key_last_write", "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        }
    )

    assert doc["artifact"]["type"] == "registry_persistence"
    assert doc["event"]["type"] == "registry_persistence_value_observed"
