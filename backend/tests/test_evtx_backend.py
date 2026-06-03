from pathlib import Path
from types import SimpleNamespace

from app.ingest.raw_parsers.evtxecmd_backend import (
    EVTXECMD_BACKEND_CSV,
    EVTX_RAW_PYTHON_BACKEND,
    detect_evtx_parser_backends,
    normalize_evtx_parser_backend,
    select_evtx_parser_backend,
)
from app.ingest.eztools.evtxecmd import parse_evtxecmd_file
from app.ingest.artifact_normalizers import normalize_evtx_row
from app.ingest.normalizer import base_document
from app.rules_engine.sigma import build_sigma_case_profile
from app.services.debug_export import _build_process_graph


def _evtx_doc(row: dict) -> dict:
    artifact_meta = {
        "artifact_type": "windows_event",
        "parser": EVTXECMD_BACKEND_CSV,
        "source_tool": "evtxecmd",
        "source_format": "evtx_csv",
        "source_path": "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
        "ingest_run_id": "run-1",
    }
    document = base_document("case-1", "evidence-1", "artifact-1", row, artifact_meta)
    return normalize_evtx_row(document, row, artifact_meta)


def test_backend_registry_detects_evtxecmd_available(monkeypatch) -> None:
    detect_evtx_parser_backends.cache_clear()
    monkeypatch.setattr("app.ingest.raw_parsers.evtxecmd_backend._evtxecmd_command", lambda: ["EvtxECmd"])

    def fake_run(*args, **kwargs):  # noqa: ARG001
        return SimpleNamespace(returncode=0, stdout="EvtxECmd version 2026.5.0\n--csv\n--json\n", stderr="")

    monkeypatch.setattr("app.ingest.raw_parsers.evtxecmd_backend.subprocess.run", fake_run)

    backends = detect_evtx_parser_backends()

    assert backends["evtxecmd"]["available"] is True
    assert backends["evtxecmd"]["version"] == "2026.5.0"
    assert backends["evtxecmd"]["supports_csv"] is True
    assert backends["evtxecmd"]["supports_json"] is True


def test_auto_selects_evtxecmd_when_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.ingest.raw_parsers.evtxecmd_backend.detect_evtx_parser_backends",
        lambda: {
            "evtxecmd": {"available": True, "version": "2026.5.0", "path": "/opt/evtxecmd/EvtxECmd.dll", "supports_csv": True, "supports_json": True},
            "evtx_raw_python": {"available": True, "role": "fallback"},
        },
    )

    selection = select_evtx_parser_backend("auto")

    assert selection["selected"] == EVTXECMD_BACKEND_CSV
    assert selection["fallback"] is False


def test_auto_falls_back_to_python_when_evtxecmd_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.ingest.raw_parsers.evtxecmd_backend.detect_evtx_parser_backends",
        lambda: {
            "evtxecmd": {"available": False, "version": "", "path": "", "supports_csv": False, "supports_json": False, "error": "missing"},
            "evtx_raw_python": {"available": True, "role": "fallback"},
        },
    )

    selection = select_evtx_parser_backend("auto")

    assert selection["selected"] == EVTX_RAW_PYTHON_BACKEND
    assert selection["fallback"] is True
    assert normalize_evtx_parser_backend("evtx_raw") == EVTX_RAW_PYTHON_BACKEND


def test_evtxecmd_csv_normalizes_to_searchable_windows_event_contract(tmp_path: Path) -> None:
    fixture = tmp_path / "EvtxECmd_Output.csv"
    fixture.write_text(
        "TimeCreatedUtc,EventId,Provider,Channel,Computer,EventRecordId,Message,TargetUserName,IpAddress\n"
        "2026-05-28T10:00:00Z,4624,Microsoft-Windows-Security-Auditing,Security,HOSTA,123,Successful logon,alice,10.0.0.5\n",
        encoding="utf-8",
    )

    docs = parse_evtxecmd_file(
        "case-1",
        "evidence-1",
        "artifact-1",
        fixture,
        {
            "artifact_type": "windows_event",
            "parser": EVTXECMD_BACKEND_CSV,
            "source_path": "Windows/System32/winevt/Logs/Security.evtx",
            "ingest_run_id": "run-1",
            "contract_version": "v1",
        },
    )

    assert len(docs) == 1
    doc = docs[0]
    assert doc["case_id"] == "case-1"
    assert doc["evidence_id"] == "evidence-1"
    assert doc["ingest_run_id"] == "run-1"
    assert doc["artifact"]["type"] == "windows_event"
    assert doc["artifact"]["parser"] == EVTXECMD_BACKEND_CSV
    assert doc["source_file"] == "Windows/System32/winevt/Logs/Security.evtx"
    assert doc["@timestamp"]
    assert doc["windows"]["event_id"] == 4624
    assert doc["windows"]["channel"] == "Security"
    assert doc["windows"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert doc["event"]["channel"] == "Security"
    assert doc["event"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert doc["host"]["name"] == "hosta"
    assert "4624" in doc["search_text"]


def test_security_4663_normalizes_object_access_fields() -> None:
    doc = _evtx_doc(
        {
            "EventId": "4663",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security",
            "Computer": "HOSTA",
            "Payload": {
                "ObjectName": "C:\\Users\\alice\\Documents\\secret.txt",
                "ObjectType": "File",
                "ObjectServer": "Security",
                "AccessMask": "0x2",
                "Accesses": "WriteData (or AddFile)",
                "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                "SubjectUserName": "alice",
                "SubjectDomainName": "EXAMPLECORP",
                "SubjectUserSid": "S-1-5-21-1-2-3-1001",
                "SubjectLogonId": "0x123",
            },
        }
    )

    assert doc["windows"]["event_id"] == 4663
    assert doc["event"]["type"] == "object_access"
    assert doc["object"]["name"] == "C:\\Users\\alice\\Documents\\secret.txt"
    assert doc["file"]["path"] == "C:\\Users\\alice\\Documents\\secret.txt"
    assert doc["process"]["name"] == "notepad.exe"
    assert doc["user"]["name"] == "alice"
    assert doc["subject"]["user"]["sid"] == "S-1-5-21-1-2-3-1001"
    assert doc["access"]["mask"] == "0x2"
    assert doc["access"]["list"] == ["WriteData (or AddFile)"]
    assert "secret.txt" in doc["search_text"]


def test_sysmon_event_id_1_normalizes_process_parent_and_commandline() -> None:
    doc = _evtx_doc(
        {
            "TimeCreatedUtc": "2026-05-28T10:00:00Z",
            "EventId": "1",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "HOSTA",
            "EventRecordId": "42",
            "Payload": {
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe /all",
                "ProcessId": "4242",
                "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
                "CurrentDirectory": "C:\\Windows\\System32",
                "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;MD5=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe /c whoami.exe /all",
                "ParentProcessId": "4000",
                "ParentProcessGuid": "{22222222-2222-2222-2222-222222222222}",
                "User": "EXAMPLECORP\\alice",
                "IntegrityLevel": "High",
            },
        }
    )

    assert doc["event"]["type"] == "sysmon_process_created"
    assert doc["process"]["name"] == "whoami.exe"
    assert doc["process"]["executable"] == "C:\\Windows\\System32\\whoami.exe"
    assert doc["process"]["command_line"] == "whoami.exe /all"
    assert doc["process"]["parent"]["name"] == "cmd.exe"
    assert doc["process"]["parent"]["command_line"] == "cmd.exe /c whoami.exe /all"
    assert doc["parent"]["process"]["executable"] == "C:\\Windows\\System32\\cmd.exe"
    assert doc["process"]["hash"]["sha256"] == "a" * 64
    assert doc["user"]["name"] == "alice"
    assert doc["user"]["domain"] == "EXAMPLECORP"
    assert doc["windows"]["event_data"]["Image"].endswith("whoami.exe")
    assert doc["winlog"]["event_data"]["CommandLine"] == "whoami.exe /all"


def test_sysmon_event_id_3_normalizes_network_fields() -> None:
    doc = _evtx_doc(
        {
            "EventId": "3",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "HOSTA",
            "Payload": {
                "Image": "C:\\Windows\\System32\\curl.exe",
                "ProcessId": "5050",
                "SourceIp": "10.0.0.10",
                "SourcePort": "49152",
                "DestinationIp": "203.0.113.5",
                "DestinationPort": "443",
                "DestinationHostname": "example.test",
                "Protocol": "tcp",
                "Initiated": "true",
            },
        }
    )

    assert doc["event"]["type"] == "sysmon_network_connection"
    assert doc["source"]["ip"] == "10.0.0.10"
    assert doc["source"]["port"] == 49152
    assert doc["destination"]["ip"] == "203.0.113.5"
    assert doc["destination"]["port"] == 443
    assert doc["destination"]["hostname"] == "example.test"
    assert doc["network"]["protocol"] == "tcp"
    assert doc["network"]["direction"] == "outbound"


def test_process_graph_attaches_sysmon_activity_edges() -> None:
    events = [
        {
            "id": "evt-proc",
            "event_id": "evt-proc",
            "@timestamp": "2024-03-22T11:20:00Z",
            "artifact": {"type": "windows_event", "parser": "sysmon_evtx"},
            "event": {"type": "sysmon_process_created"},
            "host": {"name": "hosta"},
            "process": {"entity_id": "{PROC}", "pid": 2222, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell -ep bypass .\\maintenance.ps1"},
        },
        {
            "id": "evt-dns",
            "event_id": "evt-dns",
            "@timestamp": "2024-03-22T11:20:05Z",
            "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
            "event": {"type": "sysmon_dns_query", "message": "Sysmon DNS query: example-control.test"},
            "host": {"name": "hosta"},
            "process": {"entity_id": "{PROC}", "pid": 2222, "name": "powershell.exe"},
            "dns": {"question": {"name": "example-control.test"}, "query": "example-control.test"},
        },
    ]

    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")

    assert any(node["id"] == "{PROC}" for node in graph["nodes"])
    assert any(node["id"] == "activity:evt-dns" and "dns_activity" in node["badges"] for node in graph["nodes"])
    assert any(edge["source"] == "{PROC}" and edge["target"] == "activity:evt-dns" and edge["type"] == "activity" for edge in graph["edges"])


def test_sysmon_file_dns_and_registry_fields_normalize() -> None:
    file_doc = _evtx_doc(
        {
            "EventId": "11",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {
                "TargetFilename": "C:\\Users\\alice\\Downloads\\payload.exe",
                "Image": "C:\\Windows\\explorer.exe",
                "CreationUtcTime": "2024-03-22 11:18:12.321",
            },
        }
    )
    dns_doc = _evtx_doc(
        {
            "EventId": "22",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {"QueryName": "example.test", "QueryResults": "203.0.113.5;203.0.113.6", "Image": "C:\\Windows\\System32\\curl.exe"},
        }
    )
    reg_doc = _evtx_doc(
        {
            "EventId": "13",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {"TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "Details": "C:\\Temp\\updater.exe", "EventType": "SetValue", "Image": "C:\\Windows\\reg.exe"},
        }
    )

    assert file_doc["event"]["type"] == "sysmon_file_created"
    assert file_doc["file"]["path"] == "C:\\Users\\alice\\Downloads\\payload.exe"
    assert file_doc["file"]["created"] == "2024-03-22T11:18:12.321000+00:00"
    assert file_doc["target"]["filename"].endswith("payload.exe")
    assert dns_doc["event"]["type"] == "sysmon_dns_query"
    assert dns_doc["dns"]["question"]["name"] == "example.test"
    assert dns_doc["dns"]["answers"] == ["203.0.113.5", "203.0.113.6"]
    assert reg_doc["event"]["type"] == "sysmon_registry_value_set"
    assert reg_doc["registry"]["path"].endswith("\\Updater")
    assert reg_doc["registry"]["data"] == "C:\\Temp\\updater.exe"


def test_sigma_case_profile_sees_rich_sysmon_fields() -> None:
    process_doc = _evtx_doc(
        {
            "EventId": "1",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe /all",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe /c whoami.exe /all",
            },
        }
    )
    network_doc = _evtx_doc(
        {
            "EventId": "3",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {"DestinationIp": "203.0.113.5", "DestinationPort": "443", "SourceIp": "10.0.0.10", "SourcePort": "49152"},
        }
    )
    dns_doc = _evtx_doc(
        {
            "EventId": "22",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Payload": {"QueryName": "example.test"},
        }
    )

    profile = build_sigma_case_profile([process_doc, network_doc, dns_doc])

    assert "process.executable" in profile["available_fields"]
    assert "process.parent.command_line" in profile["available_fields"]
    assert "destination.ip" in profile["available_fields"]
    assert "source.ip" in profile["available_fields"]
    assert "dns.question.name" in profile["available_fields"]
    assert "Image" in profile["field_aliases"]
    assert "DestinationIp" in profile["field_aliases"]
    assert "QueryName" in profile["field_aliases"]


def test_evtxecmd_csv_sysmon_rows_get_rich_fields(tmp_path: Path) -> None:
    fixture = tmp_path / "EvtxECmd_Sysmon.csv"
    fixture.write_text(
        "TimeCreatedUtc,EventId,Provider,Channel,Computer,EventRecordId,Image,CommandLine,ParentImage,ParentCommandLine,ProcessId,ProcessGuid,ParentProcessId,ParentProcessGuid,User,DestinationIp,DestinationPort,DestinationHostname,SourceIp,SourcePort,Protocol,Initiated,TargetFilename,QueryName,QueryResults\n"
        '2026-05-28T10:00:00Z,1,Microsoft-Windows-Sysmon,Microsoft-Windows-Sysmon/Operational,HOSTA,1,C:\\Windows\\System32\\whoami.exe,whoami.exe /all,C:\\Windows\\System32\\cmd.exe,"cmd.exe /c whoami.exe /all",4242,{11111111-1111-1111-1111-111111111111},4000,{22222222-2222-2222-2222-222222222222},EXAMPLECORP\\alice,,,,,,,,,,\n'
        "2026-05-28T10:01:00Z,3,Microsoft-Windows-Sysmon,Microsoft-Windows-Sysmon/Operational,HOSTA,2,C:\\Windows\\System32\\curl.exe,,,,5050,{33333333-3333-3333-3333-333333333333},,,EXAMPLECORP\\alice,203.0.113.5,443,example.test,10.0.0.10,49152,tcp,true,,,\n"
        "2026-05-28T10:02:00Z,22,Microsoft-Windows-Sysmon,Microsoft-Windows-Sysmon/Operational,HOSTA,3,C:\\Windows\\System32\\curl.exe,,,,5050,{33333333-3333-3333-3333-333333333333},,,EXAMPLECORP\\alice,,,,,,,,,example.test,203.0.113.5;203.0.113.6\n",
        encoding="utf-8",
    )

    docs = parse_evtxecmd_file(
        "case-1",
        "evidence-1",
        "artifact-1",
        fixture,
        {
            "artifact_type": "windows_event",
            "parser": EVTXECMD_BACKEND_CSV,
            "source_path": "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
            "ingest_run_id": "run-1",
        },
    )

    process_doc, network_doc, dns_doc = docs
    assert process_doc["event"]["type"] == "sysmon_process_created"
    assert process_doc["event"]["provider"] == "Microsoft-Windows-Sysmon"
    assert process_doc["event"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert process_doc["artifact"]["type"] == "windows_event"
    assert process_doc["process"]["executable"] == "C:\\Windows\\System32\\whoami.exe"
    assert process_doc["process"]["parent"]["command_line"] == "cmd.exe /c whoami.exe /all"
    assert network_doc["event"]["type"] == "sysmon_network_connection"
    assert network_doc["destination"]["ip"] == "203.0.113.5"
    assert network_doc["destination"]["hostname"] == "example.test"
    assert network_doc["source"]["ip"] == "10.0.0.10"
    assert dns_doc["event"]["type"] == "sysmon_dns_query"
    assert dns_doc["dns"]["question"]["name"] == "example.test"
    assert "example.test" in dns_doc["search_text"]
