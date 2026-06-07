from app.ingest.powershell.entity_normalization import normalize_powershell_entities


def _ps_doc(payload: str, *, key_entity: str | None = None, event_type: str = "pipeline_execution") -> dict:
    return {
        "artifact": {"type": "powershell", "parser": "powershell_evtx"},
        "event": {"type": event_type, "message": payload},
        "user": {"name": None},
        "process": {"name": "powershell.exe", "command_line": payload},
        "powershell": {"command": payload, "command_preview": payload[:120]},
        "windows": {
            "event_id": 800,
            "event_data": {
                "payload_columns": {
                    "Payload": payload,
                    "PayloadData1": "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                }
            },
        },
        "raw": {"Payload": payload},
        "key_entity": key_entity,
    }


def test_powershell_context_userid_extracts_user_and_command() -> None:
    payload = (
        '{"EventData":{"Data":"UserId=KAIRON-LAB01\\\\analyst\\n'
        'HostApplication=C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\n'
        'ScriptName=C:\\\\Users\\\\analyst\\\\Downloads\\\\03_lab.ps1\\n'
        'CommandLine=Write-Host \\"hello\\"\\n","Binary":""}}'
    )
    doc = normalize_powershell_entities(_ps_doc(payload))

    assert doc["user"]["name"] == "KAIRON-LAB01\\analyst"
    assert doc["user"]["confidence"] == "context"
    assert doc["powershell"]["command"] == 'Write-Host "hello"'
    assert doc["key_entity"] == "C:\\Users\\analyst\\Downloads\\03_lab.ps1"
    assert payload in doc["powershell"]["raw_payload"]


def test_powershell_connected_user_extracts_user() -> None:
    payload = "Connected User = KAIRON-LAB01\\analyst\nHostApplication=powershell.exe\nCommandLine=Get-Process"
    doc = normalize_powershell_entities(_ps_doc(payload))

    assert doc["user"]["name"] == "KAIRON-LAB01\\analyst"
    assert doc["powershell"]["command"] == "Get-Process"


def test_powershell_path_infers_user_only_when_explicit_missing() -> None:
    payload = "HostApplication=powershell.exe\nScriptName=C:\\Users\\analyst\\Downloads\\run.ps1\nCommandLine=Write-Host demo"
    doc = normalize_powershell_entities(_ps_doc(payload))

    assert doc["user"]["name"] == "analyst"
    assert doc["user"]["confidence"] == "path_inferred"


def test_powershell_raw_payload_never_assigned_to_user() -> None:
    payload = '{"EventData":{"Data":"HostApplication=powershell.exe\\nCommandLine=Get-Process","Binary":""}}'
    doc = normalize_powershell_entities(_ps_doc(payload))

    assert doc["user"]["name"] is None
    assert "EventData" not in str(doc["user"])
    assert payload in doc["powershell"]["raw_payload"]


def test_powershell_key_entity_placeholder_replaced_by_fallback() -> None:
    payload = "HostApplication=powershell.exe\nCommandLine=Get-ChildItem C:\\Users\\analyst\\Documents"
    doc = normalize_powershell_entities(_ps_doc(payload, key_entity="0x0"))

    assert doc["key_entity"] == "Get-ChildItem C:\\Users\\analyst\\Documents"
    assert doc["key_entity"] != "0x0"


def test_powershell_module_logging_uses_script_or_command_fallback() -> None:
    payload = (
        "UserId=KAIRON-LAB01\\analyst\n"
        "ScriptName=C:\\Users\\analyst\\Downloads\\module-test.ps1\n"
        "CommandLine=Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    doc = normalize_powershell_entities(_ps_doc(payload, key_entity="0x0", event_type="module_logging"))

    assert doc["key_entity"] == "C:\\Users\\analyst\\Downloads\\module-test.ps1"
    assert doc["key_entity_type"] == "script_path"


def test_powershell_empty_payload_labels_do_not_become_entities() -> None:
    payload = (
        "UserId=KAIRON-LAB01\\analyst\n"
        "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -File C:\\Users\\analyst\\Documents\\KaironLab01\\run_key_payload.ps1\n"
        "EngineVersion=5.1.22621.6133\n"
        "RunspaceId=50a25ae3-6bb5-48a2-bf0a-3dacfc5f81d9\n"
        "PipelineId=\n"
        "CommandName=\n"
        "ScriptName=\n"
        "CommandPath=\n"
        "CommandLine=, CommandInvocation(run_key_payload.ps1): \"run_key_payload.ps1\""
    )
    doc = normalize_powershell_entities(_ps_doc(payload, key_entity="0x0", event_type="pipeline_execution"))

    assert doc["powershell"]["command"] == "run_key_payload.ps1"
    assert "script_path" not in doc["powershell"]
    assert "pipeline_id" not in doc["powershell"]
    assert doc["key_entity"] == "run_key_payload.ps1"


def test_powershell_short_eventdata_fragment_does_not_become_key_entity() -> None:
    payload = 'PowerShell command observed: {"EventData"":{""Data"":[{""@Name"":""ScriptBlockId""'
    doc = normalize_powershell_entities(_ps_doc(payload, key_entity=payload, event_type="command_observed"))

    assert "EventData" not in doc["key_entity"]
    assert "EventData" not in doc["powershell"]["command"]
    assert doc["key_entity"].endswith("\\powershell.exe")
