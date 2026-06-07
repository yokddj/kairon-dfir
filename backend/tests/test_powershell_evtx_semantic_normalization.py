from app.ingest.powershell.semantic_evtx import normalize_powershell_evtx_semantics, parse_context_info


def _powershell_event(event_id: int, **overrides):
    event = {
        "id": f"ps-{event_id}",
        "@timestamp": "2026-06-06T18:23:56Z",
        "artifact": {"type": "powershell", "parser": "powershell_evtx"},
        "event": {"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"},
        "host": {"name": "KAIRON-LAB01"},
        "user": {"name": "-"},
        "windows": {"event_id": event_id, "event_data": {}},
        "source_file": "/app/data/evidence/staging/uploads/PowerShell_Operational.evtx",
    }
    event.update(overrides)
    return event


def test_rendered_message_blob_is_not_user_and_raw_is_preserved() -> None:
    blob = "Level = Informational, HostName = ConsoleHost, HostVersion = 5.1, EngineVersion = 5.1"
    event = _powershell_event(
        400,
        user={"name": blob},
        windows={"event_id": 400, "event_data": {"Message": blob}},
        raw={"Message": blob},
    )

    normalized = normalize_powershell_evtx_semantics(event)

    assert normalized["display_user"] == "-"
    assert normalized["powershell_event_normalized"]["user_confidence"] == "unknown"
    assert normalized["powershell_event_normalized"]["raw_payload"]["event_data"]["Message"] == blob


def test_contextinfo_extracts_user_command_script_path_without_using_blob_as_entity() -> None:
    context_info = (
        "UserId=KAIRON-LAB01\\analyst\n"
        "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
        "-NoProfile -ExecutionPolicy Bypass -File C:\\Users\\analyst\\Downloads\\a.ps1\n"
        "RunspaceId=11111111-2222-3333-4444-555555555555\n"
        "PipelineId=7"
    )
    event = _powershell_event(
        800,
        windows={"event_id": 800, "event_data": {"ContextInfo": context_info}},
        raw={"ContextInfo": context_info},
    )

    normalized = normalize_powershell_evtx_semantics(event)
    model = normalized["powershell_event_normalized"]

    assert model["event_type"] == "pipeline_execution"
    assert model["user"] == "KAIRON-LAB01\\analyst"
    assert model["script_path"] == "C:\\Users\\analyst\\Downloads\\a.ps1"
    assert "powershell.exe" in model["command"]
    assert model["key_entity"] in {model["script_path"], model["process_image"]}
    assert model["key_entity"] != context_info
    assert model["runspace_id"] == "11111111-2222-3333-4444-555555555555"
    assert model["pipeline_id"] == "7"


def test_script_block_event_uses_script_block_text_and_identity_fields() -> None:
    script = "function Invoke-KaironLab { Write-Host 'KAIRON-LAB01-MARKER' }; Invoke-KaironLab"
    event = _powershell_event(
        4104,
        windows={"event_id": 4104, "event_data": {"ScriptBlockText": script, "User": "KAIRON-LAB01\\analyst"}},
    )

    normalized = normalize_powershell_evtx_semantics(event)
    model = normalized["powershell_event_normalized"]

    assert model["event_type"] == "script_block"
    assert model["user"] == "KAIRON-LAB01\\analyst"
    assert model["command"] == script
    assert model["script_block_text"] == script
    assert model["key_entity"] != "0x0"
    assert "Invoke-KaironLab" in model["key_entity"]


def test_module_logging_placeholder_falls_back_to_semantic_event_type() -> None:
    event = _powershell_event(
        4103,
        key_entity="0x0",
        windows={"event_id": 4103, "event_data": {"Payload": "0x0"}},
    )

    normalized = normalize_powershell_evtx_semantics(event)

    assert normalized["powershell_event_normalized"]["event_type"] == "module_logging"
    assert normalized["display_key_entity"] == "module_logging"
    assert normalized["display_key_entity"] != "0x0"


def test_pipeline_event_with_hostapplication_extracts_process_and_command() -> None:
    host_application = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command whoami"
    event = _powershell_event(
        800,
        windows={"event_id": 800, "event_data": {"HostApplication": host_application}},
    )

    normalized = normalize_powershell_evtx_semantics(event)
    model = normalized["powershell_event_normalized"]

    assert model["command"] == host_application
    assert model["process_image"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert model["key_entity"] in {model["process_image"], "powershell.exe"}
    assert "\n" not in model["key_entity"]


def test_internal_staging_path_is_not_selected_as_key_entity() -> None:
    event = _powershell_event(
        600,
        source_file="/app/data/evidence/staging/uploads/C/Windows/System32/WindowsPowerShell/v1.0/PowerShell.evtx",
        windows={"event_id": 600, "event_data": {"ProviderName": "Registry"}},
    )

    normalized = normalize_powershell_evtx_semantics(event)

    assert "/app/data/evidence" not in normalized["display_key_entity"]
    assert normalized["display_key_entity"] in {"Microsoft-Windows-PowerShell", "provider_lifecycle", "Registry"}


def test_contextinfo_parser_uses_technical_keys_only() -> None:
    fields = parse_context_info(
        "UserId: analyst\n"
        "HostApplication=powershell.exe -File C:\\Users\\analyst\\a.ps1\n"
        "Decorative Label = this should not be exported\n"
        "PipelineId\t9"
    )

    assert fields["UserId"] == "analyst"
    assert fields["HostApplication"].startswith("powershell.exe")
    assert fields["PipelineId"] == "9"
    assert "Decorative Label" not in fields
