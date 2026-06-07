from app.ingest.normalization.field_quality import (
    choose_best_key_entity,
    clean_key_entity,
    clean_user,
    normalize_event_fields,
)


def test_clean_user_rejects_structured_rendered_message_blob() -> None:
    value = "Level = Informational, HostName = ConsoleHost, HostVersion = 5.1.22621.6133, EngineVersion = 5.1"

    result = clean_user(value)

    assert result.value == "-"
    assert result.quality == "raw_payload_rejected"


def test_clean_key_entity_rejects_0x0_and_falls_back_to_event_type() -> None:
    result = choose_best_key_entity([("0x0", "key_entity")], {"event_type": "module_logging", "artifact_type": "powershell"})

    assert result.value == "module_logging"
    assert result.quality == "fallback"
    assert result.confidence == "low"


def test_clean_key_entity_extracts_script_path_from_contextinfo_payload() -> None:
    payload = (
        "ContextInfo: UserId=KAIRON-LAB01\\analyst\n"
        "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        "ScriptName=C:\\Users\\analyst\\Downloads\\run.ps1\n"
        "CommandLine=Write-Host demo"
    )

    result = clean_key_entity(payload, artifact_type="powershell", event_type="pipeline_execution")

    assert result.value == "C:\\Users\\analyst\\Downloads\\run.ps1"
    assert result.quality == "fallback"


def test_clean_user_extracts_user_from_context_payload() -> None:
    payload = "ContextInfo: UserId=KAIRON-LAB01\\analyst\nHostName=ConsoleHost\nCommandLine=whoami"

    result = clean_user("", raw_fields={"raw": {"Payload": payload}})

    assert result.value == "KAIRON-LAB01\\analyst"
    assert result.quality == "fallback"


def test_normalize_event_fields_preserves_raw_payload_and_cleans_visible_fields() -> None:
    payload = "Level=Informational\nHostName=ConsoleHost\nUserId=KAIRON-LAB01\\analyst\nHostApplication=powershell.exe"
    document = {
        "artifact": {"type": "powershell"},
        "event": {"type": "module_logging", "message": payload},
        "user": {"name": payload},
        "key_entity": "0x0",
        "windows": {"event_data": {"payload_columns": {"Payload": payload}}},
        "process": {"name": "powershell.exe"},
    }

    normalized = normalize_event_fields(document)

    assert normalized["user"]["name"] == "KAIRON-LAB01\\analyst"
    assert normalized["key_entity"] == "powershell.exe"
    assert "HostName" not in normalized["user"]["name"]
    assert normalized["normalized_raw_payload"] == payload
    assert any(warning.startswith("user_") for warning in normalized["field_quality_warnings"])


def test_non_powershell_file_path_key_entity_remains_valid() -> None:
    document = {
        "artifact": {"type": "mft"},
        "event": {"type": "file_observed"},
        "user": {"name": None},
        "key_entity": "C:\\Users\\analyst\\Documents\\report.docx",
        "file": {"path": "C:\\Users\\analyst\\Documents\\report.docx"},
    }

    normalized = normalize_event_fields(document)

    assert normalized["key_entity"] == "C:\\Users\\analyst\\Documents\\report.docx"
