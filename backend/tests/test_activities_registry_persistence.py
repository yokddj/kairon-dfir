"""Regression coverage for registry_persistence_value_observed classification.

app.ingest.raw_parsers.registry_persistence_summary (the internal registry
hive parser that Artifact Explorer's "Startup & Persistence" view relies on
via the registry_autoruns source) emits events tagged
event.type=="registry_persistence_value_observed". Before this fix,
event_to_activity() had no branch for that event type, so it fell through
to the generic "suspicious_event" catch-all and lost all structure
(mechanism, key path, category) once it reached SemiAutoAnalysis --
meaning Run Keys/Winlogon/IFEO/AppInit never showed registry-hive-sourced
entries, only Autoruns-sourced ones.
"""
from app.analysis.activities import event_to_activity, section_activities


def _registry_event(*, key_path: str, category: str, value_name: str, mechanism_label: str, value_data: str = "C:\\malware.exe") -> dict:
    return {
        "id": f"evt-{value_name}",
        "event_id": f"evt-{value_name}",
        "@timestamp": "2026-05-03T10:45:00+00:00",
        "event": {"category": "persistence", "type": "registry_persistence_value_observed", "severity": "medium", "message": f"{mechanism_label}: {value_name} -> {value_data}"},
        "host": {"name": "ws01"},
        "user": {"name": "mshunter"},
        "registry": {"key_path": key_path, "value_name": value_name, "category": category, "persistence_mechanism": mechanism_label},
        "persistence": {"name": value_name, "category": category, "mechanism": mechanism_label, "path": value_data, "command": value_data, "user": "mshunter"},
        "tags": ["registry", "persistence", category],
        "suspicious_reasons": [],
    }


def test_registry_autorun_value_lands_in_run_key_persistence_section():
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", category="autorun", value_name="Updater", mechanism_label="HKLM Run")
    activities = event_to_activity(event)
    assert any(item.activity_type == "autorun_entry" for item in activities)
    sections = section_activities(activities)
    assert len(sections["run_key_persistence"]) == 1
    assert sections["run_key_persistence"][0]["key_fields"]["location"] == r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"


def test_registry_runonce_value_is_distinguished_from_run_key():
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", category="autorun", value_name="Setup", mechanism_label="HKLM RunOnce")
    activities = event_to_activity(event)
    sections = section_activities(activities)
    assert sections["run_key_persistence"][0]["key_fields"]["mechanism"] == "runonce_key"


def test_registry_winlogon_userinit_lands_in_winlogon_persistence_section():
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", category="winlogon", value_name="Userinit", mechanism_label="Winlogon")
    activities = event_to_activity(event)
    sections = section_activities(activities)
    assert len(sections["winlogon_persistence"]) == 1
    assert sections["winlogon_persistence"][0]["key_fields"]["mechanism"] == "winlogon_userinit"


def test_registry_ifeo_value_lands_in_ifeo_debugger_persistence_section():
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe", category="ifeo", value_name="Debugger", mechanism_label="IFEO Debugger")
    activities = event_to_activity(event)
    sections = section_activities(activities)
    assert len(sections["ifeo_debugger_persistence"]) == 1


def test_registry_appinit_value_lands_in_appinit_appcert_persistence_section():
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows", category="appinit", value_name="AppInit_DLLs", mechanism_label="AppInit / Windows Load")
    activities = event_to_activity(event)
    sections = section_activities(activities)
    assert len(sections["appinit_appcert_persistence"]) == 1


def test_registry_value_always_lands_in_generic_autoruns_persistence_bucket():
    # Even categories without a dedicated tab (e.g. active_setup, rdp,
    # defender_exclusion) must still be visible somewhere, not silently
    # dropped into an unstructured catch-all.
    event = _registry_event(key_path=r"HKLM\Software\Microsoft\Active Setup\Installed Components\{guid}", category="active_setup", value_name="StubPath", mechanism_label="HKLM Active Setup")
    activities = event_to_activity(event)
    assert not any(item.activity_type == "suspicious_event" for item in activities)
    sections = section_activities(activities)
    assert len(sections["autoruns_persistence"]) == 1
