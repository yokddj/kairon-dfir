from __future__ import annotations

from app.services import startup_persistence


class _Db:
    pass


def _event(artifact_type: str, **fields):
    return {
        "id": fields.get("id", f"{artifact_type}-1"),
        "@timestamp": fields.get("timestamp", "2024-03-22T11:00:00Z"),
        "evidence_id": "ev-1",
        "host": {"name": fields.get("host", "HOSTA")},
        "artifact": {"type": artifact_type},
        "event": {"message": fields.get("message", "")},
        **{key: value for key, value in fields.items() if key not in {"id", "timestamp", "host", "message"}},
    }


def test_scheduled_task_normalized_and_risk_scored(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        if "scheduled_task" in (params.get("artifact_type") or []):
            return 1, [_event("scheduled_task", task={"name": "OneDriveUpdateTask", "command": r"powershell.exe -ep bypass C:\Users\Public\maintenance.ps1", "enabled": True})], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"page_size": 50})

    item = result["items"][0]
    assert item["type"] == "scheduled_task"
    assert item["enabled"] is True
    assert item["risk_score"] >= 70
    assert "suspicious_powershell_flags" in item["risk_reasons"]
    assert "script_or_suspicious_extension" in item["risk_reasons"]


def test_service_normalized_and_benign_system_item_low_risk(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        if "service" in (params.get("artifact_type") or []):
            return 1, [_event("service", service={"name": "Spooler", "image_path": r"C:\Windows\System32\spoolsv.exe", "start_type": "auto"})], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"page_size": 50})

    item = result["items"][0]
    assert item["type"] == "service"
    assert item["name"] == "Spooler"
    assert item["risk_score"] <= 20
    assert "common_system_location" in item["risk_reasons"]


def test_run_key_registry_and_startup_folder_lnk_normalized(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        artifact_types = params.get("artifact_type") or []
        q = str(params.get("q") or "")
        if "registry" in artifact_types and "Run" in q:
            return 1, [_event("registry", persistence={"name": "Updater", "command": r"C:\Users\Public\updater.cmd", "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"})], [], {}
        if "lnk" in artifact_types and q == "Startup":
            return 1, [_event("lnk", file={"name": "Updater.lnk", "path": r"C:\Users\usera\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Updater.lnk"})], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"page_size": 50, "source": ["registry_autoruns", "startup_folders"]})
    types = {item["type"] for item in result["items"]}

    assert "run_key" in types
    assert "startup_folder" in types


def test_default_startup_persistence_includes_registry_hive_source(monkeypatch):
    seen_sources = []

    def fake_search(_case_id, params, **_kwargs):
        artifact_types = params.get("artifact_type") or []
        if "registry_persistence" in artifact_types:
            seen_sources.append("registry_autoruns")
            return 1, [
                _event(
                    "registry_persistence",
                    registry={
                        "category": "autorun",
                        "value_name": "KaironLab01Run",
                        "value_data": r"powershell.exe -File C:\Users\analyst\Documents\KaironLab01\run_key_payload.ps1",
                        "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "last_write": "2024-03-22T11:00:00Z",
                    },
                )
            ], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"page_size": 50})

    assert "registry_autoruns" in seen_sources
    assert result["items"][0]["type"] == "run_key"
    assert result["items"][0]["source_artifact"] == "registry_hive"
    assert result["items"][0]["name"] == "KaironLab01Run"


def test_filters_by_host_type_and_risk(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        return 2, [
            _event("service", id="svc-1", host="HOSTA", service={"name": "PSEXESVC", "image_path": r"C:\Users\Public\PSEXESVC.exe"}),
            _event("scheduled_task", id="task-1", host="HOSTB", task={"name": "MicrosoftTask", "command": r"C:\Windows\System32\cmd.exe"}),
        ], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"type": ["service"], "risk_min": 40})

    assert len(result["items"]) == 1
    assert result["items"][0]["type"] == "service"
    assert result["summary"]["suspicious"] == 1


def test_report_markdown_includes_suspicious_items():
    markdown = startup_persistence.render_startup_persistence_markdown(
        [
            {
                "host": "HOSTA",
                "type": "scheduled_task",
                "name": "OneDriveUpdateTask",
                "risk_score": 85,
                "command_or_target": "powershell.exe -ep bypass maintenance.ps1",
                "source_artifact": "scheduled_tasks",
            }
        ]
    )

    assert "OneDriveUpdateTask" in markdown
    assert "scheduled_task" in markdown
