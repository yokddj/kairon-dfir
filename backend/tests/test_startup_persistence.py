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


def _realistic_row(artifact_type: str, *, host: str = "HOSTA", evidence_id: str = "ev-1", **doc_fields) -> dict:
    """search_events_v2's actual row shape: a display-summary envelope
    (id/host/timestamp/artifact_type/...) with the real normalized document
    -- task/service/registry/persistence/event/evidence_id/... -- nested one
    level down under "raw". Mirrors real production data, unlike _event()
    above which puts fields at the top level (the shape _normalize_event_row
    used to -- incorrectly -- assume).
    """
    return {
        "id": doc_fields.pop("id", f"{artifact_type}-1"),
        "host": host,
        "artifact_type": artifact_type,
        "timestamp": doc_fields.pop("timestamp", "2024-03-22T11:00:00Z"),
        "raw": {
            "evidence_id": evidence_id,
            "artifact": {"type": artifact_type},
            "event": {"message": doc_fields.pop("message", "")},
            **doc_fields,
        },
    }


def test_field_extraction_reads_the_real_search_events_v2_row_shape(monkeypatch):
    # Regression test: _normalize_event_row used to read task/service/
    # persistence/registry/etc. from the row's top level, but
    # search_events_v2 actually nests the real document one level down
    # under row["raw"] -- so every field but artifact_type/host/timestamp
    # (which happen to also exist at the top level) came back "-" against
    # real data, no matter which source produced the item.
    def fake_search(_case_id, params, **_kwargs):
        if "service" in (params.get("artifact_type") or []):
            return 1, [_realistic_row("service", service={"name": "PSEXESVC", "image_path": r"C:\Windows\PSEXESVC.exe", "start_type": "auto"}, user={"name": "SYSTEM"})], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    result = startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"source": ["services"], "page_size": 50})

    item = result["items"][0]
    assert item["name"] == "PSEXESVC"
    assert item["command_or_target"] == r"C:\Windows\PSEXESVC.exe"
    assert item["user"] == "SYSTEM"
    assert item["evidence_id"] == "ev-1"


def test_host_filter_is_passed_as_a_single_string_not_a_list(monkeypatch):
    # search_events_v2's "host" param (EVENT_EXACT_FILTERS) is str(value).strip()
    # against a single value -- passing the whole list made str(['ws01']) become
    # the literal text "['ws01']", which matched nothing, so any host-scoped
    # Persistence view call silently returned zero results regardless of host
    # or which source actually had data for that host.
    seen_host_params = []

    def fake_search(_case_id, params, **_kwargs):
        seen_host_params.append(params.get("host"))
        return 0, [], [], {}

    monkeypatch.setattr(startup_persistence, "search_events_v2", fake_search)
    monkeypatch.setattr(startup_persistence, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    startup_persistence.list_startup_persistence_items(_Db(), "case-1", {"host": ["ws01"], "page_size": 50})

    assert seen_host_params
    for value in seen_host_params:
        assert value == "ws01"
        assert not isinstance(value, list)


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
