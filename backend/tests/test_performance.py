from types import SimpleNamespace

import pytest

from app.core import performance as performance_module
from app.core.app_settings import PERFORMANCE_PROFILE_KEY, set_setting
from app.core.performance import apply_recommended_profile, build_resource_warnings, describe_ingest_parallelism, manual_restart_instructions, performance_resources, performance_state, save_performance_profile
from app.models.app_setting import AppSetting
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.debug_export import _build_ingest_summary


class FakeQuery:
    def __init__(self, session):
        self.session = session

    def all(self):
        return list(self.session.items.values())

    def delete(self):
        self.session.items.clear()


class FakeSession:
    def __init__(self):
        self.items: dict[str, AppSetting] = {}

    def get(self, model, key):
        if model is AppSetting:
            return self.items.get(key)
        return None

    def add(self, value):
        if isinstance(value, AppSetting):
            self.items[value.key] = value

    def commit(self):
        return None

    def refresh(self, _value):
        return None

    def query(self, model):
        assert model is AppSetting
        return FakeQuery(self)


def _patch_system(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        performance_module,
        "system_snapshot",
        lambda: {
            "cpu_count": 8,
            "cpu_count_host": 8,
            "cpu_count_container": 8,
            "cpu_percent": 20.0,
            "memory_total_bytes": 16 * 1024 * 1024 * 1024,
            "memory_available_bytes": 10 * 1024 * 1024 * 1024,
            "memory_container_limit_bytes": 12 * 1024 * 1024 * 1024,
            "memory_used_percent": 35.0,
            "disk_total_bytes": 500 * 1024 * 1024 * 1024,
            "disk_free_bytes": 300 * 1024 * 1024 * 1024,
            "disk_used_percent": 40.0,
            "storage_used_bytes": 5 * 1024 * 1024 * 1024,
            "queues": {},
            "services": {
                "backend": {"status": "ok"},
                "worker": {"status": "ok", "active": 2, "known": ["worker-1", "worker-2"], "queues": {"worker-1": ["dfir-ingest"], "worker-2": ["dfir-rules"]}},
                "frontend": {"status": "ok"},
                "opensearch": {"status": "ok", "cluster_status": "green", "heap_used_percent": 35, "disk_watermark": {"high": "90%"}},
            },
            "opensearch_status": "ok",
        },
    )
    monkeypatch.setattr(
        performance_module,
        "storage_capabilities",
        lambda: {
            "allow_host_path_import": True,
            "allowed_roots": ["/mnt/evidence", "/data/evidence"],
            "max_upload_size": 2147483648,
            "supports_mounted_path": True,
            "can_edit_deployment_settings": False,
            "restart_enabled": False,
            "deployment_setting_scope": "backend+worker restart",
            "restart_commands": ["docker compose up -d --build backend worker"],
            "enable_instructions": {
                "env": {
                    "DFIR_ALLOW_HOST_PATH_IMPORT": "true",
                    "DFIR_ALLOWED_EVIDENCE_ROOTS": "/mnt/evidence,/data/evidence",
                },
                "commands": ["docker compose up -d --build backend worker"],
            },
            "allowed_root_details": [
                {"path": "/mnt/evidence", "label": "Recommended mount point for large evidence", "example_path": "/mnt/evidence/case001"},
                {"path": "/data/evidence", "label": "Alternative data volume", "example_path": "/data/evidence/case001"},
            ],
        },
    )


def test_get_performance_defaults(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    state = performance_state(db)

    assert state["profile"] == "balanced"
    assert "ingest_batch_size" in state["effective_settings"]
    assert state["system"]["cpu_count"] == 8
    assert state["system"]["allowed_roots"] == ["/mnt/evidence", "/data/evidence"]
    assert state["evidence_storage"]["allow_host_path_import"] is True
    assert state["evidence_storage"]["allowed_root_details"][0]["path"] == "/mnt/evidence"
    assert state["settings"][0]["scope"] == "runtime"
    assert state["deployment"]["restart_enabled"] is False
    assert state["resources"]["cpu_count_container"] == 8
    assert state["queue_architecture"]["recommended_workers"][0] == "worker-ingest"


def test_set_profile_max(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    result = save_performance_profile(db, "max", confirm_max=True)

    assert result["saved"] is True
    assert db.items[PERFORMANCE_PROFILE_KEY].value == "max"
    assert "worker" in result["requires_restart"]
    assert result["restart_supported"] is False
    assert result["restart_method"] == "manual"
    assert result["effective_after_restart"]["profile"] == "max"


def test_set_profile_safe_lowers_values(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    save_performance_profile(db, "safe")
    state = performance_state(db)

    assert int(state["effective_settings"]["ingest_batch_size"]) < 1000
    assert int(state["effective_settings"]["opensearch_bulk_docs"]) < 1000


def test_recommendation_chooses_balanced_for_healthy_medium_large_host(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    state = performance_state(db)

    assert state["recommendation"]["recommended_profile"] == "balanced"


def test_custom_setting_validation_rejects_negative(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    with pytest.raises(ValueError):
        save_performance_profile(db, "custom", {"worker_concurrency": -1})


def test_restart_required_semantics(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    result = save_performance_profile(db, "custom", {"ingest_batch_size": 1500, "worker_concurrency": 3})

    assert "worker" in result["requires_restart"]
    assert "INGEST_BATCH_SIZE" in result["runtime_applied"]


def test_max_profile_requires_explicit_confirmation(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    with pytest.raises(ValueError, match="explicit confirmation"):
        save_performance_profile(db, "max")


def test_pending_deployment_changes_include_scope_and_old_new_values(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    save_performance_profile(db, "custom", {"worker_concurrency": 3})
    state = performance_state(db)

    assert state["deployment"]["pending_changes"]
    change = state["deployment"]["pending_changes"][0]
    assert change["scope"] == "deployment"
    assert change["status"] == "requires_restart"
    assert change["requires_restart_services"] == ["worker"]
    assert change["old_value"] == 2
    assert change["new_value"] == 3
    assert change["diagnostic"]["setting_key"] == "WORKER_SCALE"
    assert "docker compose up -d --scale worker=3" in change["diagnostic"]["commands"][0]


def test_deployment_pending_changes_clear_when_worker_scale_matches_runtime(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    save_performance_profile(db, "custom", {"worker_concurrency": 2})
    state = performance_state(db)

    assert state["deployment"]["pending_changes"] == []


def test_manual_restart_instructions_include_services_and_commands():
    result = manual_restart_instructions(["backend", "worker", "frontend"])

    assert result["restart_supported"] is False
    assert result["restart_method"] == "manual"
    assert result["services_to_restart"] == ["backend", "worker", "frontend"]
    assert result["restart_instructions"]["commands"][0]["command"] == "docker compose restart backend worker frontend"
    assert "web UI cannot restart Docker services" in result["restart_instructions"]["notes"][2]


def test_runtime_only_settings_do_not_require_restart(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    result = save_performance_profile(db, "custom", {"ingest_batch_size": 1500})

    assert result["requires_restart"] == []
    assert result["services_to_restart"] == []


def test_performance_resources_return_safe_structure(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    resources = performance_resources(db)

    assert resources["cpu_count_host"] == 8
    assert resources["cpu_count_container"] == 8
    assert resources["memory_container_limit"] == 12 * 1024 * 1024 * 1024
    assert resources["worker_queues"]["worker-1"] == ["dfir-ingest"]
    assert resources["current_profile"] == "balanced"
    assert resources["memory_limit_source"] == "cgroup"


def test_describe_ingest_parallelism_respects_profile_and_cpu_limit(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)

    result = describe_ingest_parallelism(
        {"MAX_PARALLEL_ARTIFACTS": 8, PERFORMANCE_PROFILE_KEY: "max"},
        system=performance_module.system_snapshot(),
        artifact_count=10,
        artifact_types=["evtx_raw", "lnk_raw"],
        supported_artifact_types=["evtx_raw", "lnk_raw", "prefetch_raw"],
    )

    assert result["effective_parallelism"] == 8
    assert result["enabled"] is True


def test_describe_ingest_parallelism_falls_back_for_unsupported_parser(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)

    result = describe_ingest_parallelism(
        {"MAX_PARALLEL_ARTIFACTS": 4, PERFORMANCE_PROFILE_KEY: "balanced"},
        system=performance_module.system_snapshot(),
        artifact_count=4,
        artifact_types=["unknown_parser"],
        supported_artifact_types=["evtx_raw", "lnk_raw"],
    )

    assert result["effective_parallelism"] == 1
    assert result["limit_reason"] == "unsupported_artifact_type"


def test_apply_recommended_profile_returns_applied_and_pending(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    result = apply_recommended_profile(db)

    assert result["profile"] == "balanced"
    assert "runtime_applied" in result
    assert "pending_restart" in result


def test_search_page_size_is_clamped_to_backend_limit(monkeypatch: pytest.MonkeyPatch):
    _patch_system(monkeypatch)
    db = FakeSession()

    set_setting(db, "SEARCH_MAX_PAGE_SIZE", 5000)
    state = performance_state(db)

    assert state["effective_settings"]["search_max_page_size"] == 200


def test_low_disk_warning():
    warnings = build_resource_warnings(
        {
            "disk_free_bytes": 2 * 1024 * 1024 * 1024,
            "disk_total_bytes": 50 * 1024 * 1024 * 1024,
            "memory_available_bytes": 10 * 1024 * 1024 * 1024,
            "opensearch_status": "ok",
        },
        "balanced",
    )

    assert "low_disk_space" in warnings


def test_ingest_summary_includes_performance_snapshot():
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="sample",
        stored_path="/tmp/sample",
        original_path="/tmp/sample",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=123,
        file_count=1,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={
            "performance_profile": "max",
            "performance_settings": {"ingest_batch_size": 2000},
            "resource_warnings": ["low_disk_space"],
        },
        error_log={},
    )
    context = SimpleNamespace(evidences=[evidence])

    rows = _build_ingest_summary(context, {"ev-1": {"stats": {}}})

    assert rows[0]["performance_profile"] == "max"
    assert rows[0]["performance_settings"]["ingest_batch_size"] == 2000
    assert "low_disk_space" in rows[0]["resource_warnings"]
