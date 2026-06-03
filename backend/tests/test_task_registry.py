from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import _queue_case_rules_run
from app.api.routes_system import system_task_health
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.rule import Rule, RuleEngine
from app.schemas.rule import RulesRunRequest
from app.services import report_service
from app.services.task_registry import (
    automatic_task_categories_for_ingest_mode,
    automatic_task_entrypoints_for_ingest_mode,
    build_task_health_snapshot,
    build_task_registry,
)
from app.services.on_demand_modules import build_on_demand_module_registry
from app.services.usable_ingest import FULL_FORENSIC_MODE, USABLE_INGEST_MODE, ingest_mode_metadata
from app.services.usable_ingest import build_mode_effective_plan
from app.workers.tasks import _finish_metadata_phase_timing, _update_progress

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RULE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _case() -> Case:
    return Case(id=CASE_ID, name="Case", status="open")


def _evidence(*, current_ingest_run_id: str | None = None) -> Evidence:
    metadata = {
        **ingest_mode_metadata(USABLE_INGEST_MODE),
        "latest_ingest_run_id": "ingest-1",
        "events_indexed": 53,
    }
    if current_ingest_run_id is not None:
        metadata["current_ingest_run_id"] = current_ingest_run_id
    return Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        original_path="/tmp/collection.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="abc",
        size_bytes=128,
        file_count=3,
        ingest_status=IngestStatus.completed,
        metadata_json=metadata,
        path_validation={},
        ingest_source={},
        error_log={},
    )


def _rule() -> Rule:
    return Rule(
        id=RULE_ID,
        case_id=CASE_ID,
        name="sigma-test",
        engine=RuleEngine.sigma,
        content="title: Test\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
        enabled=True,
    )


def _summary_payload() -> dict:
    return {
        "header": {
            "case_id": CASE_ID,
            "evidence_id": EVIDENCE_ID,
            "evidence_name": "collection.zip",
            "generated_at": "2026-05-26T10:00:00Z",
            "report_type": "summary",
            "mode": "on_demand",
        },
        "ingest_summary": {"latest_ingest_run_id": "ingest-1", "ingest_mode": "usable_search", "final_status": "completed"},
        "search_summary": {"total_indexed_docs": 53, "artifact_type_counts": {"browser": 53}, "parser_counts": {"browser_chromium_history": 53}},
        "parser_contract_summary": {"contract_version": "v1", "summary": {"pass": 1}},
        "detections_summary": {"total_detections": 0, "by_severity": {}, "by_rule": {}, "latest_rule_run_ids": [], "top_detections": []},
        "problematic_artifacts": {"summary": {"problematic_count": 0}, "items": []},
        "links": {"search_this_evidence": f"/cases/{CASE_ID}/search?evidence_id={EVIDENCE_ID}&tab=results"},
        "warnings": [],
    }


def test_task_registry_contains_core_on_demand_and_advanced_entries() -> None:
    registry = build_task_registry()
    assert "app.workers.tasks.ingest_evidence" in registry
    assert "app.workers.tasks.run_rules_on_case" in registry
    assert "app.services.report_service.generate_evidence_summary_report" in registry
    assert "app.services.ingest_benchmarks.create_ingest_benchmark" in registry
    for entrypoint in (
        "app.workers.tasks.ingest_evidence",
        "app.workers.tasks.run_rules_on_case",
        "app.services.report_service.generate_evidence_summary_report",
    ):
        entry = registry[entrypoint]
        assert entry["category"]
        assert entry["queue"]
        assert entry["status"]
        assert entry["triggered_by"]


def test_usable_search_automatic_tasks_are_core_only() -> None:
    assert automatic_task_entrypoints_for_ingest_mode(USABLE_INGEST_MODE) == ["app.workers.tasks.ingest_evidence"]
    assert automatic_task_categories_for_ingest_mode(USABLE_INGEST_MODE) == ["core"]
    metadata = ingest_mode_metadata(USABLE_INGEST_MODE)
    assert metadata["skip_rules"] is True
    assert metadata["skip_detections"] is True
    assert metadata["skip_heavy_enrichment"] is True
    assert metadata["skip_benchmark"] is True
    assert metadata["automatic_tasks"] == ["app.workers.tasks.ingest_evidence"]
    assert metadata["automatic_task_categories"] == ["core"]


def test_full_forensic_mode_remains_available() -> None:
    metadata = ingest_mode_metadata(FULL_FORENSIC_MODE)
    assert metadata["ingest_mode"] == FULL_FORENSIC_MODE
    assert metadata["skip_rules"] is False
    assert metadata["automatic_tasks"] == ["app.workers.tasks.ingest_evidence"]


def test_build_mode_effective_plan_exposes_skipped_features_and_scope() -> None:
    plan = build_mode_effective_plan(
        USABLE_INGEST_MODE,
        selected_artifact_types=["windows_event", "browser"],
        available_artifact_types=["windows_event", "browser", "prefetch"],
    )

    assert plan["ingest_mode"] == USABLE_INGEST_MODE
    assert plan["automatic_tasks"] == ["app.workers.tasks.ingest_evidence"]
    assert "rules" in plan["skipped_features"]
    assert plan["enabled_artifact_categories"] == ["browser", "windows_event"]


def test_update_progress_tracks_phase_timings() -> None:
    db = _session()
    db.add(_case())
    evidence = _evidence()
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    _update_progress(db, evidence, phase="extracting", progress_pct=5, phases=["extracting", "parsing"], extra={"started_at": "2026-05-27T10:00:00Z"})
    db.refresh(evidence)
    first_snapshot = evidence.metadata_json
    assert first_snapshot["current_phase"] == "extracting"
    assert first_snapshot["phase_timings"][-1]["phase"] == "extracting"

    _update_progress(db, evidence, phase="parsing", progress_pct=30, phases=["extracting", "parsing"])
    db.refresh(evidence)
    second_snapshot = evidence.metadata_json
    phases = [item["phase"] for item in second_snapshot["phase_timings"]]
    assert "extracting" in phases
    assert "parsing" in phases


def test_update_progress_closes_terminal_phase_timing() -> None:
    db = _session()
    db.add(_case())
    evidence = _evidence()
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    _update_progress(db, evidence, phase="parsing", progress_pct=80, phases=["parsing", "completed"])
    db.refresh(evidence)
    _update_progress(db, evidence, phase="completed", progress_pct=100, phases=["parsing", "completed"], extra={"finished_at": "2026-05-27T10:05:00+00:00"})
    db.refresh(evidence)

    assert evidence.metadata_json["current_phase_timing"] is None
    assert evidence.metadata_json["phase_timings"][-1]["phase"] == "completed"
    assert evidence.metadata_json["phase_timings"][-1]["finished_at"] == "2026-05-27T10:05:00+00:00"


def test_finish_metadata_phase_timing_closes_open_phase() -> None:
    metadata = {
        "current_phase_timing": {
            "phase": "parsing",
            "started_at": "2026-05-27T10:00:00+00:00",
            "finished_at": None,
            "duration_seconds": 0,
        },
        "phase_timings": [
            {
                "phase": "parsing",
                "started_at": "2026-05-27T10:00:00+00:00",
                "finished_at": None,
                "duration_seconds": 1,
            }
        ],
    }

    _finish_metadata_phase_timing(metadata, phase="parsing")

    assert metadata["current_phase_timing"] is None
    assert len(metadata["phase_timings"]) == 1
    assert metadata["phase_timings"][-1]["phase"] == "parsing"
    assert metadata["phase_timings"][-1]["finished_at"]
    assert metadata["phase_timings"][-1]["duration_seconds"] >= 0


def test_on_demand_rules_run_does_not_modify_current_ingest_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _session()
    db.add(_case())
    db.add(_evidence(current_ingest_run_id="ingest-existing"))
    db.add(_rule())
    db.commit()

    monkeypatch.setattr("app.api.routes_rules.count_documents", lambda *args, **kwargs: {"count": 53})
    monkeypatch.setattr("app.api.routes_rules.enqueue_rules_run", lambda **kwargs: "job-123")
    monkeypatch.setattr("app.api.routes_rules.log_activity", lambda *args, **kwargs: None)

    result = _queue_case_rules_run(
        db,
        case_id=CASE_ID,
        payload=RulesRunRequest(mode="on_demand", scope="evidence", evidence_id=EVIDENCE_ID, rule_types=["sigma"]),
        requested_via="evidence_on_demand",
    )

    assert result["accepted"] is True
    evidence = db.get(Evidence, EVIDENCE_ID)
    assert evidence is not None
    assert evidence.metadata_json["current_ingest_run_id"] == "ingest-existing"


def test_on_demand_report_does_not_modify_current_ingest_run_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db = _session()
    db.add(_case())
    db.add(_evidence(current_ingest_run_id="ingest-existing"))
    db.commit()

    monkeypatch.setattr(report_service, "_count_evidence_indexed_docs", lambda evidence: 53)
    monkeypatch.setattr(report_service, "_load_evidence_manifest", lambda evidence: {"artifacts": []})
    monkeypatch.setattr(report_service, "_report_output_dir", lambda report_id: tmp_path / report_id)
    monkeypatch.setattr(report_service, "_build_evidence_summary_payload", lambda *args, **kwargs: _summary_payload())

    report = report_service.generate_evidence_summary_report(db, EVIDENCE_ID, {"report_type": "summary", "format": "json"})

    assert report["status"] == "completed"
    evidence = db.get(Evidence, EVIDENCE_ID)
    assert evidence is not None
    assert evidence.metadata_json["current_ingest_run_id"] == "ingest-existing"


def test_task_health_endpoint_returns_queue_and_category_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeJob:
        def __init__(self, job_id: str, func_name: str) -> None:
            self.id = job_id
            self.func_name = func_name

    class _FakeQueue:
        def __init__(self, name: str, connection=None) -> None:
            self.name = name
            self.count = 1 if name == "dfir-ingest" else 0
            self.job_ids = ["job-1"] if name == "dfir-ingest" else []

        def fetch_job(self, job_id: str):
            if self.name == "dfir-ingest" and job_id == "job-1":
                return _FakeJob("job-1", "app.workers.tasks.ingest_evidence")
            return None

    class _FakeStartedRegistry:
        def __init__(self, name: str, connection=None) -> None:
            self.name = name

        def __len__(self) -> int:
            return 0

        def get_job_ids(self) -> list[str]:
            return []

    class _FakeEmptyRegistry:
        def __init__(self, name: str, connection=None) -> None:
            self.name = name

        def __len__(self) -> int:
            return 0

    class _FakeWorker:
        name = "worker-1"
        queues = [type("_Q", (), {"name": "dfir-ingest"})()]

        @staticmethod
        def all(connection=None):
            return [_FakeWorker()]

    monkeypatch.setattr("app.services.task_registry.Queue", _FakeQueue)
    monkeypatch.setattr("app.services.task_registry.StartedJobRegistry", _FakeStartedRegistry)
    monkeypatch.setattr("app.services.task_registry.FailedJobRegistry", _FakeEmptyRegistry)
    monkeypatch.setattr("app.services.task_registry.FinishedJobRegistry", _FakeEmptyRegistry)
    monkeypatch.setattr("app.services.task_registry.Worker", _FakeWorker)

    snapshot = build_task_health_snapshot(connection=object())
    assert snapshot["workers"]["alive"] == 1
    assert "dfir-ingest" in snapshot["queues"]
    assert snapshot["queues"]["dfir-ingest"]["category"] == "core"
    assert snapshot["task_registry"]["by_category"]["core"] >= 1

    monkeypatch.setattr("app.api.routes_system.build_task_health_snapshot", lambda: snapshot)
    direct = system_task_health()
    assert direct["queues"]["dfir-ingest"]["category"] == "core"


def test_on_demand_module_registry_classifies_stable_and_advanced_modules() -> None:
    registry = build_on_demand_module_registry(
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        problematic_count=0,
        indexed_docs=53,
    )
    assert registry["rules"]["module_category"] == "on_demand_stable"
    assert registry["reports"]["module_category"] == "on_demand_stable"
    assert registry["benchmark"]["module_category"] == "advanced"
    assert registry["host_enrichment"]["module_category"] == "advanced"
    assert registry["benchmark"]["auto_runs"] is False
    assert registry["advanced_exports"]["auto_runs"] is False
    assert registry["deep_retry"]["status"] == "disabled"
    assert "No problematic artifacts" in str(registry["deep_retry"]["disabled_reason"])
