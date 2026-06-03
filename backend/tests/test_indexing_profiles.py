from __future__ import annotations

import importlib.util
from pathlib import Path

_service_path = Path(__file__).resolve().parents[1] / "app" / "services" / "indexing_profiles.py"
_service_spec = importlib.util.spec_from_file_location("indexing_profiles_under_test", _service_path)
assert _service_spec and _service_spec.loader
indexing_profiles = importlib.util.module_from_spec(_service_spec)
_service_spec.loader.exec_module(indexing_profiles)

build_indexing_plan = indexing_profiles.build_indexing_plan
create_indexing_plan_run = indexing_profiles.create_indexing_plan_run
evidence_has_active_indexing = indexing_profiles.evidence_has_active_indexing


def _metadata(**overrides):
    data = {
        "investigation_ready": False,
        "srum_tooling_missing": True,
        "registry_user_activity_status": "not_indexed",
        "defender_evtx_status": "not_indexed",
    }
    data.update(overrides)
    return data


def _mft(**overrides):
    data = {
        "mft_present_in_evidence": True,
        "mft_backend_available": True,
        "mft_coverage_status": "partial",
        "mft_full_records_indexed": 0,
    }
    data.update(overrides)
    return data


def _by_id(plan):
    return {item["id"]: item for item in plan["steps"]}


def test_recommended_plan_contains_investigation_steps_and_excludes_rules_reports_srum():
    plan = build_indexing_plan(profile="recommended", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=12)
    steps = _by_id(plan)

    assert plan["primary_cta"] == "Index evidence for investigation"
    assert steps["core_artifacts"]["status"] == "completed"
    assert steps["event_logs"]["status"] == "completed"
    assert steps["mft_full"]["status"] == "ready"
    assert steps["user_activity"]["status"] == "ready"
    assert steps["defender"]["status"] == "ready"
    assert steps["motw"]["status"] == "derived"
    excluded = {item["name"]: item["reason"] for item in plan["excluded"]}
    assert "Sigma rules" in excluded
    assert "Reports" in excluded
    assert "SRUM" in excluded
    assert "Windows parser worker" in excluded["SRUM"]


def test_fast_plan_downgrades_full_mft():
    plan = build_indexing_plan(profile="fast", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=0)
    steps = _by_id(plan)

    assert "mft_full" not in steps
    assert steps["mft_summary"]["status"] == "ready"
    assert any(item["name"] == "Full MFT" for item in plan["excluded"])


def test_advanced_custom_does_not_bundle_execution():
    plan = build_indexing_plan(profile="advanced_custom", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=0)

    assert plan["can_run"] is False
    assert any(item["name"] == "Automatic execution" for item in plan["excluded"])


def test_evidence_lock_detects_active_ingest_and_artifact_jobs():
    active, job = evidence_has_active_indexing({"current_ingest_run_id": "run-1"}, "processing")
    assert active is True
    assert job and job["step"] == "core_ingest"

    active, job = evidence_has_active_indexing({"mft_full_status": "queued"}, "completed")
    assert active is True
    assert job and job["step"] == "full_mft"


def test_create_indexing_plan_run_persists_step_statuses():
    plan = build_indexing_plan(profile="recommended", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=0)
    run = create_indexing_plan_run(plan, [{"step_id": "mft_full", "run_id": "job-1", "status": "queued"}])
    steps = _by_id(run)

    assert run["status"] == "queued"
    assert steps["mft_full"]["status"] == "queued"
    assert steps["mft_full"]["run_id"] == "job-1"
