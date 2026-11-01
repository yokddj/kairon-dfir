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
close_indexing_plan_job = indexing_profiles.close_indexing_plan_job


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


def test_recommended_plan_contains_investigation_steps_and_excludes_rules_reports():
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
    assert "SRUM" not in excluded
    # Without discovered sources the plan does not offer SRUM or Shellbags at all.
    assert "srum" not in steps
    assert "shellbags" not in steps


def test_recommended_plan_offers_srum_and_shellbags_when_discovered():
    metadata = {
        **_metadata(),
        "velociraptor_discovery": {
            "candidates": [
                {"artifact_type": "srum_raw", "source_path": "uploads/auto/C%3A/Windows/System32/sru/SRUDB.dat"},
                {"artifact_type": "registry_hive_raw", "source_path": "uploads/auto/C%3A/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat"},
                {"artifact_type": "registry_hive_raw", "source_path": "uploads/auto/C%3A/Windows/ServiceProfiles/LocalService/NTUSER.DAT"},
            ]
        },
    }
    plan = build_indexing_plan(profile="recommended", metadata=metadata, mft_diagnostic=_mft(), indexed_docs=12)
    steps = _by_id(plan)

    assert steps["srum"]["status"] == "ready"
    assert steps["srum"]["endpoint"] == "srum-index"
    assert steps["shellbags"]["status"] == "ready"
    assert steps["shellbags"]["endpoint"] == "shellbags-index"
    assert {"srum", "shellbags"} <= {item["id"] for item in plan["runnable_steps"]}

    done = build_indexing_plan(profile="recommended", metadata={**metadata, "srum_records_indexed": 40, "shellbags_records_indexed": 7}, mft_diagnostic=_mft(), indexed_docs=12)
    assert _by_id(done)["srum"]["status"] == "completed"
    assert _by_id(done)["shellbags"]["status"] == "completed"


def test_plan_reads_sources_the_core_ingest_selected_or_listed():
    selected = {**_metadata(), "ingest_plan": {"selected_candidates": [{"source_path": "x_0_DC/C/Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat"}]}}
    listed = {**_metadata(), "tree": ["x_0_DC/C/Windows/System32/sru/SRUDB.dat"]}
    assert "shellbags" in _by_id(build_indexing_plan(profile="recommended", metadata=selected, mft_diagnostic=_mft(), indexed_docs=12))
    assert "srum" in _by_id(build_indexing_plan(profile="recommended", metadata=listed, mft_diagnostic=_mft(), indexed_docs=12))


def test_service_profile_hives_do_not_offer_shellbags():
    metadata = {**_metadata(), "velociraptor_discovery": {"candidates": [{"source_path": "C:/Windows/ServiceProfiles/NetworkService/NTUSER.DAT"}]}}
    assert "shellbags" not in _by_id(build_indexing_plan(profile="recommended", metadata=metadata, mft_diagnostic=_mft(), indexed_docs=12))


def test_fast_plan_downgrades_full_mft():
    plan = build_indexing_plan(profile="fast", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=0)
    steps = _by_id(plan)

    assert "mft_full" not in steps
    assert steps["mft_summary"]["status"] == "ready"
    assert any(item["name"] == "Full MFT" for item in plan["excluded"])


def test_plan_reflects_a_reprocess_that_wiped_previously_indexed_mft_and_user_activity():
    """A reprocess that deletes OpenSearch events must also reset the
    on-demand step counters (mft_full_records_indexed, mft_coverage_status,
    registry_user_activity_records_indexed) that this function reads --
    otherwise it keeps reporting "already indexed" for data that no longer
    exists (see _ON_DEMAND_INDEXING_METADATA_RESET in app/workers/tasks.py)."""
    metadata = _metadata(registry_user_activity_status="", defender_evtx_status="")
    mft = _mft(mft_coverage_status="", mft_full_records_indexed=0)

    plan = build_indexing_plan(profile="recommended", metadata=metadata, mft_diagnostic=mft, indexed_docs=0)
    steps = _by_id(plan)

    assert steps["mft_full"]["status"] == "ready"
    assert steps["user_activity"]["status"] == "ready"


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


def test_waiting_selection_without_run_is_action_required_not_active():
    metadata = _metadata(
        current_phase="waiting_selection",
        velociraptor_discovery={"candidates": [{"id": "evtx-1", "supported": True, "category": "evtx"}]},
    )

    active, job = evidence_has_active_indexing(metadata, "pending")
    plan = build_indexing_plan(profile="recommended", metadata=metadata, mft_diagnostic=_mft(mft_present_in_evidence=False), indexed_docs=0, active=active, active_job=job)

    assert active is False
    assert job is None
    assert plan["requires_user_action"] is True
    assert plan["supported_candidate_count"] == 1
    assert plan["can_run"] is True


def test_pending_plan_without_run_is_planned_not_started_not_active():
    metadata = _metadata(
        current_phase="planned",
        ingest_plan={"discovery_mode": "recommended_indexing"},
        velociraptor_discovery={"candidates": [{"id": "evtx-1", "supported": True, "category": "evtx"}]},
    )

    active, job = evidence_has_active_indexing(metadata, "pending")
    plan = build_indexing_plan(profile="recommended", metadata=metadata, mft_diagnostic=_mft(mft_present_in_evidence=False), indexed_docs=0, active=active, active_job=job)

    assert active is False
    assert job is None
    assert plan["state"] == "planned_not_started"
    assert plan["status_reason"] == "Indexing plan prepared; no parser run has been started."
    assert plan["requires_user_action"] is False
    assert plan["supported_candidate_count"] == 1
    assert plan["can_run"] is True


def test_waiting_selection_with_run_id_remains_active():
    active, job = evidence_has_active_indexing({"current_phase": "waiting_selection", "current_ingest_run_id": "run-1"}, "pending")

    assert active is True
    assert job and job["run_id"] == "run-1"


def test_completed_core_plan_run_does_not_leave_active_lock():
    metadata = _metadata(
        indexing_plan_run={
            "run_id": "plan-1",
            "status": "queued",
            "queued_jobs": [{"step_id": "core_artifacts", "run_id": "ingest-1", "status": "queued"}],
        }
    )

    active, job = evidence_has_active_indexing(metadata, "completed")

    assert active is False
    assert job is None


def test_create_indexing_plan_run_persists_step_statuses():
    plan = build_indexing_plan(profile="recommended", metadata=_metadata(), mft_diagnostic=_mft(), indexed_docs=0)
    run = create_indexing_plan_run(plan, [{"step_id": "mft_full", "run_id": "job-1", "status": "queued"}])
    steps = _by_id(run)

    assert run["status"] == "queued"
    assert steps["mft_full"]["status"] == "queued"
    assert steps["mft_full"]["run_id"] == "job-1"


def test_close_indexing_plan_job_closes_the_run_once_the_only_queued_job_succeeds():
    metadata = _metadata(
        indexing_plan_run={
            "run_id": "plan-1",
            "status": "queued",
            "queued_jobs": [{"step_id": "mft_full", "run_id": "job-1", "status": "queued"}],
        }
    )

    metadata = close_indexing_plan_job(metadata, step_id="mft_full", status="completed")

    plan_run = metadata["indexing_plan_run"]
    assert plan_run["status"] == "completed"
    assert plan_run["queued_jobs"][0]["status"] == "completed"


def test_close_indexing_plan_job_reproduces_and_fixes_the_stuck_processing_bug():
    # Exact repro: an on-demand step finished successfully, but nothing ever
    # told indexing_plan_run -- this is the state that made
    # evidence_has_active_indexing() (and therefore EvidenceDetail's
    # "Processing" badge / Pause button) claim an active job forever, even
    # with Evidence.ingest_status already "completed".
    metadata = _metadata(
        indexing_plan_run={
            "run_id": "plan-1",
            "status": "queued",
            "queued_jobs": [{"step_id": "mft_full", "run_id": "job-1", "status": "queued"}],
        }
    )
    active_before, _job = evidence_has_active_indexing(metadata, "completed")
    assert active_before is True  # the bug, reproduced

    metadata = close_indexing_plan_job(metadata, step_id="mft_full", status="completed")
    active_after, job_after = evidence_has_active_indexing(metadata, "completed")

    assert active_after is False
    assert job_after is None


def test_close_indexing_plan_job_marks_completed_with_errors_on_failure():
    metadata = _metadata(
        indexing_plan_run={
            "run_id": "plan-1",
            "status": "queued",
            "queued_jobs": [{"step_id": "defender", "run_id": "job-2", "status": "queued"}],
        }
    )

    metadata = close_indexing_plan_job(metadata, step_id="defender", status="failed")

    plan_run = metadata["indexing_plan_run"]
    assert plan_run["status"] == "completed_with_errors"
    assert plan_run["queued_jobs"][0]["status"] == "failed"
    # A failed on-demand step must not look active either.
    active, _job = evidence_has_active_indexing(metadata, "completed")
    assert active is False


def test_close_indexing_plan_job_keeps_the_run_active_while_a_sibling_job_is_still_queued():
    metadata = _metadata(
        indexing_plan_run={
            "run_id": "plan-1",
            "status": "queued",
            "queued_jobs": [
                {"step_id": "mft_full", "run_id": "job-1", "status": "queued"},
                {"step_id": "user_activity", "run_id": "job-2", "status": "queued"},
            ],
        }
    )

    metadata = close_indexing_plan_job(metadata, step_id="mft_full", status="completed")

    plan_run = metadata["indexing_plan_run"]
    assert plan_run["status"] == "queued"
    assert plan_run["queued_jobs"][0]["status"] == "completed"
    assert plan_run["queued_jobs"][1]["status"] == "queued"
    active, job = evidence_has_active_indexing(metadata, "completed")
    assert active is True
    assert job["step"] == "indexing_plan"


def test_close_indexing_plan_job_is_a_no_op_when_step_never_queued():
    metadata = _metadata(indexing_plan_run={"run_id": "plan-1", "status": "queued", "queued_jobs": [{"step_id": "mft_full", "run_id": "job-1", "status": "queued"}]})

    result = close_indexing_plan_job(metadata, step_id="srum", status="completed")

    # No queued_jobs entry has step_id "srum" -- nothing should change.
    assert result["indexing_plan_run"]["status"] == "queued"


def test_close_indexing_plan_job_is_a_no_op_without_a_plan_run():
    metadata = _metadata()

    result = close_indexing_plan_job(metadata, step_id="mft_full", status="completed")

    assert "indexing_plan_run" not in result


def _collection_metadata(paths: list[str], **extra) -> dict:
    return {"velociraptor_discovery": {"candidates": [{"id": str(index), "original_path": path, "supported": True} for index, path in enumerate(paths)]}, **extra}


def test_follow_up_steps_start_only_for_sources_the_evidence_holds() -> None:
    from app.services.indexing_profiles import automatic_follow_up_steps

    windows = _collection_metadata([
        "C/Users/alice/NTUSER.DAT",
        "C/Windows/System32/sru/SRUDB.dat",
        "C/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx",
    ], ingest_mode="full_forensic")
    assert sorted(step["id"] for step in automatic_follow_up_steps(windows)) == ["defender", "shellbags", "srum", "user_activity"]

    # Nothing to read (a Linux collection): nothing started.
    assert automatic_follow_up_steps(_collection_metadata(["etc/passwd", "var/log/auth.log"], ingest_mode="full_forensic")) == []

    # Usable search is chosen to get results fast: follow-ups stay on demand.
    assert automatic_follow_up_steps({**windows, "ingest_mode": "usable_search"}) == []

    # A step that already ran is not started again.
    done = {**windows, "registry_user_activity_records_indexed": 12, "srum_records_indexed": 3}
    assert sorted(step["id"] for step in automatic_follow_up_steps(done)) == ["defender", "shellbags"]


def test_reprocess_resets_every_follow_up_step() -> None:
    """Re-index deletes the evidence's events, follow-up steps' included;
    a step left marked as done would never run again."""
    from app.services.indexing_profiles import automatic_follow_up_steps
    from app.workers.tasks import _ON_DEMAND_INDEXING_METADATA_RESET

    metadata = _collection_metadata(["C/Users/alice/NTUSER.DAT", "C/Windows/System32/sru/SRUDB.dat", "C/Windows/System32/winevt/Logs/Security.evtx"], ingest_mode="full_forensic")
    metadata.update({"registry_user_activity_records_indexed": 5, "srum_records_indexed": 5, "shellbags_records_indexed": 5, "defender_evtx_docs_indexed": 5})
    assert automatic_follow_up_steps(metadata) == []
    metadata.update(_ON_DEMAND_INDEXING_METADATA_RESET)
    assert sorted(step["id"] for step in automatic_follow_up_steps(metadata)) == ["defender", "shellbags", "srum", "user_activity"]
