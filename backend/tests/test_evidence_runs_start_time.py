from app.services.evidence_runs import list_evidence_runs, start_ingest_run, sync_ingest_run_from_metadata


def _queued_reprocess(previous_started_at: str, previous_elapsed: float) -> dict:
    metadata = {"started_at": previous_started_at, "elapsed_seconds": previous_elapsed}
    metadata = start_ingest_run(metadata, run_id="run-2", run_type="reprocess", mode="previous_selection", status="queued")
    metadata["latest_ingest_run_id"] = "run-2"
    return metadata


def test_queued_run_does_not_take_the_previous_runs_start_time():
    metadata = _queued_reprocess("2020-01-01T10:00:00+00:00", 3720.0)
    synced = sync_ingest_run_from_metadata(metadata, run_id="run-2", ingest_status="pending")
    run = list_evidence_runs(synced)[0]
    assert run["started_at"] is None
    assert run["elapsed_seconds"] is None


def test_run_takes_its_own_start_once_the_worker_sets_it_and_keeps_it():
    metadata = _queued_reprocess("2020-01-01T10:00:00+00:00", 3720.0)
    synced = sync_ingest_run_from_metadata(metadata, run_id="run-2", ingest_status="pending")
    created_at = list_evidence_runs(synced)[0]["created_at"]
    synced["started_at"] = created_at
    synced["elapsed_seconds"] = 12.0
    synced = sync_ingest_run_from_metadata(synced, run_id="run-2", ingest_status="processing")
    run = list_evidence_runs(synced)[0]
    assert run["started_at"] == created_at
    assert run["elapsed_seconds"] == 12.0


def test_running_run_without_any_start_time_is_stamped_and_keeps_it():
    metadata = _queued_reprocess("2020-01-01T10:00:00+00:00", 3720.0)
    synced = sync_ingest_run_from_metadata(metadata, run_id="run-2", ingest_status="processing")
    stamped = list_evidence_runs(synced)[0]["started_at"]
    assert stamped is not None and stamped >= list_evidence_runs(synced)[0]["created_at"]
    again = sync_ingest_run_from_metadata(synced, run_id="run-2", ingest_status="processing")
    assert list_evidence_runs(again)[0]["started_at"] == stamped
