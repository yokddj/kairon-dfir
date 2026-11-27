"""A large event log is not cut while it still reads records, and a stop never makes the file be read
again from the start with the other parser (which indexed its first batches twice)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.workers import tasks


def _callback(monkeypatch, clock: list[float], *, max_seconds=180, stall=600, max_runtime=3600):
    monkeypatch.setattr(tasks, "_update_progress_isolated", lambda *args, **kwargs: None)
    monkeypatch.setattr(tasks.time, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(tasks.settings, "evtx_artifact_max_seconds", max_seconds)
    monkeypatch.setattr(tasks.settings, "evtx_no_progress_stall_seconds", stall)
    monkeypatch.setattr(tasks.settings, "evtx_max_active_runtime_seconds", max_runtime)
    return tasks._artifact_progress_callback(
        evidence_id="e",
        artifact_name="Security.evtx",
        artifact_index=1,
        total_artifacts=1,
        artifacts_processed=0,
        indexed_count=0,
        records_processed=0,
        detection_count=0,
        raw_artifacts_detected=1,
        raw_artifacts_not_parsed=1,
        started_monotonic=clock[0],
        state={},
    )


def test_a_slow_file_that_keeps_reading_is_not_stopped(monkeypatch) -> None:
    clock = [1000.0]
    callback = _callback(monkeypatch, clock)
    for step in range(1, 30):
        clock[0] += 60  # 29 minutes, far past the 180 s "slow" mark
        callback({"records_read": step * 10_000})
    assert callback._tracker["slow_artifact_logged"] is True


def test_a_file_that_reads_nothing_new_is_stopped(monkeypatch) -> None:
    clock = [1000.0]
    callback = _callback(monkeypatch, clock, stall=600)
    callback({"records_read": 250})
    clock[0] += 601
    with pytest.raises(tasks.EvtxArtifactLimitExceeded, match="read no record for 601s"):
        callback({"records_read": 250})


def test_the_total_runtime_cap_still_applies(monkeypatch) -> None:
    clock = [1000.0]
    callback = _callback(monkeypatch, clock, max_runtime=3600)
    clock[0] += 3601
    with pytest.raises(tasks.EvtxArtifactLimitExceeded, match="exceeded 3600s"):
        callback({"records_read": 1_000_000})
    # 0 turns both stops off.
    clock = [1000.0]
    callback = _callback(monkeypatch, clock, stall=0, max_runtime=0)
    clock[0] += 10 * 86400
    callback({"records_read": 5})


class _CsvBackend:
    def __init__(self, fail_after: int, error: Exception):
        self.fail_after = fail_after
        self.error = error

    def iter_batches(self, path, **kwargs):
        for index in range(self.fail_after):
            yield SimpleNamespace(metadata={}, events=[{"n": index}])
        raise self.error


class _PythonParser:
    calls = 0

    def iter_batches(self, path, **kwargs):
        type(self).calls += 1
        yield SimpleNamespace(metadata={}, events=[{"python": True}])


@pytest.fixture()
def backends(monkeypatch):
    _PythonParser.calls = 0
    monkeypatch.setattr(tasks, "select_evtx_parser_backend", lambda requested: {"selected": tasks.EVTXECMD_BACKEND_CSV, "version": "test"})
    monkeypatch.setattr(tasks, "EvtxRawParser", _PythonParser)

    def install(fail_after: int, error: Exception) -> None:
        monkeypatch.setattr(tasks, "EvtxECmdCsvBackend", lambda: _CsvBackend(fail_after, error))

    return install


def _run(tmp_path):
    return list(tasks._iter_full_evtx_batches_with_backend(path=tmp_path / "Security.evtx", case_id="c", evidence_id="e", artifact_id="a", artifact_meta={}, batch_size=500))


def test_evtxecmd_failing_before_any_batch_falls_back(backends, tmp_path) -> None:
    backends(0, RuntimeError("EvtxECmd not runnable"))
    results = _run(tmp_path)
    assert _PythonParser.calls == 1 and results[0][0]["fallback"] is True


def test_evtxecmd_failing_after_batches_does_not_read_the_file_again(backends, tmp_path) -> None:
    backends(3, RuntimeError("EvtxECmd crashed"))
    with pytest.raises(RuntimeError, match="crashed"):
        _run(tmp_path)
    assert _PythonParser.calls == 0


def test_a_limit_stop_is_never_a_fallback(backends, tmp_path) -> None:
    backends(0, tasks.EvtxArtifactLimitExceeded("EVTX artifact exceeded 3600s"))
    with pytest.raises(tasks.EvtxArtifactLimitExceeded):
        _run(tmp_path)
    assert _PythonParser.calls == 0
