"""The symbol probe runs on the memory worker: the API container has no Volatility."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.api import routes_memory


class _Job:
    def __init__(self, statuses, value=None):
        self.statuses = list(statuses)
        self.value = value

    def get_status(self, refresh=True):
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    def return_value(self):
        return self.value


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _s: None)


def test_the_worker_result_is_returned(monkeypatch):
    found = {"evidence_id": "e1", "status": "identified", "requirement": {"pdb_name": "ntkrnlmp.pdb"}}
    monkeypatch.setattr("app.workers.tasks.enqueue_memory_symbol_probe", lambda evidence_id: _Job(["queued", "started", "finished"], found))
    assert routes_memory._probe_on_memory_worker("e1") == found


def test_a_failed_job_says_so(monkeypatch):
    monkeypatch.setattr("app.workers.tasks.enqueue_memory_symbol_probe", lambda evidence_id: _Job(["failed"]))
    result = routes_memory._probe_on_memory_worker("e1")
    assert result["status"] == "failed" and "memory worker" in result["sanitized_message"]


def test_a_probe_still_queued_is_reported_as_probing(monkeypatch):
    monkeypatch.setattr(routes_memory, "_PROBE_WAIT_SECONDS", 0.0)
    monkeypatch.setattr("app.workers.tasks.enqueue_memory_symbol_probe", lambda evidence_id: _Job(["queued"]))
    assert routes_memory._probe_on_memory_worker("e1")["status"] == "probing"


def test_an_unreachable_queue_is_reported(monkeypatch):
    def boom(evidence_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr("app.workers.tasks.enqueue_memory_symbol_probe", boom)
    assert routes_memory._probe_on_memory_worker("e1")["error_code"] == "MEMORY_PROBE_NOT_QUEUED"
