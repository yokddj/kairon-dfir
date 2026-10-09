"""delete_by_query_and_wait: large deletions run as a polled task (OpenSearch 2.x sends one
TASK_RESOURCE_USAGE header per scroll batch, and Python's HTTP client aborts past 100 headers)."""

from __future__ import annotations

import pytest

from app.core import opensearch
from app.core.opensearch import delete_by_query_and_wait


class _Tasks:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = 0

    def get(self, task_id):
        self.calls += 1
        return self.statuses.pop(0)


class _Indices:
    def __init__(self):
        self.refreshed = []

    def refresh(self, index):
        self.refreshed.append(index)


class _Client:
    def __init__(self, statuses):
        self.tasks = _Tasks(statuses)
        self.indices = _Indices()
        self.calls = []

    def delete_by_query(self, index, body, params):
        self.calls.append((index, body, params))
        return {"task": "node:42"}


def test_runs_as_a_task_and_waits_for_it() -> None:
    client = _Client([{"completed": False}, {"completed": True, "response": {"deleted": 196499, "failures": []}}])
    assert delete_by_query_and_wait(client, "dfir-events-c", {"term": {"evidence_id": "e"}}, poll_seconds=0) == 196499
    index, body, params = client.calls[0]
    assert params["wait_for_completion"] == "false" and params["conflicts"] == "proceed"
    assert body == {"query": {"term": {"evidence_id": "e"}}}
    assert client.tasks.calls == 2 and client.indices.refreshed == ["dfir-events-c"]


def test_task_failures_are_raised() -> None:
    client = _Client([{"completed": True, "response": {"deleted": 3, "failures": [{"reason": "boom"}]}}])
    with pytest.raises(RuntimeError, match="boom"):
        delete_by_query_and_wait(client, "i", {"match_all": {}}, poll_seconds=0)


def test_a_task_that_never_finishes_times_out() -> None:
    client = _Client([{"completed": False}] * 5)
    with pytest.raises(TimeoutError):
        delete_by_query_and_wait(client, "i", {"match_all": {}}, timeout_seconds=0, poll_seconds=0)


def test_evidence_deletion_uses_the_task(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client([{"completed": True, "response": {"deleted": 7}}])
    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda *a, **k: client)
    monkeypatch.setattr(opensearch, "index_exists", lambda *a: True)
    assert opensearch.delete_events_by_evidence("ev-1", "case-1") == 7
    assert client.calls[0][1] == {"query": {"term": {"evidence_id": "ev-1"}}}
