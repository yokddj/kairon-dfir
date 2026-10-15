"""Find Evil triage by process: grouping, order and the analyst's marks."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.services.memory import findevil_triage


def _name_bucket(name: str, priorities: dict[str, int], types: dict[str, int]) -> dict[str, Any]:
    return {
        "key": name,
        "doc_count": sum(priorities.values()),
        "priorities": {"buckets": [{"key": k, "doc_count": v} for k, v in priorities.items()]},
        "types": {"buckets": [{"key": k, "doc_count": v} for k, v in types.items()]},
    }


class _Client:
    def __init__(self, buckets: list[dict[str, Any]]) -> None:
        self.buckets = buckets
        self.indices = SimpleNamespace(get_field_mapping=lambda **_: {})

    def search(self, index: str, body: dict[str, Any], params: Any = None) -> dict[str, Any]:
        self.body = body
        return {"aggregations": {"pids": {"buckets": self.buckets}}}


class _Query:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def filter(self, *_args: Any) -> "_Query":
        return self

    def __iter__(self):
        return iter(self.rows)


class _Db:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def query(self, _model: Any) -> _Query:
        return _Query(self.rows)


def _run(monkeypatch, buckets, markings=()):
    client = _Client(buckets)
    monkeypatch.setattr(findevil_triage, "get_opensearch_client", lambda: client)
    return findevil_triage.findevil_processes(_Db(list(markings)), case_id="case-1", evidence_id="ev-1", run_id="run-1"), client


def test_groups_indicators_by_process_most_important_first(monkeypatch) -> None:
    processes, client = _run(monkeypatch, [
        {"key": 4744, "names": {"buckets": [_name_bucket("explorer.exe", {"medium": 2, "low": 10}, {"PRIVATE_RX": 10, "THREAD": 2})]}},
        {"key": 2192, "names": {"buckets": [_name_bucket("svchost.exe", {"high": 1, "medium": 2}, {"PROC_NOLINK": 1, "PEB_BAD_LDR": 2})]}},
        {"key": 900, "names": {"buckets": [_name_bucket("chrome.exe", {"low": 40}, {"PRIVATE_RWX": 40})]}},
        {"key": -1, "names": {"buckets": [_name_bucket("", {"high": 3}, {"AV_DETECT": 3})]}},
    ])

    assert [(p["pid"], p["process_name"]) for p in processes] == [(None, None), (2192, "svchost.exe"), (4744, "explorer.exe"), (900, "chrome.exe")]
    svchost = processes[1]
    assert svchost["priority_counts"] == {"high": 1, "medium": 2, "low": 0}
    assert svchost["top_priority"] == "high"
    assert svchost["indicator_count"] == 3
    assert svchost["triage_id"] == "memory-findevil-process:ev-1:2192:svchost.exe"
    # Scoped to the active run of this evidence.
    assert {"term": {"scan_run_id.keyword": "run-1"}} in client.body["query"]["bool"]["filter"]


def test_attaches_the_analysts_mark(monkeypatch) -> None:
    mark = SimpleNamespace(event_id="memory-findevil-process:ev-1:900:chrome.exe", id="m-1", status="not_relevant", note="JIT")
    processes, _ = _run(monkeypatch, [{"key": 900, "names": {"buckets": [_name_bucket("chrome.exe", {"low": 4}, {"PRIVATE_RWX": 4})]}}], [mark])

    assert processes[0]["marking"] == {"id": "m-1", "status": "not_relevant", "note": "JIT"}


def test_marking_identity_does_not_depend_on_the_run() -> None:
    assert findevil_triage.process_marking_id("ev-1", 4, "System") == "memory-findevil-process:ev-1:4:System"
    assert findevil_triage.process_marking_id("ev-1", None, None) == "memory-findevil-process:ev-1::"
    assert "/" not in findevil_triage.process_marking_id("ev-1", 12, "kworker/0:1")
