"""Cross-source search must hold memory-artifact rows to the active filters:
a filter memory cannot satisfy leaves memory out instead of being ignored."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import investigation_memory, search_service
from app.services.memory.search import resolve_requested_families


def test_requested_families_never_widen_to_all_memory() -> None:
    assert resolve_requested_families(None) is None
    # A non-memory artifact type (any platform) matches no memory family.
    assert resolve_requested_families(["windows_event"]) == []
    assert resolve_requested_families("linux_auth") == []
    # Memory document types and family names both resolve.
    assert resolve_requested_families(["memory_network_connection", "processes"]) == ["network", "processes"]
    assert resolve_requested_families(["memory_process_entity"]) == ["processes"]
    excluded = resolve_requested_families(None, ["memory_environment_variable"])
    assert excluded is not None and "environment" not in excluded and "processes" in excluded


def test_filters_memory_cannot_satisfy_are_reported() -> None:
    params = search_service.build_search_v2_params(scope="all", q="psexec", host=["WS01"], page_size=50)
    assert search_service.memory_unsupported_filters(params) == []
    params = search_service.build_search_v2_params(scope="all", event_type=["logon_success"], user=["bob"], page_size=50)
    assert search_service.memory_unsupported_filters(params) == ["event_type", "user"]


def _mixed_search(monkeypatch: pytest.MonkeyPatch, **kwargs):
    calls = {"memory": 0}

    def fake_events(case_id, params, db=None):
        return 1, [{"id": "evt-1", "kind": "event", "timestamp": "2026-05-15T10:00:00Z", "risk_score": 10, "raw": {}}], [], {}

    def fake_memory(db, case_id, params):
        calls["memory"] += 1
        return {"results": [{"id": "memory:1", "kind": "event", "timestamp": "2026-05-15T10:00:00Z", "risk_score": 0}], "warnings": []}

    monkeypatch.setattr(search_service, "search_events_v2", fake_events)
    monkeypatch.setattr(search_service, "search_findings_v2", lambda *a, **k: (0, [], [], []))
    monkeypatch.setattr(search_service, "memory_search_results", fake_memory)
    result = search_service.search_case_v2(None, "case-1", search_service.build_search_v2_params(scope="all", page_size=50, **kwargs))
    return calls["memory"], [row["id"] for row in result["results"]]


def test_mixed_search_leaves_memory_out_for_event_only_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    memory_calls, ids = _mixed_search(monkeypatch, event_type=["process_start"])
    assert memory_calls == 0 and ids == ["evt-1"]
    memory_calls, ids = _mixed_search(monkeypatch, q="powershell")
    assert memory_calls == 1 and set(ids) == {"evt-1", "memory:1"}


def test_memory_only_search_with_unsupported_filter_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search_service, "memory_search_results", lambda *a, **k: pytest.fail("memory must not be searched"))
    params = search_service.build_search_v2_params(scope="all", ip=["10.0.0.5"], page_size=50)
    params["source_category"] = "memory"
    result = search_service.search_case_v2(None, "case-1", params)
    assert result["total"] == 0
    assert "ip" in result["warnings"][0]


def test_memory_rows_follow_host_type_and_exclusion_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    evidences = [SimpleNamespace(id="mem-a", host="WS01"), SimpleNamespace(id="mem-b", host="SRV01"), SimpleNamespace(id="mem-c", host=None)]
    searched: list[tuple[str, object]] = []

    def fake_search(db, *, evidence_id, artifact_types, **_kwargs):
        searched.append((evidence_id, artifact_types))
        return {"results": [
            {"result_id": f"{evidence_id}-1", "title": "powershell.exe", "summary": "PID 10", "artifact_type": "memory_process_entity"},
            {"result_id": f"{evidence_id}-2", "title": "svchost.exe", "summary": "PID 20", "artifact_type": "memory_process_entity"},
        ], "warnings": []}

    monkeypatch.setattr(investigation_memory, "memory_evidences", lambda db, case_id, evidence_id=None: evidences)
    monkeypatch.setattr(investigation_memory, "_evidence_host_name", lambda db, evidence: evidence.host)
    monkeypatch.setattr(investigation_memory, "search_memory_artifacts", fake_search)
    import app.services.host_identity as host_identity
    monkeypatch.setattr(host_identity, "expand_host_filter", lambda db, case_id, name: [name])

    result = investigation_memory.memory_search_results(None, "case-1", {"host": ["ws01.corp.local"], "exclude_q": "svchost"})
    assert [evidence for evidence, _ in searched] == ["mem-a"]  # unknown host is not shown under WS01
    assert [row["title"] for row in result["results"]] == ["powershell.exe"]
    assert result["results"][0]["host"] == "WS01"

    searched.clear()
    result = investigation_memory.memory_search_results(None, "case-1", {"artifact_type": ["windows_event"]})
    assert searched == [] and result["results"] == []

    searched.clear()
    investigation_memory.memory_search_results(None, "case-1", {"exclude_host": ["SRV01"]})
    assert [evidence for evidence, _ in searched] == ["mem-a", "mem-c"]
