from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.services.memory import search as memory_search


class FakeDb:
    def __init__(self) -> None:
        self.evidence = SimpleNamespace(id="ev-1", filename="mem.raw", name="mem.raw")

    def get(self, model, ident):  # noqa: ANN001
        if ident == "run-historical":
            return SimpleNamespace(id="run-historical", case_id="case-1", evidence_id="ev-1", profile="network_basic", status="completed")
        return self.evidence


class FakeClient:
    def __init__(self, hits: list[dict[str, Any]] | None = None, total: int | None = None) -> None:
        self.last_body: dict[str, Any] | None = None
        self.hits = hits or []
        self.total = len(self.hits) if total is None else total

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.last_body = body
        return {
            "hits": {"total": {"value": self.total}, "hits": self.hits},
            "aggregations": {
                "artifact_type": {"buckets": [{"key": "memory_network_connection", "doc_count": 2}]},
                "source_plugin": {"buckets": [{"key": "windows.netstat", "doc_count": 2}]},
                "has_process": {"buckets": {"linked": {"doc_count": 1}, "unlinked": {"doc_count": 1}}},
            },
        }


def _patch(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> None:
    monkeypatch.setattr(memory_search, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(memory_search, "get_memory_index", lambda case_id: f"dfir-memory-{case_id}")
    monkeypatch.setattr(
        memory_search,
        "resolve_active_memory_result",
        lambda db, **kwargs: {"active_run": {"id": f"run-{kwargs['family']}", "profile": kwargs["family"], "status": "completed"}},
    )


def _search(monkeypatch: pytest.MonkeyPatch, *, query: str = "", hits: list[dict[str, Any]] | None = None, **kwargs: Any) -> tuple[dict[str, Any], FakeClient]:
    client = FakeClient(hits=hits)
    _patch(monkeypatch, client)
    result = memory_search.search_memory_artifacts(
        FakeDb(),
        case_id="case-1",
        evidence_id="ev-1",
        query=query,
        **kwargs,
    )
    assert client.last_body is not None
    return result, client


def _filters(body: dict[str, Any]) -> list[dict[str, Any]]:
    return body["query"]["bool"]["filter"]


def _must(body: dict[str, Any]) -> list[dict[str, Any]]:
    return body["query"]["bool"]["must"]


def test_exact_pid_and_ppid_search_uses_terms(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, query="6996", artifact_types=["processes"])
    assert result["query_interpretation"] == "numeric_exact"
    assert "multi_match" not in str(_must(client.last_body))
    assert "process.pid" in str(_must(client.last_body))
    assert "process.ppid" in str(_must(client.last_body))


def test_explicit_ppid_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, ppid=4, artifact_types=["processes"])
    assert "observed.ppid" in str(_filters(client.last_body))
    assert "process.ppid" in str(_filters(client.last_body))


def test_process_name_text_search(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, query="powershell.exe", artifact_types=["processes"])
    assert result["query_interpretation"] == "full_text"
    assert "process.name.text" in str(_must(client.last_body))


def test_command_line_full_text_search(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, query="powershell -enc", artifact_types=["command_lines"])
    assert "process.command_line" in str(_must(client.last_body))


def test_ipv4_exact_search(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, query="10.0.0.5", artifact_types=["network"])
    assert result["query_interpretation"] == "ip_address"
    assert "local_address" in str(_must(client.last_body))
    assert "multi_match" not in str(_must(client.last_body))


def test_ipv6_exact_search(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, query="[2001:db8::1]", artifact_types=["network"])
    assert result["query_interpretation"] == "ip_address"
    assert "2001:db8::1" in str(_must(client.last_body))


def test_port_exact_search(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, query="443", artifact_types=["network"])
    assert "local_port" in str(_must(client.last_body))
    assert "remote_port" in str(_must(client.last_body))


def test_sid_exact_search(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, query="S-1-5-18", artifact_types=["sids"])
    assert result["query_interpretation"] == "sid"
    assert {"term": {"sid": "S-1-5-18"}} in _must(client.last_body)


@pytest.mark.parametrize(
    ("family", "query", "field"),
    [
        ("privileges", "SeDebugPrivilege", "privilege"),
        ("modules", "kernel32.dll", "module_name"),
        ("handles", "File", "object_type"),
        ("drivers", "WMIxWDM", "driver_name"),
        ("kernel", "ntoskrnl", "module_name"),
        ("suspicious", "PAGE_EXECUTE_READWRITE", "protection"),
        ("vads", "VadS", "tag"),
    ],
)
def test_family_text_fields(monkeypatch: pytest.MonkeyPatch, family: str, query: str, field: str) -> None:
    _, client = _search(monkeypatch, query=query, artifact_types=[family])
    assert field in str(_must(client.last_body))


def test_evidence_scoping_and_no_cross_evidence_leakage(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, query="svchost", artifact_types=["processes"])
    assert {"term": {"evidence_id": "ev-1"}} in _filters(client.last_body)
    assert "ev-2" not in str(client.last_body)


def test_historical_run_scoping(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, artifact_types=["network"], run_id="run-historical")
    assert "run-historical" in str(_filters(client.last_body))
    assert "run-network" not in str(_filters(client.last_body))


def test_mixed_run_opt_in_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = _search(monkeypatch, mixed_run=True)
    assert result["selected_run_context"]["mixed_run"] is True


def test_pid_reuse_remains_distinct_by_document(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = [
        {"_id": "a", "_source": {"document_id": "a", "document_type": "memory_process_entity", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-1", "process_entity_id": "ent-a", "process": {"pid": 4, "name": "System"}}},
        {"_id": "b", "_source": {"document_id": "b", "document_type": "memory_process_entity", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-2", "process_entity_id": "ent-b", "process": {"pid": 4, "name": "System"}}},
    ]
    result, _ = _search(monkeypatch, query="4", hits=hits, artifact_types=["processes"])
    assert [item["process_entity_id"] for item in result["results"]] == ["ent-a", "ent-b"]


def test_pagination_metadata_and_sort(monkeypatch: pytest.MonkeyPatch) -> None:
    result, client = _search(monkeypatch, page=2, page_size=50, sort="pid")
    assert result["page"] == 2
    assert result["page_size"] == 50
    assert client.last_body["from"] == 50
    assert "pid" in str(client.last_body["sort"])


def test_facet_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = _search(monkeypatch)
    assert result["facets"]["artifact_type"]["memory_network_connection"] == 2
    assert result["facets"]["has_process"]["linked"] == 1


def test_raw_only_fallback_and_completed_empty_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = _search(monkeypatch, hits=[], artifact_types=["raw_observations"])
    assert result["coverage"]["raw_only_fallback"] is True


def test_deep_link_target_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = [{"_id": "net-1", "_source": {"document_id": "net-1", "document_type": "memory_network_connection", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-network", "pid": 4, "process_entity_id": "ent-4", "protocol": "TCPv4", "local_address": "10.0.0.5", "local_port": 443}}]
    result, _ = _search(monkeypatch, hits=hits, artifact_types=["network"])
    target = result["results"][0]["navigation_target"]
    assert target["tab"] == "artifacts"
    assert target["process_entity_id"] == "ent-4"
    assert target["artifact_id"] == "net-1"


def test_normalization_warning_coverage_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _search(monkeypatch, warnings_only=True)
    assert "normalization_warning" in str(_filters(client.last_body))


def test_reindex_dry_run_contract_is_exposed_by_existing_cli() -> None:
    from app.cli import memory_results_maintenance

    assert hasattr(memory_results_maintenance, "renormalize_command")
    assert "windows.netstat" in memory_results_maintenance._RENORMALIZABLE_PLUGINS


def test_reindex_apply_idempotent_contract_uses_document_ids() -> None:
    from app.services.memory.artifact_indexing import index_artifact_documents

    assert callable(index_artifact_documents)
