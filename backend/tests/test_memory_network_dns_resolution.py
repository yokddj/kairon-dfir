"""_resolve_dns_domains(): best-effort IP -> domain lookup for the memory
Network tab, cross-referencing already-indexed DNS query documents
(document.dns.ip/dns.domain) for the same case -- memory connections only
ever carry a remote IP, this is the only way to show what domain a process
actually talked to.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.api import routes_memory


class FakeClient:
    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self.hits = hits
        self.last_body: dict[str, Any] | None = None

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.last_body = body
        return {"hits": {"hits": self.hits}}


def _hit(ip: str, domain: str) -> dict[str, Any]:
    return {"_source": {"dns": {"ip": ip, "domain": domain}}}


def _patch(monkeypatch: pytest.MonkeyPatch, client: FakeClient, *, queryable: bool = True) -> None:
    monkeypatch.setattr(routes_memory, "get_opensearch_client", lambda: client)
    monkeypatch.setattr("app.core.opensearch.get_events_index", lambda case_id: f"dfir-events-{case_id}")
    monkeypatch.setattr("app.core.opensearch.is_index_queryable", lambda _client, _index: queryable)


def test_no_remote_ips_skips_the_query_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(hits=[])
    _patch(monkeypatch, client)
    assert routes_memory._resolve_dns_domains("case-1", []) == {}
    assert client.last_body is None


def test_resolves_ip_to_domain_from_indexed_dns_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(hits=[_hit("203.0.113.5", "malicious-c2.example")])
    _patch(monkeypatch, client)
    resolved = routes_memory._resolve_dns_domains("case-1", ["203.0.113.5"])
    assert resolved == {"203.0.113.5": "malicious-c2.example"}
    assert client.last_body["query"]["bool"]["filter"] == [
        {"term": {"case_id": "case-1"}},
        {"term": {"artifact.type": "dns"}},
        {"terms": {"dns.ip": ["203.0.113.5"]}},
    ]


def test_first_domain_wins_when_an_ip_resolved_multiple_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(hits=[_hit("203.0.113.5", "first.example"), _hit("203.0.113.5", "second.example")])
    _patch(monkeypatch, client)
    resolved = routes_memory._resolve_dns_domains("case-1", ["203.0.113.5"])
    assert resolved == {"203.0.113.5": "first.example"}


def test_ip_with_no_matching_dns_query_is_absent_not_fabricated(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(hits=[])
    _patch(monkeypatch, client)
    resolved = routes_memory._resolve_dns_domains("case-1", ["198.51.100.9"])
    assert resolved == {}


def test_unqueryable_index_returns_empty_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(hits=[_hit("203.0.113.5", "should-not-appear.example")])
    _patch(monkeypatch, client, queryable=False)
    assert routes_memory._resolve_dns_domains("case-1", ["203.0.113.5"]) == {}


def test_search_failure_returns_empty_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    class RaisingClient(FakeClient):
        def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("opensearch unavailable")

    _patch(monkeypatch, RaisingClient(hits=[]))
    assert routes_memory._resolve_dns_domains("case-1", ["203.0.113.5"]) == {}
