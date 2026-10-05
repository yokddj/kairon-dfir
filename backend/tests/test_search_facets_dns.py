"""The facets say how many DNS events a case has, so the DNS view is offered only when it has data."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.api import routes_search


@pytest.fixture()
def client(monkeypatch):
    fake = MagicMock()
    fake.search.return_value = {"aggregations": {}}
    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda *a, **k: fake)
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case")
    monkeypatch.setattr(routes_search, "_index_available", lambda index: True)
    monkeypatch.setattr(routes_search, "resolve_aggregatable_field", lambda client, index, field: field)
    monkeypatch.setattr(routes_search, "_cache_get", lambda *a, **k: None)
    monkeypatch.setattr(routes_search, "_cache_put", lambda cache, key, ttl, value: value)
    return fake


@pytest.mark.parametrize("count", [0, 7])
def test_the_facets_count_dns_events_across_artifact_types(client, count):
    client.count.return_value = {"count": count}
    facets = routes_search.search_facets(case_id="case", evidence_id=None, host_id=None, host_scope=None, db=MagicMock())
    assert facets["derived"] == {"dns": count}
    query = client.count.call_args.kwargs["body"]["query"]["bool"]["filter"][-1]
    assert set(query["terms"]["event.type"]) == set(routes_search.DNS_EVENT_TYPES)


def test_a_failed_count_offers_no_dns(client):
    client.count.side_effect = RuntimeError("unavailable")
    facets = routes_search.search_facets(case_id="case", evidence_id=None, host_id=None, host_scope=None, db=MagicMock())
    assert facets["derived"] == {"dns": 0}


def test_an_empty_case_has_no_dns(monkeypatch):
    monkeypatch.setattr(routes_search, "_cache_get", lambda *a, **k: None)
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case")
    monkeypatch.setattr(routes_search, "_index_available", lambda index: False)
    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda *a, **k: MagicMock())
    assert routes_search.search_facets(case_id="case", evidence_id=None, host_id=None, host_scope=None, db=MagicMock())["derived"] == {"dns": 0}
