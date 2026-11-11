"""siem_fields calls search_facets as a plain function: FastAPI defaults must not leak in."""

import pytest
from fastapi.params import Depends as DependsParam
from fastapi.params import Query as QueryParam

from app.api import routes_search


class _Stop(Exception):
    pass


def test_siem_fields_passes_real_values_to_search_facets(monkeypatch) -> None:
    seen = {}

    def fake_facets(case_id, **kwargs):
        seen.update(kwargs, case_id=case_id)
        raise _Stop

    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda: object())
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "events-case-1")
    monkeypatch.setattr(routes_search, "search_facets", fake_facets)
    with pytest.raises(_Stop):
        routes_search.siem_fields(case_id="case-1", db=None)
    assert seen["case_id"] == "case-1"
    assert not any(isinstance(value, (QueryParam, DependsParam)) for value in seen.values())


def test_sample_values_come_from_the_facet_buckets() -> None:
    facets = {"event.type": {"logon_success": 3, "process_start": 9}, "tags": ["a", "b"]}
    assert routes_search._facet_sample_values(facets, "event.type") == ["process_start", "logon_success"]
    assert routes_search._facet_sample_values(facets, "tags") == ["a", "b"]
    assert routes_search._facet_sample_values(facets, "missing") == []
