"""search_text substring matching must not depend on case_insensitive.

OpenSearch 2.15's wildcard field type returns no hits for a wildcard query with
case_insensitive=true, even when the value matches exactly. Every substring
fallback over search_text used that flag, so "psexesvc" never found
"PSEXESVC.exe" and "Invoke-Mimikatz" never found "Invoke-Mimikatz.ps1".
"""

from __future__ import annotations

import json

from app.core import opensearch
from app.core.opensearch import SEARCH_TEXT_SUBSTRING_FIELD, ensure_search_text_substring_field, search_text_substring_clause
from app.services.search_service import _build_text_query


def _substring_clauses(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "wildcard" and isinstance(value, dict) and SEARCH_TEXT_SUBSTRING_FIELD in value:
                yield value[SEARCH_TEXT_SUBSTRING_FIELD]
            else:
                yield from _substring_clauses(value)
    elif isinstance(node, list):
        for item in node:
            yield from _substring_clauses(item)


def test_clause_is_lowercase_and_never_case_insensitive() -> None:
    assert search_text_substring_clause("*PSEXESVC*") == {"wildcard": {SEARCH_TEXT_SUBSTRING_FIELD: {"value": "*psexesvc*"}}}


def test_bare_stems_and_command_like_queries_use_the_normalized_subfield() -> None:
    for query in ("PSEXESVC", "Invoke-Mimikatz", "rundll32 comsvcs", "cmd.exe /c whoami"):
        clauses = list(_substring_clauses(_build_text_query(query)))
        assert clauses, query
        assert all("case_insensitive" not in clause for clause in clauses), query
        assert all(clause["value"] == clause["value"].lower() for clause in clauses), query
    assert "search_text.wildcard\"" not in json.dumps(_build_text_query("PSEXESVC"))


def test_new_indices_map_the_subfield_with_the_lowercase_normalizer(monkeypatch) -> None:
    created = {}

    class Indices:
        def create(self, index, body):
            created.update(body)

    class Client:
        indices = Indices()

    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda **_: Client())
    monkeypatch.setattr(opensearch, "index_exists", lambda client, index: False)
    opensearch.ensure_case_index("case-1")
    fields = created["mappings"]["properties"]["search_text"]["fields"]
    assert fields["wildcard_lc"] == {"type": "wildcard", "normalizer": "lowercase"}
    assert "wildcard" not in fields


class FakeClient:
    def __init__(self, mappings, missing, busy=""):
        self.mappings = mappings
        self.missing = missing
        self.busy = busy
        self.put: list[str] = []
        self.updated: list[str] = []
        outer = self

        class Indices:
            def get_mapping(self, index, params=None):
                return outer.mappings

            def put_mapping(self, index, body):
                outer.put.append(index)

        class Tasks:
            def list(self, params=None):
                return {"nodes": {"n1": {"tasks": {"t1": {"description": outer.busy}}}}}

        self.indices = Indices()
        self.tasks = Tasks()

    def count(self, index, body):
        return {"count": self.missing[index]}

    def update_by_query(self, index, body, params):
        assert params["wait_for_completion"] == "false"
        self.updated.append(index)
        return {"task": f"node:{index}"}


def _mapping(*subfields):
    return {"mappings": {"properties": {"search_text": {"type": "text", "fields": {name: {} for name in subfields}}}}}


def test_startup_backfill_adds_the_subfield_and_fills_only_what_is_missing(monkeypatch) -> None:
    client = FakeClient(
        {
            "dfir-events-old": _mapping("keyword", "wildcard"),
            "dfir-events-done": _mapping("keyword", "wildcard_lc"),
            "dfir-events-running": _mapping("keyword", "wildcard", "wildcard_lc"),
        },
        {"dfir-events-old": 120, "dfir-events-done": 0, "dfir-events-running": 50},
        busy="update-by-query [dfir-events-running]",
    )
    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda **_: client)

    started = ensure_search_text_substring_field()

    assert client.put == ["dfir-events-old"]
    assert started == client.updated == ["dfir-events-old"]
