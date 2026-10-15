"""Shell History filters: free-text command search, source filter and the
source options derived from the run's own documents."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

from app.services.memory import artifact_indexing


class _Client:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response or {"hits": {"total": {"value": 0}, "hits": []}}
        self.body: dict[str, Any] | None = None

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.body = body
        return self.response


def _filters(**filters: Any) -> list[dict[str, Any]]:
    client = _Client()
    with patch.object(artifact_indexing, "get_opensearch_client", lambda: client):
        artifact_indexing.search_artifact_documents(
            "case-1", document_type="memory_shell_history", run_id="run-1", evidence_id="ev-1", filters=filters
        )
    assert client.body is not None
    return client.body["query"]["bool"]["filter"]


def test_command_filter_is_a_case_insensitive_substring_also_for_long_commands() -> None:
    clause = _filters(command="Invoke-Web*Request?")[-1]
    should = clause["bool"]["should"]
    # Wildcard metacharacters typed by the user are literal text, not syntax.
    assert {"wildcard": {"command.keyword": {"value": "*Invoke-WebRequest*", "case_insensitive": True}}} in should
    # Commands longer than the keyword limit are only in the analysed field.
    assert {"match_phrase": {"command": "Invoke-WebRequest"}} in should


def test_source_filter_uses_recovered_from_or_the_plugin_when_there_is_none() -> None:
    clause = _filters(source="linux.bash")[-1]
    should = clause["bool"]["should"]
    assert {"term": {"recovered_from": "linux.bash"}} in should
    assert {"bool": {"filter": [{"term": {"source_plugin": "linux.bash"}}], "must_not": [{"exists": {"field": "recovered_from"}}]}} in should


def test_source_facets_only_list_sources_present_in_the_run() -> None:
    client = _Client({
        "aggregations": {
            "recovered_from": {"buckets": [{"key": "screen", "doc_count": 3}, {"key": "command_history", "doc_count": 7}]},
            "plugin_only": {"source_plugin": {"buckets": [{"key": "linux.bash", "doc_count": 5}]}},
        }
    })
    with patch.object(artifact_indexing, "get_opensearch_client", lambda: client):
        facets = artifact_indexing.artifact_source_facets("case-1", document_type="memory_shell_history", run_id="run-1", evidence_id="ev-1")

    assert facets == [
        {"value": "command_history", "count": 7},
        {"value": "linux.bash", "count": 5},
        {"value": "screen", "count": 3},
    ]
    assert client.body is not None
    assert {"term": {"scan_run_id.keyword": "run-1"}} in client.body["query"]["bool"]["filter"]
    assert client.body["size"] == 0


def test_source_facets_are_empty_without_documents() -> None:
    with patch.object(artifact_indexing, "get_opensearch_client", lambda: _Client({"aggregations": {}})):
        assert artifact_indexing.artifact_source_facets("case-1", document_type="memory_shell_history", run_id="run-1") == []
