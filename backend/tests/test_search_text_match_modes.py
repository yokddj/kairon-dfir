"""One text-matching engine for Search, Timeline, Artifact Views and Command History."""

import json

import pytest
from fastapi import HTTPException

from app.api.routes_search import _build_text_query as build_post_text_query
from app.schemas.event import SearchRequest
from app.services import search_service
from app.services.search_service import (
    _analyze_text_query,
    build_text_query_for_mode,
    memory_unsupported_filters,
    normalize_text_match_mode,
)


def _dump(query: dict) -> str:
    return json.dumps(query, sort_keys=True)


def test_mode_names_are_normalised() -> None:
    assert normalize_text_match_mode(None) == "smart"
    assert normalize_text_match_mode("CONTAINS") == "contains"
    assert normalize_text_match_mode("exact") == "exact"
    # Artifact Views' former "ioc" mode is an exact match.
    assert normalize_text_match_mode("ioc") == "exact"
    assert normalize_text_match_mode("bogus") == "smart"


def test_contains_is_a_case_insensitive_substring_of_the_whole_input() -> None:
    dumped = _dump(build_text_query_for_mode("Invoke-WebRequest http", "contains"))
    assert "*invoke-webrequest http*" in dumped
    assert "file.path" in dumped and "download.file_name" in dumped


def test_contains_rejects_overlong_input() -> None:
    with pytest.raises(HTTPException):
        build_text_query_for_mode("x" * 200, "contains")


def test_exact_is_a_phrase_match() -> None:
    query = build_text_query_for_mode('"powershell -enc"', "exact")
    phrase = query["bool"]["should"][0]["multi_match"]
    assert phrase["type"] == "phrase" and phrase["query"] == "powershell -enc"
    # Some text fields are ip-typed in some indices: a strict phrase fails there.
    assert phrase["lenient"] is True


def test_contains_and_exact_treat_the_input_as_literal_text_not_syntax() -> None:
    info = _analyze_text_query("cmd AND whoami", "contains")
    assert info["mode"] == "plain" and info["ast"] is None
    assert "*cmd and whoami*" in _dump(info["query"])


def test_artifact_views_smart_uses_the_same_engine_as_search() -> None:
    # A bare stem ("comsvcs" in "comsvcs.dll") matched in Search through the
    # substring fallback but not in Artifact Views, which had its own engine.
    payload = SearchRequest(case_id="case-1", query="comsvcs", search_mode="smart")
    assert build_post_text_query(payload) == search_service._build_text_query("comsvcs")
    assert "*comsvcs*" in _dump(build_post_text_query(payload))


def test_artifact_views_contains_and_exact_match_the_get_endpoints() -> None:
    for mode in ("contains", "exact"):
        payload = SearchRequest(case_id="case-1", query="mimikatz.exe", search_mode=mode)
        assert build_post_text_query(payload) == build_text_query_for_mode("mimikatz.exe", mode)


def test_event_ids_stay_a_term_match_in_artifact_views() -> None:
    payload = SearchRequest(case_id="case-1", query="4624", search_mode="contains")
    assert "*4624*" not in _dump(build_post_text_query(payload))


def test_match_mode_is_not_a_filter_that_excludes_memory_rows() -> None:
    assert memory_unsupported_filters({"q": "cmd", "search_mode": "contains"}) == []


def test_exact_only_adds_typed_indicator_terms_for_a_matching_value() -> None:
    # A term with free text on an ip-typed field fails the whole OpenSearch query.
    assert "source.ip" not in _dump(build_text_query_for_mode("powershell -enc", "exact"))
    assert "term" not in _dump(build_text_query_for_mode("powershell -enc", "exact"))
    assert "term" in _dump(build_text_query_for_mode("10.0.0.5", "exact"))
