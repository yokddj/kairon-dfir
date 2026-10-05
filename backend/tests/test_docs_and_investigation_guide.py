"""The in-app documentation opens, and every search in the investigation guide is valid."""
from __future__ import annotations

import json

import pytest

from app.api.routes_system import DOCS_CATALOG, DOCS_ROOT
from app.search.query_syntax import analyze_query_syntax

GUIDE = DOCS_ROOT / "data" / "investigation-guide.json"


def _query(text: str) -> str:
    return str(analyze_query_syntax(text, lambda term: {"simple_query_string": {"query": term}})["query"])


@pytest.mark.parametrize("entry", DOCS_CATALOG, ids=[entry["slug"] for entry in DOCS_CATALOG])
def test_every_catalogued_document_exists(entry):
    assert (DOCS_ROOT / entry["filename"]).is_file(), f"{entry['slug']} points at a missing {entry['filename']}"


GUIDE_DATA = json.loads(GUIDE.read_text(encoding="utf-8"))
GUIDE_QUERIES = [search["query"] for topic in GUIDE_DATA["topics"] for search in topic["searches"]]
VIEW_TARGETS = {"artifacts", "process-graph", "host-information", "timeline", "command-history", "detections", "linux-authentication"}


def test_the_guide_has_searches_for_windows_and_linux():
    platforms = {topic["platform"] for topic in GUIDE_DATA["topics"]}
    assert platforms == {"windows", "linux"} and len(GUIDE_QUERIES) >= 30
    assert len({topic["id"] for topic in GUIDE_DATA["topics"]}) == len(GUIDE_DATA["topics"])


@pytest.mark.parametrize("query", GUIDE_QUERIES)
def test_every_search_in_the_guide_is_valid(query):
    _query(query)


@pytest.mark.parametrize("topic", GUIDE_DATA["topics"], ids=[topic["id"] for topic in GUIDE_DATA["topics"]])
def test_every_topic_is_complete_and_links_to_real_views(topic):
    assert topic["question"] and topic["why"] and topic["searches"] and topic["sources"] and topic["look_for"]
    for view in topic["views"]:
        assert view["target"] in VIEW_TARGETS, view
        if view["target"] == "artifacts":
            assert view.get("artifact_type"), view  # resolved against the frontend artifact registry by its own test


@pytest.mark.parametrize("query, field", [
    ("eventid:4624", "windows.event_id"), ("logontype:10", "windows.logon_type"), ("channel:*Sysmon*", "windows.channel"),
    ("provider:*Security*", "windows.provider"), ("service:PSEXESVC", "windows.service_name"), ("task:*Update*", "windows.task_name"),
])
def test_windows_event_fields_are_searchable(query, field):
    assert field in _query(query)


def test_an_event_id_is_matched_as_a_number():
    assert "'windows.event_id': 4624" in _query("eventid:4624")
