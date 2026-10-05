"""The in-app documentation opens, and every search in the investigation guide is valid."""
from __future__ import annotations

import re

import pytest

from app.api.routes_system import DOCS_CATALOG, DOCS_ROOT
from app.search.query_syntax import analyze_query_syntax

GUIDE = DOCS_ROOT / "search-and-investigation" / "investigation-guide.md"


def _query(text: str) -> str:
    return str(analyze_query_syntax(text, lambda term: {"simple_query_string": {"query": term}})["query"])


@pytest.mark.parametrize("entry", DOCS_CATALOG, ids=[entry["slug"] for entry in DOCS_CATALOG])
def test_every_catalogued_document_exists(entry):
    assert (DOCS_ROOT / entry["filename"]).is_file(), f"{entry['slug']} points at a missing {entry['filename']}"


def test_the_guide_is_in_the_catalog():
    assert any(entry["filename"] == "search-and-investigation/investigation-guide.md" for entry in DOCS_CATALOG)


GUIDE_QUERIES = re.findall(r"```kairon\n(.*?)\n```", GUIDE.read_text(encoding="utf-8"), re.S)


def test_the_guide_has_searches_for_windows_and_linux():
    assert len(GUIDE_QUERIES) >= 30
    assert any("eventid:" in query for query in GUIDE_QUERIES) and any("artifact:linux_" in query for query in GUIDE_QUERIES)


@pytest.mark.parametrize("query", GUIDE_QUERIES)
def test_every_search_in_the_guide_is_valid(query):
    _query(query)


@pytest.mark.parametrize("query, field", [
    ("eventid:4624", "windows.event_id"), ("logontype:10", "windows.logon_type"), ("channel:*Sysmon*", "windows.channel"),
    ("provider:*Security*", "windows.provider"), ("service:PSEXESVC", "windows.service_name"), ("task:*Update*", "windows.task_name"),
])
def test_windows_event_fields_are_searchable(query, field):
    assert field in _query(query)


def test_an_event_id_is_matched_as_a_number():
    assert "'windows.event_id': 4624" in _query("eventid:4624")
