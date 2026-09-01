"""The tool layer: aggregates first, hard caps, and no crash reaches the model."""

from __future__ import annotations

import json

import pytest

from app.services.ai import tools as tools_module
from app.services.ai.tools import (
    MAX_RESULT_CHARS,
    MAX_ROWS_HARD,
    TOOL_SPECS,
    _enforce_size,
    _limit,
    run_tool,
)


def test_every_advertised_tool_has_a_handler():
    """A tool the model can see but not call would be a silent dead end."""
    advertised = {spec["name"] for spec in TOOL_SPECS}
    assert advertised == set(tools_module.HANDLERS)


def test_every_tool_spec_declares_an_object_schema():
    for spec in TOOL_SPECS:
        assert spec["input_schema"]["type"] == "object", spec["name"]
        assert spec["description"].strip(), spec["name"]


@pytest.mark.parametrize(
    "requested,expected",
    [
        (None, tools_module.MAX_ROWS),
        (5, 5),
        (0, 1),
        (9999, MAX_ROWS_HARD),
        ("nonsense", tools_module.MAX_ROWS),
    ],
)
def test_limit_is_clamped(requested, expected):
    """A model asking for 10,000 rows must not get them."""
    assert _limit(requested) == expected


def test_unknown_tool_is_reported_not_raised():
    result = run_tool(None, "case-1", "definitely_not_a_tool", {})
    assert "Unknown tool" in result["error"]


def test_a_failing_tool_returns_an_error_the_model_can_read(monkeypatch):
    """A crash inside a service must reach the model as text, not kill the stream."""

    def boom(db, case_id, args):
        raise RuntimeError("OpenSearch is down")

    monkeypatch.setitem(tools_module.HANDLERS, "search_events", boom)
    result = run_tool(None, "case-1", "search_events", {"query": "x"})
    assert "OpenSearch is down" in result["error"]


def test_oversized_results_are_trimmed_until_they_fit():
    """One pathological row must not be able to blow the context window."""
    result = {"total_matches": 900, "events": [{"summary": "x" * 2000} for _ in range(40)]}
    trimmed = _enforce_size(result)
    assert len(json.dumps(trimmed, default=str)) <= MAX_RESULT_CHARS
    assert trimmed["truncated"]
    assert trimmed["total_matches"] == 900, "the aggregate must survive trimming"


def test_search_events_reports_totals_not_just_rows(monkeypatch):
    """The count describes the case; the rows are only a sample of it."""
    rows = [
        {
            "id": f"evt-{i}",
            "timestamp": "2026-08-01T10:00:00Z",
            "host": "WS-01",
            "artifact_type": "registry",
            "title": "Run key written",
            "risk_score": 80,
            "raw": {"enormous": "y" * 5000},
        }
        for i in range(5)
    ]
    facets = {"artifact_type": {"registry": 900, "ntfs": 300}, "severity": {"high": 12}}
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (1240, rows, [], facets),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))

    result = tools_module.tool_search_events(None, "case-1", {"query": "run key"})

    assert result["total_matches"] == 1240
    assert len(result["events"]) == 5
    assert "1240 events matched" in result["note"]
    # The breakdown counts the sample, so it must not be named as if it were
    # case-wide: an analyst told "900 registry events" when 900 was a page
    # count would be misled about the evidence.
    assert "breakdown" not in result
    assert result["sample_breakdown"]["artifact_type"]["registry"] == 900
    assert "counts only those shown" in result["note"]
    assert "raw" not in result["events"][0], "the raw document must never reach the model"


def test_search_events_projects_away_bulky_fields(monkeypatch):
    """Only analyst-meaningful fields survive the projection."""
    rows = [{"id": "e1", "host": "WS-01", "raw": {"x": "y"}, "highlights": {"a": ["b"]}, "summary": "s"}]
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (1, rows, [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))

    event = tools_module.tool_search_events(None, "case-1", {"query": "q"})["events"][0]

    assert set(event) <= set(tools_module.EVENT_KEYS)
    assert "highlights" not in event


def test_long_field_values_are_clipped():
    row = [{"id": "e1", "summary": "z" * 5000}]
    clipped = tools_module._rows(row, ("id", "summary"), 10)[0]
    assert len(clipped["summary"]) <= tools_module.MAX_FIELD_CHARS


def test_persistence_tool_passes_the_host_filter_through(monkeypatch):
    captured = {}

    def fake(db, case_id, params):
        captured.update(params)
        return {"items": [{"host": "WS-01", "type": "run_key", "name": "evil"}], "counts": {"total": 1}}

    monkeypatch.setattr("app.services.startup_persistence.list_startup_persistence_items", fake)
    session = RecordingSession(hosts=[FakeHost("id-1", "WS-01")])
    result = tools_module.tool_list_persistence(session, "case-1", {"host": "WS-01", "suspicious_only": True})

    assert captured["host"] == ["WS-01"]
    assert captured["suspicious_only"] is True
    assert result["summary"]["total"] == 1


# --------------------------------------------------------------------------
# Session hygiene. A model passing a host name where a UUID column was
# expected once aborted the Postgres transaction, and every later lookup in
# the conversation failed with "current transaction is aborted".
# --------------------------------------------------------------------------


class RecordingSession:
    """A session double that records rollbacks."""

    def __init__(self, hosts=None, explode=False):
        self.rolled_back = 0
        self._hosts = hosts or []
        self._explode = explode

    def rollback(self):
        self.rolled_back += 1

    def query(self, *_args, **_kwargs):
        if self._explode:
            raise RuntimeError("current transaction is aborted")
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def all(self):
        return self._hosts

    def first(self):
        return None


class FakeHost:
    def __init__(self, host_id, display_name, canonical_name=None):
        self.id = host_id
        self.display_name = display_name
        self.canonical_name = canonical_name or display_name
        self.event_count = 10
        self.evidence_count = 1
        self.first_seen = None
        self.last_seen = None


def test_a_failed_tool_rolls_the_session_back(monkeypatch):
    """Otherwise Postgres refuses every later statement on that connection."""

    def boom(db, case_id, args):
        raise RuntimeError("invalid input syntax for type uuid")

    monkeypatch.setitem(tools_module.HANDLERS, "search_events", boom)
    session = RecordingSession()

    result = run_tool(session, "case-1", "search_events", {"query": "x"})

    assert session.rolled_back == 1
    assert result["recoverable"] is True
    assert "try a different query" in result["hint"]


def test_the_session_is_usable_after_a_failure(monkeypatch):
    """The next lookup must succeed rather than inherit the aborted transaction."""
    calls = {"n": 0}

    def flaky(db, case_id, args):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("invalid input syntax for type uuid")
        return {"total_matches": 7}

    monkeypatch.setitem(tools_module.HANDLERS, "search_events", flaky)
    session = RecordingSession()

    first = run_tool(session, "case-1", "search_events", {"host_id": "WS01"})
    second = run_tool(session, "case-1", "search_events", {"query": "downloads"})

    assert "error" in first
    assert second["total_matches"] == 7


def test_a_tool_error_also_rolls_back(monkeypatch):
    def raise_tool_error(db, case_id, args):
        raise tools_module.ToolError("No host called 'WS01'")

    monkeypatch.setitem(tools_module.HANDLERS, "search_events", raise_tool_error)
    session = RecordingSession()

    result = run_tool(session, "case-1", "search_events", {})

    assert session.rolled_back == 1
    assert result["error"] == "No host called 'WS01'"


# --------------------------------------------------------------------------
# Host resolution: a model passes whatever the analyst said.
# --------------------------------------------------------------------------


def test_a_host_name_resolves_to_its_id():
    """The model said "WS01"; the search layer needs the UUID."""
    session = RecordingSession(hosts=[FakeHost("11111111-1111-1111-1111-111111111111", "WS01")])

    host = tools_module._resolve_host(session, "case-1", "WS01")

    assert host.id == "11111111-1111-1111-1111-111111111111"


def test_host_matching_ignores_case_and_local_suffix():
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    assert tools_module._resolve_host(session, "case-1", "ws01.local").id == "id-1"


def test_a_host_id_still_resolves():
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    assert tools_module._resolve_host(session, "case-1", "id-1").id == "id-1"


def test_an_unknown_host_names_the_real_ones():
    """The model must be able to correct itself without a stack trace."""
    session = RecordingSession(hosts=[FakeHost("id-1", "victoria"), FakeHost("id-2", "WS-07")])

    with pytest.raises(tools_module.ToolError) as excinfo:
        tools_module._resolve_host(session, "case-1", "WS01")

    message = str(excinfo.value)
    assert "victoria" in message and "WS-07" in message
    assert "list_hosts" in message


def test_no_host_means_search_everything():
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    assert tools_module._resolve_host(session, "case-1", None) is None
    assert tools_module._resolve_host(session, "case-1", "  ") is None


def test_search_events_never_passes_a_raw_name_as_host_id(monkeypatch):
    """The bug that aborted the transaction: an unresolved string reaching a UUID column."""
    captured = {}

    def fake_search(case_id, params, db=None):
        captured.update(params)
        return (0, [], [], {})

    monkeypatch.setattr("app.services.search_service.search_events_v2", fake_search)
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    session = RecordingSession(hosts=[FakeHost("11111111-1111-1111-1111-111111111111", "WS01")])

    tools_module.tool_search_events(session, "case-1", {"query": "downloads", "host_id": "WS01"})

    assert captured["host_id"] == "11111111-1111-1111-1111-111111111111"


def test_persistence_gets_the_canonical_host_name(monkeypatch):
    """That service filters by name, so an id from the model must be translated."""
    captured = {}

    def fake(db, case_id, params):
        captured.update(params)
        return {"items": [], "counts": {}}

    monkeypatch.setattr("app.services.startup_persistence.list_startup_persistence_items", fake)
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    tools_module.tool_list_persistence(session, "case-1", {"host": "id-1"})

    assert captured["host"] == ["WS01"]
