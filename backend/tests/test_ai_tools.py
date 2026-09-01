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
    result = tools_module.tool_list_persistence(None, "case-1", {"host": "WS-01", "suspicious_only": True})

    assert captured["host"] == ["WS-01"]
    assert captured["suspicious_only"] is True
    assert result["summary"]["total"] == 1
