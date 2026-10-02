"""The tool layer: aggregates first, hard caps, and no crash reaches the model."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.detection_result import DetectionResult
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

    # open_in_search is deliberately added on top of the declared projection.
    assert set(event) <= set(tools_module.EVENT_KEYS) | {"open_in_search"}
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


# --------------------------------------------------------------------------
# Knowing what the case contains. Guessing at artifact types and reading the
# resulting zero as absence is the failure this prevents.
# --------------------------------------------------------------------------


class FakeOpenSearch:
    def __init__(self, payload, exists=True):
        self.payload = payload
        self.exists = exists
        self.bodies: list[dict] = []

    def search(self, index=None, body=None, params=None, **kwargs):
        self.bodies.append(body)
        return self.payload


def _patch_opensearch(monkeypatch, client):
    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda **kw: client)
    monkeypatch.setattr("app.core.opensearch.get_events_index", lambda case_id=None: "idx")
    monkeypatch.setattr("app.core.opensearch.index_exists", lambda c, i: client.exists)


AGG_PAYLOAD = {
    "hits": {"total": {"value": 23683}},
    "aggregations": {
        "artifact_type": {"buckets": [{"key": "linux_auth", "doc_count": 23683}]},
        "parser": {"buckets": [{"key": "linux_auth_raw", "doc_count": 23683}]},
        "event_type": {"buckets": [{"key": "login_failure", "doc_count": 900}]},
        "host": {"buckets": [{"key": "victoria", "doc_count": 23683}]},
        "severity": {"buckets": [{"key": "medium", "doc_count": 12}]},
    },
}


def test_describe_case_counts_the_whole_index_not_a_page(monkeypatch):
    client = FakeOpenSearch(AGG_PAYLOAD)
    _patch_opensearch(monkeypatch, client)

    result = tools_module.tool_describe_case(None, "case-1", {})

    assert result["indexed"] is True
    assert result["total_events"] == 23683
    assert result["artifact_types"] == {"linux_auth": 23683}
    # size 0 means aggregations only: no documents are shipped back.
    assert client.bodies[0]["size"] == 0
    assert client.bodies[0]["track_total_hits"] is True


def test_describe_case_warns_that_absent_artifacts_explain_zeros(monkeypatch):
    _patch_opensearch(monkeypatch, FakeOpenSearch(AGG_PAYLOAD))

    guidance = tools_module.tool_describe_case(None, "case-1", {})["how_to_read_this"]

    assert "never collected" in guidance
    assert "NOT evidence" in guidance


def test_describe_case_reports_an_unindexed_case_plainly(monkeypatch):
    _patch_opensearch(monkeypatch, FakeOpenSearch(AGG_PAYLOAD, exists=False))

    result = tools_module.tool_describe_case(None, "case-1", {})

    assert result["indexed"] is False
    assert "no search will return anything" in result["message"]


def test_a_zero_search_explains_what_the_case_actually_holds(monkeypatch):
    """The reported failure: zeros presented as proof nothing was downloaded."""
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (0, [], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    _patch_opensearch(monkeypatch, FakeOpenSearch(AGG_PAYLOAD))

    result = tools_module.tool_search_events(None, "case-1", {"query": "file.extension:crdownload"})

    assert result["total_matches"] == 0
    guidance = result["zero_result_guidance"]
    assert "linux_auth" in guidance, "it must name what the case does contain"
    assert "never collected" in guidance


def test_a_non_zero_search_carries_no_zero_guidance(monkeypatch):
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (5, [{"id": "e1"}], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))

    result = tools_module.tool_search_events(None, "case-1", {"query": "x"})

    assert result["zero_result_guidance"] is None


def test_zero_guidance_survives_a_broken_index(monkeypatch):
    """Guidance is a bonus; failing to produce it must not fail the search."""
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (0, [], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    monkeypatch.setattr(
        "app.core.opensearch.get_opensearch_client",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("cluster down")),
    )
    session = RecordingSession()

    result = tools_module.tool_search_events(session, "case-1", {"query": "x"})

    assert result["total_matches"] == 0
    assert "describe_case" in result["zero_result_guidance"]


# --------------------------------------------------------------------------
# Downloads come from Mark of the Web, not from guessing at folder paths.
# --------------------------------------------------------------------------


def test_downloads_use_mark_of_the_web(monkeypatch):
    captured = {}

    def fake(db, case_id, params):
        captured.update(params)
        return {
            "total": 2,
            "summary": {"total": 2},
            "items": [
                {
                    "file_name": "installer.exe",
                    "host_url": "https://example.test/installer.exe",
                    "referrer_url": "https://example.test/",
                    "zone": "Internet",
                    "risk_score": 70,
                    "bulky": "x" * 9000,
                }
            ],
        }

    monkeypatch.setattr("app.services.motw.list_motw_items", fake)
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (0, [], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))

    result = tools_module.tool_list_downloads(session, "case-1", {"host": "WS01"})

    assert result["total_downloads"] == 2
    assert captured["host"] == ["WS01"]
    entry = result["downloads"][0]
    assert entry["host_url"] == "https://example.test/installer.exe"
    assert "bulky" not in entry, "unmodelled fields must not reach the model"
    assert result["note"] is None


def test_no_downloads_says_what_that_does_and_does_not_prove(monkeypatch):
    monkeypatch.setattr(
        "app.services.motw.list_motw_items",
        lambda db, case_id, params: {"total": 0, "summary": {}, "items": []},
    )
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (0, [], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    session = RecordingSession(hosts=[])

    result = tools_module.tool_list_downloads(session, "case-1", {})

    assert result["total_downloads"] == 0
    assert "describe_case" in result["note"]
    assert "not the same as nothing having been downloaded" in result["note"]


def test_browser_downloads_are_found_without_a_filesystem_artifact(monkeypatch):
    """A case with browser history but no MFT still answers the question.

    This is the reported failure: the assistant reported no downloads on a host
    whose browser history held file_downloaded events all along.
    """
    monkeypatch.setattr(
        "app.services.motw.list_motw_items",
        lambda db, case_id, params: {"total": 0, "summary": {}, "items": []},
    )
    captured = {}

    def fake_search(case_id, params, db=None):
        captured.update(params)
        return (
            3,
            [{"id": "e1", "host": "WS01", "user": "mshutter", "event_type": "file_downloaded",
              "title": "Browser download", "risk_score": 65}],
            [],
            {},
        )

    monkeypatch.setattr("app.services.search_service.search_events_v2", fake_search)
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    result = tools_module.tool_list_downloads(session, "case-1", {"host": "WS01"})

    assert result["total_downloads"] == 3
    assert result["by_source"] == {"mark_of_the_web": 0, "browser_history": 3}
    assert result["downloads"][0]["event_type"] == "file_downloaded"
    assert captured["q"] == "event.type:file_downloaded"
    assert result["note"] is None, "downloads were found, so there is nothing to caveat"


def test_a_failing_browser_lookup_does_not_hide_motw_results(monkeypatch):
    """One source breaking must not turn the other source's findings into zero."""
    monkeypatch.setattr(
        "app.services.motw.list_motw_items",
        lambda db, case_id, params: {
            "total": 1, "summary": {}, "items": [{"file_name": "a.exe", "host": "WS01"}],
        },
    )
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (_ for _ in ()).throw(RuntimeError("index missing")),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    result = tools_module.tool_list_downloads(session, "case-1", {"host": "WS01"})

    assert result["total_downloads"] == 1
    assert any("Browser history lookup failed" in w for w in result["warnings"])
    assert session.rolled_back == 1


# --------------------------------------------------------------------------
# Reading one event in full before citing it. Search rows are summaries; this
# is the tool that must be called before quoting a specific field value.
# --------------------------------------------------------------------------


RAW_EVENT = {
    "id": "evt-1",
    "@timestamp": "2026-08-01T10:00:00Z",
    "case_id": "case-1",
    "evidence_id": "ev-1",
    "host": {"name": "WS01"},
    "user": {"name": "mshutter"},
    "artifact": {"type": "browser", "parser": "browser_chromium_history"},
    "event": {"type": "file_downloaded"},
    "risk_score": 65,
    "url": {"full": "https://file.io/abc", "domain": "file.io"},
    "file": {"name": "factura.iso", "path": "C:\\Users\\mshutter\\Downloads\\factura.iso"},
}


def test_get_event_detail_returns_the_searchable_fields(monkeypatch):
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: dict(RAW_EVENT))
    monkeypatch.setattr(
        "app.services.search_service.event_context",
        lambda db, case_id, event_id: {"related_findings": [], "related_detections": [], "counts": {}},
    )

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "evt-1"})

    assert result["found"] is True
    assert result["fields"]["url.domain"] == "file.io"
    assert result["fields"]["file.path"] == "C:\\Users\\mshutter\\Downloads\\factura.iso"
    assert result["fields"]["host.name"] == "WS01"
    assert result["note"] is None


def test_get_event_detail_accepts_source_event_id_as_an_alias():
    with pytest.raises(tools_module.ToolError):
        tools_module.tool_get_event_detail(None, "case-1", {})


def test_an_unknown_event_id_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: None)

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "does-not-exist"})

    assert result["found"] is False
    assert "re-run the search" in result["note"]


def test_related_findings_and_detections_are_surfaced_with_a_warning(monkeypatch):
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: dict(RAW_EVENT))
    monkeypatch.setattr(
        "app.services.search_service.event_context",
        lambda db, case_id, event_id: {
            "related_findings": [{"id": "f1", "title": "Suspicious download"}],
            "related_detections": [],
            "counts": {"related_findings": 1, "related_detections": 0},
        },
    )

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "evt-1"})

    assert result["related_findings"][0]["title"] == "Suspicious download"
    assert "already recorded findings and/or detections" in result["note"]


def test_empty_fields_are_dropped_not_shown_as_nulls(monkeypatch):
    sparse = {"id": "evt-2", "host": {"name": "WS01"}}
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: dict(sparse))
    monkeypatch.setattr(
        "app.services.search_service.event_context",
        lambda db, case_id, event_id: {"related_findings": [], "related_detections": [], "counts": {}},
    )

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "evt-2"})

    assert result["fields"] == {"host.name": "WS01"}


def test_a_long_field_value_is_clipped(monkeypatch):
    long_cmd = {"id": "evt-3", "process": {"command_line": "x" * 5000}}
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: dict(long_cmd))
    monkeypatch.setattr(
        "app.services.search_service.event_context",
        lambda db, case_id, event_id: {"related_findings": [], "related_detections": [], "counts": {}},
    )

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "evt-3"})

    assert len(result["fields"]["process.command_line"]) <= tools_module.MAX_FIELD_CHARS


def test_get_event_detail_is_advertised_and_wired():
    assert "get_event_detail" in tools_module.HANDLERS
    spec = next(s for s in tools_module.TOOL_SPECS if s["name"] == "get_event_detail")
    assert "event_id" in spec["input_schema"]["properties"]
    assert spec["input_schema"]["required"] == ["event_id"]


# --------------------------------------------------------------------------
# Pivot links: the model must never construct its own URL. Every row that
# carries an event id gets a ready-made link to open it in Search.
# --------------------------------------------------------------------------


def test_event_pivot_url_points_at_search_with_the_exact_id():
    url = tools_module._event_pivot_url("case-1", "evt-abc")

    assert url == "/cases/case-1/search?q=event_id%3Aevt-abc&selected=evt-abc"


def test_no_pivot_url_without_an_event_id():
    assert tools_module._event_pivot_url("case-1", None) is None
    assert tools_module._event_pivot_url("case-1", "") is None


def test_pivot_url_encodes_special_characters_safely():
    url = tools_module._event_pivot_url("case-1", "evt with spaces&stuff")

    assert " " not in url and "&stuff" not in url.split("selected=")[0].split("q=")[1]


def test_search_events_rows_carry_a_pivot_link(monkeypatch):
    rows = [{"id": "evt-1", "host": "WS01"}]
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (1, rows, [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))

    result = tools_module.tool_search_events(None, "case-1", {"query": "x"})

    assert result["events"][0]["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-1&selected=evt-1"


def test_timeline_entries_carry_a_pivot_link(monkeypatch):
    monkeypatch.setattr(
        "app.services.timeline_service.build_lightweight_timeline_response",
        lambda db, case_id, params: {"total": 1, "items": [{"id": "evt-2", "host": "WS01"}]},
    )

    result = tools_module.tool_get_timeline(None, "case-1", {})

    assert result["entries"][0]["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-2&selected=evt-2"


def test_get_event_detail_carries_a_pivot_link(monkeypatch):
    monkeypatch.setattr("app.core.opensearch.fetch_event_by_id", lambda *a, **k: dict(RAW_EVENT))
    monkeypatch.setattr(
        "app.services.search_service.event_context",
        lambda db, case_id, event_id: {"related_findings": [], "related_detections": [], "counts": {}},
    )

    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "evt-1"})

    assert result["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-1&selected=evt-1"


def test_browser_download_rows_carry_a_pivot_link_but_motw_rows_do_not(monkeypatch):
    """list_motw_items rows carry no event id today, so they get no link --
    inventing one would point at something that cannot resolve."""
    monkeypatch.setattr(
        "app.services.motw.list_motw_items",
        lambda db, case_id, params: {
            "total": 1, "summary": {}, "items": [{"file_name": "a.exe", "host": "WS01"}],
        },
    )
    monkeypatch.setattr(
        "app.services.search_service.search_events_v2",
        lambda case_id, params, db=None: (1, [{"id": "evt-3", "event_type": "file_downloaded"}], [], {}),
    )
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    result = tools_module.tool_list_downloads(session, "case-1", {"host": "WS01"})

    motw_row, browser_row = result["downloads"]
    assert "open_in_search" not in motw_row
    assert browser_row["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-3&selected=evt-3"


# --------------------------------------------------------------------------
# Commands actually executed -- distinct from search_events, which is a
# generic event search and does not de-duplicate or risk-score commands.
# --------------------------------------------------------------------------


COMMAND_ITEM = {
    "id": "sha1-synthetic-dedupe-key",
    "source_event_id": "evt-cmd-1",
    "timestamp": "2026-08-01T10:00:00Z",
    "host": "WS01",
    "user": "mshutter",
    "command": "powershell -ep bypass -nop -w hidden -File c:\\f\\p.ps1",
    "shell_family": "powershell",
    "launcher": "powershell.exe",
    "source_type": "sysmon_1",
    "risk_score": 70,
    "risk_reasons": ["execution policy bypass", "hidden window"],
    "confidence": "high",
}


def test_search_command_history_reports_totals_and_summary(monkeypatch):
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {
            "total": 42,
            "items": [COMMAND_ITEM],
            "summary": {"commands_total": 42, "suspicious_total": 5},
            "warnings": [],
        },
    )

    result = tools_module.tool_search_command_history(None, "case-1", {"query": "powershell"})

    assert result["total_matches"] == 42
    assert result["summary"]["suspicious_total"] == 5
    assert len(result["commands"]) == 1
    assert "42 commands matched" in result["note"]


def test_search_command_history_uses_the_real_event_id_not_the_dedupe_hash(monkeypatch):
    """The row's own "id" is a sha1 of case+event+command for de-duplication,
    not a document id -- a pivot built from it would point at nothing."""
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {"total": 1, "items": [COMMAND_ITEM], "summary": {}, "warnings": []},
    )

    command = tools_module.tool_search_command_history(None, "case-1", {})["commands"][0]

    assert command["id"] == "evt-cmd-1"
    assert command["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-cmd-1&selected=evt-cmd-1"


def test_search_command_history_resolves_a_host_name_to_its_display_name(monkeypatch):
    captured = {}

    def fake(case_id, params):
        captured.update(params)
        return {"total": 0, "items": [], "summary": {}, "warnings": []}

    monkeypatch.setattr("app.services.command_history.get_command_history", fake)
    session = RecordingSession(hosts=[FakeHost("host-1", "WS01")])

    tools_module.tool_search_command_history(session, "case-1", {"host": "host-1"})

    assert captured["host"] == "WS01"


def test_search_command_history_projects_away_process_and_raw_payload(monkeypatch):
    """Only the summarised fields reach the model; get_event_detail is where
    full process context and raw payloads belong."""
    bulky = {
        **COMMAND_ITEM,
        "raw_payload": "x" * 9000,
        "process": {"name": "powershell.exe", "pid": 4321, "command_line": "..."},
        "parent_process": {"name": "explorer.exe"},
    }
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {"total": 1, "items": [bulky], "summary": {}, "warnings": []},
    )

    command = tools_module.tool_search_command_history(None, "case-1", {})["commands"][0]

    assert "raw_payload" not in command
    assert "process" not in command
    assert "parent_process" not in command


def test_search_command_history_passes_through_suspicious_and_risk_filters(monkeypatch):
    captured = {}

    def fake(case_id, params):
        captured.update(params)
        return {"total": 0, "items": [], "summary": {}, "warnings": []}

    monkeypatch.setattr("app.services.command_history.get_command_history", fake)

    tools_module.tool_search_command_history(None, "case-1", {"suspicious_only": True, "risk_min": 60})

    assert captured["only_suspicious"] is True
    assert captured["risk_min"] == 60


def test_no_note_when_every_match_was_returned(monkeypatch):
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {"total": 1, "items": [COMMAND_ITEM], "summary": {}, "warnings": []},
    )

    result = tools_module.tool_search_command_history(None, "case-1", {})

    assert result["note"] is None


MEMORY_COMMAND_ITEM = {
    **COMMAND_ITEM,
    "id": "memory-command:ev-1:run-1:ent-1:4321",
    "source_event_id": "memory-command:ev-1:run-1:ent-1:4321",
    "source_type": "memory",
}


def test_a_memory_sourced_command_gets_no_pivot_link(monkeypatch):
    """The reported failure: source_event_id mirrors a synthetic key with no
    backing document for memory-recovered commands, and a link built from it
    resolved to nothing."""
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {"total": 1, "items": [MEMORY_COMMAND_ITEM], "summary": {}, "warnings": []},
    )

    result = tools_module.tool_search_command_history(None, "case-1", {})
    command = result["commands"][0]

    assert "open_in_search" not in command
    assert any("memory image" in warning for warning in result["warnings"])


def test_a_disk_sourced_command_still_gets_its_pivot_link_alongside_a_memory_one(monkeypatch):
    """Fixing the memory case must not cost the disk-sourced rows their links."""
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {
            "total": 2, "items": [COMMAND_ITEM, MEMORY_COMMAND_ITEM], "summary": {}, "warnings": [],
        },
    )

    commands = tools_module.tool_search_command_history(None, "case-1", {})["commands"]

    disk_row = next(c for c in commands if c["id"] == "evt-cmd-1")
    memory_row = next(c for c in commands if "open_in_search" not in c)
    assert disk_row["open_in_search"] == "/cases/case-1/search?q=event_id%3Aevt-cmd-1&selected=evt-cmd-1"
    assert memory_row["source_type"] == "memory"


def test_no_memory_warning_when_every_row_is_disk_sourced(monkeypatch):
    monkeypatch.setattr(
        "app.services.command_history.get_command_history",
        lambda case_id, params: {"total": 1, "items": [COMMAND_ITEM], "summary": {}, "warnings": []},
    )

    result = tools_module.tool_search_command_history(None, "case-1", {})

    assert result["warnings"] == []


def test_search_command_history_is_advertised_and_wired():
    assert "search_command_history" in tools_module.HANDLERS
    spec = next(s for s in tools_module.TOOL_SPECS if s["name"] == "search_command_history")
    assert set(spec["input_schema"]["properties"]) >= {"query", "host", "risk_min", "suspicious_only"}


# --------------------------------------------------------------------------
# The process tree: who launched this, what it launched. Resolves the same
# way Execution Story does, and must never present a relaxed match as exact.
# --------------------------------------------------------------------------


def _node(**overrides) -> dict:
    base = {
        "id": "guid-1", "pid": 6996, "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -enc ABC", "user": "alex", "host": "WS01",
        "risk_score": 40,
    }
    base.update(overrides)
    return base


def _case_row(case_id="case-1"):
    return type("FakeCase", (), {"id": case_id})()


def _patch_story(monkeypatch, story: dict, case_row=None):
    import app.services.ai.tools as module

    session = RecordingSession(hosts=[])
    session.get = lambda model, ident: case_row if model.__name__ == "Case" else None
    session.query = lambda model, *a, **k: session
    session.filter = lambda *a, **k: session
    session.order_by = lambda *a, **k: session
    session.all = lambda: []
    monkeypatch.setattr("app.services.process_tree.build_execution_story", lambda *a, **k: story)
    return session


def test_a_resolved_process_returns_its_family_and_how_it_was_matched(monkeypatch):
    story = {
        "target": _node(),
        "story": {"summary": "This powershell.exe PID 6996 was launched by winword.exe."},
        "parents": [_node(id="guid-parent", pid=100, name="winword.exe")],
        "children": [_node(id="guid-child", pid=5528, name="powershell.exe")],
        "siblings": [],
        "quality": {
            "exact_story": False,
            "identity_resolution": {
                "focus_match": "name",
                "focus_match_explanation": "No node matched that PID or event, so this was matched by process name alone.",
            },
            "warnings": ["No parent process events were found for the selected process."],
        },
    }
    session = _patch_story(monkeypatch, story, _case_row())

    result = tools_module.tool_get_process_tree(session, "case-1", {"query": "powershell.exe"})

    assert result["found"] is True
    assert result["exact"] is False
    assert result["match_method"] == "name"
    assert "matched by process name alone" in result["match_explanation"]
    assert result["target"]["pid"] == 6996
    assert result["parents"][0]["name"] == "winword.exe"
    assert result["children"][0]["pid"] == 5528


def test_requires_at_least_one_identity_argument():
    with pytest.raises(tools_module.ToolError):
        tools_module.tool_get_process_tree(None, "case-1", {})


def test_pid_must_be_numeric():
    with pytest.raises(tools_module.ToolError):
        tools_module.tool_get_process_tree(None, "case-1", {"pid": "not-a-number"})


def test_an_unknown_case_is_reported(monkeypatch):
    session = RecordingSession(hosts=[])
    session.get = lambda model, ident: None
    with pytest.raises(tools_module.ToolError):
        tools_module.tool_get_process_tree(session, "case-1", {"pid": 123})


def test_no_match_offers_the_nearest_candidates_by_name(monkeypatch):
    story = {
        "target": None,
        "quality": {"identity_resolution": {"candidates": [_node(id="c1", name="powershell.exe")]}, "warnings": []},
    }
    session = _patch_story(monkeypatch, story, _case_row())

    result = tools_module.tool_get_process_tree(session, "case-1", {"query": "powersh"})

    assert result["found"] is False
    assert result["candidates"][0]["name"] == "powershell.exe"
    assert "closest processes" in result["note"]


def test_a_non_process_creation_event_is_explained_not_just_reported_empty(monkeypatch):
    """The lightweight-guidance shape: a real event, but not one that can
    anchor a process tree -- must not read the same as "nothing found"."""
    story = {
        "target": None,
        "event_summary": {"source": "PowerShell ScriptBlock"},
        "candidate_processes": [_node(id="c2", name="powershell.exe")],
        "quality": {"identity_resolution": {}, "warnings": ["This is not an exact process creation event."]},
    }
    session = _patch_story(monkeypatch, story, _case_row())

    result = tools_module.tool_get_process_tree(session, "case-1", {"source_event_id": "evt-9"})

    assert result["found"] is False
    assert "PowerShell ScriptBlock" in result["note"]
    assert result["candidates"][0]["name"] == "powershell.exe"


def test_node_projection_drops_bulky_and_empty_fields():
    node = _node(parent_link_status="linked", parent_fields={"a": 1}, source_events=["e1", "e2"])
    node["path"] = ""

    summary = tools_module._process_node_summary(node)

    assert "parent_link_status" not in summary
    assert "parent_fields" not in summary
    assert "path" not in summary
    assert summary["pid"] == 6996


def test_node_projection_of_none_is_none():
    assert tools_module._process_node_summary(None) is None
    # An empty node is indistinguishable from "no node" and must not become a
    # phantom entry in a parents/children list.
    assert tools_module._process_node_summary({}) is None


def test_get_process_tree_is_advertised_and_wired():
    assert "get_process_tree" in tools_module.HANDLERS
    spec = next(s for s in tools_module.TOOL_SPECS if s["name"] == "get_process_tree")
    assert set(spec["input_schema"]["properties"]) >= {"pid", "process_guid", "source_event_id", "query", "host"}
    assert spec["input_schema"]["required"] == []


# --------------------------------------------------------------------------
# list_detections: raw rule-engine hits, distinct from list_findings (what an
# analyst concluded). Uses a real in-memory session -- the tool builds its own
# SQLAlchemy filters inline rather than delegating to a service, so a fake
# query stub would just test the fake, not the filter logic.
# --------------------------------------------------------------------------


DETECTIONS_CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DETECTIONS_HOST_1_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
DETECTIONS_HOST_2_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _sqlite_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _detection(**overrides) -> DetectionResult:
    base = dict(
        case_id=DETECTIONS_CASE_ID,
        engine="sigma",
        rule_name="Suspicious PowerShell Download",
        severity="high",
        status="new",
        target_type="event",
        host_name="WS01",
        message="powershell.exe downloaded a file",
        risk_score=80,
    )
    base.update(overrides)
    return DetectionResult(**base)


def test_list_detections_reports_totals_and_projects_rows():
    db = _sqlite_session()
    db.add(Case(id=DETECTIONS_CASE_ID, name="Case"))
    db.add(_detection(rule_name="Rule A", severity="high"))
    db.add(_detection(rule_name="Rule B", severity="medium"))
    db.commit()

    result = tools_module.tool_list_detections(db, DETECTIONS_CASE_ID, {})

    assert result["total_matches"] == 2
    assert result["by_severity_in_sample"] == {"high": 1, "medium": 1}
    names = {row["rule_name"] for row in result["detections"]}
    assert names == {"Rule A", "Rule B"}


def test_list_detections_excludes_deleted_and_stale():
    from datetime import UTC, datetime

    db = _sqlite_session()
    db.add(Case(id=DETECTIONS_CASE_ID, name="Case"))
    db.add(_detection(rule_name="Live", status="new"))
    db.add(_detection(rule_name="Stale", status="stale"))
    db.add(_detection(rule_name="Deleted", deleted_at=datetime(2026, 1, 1, tzinfo=UTC)))
    db.commit()

    result = tools_module.tool_list_detections(db, DETECTIONS_CASE_ID, {})

    assert result["total_matches"] == 1
    assert result["detections"][0]["rule_name"] == "Live"


def test_list_detections_filters_by_host_and_severity():
    db = _sqlite_session()
    db.add(Case(id=DETECTIONS_CASE_ID, name="Case"))
    db.add(CaseHost(id=DETECTIONS_HOST_1_ID, case_id=DETECTIONS_CASE_ID, canonical_name="ws01", display_name="WS01"))
    db.add(CaseHost(id=DETECTIONS_HOST_2_ID, case_id=DETECTIONS_CASE_ID, canonical_name="ws02", display_name="WS02"))
    db.add(_detection(rule_name="On WS01", host_name="WS01", severity="critical"))
    db.add(_detection(rule_name="On WS02", host_name="WS02", severity="critical"))
    db.add(_detection(rule_name="Low severity on WS01", host_name="WS01", severity="low"))
    db.commit()

    result = tools_module.tool_list_detections(db, DETECTIONS_CASE_ID, {"host": "WS01", "severity": "critical"})

    assert result["total_matches"] == 1
    assert result["detections"][0]["rule_name"] == "On WS01"


def test_list_detections_free_text_matches_message_and_rule_name():
    db = _sqlite_session()
    db.add(Case(id=DETECTIONS_CASE_ID, name="Case"))
    db.add(_detection(rule_name="Encoded Command", message="base64 encoded payload"))
    db.add(_detection(rule_name="Unrelated Rule", message="nothing notable"))
    db.commit()

    result = tools_module.tool_list_detections(db, DETECTIONS_CASE_ID, {"query": "encoded"})

    assert result["total_matches"] == 1
    assert result["detections"][0]["rule_name"] == "Encoded Command"


def test_list_detections_is_advertised_and_wired():
    assert "list_detections" in tools_module.HANDLERS
    spec = next(s for s in TOOL_SPECS if s["name"] == "list_detections")
    assert set(spec["input_schema"]["properties"]) >= {"host", "severity", "status", "rule_name", "query", "limit"}
    assert spec["input_schema"]["required"] == []


# --------------------------------------------------------------------------
# list_email_artifacts: wraps the product's own email-artifact detector.
# --------------------------------------------------------------------------


def test_email_artifacts_tool_passes_the_host_filter_through_and_projects_rows(monkeypatch):
    captured = {}

    def fake(db, case_id, params):
        captured.update(params)
        return {
            "items": [
                {
                    "id": "email-1",
                    "host": "WS01",
                    "email_artifact_type": "store",
                    "client": "outlook",
                    "account_hint": "alex@example.com",
                    "file_path": "C:\\Users\\alex\\AppData\\Local\\Microsoft\\Outlook\\alex.ost",
                    "file_name": "alex.ost",
                    "url": "",
                    "timestamp": "2026-05-15T10:00:00Z",
                    "risk_score": 20,
                    "confidence": "high",
                    "raw": {"huge": "x" * 5000},
                    "related_indicators": ["a", "b", "c"],
                }
            ],
            "summary": {"total": 1},
            "warnings": [],
            "limitations": ["Mail content is not parsed."],
        }

    monkeypatch.setattr("app.services.email_artifacts.list_email_artifacts", fake)
    session = RecordingSession(hosts=[FakeHost("id-1", "WS01")])

    result = tools_module.tool_list_email_artifacts(session, "case-1", {"host": "WS01", "query": "outlook"})

    assert captured["host"] == ["WS01"]
    assert captured["q"] == "outlook"
    assert result["summary"] == {"total": 1}
    assert result["limitations"] == ["Mail content is not parsed."]
    row = result["items"][0]
    assert row["file_name"] == "alex.ost"
    assert "raw" not in row
    assert "related_indicators" not in row


def test_list_email_artifacts_is_advertised_and_wired():
    assert "list_email_artifacts" in tools_module.HANDLERS
    spec = next(s for s in TOOL_SPECS if s["name"] == "list_email_artifacts")
    assert set(spec["input_schema"]["properties"]) >= {"host", "query", "email_artifact_type", "client", "risk_min", "limit"}
    assert spec["input_schema"]["required"] == []


# --------------------------------------------------------------------------
# search_memory_artifacts: a case with no memory evidence must say so, since
# describe_case (the usual "does this case have X" check) does not cover the
# memory index at all.
# --------------------------------------------------------------------------


def test_memory_artifacts_tool_reports_totals_and_facets(monkeypatch):
    monkeypatch.setattr("app.services.investigation_memory.memory_evidences", lambda *a, **k: [object()])
    monkeypatch.setattr(
        "app.services.investigation_memory.memory_search_results",
        lambda db, case_id, params: {
            "total": 3,
            "facets": {"artifact_family": {"processes": 3}},
            "results": [{"id": "memory:1", "timestamp": "t", "title": "powershell.exe", "summary": "s", "artifact_type": "processes", "artifact_family": "processes", "parser": "volatility"}],
            "warnings": [],
        },
    )

    result = tools_module.tool_search_memory_artifacts(None, "case-1", {"artifact_family": "processes"})

    assert result["total_matches"] == 3
    assert result["facets"] == {"artifact_family": {"processes": 3}}
    assert result["items"][0]["title"] == "powershell.exe"
    assert not any("memory evidence" in warning for warning in result["warnings"])


def test_memory_artifacts_tool_warns_when_the_case_has_no_memory_evidence(monkeypatch):
    monkeypatch.setattr("app.services.investigation_memory.memory_evidences", lambda *a, **k: [])
    monkeypatch.setattr(
        "app.services.investigation_memory.memory_search_results",
        lambda db, case_id, params: {"total": 0, "facets": {}, "results": [], "warnings": []},
    )

    result = tools_module.tool_search_memory_artifacts(None, "case-1", {})

    assert result["total_matches"] == 0
    assert any("no memory evidence" in warning.lower() for warning in result["warnings"])


def test_search_memory_artifacts_is_advertised_and_wired():
    assert "search_memory_artifacts" in tools_module.HANDLERS
    spec = next(s for s in TOOL_SPECS if s["name"] == "search_memory_artifacts")
    assert set(spec["input_schema"]["properties"]) >= {"query", "artifact_family", "process_name", "pid", "evidence_id", "limit"}
    assert spec["input_schema"]["required"] == []
