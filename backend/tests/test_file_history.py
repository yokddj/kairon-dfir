"""A single MFT record is a snapshot (its 8 MACB fields describe what is
currently known about a file, not eight distinct observed moments), while
each USN Journal record is a discrete, reason-coded event captured as it
happened. get_file_history (app/api/routes_search.py) merges both into one
chronological view of a specific file's lifecycle, labeled by source, without
pretending to deduplicate one against the other."""

from __future__ import annotations

import pytest

from app.api import routes_search
from app.api.routes_search import get_file_history
from fastapi import HTTPException


def _term_value(filters: list[dict], field: str):
    for entry in filters:
        term = entry.get("term")
        if term and field in term:
            return term[field]
    return None


class _FakeClient:
    def __init__(self, mft_docs: list[dict], usn_docs: list[dict]):
        self.mft_docs = mft_docs
        self.usn_docs = usn_docs
        self.queries: list[dict] = []

    def search(self, *, index, body, params=None):  # noqa: ANN001
        self.queries.append(body)
        filters = body["query"]["bool"]["filter"]
        artifact_type = _term_value(filters, "artifact.type")
        docs = self.mft_docs if artifact_type == "mft" else self.usn_docs if artifact_type == "usn" else []
        return {"hits": {"hits": [{"_id": str(i), "_source": doc} for i, doc in enumerate(docs)]}}


def _mft_doc(**mft_overrides):
    return {
        "evidence_id": "ev-1",
        "host": {"name": "HOST-01"},
        "file": {"extension": ".ps1"},
        "mft": {"entry_number": "42", "in_use": True, **mft_overrides},
    }


def _usn_doc(*, event_type: str, timestamp: str, reason: str = ""):
    return {
        "evidence_id": "ev-1",
        "host": {"name": "HOST-01"},
        "@timestamp": timestamp,
        "event": {"type": event_type},
        "usn": {"timestamp": timestamp, "reasons": reason, "file_reference": "5-1"},
    }


def test_file_history_merges_mft_macb_points_and_usn_events_chronologically(monkeypatch: pytest.MonkeyPatch) -> None:
    mft_docs = [_mft_doc(si_created="2024-01-01T00:00:00+00:00", si_changed="2024-01-03T00:00:00+00:00")]
    usn_docs = [
        _usn_doc(event_type="file_created", timestamp="2024-01-01T00:00:00+00:00", reason="FileCreate"),
        _usn_doc(event_type="file_deleted", timestamp="2024-01-05T00:00:00+00:00", reason="FileDelete"),
    ]
    fake_client = _FakeClient(mft_docs, usn_docs)
    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda: fake_client)
    monkeypatch.setattr(routes_search, "index_exists", lambda client, index: True)
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case-1")

    result = get_file_history("case-1", path=r"C:\Users\Public\evil.ps1")

    assert result["mft_records"] == 1
    assert result["usn_records"] == 2
    timestamps = [event["timestamp"] for event in result["events"]]
    assert timestamps == sorted(timestamps)
    labels_by_timestamp = {event["timestamp"]: event["label"] for event in result["events"]}
    assert labels_by_timestamp["2024-01-03T00:00:00+00:00"] == "MFT entry changed (SI)"
    assert labels_by_timestamp["2024-01-05T00:00:00+00:00"] == "USN: File deleted"
    sources = {event["source"] for event in result["events"]}
    assert sources == {"mft", "usn"}


def test_file_history_only_emits_populated_macb_fields() -> None:
    from app.api.routes_search import _MFT_MACB_EVENT_LABELS

    assert set(_MFT_MACB_EVENT_LABELS) == {
        "si_created",
        "si_modified",
        "si_accessed",
        "si_changed",
        "fn_created",
        "fn_modified",
        "fn_accessed",
        "fn_changed",
    }


def test_file_history_requires_a_path() -> None:
    with pytest.raises(HTTPException) as exc_info:
        get_file_history("case-1", path="   ")

    assert exc_info.value.status_code == 400


def test_file_history_returns_empty_when_index_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda: _FakeClient([], []))
    monkeypatch.setattr(routes_search, "index_exists", lambda client, index: False)
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case-1")

    result = get_file_history("case-1", path=r"C:\missing.txt")

    assert result == {"path": r"C:\missing.txt", "events": [], "mft_records": 0, "usn_records": 0}


def test_file_history_scopes_queries_by_case_path_host_and_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeClient([], [])
    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda: fake_client)
    monkeypatch.setattr(routes_search, "index_exists", lambda client, index: True)
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case-1")

    get_file_history("case-1", path=r"C:\Users\alice\report.docx", host="HOST-01", evidence_id="ev-9")

    assert len(fake_client.queries) == 2
    for body in fake_client.queries:
        filters = body["query"]["bool"]["filter"]
        assert _term_value(filters, "case_id") == "case-1"
        assert _term_value(filters, "file.path") == r"C:\Users\alice\report.docx"
        assert _term_value(filters, "host.name") == "HOST-01"
        assert _term_value(filters, "evidence_id") == "ev-9"
