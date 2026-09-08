from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.models.event_marking import EventMarking
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.event_marking import EventMarkingBulkItem, EventMarkingBulkStatusUpdate, EventMarkingCreate, EventMarkingUpdate
from app.services import event_markings


class _FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def first(self):
        return self.items[0] if self.items else None

    def all(self):
        return list(self.items)


class _FakeDb:
    def __init__(self):
        self.markings: list[EventMarking] = []
        self.findings: list[Finding] = []

    def query(self, model):
        if model is EventMarking:
            return _FakeQuery(self.markings)
        if model is Finding:
            return _FakeQuery(self.findings)
        return _FakeQuery([])

    def get(self, model, identifier):
        if model is EventMarking:
            return next((item for item in self.markings if item.id == identifier), None)
        if model is Finding:
            return next((item for item in self.findings if item.id == identifier), None)
        return None

    def add(self, item):
        if isinstance(item, EventMarking) and item not in self.markings:
            self.markings.append(item)
        if isinstance(item, Finding) and item not in self.findings:
            self.findings.append(item)

    def commit(self):
        return None

    def refresh(self, item):
        if not getattr(item, "id", None):
            item.id = f"id-{len(self.markings) + len(self.findings)}"

    def delete(self, item):
        if item in self.markings:
            self.markings.remove(item)


def _event(event_id="evt-1"):
    return {
        "id": event_id,
        "event_id": event_id,
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "stable_event_id": "stable-1",
        "@timestamp": "2024-03-22T12:00:00Z",
        "artifact": {"type": "windows_event"},
        "host": {"name": "hosta"},
    }


def test_create_update_delete_event_marking(monkeypatch):
    monkeypatch.setattr(event_markings, "fetch_event_by_id", lambda *args, **kwargs: _event())
    db = _FakeDb()

    created = event_markings.upsert_event_marking(db, "evt-1", EventMarkingCreate(case_id="case-1", status="suspicious", labels=["triage"], note="needs review"))
    assert created["status"] == "suspicious"
    assert created["labels"] == ["triage"]
    assert created["note"] == "needs review"
    assert created["event_id"] == "evt-1"
    assert created["evidence_id"] == "ev-1"

    updated = event_markings.update_event_marking(db, created["id"], EventMarkingUpdate(status="reviewed", labels=["done"], note="reviewed"))
    assert updated["status"] == "reviewed"
    assert updated["labels"] == ["done"]

    event_markings.delete_event_marking(db, created["id"])
    assert db.markings == []


def test_duplicate_marking_updates_existing(monkeypatch):
    monkeypatch.setattr(event_markings, "fetch_event_by_id", lambda *args, **kwargs: _event())
    db = _FakeDb()

    first = event_markings.upsert_event_marking(db, "evt-1", EventMarkingCreate(case_id="case-1", status="suspicious"))
    second = event_markings.upsert_event_marking(db, "evt-1", EventMarkingCreate(case_id="case-1", status="important"))

    assert len(db.markings) == 1
    assert first["id"] == second["id"]
    assert second["status"] == "important"


def test_attach_marking_to_finding(monkeypatch):
    monkeypatch.setattr(event_markings, "fetch_event_by_id", lambda *args, **kwargs: _event())
    db = _FakeDb()
    finding = Finding(case_id="case-1", title="Finding", severity=FindingSeverity.medium, status=FindingStatus.new, source="analyst")
    finding.id = "finding-1"
    db.add(finding)
    created = event_markings.upsert_event_marking(db, "evt-1", EventMarkingCreate(case_id="case-1", status="important"))

    attached = event_markings.attach_marking_to_finding(db, created["id"], "finding-1")

    assert attached["finding_id"] == "finding-1"
    assert finding.event_ids == ["evt-1"]
    assert finding.related_event_ids == ["evt-1"]
    assert finding.related_evidence_ids == ["ev-1"]


def test_invalid_status_rejected():
    with pytest.raises(HTTPException):
        event_markings.upsert_event_marking(_FakeDb(), "evt-1", EventMarkingCreate(case_id="case-1", status="bad"))


# --------------------------------------------------------------------------
# Bulk status updates: hiding a page of timeline rows must not cost one
# OpenSearch round trip per row, and must not duplicate a marking that
# already exists for an event.
# --------------------------------------------------------------------------


class _BulkFakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.items)


class _BulkFakeDb:
    def __init__(self, markings=None):
        self.markings: list[EventMarking] = list(markings or [])

    def query(self, model):
        return _BulkFakeQuery(self.markings)

    def add(self, item):
        if item not in self.markings:
            self.markings.append(item)

    def commit(self):
        return None

    def refresh(self, item):
        if not getattr(item, "id", None):
            item.id = f"id-{len(self.markings)}"


def test_bulk_set_marking_status_never_calls_opensearch(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("bulk marking must not look up events in OpenSearch")

    monkeypatch.setattr(event_markings, "fetch_event_by_id", boom)
    db = _BulkFakeDb()

    payload = EventMarkingBulkStatusUpdate(
        status="not_relevant",
        items=[
            EventMarkingBulkItem(event_id="evt-1", host="WS01", artifact_type="prefetch", evidence_id="ev-1"),
            EventMarkingBulkItem(event_id="evt-2", host="WS01", artifact_type="amcache"),
        ],
    )

    results = event_markings.bulk_set_marking_status(db, "case-1", payload)

    assert {row["event_id"] for row in results} == {"evt-1", "evt-2"}
    assert all(row["status"] == "not_relevant" for row in results)
    assert len(db.markings) == 2


def test_bulk_set_marking_status_updates_an_existing_marking_in_place(monkeypatch):
    monkeypatch.setattr(event_markings, "fetch_event_by_id", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no ES lookup expected")))
    existing = EventMarking(id="marking-1", case_id="case-1", event_id="evt-1", status="unreviewed", host="WS01")
    db = _BulkFakeDb(markings=[existing])

    results = event_markings.bulk_set_marking_status(
        db, "case-1", EventMarkingBulkStatusUpdate(status="not_relevant", items=[EventMarkingBulkItem(event_id="evt-1")]),
    )

    assert len(db.markings) == 1
    assert results[0]["id"] == "marking-1"
    assert results[0]["status"] == "not_relevant"
    assert results[0]["host"] == "WS01", "metadata from the earlier marking must survive when the bulk item carries none"


def test_bulk_set_marking_status_rejects_invalid_status():
    with pytest.raises(HTTPException):
        event_markings.bulk_set_marking_status(
            _BulkFakeDb(), "case-1", EventMarkingBulkStatusUpdate(status="bad", items=[EventMarkingBulkItem(event_id="evt-1")]),
        )


def test_bulk_set_marking_status_with_no_items_is_a_noop():
    assert event_markings.bulk_set_marking_status(_BulkFakeDb(), "case-1", EventMarkingBulkStatusUpdate(status="not_relevant", items=[])) == []
