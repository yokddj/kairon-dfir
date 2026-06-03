from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.models.event_marking import EventMarking
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.event_marking import EventMarkingCreate, EventMarkingUpdate
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
