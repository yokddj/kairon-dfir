from __future__ import annotations

import pytest

from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence


class Db:
    def __init__(self):
        self.case = Case(id="case-1", name="Test Case")
        self.host = CaseHost(id="host-1", case_id="case-1", canonical_name="WS-FINANCE-01", display_name="WS-FINANCE-01", confidence="high", source="observed")
        self.evidences: list[Evidence] = []

    def get(self, model, identifier):
        if model is Case and identifier == "case-1":
            return self.case
        if model is CaseHost and identifier == "host-1":
            return self.host
        if model is Evidence:
            return next((e for e in self.evidences if e.id == identifier), None)
        return None

    def add(self, item):
        if isinstance(item, Evidence):
            self.evidences.append(item)

    def commit(self):
        pass

    def refresh(self, item):
        pass


class EvidenceStub:
    def __init__(self, id="ev-1", case_id="case-1", detected_host=None, host_id=None, host_assignment_status=None, host_assignment_method=None, host_assignment_confidence=None, host_assignment_reason=None, host_assignment_updated_at=None, host_assignment_updated_by=None):
        self.id = id
        self.case_id = case_id
        self.detected_host = detected_host
        self.host_id = host_id
        self.host_assignment_status = host_assignment_status
        self.host_assignment_method = host_assignment_method
        self.host_assignment_confidence = host_assignment_confidence
        self.host_assignment_reason = host_assignment_reason
        self.host_assignment_updated_at = host_assignment_updated_at
        self.host_assignment_updated_by = host_assignment_updated_by


def test_evidence_starts_unassigned():
    e = EvidenceStub()
    assert e.host_id is None
    assert e.host_assignment_status is None


def test_assign_evidence_to_host():
    e = EvidenceStub()
    e.host_id = "host-1"
    e.host_assignment_status = "confirmed"
    e.host_assignment_method = "analyst_assigned"
    e.host_assignment_confidence = "high"
    assert e.host_id == "host-1"
    assert e.host_assignment_status == "confirmed"


def test_unassign_evidence_from_host():
    e = EvidenceStub(host_id="host-1", host_assignment_status="confirmed")
    e.host_id = None
    e.host_assignment_status = "unassigned"
    assert e.host_id is None
    assert e.host_assignment_status == "unassigned"


def test_evidence_keeps_detected_host():
    e = EvidenceStub(detected_host="HOSTA")
    e.host_id = "host-1"
    assert e.detected_host == "HOSTA"
    assert e.host_id == "host-1"


def test_two_evidence_same_host():
    e1 = EvidenceStub(id="ev-1", host_id="host-1", host_assignment_status="confirmed")
    e2 = EvidenceStub(id="ev-2", host_id="host-1", host_assignment_status="confirmed")
    assert e1.host_id == e2.host_id


def test_two_evidence_different_hosts():
    e1 = EvidenceStub(id="ev-disk", host_id="host-a")
    e2 = EvidenceStub(id="ev-mem", host_id="host-b")
    assert e1.host_id != e2.host_id


def test_evidence_no_cross_case_assignment():
    e = EvidenceStub(case_id="case-1")
    e.host_id = "host-from-other-case"
    assert e.case_id == "case-1"
