from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingStatus
from app.models.rule_run import RuleRun
from app.services.finding_indicators import resolve_finding_indicators


class Query:
    def __init__(self, rows):
        self.rows = rows
    def filter(self, *args, **kwargs):
        return Query([r for r in self.rows if r])
    def order_by(self, *args, **kwargs):
        return self
    def all(self):
        return list(self.rows)
    def one_or_none(self):
        return self.rows[0] if self.rows else None
    def count(self):
        return len(self.rows)
    def first(self):
        return self.rows[0] if self.rows else None


class Db:
    def __init__(self):
        self.case = Case(id="case-1", name="Test Case")
        self.evidence = Evidence(id="ev-1", case_id="case-1", original_filename="test.raw", stored_path="/tmp/test.raw", sha256="00", size_bytes=1)
        self.findings: list[Finding] = []
        self.runs: list[RuleRun] = []

    def get(self, model, identifier):
        if model is Case and identifier == "case-1":
            return self.case
        if model is Evidence and identifier == "ev-1":
            return self.evidence
        if model is Finding:
            return next((item for item in self.findings if item.id == identifier), None)
        if model is RuleRun:
            return next((item for item in self.runs if item.id == identifier), None)
        return None

    def query(self, model):
        if model is Finding:
            return Query(self.findings)
        if model is RuleRun:
            return Query(self.runs)
        return Query([])

    def add(self, item):
        if isinstance(item, Finding):
            item.id = item.id or f"finding-{len(self.findings) + 1}"
            self.findings.append(item)
        if isinstance(item, RuleRun):
            item.id = item.id or f"run-{len(self.runs) + 1}"
            self.runs.append(item)

    def flush(self):
        pass
    def commit(self):
        pass
    def refresh(self, item):
        pass


def _art(**kwargs) -> SimpleNamespace:
    return _art(**kwargs)


def test_empty_case_returns_empty_indicators():
    db = Db()
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "proc-1"}])
    assert result["results"]["p1"]["total"] == 0
    assert result["results"]["p1"]["active"] == 0


def test_single_finding_matched_by_process_entity_id():
    db = Db()
    f = Finding(id="f-1", case_id="case-1", title="Test", status=FindingStatus.new, related_process_node_ids=["ent-1"])
    db.findings.append(f)
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "ent-1"}])
    assert result["results"]["p1"]["total"] == 1
    assert result["results"]["p1"]["active"] == 1
    assert result["results"]["p1"]["finding_ids"] == ["f-1"]


def test_finding_matched_by_artifact_id():
    db = Db()
    f = Finding(id="f-2", case_id="case-1", title="Test", status=FindingStatus.new, related_artifact_ids=["art-1"])
    db.findings.append(f)
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "a1", "entity_type": "artifact", "artifact_id": "art-1"}])
    assert result["results"]["a1"]["total"] == 1


def test_no_cross_case_leakage():
    db = Db()
    db.findings.append(Finding(id="f-other", case_id="case-2", title="Other", status=FindingStatus.new, related_process_node_ids=["ent-1"]))
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "ent-1"}])
    assert result["results"]["p1"]["total"] == 0


def test_suppressed_finding_excluded_from_active_count():
    db = Db()
    db.findings.append(Finding(id="f-sup", case_id="case-1", title="Suppressed", status=FindingStatus.suppressed, related_process_node_ids=["ent-1"]))
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "ent-1"}])
    assert result["results"]["p1"]["total"] == 1
    assert result["results"]["p1"]["active"] == 0
    assert result["results"]["p1"]["suppressed_count"] == 1


def test_batch_of_multiple_entities():
    db = Db()
    db.findings.append(Finding(id="f-a", case_id="case-1", title="A", status=FindingStatus.new, related_process_node_ids=["ent-a"]))
    db.findings.append(Finding(id="f-b", case_id="case-1", title="B", status=FindingStatus.investigating, related_process_node_ids=["ent-b"]))
    entities = [
        {"key": "a", "entity_type": "process", "process_entity_id": "ent-a"},
        {"key": "b", "entity_type": "process", "process_entity_id": "ent-b"},
        {"key": "c", "entity_type": "process", "process_entity_id": "ent-c"},
    ]
    result = resolve_finding_indicators(db, case_id="case-1", entities=entities)
    assert result["results"]["a"]["total"] == 1
    assert result["results"]["b"]["total"] == 1
    assert result["results"]["c"]["total"] == 0


def test_highest_severity_and_confidence():
    db = Db()
    db.findings.append(Finding(id="f-low", case_id="case-1", title="Low", status=FindingStatus.new, severity="low", confidence="low", related_process_node_ids=["ent-1"]))
    db.findings.append(Finding(id="f-high", case_id="case-1", title="High", status=FindingStatus.confirmed, severity="high", confidence="high", related_process_node_ids=["ent-1"]))
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "ent-1"}])
    assert result["results"]["p1"]["highest_severity"] == "high"
    assert result["results"]["p1"]["highest_confidence"] == "high"
    assert result["results"]["p1"]["total"] == 2


def test_deduplication_one_finding_visible_from_multiple_refs():
    db = Db()
    f = Finding(id="f-dual", case_id="case-1", title="Dual", status=FindingStatus.new, related_process_node_ids=["ent-1", "ent-2"], related_artifact_ids=["art-1"])
    db.findings.append(f)
    entities = [
        {"key": "p1", "entity_type": "process", "process_entity_id": "ent-1"},
        {"key": "p2", "entity_type": "process", "process_entity_id": "ent-2"},
        {"key": "a1", "entity_type": "artifact", "artifact_id": "art-1"},
    ]
    result = resolve_finding_indicators(db, case_id="case-1", entities=entities)
    assert result["results"]["p1"]["finding_ids"] == ["f-dual"]
    assert result["results"]["p2"]["finding_ids"] == ["f-dual"]
    assert result["results"]["a1"]["finding_ids"] == ["f-dual"]


def test_evidence_scoping_works():
    db = Db()
    f1 = Finding(id="f-ev1", case_id="case-1", title="EV1", status=FindingStatus.new, related_process_node_ids=["ent-1"], evidence_id="ev-1")
    f2 = Finding(id="f-ev2", case_id="case-1", title="EV2", status=FindingStatus.new, related_process_node_ids=["ent-1"], evidence_id="ev-2")
    db.findings.extend([f1, f2])
    result = resolve_finding_indicators(db, case_id="case-1", entities=[{"key": "p1", "entity_type": "process", "process_entity_id": "ent-1", "evidence_id": "ev-1"}])
    assert result["results"]["p1"]["total"] == 2
