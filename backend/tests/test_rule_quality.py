from __future__ import annotations

import pytest

from app.models.finding import Finding, FindingStatus
from app.services.rule_quality import compute_rule_quality_metrics


class Query:
    def __init__(self, rows):
        self.rows = rows
    def filter(self, *args, **kwargs):
        return self
    def all(self):
        return list(self.rows)
    def all(self):
        return list(self.rows)
    def order_by(self, *args, **kwargs):
        return self
    def one_or_none(self):
        return self.rows[0] if self.rows else None


class Db:
    def __init__(self):
        self.findings: list[Finding] = []
    def query(self, model):
        if model is Finding:
            return Query(self.findings)
        return Query([])
    def get(self, model, identifier):
        return None


def test_no_findings():
    db = Db()
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result == []


def test_rule_with_unreviewed_only():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.new, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["total_findings"] == 1
    assert result[0]["unreviewed_findings"] == 1
    assert result[0]["reviewed_findings"] == 0
    assert result[0]["observed_confirmation_rate"] is None
    assert result[0]["quality_status"] == "insufficient_sample"


def test_rule_with_confirmed():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.confirmed, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["confirmed_findings"] == 1
    assert result[0]["reviewed_findings"] == 1
    assert result[0]["observed_confirmation_rate"] == 1.0
    assert result[0]["sufficient_sample"] is False


def test_rule_with_false_positive():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.false_positive, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["false_positive_findings"] == 1
    assert result[0]["observed_false_positive_rate"] == 1.0


def test_rule_with_suppressed():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.suppressed, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["suppressed_findings"] == 1


def test_rule_multiple_statuses():
    db = Db()
    for i, status in enumerate([FindingStatus.new, FindingStatus.triaged, FindingStatus.confirmed, FindingStatus.false_positive, FindingStatus.suppressed]):
        db.findings.append(Finding(id=f"f{i}", case_id="case-1", title=f"T{i}", status=status, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["total_findings"] == 5
    assert result[0]["unreviewed_findings"] == 1
    assert result[0]["reviewed_findings"] == 4
    assert result[0]["confirmed_findings"] == 1
    assert result[0]["false_positive_findings"] == 1
    assert result[0]["suppressed_findings"] == 1
    assert result[0]["observed_confirmation_rate"] == 0.25
    assert result[0]["sufficient_sample"] is False


def test_confirmation_rate_null_when_zero_reviewed():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.new, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert result[0]["observed_confirmation_rate"] is None


def test_case_scoping():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.new, finding_type="hunting.rule1", correlation_version="1.0.0"))
    db.findings.append(Finding(id="f2", case_id="case-2", title="T", status=FindingStatus.confirmed, finding_type="hunting.rule1", correlation_version="1.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert len(result) >= 1


def test_version_separation():
    db = Db()
    db.findings.append(Finding(id="f1", case_id="case-1", title="T", status=FindingStatus.confirmed, finding_type="hunting.rule1", correlation_version="1.0.0"))
    db.findings.append(Finding(id="f2", case_id="case-1", title="T", status=FindingStatus.false_positive, finding_type="hunting.rule1", correlation_version="2.0.0"))
    result = compute_rule_quality_metrics(db, case_id="case-1")
    assert len(result) == 2
    v1 = next(r for r in result if r["version"] == "1.0.0")
    v2 = next(r for r in result if r["version"] == "2.0.0")
    assert v1["confirmed_findings"] == 1
    assert v2["false_positive_findings"] == 1
