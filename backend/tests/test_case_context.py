from datetime import UTC, datetime
from types import SimpleNamespace

from app.api import routes_cases, routes_findings
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus


class FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.items)


class FakeDb:
    def __init__(self, *, case: Case, evidences: list[Evidence], artifacts: list[Artifact], findings: list[Finding]):
        self.case = case
        self.evidences = evidences
        self.artifacts = artifacts
        self.findings = findings

    def get(self, model, identifier):
        if model is Case and identifier == self.case.id:
            return self.case
        return None

    def query(self, model):
        if model is Evidence:
            return FakeQuery(self.evidences)
        if model is Artifact:
            return FakeQuery(self.artifacts)
        if model is Finding:
            return FakeQuery(self.findings)
        return FakeQuery([])


def test_build_case_context_returns_hosts_and_evidence_summary(monkeypatch):
    case = Case(id="case-1", name="Movistar", status="open", created_at=datetime(2026, 5, 15, tzinfo=UTC), updated_at=datetime(2026, 5, 15, tzinfo=UTC))
    evidences = [
        Evidence(
            id="ev-1",
            case_id="case-1",
            original_filename="collection.zip",
            stored_path="/tmp/collection.zip",
            original_path="/tmp/collection.zip",
            storage_mode=EvidenceStorageMode.uploaded,
            is_external=False,
            copy_to_storage=True,
            evidence_type=EvidenceType.velociraptor_zip,
            sha256="00",
            size_bytes=10,
            file_count=1,
            ingest_status=IngestStatus.completed,
            detected_host="desktop-01",
            path_validation={},
            ingest_source={},
            metadata_json={},
            error_log={},
        )
    ]
    artifacts = [
        Artifact(id="art-1", case_id="case-1", evidence_id="ev-1", name="Proc", artifact_type="process", source_path="/tmp/proc.jsonl", parser="jsonl", record_count=42, status="completed"),
    ]
    findings = [
        Finding(id="f-1", case_id="case-1", title="Office spawned PowerShell", severity=FindingSeverity.high, status=FindingStatus.new, evidence_id="ev-1", related_hosts=["desktop-01"]),
    ]
    monkeypatch.setattr(
        routes_cases,
        "get_investigation_summary",
        lambda case_id, db: {
            "total_events": 42,
            "findings_count": 1,
            "top_hosts": [{"key": "desktop-01", "count": 42}],
        },
    )
    monkeypatch.setattr(routes_cases, "count_detections", lambda db, case_id: 0)
    monkeypatch.setattr(routes_cases, "count_findings", lambda db, case_id: 1)

    context = routes_cases._build_case_context(FakeDb(case=case, evidences=evidences, artifacts=artifacts, findings=findings), "case-1")

    assert context["case"].id == "case-1"
    assert context["summary"]["events_indexed"] == 42
    assert context["hosts"][0]["host"] == "desktop-01"
    assert context["hosts"][0]["findings_count"] == 1
    assert context["evidences"][0]["storage_mode"] == "uploaded"
    assert context["evidences"][0]["events_indexed"] == 42


def test_build_case_context_handles_unknown_host_without_filename_contamination(monkeypatch):
    case = Case(id="case-1", name="Noise", status="open", created_at=datetime(2026, 5, 15, tzinfo=UTC), updated_at=datetime(2026, 5, 15, tzinfo=UTC))
    evidences = [
        Evidence(
            id="ev-1",
            case_id="case-1",
            original_filename="scheduled_task_regression.xml",
            stored_path="/tmp/scheduled_task_regression.xml",
            original_path="/tmp/scheduled_task_regression.xml",
            storage_mode=EvidenceStorageMode.uploaded,
            is_external=False,
            copy_to_storage=True,
            evidence_type=EvidenceType.unknown,
            sha256="00",
            size_bytes=10,
            file_count=1,
            ingest_status=IngestStatus.completed,
            detected_host=None,
            path_validation={},
            ingest_source={},
            metadata_json={},
            error_log={},
        )
    ]
    monkeypatch.setattr(routes_cases, "get_investigation_summary", lambda case_id, db: {"total_events": 0, "findings_count": 0, "top_hosts": []})
    monkeypatch.setattr(routes_cases, "count_detections", lambda db, case_id: 0)
    monkeypatch.setattr(routes_cases, "count_findings", lambda db, case_id: 0)

    context = routes_cases._build_case_context(FakeDb(case=case, evidences=evidences, artifacts=[], findings=[]), "case-1")

    assert context["hosts"][0]["host"] == "unknown"
    assert context["hosts"][0]["host"] != "scheduled_task_regression.xml"


def test_list_findings_can_filter_by_host():
    finding_items = [
        Finding(id="f-1", case_id="case-1", title="Host one", severity=FindingSeverity.high, status=FindingStatus.new, related_hosts=["desktop-01"]),
        Finding(id="f-2", case_id="case-1", title="Host two", severity=FindingSeverity.medium, status=FindingStatus.reviewed, related_hosts=["desktop-02"]),
    ]

    class FindingDb:
        def get(self, model, identifier):
            if model is Case and identifier == "case-1":
                return SimpleNamespace(id="case-1")
            return None

        def query(self, model):
            return FakeQuery(finding_items)

    results = routes_findings.list_findings("case-1", host="desktop-02", db=FindingDb())

    assert [item.id for item in results] == ["f-2"]
