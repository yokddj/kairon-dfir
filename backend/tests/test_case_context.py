from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_cases, routes_hunting
from app.core.database import Base
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services import host_identity


CASE_ID = "00000000-0000-4000-8000-000000000001"
EVIDENCE_ID = "00000000-0000-4000-8000-000000000002"
ARTIFACT_ID = "00000000-0000-4000-8000-000000000003"
FINDING_1 = "00000000-0000-4000-8000-000000000004"
FINDING_2 = "00000000-0000-4000-8000-000000000005"
HOST_IDS = {1: "00000000-0000-4000-8000-000000000006", 2: "00000000-0000-4000-8000-000000000007"}


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    # Host attribution is cached per case id for 30 s; every test reuses CASE_ID.
    host_identity._host_attribution_cache.clear()
    routes_cases._SUMMARY_CACHE.clear()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _store(db, *rows):
    db.add_all(rows)
    db.commit()


def test_build_case_context_returns_hosts_and_evidence_summary(monkeypatch, db):
    case = Case(id=CASE_ID, name="Hostalpha", status="open", created_at=datetime(2026, 5, 15, tzinfo=UTC), updated_at=datetime(2026, 5, 15, tzinfo=UTC))
    evidences = [
        Evidence(
            id=EVIDENCE_ID,
            case_id=CASE_ID,
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
        Artifact(id=ARTIFACT_ID, case_id=CASE_ID, evidence_id=EVIDENCE_ID, name="Proc", artifact_type="process", source_path="/tmp/proc.jsonl", parser="jsonl", record_count=42, status="completed"),
    ]
    findings = [
        Finding(id=FINDING_1, case_id=CASE_ID, title="Office spawned PowerShell", severity=FindingSeverity.high, status=FindingStatus.new, evidence_id=EVIDENCE_ID, related_hosts=["desktop-01"]),
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

    _store(db, case, *evidences, *artifacts, *findings)
    context = routes_cases._build_case_context(db, CASE_ID)

    assert context["case"]["id"] == CASE_ID
    assert context["summary"]["events_indexed"] == 42
    assert [host["canonical_name"] for host in context["hosts"]] == ["desktop-01"]
    assert context["hosts"][0]["findings_count"] == 1
    assert context["evidences"][0]["detected_host"] == "desktop-01"
    assert context["evidences"][0]["storage_mode"] == "uploaded"
    assert context["evidences"][0]["events_indexed"] == 42


def test_build_case_context_handles_unknown_host_without_filename_contamination(monkeypatch, db):
    case = Case(id=CASE_ID, name="Noise", status="open", created_at=datetime(2026, 5, 15, tzinfo=UTC), updated_at=datetime(2026, 5, 15, tzinfo=UTC))
    evidences = [
        Evidence(
            id=EVIDENCE_ID,
            case_id=CASE_ID,
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

    _store(db, case, *evidences)
    context = routes_cases._build_case_context(db, CASE_ID)

    assert context["hosts"] == []
    assert context["evidences"][0]["detected_host"] is None
    assert "scheduled_task_regression.xml" not in str(context["hosts"]) + str(context["host_candidates"])


def test_list_findings_can_filter_by_host(db):
    case = Case(id=CASE_ID, name="Hosts", status="open")
    hosts = [CaseHost(id=HOST_IDS[n], case_id=CASE_ID, canonical_name=f"desktop-0{n}", display_name=f"desktop-0{n}") for n in (1, 2)]
    findings = [
        Finding(id=FINDING_1, case_id=CASE_ID, title="Host one", severity=FindingSeverity.high, status=FindingStatus.new, related_hosts=["desktop-01"], linked_host_id=HOST_IDS[1]),
        Finding(id=FINDING_2, case_id=CASE_ID, title="Host two", severity=FindingSeverity.medium, status=FindingStatus.reviewed, related_hosts=["desktop-02"], linked_host_id=HOST_IDS[2]),
    ]
    _store(db, case, *hosts, *findings)

    results = routes_hunting.hunting_list_findings(CASE_ID, status_filter=None, linked_host_id=HOST_IDS[2], page=1, page_size=100, db=db)

    assert [item["id"] for item in results["items"]] == [FINDING_2]
