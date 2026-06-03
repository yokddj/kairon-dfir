from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.case_report import CaseReport, CaseReportStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services import report_service
from app.services.usable_ingest import ingest_mode_metadata


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _case() -> Case:
    return Case(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name="Case 1", status="open")


def _evidence() -> Evidence:
    return Evidence(
        id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        original_path="/tmp/collection.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="abc",
        size_bytes=128,
        file_count=3,
        ingest_status=IngestStatus.completed,
        metadata_json={
            **ingest_mode_metadata("usable_search"),
            "latest_ingest_run_id": "ingest-1",
            "events_indexed": 53,
        },
        path_validation={},
        ingest_source={},
        error_log={},
    )


def _summary_payload() -> dict:
    return {
        "header": {
            "case_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "evidence_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "evidence_name": "collection.zip",
            "generated_at": "2026-05-26T10:00:00Z",
            "report_type": "summary",
            "mode": "on_demand",
        },
        "ingest_summary": {"latest_ingest_run_id": "ingest-1", "ingest_mode": "usable_search", "final_status": "completed"},
        "search_summary": {"total_indexed_docs": 53, "artifact_type_counts": {"browser": 53}, "parser_counts": {"browser_chromium_history": 53}},
        "parser_contract_summary": {"contract_version": "v1", "summary": {"pass": 1}},
        "detections_summary": {"total_detections": 0, "by_severity": {}, "by_rule": {}, "latest_rule_run_ids": [], "top_detections": []},
        "problematic_artifacts": {"summary": {"problematic_count": 0}, "items": []},
        "links": {"search_this_evidence": "/cases/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/search?evidence_id=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb&tab=results"},
        "warnings": [],
    }


def test_generate_evidence_summary_report_creates_completed_on_demand_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db = _session()
    db.add(_case())
    db.add(_evidence())
    db.commit()

    monkeypatch.setattr(report_service, "_count_evidence_indexed_docs", lambda evidence: 53)
    monkeypatch.setattr(report_service, "_load_evidence_manifest", lambda evidence: {"artifacts": []})
    monkeypatch.setattr(report_service, "_report_output_dir", lambda report_id: tmp_path / report_id)
    monkeypatch.setattr(report_service, "_build_evidence_summary_payload", lambda *args, **kwargs: _summary_payload())

    report = report_service.generate_evidence_summary_report(db, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", {"report_type": "summary", "format": "markdown"})

    assert report["status"] == CaseReportStatus.completed.value
    assert report["case_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert report["evidence_id"] == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    assert report["mode"] == "on_demand"
    assert report["report_type"] == "summary"
    assert report["source_ingest_run_id"] == "ingest-1"
    assert report["metadata_json"]["requested_via"] == "evidence_on_demand"


def test_generate_evidence_summary_report_rejects_evidence_without_indexed_data(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _session()
    db.add(_case())
    evidence = _evidence()
    evidence.metadata_json = {**ingest_mode_metadata("usable_search"), "latest_ingest_run_id": "ingest-1", "events_indexed": 0}
    db.add(evidence)
    db.commit()

    monkeypatch.setattr(report_service, "_count_evidence_indexed_docs", lambda evidence: 0)
    monkeypatch.setattr(report_service, "_load_evidence_manifest", lambda evidence: {"artifacts": []})
    monkeypatch.setattr(report_service, "build_problematic_artifacts_report", lambda *args, **kwargs: {"summary": {"problematic_count": 0}, "items": []})

    with pytest.raises(HTTPException) as exc:
        report_service.generate_evidence_summary_report(db, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", {"report_type": "summary", "format": "markdown"})
    assert exc.value.status_code == 400


def test_generate_evidence_summary_report_rejects_duplicate_active_report(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _session()
    db.add(_case())
    db.add(_evidence())
    db.add(
        CaseReport(
            id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            evidence_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            title="Active report",
            status=CaseReportStatus.running,
            template="evidence_summary",
            report_type="summary",
            format="markdown",
            mode="on_demand",
        )
    )
    db.commit()

    monkeypatch.setattr(report_service, "_count_evidence_indexed_docs", lambda evidence: 53)
    monkeypatch.setattr(report_service, "_load_evidence_manifest", lambda evidence: {"artifacts": []})
    monkeypatch.setattr(report_service, "build_problematic_artifacts_report", lambda *args, **kwargs: {"summary": {"problematic_count": 0}, "items": []})

    with pytest.raises(HTTPException) as exc:
        report_service.generate_evidence_summary_report(db, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", {"report_type": "summary", "format": "markdown"})
    assert exc.value.status_code == 409


def test_download_report_by_id_returns_generated_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db = _session()
    db.add(_case())
    db.add(_evidence())
    db.commit()

    monkeypatch.setattr(report_service, "_count_evidence_indexed_docs", lambda evidence: 53)
    monkeypatch.setattr(report_service, "_load_evidence_manifest", lambda evidence: {"artifacts": []})
    monkeypatch.setattr(report_service, "_report_output_dir", lambda report_id: tmp_path / report_id)
    monkeypatch.setattr(report_service, "_build_evidence_summary_payload", lambda *args, **kwargs: _summary_payload())

    report = report_service.generate_evidence_summary_report(db, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", {"report_type": "summary", "format": "json"})
    content, filename, media_type = report_service.download_report_by_id(db, report["id"], format="json")

    payload = json.loads(content.decode("utf-8"))
    assert filename.endswith(".json")
    assert media_type == "application/json"
    assert payload["header"]["evidence_id"] == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    assert payload["search_summary"]["total_indexed_docs"] == 53


def test_usable_search_metadata_keeps_reports_skipped_for_later() -> None:
    metadata = ingest_mode_metadata("usable_search")
    assert metadata["skip_rules"] is True
    assert metadata["skip_detections"] is True
    assert "advanced_reports" in metadata["skipped_features"]
