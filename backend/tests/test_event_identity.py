from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.detections import create_detection_if_missing
from app.ingest.fingerprints import apply_event_fingerprint, compute_event_fingerprint
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, EvidenceType
from app.models.timeline_bookmark import TimelineBookmark
from app.services import reconciliation


CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RULE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _evtx_event(event_id: str = "evt-1", record_id: int = 101, *, risk_score: int = 80, source_file: str = "/srv/app/evidence/case-1/ev-1/extracted/Windows/System32/winevt/Logs/Security.evtx") -> dict:
    return {
        "event_id": event_id,
        "case_id": CASE_ID,
        "evidence_id": EVIDENCE_ID,
        "source_file": source_file,
        "@timestamp": "2026-05-20T08:00:00Z",
        "risk_score": risk_score,
        "artifact": {"type": "evtx_raw", "parser": "native_evtx"},
        "event": {"type": "process_start"},
        "windows": {
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "event_record_id": record_id,
        },
        "process": {"name": "powershell.exe", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
    }


def test_stable_event_id_is_deterministic_across_event_id_and_risk_changes() -> None:
    first = _evtx_event(event_id="evt-1", risk_score=20, source_file="/mnt/one/case-1/ev-1/extracted/Security.evtx")
    second = _evtx_event(event_id="evt-2", risk_score=95, source_file="/mnt/two/case-1/ev-1/extracted/Security.evtx")

    first_fp = compute_event_fingerprint(first)
    second_fp = compute_event_fingerprint(second)

    assert first_fp.stable_event_id == second_fp.stable_event_id
    assert first_fp.best_effort is False


def test_stable_event_id_changes_when_record_locator_changes() -> None:
    first = compute_event_fingerprint(_evtx_event(record_id=101))
    second = compute_event_fingerprint(_evtx_event(record_id=102))

    assert first.stable_event_id != second.stable_event_id


def test_best_effort_fingerprint_marks_data_quality() -> None:
    document = {
        "event_id": "evt-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact": {"type": "generic", "parser": "csv"},
        "event": {"type": "observed"},
        "@timestamp": "2026-05-20T08:00:00Z",
        "raw_summary": "generic row",
    }
    apply_event_fingerprint(document)

    assert document["stable_event_id"]
    assert "fingerprint_best_effort" in document["data_quality"]


def test_reconciliation_remaps_bookmark_and_revives_stale_detection() -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="sample.zip",
        stored_path="/tmp/sample.zip",
        sha256="00",
        size_bytes=1,
        evidence_type=EvidenceType.unknown,
        metadata_json={},
    )
    db.add(case)
    db.add(evidence)
    db.commit()

    old_event = apply_event_fingerprint(_evtx_event(event_id="old-evt"))
    stable_id = old_event["stable_event_id"]
    bookmark = TimelineBookmark(
        case_id=CASE_ID,
        event_id="old-evt",
        stable_event_id=stable_id,
        title="Key event",
        timestamp=datetime(2026, 5, 20, 8, 0, tzinfo=UTC),
        remap_status="current",
    )
    db.add(bookmark)
    detection, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="old-evt",
        event_index="idx",
        opensearch_id="old-evt",
        target_type="event",
        target_path=r"C:\Users\user01\Downloads\payload.exe",
        message="match",
        matched_at="2026-05-20T08:00:00Z",
        matched_stable_event_id=stable_id,
        dedup_fingerprint="fp-1",
        commit=True,
    )
    assert created is True
    detection.status = "stale"
    evidence.metadata_json = {"reconciliation_baseline": {"detection_status_by_fingerprint": {"fp-1": {"status": "dismissed", "analyst_note": "keep"}}}}
    db.commit()

    new_event = apply_event_fingerprint(_evtx_event(event_id="new-evt"))
    assert new_event["stable_event_id"] == stable_id

    original_scope = reconciliation._event_scope
    reconciliation._event_scope = lambda case_id, evidence_id: [{"id": "new-evt", **new_event}]  # type: ignore[assignment]
    try:
        result = reconciliation.reconcile_reprocessed_evidence(db, evidence)
    finally:
        reconciliation._event_scope = original_scope  # type: ignore[assignment]

    db.refresh(bookmark)
    db.refresh(detection)
    assert bookmark.event_id == "new-evt"
    assert bookmark.remap_status in {"remapped", "current"}
    assert detection.event_id == "new-evt"
    assert detection.status == "dismissed"
    assert result["reconciliation_report"]["detections_matched_existing"] >= 1
