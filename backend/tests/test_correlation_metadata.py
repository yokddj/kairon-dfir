from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.evidence import Evidence, EvidenceType
from app.models.finding import FindingSeverity, FindingStatus
from app.services import correlation_engine

CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"
EVIDENCE_HOSTA_ID = "bbbbbbbb-2222-4222-8222-222222222222"
EVIDENCE_HOSTB_ID = "cccccccc-3333-4333-8333-333333333333"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, future=True)
    db = Session()
    case = Case(id=CASE_ID, name="Case")
    db.add(case)
    db.add(
        Evidence(
            id=EVIDENCE_HOSTA_ID,
            case_id=CASE_ID,
            original_filename="HOSTA.7z",
            stored_path="/tmp/hosta.7z",
            evidence_type=EvidenceType.unknown,
            sha256="0" * 64,
            size_bytes=1,
            detected_host="HOSTA",
        )
    )
    db.add(
        Evidence(
            id=EVIDENCE_HOSTB_ID,
            case_id=CASE_ID,
            original_filename="HOSTB.7z",
            stored_path="/tmp/hostb.7z",
            evidence_type=EvidenceType.unknown,
            sha256="1" * 64,
            size_bytes=1,
            detected_host="HOSTB",
        )
    )
    db.commit()
    return db


def _event(event_id: str, host: str, artifact_type: str) -> dict:
    return {
        "id": event_id,
        "evidence_id": EVIDENCE_HOSTA_ID if host == "HOSTA" else EVIDENCE_HOSTB_ID,
        "@timestamp": "2024-03-22T10:00:00Z",
        "artifact": {"type": artifact_type},
        "host": {"name": host},
        "event": {"type": "process_start", "message": event_id},
    }


def _saved_finding(index: int, host: str = "HOSTA") -> SimpleNamespace:
    return SimpleNamespace(
        id=f"finding-{index}",
        case_id=CASE_ID,
        evidence_id=EVIDENCE_HOSTA_ID,
        finding_type="suspicious_process_chain" if index % 2 else "defender_correlated",
        title=f"Finding {index}",
        description="Generated",
        severity=FindingSeverity.high,
        confidence="high",
        status=FindingStatus.new,
        created_at=datetime(2024, 3, 22, tzinfo=UTC),
        updated_at=datetime(2024, 3, 22, tzinfo=UTC),
        time_start=None,
        time_end=None,
        timeline=[],
        related_event_ids=[f"evt-{index}"],
        event_ids=[],
        related_stable_event_ids=[],
        related_artifact_ids=[],
        related_evidence_ids=[EVIDENCE_HOSTA_ID],
        related_process_node_ids=[],
        related_files=[],
        related_domains=[],
        related_ips=[],
        related_users=[],
        related_hosts=[host],
        risk_score=80,
        reasons=[],
        tags=[],
        mitre=[],
        recommended_triage=[],
        source="correlation_engine",
        correlation_version="v1",
        data_quality=[],
        fingerprint=f"fp-{index}",
        last_seen_at=None,
        occurrence_count=1,
    )


def test_correlation_run_metadata_paginates_and_reports_scope(monkeypatch):
    events = [_event("evt-1", "HOSTA", "windows_event"), _event("evt-2", "HOSTB", "defender"), _event("evt-3", "HOSTB", "mft")]
    saved = [_saved_finding(index, host="HOSTA" if index < 3 else "HOSTB") for index in range(5)]
    captured: dict[str, int] = {}

    def _fake_iter(case_id: str, evidence_id: str | None = None, *, max_docs: int = 100000):
        captured["max_docs"] = max_docs
        return events

    monkeypatch.setattr(correlation_engine, "_correlation_max_events", lambda _db: 2)
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", _fake_iter)
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": []}, "summary": {}})
    monkeypatch.setattr(
        correlation_engine,
        "_generate_findings",
        lambda case, evidences, events_arg, process_bundle, evidence_id=None: (
            [{"fingerprint": f"fp-{index}", "case_id": case.id, "finding_type": "x"} for index in range(5)],
            {"case_id": case.id, "evidence_id": evidence_id, "events_considered": len(events_arg), "by_type": {}},
        ),
    )
    monkeypatch.setattr(correlation_engine, "_persist_findings", lambda *args, **kwargs: (saved, 2))

    result = correlation_engine.run_correlation_engine(_session(), CASE_ID, page=1, page_size=2)
    report = result["report"]

    assert captured["max_docs"] == 3
    assert len(result["findings"]) == 2
    assert report["scope"]["scope_type"] == "case_all_evidence"
    assert set(report["scope"]["evidence_ids"]) == {EVIDENCE_HOSTA_ID, EVIDENCE_HOSTB_ID}
    assert report["counts"] == {
        "candidates_scanned": 2,
        "matched": 5,
        "returned": 2,
        "deduplicated": 2,
        "hidden_by_limit": 3,
        "has_more": True,
        "event_limit_reached": True,
    }
    assert report["limits"]["page_size"] == 2
    assert report["pagination"]["next_page"] == 2
    assert report["source_breakdown"] == {"defender": 1, "windows_event": 1}
    assert report["host_breakdown"] == {"HOSTA": 1, "HOSTB": 1}
    assert report["result_host_breakdown"] == {"HOSTA": 3, "HOSTB": 2}


def test_correlation_selected_evidence_scope_restricts_metadata(monkeypatch):
    saved = [_saved_finding(1)]
    monkeypatch.setattr(correlation_engine, "_correlation_max_events", lambda _db: 10)
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, *, max_docs=100000: [_event("evt-1", "HOSTA", "windows_event")])
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": []}, "summary": {}})
    monkeypatch.setattr(correlation_engine, "_generate_findings", lambda case, evidences, events, process_bundle, evidence_id=None: ([{"fingerprint": "fp-1", "case_id": case.id, "finding_type": "x"}], {"case_id": case.id}))
    monkeypatch.setattr(correlation_engine, "_persist_findings", lambda *args, **kwargs: (saved, 0))

    report = correlation_engine.run_correlation_engine(_session(), CASE_ID, evidence_id=EVIDENCE_HOSTA_ID)["report"]

    assert report["scope"]["scope_type"] == "selected_evidence"
    assert report["scope"]["evidence_ids"] == [EVIDENCE_HOSTA_ID]
    assert report["counts"]["has_more"] is False


def test_correlation_host_only_scope_filters_events_and_reports_effective_scope(monkeypatch):
    captured: dict[str, object] = {}
    saved = [_saved_finding(1, host="HOSTA")]

    def _fake_iter(case_id: str, evidence_id: str | None = None, *, host_aliases=None, host_evidence_ids=None, max_docs=100000):
        captured["evidence_id"] = evidence_id
        captured["host_aliases"] = host_aliases
        captured["host_evidence_ids"] = host_evidence_ids
        return [_event("evt-1", "HOSTA", "windows_event")]

    monkeypatch.setattr(correlation_engine, "_correlation_max_events", lambda _db: 10)
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", _fake_iter)
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": []}, "summary": {}, "host": kwargs.get("host")})
    monkeypatch.setattr(correlation_engine, "_generate_findings", lambda case, evidences, events, process_bundle, evidence_id=None: ([{"fingerprint": "fp-1", "case_id": case.id, "finding_type": "x"}], {"case_id": case.id}))
    monkeypatch.setattr(correlation_engine, "_persist_findings", lambda *args, **kwargs: (saved, 0))

    report = correlation_engine.run_correlation_engine(_session(), CASE_ID, host="HOSTA")["report"]

    assert captured["evidence_id"] is None
    assert EVIDENCE_HOSTA_ID in captured["host_evidence_ids"]
    assert EVIDENCE_HOSTB_ID not in captured["host_evidence_ids"]
    assert "hosta" in captured["host_aliases"]
    assert report["scope"]["scope_type"] == "selected_host"
    assert report["scope_reason"] == "host"
    assert report["effective_scope"]["canonical_host"] == "hosta"
    assert report["effective_scope"]["all_hosts"] is False
    assert report["request_scope"] == {"host": "HOSTA", "evidence_id": None}
    assert report["correlation_run_id"]
    assert report["cache_key"]
    assert report["reused_previous_run"] is False


def test_correlation_host_alias_canonicalization_and_cache_key_differs(monkeypatch):
    db = _session()
    host = CaseHost(case_id=CASE_ID, canonical_name="hosta", display_name="HOSTA")
    db.add(host)
    db.flush()
    db.add(CaseHostAlias(case_id=CASE_ID, case_host_id=host.id, alias="HOSTA", normalized_alias="hosta", source="test", confidence="high"))
    db.add(CaseHostAlias(case_id=CASE_ID, case_host_id=host.id, alias="hosta.examplecorp.local", normalized_alias="hosta.examplecorp.local", source="test", confidence="high"))
    db.commit()

    monkeypatch.setattr(correlation_engine, "_correlation_max_events", lambda _db: 10)
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, *, host_aliases=None, host_evidence_ids=None, max_docs=100000: [_event("evt-1", "HOSTA", "windows_event")])
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": []}, "summary": {}})
    monkeypatch.setattr(correlation_engine, "_generate_findings", lambda case, evidences, events, process_bundle, evidence_id=None: ([{"fingerprint": "fp-1", "case_id": case.id, "finding_type": "x"}], {"case_id": case.id}))
    monkeypatch.setattr(correlation_engine, "_persist_findings", lambda *args, **kwargs: ([_saved_finding(1, host="HOSTA")], 0))

    all_report = correlation_engine.run_correlation_engine(db, CASE_ID, page=1, page_size=25)["report"]
    alias_report = correlation_engine.run_correlation_engine(db, CASE_ID, host="hosta.examplecorp.local", page=1, page_size=25)["report"]
    short_report = correlation_engine.run_correlation_engine(db, CASE_ID, host="HOSTA", page=1, page_size=25)["report"]

    assert alias_report["effective_scope"]["canonical_host"] == "hosta"
    assert short_report["effective_scope"]["canonical_host"] == "hosta"
    assert alias_report["cache_key"] == short_report["cache_key"]
    assert alias_report["cache_key"] != all_report["cache_key"]
