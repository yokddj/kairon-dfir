from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.event_marking import EventMarking
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.models.timeline_bookmark import TimelineBookmark, TimelineBookmarkCategory, TimelineBookmarkImportance
from app.services import timeline_service


class _FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, count):
        self.items = self.items[:count]
        return self

    def all(self):
        return list(self.items)


class _FakeDb:
    def __init__(self, findings: list[Finding] | None = None, bookmarks: list[TimelineBookmark] | None = None, markings: list[EventMarking] | None = None):
        self.findings = findings or []
        self.bookmarks = bookmarks or []
        self.markings = markings or []

    def query(self, model):
        if model is Finding:
            return _FakeQuery(self.findings)
        if model is TimelineBookmark:
            return _FakeQuery(self.bookmarks)
        if model is EventMarking:
            return _FakeQuery(self.markings)
        return _FakeQuery([])

    def get(self, model, identifier):
        if model is Finding:
            return next((item for item in self.findings if item.id == identifier), None)
        if model is TimelineBookmark:
            return next((item for item in self.bookmarks if item.id == identifier), None)
        return None

    def add(self, item):
        if isinstance(item, TimelineBookmark) and item not in self.bookmarks:
            self.bookmarks.append(item)

    def commit(self):
        return None

    def refresh(self, _item):
        return None

    def delete(self, item):
        if item in self.bookmarks:
            self.bookmarks.remove(item)


def _event_doc(event_id: str, *, ts: str, host: str = "movistar-pc", evidence_id: str = "ev-1", risk: int = 0, artifact_type: str = "process", event_type: str = "process_start", message: str = "event", category: str = "execution"):
    return {
        "id": event_id,
        "kind": "event",
        "timestamp": ts,
        "title": message,
        "summary": message,
        "artifact_type": artifact_type,
        "event_type": event_type,
        "severity": "high" if risk >= 70 else "info",
        "risk_score": risk,
        "host": host,
        "user": "alex",
        "source_file": "test.jsonl",
        "matched_fields": [],
        "highlights": {},
        "raw": {
            "event_id": event_id,
            "evidence_id": evidence_id,
            "@timestamp": ts,
            "host": {"name": host},
            "user": {"name": "alex"},
            "artifact": {"type": artifact_type},
            "event": {"type": event_type, "category": category, "message": message},
            "process": {"entity_id": f"proc-{event_id}", "name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"},
            "file": {"path": f"C:\\Users\\dfir\\Downloads\\{event_id}.exe"},
        },
    }


def test_timeline_full_returns_events_ordered_asc_desc(monkeypatch):
    rows = [
        _event_doc("evt-1", ts="2026-05-15T10:00:00Z", message="first"),
        _event_doc("evt-2", ts="2026-05-15T11:00:00Z", message="second"),
    ]
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda case_id, params, **_kwargs: (2, list(rows if params.get("sort") == "timestamp_asc" else reversed(rows)), [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))

    db = _FakeDb()
    asc = timeline_service.build_timeline_response(db, "case-1", {"mode": "full", "sort": "timestamp_asc", "page_size": 10, "include_findings": False, "include_bookmarks": False})
    desc = timeline_service.build_timeline_response(db, "case-1", {"mode": "full", "sort": "timestamp_desc", "page_size": 10, "include_findings": False, "include_bookmarks": False})

    assert [item["id"] for item in asc["items"]] == ["evt-1", "evt-2"]
    assert [item["id"] for item in desc["items"]] == ["evt-2", "evt-1"]


def test_timeline_filters_by_host_and_evidence(monkeypatch):
    captured = {}

    def _fake_search(case_id, params, **_kwargs):
        captured["host"] = params.get("host")
        captured["evidence_id"] = params.get("evidence_id")
        return 1, [_event_doc("evt-1", ts="2026-05-15T10:00:00Z", host="desktop-01", evidence_id="ev-2")], [], {}

    monkeypatch.setattr(timeline_service, "search_events_v2", _fake_search)
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))

    response = timeline_service.build_timeline_response(_FakeDb(), "case-1", {"host": "desktop-01", "evidence_id": "ev-2", "include_findings": False, "include_bookmarks": False})

    assert captured == {"host": "desktop-01", "evidence_id": "ev-2"}
    assert response["items"][0]["host"] == "desktop-01"
    assert response["items"][0]["evidence_id"] == "ev-2"


def test_incident_timeline_builder_uses_high_signal_sources(monkeypatch):
    event_row = _event_doc(
        "evt-psexec",
        ts="2024-03-22T11:30:00Z",
        host="HOSTA",
        evidence_id="ev-1",
        risk=85,
        message="psexec.exe remote execution",
    )

    monkeypatch.setattr(
        timeline_service,
        "get_command_history",
        lambda *_args, **_kwargs: {
            "items": [
                {
                    "id": "cmd-1",
                    "timestamp": "2024-03-22T11:29:00Z",
                    "host": "HOSTA",
                    "evidence_id": "ev-1",
                    "command": "cmd.exe /c C:\\Users\\Public\\psexec.exe \\\\HOSTB powershell -ep bypass",
                    "launcher": "psexec.exe",
                    "shell_family": "remote_exec",
                    "risk_score": 90,
                    "risk_reasons": ["PsExec activity"],
                    "supporting_events": [{"event_id": "evt-psexec"}],
                    "parent_process": {"name": "cmd.exe", "pid": 13492},
                }
            ]
        },
    )
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, [event_row], [], {}))

    response = timeline_service.build_incident_timeline_draft(
        _FakeDb(),
        "case-1",
        {"sources": ["command_history", "defender"], "max_items": 10},
    )

    assert response["no_mft_flood_default"] is True
    assert response["items"]
    assert any(item["phase"] == "lateral_movement" for item in response["items"])
    assert any(item["source"] == "command_history" for item in response["items"])
    assert any(item["status"] == "candidate" for item in response["items"])
    assert all(item.get("source_type") for item in response["items"])
    assert response["curation"]["candidate_count"] >= 1


def test_incident_timeline_finding_is_official_and_candidates_are_separate(monkeypatch):
    finding = Finding(
        id="finding-1",
        case_id="case-1",
        title="Confirmed lateral movement",
        severity=FindingSeverity.high,
        status=FindingStatus.new,
        finding_type="lateral_movement",
        risk_score=90,
        related_hosts=["HOSTA"],
    )
    monkeypatch.setattr(timeline_service, "get_command_history", lambda *_args, **_kwargs: {"items": []})
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (0, [], [], {}))

    response = timeline_service.build_incident_timeline_draft(_FakeDb(findings=[finding]), "case-1", {"sources": ["findings"], "max_items": 10})

    assert response["items"][0]["status"] == "accepted"
    assert response["items"][0]["confidence"] == "analyst_verified"
    assert response["items"][0]["source_type"] == "finding"
    assert response["curation"]["official_count"] == 1


def test_incident_timeline_canonicalizes_host_aliases_and_caches(monkeypatch):
    timeline_service._INCIDENT_DRAFT_CACHE.clear()
    event_row = _event_doc(
        "evt-1",
        ts="2024-03-22T11:30:00Z",
        host="hosta.examplecorp.local",
        evidence_id="ev-1",
        risk=85,
        message="powershell -ep bypass",
    )
    monkeypatch.setattr(timeline_service, "get_command_history", lambda *_args, **_kwargs: {"items": []})
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, [event_row], [], {}))

    first = timeline_service.build_incident_timeline_draft(
        _FakeDb(),
        "case-cache",
        {"sources": ["defender"], "max_items": 10},
    )
    second = timeline_service.build_incident_timeline_draft(
        _FakeDb(),
        "case-cache",
        {"sources": ["defender"], "max_items": 10},
    )

    assert first["items"][0]["host"] == "HOSTA"
    assert first["items"][0]["host_alias"] == "hosta.examplecorp.local"
    assert first["hosts"] == ["HOSTA"]
    assert first["cache"]["hit"] is False
    assert second["cache"]["hit"] is True


def test_incident_timeline_persistent_cache_survives_memory_clear_and_stales(monkeypatch):
    timeline_service._INCIDENT_DRAFT_CACHE.clear()
    case_id = "11111111-1111-4111-8111-111111111111"
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, future=True)
    db = Session()
    event_row = _event_doc(
        "evt-1",
        ts="2024-03-22T11:30:00Z",
        host="HOSTA",
        evidence_id="ev-1",
        risk=85,
        message="defender detection",
        artifact_type="defender",
    )
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, [event_row], [], {}))
    monkeypatch.setattr(timeline_service, "get_command_history", lambda *_args, **_kwargs: {"items": []})

    first = timeline_service.build_incident_timeline_draft(db, case_id, {"sources": ["defender"], "max_items": 10})
    assert first["cache"]["persistent"] is True
    assert first["cache"]["hit"] is False
    assert db.query(IncidentTimelineDraft).count() == 1

    timeline_service._INCIDENT_DRAFT_CACHE.clear()
    second = timeline_service.build_incident_timeline_draft(db, case_id, {"sources": ["defender"], "max_items": 10})
    assert second["cache"]["hit"] is True
    assert second["cache"]["persistent"] is True
    assert second["cache"]["status"] == "fresh"

    db.add(EventMarking(case_id=case_id, event_id="evt-marked", status="suspicious", artifact_type="process", host="HOSTA"))
    db.commit()
    timeline_service._INCIDENT_DRAFT_CACHE.clear()
    stale = timeline_service.build_incident_timeline_draft(db, case_id, {"sources": ["defender"], "max_items": 10})
    assert stale["cache"]["hit"] is True
    assert stale["cache"]["status"] == "stale"
    assert "outdated" in " ".join(stale["warnings"]).lower()

    regenerated = timeline_service.build_incident_timeline_draft(db, case_id, {"sources": ["defender"], "max_items": 10, "regenerate": True})
    assert regenerated["cache"]["hit"] is False
    assert regenerated["cache"]["status"] == "fresh"


def test_incident_timeline_export_markdown_includes_phase_and_evidence():
    markdown = timeline_service.export_incident_timeline_markdown(
        "case-1",
        {
            "items": [
                {
                    "timestamp": "2024-03-22T11:30:00Z",
                    "host": "HOSTA",
                    "phase": "lateral_movement",
                    "title": "PsExec movement",
                    "summary": "HOSTA to HOSTB",
                    "source": "command_history",
                    "artifact_type": "command_history",
                    "event_id": "evt-1",
                    "status": "accepted",
                    "provenance_badge": "Analyst verified",
                }
            ]
        },
    )

    assert "Incident Timeline" in markdown
    assert "lateral_movement" in markdown
    assert "event `evt-1`" in markdown
    assert "Analyst verified" in markdown


def test_incident_timeline_export_excludes_candidates_by_default():
    markdown = timeline_service.export_incident_timeline_markdown(
        "case-1",
        {
            "items": [
                {"timestamp": "2024-03-22T11:30:00Z", "host": "HOSTA", "phase": "execution", "title": "Official", "source": "finding", "status": "accepted"},
                {"timestamp": "2024-03-22T11:31:00Z", "host": "HOSTA", "phase": "execution", "title": "Candidate", "source": "command_history", "status": "candidate"},
            ]
        },
    )

    assert "Official" in markdown
    assert "Candidate" not in markdown


def test_incident_timeline_item_status_update_persists_and_summarizes():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, future=True)
    db = Session()
    draft = IncidentTimelineDraft(
        case_id="case-1",
        option_key="opt",
        cache_key="cache",
        builder_version="v-test",
        data_fingerprint="fingerprint",
        payload={
            "items": [
                {"id": "candidate-1", "title": "Candidate", "status": "candidate", "source": "command_history", "source_type": "command_history"}
            ]
        },
    )
    db.add(draft)
    db.commit()
    db.refresh(draft)

    response = timeline_service.update_incident_timeline_item_status(db, "case-1", draft.id, "candidate-1", {"status": "accepted"})

    assert response["item"]["status"] == "accepted"
    assert response["curation"]["official_count"] == 1
    db.refresh(draft)
    assert draft.payload["items"][0]["status"] == "accepted"


def test_incident_story_target_classifies_exact_process():
    item = {
        "source": "command_history",
        "source_type": "command_history",
        "artifact_type": "windows_event",
        "event_id": "evt-1",
        "execution_story_url": "/cases/case-1/process-graph?story_event_id=evt-1",
        "title": "PowerShell script.ps1 execution",
        "summary": "powershell.exe -ep bypass .\\f\\script.ps1",
    }

    target = timeline_service._classify_story_target(item)

    assert target["story_target_type"] == "exact_process"
    assert target["story_primary_action"] == "Open Execution Story"


def test_incident_story_target_classifies_defender_file_and_movement():
    defender = timeline_service._classify_story_target({"source_type": "defender_detection", "artifact_type": "defender", "title": "Rubeus detected"})
    file_item = timeline_service._classify_story_target({"artifact_type": "mft", "title": "sample.iso", "summary": "C:\\Users\\usera\\Downloads\\sample.iso"})
    movement = timeline_service._classify_story_target({"phase": "lateral_movement", "title": "HOSTA -> HOSTB PsExec maintenance.ps1"})

    assert defender["story_target_type"] == "defender_detection"
    assert file_item["story_target_type"] == "file_artifact"
    assert movement["story_target_type"] == "lateral_movement"


def test_incident_story_bundle_returns_context_for_non_process_item(monkeypatch):
    item = {
        "id": "file-1",
        "timestamp": "2024-03-22T11:00:00Z",
        "host": "HOSTA",
        "phase": "initial_access",
        "title": "sample.iso opened",
        "summary": "C:\\Users\\usera\\Downloads\\sample.iso",
        "source": "validation_matrix",
        "source_type": "validation_matrix",
        "artifact_type": "mft",
        "status": "accepted",
        "search_url": "/cases/case-1/search?q=sample.iso",
    }
    monkeypatch.setattr(timeline_service, "build_incident_timeline_draft", lambda *_args, **_kwargs: {"items": timeline_service._apply_story_target_metadata([item])})

    bundle = timeline_service.build_incident_timeline_story_bundle(_FakeDb(), "case-1", "file-1")

    assert bundle["target"]["type"] == "file_artifact"
    assert bundle["file_story"]["file_name"] == "sample.iso"
    assert bundle["file_story"]["found_in_mft"] is True
    assert bundle["pivots"]["find_this_file"] == "/cases/case-1/search?host=HOSTA&q=sample.iso"
    assert bundle["pivots"]["validation_matrix"] == "/cases/case-1/validation-matrix"


def test_file_reference_extraction_prefers_query_over_narrative():
    item = {
        "title": "Suspicious ISO appears on HOSTA",
        "summary": "User activity and filesystem evidence identify the lure that starts the investigation. sample.iso",
        "query": "sample.iso",
    }

    assert timeline_service._select_file_reference(item) == "sample.iso"
    assert timeline_service._extract_file_basename(timeline_service._select_file_reference(item)) == "sample.iso"


def test_file_reference_extraction_supports_relative_script_path():
    item = {"query": r".\f\script.ps1", "summary": "powershell.exe -ep bypass -NoExit .\\f\\script.ps1"}

    assert timeline_service._select_file_reference(item) == r".\f\script.ps1"
    assert timeline_service._extract_file_basename(timeline_service._select_file_reference(item)) == "script.ps1"


def test_referenced_file_resolution_command_only_when_artifact_absent():
    item = {"source_type": "command_history", "query": r".\f\script.ps1", "command_id": "cmd-1"}

    resolution = timeline_service._referenced_file_resolution(item, file_reference=r".\f\script.ps1", basename="script.ps1")

    assert resolution["status"] == "found_only_in_command"
    assert resolution["found_in_mft"] is False
    assert resolution["found_only_in_command"] is True
    assert "mounted ISO" in resolution["explanation"]


def test_incident_story_target_falls_back_when_identity_is_insufficient():
    target = timeline_service._classify_story_target({"title": "Broad validation note", "summary": "No exact source event"})

    assert target["story_target_type"] == "none"
    assert "insufficient" in target["story_target_reason"]


def test_timeline_explicit_filters_are_applied_after_merge(monkeypatch):
    defender_row = _event_doc(
        "evt-1",
        ts="2026-05-15T10:00:00Z",
        artifact_type="defender",
        event_type="defender_detection",
        category="detection",
        risk=80,
        message="defender",
    )
    persistence_row = _event_doc(
        "evt-2",
        ts="2026-05-15T10:10:00Z",
        artifact_type="scheduled_task",
        event_type="scheduled_task",
        category="persistence",
        risk=0,
        message="task",
    )
    finding = Finding(
        id="finding-1",
        case_id="case-1",
        title="Persistence finding",
        severity=FindingSeverity.high,
        status=FindingStatus.new,
        risk_score=90,
        related_event_ids=["evt-2"],
    )
    finding_row = timeline_service._format_finding_result(finding)

    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (2, [defender_row, persistence_row], [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (1, [finding_row], [finding], []))
    monkeypatch.setattr(timeline_service, "_event_map_for_ids", lambda case_id, ids: {"evt-2": persistence_row["raw"]})

    response = timeline_service.build_timeline_response(
        _FakeDb(findings=[finding]),
        "case-1",
        {"mode": "investigation", "artifact_type": ["defender"], "include_findings": True, "include_bookmarks": False, "page_size": 20},
    )

    assert [item["id"] for item in response["items"]] == ["evt-1"]
    assert response["items"][0]["artifact_type"] == "defender"


def test_investigation_mode_includes_findings_and_bookmarks(monkeypatch):
    event_rows = [_event_doc("evt-1", ts="2026-05-15T10:00:00Z", risk=80)]
    finding = Finding(id="finding-1", case_id="case-1", title="Suspicious chain", severity=FindingSeverity.high, status=FindingStatus.new, risk_score=90, related_event_ids=["evt-2"])
    finding_row = timeline_service._format_finding_result(finding)
    bookmark = TimelineBookmark(
        id="bookmark-1",
        case_id="case-1",
        event_id="evt-3",
        timestamp=datetime(2026, 5, 15, 12, 0, tzinfo=UTC),
        title="Bookmarked",
        summary="selected",
        note="important",
        category=TimelineBookmarkCategory.execution,
        importance=TimelineBookmarkImportance.high,
        order_index=1,
        include_in_report=True,
    )

    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, event_rows, [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (1, [finding_row], [finding], []))
    monkeypatch.setattr(timeline_service, "_event_map_for_ids", lambda case_id, ids: {"evt-2": _event_doc("evt-2", ts="2026-05-15T11:00:00Z", risk=20)["raw"], "evt-3": _event_doc("evt-3", ts="2026-05-15T12:00:00Z", risk=10)["raw"]})

    response = timeline_service.build_timeline_response(_FakeDb(findings=[finding], bookmarks=[bookmark]), "case-1", {"mode": "investigation", "page_size": 20})
    kinds = {item["kind"] for item in response["items"]}

    assert "event" in kinds
    assert "finding" in kinds
    assert "bookmark" in kinds


def test_timeline_around_event_returns_window(monkeypatch):
    monkeypatch.setattr(timeline_service, "fetch_event_by_id", lambda *args, **kwargs: {"@timestamp": "2026-05-15T10:00:00Z", "evidence_id": "ev-1"})
    monkeypatch.setattr(timeline_service, "build_timeline_response", lambda db, case_id, params: {"query": params, "items": []})

    response = timeline_service.timeline_around_event(_FakeDb(), "case-1", "evt-1", window="30m", page_size=50)

    assert response["query"]["sort"] == "timestamp_asc"
    assert response["query"]["evidence_id"] == "ev-1"


def test_timeline_around_finding_returns_finding_and_related_events(monkeypatch):
    finding = Finding(
        id="finding-1",
        case_id="case-1",
        title="Chain",
        severity=FindingSeverity.high,
        status=FindingStatus.new,
        time_start=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        time_end=datetime(2026, 5, 15, 11, 0, tzinfo=UTC),
        related_hosts=["desktop-01"],
    )
    monkeypatch.setattr(timeline_service, "build_timeline_response", lambda db, case_id, params: {"query": params, "items": []})
    monkeypatch.setattr(timeline_service, "search_related_to_finding_v2", lambda db, case_id, finding_id, page_size=100: {"results": [{"id": "evt-1"}]})

    response = timeline_service.timeline_around_finding(_FakeDb(findings=[finding]), "case-1", "finding-1", window="30m", page_size=50)

    assert response["finding"]["id"] == "finding-1"
    assert response["related_events"]["results"][0]["id"] == "evt-1"


def test_key_event_create_list_update_delete(monkeypatch):
    db = _FakeDb()
    monkeypatch.setattr(timeline_service, "fetch_event_by_id", lambda *args, **kwargs: {"@timestamp": "2026-05-15T10:00:00Z", "raw_summary": "Payload executed", "event": {"message": "Process started"}, "stable_event_id": "stable-evt-1"})

    created = timeline_service.create_key_event(
        db,
        "case-1",
        {"event_id": "evt-1", "note": "Payload executed after download", "category": "execution", "importance": "high"},
    )
    listed = timeline_service.list_key_events(db, "case-1")
    updated = timeline_service.update_key_event(db, "case-1", created["id"], {"note": "Updated", "importance": "critical"})
    timeline_service.delete_key_event(db, "case-1", created["id"])

    assert created["event_id"] == "evt-1"
    assert created["stable_event_id"] == "stable-evt-1"
    assert listed[0]["id"] == created["id"]
    assert updated["importance"] == "critical"
    assert db.bookmarks == []


def test_bookmark_appears_in_timeline(monkeypatch):
    bookmark = TimelineBookmark(
        id="bookmark-1",
        case_id="case-1",
        event_id="evt-1",
        timestamp=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        title="Key event",
        summary="selected",
        note="note",
        category=TimelineBookmarkCategory.execution,
        importance=TimelineBookmarkImportance.high,
        order_index=0,
        include_in_report=True,
    )
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, [_event_doc("evt-1", ts="2026-05-15T10:00:00Z")], [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))
    monkeypatch.setattr(timeline_service, "_event_map_for_ids", lambda case_id, ids: {"evt-1": _event_doc("evt-1", ts="2026-05-15T10:00:00Z")["raw"]})

    response = timeline_service.build_timeline_response(_FakeDb(bookmarks=[bookmark]), "case-1", {"mode": "full", "page_size": 20})

    event_row = next(item for item in response["items"] if item["kind"] == "event")
    assert event_row["is_key_event"] is True


def test_timeline_cursor_pagination_has_no_duplicates(monkeypatch):
    rows = [_event_doc(f"evt-{index}", ts=f"2026-05-15T10:{index:02d}:00Z") for index in range(5)]
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (5, rows, [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))

    first = timeline_service.build_timeline_response(_FakeDb(), "case-1", {"page_size": 2, "include_findings": False, "include_bookmarks": False})
    second = timeline_service.build_timeline_response(_FakeDb(), "case-1", {"page_size": 2, "cursor": first["next_cursor"], "include_findings": False, "include_bookmarks": False})

    first_ids = {item["id"] for item in first["items"]}
    second_ids = {item["id"] for item in second["items"]}
    assert not first_ids.intersection(second_ids)


def test_timeline_facets_returned(monkeypatch):
    monkeypatch.setattr(timeline_service, "search_events_v2", lambda *args, **kwargs: (1, [_event_doc("evt-1", ts="2026-05-15T10:00:00Z", artifact_type="dns", event_type="dns_query")], [], {}))
    monkeypatch.setattr(timeline_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))

    response = timeline_service.build_timeline_response(_FakeDb(), "case-1", {"page_size": 10, "include_findings": False, "include_bookmarks": False})

    assert response["facets"]["artifact_type"]["dns"] == 1


def test_lightweight_timeline_uses_timestamped_event_search_without_heavy_facets(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_search(case_id, params, **_kwargs):
        captured.update(params)
        return 2, [
            _event_doc("evt-1", ts="2026-05-15T10:00:00Z", artifact_type="browser", event_type="browser_visit"),
            _event_doc("evt-2", ts="2026-05-15T11:00:00Z", artifact_type="windows_event", event_type="process_start"),
        ], [], {}

    monkeypatch.setattr(timeline_service, "search_events_v2", _fake_search)

    response = timeline_service.build_lightweight_timeline_response(
        _FakeDb(),
        "case-1",
        {"evidence_id": "ev-1", "page_size": 100, "group_by": "hour"},
    )

    assert captured["evidence_id"] == "ev-1"
    assert captured["has_timestamp"] is True
    assert captured["timeline_only"] is True
    assert captured["include_highlights"] is False
    assert captured["include_facets"] is False
    assert response["timeline_status"] == "lightweight"
    assert response["timestamped_docs_count"] == 2
    assert response["facets"] == {}
    assert [item["id"] for item in response["items"]] == ["evt-1", "evt-2"]


def test_lightweight_timeline_clamps_page_size(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_search(case_id, params, **_kwargs):
        captured["page_size"] = params.get("page_size")
        return 0, [], [], {}

    monkeypatch.setattr(timeline_service, "search_events_v2", _fake_search)

    response = timeline_service.build_lightweight_timeline_response(_FakeDb(), "case-1", {"page_size": 999})

    assert captured["page_size"] == 500
    assert response["page_size"] == 500


def test_markdown_export_basic():
    bookmark = TimelineBookmark(
        id="bookmark-1",
        case_id="case-1",
        event_id="evt-1",
        finding_id="finding-1",
        timestamp=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        title="Payload executed",
        summary="Process execution observed",
        note="Review process tree",
        category=TimelineBookmarkCategory.execution,
        importance=TimelineBookmarkImportance.high,
        order_index=0,
        include_in_report=True,
    )
    markdown = timeline_service.export_key_events_markdown(_FakeDb(bookmarks=[bookmark]), "case-1", {"host": "desktop-01"})

    assert "# Case Timeline Export" in markdown
    assert "Payload executed" in markdown
    assert "Review process tree" in markdown


def test_no_cross_case_leakage_for_bookmark_delete():
    bookmark = TimelineBookmark(
        id="bookmark-1",
        case_id="case-2",
        event_id="evt-1",
        timestamp=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        title="Other case",
        summary="x",
        note=None,
        category=TimelineBookmarkCategory.other,
        importance=TimelineBookmarkImportance.low,
        order_index=0,
        include_in_report=True,
    )
    with pytest.raises(HTTPException):
        timeline_service.delete_key_event(_FakeDb(bookmarks=[bookmark]), "case-1", "bookmark-1")
