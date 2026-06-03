from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import HTTPException

from app.models.case import Case, CaseMode
from app.models.case_report import CaseReport
from app.models.detection_result import DetectionResult
from app.models.event_marking import EventMarking
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.timeline_bookmark import TimelineBookmark, TimelineBookmarkCategory, TimelineBookmarkImportance
from app.services import report_service


class _FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.items)


class _FakeDb:
    def __init__(
        self,
        *,
        case: Case,
        findings: list[Finding] | None = None,
        bookmarks: list[TimelineBookmark] | None = None,
        reports: list[CaseReport] | None = None,
        detections: list[DetectionResult] | None = None,
        markings: list[EventMarking] | None = None,
        evidences: list | None = None,
    ):
        self.case = case
        self.findings = findings or []
        self.bookmarks = bookmarks or []
        self.reports = reports or []
        self.detections = detections or []
        self.markings = markings or []
        self.evidences = evidences or []

    def query(self, model):
        if model is Finding:
            return _FakeQuery(self.findings)
        if model is TimelineBookmark:
            return _FakeQuery(self.bookmarks)
        if model is CaseReport:
            return _FakeQuery(self.reports)
        if model is DetectionResult:
            return _FakeQuery(self.detections)
        if model is EventMarking:
            return _FakeQuery(self.markings)
        if model.__name__ == "Evidence":
            return _FakeQuery(self.evidences)
        return _FakeQuery([])

    def get(self, model, identifier):
        if model is Case and self.case.id == identifier:
            return self.case
        if model is CaseReport:
            return next((item for item in self.reports if item.id == identifier), None)
        return None

    def add(self, item):
        if isinstance(item, CaseReport) and item not in self.reports:
            self.reports.append(item)

    def commit(self):
        return None

    def refresh(self, _item):
        return None


def _finding(
    identifier: str,
    *,
    title: str,
    severity: FindingSeverity,
    status: FindingStatus,
    finding_type: str = "office_powershell",
    risk: int = 80,
    evidence_id: str | None = "ev-1",
    hosts: list[str] | None = None,
    files: list[str] | None = None,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
) -> Finding:
    return Finding(
        id=identifier,
        case_id="case-1",
        title=title,
        description=f"{title} description",
        severity=severity,
        status=status,
        finding_type=finding_type,
        risk_score=risk,
        evidence_id=evidence_id,
        related_hosts=hosts or ["desktop-01"],
        related_files=files or ["C:\\Users\\dfir\\Downloads\\payload.exe"],
        related_domains=domains or ["duckdns.org"],
        related_ips=ips or ["185.10.10.10"],
        reasons=["PowerShell resolved duckdns.org", "token=abcdef0123456789abcdef0123456789abcdef012345"],
        recommended_triage=["Review process tree", "Reset credentials if exposure is confirmed"],
        related_event_ids=["evt-1"],
        related_process_node_ids=["proc-1"],
        timeline=[{"timestamp": "2026-05-15T10:00:00Z", "event_type": "process_start", "summary": "WINWORD.EXE -> powershell.exe", "event_id": "evt-1"}],
        created_at=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        time_start=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        time_end=datetime(2026, 5, 15, 10, 5, tzinfo=UTC),
    )


def _bookmark(identifier: str, *, event_id: str, host: str = "desktop-01", evidence_id: str = "ev-1", order_index: int = 0) -> TimelineBookmark:
    bookmark = TimelineBookmark(
        id=identifier,
        case_id="case-1",
        event_id=event_id,
        timestamp=datetime(2026, 5, 15, 10, order_index, tzinfo=UTC),
        title=f"Bookmark {identifier}",
        summary="Payload executed",
        note="Payload executed after browser download",
        category=TimelineBookmarkCategory.execution,
        importance=TimelineBookmarkImportance.high,
        order_index=order_index,
        include_in_report=True,
    )
    bookmark._host = host  # type: ignore[attr-defined]
    bookmark._evidence_id = evidence_id  # type: ignore[attr-defined]
    return bookmark


def _event_payload(host: str = "desktop-01", evidence_id: str = "ev-1"):
    return {
        "evidence_id": evidence_id,
        "host": {"name": host},
        "file": {
            "path": "C:\\Users\\dfir\\Downloads\\payload.exe",
            "sha256": "a" * 64,
        },
        "download": {"url": "https://raw.githubusercontent.com/example/payload.exe"},
        "dns": {"domain": "duckdns.org", "ip": "185.10.10.10"},
        "registry": {"key_path": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc AAAA", "path": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        "network": {"destination_ip": "185.10.10.10"},
    }


def _detection(identifier: str, *, host: str = "desktop-01", evidence_id: str = "ev-1", status: str = "new", severity: str = "high", risk: int = 80) -> DetectionResult:
    return DetectionResult(
        id=identifier,
        case_id="case-1",
        evidence_id=evidence_id,
        engine="sigma",
        rule_name="Suspicious PowerShell",
        rule_title="Suspicious PowerShell",
        rule_level=severity,
        severity=severity,
        status=status,
        risk_score=risk,
        host_name=host,
        matched_at="2026-05-15T10:01:00Z",
        target_type="event",
        matched_fields={"CommandLine": "powershell.exe -ep bypass"},
        created_at=datetime(2026, 5, 15, 10, 1, tzinfo=UTC),
    )


def _marking(identifier: str, *, host: str = "desktop-01", evidence_id: str = "ev-1", status: str = "suspicious") -> EventMarking:
    return EventMarking(
        id=identifier,
        case_id="case-1",
        evidence_id=evidence_id,
        event_id=f"event-{identifier}",
        search_doc_id=f"doc-{identifier}",
        artifact_type="windows_event",
        timestamp=datetime(2026, 5, 15, 10, 2, tzinfo=UTC),
        host=host,
        status=status,
        labels=["validation-sample"],
        note="Analyst marked this event.",
    )


def test_create_draft_auto_selects_high_findings_and_key_events(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open")
    findings = [
      _finding("finding-1", title="Office spawned PowerShell", severity=FindingSeverity.high, status=FindingStatus.confirmed),
      _finding("finding-2", title="Low noise", severity=FindingSeverity.low, status=FindingStatus.new, risk=10),
    ]
    bookmarks = [_bookmark("bookmark-1", event_id="evt-1")]
    db = _FakeDb(case=case, findings=findings, bookmarks=bookmarks)
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *args, **kwargs: _event_payload())

    report = report_service.create_case_report_draft(db, "case-1", {"auto_select": True, "filters": {"include_statuses": ["confirmed", "reviewed", "new"], "min_severity": "medium"}})

    assert report["selected_finding_ids"] == ["finding-1"]
    assert report["selected_key_event_ids"] == ["bookmark-1"]
    assert report["selected_process_chain_ids"] == ["finding-1"]


def test_create_draft_uses_generic_title_when_case_name_missing() -> None:
    case = Case(id="12345678-1234-4000-8000-abcdefabcdef", name="", status="open")
    db = _FakeDb(case=case, findings=[], bookmarks=[])

    report = report_service.create_case_report_draft(db, case.id, {"auto_select": False})

    assert report["title"] == "Kairon DFIR Investigation Report - Case 12345678"


def test_create_draft_includes_ground_truth_only_for_validation_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    class _SettingsDisabled:
        validation_features_enabled = False

    class _SettingsEnabled:
        validation_features_enabled = True

    monkeypatch.setattr(report_service, "get_settings", lambda: _SettingsDisabled())
    normal_case = Case(id="normal-case", name="Normal investigation", status="open")
    normal_db = _FakeDb(case=normal_case, findings=[], bookmarks=[])
    normal_report = report_service.create_case_report_draft(normal_db, normal_case.id, {"auto_select": False})

    validation_case = Case(id="validation-case", name="Validation sample", status="open", mode=CaseMode.validation)
    disabled_db = _FakeDb(case=validation_case, findings=[], bookmarks=[])
    disabled_report = report_service.create_case_report_draft(disabled_db, validation_case.id, {"auto_select": False})

    monkeypatch.setattr(report_service, "get_settings", lambda: _SettingsEnabled())
    enabled_db = _FakeDb(case=validation_case, findings=[], bookmarks=[])
    validation_report = report_service.create_case_report_draft(enabled_db, validation_case.id, {"auto_select": False})

    assert normal_report["filters"]["include_ground_truth_coverage"] is False
    assert disabled_report["filters"]["include_ground_truth_coverage"] is False
    assert validation_report["filters"]["include_ground_truth_coverage"] is True


def test_preview_contains_core_sections_and_respects_disabled_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open", timezone="UTC")
    finding = _finding("finding-1", title="Office spawned PowerShell", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    bookmark = _bookmark("bookmark-1", event_id="evt-1")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Kairon DFIR Investigation Report - Movistar",
        template="standard_investigation",
        sections_enabled={**report_service.DEFAULT_SECTIONS_ENABLED, "appendix": False},
        analyst_notes={"executive_summary": "Analyst summary", "recommendations": "", "limitations": ""},
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=["finding-1"],
        selected_key_event_ids=["bookmark-1"],
        selected_process_chain_ids=["finding-1"],
    )
    db = _FakeDb(case=case, findings=[finding], bookmarks=[bookmark], reports=[report])
    monkeypatch.setattr(report_service, "_build_case_context", lambda db, case_id: {"case": {"id": case_id, "name": "Movistar"}, "hosts": [{"host": "desktop-01", "events_count": 15, "findings_count": 1, "high_risk_count": 1}], "evidences": [{"id": "ev-1", "name": "Collection.zip", "status": "completed", "storage_mode": "uploaded", "is_external": False, "events_indexed": 15, "parser_errors": 0, "detected_host": "desktop-01"}], "summary": {"events_indexed": 15, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []}})
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *args, **kwargs: _event_payload())

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    section_ids = [section["id"] for section in preview["sections"]]

    assert "executive_summary" in section_ids
    assert "scope" in section_ids
    assert "findings" in section_ids
    assert "timeline" in section_ids
    assert "appendix" not in section_ids
    assert "Analyst summary" in preview["sections"][0]["markdown"]


def test_preview_reports_filter_counts_and_includes_marked_events_and_detections(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Validation sample", status="open", timezone="UTC")
    finding = _finding("finding-1", title="Validation sample PowerShell", severity=FindingSeverity.high, status=FindingStatus.confirmed, hosts=["HOSTA"])
    bookmark = _bookmark("bookmark-1", event_id="evt-1", host="HOSTA", evidence_id="ev-1")
    detection = _detection("det-1", host="hosta.examplecorp.local", evidence_id="ev-1", status="new", severity="high", risk=90)
    dismissed = _detection("det-2", host="hosta.examplecorp.local", evidence_id="ev-1", status="dismissed", severity="high", risk=90)
    marking = _marking("mark-1", host="hosta.examplecorp.local", evidence_id="ev-1", status="suspicious")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="HOSTA report",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters={
            **report_service.DEFAULT_FILTERS,
            "host": "HOSTA",
            "evidence_id": "ev-1",
            "include_findings": True,
            "include_detections": True,
            "include_marked_events": True,
            "include_timeline_events": True,
            "detection_statuses": ["new", "reviewed", "confirmed"],
            "marking_statuses": ["suspicious", "important"],
        },
        selected_finding_ids=["finding-1"],
        selected_key_event_ids=["bookmark-1"],
        selected_process_chain_ids=[],
    )
    db = _FakeDb(case=case, findings=[finding], bookmarks=[bookmark], reports=[report], detections=[detection, dismissed], markings=[marking])
    monkeypatch.setattr(report_service, "_build_case_context", lambda db, case_id: {"case": {"id": case_id, "name": "Validation sample"}, "hosts": [{"host": "HOSTA", "events_count": 71033, "findings_count": 1, "high_risk_count": 1}], "evidences": [{"id": "ev-1", "name": "HOSTA.7z", "status": "completed", "storage_mode": "uploaded", "is_external": False, "events_indexed": 71033, "parser_errors": 0, "detected_host": "HOSTA"}], "summary": {"events_indexed": 71033, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []}})
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *args, **kwargs: _event_payload(host="HOSTA", evidence_id="ev-1"))

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    section_ids = [section["id"] for section in preview["sections"]]
    timeline_section = next(section for section in preview["sections"] if section["id"] == "timeline")
    detections_section = next(section for section in preview["sections"] if section["id"] == "detections")

    assert preview["counts"]["findings_matched"] == 1
    assert preview["counts"]["detections_matched"] == 1
    assert preview["counts"]["marked_events_matched"] == 1
    assert preview["counts"]["timeline_events_matched"] == 1
    assert preview["filters_applied"]["host"] == "HOSTA"
    assert preview["filters_applied"]["evidence_id"] == "ev-1"
    assert "detections" in section_ids
    assert "Suspicious PowerShell" in detections_section["markdown"]
    assert "dismissed" not in detections_section["markdown"]
    assert "Analyst marked this event." in timeline_section["markdown"]


def test_preview_and_markdown_include_command_history_and_execution_story(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Validation sample", status="open", timezone="UTC")
    evidence = Evidence(id="ev-1", case_id="case-1", original_filename="HOSTA.7z", stored_path="/tmp/HOSTA.7z", sha256="a" * 64, size_bytes=1)
    marking = _marking("cmd-mark-1", host="HOSTA", evidence_id="ev-1", status="suspicious")
    marking.event_id = "evt-ps"
    marking.search_doc_id = "evt-ps"
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="HOSTA command report",
        template="standard_investigation",
        sections_enabled={**report_service.DEFAULT_SECTIONS_ENABLED, "appendix": False},
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters={
            **report_service.DEFAULT_FILTERS,
            "host": "HOSTA",
            "evidence_id": "ev-1",
            "include_command_history": True,
            "command_only_suspicious": True,
            "include_execution_stories": True,
            "max_commands": 5,
            "max_execution_stories": 2,
        },
    )
    db = _FakeDb(case=case, reports=[report], markings=[marking], evidences=[evidence])
    command_item = {
        "id": "cmd-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "host": "HOSTA",
        "timestamp": "2024-03-22T11:26:39Z",
        "command": r"powershell.exe -ep bypass -nop -w hidden -NoExit .\f\script.ps1",
        "shell": "powershell",
        "shell_family": "powershell",
        "launcher": "powershell.exe",
        "classification_confidence": "high",
        "source_type": "sysmon_1",
        "source_file": "Sysmon.evtx",
        "user": "usera",
        "process": {"name": "powershell.exe", "pid": 6996, "guid": "guid-ps", "command_line": r"powershell.exe -ep bypass -nop -w hidden -NoExit .\f\script.ps1"},
        "parent_process": {"name": "cmd.exe", "pid": 13492},
        "risk_score": 80,
        "risk_reasons": ["PowerShell execution policy bypass", "hidden window execution"],
        "supporting_events": [{"event_id": "evt-ps", "source_type": "sysmon_1", "windows_event_id": 1, "timestamp": "2024-03-22T11:26:39Z"}],
        "linked_search_url": "/cases/case-1/search?event_id=evt-ps&tab=results&evidence_id=ev-1",
    }
    monkeypatch.setattr(
        report_service,
        "_build_case_context",
        lambda db, case_id: {"case": {"id": case_id, "name": "Validation sample"}, "hosts": [{"host": "HOSTA", "events_count": 71033, "findings_count": 0, "high_risk_count": 0}], "evidences": [{"id": "ev-1", "name": "HOSTA.7z", "status": "completed", "storage_mode": "uploaded", "is_external": False, "events_indexed": 71033, "parser_errors": 0, "detected_host": "HOSTA"}], "summary": {"events_indexed": 71033, "findings_total": 0, "findings_high": 0, "parser_errors": 0, "warnings": []}},
    )
    monkeypatch.setattr(
        report_service,
        "get_command_history",
        lambda case_id, params: {
            "total": 1,
            "items": [command_item],
            "facets": {"shell": {"powershell": 1}, "family": {"powershell": 1}, "launcher": {"powershell.exe": 1}, "source_type": {"sysmon_1": 1}},
            "summary": {"commands_total": 1, "suspicious_total": 1},
        },
    )
    monkeypatch.setattr(
        report_service,
        "build_execution_story",
        lambda *args, **kwargs: {
            "target": {"name": "powershell.exe", "pid": 6996},
            "story": {
                "parent_sentence": "Parent process could not be linked from available events.",
                "children_sentence": "It launched powershell.exe PID 5528.",
                "activity_sentence": "It produced 22 file events.",
                "risk_sentence": "Suspicious because PowerShell execution policy bypass.",
            },
            "activity_groups": {"items": [{"group": "file", "count": 22}], "omitted_counts": {}},
            "source_events": ["evt-ps"],
        },
    )

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    command_section = next(section for section in preview["sections"] if section["id"] == "command_history")

    assert preview["counts"]["command_history_matched"] == 1
    assert preview["counts"]["suspicious_commands_matched"] == 1
    assert preview["counts"]["marked_commands_matched"] == 1
    assert preview["counts"]["execution_stories_included"] == 1
    assert preview["counts"]["commands_by_family"]["powershell"] == 1
    assert preview["counts"]["commands_by_launcher"]["powershell.exe"] == 1
    assert preview["filters_applied"]["include_command_history"] is True
    assert "powershell.exe -ep bypass" in command_section["markdown"]
    assert "Family: `powershell`" in command_section["markdown"]
    assert "Launcher: `powershell.exe`" in command_section["markdown"]
    assert "PowerShell execution policy bypass" in command_section["markdown"]
    assert "Execution Story: powershell.exe PID 6996" in command_section["markdown"]
    assert "Analyst marked this event." in command_section["markdown"]


def test_markdown_export_redacts_secrets_and_deduplicates_iocs(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open", timezone="UTC")
    finding = _finding(
        "finding-1",
        title="Suspicious PowerShell",
        severity=FindingSeverity.high,
        status=FindingStatus.confirmed,
        files=["C:\\Users\\dfir\\Downloads\\payload.exe", "C:\\Users\\dfir\\Downloads\\payload.exe"],
        domains=["duckdns.org", "duckdns.org"],
        ips=["185.10.10.10", "185.10.10.10"],
    )
    bookmark = _bookmark("bookmark-1", event_id="evt-1")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Kairon DFIR Investigation Report - Movistar",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=["finding-1"],
        selected_key_event_ids=["bookmark-1"],
        selected_process_chain_ids=["finding-1"],
    )
    db = _FakeDb(case=case, findings=[finding], bookmarks=[bookmark], reports=[report])
    monkeypatch.setattr(report_service, "_build_case_context", lambda db, case_id: {"case": {"id": case_id, "name": "Movistar"}, "hosts": [], "evidences": [], "summary": {"events_indexed": 15, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []}})
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *args, **kwargs: _event_payload())

    content, filename, media_type = report_service.export_case_report(db, "case-1", "report-1", format="markdown")

    assert filename.endswith(".md")
    assert media_type.startswith("text/markdown")
    assert "Executive Summary" in content
    assert content.count("duckdns.org") >= 1
    assert "REDACTED" in content
    assert "raw.githubusercontent.com" in content


def test_report_hosts_section_excludes_rejected_host_values(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open", timezone="UTC")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Kairon DFIR Investigation Report - Movistar",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=[],
        selected_key_event_ids=[],
        selected_process_chain_ids=[],
    )
    db = _FakeDb(case=case, reports=[report])
    monkeypatch.setattr(
        report_service,
        "_build_case_context",
        lambda db, case_id: {
            "case": {"id": case_id, "name": "Movistar"},
            "hosts": [{"host": "movistar-pc", "events_count": 15, "findings_count": 1, "high_risk_count": 1, "is_primary": True}],
            "host_candidates": [{"value": "desktop-b52vgbl", "confidence": "high", "source": "evtx_computer"}],
            "rejected_host_candidates": [{"value": "applockerfltr", "reason": "driver_or_filter_name"}],
            "evidences": [{"id": "ev-1", "name": "Collection.zip", "status": "completed", "storage_mode": "uploaded", "is_external": False, "events_indexed": 15, "parser_errors": 0, "detected_host": "movistar-pc"}],
            "summary": {"events_indexed": 15, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []},
        },
    )

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    hosts_section = next(section for section in preview["sections"] if section["id"] == "hosts")

    assert "movistar-pc" in hosts_section["markdown"]
    assert "desktop-b52vgbl" in hosts_section["markdown"]
    assert "applockerfltr" not in hosts_section["markdown"]


def test_host_and_evidence_filters_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open", timezone="UTC")
    findings = [
        _finding("finding-1", title="Desktop finding", severity=FindingSeverity.high, status=FindingStatus.confirmed, evidence_id="ev-1", hosts=["desktop-01"]),
        _finding("finding-2", title="Laptop finding", severity=FindingSeverity.high, status=FindingStatus.confirmed, evidence_id="ev-2", hosts=["laptop-01"]),
    ]
    bookmarks = [_bookmark("bookmark-1", event_id="evt-1", host="desktop-01", evidence_id="ev-1"), _bookmark("bookmark-2", event_id="evt-2", host="laptop-01", evidence_id="ev-2")]
    db = _FakeDb(case=case, findings=findings, bookmarks=bookmarks)
    monkeypatch.setattr(
        report_service,
        "fetch_event_by_id",
        lambda case_id, event_id, **kwargs: _event_payload(host="desktop-01", evidence_id="ev-1") if event_id == "evt-1" else _event_payload(host="laptop-01", evidence_id="ev-2"),
    )

    report = report_service.create_case_report_draft(db, "case-1", {"auto_select": True, "filters": {"host": "desktop-01", "evidence_id": "ev-1", "include_statuses": ["confirmed"], "min_severity": "medium"}})

    assert report["selected_finding_ids"] == ["finding-1"]
    assert report["selected_key_event_ids"] == ["bookmark-1"]


def test_pdf_export_returns_clear_not_available(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar / PDF", status="open", timezone="UTC")
    finding = _finding("finding-1", title="Office spawned PowerShell", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    bookmark = _bookmark("bookmark-1", event_id="evt-1")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Kairon DFIR Investigation Report: Movistar / PDF",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes={
            "executive_summary": "password=SuperSecret access_token=abcdefghijklmnopqrstuvwxyz123456",
            "recommendations": "",
            "limitations": "",
        },
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=["finding-1"],
        selected_key_event_ids=["bookmark-1"],
        selected_process_chain_ids=["finding-1"],
    )
    db = _FakeDb(case=case, findings=[finding], bookmarks=[bookmark], reports=[report])
    monkeypatch.setattr(
        report_service,
        "_build_case_context",
        lambda db, case_id: {
            "case": {"id": case_id, "name": "Movistar"},
            "hosts": [{"host": "movistar-pc", "events_count": 97_712, "findings_count": 1, "high_risk_count": 1}],
            "evidences": [{"id": "ev-1", "name": "Collection.zip", "status": "completed", "storage_mode": "uploaded", "is_external": False, "events_indexed": 97_712, "parser_errors": 0, "detected_host": "movistar-pc"}],
            "summary": {"events_indexed": 97_712, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []},
        },
    )
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *args, **kwargs: _event_payload(host="movistar-pc"))

    content, filename, media_type = report_service.export_case_report(db, "case-1", "report-1", format="pdf")
    text = content.decode("latin-1", errors="ignore")

    assert isinstance(content, bytes)
    assert content.startswith(b"%PDF")
    assert len(content) > 3000
    assert filename.endswith(".pdf")
    assert filename == "kairon-dfir-investigation-report-movistar-pdf.pdf"
    assert media_type == "application/pdf"
    assert "Executive Summary" in text
    assert "Scope" in text
    assert "Evidence Processed" in text
    assert "Findings" in text
    assert "Investigation Timeline" in text
    assert "IOCs" in text
    assert "SuperSecret" not in text
    assert "abcdefghijklmnopqrstuvwxyz123456" not in text
    assert "REDACTED" in text


def test_pdf_export_handles_empty_report(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Empty", status="open", timezone="UTC")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Empty report",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=[],
        selected_key_event_ids=[],
        selected_process_chain_ids=[],
    )
    db = _FakeDb(case=case, findings=[], bookmarks=[], reports=[report])
    monkeypatch.setattr(report_service, "_build_case_context", lambda *args, **kwargs: {"case": {"id": "case-1", "name": "Empty"}, "hosts": [], "evidences": [], "summary": {"events_indexed": 0, "findings_total": 0, "findings_high": 0, "parser_errors": 0, "warnings": []}})

    content, filename, media_type = report_service.export_case_report(db, "case-1", "report-1", format="pdf")
    text = content.decode("latin-1", errors="ignore")

    assert content.startswith(b"%PDF")
    assert filename == "empty-report.pdf"
    assert media_type == "application/pdf"
    assert "No findings selected for this report." in text


def test_pdf_export_omits_disabled_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Minimal", status="open", timezone="UTC")
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Minimal report",
        template="standard_investigation",
        sections_enabled={**report_service.DEFAULT_SECTIONS_ENABLED, "appendix": False, "iocs": False},
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=[],
        selected_key_event_ids=[],
        selected_process_chain_ids=[],
    )
    db = _FakeDb(case=case, reports=[report])
    monkeypatch.setattr(report_service, "_build_case_context", lambda *args, **kwargs: {"case": {"id": "case-1", "name": "Minimal"}, "hosts": [], "evidences": [], "summary": {"events_indexed": 0, "findings_total": 0, "findings_high": 0, "parser_errors": 0, "warnings": []}})

    content, _, _ = report_service.export_case_report(db, "case-1", "report-1", format="pdf")
    text = content.decode("latin-1", errors="ignore")

    assert "Appendix" not in text
    assert "IOCs" not in text


def test_pdf_export_long_path_does_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Long path", status="open", timezone="UTC")
    long_path = "C:\\" + "\\nested".join(["folder"] * 45) + "\\payload.exe"
    finding = _finding("finding-1", title="Long path execution", severity=FindingSeverity.high, status=FindingStatus.confirmed, files=[long_path])
    report = CaseReport(
        id="report-1",
        case_id="case-1",
        title="Long path report",
        template="standard_investigation",
        sections_enabled=report_service.DEFAULT_SECTIONS_ENABLED,
        analyst_notes=report_service.DEFAULT_ANALYST_NOTES,
        filters=report_service.DEFAULT_FILTERS,
        selected_finding_ids=["finding-1"],
        selected_key_event_ids=[],
        selected_process_chain_ids=["finding-1"],
    )
    db = _FakeDb(case=case, findings=[finding], reports=[report])
    monkeypatch.setattr(report_service, "_build_case_context", lambda *args, **kwargs: {"case": {"id": "case-1", "name": "Long path"}, "hosts": [], "evidences": [], "summary": {"events_indexed": 1, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": []}})

    content, _, _ = report_service.export_case_report(db, "case-1", "report-1", format="pdf")

    assert content.startswith(b"%PDF")


def test_pdf_export_renderer_unavailable_returns_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Movistar", status="open")
    report = CaseReport(id="report-1", case_id="case-1", title="Report", template="standard_investigation")
    db = _FakeDb(case=case, reports=[report])
    monkeypatch.setattr(report_service, "_render_pdf_document", lambda *args, **kwargs: (_ for _ in ()).throw(report_service.PdfRendererUnavailableError("renderer missing")))
    monkeypatch.setattr(report_service, "_build_case_context", lambda *args, **kwargs: {"case": {"id": "case-1", "name": "Movistar"}, "hosts": [], "evidences": [], "summary": {"events_indexed": 0, "findings_total": 0, "findings_high": 0, "parser_errors": 0, "warnings": []}})

    with pytest.raises(HTTPException) as exc:
        report_service.export_case_report(db, "case-1", "report-1", format="pdf")

    assert exc.value.status_code == 503
    assert "renderer missing" in str(exc.value.detail)
