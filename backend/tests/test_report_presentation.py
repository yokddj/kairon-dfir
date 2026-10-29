from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.case import Case
from app.models.case_report import CaseReport
from app.models.detection_result import DetectionResult
from app.models.finding import FindingSeverity, FindingStatus
from app.services import report_service
from tests.test_reports import _FakeDb, _finding


def _context(name: str = "Sample") -> dict:
    return {
        "case": {"id": "case-1", "name": name},
        "hosts": [{"host": "desktop-01", "events_count": 15, "findings_count": 1, "high_risk_count": 1}],
        "evidences": [{"id": "ev-1", "name": "Collection.zip", "status": "completed_with_warnings", "storage_mode": "uploaded", "is_external": False, "events_indexed": 15, "parser_errors": 0, "detected_host": "desktop-01"}],
        "summary": {"events_indexed": 15, "findings_total": 1, "findings_high": 1, "parser_errors": 0, "warnings": ["multi_host_case"]},
    }


def _report(**overrides) -> CaseReport:
    values = {
        "id": "report-1",
        "case_id": "case-1",
        "title": "Sample report",
        "template": "standard_investigation",
        "sections_enabled": report_service.DEFAULT_SECTIONS_ENABLED,
        "analyst_notes": report_service.DEFAULT_ANALYST_NOTES,
        "filters": report_service.DEFAULT_FILTERS,
        "selected_finding_ids": [],
        "selected_key_event_ids": [],
        "selected_process_chain_ids": [],
    }
    values.update(overrides)
    return CaseReport(**values)


def _quiet_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report_service, "_build_case_context", lambda *_a, **_k: _context())
    monkeypatch.setattr(report_service, "get_command_history", lambda *_a, **_k: {"total": 0, "items": []})
    monkeypatch.setattr(report_service, "fetch_event_by_id", lambda *_a, **_k: {})


def test_export_leaves_out_empty_optional_sections_and_lists_them_once(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[_report()])

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    content, _filename, _media = report_service.export_case_report(db, "case-1", "report-1", format="markdown")

    defender = next(section for section in preview["sections"] if section["id"] == "defender")
    assert defender["empty"] is True and defender["warnings"] == []
    assert "## " in content and "Microsoft Defender\n" not in content.split("### Sections without matching data")[0]
    assert "No Defender events matched" not in content
    assert "left out of the exported report: " in content and "Microsoft Defender" in content
    # Core sections stay even when empty: the reader must see "no findings".
    assert "No findings selected for this report." in content
    assert "## 1. Executive Summary" in content
    # Internal context codes are not reader-facing coverage notes.
    assert "multi_host_case" not in content


def test_executive_summary_counts_findings_still_awaiting_review(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    confirmed = _finding("finding-1", title="Confirmed execution", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    pending = _finding("finding-2", title="Unreviewed lead", severity=FindingSeverity.high, status=FindingStatus.new)
    dismissed = _finding("finding-3", title="Dismissed lead", severity=FindingSeverity.high, status=FindingStatus.false_positive)
    db = _FakeDb(
        case=Case(id="case-1", name="Sample", status="open", timezone="UTC"),
        findings=[confirmed, pending, dismissed],
        reports=[_report(selected_finding_ids=["finding-1"])],
    )

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")
    summary = preview["sections"][0]["markdown"]

    assert preview["stats"]["findings_pending_review"] == 1
    assert "**1 finding** is reported (1 high)." in summary
    assert "1 further finding is still awaiting analyst review" in summary
    assert "Confirmed execution" in summary and "Unreviewed lead" not in summary


def test_detection_summary_never_presents_rule_run_time_as_event_time() -> None:
    detection = DetectionResult(
        id="det-1",
        case_id="case-1",
        engine="builtin",
        rule_name="Built-in: High-risk event",
        severity="high",
        status="new",
        host_name="desktop-01",
        matched_at=None,
        created_at=datetime(2026, 10, 20, 9, 54, tzinfo=UTC),
    )

    markdown = report_service._render_detections([detection], 1)

    assert "2026-10-20" not in markdown
    assert "First event" not in markdown  # column dropped: no event time is known
    assert "| Built-in: High-risk event | high | 1 | desktop-01 |" in markdown
    assert "have not been reviewed by an analyst" in markdown


def test_command_seen_by_several_sources_is_reported_once() -> None:
    base = {
        "case_id": "case-1",
        "host": "WS01",
        "user": "CORP\\admin",
        "command": "/c C:\\Users\\public\\psexec.exe \\\\WS02 -accepteula",
        "risk_score": 60,
        "risk_reasons": ["PsExec activity"],
        "shell_family": "remote_exec",
        "launcher": "cmd.exe",
    }
    from_memory = {**base, "id": "cmd-mem", "timestamp": "2024-03-22T12:17:30+00:00", "source_type": "memory", "process": {"name": "cmd.exe", "pid": 13492}}
    from_sysmon = {
        **base,
        "id": "cmd-sysmon",
        "timestamp": "2024-03-22T12:17:30.075607+00:00",
        "process": {"name": "cmd.exe", "pid": 13492},
        "parent_process": {"name": "powershell.exe", "pid": 12720},
        "supporting_events": [{"event_id": "evt-1", "source_type": "sysmon_1"}],
    }

    markdown = report_service._render_command_history_section([from_memory, from_sysmon], [])

    assert "1 distinct command (2 records" in markdown
    assert markdown.count("##### ") == 1
    assert "Process chain: powershell.exe (PID 12720) → cmd.exe (PID 13492)" in markdown
    assert "Seen in: Memory, Sysmon 1" in markdown
    # Code spans are literal: underscores must not be backslash-escaped.
    assert "`remote_exec`" in markdown


def test_incident_timeline_section_drops_items_of_dismissed_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    kept = _finding("finding-1", title="Kept", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    archived = _finding("finding-2", title="Archived", severity=FindingSeverity.high, status=FindingStatus.archived)
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), findings=[kept, archived])
    monkeypatch.setattr(
        report_service,
        "build_incident_timeline_draft",
        lambda *_a, **_k: {"items": [{"title": "Kept", "finding_id": "finding-1"}, {"title": "Archived", "finding_id": "finding-2"}, {"title": "Marked event"}], "warnings": []},
    )

    context = report_service._build_incident_timeline_report_context(db, "case-1", dict(report_service.DEFAULT_FILTERS))

    assert [item["title"] for item in context["items"]] == ["Kept", "Marked event"]


def test_presentation_helpers() -> None:
    assert report_service._fmt_ts("2024-03-22T11:26:39.331771+00:00") == "2024-03-22 11:26:39"
    assert report_service._fmt_ts(datetime(2024, 3, 22, 13, 0, tzinfo=UTC)) == "2024-03-22 13:00:00"
    assert report_service._fmt_ts("not a time") == "not a time"
    assert report_service._human_bytes(4_255_346_688) == "4.0 GB"
    assert report_service._human_bytes(512) == "512 bytes"
    assert report_service._drop_empty_columns([["A", "B", "C"], ["x", "-", "0"], ["y", "", "0"]], zero_is_empty={"C"}) == [["A"], ["x"], ["y"]]
    collapsed = report_service._collapse_duplicate_table_rows("| H | T |\n| --- | --- |\n| ws01 | a |\n| ws01 | a |\n| ws01 | b |")
    assert collapsed.splitlines()[2:] == ["| ws01 (×2) | a |", "| ws01 | b |"]
    humanized = report_service._humanize_table_columns("| Type | Path |\n| --- | --- |\n| scheduled_task | C:\\my_dir |", {"Type", "Path"})
    assert humanized.splitlines()[2] == "| Scheduled task | C:\\my_dir |"
    assert report_service._pdf_inline("a\\_b `x_y` **bold\\_text**") == "a_b <font name='Courier' size='7.8'>x_y</font> <b>bold_text</b>"


def test_pdf_has_contents_page_and_page_totals(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[_report()])

    content, _filename, _media = report_service.export_case_report(db, "case-1", "report-1", format="pdf")
    text = content.decode("latin-1", errors="ignore")

    assert "Contents" in text
    assert "DIGITAL FORENSIC INVESTIGATION REPORT" in text
    assert "of " in text and "Page 2 of" in text
    assert "Microsoft Defender" in text  # named once, in the appendix list
    assert "No Defender events matched" not in text


def test_detection_without_stored_event_time_uses_the_matched_event_time(monkeypatch: pytest.MonkeyPatch) -> None:
    detection = DetectionResult(
        id="det-1", case_id="case-1", engine="builtin", rule_name="Built-in: RDP activity", severity="medium",
        status="new", host_name="WS01", opensearch_id="evt-1", matched_at=None,
        created_at=datetime(2026, 10, 20, 9, 54, tzinfo=UTC),
    )
    queries: list[dict] = []

    def fake_search(_index, body):
        queries.append(body)
        return {"hits": {"hits": [{"_id": "evt-1", "_source": {"@timestamp": "2024-03-22T11:37:40.44+00:00"}}]}}

    monkeypatch.setattr(report_service, "search_documents", fake_search)
    times = report_service._resolve_detection_event_times("case-1", [detection])
    markdown = report_service._render_detections([detection], 1, event_times=times)

    assert queries[0]["query"] == {"ids": {"values": ["evt-1"]}}
    assert "| 2024-03-22 11:37:40 | 2024-03-22 11:37:40 |" in markdown
    assert "2026-10-20" not in markdown

    def failing_search(_index, _body):
        raise ConnectionError("down")

    monkeypatch.setattr(report_service, "search_documents", failing_search)
    assert report_service._resolve_detection_event_times("case-1", [detection]) == {}


def test_analyst_narrative_is_not_clipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    long_summary = ("The attacker moved from WS01 to the domain controller. " * 40).strip() + " END-OF-SUMMARY"
    notes = {**report_service.DEFAULT_ANALYST_NOTES, "executive_summary": long_summary}
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[_report(analyst_notes=notes)])

    preview = report_service.build_case_report_preview(db, "case-1", "report-1")

    assert len(long_summary) > 1200
    assert "END-OF-SUMMARY" in preview["sections"][0]["markdown"]


def test_hosts_table_counts_the_reported_findings() -> None:
    finding = _finding("finding-1", title="Lateral movement", severity=FindingSeverity.high, status=FindingStatus.confirmed, hosts=["WS01", "ws02.corp.local"])
    context = {"hosts": [{"host": "WS01", "events_count": 10}, {"host": "WS02", "events_count": 5}, {"host": "DC01", "events_count": 1}]}

    markdown = report_service._render_hosts(context, [finding])

    assert "| WS01 | 10 | 1 | 1 |" in markdown
    assert "| DC01 | 1 | 0 | 0 |" in markdown


def test_iocs_leave_out_system_binaries_hosts_and_command_lines() -> None:
    rows: list[tuple] = []

    def remember(ioc_type, value, **_kwargs):
        rows.append((ioc_type, value))

    report_service._extract_iocs_from_event(
        {
            "process": {"name": "svchost.exe", "executable": r"C:\Windows\System32\svchost.exe", "command_line": "svchost.exe -k netsvcs"},
            "file": {"path": r"C:\Users\Public\psexec.exe", "sha256": "b" * 64},
        },
        remember,
        "bookmark:x",
        None,
    )
    report_service._extract_iocs_from_event({"process": {"executable": r"C:\Users\bob\Downloads\tool.exe"}}, remember, "bookmark:y", None)

    assert ("file", r"C:\Users\Public\psexec.exe") in rows and ("hash", "b" * 64) in rows
    assert ("file", r"C:\Users\bob\Downloads\tool.exe") in rows
    assert not any(kind == "process" or "svchost" in str(value) for kind, value in rows)


def test_powershell_script_arguments_are_not_a_download_target() -> None:
    from app.ingest.powershell.helpers import extract_primary_download_target

    script = r".\baklavasom.ps1 -e \\SRV01\files -s 203.0.113.9 -p 8800 -x"
    assert extract_primary_download_target(script, None) is None
    assert extract_primary_download_target(r"iwr -uri https://x.test/a.exe -OutFile C:\Users\Public\a.exe", None) == r"C:\Users\Public\a.exe"


def test_download_target_without_url_is_not_an_ioc() -> None:
    rows: list[tuple] = []
    report_service._extract_iocs_from_event({"download": {"url": None, "target_path": r"\\SRV01\files -s 1.2.3.4"}}, lambda t, v, **_k: rows.append((t, v)), "x", None)
    assert rows == []


def test_unc_paths_and_multiline_commands_render_intact() -> None:
    assert report_service._pdf_inline(r"encrypted \\SRV01\files") == r"encrypted \\SRV01\files"
    assert report_service._code("line one\nline two") == "`line one line two`"


def test_defender_section_keeps_detections_and_protection_changes_only() -> None:
    def row(event_id, threat=None):
        return {"raw": {"windows": {"event_id": event_id}, "threat": {"name": threat} if threat else {}}}

    assert report_service._is_reportable_defender_event(row(1116))
    assert report_service._is_reportable_defender_event(row(5001))  # real-time protection disabled
    assert report_service._is_reportable_defender_event(row(9999, threat="Trojan:Win32/Test"))
    assert not report_service._is_reportable_defender_event(row(1151))  # health report
    assert not report_service._is_reportable_defender_event(row(1013))  # history clean-up


def test_unclassified_archive_is_labelled_as_archive() -> None:
    assert report_service._archive_label("DC02.zip") == "Archive (zip)"
    assert report_service._archive_label("bundle.tar.gz") == "Archive (tar.gz)"
    assert report_service._archive_label("notes.txt") == "-"


def test_mitre_section_files_techniques_by_tactic_in_attack_order() -> None:
    first = _finding("f-1", title="Initial access via ISO", severity=FindingSeverity.critical, status=FindingStatus.confirmed)
    first.mitre = ["T1566", "T1059.001"]
    second = _finding("f-2", title="Ransomware", severity=FindingSeverity.critical, status=FindingStatus.confirmed)
    second.mitre = ["T1486", "T1059.001"]
    untagged = _finding("f-3", title="No tags", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    untagged.mitre, untagged.tags = [], []

    markdown = report_service._render_mitre([first, second, untagged])

    assert "| Initial access | T1566 Phishing | F1 |" in markdown
    assert "| Execution | T1059.001 Command and Scripting Interpreter | F1, F2 |" in markdown
    assert "| Impact | T1486 Data Encrypted for Impact | F2 |" in markdown
    assert markdown.index("Initial access") < markdown.index("Execution") < markdown.index("Impact")
    assert report_service._render_mitre([untagged]) == ""


def test_iocs_take_hashes_of_the_binary_from_finding_events(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = _finding("f-1", title="Lateral movement", severity=FindingSeverity.high, status=FindingStatus.confirmed, files=["x"], domains=["d.test"], ips=["203.0.113.1"])
    finding.related_event_ids = ["evt-1"]
    finding.timeline = []
    event = {
        "@timestamp": "2024-03-22T11:41:07Z",
        "process": {"executable": "C:\\Users\\Public\\psexec.exe"},
        "windows": {"event_data": {"Hashes": "MD5=24A648A48741B1AC809E47B9543C6F12,SHA256=078163D5C16F64CAA5A14784323FD51451B8C831C73396B967B4E35E6879937B,IMPHASH=1193BC223DAD681F22F8248608CBB592"}},
    }
    monkeypatch.setattr(report_service, "_fetch_events_by_ids", lambda case_id, ids: {"evt-1": event} if "evt-1" in ids else {})

    rows = report_service._extract_iocs("case-1", [finding], [])
    hashes = {row["value"]: row["notes"] for row in rows if row["type"] == "hash"}

    assert hashes == {
        "24a648a48741b1ac809e47b9543c6f12": "MD5 of C:\\Users\\Public\\psexec.exe",
        "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b": "SHA256 of C:\\Users\\Public\\psexec.exe",
    }
    assert not any(row["type"] == "host" for row in rows)


def test_timeline_merges_accepted_incident_items_without_duplicates() -> None:
    entries = [
        {"timestamp": "2024-03-22T11:26:39Z", "title": "Key event", "note": "first code", "event_id": "evt-1", "category": "execution", "importance": "critical"},
    ]
    incident = [
        {"status": "accepted", "source": "marked_event", "event_id": "evt-1", "host": "WS01", "phase": "initial_access", "title": "dup"},
        {"status": "accepted", "source": "finding", "finding_id": "f-1", "host": "WS01", "phase": "initial_access", "title": "finding row"},
        {"status": "accepted", "source": "command_history", "event_id": "evt-2", "host": "WS02", "phase": "lateral_movement", "title": "psexec", "timestamp": "2024-03-22T11:41:07Z"},
        {"status": "candidate", "source": "command_history", "event_id": "evt-3", "title": "not accepted"},
    ]

    merged = report_service._merge_incident_items(entries, incident)

    assert [row["title"] for row in merged] == ["Key event", "psexec"]
    assert merged[0]["host"] == "WS01" and merged[0]["phase"] == "initial_access"
    markdown = report_service._render_timeline(merged)
    assert "| 2024-03-22 11:26:39 | WS01 | Initial access | Key event | first code | critical |" in markdown


def test_spanish_report_translates_kairon_text_but_not_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    finding = _finding("finding-1", title="Suspicious PowerShell", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    report = _report(selected_finding_ids=["finding-1"], metadata_json={"language": "es"})
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), findings=[finding], reports=[report])

    content, _filename, _media = report_service.export_case_report(db, "case-1", "report-1", format="markdown")

    assert "## 1. Resumen ejecutivo" in content
    assert "## 5. Hallazgos" in content
    assert "Se informa de **1 hallazgo** (1 alta)." in content
    assert "| Severidad | Riesgo | Confianza | Estado | Observado (UTC) |" in content
    # Evidence values and finding titles stay as written.
    assert "Suspicious PowerShell" in content and "C:\\Users\\dfir\\Downloads\\payload.exe" in content
    pdf, _f, _m = report_service.export_case_report(db, "case-1", "report-1", format="pdf")
    assert "INFORME DE INVESTIGACI" in pdf.decode("latin-1", errors="ignore")
    # The language does not leak into the next (English) report.
    english, _f, _m = report_service.export_case_report(_FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[_report()]), "case-1", "report-1", format="markdown")
    assert "## 1. Executive Summary" in english


def test_language_is_saved_on_the_report() -> None:
    from app.models.case_report import CaseReportStatus

    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[_report(status=CaseReportStatus.draft)])
    updated = report_service.update_case_report(db, "case-1", "report-1", {"language": "ES"})
    assert updated["language"] == "es"
    assert report_service.update_case_report(db, "case-1", "report-1", {"language": "fr"})["language"] == "en"
