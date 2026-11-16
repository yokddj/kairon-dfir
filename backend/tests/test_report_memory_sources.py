"""Report sections fed by records recovered from a memory image, and the
parsing they depend on. Synthetic values only."""

from __future__ import annotations

from app.api import routes_cases
from app.ingest.defender.helpers import extract_paths_from_defender_resource
from app.ingest.normalizer import _protected_service_image_score
from app.models.case_report import CaseReport
from app.models.finding import FindingSeverity, FindingStatus
from app.services import motw, report_service
from app.services.memory.memprocfs_timeline import event_data_fields
from app.services.report_i18n import report_language
from tests.test_reports import _finding

RESOURCE = r"file:_C:\Users\usera\Downloads\tool.exe; webfile:_C:\Users\usera\Downloads\tool.exe|http://198.51.100.7:8080/tool.exe|pid:100,ProcessStart:1; Origin ID=4"


def test_resource_list_yields_the_file_path_only() -> None:
    assert extract_paths_from_defender_resource(RESOURCE)[0] == r"C:\Users\usera\Downloads\tool.exe"
    assert extract_paths_from_defender_resource(r"C:\Program Files\Vendor\app.exe")[0] == r"C:\Program Files\Vendor\app.exe"


def test_event_data_fields_split_on_names_with_spaces() -> None:
    fields = event_data_fields("Product Name=Defender; Threat Name=Trojan:Win32/Test; " + RESOURCE.replace("file:_", "Path=file:_", 1) + "; Action Name=Not Applicable")
    assert fields["Threat Name"] == "Trojan:Win32/Test"
    assert fields["Path"].startswith(r"file:_C:\Users\usera\Downloads\tool.exe; webfile:")
    assert fields["Origin ID"] == "4"
    assert fields["Action Name"] == "Not Applicable"


def test_supporting_events_skip_status_history_and_fall_back_to_the_source_row() -> None:
    finding = _finding("f-1", title="Download", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    finding.timeline = [{"kind": "hunting_meta", "payload": {"status_history": []}}]
    finding.source_snapshot_json = {"type": "file_created", "summary": r"\Users\usera\Desktop\note.txt", "timestamp": "2025-01-01T10:00:00Z"}

    events = report_service._finding_events(finding)

    assert events == [{"timestamp": "2025-01-01T10:00:00Z", "event_type": "file_created", "summary": r"\Users\usera\Desktop\note.txt", "event_id": None}]
    finding.source_snapshot_json, finding.source_summary = None, None
    assert report_service._finding_events(finding) == []


def test_defender_records_from_memory_reach_the_report(monkeypatch) -> None:
    source = {
        "@timestamp": "2025-01-01T10:00:00Z",
        "host": {"name": "host-a"},
        "artifact": {"type": "memprocfs_eventlog"},
        "windows": {"event_id": 1116, "record_id": "7", "provider": "Microsoft-Windows-Windows Defender"},
        "detection": {"threat_name": "Trojan:Win32/Test", "severity": "severe", "action": "not applicable", "path": r"C:\Users\usera\Downloads\tool.exe"},
        "user": {"name": "usera"},
    }
    queries = []

    def fake_search(_index, body):
        queries.append(body)
        return {"hits": {"hits": [{"_id": "m-1", "_source": source}]}}

    monkeypatch.setattr(report_service, "search_documents", fake_search)
    monkeypatch.setattr(report_service, "get_events_index", lambda case_id: f"events-{case_id}")
    monkeypatch.setattr(report_service, "search_events_v2", lambda *_a, **_k: (1, [{"raw": {**source, "artifact": {"type": "defender"}}}], [], {}))

    context = report_service._build_defender_report_context(None, "case-1", {"host": ["host-a"]})

    assert len(context["events"]) == 1  # the same record read from disk and memory is reported once
    assert {"terms": {"host.name": ["host-a"]}} in queries[0]["query"]["bool"]["filter"]
    markdown = report_service._render_defender_section(report_service._memory_defender_rows("case-1", {}))
    assert "Trojan:Win32/Test" in markdown and r"C:\Users\usera\Downloads\tool.exe" in markdown


def test_defender_download_origin_is_listed_with_downloads(monkeypatch) -> None:
    def row(event_id: int):
        return {
            "id": f"evt-{event_id}",
            "timestamp": "2025-01-01T10:00:00Z",
            "raw": {"host": {"name": "host-a"}, "windows": {"event_id": event_id, "event_data": {"Path": RESOURCE}}},
        }

    def fake_search(_case_id, params, **_kwargs):
        if "memprocfs_eventlog" in (params.get("artifact_type") or []):
            return 2, [row(1116), row(1117)], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(motw, "search_events_v2", fake_search)

    items = motw.list_motw_items(None, "case-1", {"page_size": 50})["items"]

    assert len(items) == 1
    assert items[0]["file_path"] == r"C:\Users\usera\Downloads\tool.exe"
    assert items[0]["host_url"] == "http://198.51.100.7:8080/tool.exe"
    assert items[0]["source_artifact"] == "defender_webfile"
    assert items[0]["zone_id"] is None


def test_generic_recommendations_follow_the_report_language() -> None:
    finding = _finding("f-1", title="Download", severity=FindingSeverity.high, status=FindingStatus.confirmed)
    report = CaseReport(id="r-1", case_id="case-1", title="R", analyst_notes={})
    with report_language("es"):
        text = report_service._render_recommendations([finding], report)
    assert "Bloquear o vigilar los IOC" in text and "Block or monitor" not in text


def test_services_in_protected_folders_are_not_critical() -> None:
    assert _protected_service_image_score(r"\SystemRoot\System32\drivers\vendor.sys") == 30
    assert _protected_service_image_score(r"system32\DRIVERS\vendor.sys") == 30
    assert _protected_service_image_score(r"%SystemRoot%\system32\svchost.exe -k group") == 30
    assert _protected_service_image_score(r'"C:\Program Files\Vendor\agent.exe"') == 50
    assert _protected_service_image_score(r"C:\Windows\System32\cmd.exe /c C:\Users\Public\x.exe") is None
    assert _protected_service_image_score(r"C:\ProgramData\vendor.sys") is None
    assert _protected_service_image_score(r"C:\Users\usera\AppData\Local\Temp\svc.exe") is None


def test_evidence_counts_include_events_without_an_artifact_row(monkeypatch) -> None:
    class Client:
        def search(self, **_kwargs):
            return {"aggregations": {"evidence": {"buckets": [{"key": "ev-1", "doc_count": 42}]}}}

    monkeypatch.setattr(routes_cases, "get_opensearch_client", lambda: Client())
    monkeypatch.setattr(routes_cases, "index_exists", lambda *_a: True)
    monkeypatch.setattr(routes_cases, "is_index_queryable", lambda *_a: True)

    assert routes_cases._indexed_counts_by_evidence("case-1") == {"ev-1": 42}
