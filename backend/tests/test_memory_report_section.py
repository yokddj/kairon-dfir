"""The case report's Memory Analysis section (app.services.memory.report_section)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.event_marking import EventMarking
from app.models.finding import Finding
from app.models.memory import MemoryScanRun
from app.services import report_service
from app.services.memory import findevil_triage, report_section

SYSTEM_INFO = {
    "os": {"family": "windows", "machine_type": "x64", "windows_build": "26100", "kernel_version": "10.0.26100"},
    "raw": {"fields": {"SystemTime": "2026-06-23 15:04:26+00:00"}},
}


class _Query:
    def __init__(self, items):
        self.items = items

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.items)

    def count(self):
        return len(self.items)


class _Db:
    def __init__(self, runs, findings, markings=()):
        self.runs, self.findings, self.markings = runs, findings, list(markings)

    def query(self, model):
        if model is EventMarking:
            return _Query(self.markings)
        return _Query(self.runs if model is MemoryScanRun else self.findings if model is Finding else [])


def _landing(evidence_id="ev-1", host="ws01", find_evil_run="run-9", metadata=None):
    return {
        "evidence_id": evidence_id,
        "filename": "memoria.raw",
        "detected_host": host,
        "size_bytes": 4294967296,
        "detected_format": "windows_kernel_scan",
        "metadata": metadata or {},
        "families": [
            {"family": "system_info", "title": "System metadata", "state": "analyzed_with_results", "count": 1, "active_run": {"id": "run-1"}},
            {"family": "find_evil", "title": "find_evil", "state": "analyzed_with_results", "count": 7, "active_run": {"id": find_evil_run}},
            {"family": "processes", "title": "Processes", "state": "analyzed_with_results", "count": 152, "active_run": {"id": "run-2"}},
            {"family": "network", "title": "Network connections", "state": "analyzed_empty", "count": 0, "active_run": {"id": "run-3"}},
            {"family": "drivers", "title": "Drivers", "state": "not_analyzed", "count": 0, "active_run": None},
        ],
    }


def _process(pid, name, counts, mark=None, note=None):
    return {
        "pid": pid, "process_name": name, "indicator_count": sum(counts.values()),
        "priority_counts": {"high": 0, "medium": 0, "low": 0, **counts},
        "top_priority": next((p for p in ("high", "medium", "low") if counts.get(p)), None),
        "indicator_types": [{"value": "PE_INJECT", "count": 1}],
        "marking": {"id": "m", "status": mark, "note": note} if mark else None,
    }


@pytest.fixture
def memory_case(monkeypatch):
    monkeypatch.setattr(report_section, "get_evidence_landing", lambda db, case_id: [_landing(), _landing("ev-2", "srv02", None)])
    calls = []

    def processes(db, *, case_id, evidence_id, run_id):
        calls.append(run_id)
        return [
            _process(4012, "rundll32.exe", {"high": 2}, "suspicious", "beacon to 203.0.113.7"),
            _process(2152, "msedge.exe", {"low": 3}, "not_relevant"),
            _process(52, "WmiPrvSE.exe", {"medium": 1}),
            _process(77, "notepad.exe", {"medium": 1}, "important"),
        ]

    monkeypatch.setattr(findevil_triage, "findevil_processes", processes)
    db = _Db([SimpleNamespace(metadata_json={}), SimpleNamespace(metadata_json={"system_info": SYSTEM_INFO})], [SimpleNamespace(id="f-1", status="confirmed"), SimpleNamespace(id="f-2", status="new")])
    return db, calls


def test_context_has_system_analyses_and_find_evil_triage(memory_case):
    db, calls = memory_case
    entries = report_section.build_memory_report_context(db, "case-1")
    assert [entry["evidence_id"] for entry in entries] == ["ev-1", "ev-2"]
    entry = entries[0]
    assert entry["system"] == "Windows 10.0.26100 (build 26100)"
    assert entry["captured_at"] == "2026-06-23 15:04:26+00:00"
    assert [item["family"] for item in entry["analyses"]] == ["system_info", "find_evil", "processes", "network"]
    find_evil = entry["find_evil"]
    assert find_evil["indicator_counts"] == {"high": 2, "medium": 2, "low": 3}
    assert [(p["process"], p["mark"]) for p in find_evil["marked_processes"]] == [("rundll32.exe", "suspicious"), ("notepad.exe", "important")]
    assert (find_evil["settled_count"], find_evil["unreviewed_count"]) == (1, 1)
    assert entry["findings_count"] == 2
    # The second image has no Find Evil run: no triage is read for it.
    assert entries[1]["find_evil"] is None and calls == ["run-9"]


def test_context_filters_by_evidence_and_host(memory_case):
    db, _ = memory_case
    assert [e["evidence_id"] for e in report_section.build_memory_report_context(db, "case-1", evidence_id="ev-2")] == ["ev-2"]
    only_ws01 = report_section.build_memory_report_context(db, "case-1", host_matches=lambda host: host == "ws01")
    assert [e["evidence_id"] for e in only_ws01] == ["ev-1"]


def test_linux_image_system_from_the_kernel_banner(monkeypatch):
    monkeypatch.setattr(report_section, "get_evidence_landing", lambda db, case_id: [_landing(find_evil_run=None, metadata={"linux_kernel": {"kernel_release": "6.5.0-41-generic", "architecture": "x64"}})])
    entries = report_section.build_memory_report_context(_Db([], []), "case-1")
    assert entries[0]["system"] == "Linux 6.5.0-41-generic"


def test_no_section_when_the_landing_fails(monkeypatch):
    def broken(db, case_id):
        raise ConnectionError("opensearch down")

    monkeypatch.setattr(report_section, "get_evidence_landing", broken)
    assert report_section.build_memory_report_context(_Db([], []), "case-1") == []


def test_rendered_section(memory_case):
    db, _ = memory_case
    markdown = report_service._render_memory_section(report_section.build_memory_report_context(db, "case-1"))
    assert "### memoria.raw" in markdown
    assert "| System | Windows 10.0.26100 (build 26100) (x64) |" in markdown
    assert "| Find Evil | completed | 7 |" in markdown
    assert "| Network connections | completed, nothing found | 0 |" in markdown
    assert "System metadata" not in markdown and "Drivers" not in markdown
    assert "7 indicators in 4 processes (2 high, 2 medium, 3 low priority)" in markdown
    assert "| rundll32.exe | 4012 | suspicious | high | 2 | PE_INJECT | beacon to 203.0.113.7 |" in markdown
    assert "msedge.exe" not in markdown


def test_report_skips_memory_when_disabled(monkeypatch):
    monkeypatch.setattr(report_service.settings, "memory_enabled", False)
    assert report_service._build_memory_report_context(None, "case-1", {}) == []


def test_findings_count_includes_findings_holding_a_marked_item_of_the_image() -> None:
    findings = [SimpleNamespace(id="f-direct", status="confirmed"), SimpleNamespace(id="f-attached", status="confirmed"), SimpleNamespace(id="f-dismissed", status="false_positive")]
    markings = [SimpleNamespace(finding_id="f-attached"), SimpleNamespace(finding_id=None)]
    db = _Db([], findings, markings)
    # The fake returns every finding for each query; dismissed ones never count.
    assert report_section._findings_linked_to_image(db, "case-1", "ev-1") == 2
