"""Drafting a report's narrative with AI: only curated material goes out, the
reply is validated against it, nothing is saved, and accepted drafts say so in
the report."""

from __future__ import annotations

import json

import pytest

from app.models.case import Case
from app.models.case_report import CaseReportStatus
from app.services import report_service
from app.services.ai import config as ai_config
from app.services.ai import report_draft
from app.services.ai.providers import StreamEvent
from tests.test_ai_assistant import _client, _configured_db
from tests.test_report_presentation import _quiet_sources, _report
from tests.test_reports import _FakeDb

MATERIAL = {
    "case": {"name": "Sample"},
    "language": "en",
    "findings": [{"ref": "F1", "title": "Encoded PowerShell download", "hosts": ["desktop-01"], "ips": ["203.0.113.7"]}],
    "timeline": [{"time_utc": "2026-05-15T12:07:21Z", "host": "desktop-01", "phase": "execution", "event": "powershell.exe -enc"}],
    "coverage_notes": ["Security log cleared at 12:45:25 on desktop-01"],
}


def test_reply_is_parsed_from_fenced_or_loose_json() -> None:
    reply = 'Here it is:\n```json\n{"executive_summary": "A", "recommendations": ["Isolate host", "- Reset passwords"]}\n```'
    draft = report_draft.parse_draft(reply)
    assert draft["executive_summary"] == "A"
    assert draft["recommendations"] == "- Isolate host\n- Reset passwords"
    assert draft["attack_narrative"] == "" and draft["limitations"] == ""
    with pytest.raises(report_draft.ProviderError):
        report_draft.parse_draft("I cannot help with that.")


def test_validation_flags_invented_citations_and_facts() -> None:
    draft = {
        "executive_summary": "PowerShell downloaded a payload from 203.0.113.7 at 12:07 [F1][12:07:21].",
        "attack_narrative": "The attacker then moved to 198.51.100.9 at 13:30 [F4]. Persistence was set up with a scheduled task on the host.",
        "recommendations": "- Reset the 12 affected accounts",
        "limitations": "",
    }
    validation = report_draft.validate_draft(draft, MATERIAL)
    found = {(issue["field"], issue["kind"], issue["value"]) for issue in validation["issues"]}
    assert ("attack_narrative", "unknown_citation", "F4") in found
    assert ("attack_narrative", "unsupported_fact", "198.51.100.9") in found
    assert ("attack_narrative", "unsupported_fact", "13:30") in found
    assert ("recommendations", "unsupported_fact", "12") in found
    assert any(kind == "uncited_sentence" and "scheduled task" in value for _f, kind, value in found)
    # Grounded facts and valid citations raise nothing.
    assert not any(field == "executive_summary" for field, _k, _v in found)
    assert validation["ok"] is False
    assert report_draft.validate_draft({"executive_summary": "Payload fetched from 203.0.113.7 [F1].", "limitations": "- Log cleared at 12:45:25"}, MATERIAL)["ok"] is True


class _DraftingProvider:
    seen: dict = {}

    def __init__(self, credentials):
        self.credentials = credentials

    def stream_chat(self, *, system, messages, tools=None):
        _DraftingProvider.seen = {"system": system, "messages": messages, "tools": tools}
        yield StreamEvent(type="text", text='{"executive_summary": "Payload fetched from ')
        yield StreamEvent(type="text", text='203.0.113.7 [F1].", "attack_narrative": "", "recommendations": "", "limitations": ""}')


def test_endpoint_drafts_from_curated_material_only(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _configured_db(monkeypatch)
    monkeypatch.setattr(report_draft, "build_provider", _DraftingProvider)
    requested = {}

    def fake_preview(_db, case_id, report_id, *, collect_ai_context=False):
        requested.update(case_id=case_id, report_id=report_id, collect_ai_context=collect_ai_context)
        return {"sections": [{"id": "raw"}], "ai_context": MATERIAL}

    monkeypatch.setattr(report_service, "build_case_report_preview", fake_preview)
    response = _client(db).post("/api/cases/case-1/reports/report-1/ai-draft")
    assert response.status_code == 200, response.text
    body = response.json()
    assert requested == {"case_id": "case-1", "report_id": "report-1", "collect_ai_context": True}
    assert body["draft"]["executive_summary"] == "Payload fetched from 203.0.113.7 [F1]."
    assert body["validation"]["ok"] is True
    assert body["provenance"]["model"] == "llama-local" and body["provenance"]["hosting"] == "local"
    assert body["provenance"]["prompt_version"] == report_draft.PROMPT_VERSION
    sent = _DraftingProvider.seen["messages"][0]["content"]
    assert json.loads(sent.split("\n", 1)[1]) == MATERIAL
    assert _DraftingProvider.seen["tools"] is None
    assert "English" in _DraftingProvider.seen["system"]


def test_provider_gateway_errors_are_readable() -> None:
    page = report_draft.ProviderError("Provider returned HTTP 403. <HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>Denied &#58; " + "x" * 500 + "</BODY>")
    text = report_draft.provider_error_text(page)
    assert text.startswith("Provider returned HTTP 403. Access Denied Denied :") and "<" not in text
    assert len(text) <= 303


class _ThinkingProvider:
    seen_max_tokens = 0

    def __init__(self, credentials):
        _ThinkingProvider.seen_max_tokens = credentials.max_tokens

    def stream_chat(self, *, system, messages, tools=None):
        yield StreamEvent(type="notice", text=report_draft.TRUNCATED_NOTICE)


def test_drafting_raises_the_token_limit_and_explains_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _configured_db(monkeypatch)
    monkeypatch.setattr(report_draft, "build_provider", _ThinkingProvider)
    monkeypatch.setattr(report_service, "build_case_report_preview", lambda *_a, **_k: {"ai_context": MATERIAL})
    response = _client(db).post("/api/cases/case-1/reports/report-1/ai-draft")
    assert response.status_code == 502
    assert _ThinkingProvider.seen_max_tokens == report_draft.DRAFT_MIN_TOKENS
    detail = response.json()["detail"]
    assert "token limit" in detail and "wrote nothing" in detail and "Max tokens" in detail


def test_endpoint_refuses_when_ai_is_off_or_there_is_nothing_to_draft(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _configured_db(monkeypatch)
    monkeypatch.setattr(report_service, "build_case_report_preview", lambda *_a, **_k: {"ai_context": {"findings": [], "timeline": []}})
    assert _client(db).post("/api/cases/case-1/reports/report-1/ai-draft").status_code == 409
    ai_config.update_general(db, enabled=False)
    response = _client(db).post("/api/cases/case-1/reports/report-1/ai-draft")
    assert response.status_code == 409 and "not enabled" in response.json()["detail"]
    assert _client(db).post("/api/cases/other/reports/report-1/ai-draft").status_code == 404


def test_accepted_draft_shows_narrative_and_ai_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_sources(monkeypatch)
    notes = {**report_service.DEFAULT_ANALYST_NOTES, "attack_narrative": "Initial access by phishing [F1]."}
    report = _report(analyst_notes=notes, author="J. Analyst", status=CaseReportStatus.draft, metadata_json={})
    db = _FakeDb(case=Case(id="case-1", name="Sample", status="open", timezone="UTC"), reports=[report])
    report_service.update_case_report(db, "case-1", "report-1", {"ai_provenance": {
        "provider": "Ollama", "model": "llama-local", "hosting": "local", "generated_at": "2026-05-15T12:00:00+00:00", "prompt_version": "v1", "extra": "dropped",
    }})
    assert set(report.metadata_json["ai_provenance"]) == {"provider", "model", "hosting", "generated_at", "prompt_version"}

    content, _filename, _media = report_service.export_case_report(db, "case-1", "report-1", format="markdown")
    assert "Attack Narrative" in content and "Initial access by phishing [F1]." in content
    assert "### Use of AI" in content and "Ollama, model llama-local" in content and "J. Analyst" in content

    report_service.update_case_report(db, "case-1", "report-1", {"ai_provenance": None})
    assert "ai_provenance" not in report.metadata_json
    content, _filename, _media = report_service.export_case_report(db, "case-1", "report-1", format="markdown")
    assert "Use of AI" not in content
