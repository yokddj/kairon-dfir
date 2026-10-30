"""Finding suggestions with AI: open leads go out with references, the reply is
checked against them, links come from the leads and nothing is created."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.ai import finding_suggestions, report_draft
from app.services.ai.providers import StreamEvent
from tests.test_ai_assistant import _client, _configured_db

PROVENANCE = {"provider": "Local", "model": "llama-local"}


def _leads() -> list[dict]:
    leads = [
        finding_suggestions._lead(
            "command", time="2026-01-10T09:15:02Z", host="ws-01", label="Command (risk 90): tool.exe dump",
            details={"command": "tool.exe dump /target:SRV/svc", "user": "alice", "risk": 90},
            event_ids=["ev-1"], evidence_ids=["evd-1"], hosts=["ws-01"], users=["alice"],
        ),
        finding_suggestions._lead(
            "lateral", time="2026-01-10T09:30:00Z", last="2026-01-10T09:40:00Z", host="srv-01",
            label="Remote logon ws-01 (192.0.2.42) -> srv-01 as svc",
            details={"from_ip": "192.0.2.42", "to_host": "srv-01", "account": "svc", "succeeded": 3},
            hosts=["srv-01", "ws-01"], ips=["192.0.2.42"], users=["svc"],
        ),
        finding_suggestions._lead(
            "detection", time="2026-01-10T09:14:00Z", host="ws-01", label="Rule Suspicious tool (2 matches)",
            details={"rule": "Suspicious tool", "matches": 2}, detection_ids=["det-1", "det-2"], hosts=["ws-01"],
        ),
    ]
    for number, lead in enumerate(leads, start=1):
        lead["ref"] = f"L{number}"
    return leads


def test_suggestions_are_checked_and_linked_from_their_leads() -> None:
    raw = [
        {
            "title": "Service account credential theft and use",
            "severity": "HIGH",
            "confidence": "medium",
            "mitre": ["T1558.003", "credential access", "t1021"],
            "leads": ["L1", "L2", "L9"],
            "description": "tool.exe dumped a ticket for svc on ws-01 [L1], then svc logged on to srv-01 from 192.0.2.42 three times [L2]. "
                           "It also reached 198.51.100.9 at 11:00.",
        },
        {"title": "Nothing behind it", "leads": ["L42"], "description": "Invented [L42]."},
        {"title": "", "leads": ["L3"]},
        "not an object",
    ]
    suggestions, dropped = finding_suggestions.build_suggestions(raw, _leads(), PROVENANCE)
    assert dropped == 3 and len(suggestions) == 1
    item = suggestions[0]
    assert item["severity"] == "high" and item["confidence"] == "medium"
    assert item["mitre"] == ["T1558.003", "T1021"] and item["phase"] == "credential_access"
    assert [lead["ref"] for lead in item["leads"]] == ["L1", "L2"]
    issues = {(issue["kind"], issue["value"]) for issue in item["issues"]}
    assert issues == {("unknown_citation", "L9"), ("unsupported_fact", "198.51.100.9"), ("unsupported_fact", "11:00")}
    finding = item["finding"]
    # Links come from the cited leads, not from the text.
    assert finding["event_ids"] == ["ev-1"] and finding["detection_ids"] == []
    assert finding["related_hosts"] == ["ws-01", "srv-01"] and finding["related_ips"] == ["192.0.2.42"]
    assert finding["related_users"] == ["alice", "svc"] and finding["linked_evidence_id"] == "evd-1"
    assert finding["time_start"] == "2026-01-10T09:15:02Z" and finding["time_end"] == "2026-01-10T09:40:00Z"
    assert finding["source"] == "ai_suggestion" and finding["tags"] == ["ai-suggested"] and finding["status"] == "new"
    assert "llama-local" in finding["source_label"]


def test_cited_ranges_of_leads_are_expanded() -> None:
    suggestions, _ = finding_suggestions.build_suggestions(
        [{"title": "Activity on ws-01", "leads": ["L1-L2"], "description": "Tool run and logons [L2–3]. Also [L9-L12]."}],
        _leads(), PROVENANCE,
    )
    item = suggestions[0]
    assert [lead["ref"] for lead in item["leads"]] == ["L1", "L2", "L3"]
    assert {issue["value"] for issue in item["issues"] if issue["kind"] == "unknown_citation"} == {"L9", "L10", "L11", "L12"}
    assert not [issue for issue in item["issues"] if issue["kind"] == "unsupported_fact"]


def test_unknown_severity_and_confidence_fall_back() -> None:
    suggestions, _ = finding_suggestions.build_suggestions(
        [{"title": "Detections on ws-01", "severity": "severe", "confidence": "certain", "mitre": "T1059.001", "description": "Rule fired [L3]."}],
        _leads(), PROVENANCE,
    )
    item = suggestions[0]
    assert item["severity"] == "medium" and item["confidence"] is None and item["mitre"] == ["T1059.001"]
    assert item["finding"]["detection_ids"] == ["det-1", "det-2"] and item["finding"]["linked_evidence_id"] is None


def test_leads_are_referenced_in_time_order_and_a_failing_source_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    leads = _leads()
    monkeypatch.setattr(finding_suggestions, "_open_findings", lambda _db, _case: [SimpleNamespace(event_ids=["ev-9"], related_event_ids=[])])
    seen_covered = {}

    def detections(_db, _case, covered):
        seen_covered["value"] = covered
        return [leads[2]]

    def broken(*_args):
        raise RuntimeError("index down")

    monkeypatch.setattr(finding_suggestions, "_detection_leads", detections)
    monkeypatch.setattr(finding_suggestions, "_command_leads", lambda *_a: [leads[0]])
    monkeypatch.setattr(finding_suggestions, "_memory_leads", broken)
    monkeypatch.setattr(finding_suggestions, "_lateral_leads", lambda *_a: [leads[1]])
    collected, _findings, unavailable = finding_suggestions.collect_leads(None, "case-1")
    assert [(lead["ref"], lead["kind"]) for lead in collected] == [("L1", "detection"), ("L2", "command"), ("L3", "lateral")]
    assert unavailable == ["memory"] and seen_covered["value"] == {"ev-9"}


def test_command_leads_skip_covered_events_and_keep_memory_commands_unlinked(monkeypatch: pytest.MonkeyPatch) -> None:
    items = [
        {"timestamp": "2026-01-10T09:00:00Z", "host": "ws-01", "command": "whoami /all", "risk_score": 40, "source_event_id": "ev-1", "source_type": "sysmon"},
        {"timestamp": "2026-01-10T09:05:00Z", "host": "ws-01", "command": "covered.exe", "risk_score": 95, "source_event_id": "ev-2", "source_type": "sysmon"},
        {"timestamp": "2026-01-10T09:10:00Z", "host": "ws-01", "command": "tool.exe dump", "risk_score": 90, "source_event_id": "mem-key", "source_type": "memory"},
        {"timestamp": "2026-01-10T09:12:00Z", "host": "ws-01", "command": "whoami  /all", "risk_score": 40, "source_event_id": "ev-3", "source_type": "sysmon"},
    ]
    monkeypatch.setattr("app.services.command_history.get_command_history", lambda *_a, **_k: {"items": items})
    leads = finding_suggestions._command_leads(None, "case-1", {"ev-2"})
    assert [lead["details"]["command"] for lead in leads] == ["tool.exe dump", "whoami /all"]
    assert leads[0]["backing"]["event_ids"] == []
    # The same command on the same host is one lead with every run.
    assert leads[1]["backing"]["event_ids"] == ["ev-1", "ev-3"] and leads[1]["details"]["runs"] == 2
    assert leads[1]["time_utc"] == "2026-01-10T09:00:00Z" and leads[1]["last_utc"] == "2026-01-10T09:12:00Z"


def test_lateral_leads_leave_out_routine_logons(monkeypatch: pytest.MonkeyPatch) -> None:
    edges = [
        {"target_host": "srv-01", "source_ip": "192.0.2.41", "source_hosts": ["ws-01"], "user": "WS-01$", "routine_reason": "machine account", "first_seen": "2026-01-10T08:00:00Z"},
        {"target_host": "srv-01", "source_ip": "192.0.2.42", "source_hosts": [], "user": "svc", "domain": "CORP", "routine_reason": None,
         "first_seen": "2026-01-10T09:30:00Z", "successes": 3, "failures": 0, "method": "Remote Desktop (type 10)"},
    ]
    monkeypatch.setattr("app.services.lateral_movement.get_lateral_movement", lambda *_a: {"edges": edges})
    leads = finding_suggestions._lateral_leads(None, "case-1")
    assert len(leads) == 1
    assert leads[0]["details"]["account"] == "CORP\\svc" and "not a case host" in leads[0]["label"]
    assert leads[0]["backing"] == {"hosts": ["srv-01"], "ips": ["192.0.2.42"], "users": ["svc"]}


class _SuggestingProvider:
    seen: dict = {}

    def __init__(self, credentials):
        _SuggestingProvider.seen = {"max_tokens": credentials.max_tokens}

    def stream_chat(self, *, system, messages, tools=None):
        _SuggestingProvider.seen.update(system=system, messages=messages, tools=tools)
        yield StreamEvent(type="text", text='```json\n{"suggestions": [{"title": "Tool run on ws-01", "severity": "high", "leads": ["L1"], ')
        yield StreamEvent(type="text", text='"description": "tool.exe dump ran on ws-01 [L1]."}]}\n```')


def test_endpoint_sends_leads_without_their_links_and_creates_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _configured_db(monkeypatch)
    monkeypatch.setattr(report_draft, "build_provider", _SuggestingProvider)
    existing = SimpleNamespace(title="Known finding", severity=SimpleNamespace(value="high"), mitre=["T1078"])
    monkeypatch.setattr(finding_suggestions, "collect_leads", lambda _db, _case: (_leads(), [existing], []))
    response = _client(db).post("/api/cases/case-1/ai/finding-suggestions")
    assert response.status_code == 200, response.text
    body = response.json()
    assert [item["title"] for item in body["suggestions"]] == ["Tool run on ws-01"]
    assert body["suggestions"][0]["issues"] == [] and body["dropped"] == 0
    assert body["lead_counts"] == {"command": 1, "lateral": 1, "detection": 1}
    assert body["provenance"]["prompt_version"] == finding_suggestions.PROMPT_VERSION
    sent = json.loads(_SuggestingProvider.seen["messages"][0]["content"].split("\n", 1)[1])
    assert sent["existing_findings"] == [{"title": "Known finding", "severity": "high", "mitre": ["T1078"]}]
    assert sent["leads"][0]["ref"] == "L1" and "backing" not in sent["leads"][0] and "label" not in sent["leads"][0]
    assert _SuggestingProvider.seen["tools"] is None
    assert _SuggestingProvider.seen["max_tokens"] == report_draft.DRAFT_MIN_TOKENS


def test_endpoint_refuses_without_leads_or_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _configured_db(monkeypatch)
    monkeypatch.setattr(finding_suggestions, "collect_leads", lambda _db, _case: ([], [], []))
    response = _client(db).post("/api/cases/case-1/ai/finding-suggestions")
    assert response.status_code == 409 and "no open leads" in response.json()["detail"]
    from app.services.ai import config as ai_config

    ai_config.update_general(db, enabled=False)
    response = _client(db).post("/api/cases/case-1/ai/finding-suggestions")
    assert response.status_code == 409 and "not enabled" in response.json()["detail"]
    assert _client(db).post("/api/cases/other/ai/finding-suggestions").status_code == 404
