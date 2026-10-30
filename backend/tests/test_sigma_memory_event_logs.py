"""Sigma rules over Windows event log records recovered from memory (memprocfs_eventlog)."""

from __future__ import annotations

from app.rules_engine.sigma import build_sigma_rule_prefilter, document_matches_sigma_logsource, evaluate_sigma_rule, parse_sigma_rule

DEFENDER_RULE = """
title: Windows Defender Threat Detected
logsource:
  product: windows
  service: windefend
detection:
  selection:
    EventID:
    - 1116
    - 1117
  condition: selection
level: high
"""


def _record(artifact_type: str) -> dict:
    return {
        "artifact": {"type": artifact_type, "parser": "memprocfs"},
        "windows": {"event_id": 1116, "channel": "Microsoft-Windows-Windows Defender/Operational", "provider": "Microsoft-Windows-Windows Defender"},
        "event": {"category": "detection"},
    }


def test_a_record_from_memory_matches_the_rule_its_evtx_copy_matches() -> None:
    rule = parse_sigma_rule(DEFENDER_RULE)[0]
    for artifact_type in ("windows_event", "memprocfs_eventlog"):
        assert document_matches_sigma_logsource(rule["logsource"], _record(artifact_type)) == (True, None)
        assert evaluate_sigma_rule(rule, _record(artifact_type))["matched"]


def test_other_memory_timelines_are_still_not_windows_event_logs() -> None:
    rule = parse_sigma_rule(DEFENDER_RULE)[0]
    assert document_matches_sigma_logsource(rule["logsource"], _record("memprocfs_registry"))[0] is False


def test_the_candidate_query_includes_memory_records_when_the_case_has_them() -> None:
    rule = parse_sigma_rule(DEFENDER_RULE)[0]
    memory_only = build_sigma_rule_prefilter(rule, {"artifact_types_present": {"memprocfs_eventlog": 10}})
    assert memory_only["artifact_types"] == ["memprocfs_eventlog"]
    both = build_sigma_rule_prefilter(rule, {"artifact_types_present": {"memprocfs_eventlog": 10, "windows_event": 5}})
    assert both["artifact_types"] == ["memprocfs_eventlog", "windows_event"]


def _windows_document(event_id: int, provider: str, channel: str, event_data: dict) -> dict:
    return {"tags": [], "event": {"severity": "info"}, "windows": {"event_id": event_id, "provider": provider, "channel": channel, "event_data": event_data}, "process": {}, "file": {}}


def test_console_sessions_are_not_rdp_and_other_providers_106_is_not_a_task() -> None:
    from app.ingest.normalizer import _apply_suspicious_tags

    lsm = ("Microsoft-Windows-TerminalServices-LocalSessionManager", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    console = _windows_document(21, *lsm, {"User": "PC\\bob", "Address": "LOCAL"})
    console["tags"] = ["rdp", "remote_access"]
    assert "rdp" not in _apply_suspicious_tags(console)["tags"]
    remote = _windows_document(21, *lsm, {"User": "PC\\bob", "Address": "10.1.2.3"})
    remote["tags"] = ["rdp", "remote_access"]
    assert "rdp" in _apply_suspicious_tags(remote)["tags"]
    other = _apply_suspicious_tags(_windows_document(106, "Microsoft-Windows-AppReadiness", "Microsoft-Windows-AppReadiness/Operational", {}))
    assert "scheduled_task" not in other["tags"]
    task = _apply_suspicious_tags(_windows_document(106, "Microsoft-Windows-TaskScheduler", "Microsoft-Windows-TaskScheduler/Operational", {}))
    assert {"scheduled_task", "persistence"} <= set(task["tags"])
