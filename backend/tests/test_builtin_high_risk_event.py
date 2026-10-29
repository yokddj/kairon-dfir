"""The built-in "High-risk event" detection needs a security signal: an event
log's operational level (Error -> severity high) is not a threat."""

from __future__ import annotations

from app.workers import tasks


def _doc(**extra):
    document = {"event": {"type": "event_id_6113", "severity": "high"}, "tags": ["windows_event"], "risk_score": 0}
    document.update(extra)
    return document


def test_high_level_without_any_suspicion_is_not_a_detection(monkeypatch) -> None:
    monkeypatch.setattr(tasks, "load_builtin_detection_overrides", lambda: {})
    assert tasks._builtin_detection_from_document(_doc()) is None


def test_high_severity_with_a_security_signal_still_detects(monkeypatch) -> None:
    monkeypatch.setattr(tasks, "load_builtin_detection_overrides", lambda: {})
    with_reason = tasks._builtin_detection_from_document(_doc(suspicious_reasons=["PowerShell download cradle"]))
    with_risk = tasks._builtin_detection_from_document(_doc(risk_score=80))
    with_tag = tasks._builtin_detection_from_document(_doc(tags=["windows_event", "credential_access"]))
    assert all(result and result[0] == "high_risk_event" for result in (with_reason, with_risk, with_tag))
