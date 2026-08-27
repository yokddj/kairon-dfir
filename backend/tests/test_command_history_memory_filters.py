from __future__ import annotations

from typing import Any

from app.services import command_history


def _memory_command(**extra: Any) -> dict[str, Any]:
    row = {
        "id": "memory-command:ev-1:run-1:pe-1:4",
        "command": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
        "command_normalized": "c:\\windows\\system32\\svchost.exe -k netsvcs",
        "launcher": "svchost.exe",
        "shell_family": "memory",
        "artifact_type": "memory_command_line",
        "source_type": "memory",
        "host": "HOSTA",
        "user": None,
        "risk_score": 0,
        "risk_reasons": [],
        "supporting_events": [],
        "timestamp": "2024-02-29T09:27:51Z",
    }
    row.update(extra)
    return row


def _patch_sources(monkeypatch, memory_rows: list[dict[str, Any]]) -> None:
    monkeypatch.setattr(command_history, "_fetch_candidate_events", lambda *_a, **_k: ([], False))
    monkeypatch.setattr(
        command_history,
        "memory_command_history",
        lambda *_a, **_k: {"items": memory_rows, "total": len(memory_rows)},
    )


def test_only_suspicious_is_applied_to_memory_commands(monkeypatch) -> None:
    """Filters used to run before the memory half was merged in.

    The disk half collapsed to nothing, the unfiltered memory half was appended
    afterwards, and the analyst got a full page of rows matching none of what
    they asked for -- so the filter looked like it had worked.
    """
    _patch_sources(monkeypatch, [_memory_command(), _memory_command(id="m2", risk_score=90)])

    result = command_history.get_command_history("case-1", {"only_suspicious": True, "page_size": 50})

    assert [item["risk_score"] for item in result["items"]] == [90]
    assert result["total"] == 1


def test_risk_min_is_applied_to_memory_commands(monkeypatch) -> None:
    _patch_sources(monkeypatch, [_memory_command(), _memory_command(id="m2", risk_score=60)])

    result = command_history.get_command_history("case-1", {"risk_min": 50, "page_size": 50})

    assert result["total"] == 1
    assert result["items"][0]["risk_score"] == 60


def test_launcher_filter_is_applied_to_memory_commands(monkeypatch) -> None:
    _patch_sources(monkeypatch, [_memory_command(), _memory_command(id="m2", launcher="powershell.exe")])

    result = command_history.get_command_history("case-1", {"launcher": "powershell.exe", "page_size": 50})

    assert result["total"] == 1
    assert result["items"][0]["launcher"] == "powershell.exe"


def test_host_filter_is_applied_to_memory_commands(monkeypatch) -> None:
    _patch_sources(monkeypatch, [_memory_command(), _memory_command(id="m2", host="HOSTB")])

    result = command_history.get_command_history("case-1", {"host": "HOSTB", "page_size": 50})

    assert result["total"] == 1
    assert result["items"][0]["host"] == "HOSTB"


def test_unfiltered_request_still_returns_memory_commands(monkeypatch) -> None:
    """Guards against a filter fix that simply drops the memory source."""
    _patch_sources(monkeypatch, [_memory_command(), _memory_command(id="m2")])

    result = command_history.get_command_history("case-1", {"page_size": 50})

    assert result["total"] == 2


def test_memory_evidence_host_falls_back_to_its_case_host_assignment(monkeypatch) -> None:
    """A memory dump rarely announces its own hostname.

    detected_host is empty for raw images, so memory rows arrived hostless and
    were invisible to every host filter in the product -- even though the
    evidence itself was already assigned to a host in the case.
    """
    from types import SimpleNamespace

    from app.services import investigation_memory

    evidence = SimpleNamespace(id="ev-1", detected_host=None, host_id="host-1")
    db = SimpleNamespace(get=lambda _model, ident: SimpleNamespace(canonical_name="workstation-7") if ident == "host-1" else None)

    assert investigation_memory._evidence_host_name(db, evidence) == "workstation-7"


def test_detected_host_wins_over_the_assignment(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.services import investigation_memory

    evidence = SimpleNamespace(id="ev-1", detected_host="REALNAME", host_id="host-1")
    db = SimpleNamespace(get=lambda _model, ident: SimpleNamespace(canonical_name="workstation-7"))

    assert investigation_memory._evidence_host_name(db, evidence) == "REALNAME"


def test_unassigned_memory_evidence_stays_hostless(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.services import investigation_memory

    evidence = SimpleNamespace(id="ev-1", detected_host=None, host_id=None)
    db = SimpleNamespace(get=lambda _model, ident: None)

    assert investigation_memory._evidence_host_name(db, evidence) is None
