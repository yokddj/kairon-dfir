from __future__ import annotations

from typing import Any

from app.services import startup_persistence


def _row(index: int, risk: int) -> dict[str, Any]:
    return {
        "id": f"item-{index}",
        "type": "run_key",
        "name": f"entry-{index}",
        "host": "HOSTA",
        "risk_score": risk,
        "enabled": True,
        "source_artifact": "registry",
    }


def _drive(monkeypatch, rows: list[dict[str, Any]], params: dict[str, Any]) -> dict[str, Any]:
    """Run the real listing with the source layer stubbed out."""
    monkeypatch.setattr(startup_persistence, "SOURCE_QUERIES", [
        {"source": "registry", "artifact_types": ["registry"], "queries": ["run"], "limit": 100},
    ])
    monkeypatch.setattr(startup_persistence, "_active_source_names", lambda *_a, **_k: {"registry"})
    monkeypatch.setattr(startup_persistence, "search_events_v2", lambda *_a, **_k: (len(rows), rows, [], {}))
    monkeypatch.setattr(startup_persistence, "_normalize_event_row", lambda _case, row, _source: row)
    monkeypatch.setattr(startup_persistence, "_dedupe_items", lambda items: items)
    monkeypatch.setattr(startup_persistence, "_command_history_candidates", lambda *_a, **_k: [])
    return startup_persistence.list_startup_persistence_items(None, "case-1", params)


def test_summary_describes_the_population_not_the_selection(monkeypatch) -> None:
    """"38 items, 38 suspicious" is a tautology, not a finding.

    The summary was computed after the suspicious_only filter, so a caller that
    asked only for suspicious entries was told every entry it got back was
    suspicious -- which reads as though the host were entirely compromised, and
    conveys nothing about how unusual those entries actually are.
    """
    rows = [_row(index, 80 if index < 3 else 5) for index in range(10)]

    result = _drive(monkeypatch, rows, {"suspicious_only": True, "page_size": 50})

    assert result["total"] == 3, "only the suspicious entries are selected"
    assert result["summary"]["total"] == 10, "but the summary describes all ten found"
    assert result["summary"]["suspicious"] == 3
    assert result["summary"]["matched"] == 3


def test_structural_filters_still_narrow_the_population(monkeypatch) -> None:
    """Type and enabled scope what is being described; risk only selects."""
    rows = [_row(index, 80) for index in range(4)]
    rows[0]["type"] = "service"

    result = _drive(monkeypatch, rows, {"type": ["run_key"], "page_size": 50})

    assert result["summary"]["total"] == 3
    assert result["total"] == 3


def test_without_a_risk_filter_population_and_selection_agree(monkeypatch) -> None:
    rows = [_row(index, 80 if index < 2 else 0) for index in range(5)]

    result = _drive(monkeypatch, rows, {"page_size": 50})

    assert result["summary"]["total"] == 5
    assert result["summary"]["matched"] == 5
    assert result["summary"]["suspicious"] == 2
