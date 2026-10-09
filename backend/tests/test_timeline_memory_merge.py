"""Volatility's dated memory events in the case Timeline's lightweight view
(timeline_service._merged_lightweight_page / _volatility_timeline_rows)."""

from __future__ import annotations

import random
from typing import Any

import pytest

from app.services import timeline_service
from app.services.search_service import _decode_cursor


def _event(index: int, second: int) -> dict[str, Any]:
    return {"id": f"evt-{index:04d}", "timestamp": f"2025-03-07T19:00:{second:02d}Z", "title": f"event {index}", "raw": {"evidence_id": "disk"}}


def _memory(index: int, second: int) -> dict[str, Any]:
    return {"id": f"memory:vol-{index:04d}", "kind": "event", "timestamp": f"2025-03-07T19:00:{second:02d}Z", "title": f"process {index}"}


def _fake_search(events: list[dict[str, Any]], descending: bool):
    ordered = sorted(events, key=lambda row: row["timestamp"], reverse=descending)  # stable: ties keep their order

    def search(case_id, params, db=None):
        start = _decode_cursor(params.get("cursor")) if params.get("cursor") else 0
        size = int(params["page_size"])
        return len(ordered), ordered[start : start + size], [], {}

    return ordered, search


@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize("seed", range(6))
def test_every_page_matches_the_full_merge(monkeypatch: pytest.MonkeyPatch, descending: bool, seed: int) -> None:
    rng = random.Random(seed)
    events = [_event(i, rng.randrange(0, 40)) for i in range(rng.randrange(0, 90))]
    memory = [_memory(i, rng.randrange(0, 40)) for i in range(rng.randrange(1, 25))]
    ordered, search = _fake_search(events, descending)
    monkeypatch.setattr(timeline_service, "search_events_v2", search)
    monkeypatch.setattr(timeline_service, "_compact_event_row_lightweight", lambda row: row)

    # Reference: events in their own order, memory events by time, events first on equal times.
    sorted_memory = sorted(memory, key=lambda row: (row["timestamp"], row["id"]), reverse=descending)
    expected: list[dict[str, Any]] = []
    i = j = 0
    while i < len(ordered) or j < len(sorted_memory):
        take_memory = i >= len(ordered) or (j < len(sorted_memory) and (sorted_memory[j]["timestamp"] > ordered[i]["timestamp"] if descending else sorted_memory[j]["timestamp"] < ordered[i]["timestamp"]))
        if take_memory:
            expected.append(sorted_memory[j]); j += 1
        else:
            expected.append(ordered[i]); i += 1

    page_size = rng.choice([3, 7, 10])
    seen: list[str] = []
    for offset in range(0, len(expected), page_size):
        total, page, _ = timeline_service._merged_lightweight_page("c", {}, memory, offset=offset, page_size=page_size, descending=descending, db=None)
        assert total == len(expected)
        assert [row["id"] for row in page] == [row["id"] for row in expected[offset : offset + page_size]], (offset, page_size)
        seen.extend(row["id"] for row in page)
    assert len(seen) == len(set(seen)) == len(expected)


def _volatility_item(kind: str, second: int, **extra: Any) -> dict[str, Any]:
    return {"id": f"vol-{kind}-{second}", "timestamp": f"2025-03-07T19:00:{second:02d}Z", "producer": "volatility", "kind": kind, "kind_label": kind, "event_type": "process_start" if kind == "processes" else "network_connection", "title": f"{kind} {second}", "summary": None, "pid": 4, "process_name": "dumpit.exe", "source": "windows.pslist", "run_id": "run-1", **extra}


@pytest.fixture
def one_memory_evidence(monkeypatch: pytest.MonkeyPatch):
    from types import SimpleNamespace

    from app.services import investigation_memory
    from app.services.memory import evidence_timeline

    evidence = SimpleNamespace(id="ev-mem")
    monkeypatch.setattr(investigation_memory, "memory_evidences", lambda db, case_id, evidence_id=None: [evidence] if evidence_id in (None, "ev-mem") else [])
    monkeypatch.setattr(investigation_memory, "_evidence_host_name", lambda db, evidence: "DESKTOP-1")
    monkeypatch.setattr(evidence_timeline, "_volatility_items", lambda db, case_id, evidence_id, kinds: [_volatility_item("processes", 10), _volatility_item("network", 20)])


def test_rows_carry_memory_source_host_and_types(one_memory_evidence) -> None:
    rows = timeline_service._volatility_timeline_rows(None, "c", {})
    assert [row["artifact_type"] for row in rows] == ["memory_process", "memory_network"]
    assert rows[0]["source_category"] == "Memory" and rows[0]["host"] == "DESKTOP-1" and rows[0]["evidence_id"] == "ev-mem"
    assert rows[0]["event_type"] == "process_start" and rows[0]["raw"]["process"] == {"pid": 4, "name": "dumpit.exe"}


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"artifact_type": ["volatility"]}, 2),
        ({"artifact_type": ["memprocfs"]}, 0),
        ({"event_type": ["process_start"]}, 1),
        ({"time_from": "2025-03-07T19:00:15Z"}, 1),
        ({"q": "network"}, 1),
        ({"host": "desktop-1"}, 2),
        ({"host": "other"}, 0),
        ({"evidence_id": "disk-1"}, 0),
        ({"file_path": "C:\\x"}, 0),
        ({"risk_min": 40}, 0),
        ({"source_category": "Disk"}, 0),
    ],
)
def test_filters_apply_to_memory_rows(one_memory_evidence, params, expected) -> None:
    assert len(timeline_service._volatility_timeline_rows(None, "c", params)) == expected


def test_lightweight_view_includes_memory_events(monkeypatch: pytest.MonkeyPatch, one_memory_evidence) -> None:
    events = [_event(1, 5), _event(2, 15)]
    _ordered, search = _fake_search(events, False)
    monkeypatch.setattr(timeline_service, "search_events_v2", search)
    response = timeline_service.build_lightweight_timeline_response(None, "c", {"sort": "timestamp_asc", "page_size": 50})
    assert [item["id"] for item in response["items"]] == ["evt-0001", "memory:vol-processes-10", "evt-0002", "memory:vol-network-20"]
    assert response["total"] == 4 and response["next_cursor"] is None


def test_quick_filter_and_alias_cover_volatility_events() -> None:
    from app.services.search_service import _artifact_type_values

    quick = next(item for item in timeline_service.TIMELINE_QUICK_FILTERS if item["id"] == "memory_volatility")
    assert set(_artifact_type_values(quick["params"]["artifact_type"])) >= {"memory_process", "memory_network"}
