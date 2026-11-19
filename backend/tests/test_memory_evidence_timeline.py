"""A memory evidence's own timeline (app.services.memory.evidence_timeline): Volatility's dated
events merged with MemProcFS's timelines, paged by cursor."""

from __future__ import annotations

from typing import Any

import pytest

from app.services.memory import evidence_timeline
from app.services.memory.evidence_timeline import decode_cursor, encode_cursor, memory_evidence_timeline


def _vol(index: int, minute: int, kind: str = "processes") -> dict[str, Any]:
    return {"id": f"vol-{index:03d}", "timestamp": f"2025-03-07T19:{minute:02d}:00Z", "producer": "volatility", "kind": kind, "kind_label": kind, "title": f"Process started: p{index}.exe", "summary": None, "pid": index, "process_name": f"p{index}.exe"}


def _mp(index: int, minute: int, kind: str = "eventlog") -> dict[str, Any]:
    return {"id": f"memprocfs-{index:03d}", "timestamp": f"2025-03-07T19:{minute:02d}:00Z", "producer": "memprocfs", "kind": kind, "kind_label": kind, "title": f"event {index}", "summary": None, "pid": None, "process_name": None}


@pytest.fixture
def fake_sources(monkeypatch: pytest.MonkeyPatch):
    volatility = [_vol(i, i) for i in range(0, 40, 2)]  # even minutes
    memprocfs = [_mp(i, i) for i in range(1, 40, 2)] + [_mp(100 + i, i, "ntfs") for i in range(5)]
    calls: dict[str, Any] = {}

    monkeypatch.setattr(evidence_timeline, "_volatility_items", lambda db, case_id, evidence_id, kinds: list(volatility))

    def page(case_id, evidence_id, kinds, query, cursor, descending, size, window=(None, None)):
        calls["kinds"] = kinds
        calls["window"] = window
        rows = sorted((item for item in memprocfs if item["kind"] in kinds and (not query or query in item["title"]) and evidence_timeline._in_window(item, window)), key=evidence_timeline._sort_key, reverse=descending)
        rows = [item for item in rows if evidence_timeline._after(item, cursor, descending)]
        return rows[:size], len(rows)

    monkeypatch.setattr(evidence_timeline, "_memprocfs_page", page)
    monkeypatch.setattr(evidence_timeline, "_memprocfs_counts", lambda case_id, evidence_id, query, window=(None, None): {"eventlog": 20, "ntfs": 5})
    return calls


def _walk(**kwargs) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    cursor = None
    while True:
        result = memory_evidence_timeline(None, case_id="c", evidence_id="e", cursor=cursor, page_size=50, **kwargs)
        seen.extend(result["items"])
        cursor = result["next_cursor"]
        if not cursor:
            return seen


def test_cursor_round_trips() -> None:
    assert decode_cursor(encode_cursor("2025-03-07T19:00:00Z", "vol-1")) == ("2025-03-07T19:00:00Z", "vol-1")
    assert decode_cursor("not-a-cursor") is None


def test_both_producers_are_merged_in_time_order_without_ntfs_by_default(fake_sources) -> None:
    result = memory_evidence_timeline(None, case_id="c", evidence_id="e", page_size=50)
    minutes = [item["timestamp"] for item in result["items"]]
    assert minutes == sorted(minutes)
    assert {item["producer"] for item in result["items"]} == {"volatility", "memprocfs"}
    assert "ntfs" not in fake_sources["kinds"] and "registry" not in result["selected_kinds"]
    assert result["counts"]["processes"] == 20 and result["counts"]["ntfs"] == 5
    assert result["total"] == 40


def test_walking_every_page_returns_each_event_once_in_both_orders(fake_sources, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence_timeline, "PAGE_SIZES", (2, 50))
    for order in ("asc", "desc"):
        items = []
        cursor = None
        while True:
            result = memory_evidence_timeline(None, case_id="c", evidence_id="e", cursor=cursor, page_size=2, order=order, kinds=["processes", "eventlog", "ntfs"])
            items.extend(result["items"])
            cursor = result["next_cursor"]
            if not cursor:
                break
        ids = [item["id"] for item in items]
        assert len(ids) == len(set(ids)) == 45
        keys = [evidence_timeline._sort_key(item) for item in items]
        assert keys == sorted(keys, reverse=order == "desc")


def test_selected_kinds_and_text_filter_apply_to_both_producers(fake_sources) -> None:
    only_memprocfs = _walk(kinds=["ntfs"])
    assert {item["kind"] for item in only_memprocfs} == {"ntfs"}
    searched = _walk(q="p4.exe")
    assert [item["id"] for item in searched] == ["vol-004"]


def test_unknown_kinds_are_ignored(fake_sources) -> None:
    assert memory_evidence_timeline(None, case_id="c", evidence_id="e", kinds=["bogus"])["selected_kinds"] == []


def test_memprocfs_page_asks_opensearch_for_the_rows_after_the_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import opensearch

    bodies: list[dict[str, Any]] = []

    class Client:
        def search(self, index, body, params=None):
            bodies.append(body)
            return {"hits": {"total": {"value": 1}, "hits": [{"_id": "x", "_source": {"event_id": "memprocfs-x", "@timestamp": "2025-03-07T19:41:00Z", "artifact": {"type": "memprocfs_eventlog"}, "event": {"message": "Security event 4688", "type": "event_id_4688"}, "process": {"pid": "4"}}}]}}

    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda *a, **k: Client())
    rows, remaining = evidence_timeline._memprocfs_page("c", "e", ["eventlog"], "4688", ("2025-03-07T19:00:00Z", "memprocfs-a"), True, 50)
    assert rows[0]["kind"] == "eventlog" and rows[0]["pid"] == 4 and rows[0]["title"] == "Security event 4688" and remaining == 1
    body = bodies[0]
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}, {"event_id": {"order": "desc"}}]
    filters = str(body["query"]["bool"]["filter"])
    assert "'lt': '2025-03-07T19:00:00Z'" in filters and "memprocfs_eventlog" in filters and "*4688*" in filters


def test_route_rejects_evidence_from_another_case() -> None:
    from fastapi import HTTPException

    from app.api import routes_memory

    class Db:
        def get(self, model, key):
            return type("E", (), {"case_id": "other"})()

    with pytest.raises(HTTPException) as exc:
        routes_memory.get_memory_evidence_timeline("c", "e", kinds=None, q=None, order="asc", cursor=None, page_size=100, db=Db())
    assert exc.value.status_code == 404


def test_a_time_window_limits_both_producers(fake_sources) -> None:
    items = _walk(time_from="2025-03-07T19:10:00Z", time_to="2025-03-07T19:19:59Z")
    assert [item["timestamp"][14:16] for item in items] == [f"{minute:02d}" for minute in range(10, 20)]
    assert {item["producer"] for item in items} == {"volatility", "memprocfs"}
    result = memory_evidence_timeline(None, case_id="c", evidence_id="e", time_from="2025-03-07T19:10:00Z")
    assert result["counts"]["processes"] == 15
    assert result["time_range"] == {"from": "2025-03-07T19:10:00Z", "to": None}


def test_a_window_in_another_timezone_is_compared_as_the_same_moment(fake_sources) -> None:
    items = _walk(time_from="2025-03-07T21:30:00+02:00", time_to="2025-03-07T21:31:59+02:00")
    assert [item["id"] for item in items] == ["vol-030", "memprocfs-031"]


def test_an_unreadable_window_is_a_400(fake_sources) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as excinfo:
        memory_evidence_timeline(None, case_id="c", evidence_id="e", time_from="not a date")
    assert excinfo.value.status_code == 400


def test_memprocfs_rows_are_limited_to_the_window_in_opensearch(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import opensearch

    bodies: list[dict[str, Any]] = []

    class Client:
        def search(self, index, body, params=None):
            bodies.append(body)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda *a, **k: Client())
    window = evidence_timeline._window("2025-03-07T19:00:00Z", "2025-03-07T20:00:00Z")
    evidence_timeline._memprocfs_page("c", "e", ["eventlog"], "", None, False, 50, window)
    assert {"range": {"@timestamp": {"gte": "2025-03-07T19:00:00+00:00", "lte": "2025-03-07T20:00:00+00:00"}}} in bodies[0]["query"]["bool"]["filter"]
