from datetime import UTC, datetime
from types import SimpleNamespace

import app.services.process_tree as process_tree


def _context() -> process_tree._ProcessTreeContext:
    case = SimpleNamespace(id="case-1")
    return process_tree._ProcessTreeContext(case=case, evidences=[], export_timestamp=datetime.now(UTC), scope="case", evidence_id=None, max_events_per_type=250)


def _fake_index(monkeypatch, total: int) -> list[dict]:
    bodies: list[dict] = []
    docs = [{"_id": f"e{index:05d}", "_source": {"event_id": f"e{index:05d}"}, "sort": [index]} for index in range(total)]

    def fake_search(index: str, body: dict) -> dict:  # noqa: ARG001
        bodies.append(dict(body))
        start = int(body["search_after"][0]) + 1 if body.get("search_after") else int(body.get("from") or 0)
        return {"hits": {"total": {"value": total}, "hits": docs[start : start + int(body["size"])]}}

    monkeypatch.setattr(process_tree, "search_documents", fake_search)
    monkeypatch.setattr(process_tree, "get_events_index", lambda case_id: f"dfir-events-{case_id}")
    return bodies


def test_reads_every_event_past_one_page(monkeypatch) -> None:
    monkeypatch.setattr(process_tree, "_SEARCH_PAGE_SIZE", 10)
    bodies = _fake_index(monkeypatch, total=25)

    events, total, _ = process_tree._search_scope_events(_context(), size=100)

    assert total == 25
    assert [event["id"] for event in events] == [f"e{index:05d}" for index in range(25)]
    assert len(bodies) == 3
    assert all("from" not in body for body in bodies)
    assert bodies[0]["sort"][-1] == {"event_id": {"order": "asc", "missing": "_last"}}


def test_stops_at_the_requested_size(monkeypatch) -> None:
    monkeypatch.setattr(process_tree, "_SEARCH_PAGE_SIZE", 10)
    _fake_index(monkeypatch, total=25)

    events, total, _ = process_tree._search_scope_events(_context(), size=15)

    assert len(events) == 15
    assert total == 25


def test_small_reads_stay_a_single_request(monkeypatch) -> None:
    bodies = _fake_index(monkeypatch, total=25)

    events, _, _ = process_tree._search_scope_events(_context(), size=5)

    assert len(events) == 5
    assert len(bodies) == 1


def test_graph_says_when_the_limit_cut_process_events_off(monkeypatch) -> None:
    monkeypatch.setattr(process_tree, "_PROCESS_EVENT_LIMIT", 2)
    monkeypatch.setattr(process_tree, "_SEARCH_PAGE_SIZE", 1)
    _fake_index(monkeypatch, total=5)

    bundle = process_tree.build_process_tree_bundle(SimpleNamespace(id="case-1"), [], scope="case")

    assert "Read the latest 2 of 5 process start events; older processes and their links are not in the graph." in bundle["graph"]["summary"]["warnings"]
