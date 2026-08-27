from __future__ import annotations

from app.workers import tasks


class _FakeIndices:
    def __init__(self, settings: dict) -> None:
        self._settings = settings

    def get_settings(self, index: str) -> dict:
        return self._settings


class _FakeClient:
    def __init__(self, settings: dict) -> None:
        self.indices = _FakeIndices(settings)


def _settings(window: int | None) -> dict:
    index_settings: dict = {}
    if window is not None:
        index_settings["max_result_window"] = str(window)
    return {"dfir-events-case-1": {"settings": {"index": index_settings}}}


def test_the_configured_window_is_used(monkeypatch) -> None:
    tasks._RESULT_WINDOW_CACHE.clear()
    monkeypatch.setattr(tasks, "get_opensearch_client", lambda: _FakeClient(_settings(50000)))

    assert tasks._index_result_window("case-1") == 50000


def test_an_index_without_the_setting_falls_back_to_the_default(monkeypatch) -> None:
    """OpenSearch's own default, which is what refuses the oversized search."""
    tasks._RESULT_WINDOW_CACHE.clear()
    monkeypatch.setattr(tasks, "get_opensearch_client", lambda: _FakeClient(_settings(None)))

    assert tasks._index_result_window("case-1") == 10000


def test_an_unreachable_index_does_not_take_the_run_down(monkeypatch) -> None:
    tasks._RESULT_WINDOW_CACHE.clear()

    def _boom():
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(tasks, "get_opensearch_client", _boom)

    assert tasks._index_result_window("case-1") == 10000


def test_the_window_is_looked_up_once_per_case(monkeypatch) -> None:
    """It is consulted once per rule, and a pack holds thousands."""
    tasks._RESULT_WINDOW_CACHE.clear()
    calls = {"n": 0}

    def _client():
        calls["n"] += 1
        return _FakeClient(_settings(10000))

    monkeypatch.setattr(tasks, "get_opensearch_client", _client)

    tasks._index_result_window("case-1")
    tasks._index_result_window("case-1")

    assert calls["n"] == 1


def test_the_balanced_mode_asks_for_more_than_a_search_can_return() -> None:
    """Pins the premise of the clamp.

    balanced requests 25000 candidates per rule and exhaustive 200000, while a
    single search may return 10000. Without a clamp those are not truncated
    scans -- the search is rejected outright and the rule contributes nothing.
    """
    assert tasks.SIGMA_RUN_MODE_CONFIG["balanced"]["max_candidate_events_per_rule"] > tasks._DEFAULT_RESULT_WINDOW
    assert tasks.SIGMA_RUN_MODE_CONFIG["exhaustive"]["max_candidate_events_per_rule"] > tasks._DEFAULT_RESULT_WINDOW
    assert tasks.SIGMA_RUN_MODE_CONFIG["fast_triage"]["max_candidate_events_per_rule"] <= tasks._DEFAULT_RESULT_WINDOW
