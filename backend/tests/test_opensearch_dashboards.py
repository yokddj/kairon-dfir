import json

from app.services import opensearch_dashboards as dashboards


class _DummyIndices:
    def get(self, index: str, params: dict | None = None) -> dict:
        return {index: {}}


class _DummyClient:
    def __init__(self) -> None:
        self.indices = _DummyIndices()


def test_status_returns_dashboards_unavailable_gracefully(monkeypatch) -> None:
    monkeypatch.setattr(dashboards, "get_opensearch_client", lambda: _DummyClient())
    monkeypatch.setattr(dashboards, "count_documents", lambda index, body: {"count": 7})
    monkeypatch.setattr(dashboards, "_dashboard_request", lambda method, path, payload=None, timeout=5: (0, None, "connection refused"))
    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (None, ["dashboards_unreachable"]))

    result = dashboards.dashboards_admin_status()

    assert result["dashboards"]["available"] is False
    assert "dashboards_unreachable" in result["dashboards"]["warnings"]


def test_bootstrap_creates_data_view_when_missing(monkeypatch) -> None:
    calls: list[tuple[str, str, dict | None]] = []

    def fake_request(method: str, path: str, payload: dict | None = None, timeout: int = 5):
        calls.append((method, path, payload))
        return 200, {"id": "dfir-events"}, None

    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (None, []))
    monkeypatch.setattr(dashboards, "_dashboard_request", fake_request)

    result = dashboards.bootstrap_dashboards_data_view()

    assert result["created"] is True
    assert calls[0][0] == "POST"
    assert "/api/saved_objects/index-pattern/dfir-events" in calls[0][1]


def test_bootstrap_is_idempotent_when_existing(monkeypatch) -> None:
    existing = {"id": "dfir-events", "attributes": {"title": "dfir-events-*", "timeFieldName": "@timestamp"}}
    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (existing, []))

    called = {"count": 0}

    def fake_request(method: str, path: str, payload: dict | None = None, timeout: int = 5):
        called["count"] += 1
        return 200, {"id": "dfir-events"}, None

    monkeypatch.setattr(dashboards, "_dashboard_request", fake_request)

    result = dashboards.bootstrap_dashboards_data_view()

    assert result["created"] is False
    assert result["updated"] is False
    assert called["count"] == 0


def test_repair_updates_wrong_time_field(monkeypatch) -> None:
    existing = {"id": "dfir-events", "attributes": {"title": "dfir-events-*", "timeFieldName": "timestamp"}}
    calls: list[tuple[str, str, dict | None]] = []

    def fake_request(method: str, path: str, payload: dict | None = None, timeout: int = 5):
        calls.append((method, path, payload))
        return 200, {"id": "dfir-events"}, None

    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (existing, []))
    monkeypatch.setattr(dashboards, "_dashboard_request", fake_request)

    result = dashboards.bootstrap_dashboards_data_view(repair=True)

    assert result["updated"] is True
    assert calls[0][0] == "POST"
    assert "overwrite=true" in calls[0][1]
    assert calls[0][2]["attributes"]["timeFieldName"] == "@timestamp"


def test_status_includes_event_count(monkeypatch) -> None:
    monkeypatch.setattr(dashboards, "get_opensearch_client", lambda: _DummyClient())
    monkeypatch.setattr(dashboards, "count_documents", lambda index, body: {"count": 123})
    monkeypatch.setattr(dashboards, "_dashboard_request", lambda method, path, payload=None, timeout=5: (200, {"status": "ok"}, None))
    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (None, []))

    result = dashboards.dashboards_admin_status()

    assert result["opensearch"]["events_count"] == 123


def test_status_does_not_leak_credentials(monkeypatch) -> None:
    monkeypatch.setattr(dashboards, "get_opensearch_client", lambda: _DummyClient())
    monkeypatch.setattr(dashboards, "count_documents", lambda index, body: {"count": 1})
    monkeypatch.setattr(dashboards, "_dashboard_request", lambda method, path, payload=None, timeout=5: (200, {"status": "ok"}, None))
    monkeypatch.setattr(dashboards, "_find_data_view", lambda pattern: (None, []))

    result = dashboards.dashboards_admin_status()
    dumped = json.dumps(result)

    assert dashboards.settings.opensearch_password not in dumped
