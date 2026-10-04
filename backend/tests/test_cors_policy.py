"""The API answers cross-origin requests only for the configured origins."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import app

client = TestClient(app)


def _preflight(origin: str):
    return client.options("/api/cases", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})


def test_an_unknown_origin_is_not_allowed():
    # Starlette refuses the preflight; without an allow-origin header the browser blocks the request.
    response = _preflight("http://evil.example")
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_another_local_port_is_not_allowed():
    assert "access-control-allow-origin" not in _preflight("http://localhost:3000").headers


def test_a_plain_request_from_an_unknown_origin_gets_no_cors_headers():
    response = client.get("/api/system/version", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_the_configured_origin_is_allowed_with_credentials():
    origin = Settings().cors_origins[0]
    response = _preflight(origin)
    assert response.headers.get("access-control-allow-origin") == origin
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_no_origin_pattern_is_set_unless_configured(monkeypatch):
    assert Settings().cors_origin_regex is None
    monkeypatch.setenv("BACKEND_CORS_ORIGIN_REGEX", r"https://.*\.example\.com")
    assert Settings().cors_origin_regex == r"https://.*\.example\.com"
