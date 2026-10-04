"""State-changing requests from another origin are refused; same-origin and non-browser ones are not."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.csrf import origin_is_trusted
from app.main import app

client = TestClient(app)
ALLOWED = ["http://localhost:5173"]


def _trusted(origin: str, host: str | None = "kairon.lan:5173", regex: str | None = None) -> bool:
    return origin_is_trusted(origin, host=host, allowed_origins=ALLOWED, allowed_regex=regex)


@pytest.mark.parametrize(
    "origin, host",
    [
        ("http://kairon.lan:5173", "kairon.lan:5173"),          # LAN mode through Nginx
        ("http://localhost:5173", "localhost:8000"),            # Vite dev proxy rewrites Host; allowed list
        ("https://kairon.example.com", "kairon.example.com"),   # default port omitted on both sides
        ("https://kairon.example.com", "kairon.example.com:443"),
        ("http://KAIRON.lan:5173", "kairon.lan:5173"),
    ],
)
def test_same_origin_and_configured_origins_are_trusted(origin, host):
    assert _trusted(origin, host)


@pytest.mark.parametrize(
    "origin, host",
    [
        ("http://evil.example", "kairon.lan:5173"),
        ("http://localhost:3000", "localhost:5173"),     # another port of the same host
        ("http://kairon.lan:5174", "kairon.lan:5173"),
        ("http://kairon.lan", "kairon.lan:5173"),
        ("null", "kairon.lan:5173"),                     # sandboxed iframe, file://
        ("", "kairon.lan:5173"),
        ("http://kairon.lan:5173", None),
        ("not a url", "kairon.lan:5173"),
    ],
)
def test_other_origins_are_not_trusted(origin, host):
    assert not _trusted(origin, host)


def test_an_explicit_pattern_extends_the_allowed_origins():
    assert _trusted("https://a.example.com", "kairon.lan", regex=r"https://.*\.example\.com")
    assert not _trusted("https://a.example.org", "kairon.lan", regex=r"https://.*\.example\.com")


def test_a_cross_site_post_is_refused_before_it_reaches_the_route():
    response = client.post("/api/auth/login", json={"username": "x", "password": "y"}, headers={"Origin": "http://evil.example"})
    assert (response.status_code, response.json()) == (403, {"detail": "Cross-site request refused"})


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_every_state_changing_method_is_checked(method):
    response = client.request(method.upper(), "/api/cases/x", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 403


def test_the_referer_is_used_when_there_is_no_origin():
    refused = client.post("/api/auth/logout", headers={"Referer": "http://evil.example/page"})
    allowed = client.post("/api/auth/logout", headers={"Referer": "http://testserver/cases"})
    assert refused.status_code == 403 and allowed.status_code != 403


def test_same_origin_and_non_browser_requests_pass():
    assert client.post("/api/auth/logout", headers={"Origin": "http://testserver"}).status_code != 403
    assert client.post("/api/auth/logout").status_code != 403   # curl, scripts, the CLI
    assert client.post("/api/auth/logout", headers={"Origin": "http://localhost:5173"}).status_code != 403


def test_reads_are_never_checked():
    assert client.get("/api/system/version", headers={"Origin": "http://evil.example"}).status_code == 200
