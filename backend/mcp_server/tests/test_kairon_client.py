"""The HTTP client this server uses to talk to Kairon's own API: argument
shaping (dropping None, scalar query params) and error translation
(a non-2xx response becomes a KaironAPIError the server can report to the
model instead of crashing on).
"""
from __future__ import annotations

import httpx
import pytest

from mcp_server.kairon_client import KaironAPIError, KaironClient


class _Response:
    def __init__(self, status_code: int, json_body=None, text: str = ""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text or (str(json_body) if json_body is not None else "")

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


def test_from_env_requires_the_api_url(monkeypatch):
    monkeypatch.delenv("KAIRON_API_URL", raising=False)
    monkeypatch.setenv("KAIRON_SERVICE_TOKEN", "x")

    with pytest.raises(RuntimeError, match="KAIRON_API_URL"):
        KaironClient.from_env()


def test_from_env_requires_the_service_token(monkeypatch):
    monkeypatch.setenv("KAIRON_API_URL", "http://localhost:8000")
    monkeypatch.delenv("KAIRON_SERVICE_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="KAIRON_SERVICE_TOKEN"):
        KaironClient.from_env()


def test_from_env_builds_a_working_client(monkeypatch):
    monkeypatch.setenv("KAIRON_API_URL", "http://localhost:8000/")
    monkeypatch.setenv("KAIRON_SERVICE_TOKEN", "kairon_svc_abc")

    client = KaironClient.from_env()

    assert client.base_url == "http://localhost:8000"  # trailing slash stripped


def test_every_request_carries_the_bearer_token(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return _Response(200, json_body={"tools": []})

    monkeypatch.setattr(httpx, "get", fake_get)
    client = KaironClient("http://localhost:8000", "kairon_svc_abc")

    client.list_tool_specs()

    assert captured["headers"] == {"Authorization": "Bearer kairon_svc_abc"}
    assert captured["url"] == "http://localhost:8000/api/ai/tools"


def test_a_404_response_raises_a_kairon_api_error_with_the_detail(monkeypatch):
    monkeypatch.setattr(
        httpx, "get",
        lambda *a, **k: _Response(404, json_body={"detail": "Case not found"}),
    )
    client = KaironClient("http://localhost:8000", "token")

    with pytest.raises(KaironAPIError) as excinfo:
        client.call_tool("missing-case", "list_hosts", {})

    assert excinfo.value.status_code == 404
    assert excinfo.value.detail == "Case not found"


def test_a_response_with_no_json_body_still_reports_something_useful(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Response(500, text="internal server error"))
    client = KaironClient("http://localhost:8000", "token")

    with pytest.raises(KaironAPIError) as excinfo:
        client.list_cases()

    assert excinfo.value.status_code == 500
    assert "internal server error" in excinfo.value.detail


def test_a_network_failure_is_also_a_kairon_api_error_not_a_raw_httpx_exception(monkeypatch):
    def raise_connect_error(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", raise_connect_error)
    client = KaironClient("http://localhost:8000", "token")

    with pytest.raises(KaironAPIError) as excinfo:
        client.list_cases()

    assert "Could not reach Kairon" in excinfo.value.detail


def test_none_valued_arguments_are_dropped_not_sent_as_empty_strings(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["params"] = params
        return _Response(200, json_body={})

    monkeypatch.setattr(httpx, "get", fake_get)
    client = KaironClient("http://localhost:8000", "token")

    client.call_tool("case-1", "search_events", {"query": "powershell", "host": None, "limit": 10})

    assert captured["params"] == {"query": "powershell", "limit": 10}


def test_list_cases_forwards_its_keyword_filters_as_query_params(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _Response(200, json_body=[])

    monkeypatch.setattr(httpx, "get", fake_get)
    client = KaironClient("http://localhost:8000", "token")

    client.list_cases(q="smith", include_archived=None)

    assert captured["url"] == "http://localhost:8000/api/cases"
    assert captured["params"] == {"q": "smith"}
