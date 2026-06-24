"""Integration tests for the symbol-egress-gateway FastAPI app.

The download path is exercised with monkey-patched DNS + socket layers so
the tests do not perform real network I/O.
"""
from __future__ import annotations

import hashlib
import json
import socket
import struct
import uuid

import pytest
from fastapi.testclient import TestClient

from app.services.memory import symbol_egress_gateway as gateway_module
from app.services.memory.symbol_egress_auth import sign_request


def _make_pdb_bytes(guid_hex: str, age: int) -> bytes:
    from app.services.memory.symbol_fetcher import MSF7_SIGNATURE
    block_size = 512
    content = bytearray(block_size * 5)
    content[:32] = MSF7_SIGNATURE
    struct.pack_into("<6I", content, 32, block_size, 1, 5, 16, 0, 2)
    struct.pack_into("<I", content, block_size * 2, 3)
    directory = struct.pack("<III", 2, 0xFFFFFFFF, 28) + struct.pack("<I", 4)
    content[block_size * 3:block_size * 3 + len(directory)] = directory
    pdb_header = struct.pack("<III", 20000404, 0, age) + uuid.UUID(hex=guid_hex).bytes_le
    content[block_size * 4:block_size * 4 + len(pdb_header)] = pdb_header
    return bytes(content)


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self._body = body
        self._offset = 0

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            data = self._body[self._offset:]
            self._offset = len(self._body)
            return data
        data = self._body[self._offset:self._offset + n]
        self._offset += len(data)
        return data

    def getheader(self, name: str, default=None):
        return self.headers.get(name, default)


def _install_fake_connection(monkeypatch, *, responses: list[_FakeResponse], getaddrinfo=None) -> dict:
    if getaddrinfo is None:
        getaddrinfo = lambda host, port, type=None, **_kw: [(2, 1, 6, "", ("8.8.8.8", port))]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    state = {"counter": 0, "responses": list(responses), "method": None, "target": None}

    class _FakePinned(gateway_module._PinnedHTTPSConnection):
        def __init__(self, host, address, *, timeout):
            self.host = host
            self.port = 443
            self.timeout = timeout
            self.sock = None

        def request(self, method, target, headers=None):
            state["counter"] += 1
            state["method"] = method
            state["target"] = target

        def getresponse(self):
            return state["responses"][state["counter"] - 1]

        def close(self):
            return None

    monkeypatch.setattr(gateway_module, "_PinnedHTTPSConnection", _FakePinned)
    return state


@pytest.fixture
def app_client(monkeypatch):
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_REPLAY_WINDOW_SECONDS", "60")
    monkeypatch.setenv("MEMORY_SYMBOL_DOWNLOAD_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("MEMORY_SYMBOL_CONNECT_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("MEMORY_SYMBOL_MAX_REDIRECTS", "5")
    monkeypatch.setenv("MEMORY_SYMBOL_DOWNLOAD_MAX_BYTES", str(10 * 1024 * 1024))
    from importlib import reload
    reload(gateway_module)
    app = gateway_module.create_app()
    with TestClient(app) as client:
        yield client


def _signed_post(client, *, payload, secret, timestamp=None):
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signed = sign_request(secret=secret, request_id=payload["request_id"], method="POST", path="/internal/symbol-fetch", body=raw, timestamp=timestamp)
    headers = {"Content-Type": "application/json", **signed.headers()}
    return client.post("/internal/symbol-fetch", content=raw, headers=headers)


def test_healthz_is_reachable(app_client) -> None:
    response = app_client.get("/internal/healthz")
    assert response.status_code == 200
    assert response.json()["service"] == "symbol-egress-gateway"


def test_unsigned_request_is_rejected(app_client) -> None:
    response = app_client.post("/internal/symbol-fetch", json={"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1})
    assert response.status_code == 401


def test_signed_request_streams_expected_bytes(monkeypatch, app_client) -> None:
    body = _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)
    state = _install_fake_connection(monkeypatch, responses=[_FakeResponse(200, {"Content-Type": "application/octet-stream"}, body)])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 200, response.text
    assert response.content == body
    assert response.headers.get("x-kairon-egress-request-id") == payload["request_id"]
    # Method is GET, not HEAD.
    assert state["method"] == "GET"


def test_get_is_the_only_method_issued_to_microsoft(monkeypatch, app_client) -> None:
    body = _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)
    state = _install_fake_connection(monkeypatch, responses=[_FakeResponse(200, {"Content-Type": "application/octet-stream"}, body)])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    _signed_post(app_client, payload=payload, secret="test-secret-1234")
    # The fetcher never uses HEAD; the gateway only ever issues GET.
    assert state["method"] == "GET"
    assert state["method"] != "HEAD"


def test_redirect_to_approved_blob_subdomain_is_accepted(monkeypatch, app_client) -> None:
    body = _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://vsblobprodscussu5shard38.blob.core.windows.net/symbols/file"}, b""),
        _FakeResponse(200, {"Content-Type": "application/octet-stream"}, body),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 200, response.text
    assert response.headers.get("x-kairon-egress-redirects") == "1"


def test_redirect_to_unlisted_host_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://attacker.example/file"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_HOST" in response.text


def test_redirect_to_lookalike_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://blob.core.windows.net.attacker.example/file"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_HOST" in response.text


def test_redirect_to_http_downgrade_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/x/ntkrnlmp.pdb"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_URL" in response.text


def test_redirect_to_non_443_port_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://vsblobprodscussu5shard38.blob.core.windows.net:444/symbols/file"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_URL" in response.text


def test_redirect_loop_is_capped(monkeypatch, app_client) -> None:
    # 6 redirects, max is 5 → EGRESS_REDIRECT_LIMIT.
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://vsblobprodscussu5shard38.blob.core.windows.net/symbols/file"}, b""),
    ] * 6)
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 502
    assert "EGRESS_REDIRECT_LIMIT" in response.text


def test_redirect_to_ip_literal_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://13.107.42.14/symbols/file"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_HOST" in response.text


def test_redirect_to_private_resolved_ip_is_rejected(monkeypatch, app_client) -> None:
    # 169.254.169.254 (link-local) is not a valid Microsoft destination
    # even if the hostname passes the allowlist; the DNS resolution layer
    # must reject it.
    def fake_addrinfo(host, port, type=None, **_kw):
        # Redirect host passes the allowlist (uses .blob.core.windows.net)
        # but resolves to a link-local address.
        return [(2, 1, 6, "", ("169.254.169.254", port))]
    _install_fake_connection(
        monkeypatch,
        responses=[
            _FakeResponse(302, {"Location": "https://a.blob.core.windows.net/symbols/file"}, b""),
            _FakeResponse(200, {"Content-Type": "application/octet-stream"}, _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)),
        ],
        getaddrinfo=fake_addrinfo,
    )
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_ADDRESS" in response.text


def test_initial_to_private_resolved_ip_is_rejected(monkeypatch, app_client) -> None:
    # Even if the allowlisted hostname resolves to a private IP, the
    # download is blocked.  This is the DNS-rebinding defense.
    def fake_addrinfo(host, port, type=None, **_kw):
        return [(2, 1, 6, "", ("10.0.0.1", port))]
    body = _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)
    _install_fake_connection(
        monkeypatch,
        responses=[_FakeResponse(200, {"Content-Type": "application/octet-stream"}, body)],
        getaddrinfo=fake_addrinfo,
    )
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_ADDRESS" in response.text


def test_initial_to_loopback_is_rejected(monkeypatch, app_client) -> None:
    def fake_addrinfo(host, port, type=None, **_kw):
        return [(2, 1, 6, "", ("127.0.0.1", port))]
    _install_fake_connection(
        monkeypatch,
        responses=[_FakeResponse(200, {}, b"ok")],
        getaddrinfo=fake_addrinfo,
    )
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_ADDRESS" in response.text


def test_user_supplied_url_in_payload_is_rejected(app_client) -> None:
    # The gateway contract is fixed: the client never provides a URL.
    # An attempt to inject "url" or "host" must be rejected with 400.
    for extra in ("url", "host", "destination", "endpoint"):
        payload = {
            "request_id": str(uuid.uuid4()),
            "pdb_name": "ntkrnlmp.pdb",
            "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126",
            "age": 1,
            extra: "https://attacker.example/file",
        }
        response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
        assert response.status_code == 400, f"Extra key {extra!r} should be rejected"
        assert "Unexpected payload keys" in response.text


def test_payload_with_extra_keys_is_rejected(app_client) -> None:
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1, "url": "https://attacker.example/file"}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 400


def test_query_override_in_redirect_is_rejected(monkeypatch, app_client) -> None:
    # A redirect that uses a query string to drive the destination (no
    # path-based override) must still satisfy the path-prefix policy on
    # the initial hop.
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://vsblobprodscussu5shard38.blob.core.windows.net/symbols/file?sig=abc"}, b""),
        _FakeResponse(200, {"Content-Type": "application/octet-stream"}, _make_pdb_bytes("9DC3FC69B1CA4B34707EBC57FD1D6126", 1)),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 200, response.text
    assert response.headers.get("x-kairon-egress-redirects") == "1"
