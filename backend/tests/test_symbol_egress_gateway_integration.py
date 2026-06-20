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


def _install_fake_connection(monkeypatch, *, responses: list[_FakeResponse]) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type=None, **_kw: [(2, 1, 6, "", ("8.8.8.8", port))])
    state = {"counter": 0, "responses": list(responses)}

    class _FakePinned(gateway_module._PinnedHTTPSConnection):
        def __init__(self, host, address, *, timeout):
            self.host = host
            self.port = 443
            self.timeout = timeout
            self.sock = None

        def request(self, method, target, headers=None):
            state["counter"] += 1

        def getresponse(self):
            return state["responses"][state["counter"] - 1]

        def close(self):
            return None

    monkeypatch.setattr(gateway_module, "_PinnedHTTPSConnection", _FakePinned)


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
    _install_fake_connection(monkeypatch, responses=[_FakeResponse(200, {"Content-Type": "application/octet-stream"}, body)])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 200, response.text
    assert response.content == body
    assert response.headers.get("x-kairon-egress-request-id") == payload["request_id"]


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


def test_redirect_to_lookalike_is_rejected(monkeypatch, app_client) -> None:
    _install_fake_connection(monkeypatch, responses=[
        _FakeResponse(302, {"Location": "https://blob.core.windows.net.attacker.example/file"}, b""),
    ])
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 403
    assert "EGRESS_DENIED_HOST" in response.text


def test_payload_with_extra_keys_is_rejected(app_client) -> None:
    payload = {"request_id": str(uuid.uuid4()), "pdb_name": "ntkrnlmp.pdb", "guid": "9DC3FC69B1CA4B34707EBC57FD1D6126", "age": 1, "url": "https://attacker.example/file"}
    response = _signed_post(app_client, payload=payload, secret="test-secret-1234")
    assert response.status_code == 400
