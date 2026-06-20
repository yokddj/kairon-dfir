"""Tests for the symbol-egress-client (fetcher -> gateway)."""
from __future__ import annotations

import json
import os
import socket
from typing import Any

import pytest

from app.services.memory.symbol_egress_client import SymbolFetchError, fetch_pdb_via_egress
from app.services.memory.symbol_egress_auth import sign_request


class _FakeHandler:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.received: dict[str, Any] = {}

    def __call__(self, request):  # noqa: D401
        from urllib.error import HTTPError

        self.received["url"] = request.full_url
        self.received["method"] = request.get_method()
        self.received["headers"] = dict(request.headers)
        self.received["body"] = request.data
        if self.status >= 400:
            raise HTTPError(request.full_url, self.status, "error", self.headers, None)
        return _FakeResponse(self)


class _FakeResponse:
    def __init__(self, handler: _FakeHandler):
        self._handler = handler
        self._body = handler.body
        self._offset = 0
        self.headers = handler.headers

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            data = self._body[self._offset:]
            self._offset = len(self._body)
            return data
        data = self._body[self._offset:self._offset + n]
        self._offset += len(data)
        return data

    def close(self) -> None:
        return None


def test_fetch_succeeds_when_gateway_responds_200(monkeypatch, tmp_path) -> None:
    body = b"PDBDATA"
    import hashlib
    expected_sha = hashlib.sha256(body).hexdigest()
    handler = _FakeHandler(200, body, {
        "X-Kairon-Egress-Sha256": expected_sha,
        "X-Kairon-Egress-Redirects": "0",
        "Content-Type": "application/octet-stream",
    })

    def fake_urlopen(request, timeout=None):
        return handler(request)

    monkeypatch.setattr("app.services.memory.symbol_egress_client.urlopen", fake_urlopen)
    partial = tmp_path / "x.pdb.partial"
    result = fetch_pdb_via_egress(
        gateway_url="http://gateway:8443",
        secret="topsecret",
        pdb_name="ntkrnlmp.pdb",
        guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
        age=1,
        timeout_seconds=30,
        max_response_bytes=10_000_000,
        partial_path=partial,
    )
    assert result.bytes_received == len(body)
    assert result.sha256 == expected_sha
    assert partial.read_bytes() == body
    # Request must have been signed.
    headers = {k.lower(): v for k, v in handler.received["headers"].items()}
    assert "x-kairon-egress-signature" in headers
    assert len(headers["x-kairon-egress-signature"]) == 64
    body_payload = json.loads(handler.received["body"].decode("utf-8"))
    assert body_payload["pdb_name"] == "ntkrnlmp.pdb"
    assert body_payload["guid"] == "9DC3FC69B1CA4B34707EBC57FD1D6126"
    assert body_payload["age"] == 1


def test_fetch_rejects_when_gateway_returns_hash_mismatch(monkeypatch, tmp_path) -> None:
    body = b"PDBDATA"
    handler = _FakeHandler(200, body, {
        "X-Kairon-Egress-Sha256": "0" * 64,
    })

    def fake_urlopen(request, timeout=None):
        return handler(request)

    monkeypatch.setattr("app.services.memory.symbol_egress_client.urlopen", fake_urlopen)
    partial = tmp_path / "x.pdb.partial"
    with pytest.raises(SymbolFetchError) as exc:
        fetch_pdb_via_egress(
            gateway_url="http://gateway:8443",
            secret="topsecret",
            pdb_name="ntkrnlmp.pdb",
            guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
            age=1,
            timeout_seconds=30,
            max_response_bytes=10_000_000,
            partial_path=partial,
        )
    assert exc.value.code == "SYMBOL_EGRESS_HASH_MISMATCH"
    assert not partial.exists()


def test_fetch_translates_403_from_gateway(monkeypatch, tmp_path) -> None:
    from urllib.error import HTTPError

    def fake_urlopen(request, timeout=None):
        raise HTTPError(request.full_url, 403, "forbidden", {}, None)

    monkeypatch.setattr("app.services.memory.symbol_egress_client.urlopen", fake_urlopen)
    partial = tmp_path / "x.pdb.partial"
    with pytest.raises(SymbolFetchError):
        fetch_pdb_via_egress(
            gateway_url="http://gateway:8443",
            secret="topsecret",
            pdb_name="ntkrnlmp.pdb",
            guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
            age=1,
            timeout_seconds=30,
            max_response_bytes=10_000_000,
            partial_path=partial,
        )


def test_fetch_translates_unreachable_gateway(monkeypatch, tmp_path) -> None:
    from urllib.error import URLError

    def fake_urlopen(request, timeout=None):
        raise URLError("no route")

    monkeypatch.setattr("app.services.memory.symbol_egress_client.urlopen", fake_urlopen)
    partial = tmp_path / "x.pdb.partial"
    with pytest.raises(SymbolFetchError) as exc:
        fetch_pdb_via_egress(
            gateway_url="http://gateway:8443",
            secret="topsecret",
            pdb_name="ntkrnlmp.pdb",
            guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
            age=1,
            timeout_seconds=30,
            max_response_bytes=10_000_000,
            partial_path=partial,
        )
    assert exc.value.code == "SYMBOL_EGRESS_UNREACHABLE"
