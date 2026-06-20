"""Unit tests for the symbol egress auth module (HMAC + nonce store)."""
from __future__ import annotations

import time

import pytest

from app.services.memory.symbol_egress_auth import (
    EgressAuthError,
    NonceStore,
    generate_secret,
    sign_request,
    verify_signed_headers,
)


def test_sign_then_verify_round_trip() -> None:
    secret = generate_secret()
    body = b'{"pdb_name":"ntkrnlmp.pdb","guid":"A"*32,"age":1}'
    signed = sign_request(secret=secret, request_id="req-1", method="POST", path="/internal/symbol-fetch", body=body, timestamp=1_700_000_000)
    headers = signed.headers()
    store = NonceStore(ttl_seconds=120)
    returned = verify_signed_headers(
        secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
        headers=headers, nonce_store=store, replay_window_seconds=60, now=1_700_000_000,
    )
    assert returned == "req-1"
    assert len(store) == 1


def test_replay_within_window_is_rejected() -> None:
    secret = generate_secret()
    body = b"{}"
    signed = sign_request(secret=secret, request_id="req-1", method="POST", path="/internal/symbol-fetch", body=body, timestamp=1_700_000_000)
    store = NonceStore(ttl_seconds=120)
    verify_signed_headers(
        secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
        headers=signed.headers(), nonce_store=store, replay_window_seconds=60, now=1_700_000_000,
    )
    with pytest.raises(EgressAuthError) as exc:
        verify_signed_headers(
            secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
            headers=signed.headers(), nonce_store=store, replay_window_seconds=60, now=1_700_000_000,
        )
    assert exc.value.code == "EGRESS_AUTH_REPLAY"


def test_expired_timestamp_rejected() -> None:
    secret = generate_secret()
    body = b"{}"
    signed = sign_request(secret=secret, request_id="req-2", method="POST", path="/internal/symbol-fetch", body=body, timestamp=1_700_000_000)
    store = NonceStore(ttl_seconds=120)
    with pytest.raises(EgressAuthError) as exc:
        verify_signed_headers(
            secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
            headers=signed.headers(), nonce_store=store, replay_window_seconds=60, now=1_700_001_000,
        )
    assert exc.value.code == "EGRESS_AUTH_EXPIRED"


def test_bad_signature_rejected() -> None:
    secret = generate_secret()
    body = b"{}"
    signed = sign_request(secret=secret, request_id="req-3", method="POST", path="/internal/symbol-fetch", body=body, timestamp=1_700_000_000)
    headers = signed.headers()
    headers["X-Kairon-Egress-Signature"] = "0" * 64
    store = NonceStore(ttl_seconds=120)
    with pytest.raises(EgressAuthError) as exc:
        verify_signed_headers(
            secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
            headers=headers, nonce_store=store, replay_window_seconds=60, now=1_700_000_000,
        )
    assert exc.value.code == "EGRESS_AUTH_BAD_SIGNATURE"


def test_missing_version_rejected() -> None:
    secret = generate_secret()
    body = b"{}"
    signed = sign_request(secret=secret, request_id="req-4", method="POST", path="/internal/symbol-fetch", body=body, timestamp=1_700_000_000)
    headers = signed.headers()
    headers.pop("X-Kairon-Egress-Version")
    store = NonceStore(ttl_seconds=120)
    with pytest.raises(EgressAuthError) as exc:
        verify_signed_headers(
            secret=secret, method="POST", path="/internal/symbol-fetch", body=body,
            headers=headers, nonce_store=store, replay_window_seconds=60, now=1_700_000_000,
        )
    assert exc.value.code == "EGRESS_AUTH_BAD_VERSION"


def test_secret_required() -> None:
    with pytest.raises(EgressAuthError) as exc:
        sign_request(secret="", request_id="req-5", method="POST", path="/internal/symbol-fetch", body=b"{}")
    assert exc.value.code == "EGRESS_AUTH_NOT_CONFIGURED"


def test_nonce_store_ttl_eviction() -> None:
    store = NonceStore(ttl_seconds=10)
    base = 1_700_000_000
    for i in range(5):
        store.check_and_store(f"nonce-padding-{i:04d}", timestamp=base + i, now=base + i)
    assert len(store) == 5
    # Advance the clock by 100 seconds; the TTL is 10s, so all old nonces
    # must be evicted on the next insert.
    store.check_and_store("nonce-padding-new", timestamp=base + 100, now=base + 100)
    assert len(store) == 1
    # The new nonce is still in the store.
    assert ("nonce-padding-new", base + 100) in store._entries
