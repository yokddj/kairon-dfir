"""HMAC-signed requests for symbol-fetcher -> symbol-egress-gateway.

The gateway is the only outbound path of the symbol subsystem.  All requests
from the fetcher to the gateway MUST carry:

* request_id (UUID4 hex)
* timestamp (unix seconds, integer)
* nonce (>=16 random bytes, hex)
* signature (HMAC-SHA256 over canonical string)

The canonical string is:

    v1\n{request_id}\n{timestamp}\n{nonce}\n{method}\n{path}\n{sha256(body)}

The shared secret is server-generated, stored only in environment
configuration, and rotated via the deploy script.  It is NEVER committed,
exposed via API, or returned to frontend users.

Replay protection:

* timestamp must be within +/- replay_window_seconds of server clock
* nonces seen in the last 2 * replay_window_seconds are rejected
* nonces are kept in process memory only (not persisted)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass


CANONICAL_VERSION = "v1"
NONCE_BYTES = 24
MAX_NONCE_STORE = 4096


class EgressAuthError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SignedRequest:
    request_id: str
    timestamp: int
    nonce: str
    signature: str

    def headers(self) -> dict[str, str]:
        return {
            "X-Kairon-Egress-Version": CANONICAL_VERSION,
            "X-Kairon-Egress-Request-Id": self.request_id,
            "X-Kairon-Egress-Timestamp": str(self.timestamp),
            "X-Kairon-Egress-Nonce": self.nonce,
            "X-Kairon-Egress-Signature": self.signature,
        }


def generate_secret() -> str:
    return secrets.token_hex(32)


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def _canonical_string(version: str, request_id: str, timestamp: int, nonce: str, method: str, path: str, body: bytes) -> str:
    body_digest = hashlib.sha256(body).hexdigest()
    return "\n".join([version, request_id, str(int(timestamp)), nonce, method.upper(), path, body_digest])


def sign_request(*, secret: str, request_id: str, method: str, path: str, body: bytes, timestamp: int | None = None, nonce: str | None = None) -> SignedRequest:
    if not secret:
        raise EgressAuthError("EGRESS_AUTH_NOT_CONFIGURED", "Egress gateway shared secret is not configured.")
    if not request_id or len(request_id) > 128:
        raise EgressAuthError("EGRESS_AUTH_BAD_REQUEST_ID", "Signed request id is invalid.")
    ts = int(time.time()) if timestamp is None else int(timestamp)
    nc = new_nonce() if nonce is None else nonce
    canonical = _canonical_string(CANONICAL_VERSION, request_id, ts, nc, method, path, body)
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return SignedRequest(request_id=request_id, timestamp=ts, nonce=nc, signature=signature)


class NonceStore:
    """In-memory bounded nonce cache with TTL eviction.

    Not persisted on purpose.  Restart of the gateway invalidates nonces, which
    is the correct behavior because signing keys may have rotated as well.
    """

    def __init__(self, ttl_seconds: int = 120, max_entries: int = MAX_NONCE_STORE):
        self._ttl = max(1, int(ttl_seconds))
        self._max = max(64, int(max_entries))
        self._entries: "OrderedDict[tuple[str, int], None]" = OrderedDict()

    def _evict_expired(self, now: int) -> None:
        cutoff = now - self._ttl
        while self._entries:
            oldest = next(iter(self._entries))
            if oldest[1] < cutoff:
                self._entries.popitem(last=False)
            else:
                break

    def check_and_store(self, nonce: str, timestamp: int, now: int | None = None) -> None:
        if not nonce or len(nonce) < 16 or len(nonce) > 256:
            raise EgressAuthError("EGRESS_AUTH_BAD_NONCE", "Signed request nonce is invalid.")
        if not (0 < int(timestamp) < 2**63):
            raise EgressAuthError("EGRESS_AUTH_BAD_TIMESTAMP", "Signed request timestamp is invalid.")
        current = int(time.time()) if now is None else int(now)
        self._evict_expired(current)
        key = (nonce, int(timestamp))
        if key in self._entries:
            raise EgressAuthError("EGRESS_AUTH_REPLAY", "Signed request nonce has already been used.")
        self._entries[key] = None
        if len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


def verify_signed_headers(
    *,
    secret: str,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    nonce_store: NonceStore,
    replay_window_seconds: int,
    now: int | None = None,
) -> str:
    """Verify a signed request.  Returns the request_id on success.

    Raises EgressAuthError on any failure.
    """
    if not secret:
        raise EgressAuthError("EGRESS_AUTH_NOT_CONFIGURED", "Egress gateway shared secret is not configured.")
    lower = {str(k).lower(): v for k, v in headers.items()}
    version = lower.get("x-kairon-egress-version", "")
    if version != CANONICAL_VERSION:
        raise EgressAuthError("EGRESS_AUTH_BAD_VERSION", "Signed request protocol version is not supported.")
    request_id = str(lower.get("x-kairon-egress-request-id", "")).strip()
    timestamp_raw = str(lower.get("x-kairon-egress-timestamp", "")).strip()
    nonce = str(lower.get("x-kairon-egress-nonce", "")).strip()
    signature = str(lower.get("x-kairon-egress-signature", "")).strip().lower()
    if not request_id or len(request_id) > 128:
        raise EgressAuthError("EGRESS_AUTH_BAD_REQUEST_ID", "Signed request id is invalid.")
    try:
        timestamp = int(timestamp_raw)
    except ValueError as exc:
        raise EgressAuthError("EGRESS_AUTH_BAD_TIMESTAMP", "Signed request timestamp is invalid.") from exc
    if not nonce:
        raise EgressAuthError("EGRESS_AUTH_BAD_NONCE", "Signed request nonce is missing.")
    if not signature or len(signature) != 64 or any(c not in "0123456789abcdef" for c in signature):
        raise EgressAuthError("EGRESS_AUTH_BAD_SIGNATURE", "Signed request signature is malformed.")
    current = int(time.time()) if now is None else int(now)
    if abs(current - timestamp) > int(replay_window_seconds):
        raise EgressAuthError("EGRESS_AUTH_EXPIRED", "Signed request is outside the replay window.")
    canonical = _canonical_string(version, request_id, timestamp, nonce, method, path, body)
    expected = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise EgressAuthError("EGRESS_AUTH_BAD_SIGNATURE", "Signed request signature does not match.")
    nonce_store.check_and_store(nonce, timestamp, now=current)
    return request_id


def require_secret(secret: str | None) -> str:
    if not secret:
        raise EgressAuthError("EGRESS_AUTH_NOT_CONFIGURED", "Egress gateway shared secret is not configured.")
    return secret
