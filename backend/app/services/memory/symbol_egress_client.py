"""Symbol egress client used by the symbol-fetcher.

The fetcher NEVER makes outbound HTTPS connections.  All acquisition goes
through the symbol-egress-gateway.  The client signs each request with a
server-controlled shared secret and the gateway validates the destination
policy itself.

Errors are translated to SymbolFetchError codes so the calling worker can
handle them uniformly.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest, urlopen

from app.services.memory.symbol_egress_auth import (
    EgressAuthError,
    SignedRequest,
    sign_request,
)


logger = logging.getLogger(__name__)


class SymbolFetchError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass(frozen=True)
class EgressDownloadResult:
    bytes_received: int
    sha256: str
    redirect_count: int
    content_type: str | None
    duration_ms: int


def _build_payload(*, request_id: str, pdb_name: str, guid: str, age: int) -> dict[str, Any]:
    return {
        "request_id": str(request_id),
        "pdb_name": pdb_name,
        "guid": guid,
        "age": int(age),
    }


def request_egress_download(
    *,
    gateway_url: str,
    secret: str,
    request_id: str,
    pdb_name: str,
    guid: str,
    age: int,
    timeout_seconds: int,
    max_response_bytes: int,
) -> EgressDownloadResult:
    """Call the symbol-egress-gateway and stream the response into a partial file.

    Returns the size, sha256, redirect count, and content type.  Raises
    SymbolFetchError on any failure.
    """
    body = json.dumps(_build_payload(request_id=request_id, pdb_name=pdb_name, guid=guid, age=age), separators=(",", ":")).encode("utf-8")
    try:
        signed: SignedRequest = sign_request(secret=secret, request_id=request_id, method="POST", path="/internal/symbol-fetch", body=body)
    except EgressAuthError as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_AUTH_FAILED", exc.message) from exc

    url = gateway_url.rstrip("/") + "/internal/symbol-fetch"
    headers = {"Content-Type": "application/json"}
    headers.update(signed.headers())
    request = URLRequest(url=url, data=body, headers=headers, method="POST")
    started = time.monotonic()
    try:
        response = urlopen(request, timeout=max(1, int(timeout_seconds)))
    except HTTPError as exc:
        # The gateway returns structured errors as JSON.  Read a bounded
        # amount of the body so we never pull the full error blob into
        # memory.
        detail = exc.read(4096)
        try:
            decoded = json.loads(detail.decode("utf-8"))
        except Exception:
            decoded = None
        if isinstance(decoded, dict) and isinstance(decoded.get("detail"), dict):
            code = decoded["detail"].get("code") or "SYMBOL_EGRESS_REJECTED"
            message = decoded["detail"].get("message") or "The egress gateway rejected the request."
        elif isinstance(decoded, dict) and isinstance(decoded.get("detail"), str):
            code = "SYMBOL_EGRESS_REJECTED"
            message = decoded["detail"]
        else:
            code = "SYMBOL_EGRESS_HTTP_ERROR"
            message = f"The egress gateway returned HTTP {exc.code}."
        retryable = exc.code in {408, 425, 429, 500, 502, 503, 504}
        raise SymbolFetchError(code, message, retryable=retryable) from exc
    except URLError as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_UNREACHABLE", "The egress gateway is not reachable.", retryable=True) from exc
    except (TimeoutError, OSError) as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_TIMEOUT", "The egress gateway request timed out.", retryable=True) from exc

    final_sha = response.headers.get("X-Kairon-Egress-Sha256", "")
    redirects = int(response.headers.get("X-Kairon-Egress-Redirects", "0") or "0")
    content_type = response.headers.get("Content-Type")
    # The gateway does not pre-compute the SHA-256; the fetcher re-hashes
    # the streamed bytes.  The header is reserved for future use.
    if final_sha and final_sha != "client-computed":
        pass
    return _stream_to_temporary(
        response=response,
        max_response_bytes=max_response_bytes,
        started=started,
        declared_sha256="",
        redirect_count=redirects,
        content_type=content_type,
    )


def _stream_to_temporary(*, response, max_response_bytes: int, started: float, declared_sha256: str, redirect_count: int, content_type: str | None) -> EgressDownloadResult:
    import hashlib
    import os
    from io import BytesIO

    # We do not write to the caller's partial file here: that is the
    # responsibility of the worker.  We stream into memory in bounded
    # chunks and re-emit.  For a 1 GiB cap this would be unsafe; the
    # gateway's max_bytes and the client's max_response_bytes MUST be
    # tuned together.
    digest = hashlib.sha256()
    received = 0
    # Defensive cap based on max_response_bytes.
    cap = max(1024, int(max_response_bytes))
    if cap <= 0 or cap > 2 * 1024 * 1024 * 1024:
        # Hard ceiling to keep this client safe even if config is wrong.
        cap = 2 * 1024 * 1024 * 1024
    try:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            received += len(chunk)
            if received > cap:
                raise SymbolFetchError("SYMBOL_DOWNLOAD_TOO_LARGE", "Egress gateway response exceeded the configured limit.")
            digest.update(chunk)
    except (TimeoutError, OSError) as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_TIMEOUT", "Egress gateway response stream was interrupted.", retryable=True) from exc
    finally:
        try:
            response.close()
        except Exception:
            pass

    computed = digest.hexdigest()
    if declared_sha256 and declared_sha256.lower() != computed.lower():
        raise SymbolFetchError("SYMBOL_EGRESS_HASH_MISMATCH", "Egress gateway declared hash does not match the streamed bytes.")
    duration_ms = int((time.monotonic() - started) * 1000)
    return EgressDownloadResult(
        bytes_received=received,
        sha256=computed,
        redirect_count=redirect_count,
        content_type=content_type,
        duration_ms=duration_ms,
    )


def fetch_pdb_via_egress(
    *,
    gateway_url: str,
    secret: str,
    pdb_name: str,
    guid: str,
    age: int,
    timeout_seconds: int,
    max_response_bytes: int,
    partial_path: Path,
) -> EgressDownloadResult:
    """Stream the symbol from the gateway directly to a controlled partial file.

    This is the path used by the worker.  It avoids holding the full PDB
    in memory.
    """
    import hashlib
    import os

    body = json.dumps(_build_payload(request_id=str(uuid.uuid4()), pdb_name=pdb_name, guid=guid, age=age), separators=(",", ":")).encode("utf-8")
    request_id = str(uuid.uuid4())
    # Rebuild the payload using the request_id we will actually sign with.
    body = json.dumps(_build_payload(request_id=request_id, pdb_name=pdb_name, guid=guid, age=age), separators=(",", ":")).encode("utf-8")
    try:
        signed = sign_request(secret=secret, request_id=request_id, method="POST", path="/internal/symbol-fetch", body=body)
    except EgressAuthError as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_AUTH_FAILED", exc.message) from exc

    url = gateway_url.rstrip("/") + "/internal/symbol-fetch"
    headers = {"Content-Type": "application/json"}
    headers.update(signed.headers())
    req = URLRequest(url=url, data=body, headers=headers, method="POST")
    started = time.monotonic()
    try:
        response = urlopen(req, timeout=max(1, int(timeout_seconds)))
    except HTTPError as exc:
        detail = exc.read(4096)
        try:
            decoded = json.loads(detail.decode("utf-8"))
        except Exception:
            decoded = None
        if isinstance(decoded, dict) and isinstance(decoded.get("detail"), dict):
            code = decoded["detail"].get("code") or "SYMBOL_EGRESS_REJECTED"
            message = decoded["detail"].get("message") or "The egress gateway rejected the request."
        elif isinstance(decoded, dict) and isinstance(decoded.get("detail"), str):
            code = "SYMBOL_EGRESS_REJECTED"
            message = decoded["detail"]
        else:
            code = "SYMBOL_EGRESS_HTTP_ERROR"
            message = f"The egress gateway returned HTTP {exc.code}."
        retryable = exc.code in {408, 425, 429, 500, 502, 503, 504}
        raise SymbolFetchError(code, message, retryable=retryable) from exc
    except URLError as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_UNREACHABLE", "The egress gateway is not reachable.", retryable=True) from exc
    except (TimeoutError, OSError) as exc:
        raise SymbolFetchError("SYMBOL_EGRESS_TIMEOUT", "The egress gateway request timed out.", retryable=True) from exc

    digest = hashlib.sha256()
    received = 0
    cap = max(1024, int(max_response_bytes))
    if cap <= 0 or cap > 2 * 1024 * 1024 * 1024:
        cap = 2 * 1024 * 1024 * 1024
    partial_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if partial_path.exists() or partial_path.is_symlink():
        raise SymbolFetchError("SYMBOL_CACHE_WRITE_FAILED", "A symbol partial already exists.")
    descriptor = os.open(partial_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
    try:
        with os.fdopen(descriptor, "wb") as output:
            while True:
                if time.monotonic() - started > timeout_seconds:
                    raise SymbolFetchError("SYMBOL_EGRESS_TIMEOUT", "Egress gateway response stream was interrupted.", retryable=True)
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > cap:
                    raise SymbolFetchError("SYMBOL_DOWNLOAD_TOO_LARGE", "Egress gateway response exceeded the configured limit.")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        partial_path.unlink(missing_ok=True)
        raise
    finally:
        try:
            response.close()
        except Exception:
            pass

    declared = response.headers.get("X-Kairon-Egress-Sha256", "") if hasattr(response, "headers") else ""
    # The gateway does not pre-compute the SHA-256; the fetcher always
    # re-hashes the streamed bytes.
    computed = digest.hexdigest()
    if declared and declared not in ("", "client-computed") and declared.lower() != computed.lower():
        partial_path.unlink(missing_ok=True)
        raise SymbolFetchError("SYMBOL_EGRESS_HASH_MISMATCH", "Egress gateway declared hash does not match the streamed bytes.")
    redirects = 0
    try:
        redirects = int(response.headers.get("X-Kairon-Egress-Redirects", "0") or "0")
    except Exception:
        redirects = 0
    content_type = response.headers.get("Content-Type") if hasattr(response, "headers") else None
    duration_ms = int((time.monotonic() - started) * 1000)
    return EgressDownloadResult(
        bytes_received=received,
        sha256=computed,
        redirect_count=redirects,
        content_type=content_type,
        duration_ms=duration_ms,
    )
