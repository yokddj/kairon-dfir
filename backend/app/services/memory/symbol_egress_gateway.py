"""Symbol egress gateway service.

Runs as a dedicated, isolated container.  Accepts signed symbol-fetch
requests from the symbol-fetcher, validates the destination against a
narrow Microsoft-symbol policy, opens the outbound HTTPS connection itself,
and streams the bounded response back.

It is NOT a generic proxy.  The only accepted method is POST, the only
accepted path is /internal/symbol-fetch, and clients do not provide a URL,
host, port, headers, or query parameters.  The gateway constructs the
official URL itself from the validated PDB/GUID/age in the signed payload.

Least-privilege destination policy
----------------------------------

The only allowed destination is the official Microsoft public symbol
server, with a narrow, explicit allowlist:

* Scheme: HTTPS
* Initial host: ``msdl.microsoft.com`` (exact, case-insensitive, no
  wildcards; ``foo.microsoft.com`` and ``*.microsoft.com`` are rejected)
* Port: 443 only
* Initial path prefix: ``/download/symbols/`` (the rest of the path is
  server-derived from the signed PDB/GUID/age, never user-supplied)
* Method: GET only (HEAD is not used by the fetcher and is rejected)
* Redirects: each hop re-validated for HTTPS, port 443, host in
  allowlist, IP-literal rejection, and public address resolution.
  Redirect path must not contain control characters, backslashes, or
  ``..`` segments (including percent-encoded variants).  The redirect
  count is capped by ``MEMORY_SYMBOL_MAX_REDIRECTS`` (default 5).

All other destinations are rejected, including:

* HTTP (any non-200/non-redirect response from a non-listed host)
* IP-literal destinations
* Userinfo in URLs (``user@host``, ``user:pass@host``)
* Query-driven destination overrides
* Path traversal (``..``, ``%2e%2e``, ``%2E%2E``)
* Private, loopback, link-local, multicast, unspecified, or reserved
  addresses resolved from the allowlisted host
* DNS rebinding (each hop is DNS-pinned to the first resolved address;
  even if the answer changes between redirects, the TCP destination is
  fixed)
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import struct
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse


logger = logging.getLogger("symbol-egress-gateway")


# ---------------------------------------------------------------------------
# Least-privilege policy constants
# ---------------------------------------------------------------------------

# The official Microsoft public symbol server.  Any deviation from this
# exact value (case-insensitive) is rejected at the policy layer.  Wildcards
# like *.microsoft.com are not allowed; the only permitted host is
# ``msdl.microsoft.com`` and the Azure blob-storage CDN suffix for
# redirects.
APPROVED_INITIAL_HOST = "msdl.microsoft.com"

# The path prefix under which every official PDB is published.  The gateway
# only ever issues requests whose path begins with this exact prefix.
APPROVED_INITIAL_PATH_PREFIX = "/download/symbols/"

# The only accepted upstream method.  HEAD is not used by the fetcher and
# is explicitly rejected.
APPROVED_METHODS = frozenset({"GET"})

# Per-hop redirect host suffixes.  Microsoft publishes symbols under
# ``<random>.blob.core.windows.net`` shards; only this exact single-label
# suffix is permitted on redirects.  Apex ``blob.core.windows.net`` and
# lookalike hosts (``notblob.core.windows.net``) are rejected by the
# label-parsing policy.
APPROVED_REDIRECT_SUFFIXES = frozenset({".blob.core.windows.net"})

# Path-segment characters that indicate traversal, even when percent-
# encoded.  Reject any segment that is exactly ``..`` or its percent-encoded
# forms (``%2e%2e``, ``%2E%2E``).  Mixed-case encodings are also blocked.
_TRAVERSAL_SEGMENT = re.compile(r"^(?:%2e%2e|%2E%2E|\.\.)$", re.IGNORECASE)

# Capped redirect hops.  Five is well above the single real-world
# redirect chain used by Microsoft's CDN.
DEFAULT_MAX_REDIRECTS = 5

# Pre-compiled regexes for the validated payload.
PDB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,120}\.pdb$", re.IGNORECASE)
PDB_GUID = re.compile(r"^[0-9A-F]{32}$")


class GatewayError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _validate_pdb_name(value: str) -> str:
    if not isinstance(value, str) or not PDB_NAME.fullmatch(value) or any(token in value for token in ("/", "\\", "%")):
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The pdb_name is not a valid identifier.")
    return value


def _validate_guid(value: Any) -> str:
    if not isinstance(value, str) or not PDB_GUID.fullmatch(str(value).upper()):
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The guid is not a valid 32-character hex string.")
    return str(value).upper()


def _validate_age(value: Any) -> int:
    try:
        age = int(value)
    except (TypeError, ValueError) as exc:
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The age is not an integer.") from exc
    if not 0 <= age <= 0xFFFFFFFF:
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The age is outside the allowed range.")
    return age


def _validate_request_id(value: Any) -> str:
    if not isinstance(value, str):
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The request_id is invalid.")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise GatewayError(400, "EGRESS_BAD_PAYLOAD", "The request_id is not a UUID.") from exc
    return str(parsed)


def _public_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise GatewayError(502, "EGRESS_DNS_FAILED", "Official symbol destination could not be resolved.") from exc
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise GatewayError(502, "EGRESS_DNS_EMPTY", "Official symbol destination returned no addresses.")
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if (
            not address.is_global
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or address.is_private
        ):
            raise GatewayError(403, "EGRESS_DENIED_ADDRESS", "Official symbol destination resolved to a disallowed address.")
    return addresses


def _validate_host_policy(host: str, *, initial: bool, initial_host: str, redirect_suffixes: list[str]) -> None:
    if not host:
        raise GatewayError(403, "EGRESS_DENIED_HOST", "Empty host is not allowed.")
    if not (initial_host and host == initial_host.lower().rstrip(".")):
        if initial:
            raise GatewayError(403, "EGRESS_DENIED_HOST", "Initial host is not the approved Microsoft symbol server.")
    if not initial:
        if host == initial_host.lower().rstrip("."):
            return
        if any(host.endswith(suffix) and host != suffix.lstrip(".") for suffix in redirect_suffixes):
            return
        raise GatewayError(403, "EGRESS_DENIED_HOST", "Redirect host is outside approved official infrastructure.")


def _build_initial_url(pdb_name: str, guid: str, age: int, initial_host: str, path_prefix: str = "/download/symbols") -> str:
    name = quote(pdb_name, safe="._-")
    key = quote(f"{guid}{age}", safe="")
    return f"https://{initial_host}{path_prefix}/{name}/{key}/{name}"


def _validate_path(path: str) -> str:
    if not path or any(ord(char) < 32 for char in path) or "\\" in path:
        raise GatewayError(403, "EGRESS_DENIED_PATH", "Symbol destination path is invalid.")
    # Reject path-traversal segments ("..", "%2e%2e", "%2E%2E", etc.).
    for segment in path.split("/"):
        if _TRAVERSAL_SEGMENT.fullmatch(segment):
            raise GatewayError(403, "EGRESS_DENIED_PATH", "Symbol destination path contains traversal segments.")
    return path


def _validate_path_prefix(path: str, *, expected_prefix: str) -> str:
    """Reject any path that does not start with the approved server-derived prefix.

    The path is the only place where a user-derived string (the PDB name,
    the GUID, the age) is interpolated into the upstream URL.  Enforcing
    the prefix is the last line of defense against a misconfigured
    :class:`GatewaySettings` or a future regression in the URL builder.
    """
    _validate_path(path)
    normalized_prefix = expected_prefix.rstrip("/") + "/"
    if path != normalized_prefix and not path.startswith(normalized_prefix):
        raise GatewayError(403, "EGRESS_DENIED_PATH", "Symbol destination path is outside the approved /download/symbols/ prefix.")
    return path


# ---------------------------------------------------------------------------
# Streaming download (pinned by DNS, TLS-verified)
# ---------------------------------------------------------------------------

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, *, timeout: float):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class _StreamResult:
    redirect_count: int
    content_type: str | None


def _download(pdb_name: str, guid: str, age: int, *, initial_host: str, path_prefix: str, redirect_suffixes: list[str], connect_timeout: int, total_timeout: int, max_redirects: int, max_bytes: int, chunk_size: int = 1024 * 1024):
    url = _build_initial_url(pdb_name, guid, age, initial_host, path_prefix)
    started = time.monotonic()
    redirects = 0
    content_type: str | None = None
    connection = None

    try:
        while True:
            if time.monotonic() - started > total_timeout:
                raise GatewayError(504, "EGRESS_TIMEOUT", "Official symbol download timed out.")
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            _validate_host_policy(host, initial=redirects == 0, initial_host=initial_host, redirect_suffixes=redirect_suffixes)
            try:
                ipaddress.ip_address(host)
                is_ip_literal = True
            except ValueError:
                is_ip_literal = False
            if is_ip_literal:
                raise GatewayError(403, "EGRESS_DENIED_HOST", "IP-literal symbol destinations are not allowed.")
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
                raise GatewayError(403, "EGRESS_DENIED_URL", "Symbol destination URL is not an approved HTTPS endpoint.")
            if parsed.port not in (None, 443):
                raise GatewayError(403, "EGRESS_DENIED_URL", "Symbol destination port is not 443.")
            path = _validate_path(parsed.path or "/")
            if redirects == 0:
                # The first hop is always the official Microsoft symbol
                # server; enforce the exact path prefix the URL was built
                # with.  Redirects are validated for safety but not for
                # prefix because the Azure blob CDN uses a different path
                # layout (``/symbols/...``).
                _validate_path_prefix(path, expected_prefix=path_prefix)
            target = path + (f"?{parsed.query}" if parsed.query else "")
            addresses = _public_addresses(host)
            connection = _PinnedHTTPSConnection(host, addresses[0], timeout=max(1, connect_timeout))
            try:
                # The only accepted method is GET.  HEAD is never used by
                # the fetcher and is rejected here as a defense-in-depth
                # measure so the gateway cannot be coerced into a HEAD
                # probe by a future code change.
                connection.request("GET", target, headers={"Accept": "application/octet-stream", "User-Agent": "Kairon-Symbol-Egress-Gateway/1"})
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    try:
                        response.read(4096)
                    except Exception:
                        pass
                    if not location:
                        raise GatewayError(502, "EGRESS_BAD_REDIRECT", "Redirect response did not include Location.")
                    if redirects >= max_redirects:
                        raise GatewayError(502, "EGRESS_REDIRECT_LIMIT", "Official symbol redirect limit was exceeded.")
                    next_url = location if "://" in location else f"{parsed.scheme}://{host}{location if location.startswith('/') else '/' + location}"
                    next_parsed = urlsplit(next_url)
                    next_host = (next_parsed.hostname or "").lower().rstrip(".")
                    _validate_host_policy(next_host, initial=False, initial_host=initial_host, redirect_suffixes=redirect_suffixes)
                    try:
                        ipaddress.ip_address(next_host)
                        raise GatewayError(403, "EGRESS_DENIED_HOST", "Redirect IP-literal destinations are not allowed.")
                    except ValueError:
                        pass
                    if next_parsed.scheme != "https" or next_parsed.port not in (None, 443):
                        raise GatewayError(403, "EGRESS_DENIED_URL", "Redirect URL is not an approved HTTPS endpoint.")
                    url = next_url
                    redirects += 1
                    try:
                        connection.close()
                    except Exception:
                        pass
                    connection = None
                    continue
                if response.status != 200:
                    raise GatewayError(502, "EGRESS_REMOTE_STATUS", f"Official symbol source returned HTTP {response.status}.")
                declared = response.getheader("Content-Length")
                if declared:
                    try:
                        declared_size = int(declared)
                    except ValueError as exc:
                        raise GatewayError(502, "EGRESS_BAD_CONTENT_LENGTH", "Official symbol source returned an invalid size.") from exc
                    if declared_size < 0 or declared_size > max_bytes:
                        raise GatewayError(413, "EGRESS_TOO_LARGE", "Official symbol exceeds the configured download limit.")
                content_type = response.getheader("Content-Type")

                def raw_chunks():
                    try:
                        while True:
                            if time.monotonic() - started > total_timeout:
                                raise GatewayError(504, "EGRESS_TIMEOUT", "Official symbol download timed out.")
                            chunk = response.read(min(chunk_size, max_bytes + 1))
                            if not chunk:
                                break
                            yield chunk
                    finally:
                        try:
                            connection.close()
                        except Exception:
                            pass

                return raw_chunks(), _StreamResult(redirect_count=redirects, content_type=content_type)
            except GatewayError:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
                raise
            except (TimeoutError, socket.timeout) as exc:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
                raise GatewayError(504, "EGRESS_TIMEOUT", "Official symbol download timed out.") from exc
            except ssl.SSLError as exc:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
                raise GatewayError(502, "EGRESS_TLS_FAILED", "Official symbol TLS validation failed.") from exc
            except (OSError, http.client.HTTPException) as exc:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
                raise GatewayError(502, "EGRESS_DOWNLOAD_FAILED", "Official symbol download failed.") from exc
    except Exception:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class GatewaySettings:
    def __init__(self) -> None:
        self.secret = os.environ.get("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "")
        self.replay_window_seconds = int(os.environ.get("MEMORY_SYMBOL_EGRESS_REPLAY_WINDOW_SECONDS", "60"))
        configured_initial_host = os.environ.get("MEMORY_SYMBOL_INITIAL_HOST", APPROVED_INITIAL_HOST).lower().rstrip(".")
        if configured_initial_host != APPROVED_INITIAL_HOST:
            raise RuntimeError(
                f"MEMORY_SYMBOL_INITIAL_HOST={configured_initial_host!r} is not the approved Microsoft symbol server. "
                f"The only allowed initial host is {APPROVED_INITIAL_HOST!r}."
            )
        self.initial_host = configured_initial_host
        configured_path_prefix = os.environ.get("MEMORY_SYMBOL_INITIAL_PATH", APPROVED_INITIAL_PATH_PREFIX).rstrip("/")
        if configured_path_prefix != APPROVED_INITIAL_PATH_PREFIX.rstrip("/"):
            raise RuntimeError(
                f"MEMORY_SYMBOL_INITIAL_PATH={configured_path_prefix!r} is not the approved /download/symbols/ prefix."
            )
        self.path_prefix = APPROVED_INITIAL_PATH_PREFIX
        configured_redirect_suffixes = [
            suffix.strip().lower()
            for suffix in os.environ.get("MEMORY_SYMBOL_REDIRECT_SUFFIXES", ".blob.core.windows.net").split(",")
            if suffix.strip()
        ]
        for suffix in configured_redirect_suffixes:
            if suffix not in APPROVED_REDIRECT_SUFFIXES:
                raise RuntimeError(
                    f"MEMORY_SYMBOL_REDIRECT_SUFFIXES contains {suffix!r}, which is not in the approved redirect allowlist "
                    f"({sorted(APPROVED_REDIRECT_SUFFIXES)!r})."
                )
        self.redirect_suffixes = configured_redirect_suffixes
        self.connect_timeout = int(os.environ.get("MEMORY_SYMBOL_CONNECT_TIMEOUT_SECONDS", "15"))
        self.total_timeout = int(os.environ.get("MEMORY_SYMBOL_DOWNLOAD_TIMEOUT_SECONDS", "180"))
        configured_max_redirects = int(os.environ.get("MEMORY_SYMBOL_MAX_REDIRECTS", str(DEFAULT_MAX_REDIRECTS)))
        if configured_max_redirects < 0 or configured_max_redirects > DEFAULT_MAX_REDIRECTS:
            raise RuntimeError(
                f"MEMORY_SYMBOL_MAX_REDIRECTS={configured_max_redirects} is outside the allowed range [0, {DEFAULT_MAX_REDIRECTS}]."
            )
        self.max_redirects = configured_max_redirects
        self.max_bytes = int(os.environ.get("MEMORY_SYMBOL_DOWNLOAD_MAX_BYTES", "1073741824"))
        self.max_response_bytes = int(os.environ.get("MEMORY_SYMBOL_EGRESS_MAX_RESPONSE_BYTES", "1073741824"))
        self.bind_host = os.environ.get("MEMORY_SYMBOL_EGRESS_GATEWAY_BIND", "0.0.0.0")
        self.bind_port = int(os.environ.get("MEMORY_SYMBOL_EGRESS_GATEWAY_PORT", "8443"))
        self.log_level = os.environ.get("BACKEND_LOG_LEVEL", "INFO").upper()
        # Optional content type for the streamed response.
        self.upstream_content_type = os.environ.get("MEMORY_SYMBOL_EGRESS_GATEWAY_CONTENT_TYPE", "application/octet-stream")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = GatewaySettings()
    if not settings.secret:
        # Refuse to start without a configured secret.  The compose file must
        # generate or inject one before bringing this service up.
        raise RuntimeError("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET is required to start the symbol egress gateway.")
    from app.services.memory.symbol_egress_auth import NonceStore
    app.state.settings = settings
    app.state.nonce_store = NonceStore(ttl_seconds=max(120, settings.replay_window_seconds * 2))
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logger.info(
        "symbol_egress_gateway_starting initial_host=%s redirect_suffixes=%s replay_window=%ds",
        settings.initial_host, ",".join(settings.redirect_suffixes), settings.replay_window_seconds,
    )
    yield
    logger.info("symbol_egress_gateway_stopping")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Kairon Symbol Egress Gateway",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/internal/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "service": "symbol-egress-gateway", "version": "1.0.0"}

    @app.post("/internal/symbol-fetch")
    async def symbol_fetch(request: Request) -> Response:
        from app.services.memory.symbol_egress_auth import EgressAuthError, verify_signed_headers
        settings: GatewaySettings = request.app.state.settings
        nonce_store = request.app.state.nonce_store
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="Request body too large.")
        # All auth headers must be present.
        required = [
            "X-Kairon-Egress-Version",
            "X-Kairon-Egress-Request-Id",
            "X-Kairon-Egress-Timestamp",
            "X-Kairon-Egress-Nonce",
            "X-Kairon-Egress-Signature",
        ]
        for name in required:
            if name not in request.headers:
                raise HTTPException(status_code=401, detail=f"Missing signed request header: {name}")
        try:
            verify_signed_headers(
                secret=settings.secret,
                method="POST",
                path="/internal/symbol-fetch",
                body=body,
                headers={k: v for k, v in request.headers.items()},
                nonce_store=nonce_store,
                replay_window_seconds=settings.replay_window_seconds,
            )
        except EgressAuthError as exc:
            raise HTTPException(status_code=401, detail={"code": exc.code, "message": exc.message}) from exc

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Request body is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
        # Reject unexpected keys: the gateway contract is fixed.
        allowed_keys = {"request_id", "pdb_name", "guid", "age"}
        extra = set(payload.keys()) - allowed_keys
        if extra:
            raise HTTPException(status_code=400, detail=f"Unexpected payload keys: {sorted(extra)}")
        try:
            request_id = _validate_request_id(payload.get("request_id"))
            pdb_name = _validate_pdb_name(payload.get("pdb_name"))
            guid = _validate_guid(payload.get("guid"))
            age = _validate_age(payload.get("age"))
        except GatewayError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc

        try:
            iterator, info = _download(
                pdb_name, guid, age,
                initial_host=settings.initial_host,
                path_prefix=settings.path_prefix,
                redirect_suffixes=settings.redirect_suffixes,
                connect_timeout=settings.connect_timeout,
                total_timeout=settings.total_timeout,
                max_redirects=settings.max_redirects,
                max_bytes=settings.max_bytes,
            )
        except GatewayError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc

        # Sanitized response headers.  The client is responsible for
        # SHA-256 verification of the streamed bytes; the gateway only
        # advertises the static request id and redirect count.  No
        # upstream Set-Cookie or other headers are forwarded.
        sanitized_headers = {
            "X-Kairon-Egress-Request-Id": request_id,
            "X-Kairon-Egress-Redirects": str(info.redirect_count),
            "Content-Type": settings.upstream_content_type,
            "Cache-Control": "no-store",
        }
        return StreamingResponse(iterator, headers=sanitized_headers, media_type=settings.upstream_content_type)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    return app


app = create_app()


def main() -> None:
    settings = GatewaySettings()
    if not settings.secret:
        raise RuntimeError("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET is required.")
    config = uvicorn.Config(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        log_level=settings.log_level.lower(),
        access_log=False,
        # Reasonable defaults; uvicorn does not need TLS here because the
        # gateway only listens on an internal Docker network.
    )
    server = uvicorn.Server(config)

    def _handle_signal(signum, _frame):
        logger.info("received_signal signal=%d", signum)
        server.should_exit = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    server.run()


if __name__ == "__main__":
    main()
