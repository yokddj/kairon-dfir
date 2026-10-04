"""Cross-site request forgery protection by origin check.

The session is a cookie, so a page on another site (or another port of the same host, which the
browser treats as the same site for SameSite=Lax) could make the analyst's browser send a
state-changing request that carries it. Browsers always say where such a request comes from: they
send ``Origin`` on every cross-origin request and on same-origin POST/PUT/PATCH/DELETE, and
``Referer`` otherwise. A state-changing request is refused when that origin is neither the server's
own (the ``Host`` the request was sent to) nor one of the configured allowed origins.

A request with neither header did not come from a page in a browser (curl, scripts, the CLI) and is
let through: it cannot ride on a browser's cookie. Safe methods (GET, HEAD, OPTIONS) change nothing
and are never checked.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _netloc(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    netloc = parts.netloc.lower()
    # A default port is omitted by the browser in Origin and by most clients in Host.
    for scheme, port in (("http", ":80"), ("https", ":443")):
        if parts.scheme == scheme and netloc.endswith(port):
            netloc = netloc[: -len(port)]
    return netloc


def origin_is_trusted(origin: str, *, host: str | None, allowed_origins: list[str], allowed_regex: str | None) -> bool:
    """Whether a browser request from ``origin`` may change state on this server."""
    origin = origin.strip()
    if not origin or origin == "null":
        return False
    if "*" in allowed_origins:
        return True
    if origin.rstrip("/") in {value.rstrip("/") for value in allowed_origins}:
        return True
    if allowed_regex and re.fullmatch(allowed_regex, origin):
        return True
    source = _netloc(origin)
    if source is None or not host:
        return False
    host = host.strip().lower()
    for port in (":80", ":443"):
        if host.endswith(port) and source == host[: -len(port)]:
            return True
    return source == host


class CSRFOriginMiddleware:
    """Refuse state-changing browser requests that come from another origin."""

    def __init__(self, app: ASGIApp, *, allowed_origins: Callable[[], list[str]], allowed_regex: Callable[[], str | None]) -> None:
        self.app = app
        self.allowed_origins = allowed_origins
        self.allowed_regex = allowed_regex

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        source = headers.get("origin")
        if source is None and headers.get("referer"):
            referer = urlsplit(headers["referer"])
            source = f"{referer.scheme}://{referer.netloc}" if referer.scheme and referer.netloc else "null"
        if source is not None and not origin_is_trusted(
            source, host=headers.get("host"), allowed_origins=self.allowed_origins(), allowed_regex=self.allowed_regex()
        ):
            response = JSONResponse(status_code=403, content={"detail": "Cross-site request refused"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

