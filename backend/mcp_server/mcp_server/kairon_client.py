"""A thin HTTP client for Kairon's case API, used by the MCP tool handlers.

This package is a client of Kairon, not a part of it: it never imports
anything from ``app.*`` and never touches the database directly. It talks to
a running Kairon backend exactly the way any other external integration
would -- over HTTP, authenticated with a read-only service token sent as
``Authorization: Bearer`` (see ``app.services.service_tokens`` on the backend
side). That separation is deliberate: this server can run on its own host,
with its own lifecycle, independent of the backend's.
"""
from __future__ import annotations

import os
import re
from urllib.parse import quote

import httpx

# A case id is a single path segment (a UUID today). Anything else -- a "/",
# "..", "?" or "#" -- would make the request reach another endpoint than
# the tool's, e.g. "../admin/..." from text an attacker planted in case data
# that a connected model then passes along. Refused before any request.
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


class KaironAPIError(RuntimeError):
    """The backend answered, but not with success. Carries enough detail for
    a tool to report back to the model instead of crashing the server."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Kairon API error {status_code}: {detail}")


class KaironClient:
    """Stateless; every call opens its own request. An MCP server handles one
    tool call at a time per session, so there is no meaningful connection
    pooling to lose by not holding a long-lived ``httpx.Client`` across
    calls, and it sidesteps event-loop lifecycle questions entirely."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    @classmethod
    def from_env(cls) -> "KaironClient":
        base_url = os.environ.get("KAIRON_API_URL", "").strip()
        token = os.environ.get("KAIRON_SERVICE_TOKEN", "").strip()
        if not base_url:
            raise RuntimeError("KAIRON_API_URL is not set (e.g. http://localhost:8000)")
        if not token:
            raise RuntimeError(
                "KAIRON_SERVICE_TOKEN is not set. Create one as an administrator: "
                "POST /api/admin/service-tokens."
            )
        return cls(base_url, token)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.get(url, params=params, headers=self._headers(), timeout=self._timeout)
        except httpx.HTTPError as exc:
            raise KaironAPIError(0, f"Could not reach Kairon at {url}: {exc}") from exc
        if response.status_code >= 400:
            detail = _error_detail(response)
            raise KaironAPIError(response.status_code, detail)
        return response.json()

    def list_tool_specs(self) -> list[dict]:
        return self.get("/api/ai/tools")["tools"]

    def list_cases(self, **params) -> list[dict]:
        return self.get("/api/cases", params=_drop_none(params))

    def call_tool(self, case_id: str, tool_name: str, arguments: dict) -> dict:
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
            raise KaironAPIError(400, "Invalid case_id: use an id returned by list_cases.")
        # Every tool parameter is a scalar (see app.services.ai.tools), so
        # plain query parameters always suffice -- no request body, no
        # encoding scheme to agree on with the backend.
        path = f"/api/cases/{quote(case_id, safe='')}/ai/tools/{quote(tool_name, safe='')}"
        return self.get(path, params=_drop_none(arguments))


def _drop_none(params: dict) -> dict:
    """An omitted MCP argument arrives here as ``None``; sending it as an
    empty query string parameter is not the same as omitting it (an empty
    string is a valid, if unusual, filter value for some tools)."""
    return {key: value for key, value in params.items() if value is not None}


def _error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:500]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:500]
