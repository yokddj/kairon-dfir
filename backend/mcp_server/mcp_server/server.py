"""A generic MCP server over Kairon's read-only case tools.

Any MCP-compatible client (an IDE, a desktop assistant, a chat application
with MCP support) can use this to look at a case's parsed data -- search its
events, read its timeline, list its findings and detections, walk a process
tree -- while investigating an alert or an incident, without that client
needing to know anything about Kairon's own API.

It is a thin bridge, not a second implementation: every tool it exposes is
fetched from the backend's own catalog (``GET /api/ai/tools``, backed by
``app.services.ai.tools.TOOL_SPECS``) and executed by calling the backend
back (``GET /api/cases/{case_id}/ai/tools/{tool_name}``). The descriptions,
parameters and behaviour are defined once, in the backend, and used by the
in-app assistant and this server alike.

One tool is added here, not in the backend's catalog: ``list_cases``, to
resolve "the Smith investigation" or similar to a case id before calling any
of the per-case tools below. The backend's own catalog has no equivalent
because the in-app assistant already has its case fixed by the page it is
open on; an external client asking about an unspecified case needs a way to
find it first.

Authentication is a single read-only service token (see
``app.services.service_tokens`` on the backend), supplied once via the
``KAIRON_SERVICE_TOKEN`` environment variable -- never per call, and never
visible to the connected MCP client, which only ever sees tool names,
descriptions and results.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import time

import mcp_types as types
from mcp.server.lowlevel import Server

from mcp_server.kairon_client import KaironAPIError, KaironClient

logger = logging.getLogger(__name__)

SERVER_NAME = "kairon-dfir"
# How long the backend's tool catalog is reused before tools/list refetches
# it, so a backend upgrade that adds or changes a tool reaches connected
# clients without restarting this server.
CATALOG_TTL_SECONDS = 300
LOCAL_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
LOCAL_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

LIST_CASES_TOOL = {
    "name": "list_cases",
    "description": (
        "List the cases this server can see, with their id, name, status and "
        "evidence/host counts. Call this first to resolve a case by name before "
        "using any other tool here, all of which need a case_id. Every other "
        "tool's result also carries its own case_id for a quick repeat lookup."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "q": {"type": "string", "description": "Free-text filter over the case's name, description and notes."},
            "status": {"type": "string", "description": "e.g. active, closed, archived."},
            "include_archived": {"type": "boolean", "description": "Also list archived cases. Default false."},
        },
        "required": [],
    },
}


def _case_scoped_tool(spec: dict) -> dict:
    """A backend tool spec, with case_id added as a required parameter.

    The in-app assistant never needs this: its case is fixed by the page
    it runs on. An external MCP client has no such context, so every call
    here must name its case explicitly.
    """
    augmented = dict(spec)
    schema = dict(spec.get("input_schema") or {"type": "object", "properties": {}})
    properties = dict(schema.get("properties") or {})
    properties["case_id"] = {
        "type": "string",
        "description": "The case to look at. A value from list_cases.",
    }
    schema["properties"] = properties
    schema["required"] = sorted(set(schema.get("required") or []) | {"case_id"})
    augmented["input_schema"] = schema
    return augmented


def _all_specs(backend_specs: list[dict]) -> list[dict]:
    return [LIST_CASES_TOOL] + [_case_scoped_tool(spec) for spec in backend_specs]


def transport_security(extra_hosts: list[str]):  # noqa: ANN201
    """Host/Origin checks for the HTTP transport (DNS rebinding protection).

    Localhost is always allowed. A remote client reaches this server by some
    other name (a VPN hostname, a LAN address); each such name must be
    listed, or the SDK answers 421 Misdirected Request -- an unlisted Host
    is exactly what a DNS rebinding attack looks like.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts = list(LOCAL_HOSTS)
    origins = list(LOCAL_ORIGINS)
    for raw in extra_hosts:
        name = raw.strip()
        if not name:
            continue
        host = name if ":" in name.rsplit("]", 1)[-1] else f"{name}:*"
        hosts.append(host)
        origins.extend([f"http://{host}", f"https://{host}"])
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins)


def _text_result(payload: object, *, is_error: bool = False) -> types.CallToolResult:
    """Every tool here answers with structured data; this project's MCP
    client surface (and most today) reads a tool result as text, so the
    payload is serialized as JSON text rather than a typed content block
    the client may not render."""
    import json

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, default=str))],
        is_error=is_error,
    )


def build_server(client: KaironClient) -> Server:
    """Construct the MCP server. Kept separate from ``main()`` so tests can
    build one against a fake/stubbed ``KaironClient`` without a live backend
    or a real transport."""

    # Fetched at startup (so a misconfigured URL or token fails loudly right
    # away) and reused for CATALOG_TTL_SECONDS: refetching on every
    # tools/list would cost a round trip to Kairon before the client even
    # picks a tool; never refetching would keep a stale catalog after a
    # backend upgrade until this process restarts.
    try:
        initial_specs = client.list_tool_specs()
    except KaironAPIError as exc:
        raise RuntimeError(
            f"Could not load the tool catalog from Kairon at {client.base_url}: {exc}"
        ) from exc
    catalog = {"specs": _all_specs(initial_specs), "loaded_at": time.monotonic()}

    async def _current_specs() -> list[dict]:
        if time.monotonic() - catalog["loaded_at"] >= CATALOG_TTL_SECONDS:
            try:
                fresh = await asyncio.to_thread(client.list_tool_specs)
                catalog["specs"] = _all_specs(fresh)
            except KaironAPIError as exc:
                logger.warning("Keeping the previous tool catalog; refresh failed: %s", exc)
            catalog["loaded_at"] = time.monotonic()
        return catalog["specs"]

    def _tool_from_spec(spec: dict) -> types.Tool:
        return types.Tool(name=spec["name"], description=spec["description"], input_schema=spec["input_schema"])

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[_tool_from_spec(spec) for spec in await _current_specs()])

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name = params.name
        arguments = dict(params.arguments or {})
        specs_by_name = {spec["name"]: spec for spec in await _current_specs()}

        if name not in specs_by_name:
            return _text_result(
                {"error": f"Unknown tool '{name}'. Available: {', '.join(sorted(specs_by_name))}."},
                is_error=True,
            )

        try:
            # The client is synchronous (httpx); run it off the event loop so
            # one slow tool call does not stall every other session served
            # by this process (the HTTP transport serves many at once).
            if name == "list_cases":
                result = await asyncio.to_thread(client.list_cases, **arguments)
            else:
                case_id = arguments.pop("case_id", None)
                if not case_id:
                    return _text_result({"error": "case_id is required. Call list_cases first."}, is_error=True)
                result = await asyncio.to_thread(client.call_tool, case_id, name, arguments)
        except KaironAPIError as exc:
            # A 403/404 here is ordinary -- an unknown or inaccessible case,
            # say -- and worth the model seeing and adapting to, not a crash.
            return _text_result({"error": exc.detail, "status_code": exc.status_code}, is_error=True)

        return _text_result(result)

    return Server(SERVER_NAME, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def _run_stdio(server: Server) -> None:
    import mcp.server.stdio as stdio

    async with stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def _run_http(server: Server, *, host: str, port: int, allowed_hosts: list[str]) -> None:
    import uvicorn

    app = server.streamable_http_app(transport_security=transport_security(allowed_hosts))
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="MCP server over Kairon's read-only case tools.")
    parser.add_argument(
        "--transport", choices=["stdio", "http"], default="stdio",
        help="stdio for a local MCP client (the default); http for a remote one.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP transport only.")
    parser.add_argument("--port", type=int, default=8800, help="HTTP transport only.")
    parser.add_argument(
        "--allowed-host", action="append", default=[],
        help=(
            "HTTP transport only: a host name (optionally host:port) remote clients use to reach this "
            "server, e.g. kairon.vpn.example. Repeatable; also KAIRON_MCP_ALLOWED_HOSTS (comma-separated). "
            "Localhost is always allowed."
        ),
    )
    args = parser.parse_args()

    client = KaironClient.from_env()
    server = build_server(client)

    if args.transport == "stdio":
        asyncio.run(_run_stdio(server))
    else:
        env_hosts = [item for item in os.environ.get("KAIRON_MCP_ALLOWED_HOSTS", "").split(",") if item.strip()]
        _run_http(server, host=args.host, port=args.port, allowed_hosts=[*env_hosts, *args.allowed_host])


if __name__ == "__main__":
    main()
