"""The MCP server bridges to Kairon's own tool catalog; these tests build it
against a fake KaironClient (no network, no real backend) and drive it the
same way a real MCP transport would -- through the server's registered
tools/list and tools/call handlers -- to check the bridging logic itself:
case_id injection, the list_cases addition, and error shapes.
"""
from __future__ import annotations

import asyncio
import json

import mcp_types as types
import pytest

from mcp_server.kairon_client import KaironAPIError
from mcp_server.server import build_server


class FakeKaironClient:
    """Stands in for mcp_server.kairon_client.KaironClient. Records every
    call so a test can assert on exactly what reached "the backend"."""

    base_url = "http://fake-kairon.test"

    def __init__(self, tool_specs=None, cases=None, tool_result=None, raise_on_call: KaironAPIError | None = None):
        self._tool_specs = tool_specs if tool_specs is not None else [
            {
                "name": "list_hosts",
                "description": "List hosts in the case.",
                "input_schema": {"type": "object", "properties": {}, "required": []},
            },
            {
                "name": "search_events",
                "description": "Search the case's events.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query."},
                        "limit": {"type": "integer", "description": "Max rows."},
                    },
                    "required": [],
                },
            },
        ]
        self._cases = cases if cases is not None else [{"id": "case-1", "name": "Test case", "status": "active"}]
        self._tool_result = tool_result if tool_result is not None else {"hosts": []}
        self._raise_on_call = raise_on_call
        self.list_cases_calls: list[dict] = []
        self.call_tool_calls: list[tuple[str, str, dict]] = []

    def list_tool_specs(self) -> list[dict]:
        return self._tool_specs

    def list_cases(self, **params) -> list[dict]:
        self.list_cases_calls.append(params)
        return self._cases

    def call_tool(self, case_id: str, tool_name: str, arguments: dict) -> dict:
        self.call_tool_calls.append((case_id, tool_name, arguments))
        if self._raise_on_call is not None:
            raise self._raise_on_call
        return self._tool_result


def _list_tools(server):
    return asyncio.run(server._request_handlers["tools/list"].handler(None, types.PaginatedRequestParams()))


def _call_tool(server, name: str, arguments: dict):
    return asyncio.run(
        server._request_handlers["tools/call"].handler(
            None, types.CallToolRequestParams(name=name, arguments=arguments)
        )
    )


def _result_json(result: types.CallToolResult) -> dict:
    return json.loads(result.content[0].text)


# --- building the catalog ----------------------------------------------


def test_the_catalog_includes_list_cases_plus_every_backend_tool():
    client = FakeKaironClient()
    server = build_server(client)

    result = _list_tools(server)

    names = {tool.name for tool in result.tools}
    assert names == {"list_cases", "list_hosts", "search_events"}


def test_every_backend_tool_gets_case_id_added_as_required():
    client = FakeKaironClient()
    server = build_server(client)

    result = _list_tools(server)

    search_events = next(t for t in result.tools if t.name == "search_events")
    assert "case_id" in search_events.input_schema["properties"]
    assert "case_id" in search_events.input_schema["required"]
    # The backend's own parameters are preserved alongside it.
    assert "query" in search_events.input_schema["properties"]


def test_list_cases_itself_has_no_case_id_parameter():
    client = FakeKaironClient()
    server = build_server(client)

    result = _list_tools(server)

    list_cases = next(t for t in result.tools if t.name == "list_cases")
    assert "case_id" not in list_cases.input_schema["properties"]


def test_a_tool_with_no_parameters_still_gets_case_id():
    client = FakeKaironClient()
    server = build_server(client)

    result = _list_tools(server)

    list_hosts = next(t for t in result.tools if t.name == "list_hosts")
    assert list_hosts.input_schema["required"] == ["case_id"]


def test_building_the_server_fails_loudly_if_the_catalog_cannot_be_fetched():
    class BrokenClient(FakeKaironClient):
        def list_tool_specs(self):
            raise KaironAPIError(0, "connection refused")

    with pytest.raises(RuntimeError, match="Could not load the tool catalog"):
        build_server(BrokenClient())


# --- calling tools -------------------------------------------------------


def test_list_cases_calls_the_client_and_returns_its_result():
    client = FakeKaironClient(cases=[{"id": "case-9", "name": "Another case"}])
    server = build_server(client)

    result = _call_tool(server, "list_cases", {})

    assert result.is_error is False
    assert _result_json(result) == [{"id": "case-9", "name": "Another case"}]


def test_list_cases_forwards_its_filters():
    client = FakeKaironClient()
    server = build_server(client)

    _call_tool(server, "list_cases", {"q": "smith", "status": "active"})

    assert client.list_cases_calls == [{"q": "smith", "status": "active"}]


def test_a_case_scoped_tool_strips_case_id_before_forwarding_arguments():
    client = FakeKaironClient(tool_result={"total_matches": 3})
    server = build_server(client)

    result = _call_tool(server, "search_events", {"case_id": "case-1", "query": "powershell", "limit": 5})

    assert client.call_tool_calls == [("case-1", "search_events", {"query": "powershell", "limit": 5})]
    assert _result_json(result) == {"total_matches": 3}


def test_a_case_scoped_tool_without_case_id_is_refused_before_calling_the_backend():
    client = FakeKaironClient()
    server = build_server(client)

    result = _call_tool(server, "search_events", {"query": "powershell"})

    assert result.is_error is True
    assert "case_id is required" in _result_json(result)["error"]
    assert client.call_tool_calls == []


def test_an_unknown_tool_is_reported_not_raised():
    client = FakeKaironClient()
    server = build_server(client)

    result = _call_tool(server, "not_a_real_tool", {"case_id": "case-1"})

    assert result.is_error is True
    assert "Unknown tool" in _result_json(result)["error"]


def test_a_backend_api_error_is_surfaced_as_an_error_result_not_a_crash():
    client = FakeKaironClient(raise_on_call=KaironAPIError(404, "Case not found"))
    server = build_server(client)

    result = _call_tool(server, "list_hosts", {"case_id": "does-not-exist"})

    assert result.is_error is True
    body = _result_json(result)
    assert body["error"] == "Case not found"
    assert body["status_code"] == 404
