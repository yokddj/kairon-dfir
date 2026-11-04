"""The HTTP surface an external MCP server (or any other non-interactive
client) calls to list and run the assistant's read-only lookup tools,
independent of the chat/model loop: GET /api/ai/tools (the catalog, not
case-scoped) and GET /api/cases/{case_id}/ai/tools/{tool_name} (run one,
case-scoped).
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_ai
from app.core.database import Base, get_db
from app.main import app
from app.models.case import Case


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"


def _db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    return db


def _client(db):
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _reset():
    app.dependency_overrides.pop(get_db, None)


def test_the_tool_catalog_matches_what_the_in_app_assistant_sees():
    """Same TOOL_SPECS, same descriptions -- no separate catalog to drift."""
    client = TestClient(app)
    response = client.get("/api/ai/tools")
    assert response.status_code == 200
    names = {tool["name"] for tool in response.json()["tools"]}
    assert "describe_case" in names
    assert "list_hosts" in names
    assert "search_events" in names


def test_listing_tools_does_not_require_a_case_or_the_assistant_enabled():
    """The catalog is not case data: no case_id, no model provider involved."""
    client = TestClient(app)
    response = client.get("/api/ai/tools")
    assert response.status_code == 200


def test_calling_a_tool_runs_it_and_returns_its_result(monkeypatch):
    captured = {}

    def fake_run_tool(db, case_id, name, args):
        captured["case_id"] = case_id
        captured["name"] = name
        captured["args"] = args
        return {"hosts": [{"id": "h1", "name": "WS-01"}]}

    monkeypatch.setattr(routes_ai, "run_tool", fake_run_tool)
    db = _db_session()
    client = _client(db)
    try:
        response = client.get(f"/api/cases/{CASE_ID}/ai/tools/list_hosts")
        assert response.status_code == 200
        assert response.json() == {"hosts": [{"id": "h1", "name": "WS-01"}]}
        assert captured["case_id"] == CASE_ID
        assert captured["name"] == "list_hosts"
    finally:
        _reset()


def test_calling_an_unknown_tool_is_not_a_server_error(monkeypatch):
    """run_tool itself reports an unknown name as a normal result, not a
    raised error (see tools.run_tool) -- this endpoint must not get in the
    way of that."""
    db = _db_session()
    client = _client(db)
    try:
        response = client.get(f"/api/cases/{CASE_ID}/ai/tools/not_a_real_tool")
        assert response.status_code == 200
        assert "error" in response.json()
    finally:
        _reset()


def test_query_parameters_become_the_tool_arguments(monkeypatch):
    captured = {}

    def fake_run_tool(db, case_id, name, args):
        captured.update(args)
        return {}

    monkeypatch.setattr(routes_ai, "run_tool", fake_run_tool)
    db = _db_session()
    client = _client(db)
    try:
        client.get(f"/api/cases/{CASE_ID}/ai/tools/search_events", params={"query": "powershell", "limit": "10"})
        assert captured == {"query": "powershell", "limit": 10}
    finally:
        _reset()


def test_boolean_query_parameters_are_coerced_not_left_as_truthy_strings(monkeypatch):
    """bool('false') is True in Python -- a tool reading args.get('x') and
    wrapping it in bool() directly (several do) would treat ?x=false as
    true. This endpoint must coerce before the tool ever sees the value."""
    captured = {}

    def fake_run_tool(db, case_id, name, args):
        captured.update(args)
        return {}

    monkeypatch.setattr(routes_ai, "run_tool", fake_run_tool)
    db = _db_session()
    client = _client(db)
    try:
        client.get(f"/api/cases/{CASE_ID}/ai/tools/search_command_history", params={"suspicious_only": "false"})
        assert captured["suspicious_only"] is False

        client.get(f"/api/cases/{CASE_ID}/ai/tools/search_command_history", params={"suspicious_only": "true"})
        assert captured["suspicious_only"] is True
    finally:
        _reset()


def test_an_argument_not_in_the_tool_schema_passes_through_as_a_string(monkeypatch):
    captured = {}

    def fake_run_tool(db, case_id, name, args):
        captured.update(args)
        return {}

    monkeypatch.setattr(routes_ai, "run_tool", fake_run_tool)
    db = _db_session()
    client = _client(db)
    try:
        client.get(f"/api/cases/{CASE_ID}/ai/tools/list_hosts", params={"unexpected": "value"})
        assert captured["unexpected"] == "value"
    finally:
        _reset()


def test_calling_a_tool_for_an_unknown_case_is_404():
    db = _db_session()
    client = _client(db)
    try:
        response = client.get("/api/cases/does-not-exist/ai/tools/list_hosts")
        assert response.status_code == 404
    finally:
        _reset()


# --- argument coercion unit tests -------------------------------------------


def test_coerce_tool_args_converts_declared_types():
    result = routes_ai._coerce_tool_args(
        "search_command_history",
        {"query": "mimikatz", "risk_min": "50", "suspicious_only": "true"},
    )
    assert result == {"query": "mimikatz", "risk_min": 50, "suspicious_only": True}


def test_coerce_tool_args_leaves_an_unparsable_integer_as_a_string():
    result = routes_ai._coerce_tool_args("search_command_history", {"risk_min": "not-a-number"})
    assert result == {"risk_min": "not-a-number"}


def test_coerce_tool_args_for_an_unknown_tool_passes_everything_through():
    result = routes_ai._coerce_tool_args("not_a_real_tool", {"anything": "value"})
    assert result == {"anything": "value"}
