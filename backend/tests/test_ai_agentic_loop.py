"""The tool-calling loop: the model looks things up, then answers."""

from __future__ import annotations

import json

import pytest

from app.services.ai import chat as chat_service
from app.services.ai.providers import StreamEvent


class ScriptedProvider:
    """Replays a scripted sequence of turns and records what it was asked."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls: list[dict] = []

    def stream_chat(self, *, system, messages, tools=None):
        self.calls.append({"system": system, "messages": list(messages), "tools": tools})
        for event in self.turns.pop(0) if self.turns else []:
            yield event

    def tool_turn_messages(self, calls, results):
        return [
            {"role": "assistant", "content": [{"type": "tool_use", **call} for call in calls]},
            {"role": "user", "content": [{"type": "tool_result", "content": r} for r in results]},
        ]


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    monkeypatch.setattr(chat_service, "log_audit", lambda *a, **k: None)


def _run(provider, monkeypatch, tool_result=None):
    monkeypatch.setattr(
        chat_service, "run_tool", lambda db, case_id, name, args: tool_result or {"total_matches": 3}
    )
    return list(
        chat_service._run_with_tools(
            None,
            client=provider,
            case_id="case-1",
            system="sys",
            conversation=[{"role": "user", "content": "any persistence?"}],
            actor_user_id=None,
        )
    )


def test_a_tool_call_is_executed_and_the_answer_continues(monkeypatch):
    """The model asks, we look, it answers -- all inside one stream."""
    provider = ScriptedProvider(
        [
            [StreamEvent(type="tool_use", data={"id": "t1", "name": "list_persistence", "input": {}})],
            [StreamEvent(type="text", text="Found 3 run keys.")],
        ]
    )

    events = _run(provider, monkeypatch)

    assert [e.type for e in events] == ["notice", "text"]
    assert "persistence" in events[0].text.lower()
    assert events[1].text == "Found 3 run keys."
    assert len(provider.calls) == 2, "the model must be called again with the tool result"


def test_the_tool_result_is_fed_back_to_the_model(monkeypatch):
    provider = ScriptedProvider(
        [
            [StreamEvent(type="tool_use", data={"id": "t1", "name": "search_events", "input": {"query": "x"}})],
            [StreamEvent(type="text", text="done")],
        ]
    )

    _run(provider, monkeypatch, tool_result={"total_matches": 42})

    second_turn = provider.calls[1]["messages"]
    assert any("42" in json.dumps(m, default=str) for m in second_turn)


def test_an_answer_with_no_tool_call_short_circuits(monkeypatch):
    """A plain question must cost exactly one request."""
    provider = ScriptedProvider([[StreamEvent(type="text", text="Hello.")]])

    events = _run(provider, monkeypatch)

    assert [e.type for e in events] == ["text"]
    assert len(provider.calls) == 1


def test_the_loop_is_bounded_and_the_last_round_withholds_tools(monkeypatch):
    """A model that only ever calls tools must still be forced to answer."""
    always_tool = [StreamEvent(type="tool_use", data={"id": "t", "name": "list_hosts", "input": {}})]
    provider = ScriptedProvider([always_tool] * (chat_service.MAX_TOOL_ROUNDS + 1))

    _run(provider, monkeypatch)

    assert len(provider.calls) == chat_service.MAX_TOOL_ROUNDS + 1
    assert provider.calls[-1]["tools"] is None, "the final round must force an answer"
    assert all(c["tools"] is not None for c in provider.calls[:-1])


def test_a_lookup_notice_names_the_tool_for_the_ui(monkeypatch):
    """The panel shows these, so they must carry the tool name in data."""
    provider = ScriptedProvider(
        [
            [StreamEvent(type="tool_use", data={"id": "t1", "name": "search_events", "input": {"query": "mimikatz"}})],
            [StreamEvent(type="text", text="ok")],
        ]
    )

    notice = _run(provider, monkeypatch)[0]

    assert notice.data["tool"] == "search_events"
    assert notice.data["arguments"] == {"query": "mimikatz"}
    assert "mimikatz" in notice.text


def test_parallel_tool_calls_in_one_turn_are_all_executed(monkeypatch):
    """Models batch lookups; each one must run and come back paired."""
    provider = ScriptedProvider(
        [
            [
                StreamEvent(type="tool_use", data={"id": "a", "name": "list_hosts", "input": {}}),
                StreamEvent(type="tool_use", data={"id": "b", "name": "list_findings", "input": {}}),
            ],
            [StreamEvent(type="text", text="ok")],
        ]
    )

    events = _run(provider, monkeypatch)

    assert [e.type for e in events].count("notice") == 2


def test_the_system_prompt_tells_the_model_it_can_look(monkeypatch):
    """The Phase 1 prompt claimed the opposite; that claim must be gone."""
    assert "search_events" in chat_service.SYSTEM_PROMPT
    assert "You have no search capability" not in chat_service.SYSTEM_PROMPT
    assert "untrusted attacker-controlled" in chat_service.SYSTEM_PROMPT


def test_the_active_host_reaches_the_prompt(monkeypatch):
    monkeypatch.setattr(chat_service, "build_case_context", lambda db, case_id: "## Case briefing")

    prompt = chat_service.build_system_prompt(None, "case-1", active_host="WS-01")

    assert "WS-01" in prompt
    assert "currently looking at host" in prompt


def test_no_active_host_adds_nothing(monkeypatch):
    monkeypatch.setattr(chat_service, "build_case_context", lambda db, case_id: "## Case briefing")

    assert "currently looking at host" not in chat_service.build_system_prompt(None, "case-1")
