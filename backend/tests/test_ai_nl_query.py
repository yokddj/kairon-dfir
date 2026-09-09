"""nl_query: translating a plain-English question into Search's own query syntax.

A single completion, not the agentic tool loop -- so these tests stub the provider
directly rather than routing through chat.py's tool machinery.
"""

from __future__ import annotations

from app.services.ai import nl_query
from app.services.ai.providers import StreamEvent


class StubProvider:
    def __init__(self, credentials):
        self.credentials = credentials

    def stream_chat(self, *, system, messages, tools=None):
        StubProvider.last_system = system
        StubProvider.last_messages = messages
        StubProvider.last_tools = tools
        yield StreamEvent(type="text", text=StubProvider.answer)


def _stub(monkeypatch, answer: str, described: dict | None = None):
    StubProvider.answer = answer
    monkeypatch.setattr(nl_query, "build_provider", lambda creds: StubProvider(creds))
    monkeypatch.setattr(nl_query, "resolve_provider", lambda db, provider=None: object())
    monkeypatch.setattr(
        nl_query,
        "tool_describe_case",
        lambda db, case_id, args: described
        if described is not None
        else {"indexed": True, "artifact_types": {"process_execution": 10}, "hosts": {"WS01": 10}, "event_types": {"process_start": 10}},
    )


def test_blank_question_never_calls_the_provider(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(nl_query, "build_provider", lambda creds: called.update(n=called["n"] + 1))
    assert nl_query.translate_natural_language_query(None, "case-1", "   ") == ""
    assert called["n"] == 0


def test_translates_a_question_into_a_query(monkeypatch):
    _stub(monkeypatch, "process.name:powershell.exe host.name:WS01")
    result = nl_query.translate_natural_language_query(None, "case-1", "what did powershell do on WS01")
    assert result == "process.name:powershell.exe host.name:WS01"


def test_translates_a_question_asked_in_another_language(monkeypatch):
    # The system prompt must not restrict this to English -- an analyst asking in
    # Spanish (or any other language) should get the same English-syntax query out.
    _stub(monkeypatch, "process.name:powershell.exe host.name:WS01")
    result = nl_query.translate_natural_language_query(None, "case-1", "que hizo powershell en WS01")
    assert result == "process.name:powershell.exe host.name:WS01"


def test_system_prompt_does_not_restrict_the_question_to_english(monkeypatch):
    _stub(monkeypatch, "risk_score>=70")
    nl_query.translate_natural_language_query(None, "case-1", "actividad de alto riesgo")
    assert "any other language" in StubProvider.last_system
    assert "the query syntax itself" in StubProvider.last_system.lower()


def test_grounds_the_prompt_with_this_case_s_real_facets(monkeypatch):
    _stub(
        monkeypatch,
        "artifact.type:process_execution",
        described={"indexed": True, "artifact_types": {"process_execution": 5}, "hosts": {"DC01": 5}, "event_types": {}},
    )
    nl_query.translate_natural_language_query(None, "case-1", "any process execution")
    assert "process_execution" in StubProvider.last_system
    assert "DC01" in StubProvider.last_system


def test_says_plainly_when_the_case_has_nothing_indexed(monkeypatch):
    _stub(monkeypatch, "", described={"indexed": False, "message": "No events are indexed for this case yet."})
    nl_query.translate_natural_language_query(None, "case-1", "anything suspicious")
    assert "No events are indexed yet." in StubProvider.last_system


def test_strips_quotes_backticks_and_extra_lines(monkeypatch):
    _stub(monkeypatch, '`"risk_score>=70"`\nsome trailing explanation the model was told not to add')
    result = nl_query.translate_natural_language_query(None, "case-1", "high risk activity")
    assert result == "risk_score>=70"


def test_empty_model_answer_yields_an_empty_query(monkeypatch):
    _stub(monkeypatch, "")
    assert nl_query.translate_natural_language_query(None, "case-1", "hello") == ""
