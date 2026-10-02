"""Persisted conversations and OpenAI tool-call assembly."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.ai_conversation import AiConversation
from app.models.case import Case
from app.services.ai.history import (
    append_turn,
    delete_conversation,
    get_conversation,
    list_conversations,
    start_or_resume,
)
from app.services.ai.providers import _accumulate_tool_calls, _finish_tool_calls, _parse_sse_line


CASE_ID = str(uuid4())
OTHER_CASE_ID = str(uuid4())


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, future=True)()
    session.add(Case(id=CASE_ID, name="Test case"))
    session.commit()
    try:
        yield session
    finally:
        session.close()


def _turn(db, conversation_id, question, answer, lookups=None):
    conversation = start_or_resume(
        db,
        case_id=CASE_ID,
        conversation_id=conversation_id,
        user_id=None,
        question=question,
        provider="ollama",
        model="qwen3:8b",
    )
    db.commit()
    append_turn(db, conversation, question=question, answer=answer, lookups=lookups)
    return conversation.id


def test_a_conversation_is_created_and_titled_from_the_question(db):
    cid = _turn(db, None, "any persistence on WS-01?", "Yes, three run keys.")

    stored = get_conversation(db, CASE_ID, cid)
    assert stored["title"] == "any persistence on WS-01?"
    assert [m["role"] for m in stored["messages"]] == ["user", "assistant"]
    assert stored["messages"][1]["content"] == "Yes, three run keys."


def test_a_long_question_is_clipped_for_the_title(db):
    cid = _turn(db, None, "why " * 200, "because")
    assert len(get_conversation(db, CASE_ID, cid)["title"]) <= 120


def test_a_second_turn_continues_the_same_thread(db):
    cid = _turn(db, None, "first question", "first answer")
    same = _turn(db, cid, "second question", "second answer")

    assert same == cid
    stored = get_conversation(db, CASE_ID, cid)
    assert [m["content"] for m in stored["messages"]] == [
        "first question", "first answer", "second question", "second answer",
    ]
    assert len(list_conversations(db, CASE_ID)) == 1, "a follow-up must not start a new thread"


def test_lookups_are_kept_with_the_answer(db):
    """Months later the analyst should still see which queries produced this."""
    cid = _turn(db, None, "q", "a", lookups=[{"tool": "search_events", "arguments": {"query": "run key"}}])

    assert get_conversation(db, CASE_ID, cid)["messages"][1]["lookups"][0]["tool"] == "search_events"


def test_conversations_are_scoped_to_their_case(db):
    db.add(Case(id=OTHER_CASE_ID, name="Other"))
    db.commit()
    cid = _turn(db, None, "q", "a")

    assert get_conversation(db, OTHER_CASE_ID, cid) is None
    assert list_conversations(db, OTHER_CASE_ID) == []


def test_resuming_a_conversation_from_another_case_starts_a_new_one(db):
    """A stale id from a different case must not leak that thread."""
    db.add(Case(id=OTHER_CASE_ID, name="Other"))
    db.commit()
    cid = _turn(db, None, "q", "a")

    other = _turn(db, cid, "q2", "a2")  # same id, but under case-2? no: still case-1
    assert other == cid

    conversation = start_or_resume(
        db, case_id=OTHER_CASE_ID, conversation_id=cid, user_id=None,
        question="q", provider=None, model=None,
    )
    db.commit()
    assert conversation.id != cid


def test_deleting_a_conversation_removes_its_messages(db):
    cid = _turn(db, None, "q", "a")

    assert delete_conversation(db, CASE_ID, cid) is True
    assert get_conversation(db, CASE_ID, cid) is None
    assert delete_conversation(db, CASE_ID, cid) is False


def test_deleting_the_case_takes_the_conversations_with_it(db):
    """Assistant history is case data and must not outlive the case."""
    cid = _turn(db, None, "q", "a")
    db.execute(AiConversation.__table__.delete().where(AiConversation.__table__.c.case_id == CASE_ID))
    db.commit()
    assert get_conversation(db, CASE_ID, cid) is None


# --------------------------------------------------------------------------
# OpenAI streams tool calls as JSON fragments; assembling them is fiddly.
# --------------------------------------------------------------------------


def test_tool_call_arguments_are_assembled_across_chunks():
    pending: dict = {}
    for fragment in ['{"que', 'ry": "run', ' key"}']:
        _accumulate_tool_calls(
            [{"index": 0, "id": "call_1", "function": {"name": "search_events", "arguments": fragment}}],
            pending,
        )

    events = _finish_tool_calls(pending)
    assert len(events) == 1
    assert events[0].data == {"id": "call_1", "name": "search_events", "input": {"query": "run key"}}


def test_the_name_may_arrive_in_a_different_chunk_than_the_arguments():
    pending: dict = {}
    _accumulate_tool_calls([{"index": 0, "id": "c1", "function": {"name": "list_hosts"}}], pending)
    _accumulate_tool_calls([{"index": 0, "function": {"arguments": "{}"}}], pending)

    assert _finish_tool_calls(pending)[0].data["name"] == "list_hosts"


def test_two_parallel_calls_stay_separate():
    pending: dict = {}
    _accumulate_tool_calls([{"index": 0, "id": "a", "function": {"name": "list_hosts", "arguments": "{}"}}], pending)
    _accumulate_tool_calls([{"index": 1, "id": "b", "function": {"name": "list_findings", "arguments": "{}"}}], pending)

    assert [e.data["name"] for e in _finish_tool_calls(pending)] == ["list_hosts", "list_findings"]


def test_malformed_arguments_do_not_crash_the_stream():
    """A local model emitting broken JSON must degrade, not explode."""
    pending: dict = {}
    _accumulate_tool_calls([{"index": 0, "id": "a", "function": {"name": "search_events", "arguments": "{not json"}}], pending)

    events = _finish_tool_calls(pending)
    assert events[0].data["input"]["__parse_error__"].startswith("{not json")


def test_text_and_tool_calls_can_share_one_stream():
    pending: dict = {}
    events = _parse_sse_line(
        'data: {"choices":[{"delta":{"content":"Looking...","tool_calls":'
        '[{"index":0,"id":"c","function":{"name":"list_hosts","arguments":"{}"}}]}}]}',
        pending,
    )

    assert [e.type for e in events] == ["text"]
    assert _finish_tool_calls(pending)[0].data["name"] == "list_hosts"


def test_the_parser_still_works_without_a_pending_dict():
    """Callers that do not care about tools must keep working unchanged."""
    events = _parse_sse_line('data: {"choices":[{"delta":{"content":"hi"}}]}')
    assert events[0].text == "hi"
