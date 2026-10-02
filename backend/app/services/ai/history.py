"""Reading and writing persisted assistant conversations."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.ai_conversation import AiConversation, AiMessage

TITLE_MAX_CHARS = 120
LIST_LIMIT = 50


def _title_from(question: str) -> str:
    text = " ".join((question or "").split())
    if not text:
        return "New conversation"
    return text if len(text) <= TITLE_MAX_CHARS else text[: TITLE_MAX_CHARS - 1] + "…"


def start_or_resume(
    db: Session,
    *,
    case_id: str,
    conversation_id: str | None,
    user_id: str | None,
    question: str,
    provider: str | None,
    model: str | None,
) -> AiConversation:
    """Fetch the thread this turn belongs to, creating it on the first question."""
    if conversation_id:
        existing = (
            db.query(AiConversation)
            .filter(AiConversation.id == conversation_id, AiConversation.case_id == case_id)
            .one_or_none()
        )
        if existing is not None:
            existing.provider = provider or existing.provider
            existing.model = model or existing.model
            return existing

    conversation = AiConversation(
        case_id=case_id,
        user_id=user_id,
        title=_title_from(question),
        provider=provider,
        model=model,
    )
    db.add(conversation)
    db.flush()
    return conversation


def append_turn(
    db: Session,
    conversation: AiConversation,
    *,
    question: str,
    answer: str,
    lookups: list[dict] | None = None,
) -> None:
    """Record one question and its answer. Called once the stream has finished."""
    position = (
        db.query(AiMessage)
        .filter(AiMessage.conversation_id == conversation.id)
        .count()
    )
    db.add(AiMessage(conversation_id=conversation.id, role="user", content=question, position=position))
    db.add(
        AiMessage(
            conversation_id=conversation.id,
            role="assistant",
            content=answer,
            position=position + 1,
            lookups=lookups or None,
        )
    )
    db.commit()


def list_conversations(db: Session, case_id: str, *, user_id: str | None = None) -> list[dict]:
    query = db.query(AiConversation).filter(AiConversation.case_id == case_id)
    if user_id:
        query = query.filter(AiConversation.user_id == user_id)
    rows = query.order_by(AiConversation.updated_at.desc()).limit(LIST_LIMIT).all()
    return [
        {
            "id": row.id,
            "title": row.title,
            "provider": row.provider,
            "model": row.model,
            "message_count": len(row.messages),
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
        for row in rows
    ]


def get_conversation(db: Session, case_id: str, conversation_id: str) -> dict | None:
    row = (
        db.query(AiConversation)
        .filter(AiConversation.id == conversation_id, AiConversation.case_id == case_id)
        .one_or_none()
    )
    if row is None:
        return None
    return {
        "id": row.id,
        "title": row.title,
        "provider": row.provider,
        "model": row.model,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "lookups": m.lookups or [],
            }
            for m in row.messages
        ],
    }


def delete_conversation(db: Session, case_id: str, conversation_id: str) -> bool:
    row = (
        db.query(AiConversation)
        .filter(AiConversation.id == conversation_id, AiConversation.case_id == case_id)
        .one_or_none()
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True
