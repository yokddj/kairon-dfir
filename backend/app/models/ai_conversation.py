"""Persisted assistant conversations, one thread per case per analyst.

Kept in Postgres rather than the browser so a thread survives a reload, and so
the reasoning behind a finding stays attached to the case for whoever picks it
up next. Conversations are scoped to their case and cascade with it: deleting a
case takes its assistant history with it, like every other case artifact.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class AiConversation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ai_conversations"

    case_id: Mapped[str] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Derived from the opening question so the sidebar reads like a list of
    # questions asked, not a list of UUIDs.
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="New conversation")
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    messages: Mapped[list["AiMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AiMessage.position",
    )


class AiMessage(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ai_messages"

    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Explicit ordering: two messages in the same second must still replay in
    # the order they were said.
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # What the assistant looked up for this turn, so the analyst can see which
    # queries produced an answer months later.
    lookups: Mapped[list | None] = mapped_column(JSONVariant, nullable=True)

    conversation: Mapped[AiConversation] = relationship(back_populates="messages")
