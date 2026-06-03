from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class EventMarking(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "event_markings"
    __table_args__ = (UniqueConstraint("case_id", "event_id", name="uq_event_marking_case_event"),)

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    stable_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    search_doc_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    artifact_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="unreviewed", nullable=False, index=True)
    labels: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(255), default="analyst", nullable=True)
