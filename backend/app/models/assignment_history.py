from uuid import uuid4

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, UUIDMixin


class AssignmentHistory(UUIDMixin, Base):
    __tablename__ = "assignment_history"

    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    previous_host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id"), nullable=True)
    new_host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id"), nullable=True)
    previous_status: Mapped[str | None] = mapped_column(String, nullable=True)
    new_status: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[str | None] = mapped_column(String, nullable=True)
    actor: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at_str: Mapped[str | None] = mapped_column("created_at", String, nullable=True)
