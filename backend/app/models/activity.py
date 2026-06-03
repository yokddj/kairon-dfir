import enum
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


class ActivitySeverity(str, enum.Enum):
    info = "info"
    warning = "warning"
    error = "error"


class AppActivityEvent(UUIDMixin, Base):
    __tablename__ = "app_activity_events"

    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True, default="system")
    activity_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[ActivitySeverity] = mapped_column(Enum(ActivitySeverity), default=ActivitySeverity.info, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False, index=True)

    case = relationship("Case", back_populates="activity_events")
    evidence = relationship("Evidence", back_populates="activity_events")
