from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class IncidentTimelineDraft(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "incident_timeline_drafts"

    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    option_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    cache_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    builder_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    data_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="fresh", index=True)
    generated_by: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    sources: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    filters: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    phases: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    generation_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary_metadata: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
