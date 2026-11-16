import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.database import Base, TimestampMixin, UUIDMixin


class TimelineBookmarkCategory(str, enum.Enum):
    execution = "execution"
    download = "download"
    detection = "detection"
    persistence = "persistence"
    network = "network"
    cleanup = "cleanup"
    other = "other"


class TimelineBookmarkImportance(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TimelineBookmark(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "timeline_bookmarks"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    stable_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[TimelineBookmarkCategory] = mapped_column(Enum(TimelineBookmarkCategory), default=TimelineBookmarkCategory.other, nullable=False)
    importance: Mapped[TimelineBookmarkImportance] = mapped_column(Enum(TimelineBookmarkImportance), default=TimelineBookmarkImportance.medium, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    order_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    include_in_report: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    remap_status: Mapped[str] = mapped_column(String(32), default="current", nullable=False)

    @validates("title", "created_by")
    def _fit_column(self, key: str, value: str | None) -> str | None:
        # A key event's title defaults to the event's message, which for some sources (a Defender
        # detection with its full resource path, a long command line) is far longer than the
        # column: saving it failed with a 500. The full text stays in summary.
        limit = 255
        if value is not None and len(value) > limit:
            return value[: limit - 1] + "\u2026"
        return value
