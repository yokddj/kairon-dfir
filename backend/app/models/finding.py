import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class FindingSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    new = "new"
    reviewed = "reviewed"
    dismissed = "dismissed"
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    closed = "closed"


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), default=FindingSeverity.info, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.new, nullable=False)
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    detection_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    correlation_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    time_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timeline: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_event_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_stable_event_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_artifact_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_evidence_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_process_node_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_files: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_domains: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_ips: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_users: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_hosts: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    reasons: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    mitre: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    recommended_triage: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    data_quality: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    case = relationship("Case", back_populates="findings")
