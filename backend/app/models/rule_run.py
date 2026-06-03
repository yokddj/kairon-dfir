import enum

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class RuleRunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    stale = "stale"
    skipped = "skipped"


class RuleRun(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rule_runs"

    rule_id: Mapped[str | None] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_set_id: Mapped[str | None] = mapped_column(ForeignKey("rule_sets.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    engine: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[RuleRunStatus] = mapped_column(Enum(RuleRunStatus), default=RuleRunStatus.queued, nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(32), default="case", nullable=False)
    matched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_rules: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed_rules: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scanned_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_detections: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicates: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scanned_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    heartbeat_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    errors: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    started_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    rule = relationship("Rule", back_populates="rule_runs")
    rule_set = relationship("RuleSet", back_populates="rule_runs")
    case = relationship("Case", back_populates="rule_runs")
    evidence = relationship("Evidence", back_populates="rule_runs")
