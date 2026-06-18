from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


MEMORY_SCAN_STATUSES = {"pending", "ready", "disabled", "unsupported", "failed"}


class MemoryScanRun(UUIDMixin, Base):
    __tablename__ = "memory_scan_runs"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    backend: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile: Mapped[str] = mapped_column(String(128), default="metadata_only", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    plugin_count: Mapped[int] = mapped_column(default=0, nullable=False)
    plugins_completed: Mapped[int] = mapped_column(default=0, nullable=False)
    plugins_failed: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    output_dir: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    error_log: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="memory_scan_runs")
    evidence = relationship("Evidence", back_populates="memory_scan_runs")
    artifact_summaries = relationship("MemoryArtifactSummary", back_populates="memory_run", cascade="all, delete-orphan")


class MemoryArtifactSummary(UUIDMixin, Base):
    __tablename__ = "memory_artifact_summaries"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    memory_run_id: Mapped[str | None] = mapped_column(ForeignKey("memory_scan_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    memory_artifact_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    count: Mapped[int] = mapped_column(default=0, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="memory_artifact_summaries")
    evidence = relationship("Evidence", back_populates="memory_artifact_summaries")
    memory_run = relationship("MemoryScanRun", back_populates="artifact_summaries")
