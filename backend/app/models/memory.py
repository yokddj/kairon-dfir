from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


MEMORY_SCAN_STATUSES = {
    "pending",
    "queued",
    "running",
    "completed",
    "completed_with_errors",
    "failed",
    "timed_out",
    "disabled",
    "backend_unavailable",
    "invalid_evidence",
    "cancelled",
}
MEMORY_PLUGIN_STATUSES = {"pending", "running", "completed", "failed", "timed_out"}


class MemoryUpload(UUIDMixin, Base):
    __tablename__ = "memory_uploads"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="validating", index=True)
    bytes_received: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    expected_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_host: Mapped[str] = mapped_column(String(255), nullable=False)
    extension: Mapped[str] = mapped_column(String(32), nullable=False)
    staging_name: Mapped[str] = mapped_column(String(255), nullable=False)
    canonical_relative_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    finalization_strategy: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lock_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    progress_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)

    __table_args__ = (Index("ix_memory_upload_case_updated", "case_id", "updated_at"),)


class MemoryScanRun(UUIDMixin, Base):
    __tablename__ = "memory_scan_runs"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    backend: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile: Mapped[str] = mapped_column(String(128), default="metadata_only", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    requested_plugin_count: Mapped[int] = mapped_column(default=0, nullable=False)
    plugin_count: Mapped[int] = mapped_column(default=0, nullable=False)
    plugins_completed: Mapped[int] = mapped_column(default=0, nullable=False)
    plugins_failed: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(nullable=True)
    output_dir: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    error_log: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    backend_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    worker_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancellation_requested: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="memory_scan_runs")
    evidence = relationship("Evidence", back_populates="memory_scan_runs")
    artifact_summaries = relationship("MemoryArtifactSummary", back_populates="memory_run", cascade="all, delete-orphan")
    plugin_runs = relationship("MemoryPluginRun", back_populates="memory_scan_run", cascade="all, delete-orphan")


class MemoryPluginRun(UUIDMixin, Base):
    __tablename__ = "memory_plugin_runs"

    memory_scan_run_id: Mapped[str] = mapped_column(ForeignKey("memory_scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    plugin: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(nullable=True)
    row_count: Mapped[int] = mapped_column(default=0, nullable=False)
    output_relative_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    output_size: Mapped[int | None] = mapped_column(nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    memory_scan_run = relationship("MemoryScanRun", back_populates="plugin_runs")
    case = relationship("Case")
    evidence = relationship("Evidence")


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
