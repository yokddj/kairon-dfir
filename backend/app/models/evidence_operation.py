from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class EvidenceOperation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence_operations"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    upload_session_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_upload_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    stage: Mapped[str] = mapped_column(String(64), nullable=False, default="created")
    owner: Mapped[str] = mapped_column(String(32), nullable=False, default="backend")
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expected_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)


class EvidenceOperationJob(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence_operation_jobs"
    __table_args__ = (UniqueConstraint("operation_id", "job_type", "dedupe_key", name="uq_evidence_operation_jobs_dedupe"),)

    operation_id: Mapped[str] = mapped_column(ForeignKey("evidence_operations.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    upload_session_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_upload_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    job_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner: Mapped[str] = mapped_column(String(32), nullable=False, default="worker")
    rq_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
