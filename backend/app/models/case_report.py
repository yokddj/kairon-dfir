import enum
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class CaseReportStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    completed_with_warnings = "completed_with_warnings"
    completed_with_errors = "completed_with_errors"
    failed = "failed"
    cancelled = "cancelled"
    draft = "draft"
    generated = "generated"
    archived = "archived"


class CaseReport(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "case_reports"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[CaseReportStatus] = mapped_column(Enum(CaseReportStatus), default=CaseReportStatus.draft, nullable=False)
    template: Mapped[str] = mapped_column(String(128), nullable=False, default="standard_investigation")
    report_type: Mapped[str] = mapped_column(String(64), nullable=False, default="investigation")
    format: Mapped[str] = mapped_column(String(32), nullable=False, default="markdown")
    mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ingest_run_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    time_range: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    filters: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    sections_enabled: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    analyst_notes: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    selected_finding_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    selected_key_event_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    selected_process_chain_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    include_raw_appendix: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    include_debug_metadata: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    case = relationship("Case", back_populates="reports")
