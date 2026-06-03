import enum
from datetime import datetime

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class CaseAnalysisJobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class CaseAnalysisJob(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "case_analysis_jobs"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    analysis_type: Mapped[str] = mapped_column(String(64), nullable=False, default="semi_auto")
    status: Mapped[CaseAnalysisJobStatus] = mapped_column(Enum(CaseAnalysisJobStatus), nullable=False, default=CaseAnalysisJobStatus.queued)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_phase: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phases: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    parameters_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    result_json: Mapped[dict | None] = mapped_column(JSONVariant, nullable=True)
    metrics_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)

    case = relationship("Case", back_populates="analysis_jobs")
