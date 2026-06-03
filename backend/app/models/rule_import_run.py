import enum

from sqlalchemy import Boolean, Enum, ForeignKey, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class RuleImportRunStatus(str, enum.Enum):
    queued = "queued"
    uploading = "uploading"
    extracting = "extracting"
    parsing = "parsing"
    validating = "validating"
    compiling = "compiling"
    saving = "saving"
    completed = "completed"
    completed_with_warnings = "completed_with_warnings"
    cancelled = "cancelled"
    failed = "failed"


class RuleImportRun(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rule_import_runs"

    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    engine: Mapped[str] = mapped_column(String(32), nullable=False, index=True, default="unknown")
    source_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="single_file")
    uploaded_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pack_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[RuleImportRunStatus] = mapped_column(Enum(RuleImportRunStatus), nullable=False, default=RuleImportRunStatus.queued, index=True)
    started_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cancelled_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    elapsed_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_rules_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed_rules: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    imported_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    invalid_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    compiled_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unsupported_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    warning_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    warnings_summary: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    errors_summary: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    created_rule_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    updated_rule_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    duplicate_rule_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    invalid_items: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    unsupported_items: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    import_options: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    details_json: Mapped[dict] = mapped_column("details", JSONVariant, default=dict, nullable=False)
