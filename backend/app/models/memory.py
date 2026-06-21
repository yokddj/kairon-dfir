from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
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
    batch_id: Mapped[str | None] = mapped_column(
        ForeignKey("memory_analysis_batches.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    batch_position: Mapped[int | None] = mapped_column(nullable=True)
    batch_total: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="memory_scan_runs")
    evidence = relationship("Evidence", back_populates="memory_scan_runs")
    artifact_summaries = relationship("MemoryArtifactSummary", back_populates="memory_run", cascade="all, delete-orphan")
    plugin_runs = relationship("MemoryPluginRun", back_populates="memory_scan_run", cascade="all, delete-orphan")

    @property
    def plugins_skipped(self) -> int:
        return sum(1 for item in self.plugin_runs if item.status == "skipped_dependency")


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


class MemorySymbolRequirement(UUIDMixin, Base):
    __tablename__ = "memory_symbol_requirements"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    source_run_id: Mapped[str] = mapped_column(ForeignKey("memory_scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_plugin_run_id: Mapped[str] = mapped_column(ForeignKey("memory_plugin_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    pdb_name: Mapped[str] = mapped_column(String(128), nullable=False)
    pdb_guid: Mapped[str] = mapped_column(String(32), nullable=False)
    pdb_age: Mapped[int] = mapped_column(nullable=False)
    # The age that was originally requested (typically the one Volatility's
    # windows.info plugin reported).  Preserved for audit even if pdb_age
    # is corrected to match a re-published PDB on Microsoft's symbol server.
    requested_pdb_age: Mapped[int | None] = mapped_column(nullable=True)
    # True when pdb_age was adjusted to match a re-published symbol whose
    # internal age differs from the requested age.  The cache key uses
    # the corrected age but the audit metadata keeps the requested one.
    age_corrected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    architecture: Mapped[str] = mapped_column(String(32), nullable=False)
    symbol_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unavailable_offline", index=True)
    acquisition_request_id: Mapped[str | None] = mapped_column(nullable=True, index=True)
    cached_symbol_id: Mapped[str | None] = mapped_column(nullable=True, index=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (UniqueConstraint("evidence_id", "pdb_name", "pdb_guid", "pdb_age", name="uq_memory_evidence_symbol_identity"),)


class MemorySymbolAcquisition(UUIDMixin, Base):
    __tablename__ = "memory_symbol_acquisitions"

    requirement_id: Mapped[str] = mapped_column(ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    source_category: Mapped[str] = mapped_column(String(64), nullable=False, default="official_microsoft_symbols")
    downloaded_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    pdb_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    isf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)


class MemoryCachedSymbol(UUIDMixin, Base):
    __tablename__ = "memory_cached_symbols"

    symbol_key: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    pdb_name: Mapped[str] = mapped_column(String(128), nullable=False)
    pdb_guid: Mapped[str] = mapped_column(String(32), nullable=False)
    pdb_age: Mapped[int] = mapped_column(nullable=False)
    architecture: Mapped[str] = mapped_column(String(32), nullable=False)
    pdb_relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    isf_relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    pdb_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    isf_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    pdb_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    isf_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="validated")
    source_category: Mapped[str] = mapped_column(String(64), nullable=False, default="official_microsoft_symbols")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)


class MemorySymbolAcquisitionRequest(UUIDMixin, Base):
    __tablename__ = "memory_symbol_acquisition_requests"

    requirement_id: Mapped[str] = mapped_column(ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="awaiting_network_isolation", index=True)
    source_category: Mapped[str] = mapped_column(String(64), nullable=False, default="official_microsoft_symbols")
    requirement_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    approval_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    approval_consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    downloaded_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    redirect_count: Mapped[int] = mapped_column(nullable=False, default=0)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_memory_symbol_req_requirement", "requirement_id"),
        Index("ix_memory_symbol_req_status_updated", "status", "updated_at"),
    )


class MemorySymbolApproval(UUIDMixin, Base):
    __tablename__ = "memory_symbol_approvals"

    request_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_acquisition_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requirement_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    actor_category: Mapped[str] = mapped_column(String(64), nullable=False, default="local_operator")
    actor_label: Mapped[str] = mapped_column(String(128), nullable=False, default="server-operator")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    audit_metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_memory_symbol_approval_status_expires", "status", "expires_at"),
        Index("ix_memory_symbol_approval_request_status", "request_id", "status"),
    )


MEMORY_BATCH_STATUSES = {
    "queued",
    "running",
    "completed",
    "completed_with_errors",
    "failed",
    "cancelled",
}

MEMORY_BATCH_MODES = {"missing_or_failed", "rerun_all"}


class MemoryAnalysisBatch(UUIDMixin, Base):
    """A server-side orchestrated batch of memory scan profiles.

    A batch is created via ``POST .../memory/evidences/{evidence_id}/run-all``
    and executes its profiles sequentially (never in parallel).  The
    batch is scoped to a single ``evidence_id``: cross-evidence state
    is not allowed.

    A batch enqueues only the FIRST profile.  When that profile's
    ``MemoryScanRun`` reaches a terminal state, the worker callback
    advances the batch by enqueuing the next profile.  A new batch
    is rejected (HTTP 409) while another batch is still active for
    the same evidence.
    """

    __tablename__ = "memory_analysis_batches"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="missing_or_failed")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    requested_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    skipped_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    current_profile: Mapped[str | None] = mapped_column(String(64), nullable=True)
    completed_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    failed_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    continue_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancellation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authorization_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authorization_acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    audit_metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), default=utc_now_naive, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    # Runtime-safety fields added by the versioned migration v2.
    version: Mapped[int] = mapped_column(default=1, nullable=False)
    last_advanced_run_id: Mapped[str | None] = mapped_column(nullable=True)
    last_advanced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="server-operator", nullable=False)

    case = relationship("Case")
    evidence = relationship("Evidence")

    __table_args__ = (
        Index("ix_memory_batch_evidence_status", "evidence_id", "status"),
        Index("ix_memory_batch_case_created", "case_id", "created_at"),
    )
