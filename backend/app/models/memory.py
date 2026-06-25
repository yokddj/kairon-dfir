from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
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
    # Registration recovery lifecycle (migration v9).
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    registration_state: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    registration_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    last_registration_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_registration_error_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    canonical_preserved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
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
    # Canonical materialization lifecycle.  A run that has raw observations
    # but no canonical materialization is NOT eligible as the active
    # result for the processes family.
    canonical_materialization_status: Mapped[str] = mapped_column(
        String(32), default="not_required", nullable=False
    )
    canonical_entity_count: Mapped[int] = mapped_column(default=0, nullable=False)
    canonical_observation_count: Mapped[int] = mapped_column(default=0, nullable=False)
    canonical_root_count: Mapped[int] = mapped_column(default=0, nullable=False)
    canonical_orphan_count: Mapped[int] = mapped_column(default=0, nullable=False)
    canonical_scan_only_count: Mapped[int] = mapped_column(default=0, nullable=False)
    canonical_materialization_error: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    canonical_materialization_version: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    canonical_materialized_at: Mapped[datetime | None] = mapped_column(nullable=True)
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


class MemoryEvidenceContent(UUIDMixin, Base):
    """Stable content identity for a memory evidence.

    A memory evidence's ``evidence_id`` is regenerated whenever the
    operator re-uploads the same file (or whenever the case is
    re-built).  The content identity — ``evidence_sha256`` plus
    ``size_bytes`` — is stable across re-uploads and is the
    cross-case correlation key for symbol readiness reuse.

    Multiple ``MemoryEvidence`` rows can share the same
    ``MemoryEvidenceContent`` (one per case + one per ingestion);
    the content identity is the bridge between the per-case
    evidence view and the global symbol cache.
    """

    __tablename__ = "memory_evidence_contents"

    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Optional: capture additional acquisition metadata that
    # survives re-uploads (acquisition host, tool, capture date).
    acquisition_metadata: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    # Cached readiness summary so subsequent re-uploads of the
    # same file can short-circuit the catalogue without recomputing
    # the requirement.
    last_readiness: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    last_requirement_id: Mapped[str | None] = mapped_column(nullable=True, index=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (UniqueConstraint("evidence_sha256", "size_bytes", name="uq_memory_content_identity"),)


class MemoryEvidenceSymbolLink(UUIDMixin, Base):
    """Per-evidence link to a Windows symbol requirement.

    Decouples evidence identity from requirement identity.  Several
    evidences (same file, different cases) can share the same
    requirement without duplicating the cache row.
    """

    __tablename__ = "memory_evidence_symbol_links"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    requirement_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # How the link was established: "probe", "cache_reuse_by_hash",
    # "backfill_history", "operator".
    link_source: Mapped[str] = mapped_column(String(32), nullable=False, default="probe")
    # Per-evidence state in the preparation pipeline.  The global
    # state lives on the requirement; the per-evidence state is a
    # snapshot of the latest preparation step for THIS evidence.
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_transition_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive
    )
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        UniqueConstraint("evidence_id", "requirement_id", name="uq_memory_evidence_symbol_link"),
    )


class MemorySymbolPreparation(UUIDMixin, Base):
    """Per-evidence preparation task (probe / cache check / acquisition).

    Each row represents the *latest* preparation attempt for a given
    evidence.  The row is created on upload (auto-probe), on
    confirmation, on reconciliation and on demand.
    """

    __tablename__ = "memory_symbol_preparations"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    # The state values (single source of truth):
    #   queued                       - waiting to be picked up
    #   probing                      - the read-only probe is in flight
    #   identified                   - PDB/GUID/age identified
    #   cache_hit                    - exact cache match found
    #   acquisition_pending          - operator approval awaited
    #   acquiring                    - download in progress
    #   isf_creation                 - PDB->ISF conversion in progress
    #   ready                        - offline-ready (cache hit or ISF built)
    #   requirement_unknown          - probe could not identify a symbol
    #   acquisition_failed           - download / validation failed
    #   unsupported                  - OS / arch / plugin not supported
    #   negative_cached              - this exact symbol is not available
    #                                 at the configured source
    #   cancelled                    - cancelled by the operator
    state_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requirement_id: Mapped[str | None] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Cooldown: when the next probe may run (negative cache TTL).
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True, index=True)
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    worker_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Queue that owns the worker task.  Sprint 6 (OS-agnostic
    # preparation) documents one documented queue per process
    # boundary so the diagnostics endpoint can detect
    # mismatches between the API and the memory-worker.
    queue_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)
    # Reconciliation fields (v1 stabilization).
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    current_step: Mapped[str | None] = mapped_column(String(64), nullable=True)
    progress_percent: Mapped[int] = mapped_column(nullable=False, default=0)
    source_of_truth: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    # Active flag: only one preparation row per evidence can be
    # ``active=True`` at a time.  Historical rows stay in the table
    # for audit and may have ``active=False``.
    active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)

    __table_args__ = (
        Index("ix_memory_symbol_prep_evidence_state", "evidence_id", "state"),
        Index("ix_memory_symbol_prep_state_updated", "state", "updated_at"),
        # Partial index (PostgreSQL) ensures the active-row lookup
        # is fast; SQLite ignores the WHERE clause but the index is
        # still valid.
        Index(
            "uq_memory_symbol_prep_active_evidence",
            "evidence_id",
            unique=True,
            postgresql_where=sa.text("active = true"),
            sqlite_where=sa.text("active = 1"),
        ),
    )


class MemorySymbolNegativeCache(UUIDMixin, Base):
    """Cooldown records for symbols that are NOT available.

    Prevents the system from hammering the symbol source for
    symbols the source does not have (e.g. Windows XP era PDBs that
    are no longer distributed).
    """

    __tablename__ = "memory_symbol_negative_cache"

    symbol_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True, unique=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="official_microsoft_symbols")
    error_code: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    attempts: Mapped[int] = mapped_column(nullable=False, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)


class MemorySymbolPendingAnalysis(UUIDMixin, Base):
    """Operator-intent row for "Run when ready".

    When the user presses Run analysis or Run all before the
    symbol preparation pipeline is ready, an intent row is
    recorded.  When the per-evidence preparation reaches
    ``ready``, the intent is materialised into a real
    ``MemoryScanRun`` (or ``MemoryAnalysisBatch``) and the intent
    row is consumed.  Cancellable.
    """

    __tablename__ = "memory_symbol_pending_analysis"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # "single_profile" | "run_all"
    profile: Mapped[str | None] = mapped_column(String(64), nullable=True)  # for single_profile
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="missing_or_failed")
    requested_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    # When the materialization runs, the resulting batch / run is
    # recorded here for audit.
    materialized_batch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    materialized_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        Index("ix_memory_symbol_pending_evidence_status", "evidence_id", "status"),
    )


class MemorySymbolRequirement(UUIDMixin, Base):
    __tablename__ = "memory_symbol_requirements"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    source_run_id: Mapped[str | None] = mapped_column(ForeignKey("memory_scan_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    source_plugin_run_id: Mapped[str | None] = mapped_column(ForeignKey("memory_plugin_runs.id", ondelete="CASCADE"), nullable=True, index=True)
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
    # Legacy symbol-readiness recovery: which source produced this row.
    # One of: "probe", "historical_run", "historical_plugin_run",
    # "historical_system_info", "historical_process_metadata",
    # "cache_match", or None for legacy rows.
    source: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    reconstructed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    backfill_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    # The "owned" by link: when the same requirement is shared by
    # multiple evidences, only one of them is the canonical owner
    # (the one that triggered the original probe).  Other evidences
    # have a link with link_source="cache_reuse_by_hash".
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        UniqueConstraint("evidence_id", "pdb_name", "pdb_guid", "pdb_age", name="uq_memory_evidence_symbol_identity"),
        Index("ix_memory_symbol_requirement_symbol_key", "symbol_key"),
        Index("ix_memory_symbol_requirement_status", "status"),
    )


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
    # Observed identity from the downloaded file, populated when the
    # acquisition reaches validating_pdb.  Stays NULL if the download
    # failed before the identity could be read.  Used for diagnostic
    # surfaces so the operator can see exactly which GUID/age the
    # Microsoft symbol server actually returned vs. the requirement.
    observed_pdb_guid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    observed_pdb_age: Mapped[int | None] = mapped_column(nullable=True)
    observed_architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    # Provenance for the Exact Symbol Recovery Sources v1 feature.
    # These columns are safe to expose to analysts: the secret
    # value (if any) is never stored on this row.
    provenance_source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="microsoft_public")
    provenance_source_name: Mapped[str] = mapped_column(String(128), nullable=False, default="Microsoft public")
    provenance_actor: Mapped[str] = mapped_column(String(128), nullable=False, default="server-operator")
    provenance_acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
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

MEMORY_BATCH_MODES = {"missing_or_failed", "rerun_all", "runtime_validation"}


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
    # ``last_advanced_run_id`` references ``memory_scan_runs.id``,
    # which is a native UUID in PostgreSQL and a string in Python.
    # We declare it explicitly as ``PgUUID(as_uuid=True)`` so the
    # SQLAlchemy type matches the database column.  ``as_uuid=True``
    # would convert to ``uuid.UUID`` in Python, but ``UUIDMixin``
    # uses ``as_uuid=False`` (Python str) everywhere, so we mirror
    # that to keep the comparison ``batch.last_advanced_run_id ==
    # run.id`` working without manual casts.  Migration v11 aligns
    # the column type on PostgreSQL.
    last_advanced_run_id: Mapped[str | None] = mapped_column(PgUUID(as_uuid=False), nullable=True)
    last_advanced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="server-operator", nullable=False)

    case = relationship("Case")
    evidence = relationship("Evidence")

    __table_args__ = (
        Index("ix_memory_batch_evidence_status", "evidence_id", "status"),
        Index("ix_memory_batch_case_created", "case_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Exact Symbol Recovery Sources v1
# ---------------------------------------------------------------------------

MEMORY_RECOVERY_SOURCE_TYPES = {
    "microsoft_public",
    "corporate_symbol_server",
    "manual_pdb_import",
    "manual_isf_import",
    "offline_symbol_package",
}

MEMORY_RECOVERY_SOURCE_NAMES = {
    "microsoft_public": "Microsoft public",
    "corporate_symbol_server": "Corporate symbol server",
    "manual_pdb_import": "Administrator-imported PDB",
    "manual_isf_import": "Administrator-imported ISF",
    "offline_symbol_package": "Offline package",
}


class MemorySymbolRecoverySource(UUIDMixin, Base):
    """Administrator-configured recovery source for exact symbols.

    Every successful symbol recovery must satisfy exact identity
    validation (PDB name, GUID, age, architecture, Volatility
    usability).  No recovery source may supply an approximate or
    same-name symbol.

    Persistence rules:
    * Only safe metadata is stored.  Plaintext credentials,
      internal hostnames, bearer tokens, and full URLs are never
      stored on this row.
    * ``host`` and ``path_prefix`` are the only network-address
      fields; they are admin-supplied and frozen at creation time
      (the spec forbids runtime mutation that would let an
      attacker redirect the egress).
    * The actual outbound secret (if any) is referenced through
      the project secret mechanism via ``credential_secret_name``
      (the canonical name of a secret stored in
      ``memory_symbol_egress_gateway_secret`` / a dedicated
      env-var lookup).  The secret value is never copied to this
      row.
    """

    __tablename__ = "memory_symbol_recovery_sources"

    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    priority: Mapped[int] = mapped_column(nullable=False, default=100, index=True)
    # Corporate symbol server only — frozen at creation time.
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(nullable=True)
    path_prefix: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tls_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Name of the secret used to authenticate to the source.  The
    # secret value itself is never persisted on this row.
    credential_secret_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Admin / audit fields.  ``configured_by`` is a server-side
    # label only; the system does not currently provide an
    # authenticated administrator role, so the value comes from
    # the deployment host (operator label or "server-operator").
    configured_by: Mapped[str] = mapped_column(String(128), nullable=False, default="server-operator")
    note: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        Index("ix_memory_recovery_source_enabled_priority", "enabled", "priority"),
        UniqueConstraint("source_type", "name", name="uq_memory_recovery_source_type_name"),
    )


class MemorySymbolRecoveryAttempt(UUIDMixin, Base):
    """One per-source per-requirement attempt record.

    Written by the recovery orchestrator.  The UI uses this table
    to render the "Microsoft public → pending / Corporate symbol
    server → succeeded / …" attempt log the operator sees on the
    blocked-symbols evidence page.

    Safe to expose to analysts: the secret value (if any) is never
    stored on this row.  ``sanitized_message`` is a short
    pre-sanitised summary written by the orchestrator.

    Active-attempt uniqueness is enforced by a partial unique
    index in migration v16: at most one row per
    ``(requirement_id, source_type)`` may have a NULL
    ``terminal_at``.  Multiple terminal rows are allowed; the
    operator may retry by creating a new active row.
    """

    __tablename__ = "memory_symbol_recovery_attempts"

    requirement_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id: Mapped[str | None] = mapped_column(
        ForeignKey("memory_symbol_recovery_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_label: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # NULL while the attempt is active (pending / in-flight).
    # Set to ``utc_now_naive()`` when the attempt reaches a
    # terminal state (``succeeded`` / ``failed`` / ``skipped``).
    terminal_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True, index=True,
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sanitized_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)

    __table_args__ = (
        Index("ix_memory_recovery_attempt_requirement", "requirement_id"),
        Index("ix_memory_recovery_attempt_case_evidence", "case_id", "evidence_id"),
        # Partial unique index: at most one active attempt per
        # ``(requirement_id, source_type)`` tuple.  Multiple
        # terminal rows are allowed (operator retry).  The
        # partial index is created in migration v16.
        Index(
            "uq_memory_recovery_attempt_active",
            "requirement_id",
            "source_type",
            unique=True,
            postgresql_where=sa.text("terminal_at IS NULL"),
            sqlite_where=sa.text("terminal_at IS NULL"),
        ),
    )
