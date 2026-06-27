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
    expected_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_host: Mapped[str] = mapped_column(String(255), nullable=False)
    extension: Mapped[str] = mapped_column(String(32), nullable=False)
    staging_name: Mapped[str] = mapped_column(String(255), nullable=False)
    canonical_relative_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    chunk_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_chunks: Mapped[int] = mapped_column(nullable=False, default=0)
    received_chunk_count: Mapped[int] = mapped_column(nullable=False, default=0)
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
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True, index=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)

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
    # Trust domain for the run.  ``validated`` runs are produced by
    # exact symbol matches and may be used by validated forensic
    # views; ``experimental`` runs use a mismatched symbol and are
    # kept in an isolated trust domain.  Default is ``validated`` for
    # every existing run created before the experimental feature.
    # See ``app/services/memory/experimental_trust.py`` for the
    # single source of truth on the trust boundary.
    analysis_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="validated", index=True
    )
    trust_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="validated", index=True
    )
    symbol_match_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="exact", index=True
    )
    experimental_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("memory_experimental_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="memory_scan_runs")
    evidence = relationship("Evidence", back_populates="memory_scan_runs")
    artifact_summaries = relationship("MemoryArtifactSummary", back_populates="memory_run", cascade="all, delete-orphan")
    plugin_runs = relationship("MemoryPluginRun", back_populates="memory_scan_run", cascade="all, delete-orphan")
    experimental_run = relationship("MemoryExperimentalRun", foreign_keys=[experimental_run_id])

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
    # Trust fields (mirror ``MemoryScanRun``).  All validated
    # MemoryPluginRun rows default to ``validated`` trust; the
    # experimental flow writes ``untrusted``.
    analysis_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="validated", index=True
    )
    trust_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="validated", index=True
    )
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
    # Cache classification for the Experimental Mismatched-Symbol
    # Analysis v1 feature.  ``exact`` rows are produced by the
    # exact-symbol path and are the only rows that satisfy the
    # standard readiness contract.  ``experimental_candidate`` rows
    # carry a same-name/same-GUID/age-mismatch symbol and may only
    # be used by the experimental run flow.  The default is
    # ``exact``; new columns are added in migration v17.
    cache_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="exact", index=True
    )
    # When ``cache_classification = "experimental_candidate"`` the
    # cache row records the *required* identity (PDB name, GUID,
    # age, architecture) the candidate was created for.  This is
    # the only way the experimental run can verify that the symbol
    # it consumes is the one the operator approved.
    required_pdb_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    required_pdb_guid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    required_pdb_age: Mapped[int | None] = mapped_column(nullable=True)
    required_architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
        # Database-enforced invariant: at most one active batch per
        # (case, evidence).  Terminal states (completed, failed,
        # cancelled) are excluded so a new batch may start after the
        # previous one reaches a terminal state.  The companion
        # migration creates the matching index on existing databases.
        Index(
            "uq_memory_analysis_batches_one_active",
            "case_id",
            "evidence_id",
            unique=True,
            postgresql_where=sa.text(
                "status IN ('queued', 'running')"
            ),
            sqlite_where=sa.text(
                "status IN ('queued', 'running')"
            ),
        ),
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
    # Operator-only CLI import.  Reachable only through
    # ``python -m app.cli.memory_symbols import-pdb`` /
    # ``import-isf``; no HTTP route mounts these source types
    # and no frontend control references them.
    "operator_cli_pdb",
    "operator_cli_isf",
}

MEMORY_RECOVERY_SOURCE_NAMES = {
    "microsoft_public": "Microsoft public",
    "corporate_symbol_server": "Corporate symbol server",
    "manual_pdb_import": "Administrator-imported PDB",
    "manual_isf_import": "Administrator-imported ISF",
    "offline_symbol_package": "Offline package",
    "operator_cli_pdb": "Operator CLI PDB import",
    "operator_cli_isf": "Operator CLI ISF import",
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


# ---------------------------------------------------------------------------
# Experimental Mismatched-Symbol Analysis v1
# ---------------------------------------------------------------------------

# Trust fields and run states for the experimental analysis mode.  These
# constants are the single source of truth for the trust domain boundary
# between validated forensic analysis and experimental, untrusted
# mismatched-symbol analysis.  The same constants are referenced from
# ``app/services/memory/experimental_trust.py``.
EXPERIMENTAL_ANALYSIS_MODES = {"validated", "experimental"}
EXPERIMENTAL_TRUST_LEVELS = {"validated", "untrusted"}
EXPERIMENTAL_SYMBOL_MATCH_TYPES = {
    "exact",
    "guid_only_age_mismatch",
}
EXPERIMENTAL_RUN_STATUSES = {
    "candidate_unavailable",
    "acknowledgement_required",
    "canary_queued",
    "canary_running",
    "canary_passed",
    "canary_degraded",
    "canary_failed",
    "canary_inconclusive",
    "full_run_queued",
    "full_run_running",
    "completed_untrusted",
    "partial_untrusted",
    "failed_untrusted",
    "cancelled",
    "deleted",
}
EXPERIMENTAL_CANARY_STATUSES = {
    "pending",
    "running",
    "passed",
    "degraded",
    "failed",
    "inconclusive",
    "skipped",
}
EXPERIMENTAL_ACK_WARNING_VERSION = "experimental-mismatch-ack-v1"


class MemoryExperimentalSymbolCandidate(UUIDMixin, Base):
    """A mismatched Windows symbol candidate eligible for experimental runs.

    The candidate represents a same-name / same-GUID / age-mismatch /
    compatible-architecture PDB or ISF that the operator has supplied
    for *triage-only* analysis.  The candidate is NEVER linked to a
    ``MemorySymbolRequirement`` and NEVER changes the requirement's
    ``pdb_age``.  A candidate only exists while its parent
    ``MemorySymbolRequirement`` remains ``blocked_symbols``.

    The candidate is created in the operator CLI path
    (``app/cli/memory_symbols.py``) and exposed read-only through
    the API.  It is *not* visible in the standard analyst views.
    """

    __tablename__ = "memory_experimental_symbol_candidates"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    # The exact-symbol requirement this candidate was created for.  The
    # requirement is never mutated; the candidate simply lives in a
    # separate trust domain.
    requirement_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The cache row carrying the candidate symbol; classification
    # MUST be ``experimental_candidate``.  We denormalise
    # ``required_*`` columns for fast trust verification.
    cached_symbol_id: Mapped[str] = mapped_column(
        ForeignKey("memory_cached_symbols.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Required identity (from the requirement).
    required_pdb_name: Mapped[str] = mapped_column(String(128), nullable=False)
    required_pdb_guid: Mapped[str] = mapped_column(String(32), nullable=False)
    required_pdb_age: Mapped[int] = mapped_column(nullable=False)
    required_architecture: Mapped[str] = mapped_column(String(32), nullable=False)
    # Observed identity (from the cached symbol).
    observed_pdb_name: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_pdb_guid: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_pdb_age: Mapped[int] = mapped_column(nullable=False)
    observed_architecture: Mapped[str] = mapped_column(String(32), nullable=False)
    symbol_match_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # The exact mismatch observed.  ``guid_only_age_mismatch`` is
    # the only allowed match type for now.
    symbol_warning: Mapped[str] = mapped_column(String(255), nullable=False)
    # Provenance.
    provenance_source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="operator_cli_pdb")
    provenance_source_name: Mapped[str] = mapped_column(String(128), nullable=False, default="Operator CLI")
    provenance_actor: Mapped[str] = mapped_column(String(128), nullable=False, default="server-operator")
    # Source path.  Stored for audit, never returned to the analyst
    # via the standard symbol view.  Exposed only on
    # ``GET .../experimental-symbol-candidates`` to the analyst who
    # owns the case.
    source_host_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pdb_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    isf_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    isf_validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="validated")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True, index=True)
    revoked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_memory_exp_candidate_case_evidence", "case_id", "evidence_id"),
        # Only one *active* candidate per requirement at a time.
        # Multiple terminal rows (revoked) are allowed.
        Index(
            "uq_memory_exp_candidate_active_requirement",
            "requirement_id",
            unique=True,
            postgresql_where=sa.text("revoked_at IS NULL"),
            sqlite_where=sa.text("revoked_at IS NULL"),
        ),
    )


class MemoryExperimentalRun(UUIDMixin, Base):
    """An isolated, never-trusted mismatched-symbol analysis run.

    The run owns its ``MemoryScanRun`` and ``MemoryPluginRun`` rows
    through the ``experimental_run_id`` foreign key on
    ``MemoryScanRun``.  The run also owns a canary phase that
    MUST complete successfully (or be explicitly operator-overridden
    on a degraded status) before any full experimental analysis
    runs.

    A run is created only after:

    1. the operator supplied an eligible candidate;
    2. the operator POSTed an acknowledgement payload;
    3. the server-side acknowledgement payload was verified.

    Deleting a run deletes all of its plugin runs and (via the
    worker) clears the experimental OpenSearch index entries.
    The exact symbol cache, the exact symbol requirement, and
    the validated runs are NEVER touched.
    """

    __tablename__ = "memory_experimental_runs"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("memory_experimental_symbol_candidates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requirement_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cached_symbol_id: Mapped[str] = mapped_column(
        ForeignKey("memory_cached_symbols.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Status of the run.  See ``EXPERIMENTAL_RUN_STATUSES`` for the
    # exhaustive set of values.  ``acknowledgement_required`` is
    # the initial state; the run never advances to ``canary_*``
    # until the acknowledgement payload is verified.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="acknowledgement_required", index=True)
    # Acknowledgement snapshot.  Persisted verbatim on the row.
    acknowledgement_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    acknowledgement_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    acknowledgement_warning_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledgement_required_pdb_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    acknowledgement_required_pdb_guid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledgement_required_pdb_age: Mapped[int | None] = mapped_column(nullable=True)
    acknowledgement_required_architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledgement_observed_pdb_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    acknowledgement_observed_pdb_guid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledgement_observed_pdb_age: Mapped[int | None] = mapped_column(nullable=True)
    acknowledgement_observed_architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledgement_warning_text: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    # Canary phase.  The canary runs before any full analysis.
    canary_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    canary_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    canary_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    canary_score: Mapped[float | None] = mapped_column(nullable=True)
    canary_checks: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    canary_summary: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    # Operator-only override for ``canary_inconclusive`` /
    # ``canary_degraded`` states.  The run may only proceed when
    # the operator explicitly accepts the canary outcome.
    canary_override_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    canary_override_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    canary_override_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    canary_override_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Requested profile set for the canary and (if the canary
    # passes) the full run.
    requested_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    canary_profiles: Mapped[list] = mapped_column(JSONVariant, nullable=False, default=list)
    # Worker tracking.
    canary_worker_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    full_worker_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Aggregate counts.
    profiles_queued: Mapped[int] = mapped_column(default=0, nullable=False)
    profiles_completed: Mapped[int] = mapped_column(default=0, nullable=False)
    profiles_failed: Mapped[int] = mapped_column(default=0, nullable=False)
    profiles_cancelled: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    cancelled_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True, index=True)
    deleted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deletion_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    audit_metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        Index("ix_memory_exp_run_case_evidence", "case_id", "evidence_id"),
        Index("ix_memory_exp_run_status", "status"),
        Index(
            "uq_memory_exp_run_active_evidence",
            "case_id",
            "evidence_id",
            unique=True,
            postgresql_where=sa.text(
                "deleted_at IS NULL AND status NOT IN ('candidate_unavailable','cancelled','deleted','completed_untrusted','partial_untrusted','failed_untrusted','canary_failed','canary_inconclusive')"
            ),
            sqlite_where=sa.text(
                "deleted_at IS NULL AND status NOT IN ('candidate_unavailable','cancelled','deleted','completed_untrusted','partial_untrusted','failed_untrusted','canary_failed','canary_inconclusive')"
            ),
        ),
    )

    case = relationship("Case")
    evidence = relationship("Evidence")
    candidate = relationship("MemoryExperimentalSymbolCandidate")
    requirement = relationship("MemorySymbolRequirement")
    cached_symbol = relationship("MemoryCachedSymbol")
    scan_runs = relationship(
        "MemoryScanRun",
        primaryjoin="foreign(MemoryScanRun.experimental_run_id)==MemoryExperimentalRun.id",
        viewonly=True,
    )


NATIVE_PROBE_STATUSES = {
    "queued",
    "running",
    "compatible",
    "incompatible",
    "failed",
    "timeout",
}


class MemoryNativeProbe(UUIDMixin, Base):
    """A bounded Volatility-native compatibility probe for a Windows requirement.

    When Kairon's internal PDB parser reports an age mismatch (e.g. required=1,
    observed=5) that would normally produce ``blocked_symbols``, this probe
    runs the pinned Volatility engine against the evidence using the symbol
    downloaded through the approved egress gateway.  If Volatility succeeds and
    produces structurally valid output, the evidence is marked compatible and
    normal validated analysis can proceed.
    """

    __tablename__ = "memory_native_probes"

    case_id: Mapped[str] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requirement_id: Mapped[str] = mapped_column(
        ForeignKey("memory_symbol_requirements.id", ondelete="CASCADE"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="queued", index=True
    )
    queue_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vol_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plugin: Mapped[str] = mapped_column(String(128), nullable=False, default="windows.pslist.PsList")
    exit_code: Mapped[int | None] = mapped_column(nullable=True)

    output_row_count: Mapped[int | None] = mapped_column(nullable=True)
    output_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    sanitized_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    structural_validation: Mapped[dict | None] = mapped_column(JSONVariant, nullable=True)

    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utc_now_naive
    )

    __table_args__ = (
        Index("ix_memory_native_probe_evidence", "case_id", "evidence_id"),
        Index("ix_memory_native_probe_status", "status"),
        Index(
            "uq_memory_native_probe_active",
            "evidence_id",
            unique=True,
            postgresql_where=sa.text(
                "status IN ('queued', 'running')"
            ),
            sqlite_where=sa.text(
                "status IN ('queued', 'running')"
            ),
        ),
    )

    case = relationship("Case")
    evidence = relationship("Evidence")
    requirement = relationship("MemorySymbolRequirement")
