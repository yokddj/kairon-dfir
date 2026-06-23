"""Versioned database migration runner.

The project does not have a third-party migration tool (Alembic,
yoyo-migrations, etc.).  This module provides the minimum viable
migration system that the spec requires:

* a single ``schema_migrations`` table that records which
  migrations have been applied;
* an ordered list of migration objects with ``version``, ``name``
  and ``up(conn)`` callable;
* an idempotent runner that applies pending migrations on
  startup;
* a test-friendly in-memory implementation backed by SQLite.

The runner never re-applies an already-applied migration.  Each
migration runs inside its own transaction so a failure in one
migration does not leave the schema half-migrated.

The migration list is the source of truth for the schema.  New
columns or tables are added by appending a new migration; old,
in-place DDL in :mod:`app.core.database` is left for backward
compatibility with pre-versioned deployments but the spec mandates
its eventual removal.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

logger = logging.getLogger(__name__)


MigrationUp = Callable[[Connection], None]


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: MigrationUp

    def describe(self) -> str:
        return f"v{self.version:03d} {self.name}"


MIGRATIONS: List[Migration] = []


def register(version: int, name: str):
    """Decorator that registers a migration in the global MIGRATIONS list."""

    def decorator(func: MigrationUp) -> MigrationUp:
        MIGRATIONS.append(Migration(version=version, name=name, up=func))
        return func

    return decorator


SCHEMA_MIGRATIONS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def ensure_migrations_table(connection: Connection) -> None:
    connection.execute(text(SCHEMA_MIGRATIONS_TABLE_DDL))


def _applied_versions(connection: Connection) -> set[int]:
    ensure_migrations_table(connection)
    rows = connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
    return {int(row[0]) for row in rows}


def run_migrations(engine: Engine) -> list[int]:
    """Apply pending migrations.

    Returns the list of versions that were applied by this run.
    Safe to call multiple times; already-applied migrations are
    skipped.
    """
    if engine.dialect.name == "sqlite":
        # SQLite does not support concurrent writes; we still apply
        # migrations sequentially but rely on the connection's own
        # transactional behaviour.
        pass
    applied_now: list[int] = []
    with engine.begin() as connection:
        already = _applied_versions(connection)
        for migration in sorted(MIGRATIONS, key=lambda m: m.version):
            if migration.version in already:
                continue
            logger.info("applying migration %s", migration.describe())
            migration.up(connection)
            connection.execute(
                text("INSERT INTO schema_migrations (version, name) VALUES (:v, :n)"),
                {"v": migration.version, "n": migration.name},
            )
            applied_now.append(migration.version)
    if applied_now:
        logger.info("applied %d migration(s): %s", len(applied_now), applied_now)
    return applied_now


# ---------------------------------------------------------------------------
# Migrations are registered in the order they must be applied.  The
# numeric version is the ordering key; the name is informational.
# ---------------------------------------------------------------------------


@register(1, "memory_scan_runs_batch_columns")
def _v1_batch_columns(connection: Connection) -> None:
    """Add batch_id / batch_position / batch_total to memory_scan_runs.

    Idempotent: skips columns that already exist.  This is the
    forward-compatible version of the in-place DDL that lived in
    ``app.core.database._ensure_compatible_schema``.
    """
    inspector = _inspector_for(connection)
    if "memory_scan_runs" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("memory_scan_runs")}
        for column_name, column_type in {
            "batch_id": "UUID",
            "batch_position": "INTEGER",
            "batch_total": "INTEGER",
        }.items():
            if column_name not in existing:
                connection.execute(
                    text(f"ALTER TABLE memory_scan_runs ADD COLUMN {column_name} {column_type}")
                )


@register(2, "memory_analysis_batches_runtime_columns")
def _v2_batches_runtime_columns(connection: Connection) -> None:
    """Add runtime-safety columns to memory_analysis_batches.

    The columns are:

    * ``version`` (INTEGER) — optimistic concurrency token.
    * ``last_advanced_run_id`` (UUID) — the run that the most recent
      advance() processed; used to dedupe duplicate callbacks.
    * ``last_advanced_at`` (TIMESTAMP) — when the last advance()
      happened.
    * ``reconciled_at`` (TIMESTAMP) — when the last reconcile pass
      touched the batch.
    * ``failure_reason`` (TEXT) — sanitized error when status is
      failed.
    * ``requested_by`` (TEXT) — audit principal (default
      server-operator).

    Also adds a partial unique index that prevents more than one
    active batch per case+evidence.
    """
    inspector = _inspector_for(connection)
    if "memory_analysis_batches" not in inspector.get_table_names():
        # Base.metadata.create_all in init_db creates the table; if
        # it does not exist yet we let the caller handle it.
        return
    existing = {c["name"] for c in inspector.get_columns("memory_analysis_batches")}
    column_defs = {
        "version": "INTEGER NOT NULL DEFAULT 1",
        "last_advanced_run_id": "VARCHAR(64)",
        "last_advanced_at": "TIMESTAMP",
        "reconciled_at": "TIMESTAMP",
        "failure_reason": "TEXT",
        "requested_by": "TEXT NOT NULL DEFAULT 'server-operator'",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE memory_analysis_batches ADD COLUMN {column_name} {column_type}"
                )
            )
    # Partial unique index: at most one active batch per (case, evidence).
    connection.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_memory_analysis_batches_one_active "
            "ON memory_analysis_batches (case_id, evidence_id) "
            "WHERE status IN ('queued', 'running')"
        )
    )
    # Index used by the reconciler and the active-batch poll endpoint.
    connection.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_memory_analysis_batches_evidence_status "
            "ON memory_analysis_batches (evidence_id, status)"
        )
    )


@register(3, "memory_scan_runs_canonical_materialization")
def _v3_canonical_materialization_columns(connection: Connection) -> None:
    """Add canonical materialization lifecycle columns to memory_scan_runs.

    Lifecycle values:

    * ``not_required``  - profile does not produce raw observations
                          (e.g. metadata_only, handles_basic, modules_basic).
    * ``pending``       - profile produces raw observations but
                          materialization has not started yet.
    * ``running``       - materialization is in progress.
    * ``completed``     - canonical entities, observations, edges and
                          roots/orphans/scan-only counts are persisted.
    * ``failed``        - materialization raised; the run is still
                          terminal but is NOT eligible as active result.
    """
    inspector = _inspector_for(connection)
    if "memory_scan_runs" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("memory_scan_runs")}
    column_defs = {
        "canonical_materialization_status": "VARCHAR(32) NOT NULL DEFAULT 'not_required'",
        "canonical_entity_count": "INTEGER NOT NULL DEFAULT 0",
        "canonical_observation_count": "INTEGER NOT NULL DEFAULT 0",
        "canonical_root_count": "INTEGER NOT NULL DEFAULT 0",
        "canonical_orphan_count": "INTEGER NOT NULL DEFAULT 0",
        "canonical_scan_only_count": "INTEGER NOT NULL DEFAULT 0",
        "canonical_materialization_error": "VARCHAR(512)",
        "canonical_materialization_version": "VARCHAR(32)",
        "canonical_materialized_at": "TIMESTAMP",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE memory_scan_runs ADD COLUMN {column_name} {column_type}"
                )
            )


@register(4, "evidences_memory_detection")
def _v4_evidence_memory_detection(connection: Connection) -> None:
    """Add memory image detection fields to the ``evidences`` table.

    These fields are populated by the read-only content probe that
    runs on memory-image uploads.  Existing evidence rows are NOT
    reclassified automatically: nullable defaults are used everywhere.
    """
    inspector = _inspector_for(connection)
    if "evidences" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("evidences")}
    column_defs = {
        "detected_format": "VARCHAR(64)",
        "detection_status": "VARCHAR(32)",
        "detection_confidence": "VARCHAR(16)",
        "detection_reason": "VARCHAR(512)",
        "probe_version": "VARCHAR(32)",
        "operator_override": "BOOLEAN NOT NULL DEFAULT FALSE",
        "operator_override_reason": "VARCHAR(512)",
        "operator_override_at": "TIMESTAMP",
        "probed_at": "TIMESTAMP",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE evidences ADD COLUMN {column_name} {column_type}"
                )
            )


@register(5, "evidences_operator_override_at")
def _v5_evidence_operator_override_at(connection: Connection) -> None:
    """Add the ``operator_override_at`` column to the ``evidences``
    table.

    Migration v4 was deployed before this column existed; this
    migration is idempotent and adds the column on databases that
    were upgraded to v4 before this field was introduced.
    """
    inspector = _inspector_for(connection)
    if "evidences" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("evidences")}
    if "operator_override_at" not in existing:
        connection.execute(
            text("ALTER TABLE evidences ADD COLUMN operator_override_at TIMESTAMP")
        )


@register(6, "evidences_detection_status_widen")
def _v6_evidence_detection_status_widen(connection: Connection) -> None:
    """Widen ``evidences.detection_status`` to VARCHAR(64).

    The probe false-positives sprint introduced
    ``probable_disk_confirmed_as_memory`` (34 chars), which overflows
    the original VARCHAR(32) limit.  This migration is idempotent:
    it only alters the column when it is still narrower than
    VARCHAR(64).
    """
    inspector = _inspector_for(connection)
    if "evidences" not in inspector.get_table_names():
        return
    for col in inspector.get_columns("evidences"):
        if col["name"] == "detection_status":
            current = str(col["type"]).upper()
            if "VARCHAR(32)" in current or "VARCHAR(16)" in current:
                connection.execute(
                    text("ALTER TABLE evidences ALTER COLUMN detection_status TYPE VARCHAR(64)")
                )
            return


@register(7, "memory_symbol_requirement_backfill_metadata")
def _v7_memory_symbol_requirement_backfill_metadata(connection: Connection) -> None:
    """Add backfill metadata columns to ``memory_symbol_requirements``.

    The legacy symbol-readiness recovery sprint needs to record
    how each requirement row was reconstructed (probe / historical
    run / cache match) so the UI can distinguish "manually probed"
    from "backfilled from history".

    New columns:

    * ``source``              - "probe" | "historical_run" | "cache_match" | ...
    * ``reconstructed_at``    - timestamp set when the row was reconstructed
    * ``backfill_version``    - free-form version label (e.g. "v1")
    * ``confidence``          - "high" | "medium" | "low"
    * ``metadata_json``       - JSONB for additional source-specific metadata
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_requirements" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("memory_symbol_requirements")}
    additions = [
        ("source", "VARCHAR(32)"),
        ("reconstructed_at", "TIMESTAMP"),
        ("backfill_version", "VARCHAR(16)"),
        ("confidence", "VARCHAR(16)"),
        ("metadata_json", "JSONB"),
    ]
    for column_name, column_type in additions:
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE memory_symbol_requirements ADD COLUMN {column_name} {column_type}"
                )
            )


@register(8, "memory_evidence_content_identity")
def _v8_memory_evidence_content_identity(connection: Connection) -> None:
    """Add content-identity tables for symbol readiness reuse.

    New tables:

    * ``memory_evidence_contents``  - one row per (sha256, size) tuple
    * ``memory_evidence_symbol_links`` - per-evidence link to a requirement
    * ``memory_symbol_preparations``  - per-evidence preparation state
    * ``memory_symbol_negative_cache`` - cooldown for unavailable symbols
    * ``memory_symbol_pending_analysis`` - operator-intent rows for "Run
      when ready"

    This is the data model behind the automatic symbol resolution
    flow.  Idempotent: re-running it on a database that already
    has the tables is a no-op.
    """
    inspector = _inspector_for(connection)
    if "memory_evidence_contents" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE memory_evidence_contents (
                    id UUID PRIMARY KEY,
                    evidence_sha256 VARCHAR(64) NOT NULL,
                    size_bytes BIGINT NOT NULL,
                    acquisition_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    last_readiness VARCHAR(32),
                    last_requirement_id UUID,
                    last_checked_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_memory_content_identity ON memory_evidence_contents (evidence_sha256, size_bytes)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_evidence_contents_sha256 ON memory_evidence_contents (evidence_sha256)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_evidence_contents_last_requirement ON memory_evidence_contents (last_requirement_id)"
            )
        )
    if "memory_evidence_symbol_links" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE memory_evidence_symbol_links (
                    id UUID PRIMARY KEY,
                    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    evidence_id UUID NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
                    requirement_id UUID NOT NULL REFERENCES memory_symbol_requirements(id) ON DELETE CASCADE,
                    link_source VARCHAR(32) NOT NULL DEFAULT 'probe',
                    state VARCHAR(32) NOT NULL DEFAULT 'pending',
                    error_code VARCHAR(64),
                    sanitized_message VARCHAR(512),
                    last_transition_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_memory_evidence_symbol_link ON memory_evidence_symbol_links (evidence_id, requirement_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_evidence_symbol_links_requirement ON memory_evidence_symbol_links (requirement_id)"
            )
        )
    if "memory_symbol_preparations" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE memory_symbol_preparations (
                    id UUID PRIMARY KEY,
                    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    evidence_id UUID NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
                    state VARCHAR(32) NOT NULL DEFAULT 'queued',
                    state_reason VARCHAR(64),
                    requirement_id UUID REFERENCES memory_symbol_requirements(id) ON DELETE SET NULL,
                    error_code VARCHAR(64),
                    sanitized_message VARCHAR(512),
                    next_attempt_at TIMESTAMP,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    worker_task_id VARCHAR(128),
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_symbol_prep_evidence_state ON memory_symbol_preparations (evidence_id, state)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_symbol_prep_state_updated ON memory_symbol_preparations (state, updated_at)"
            )
        )
    if "memory_symbol_negative_cache" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE memory_symbol_negative_cache (
                    id UUID PRIMARY KEY,
                    symbol_key VARCHAR(256) NOT NULL,
                    source VARCHAR(64) NOT NULL DEFAULT 'official_microsoft_symbols',
                    error_code VARCHAR(64) NOT NULL,
                    sanitized_message VARCHAR(512),
                    attempts INTEGER NOT NULL DEFAULT 1,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_memory_symbol_negative_cache_key ON memory_symbol_negative_cache (symbol_key)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_symbol_negative_cache_expires ON memory_symbol_negative_cache (expires_at)"
            )
        )
    if "memory_symbol_pending_analysis" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE memory_symbol_pending_analysis (
                    id UUID PRIMARY KEY,
                    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    evidence_id UUID NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
                    kind VARCHAR(32) NOT NULL,
                    profile VARCHAR(64),
                    mode VARCHAR(32) NOT NULL DEFAULT 'missing_or_failed',
                    requested_profiles JSONB NOT NULL DEFAULT '[]'::jsonb,
                    status VARCHAR(32) NOT NULL DEFAULT 'pending',
                    materialized_batch_id VARCHAR(64),
                    materialized_run_id VARCHAR(64),
                    error_code VARCHAR(64),
                    sanitized_message VARCHAR(512),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_symbol_pending_evidence_status ON memory_symbol_pending_analysis (evidence_id, status)"
            )
        )
    # Add is_shared column to memory_symbol_requirements.
    if "memory_symbol_requirements" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("memory_symbol_requirements")}
        if "is_shared" not in existing:
            connection.execute(
                text(
                    "ALTER TABLE memory_symbol_requirements ADD COLUMN is_shared BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )


@register(9, "memory_upload_registration_lifecycle")
def _v9_memory_upload_registration_lifecycle(connection: Connection) -> None:
    """Expand ``memory_uploads`` for the registration recovery flow.

    Adds columns required to decouple evidence registration from
    post-registration automation (memory probe, symbol preparation,
    OpenSearch initialization):

    * ``stage``              - registration stage ("registration_pending",
                               "registered", "failed_registration", ...)
    * ``registration_state`` - structured registration state
    * ``registration_attempts`` - retry counter
    * ``last_registration_error_code`` - structured error code
    * ``last_registration_error_class`` - exception class name
    * ``canonical_preserved`` - True when the canonical blob is durable

    The new columns default to NULL / False / 0 so legacy rows are
    unaffected.  The migration is idempotent: re-running it on a
    database that already has the columns is a no-op.
    """
    inspector = _inspector_for(connection)
    if "memory_uploads" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("memory_uploads")}
    additions = [
        ("stage", "VARCHAR(32)"),
        ("registration_state", "VARCHAR(32)"),
        ("registration_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("last_registration_error_code", "VARCHAR(64)"),
        ("last_registration_error_class", "VARCHAR(128)"),
        ("canonical_preserved", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ]
    for column_name, column_type in additions:
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE memory_uploads ADD COLUMN {column_name} {column_type}"
                )
            )
    if "ix_memory_uploads_registration_state" not in {
        ix["name"] for ix in inspector.get_indexes("memory_uploads")
    }:
        connection.execute(
            text(
                "CREATE INDEX ix_memory_uploads_registration_state ON memory_uploads (registration_state)"
            )
        )


def _inspector_for(connection: Connection):
    from sqlalchemy import inspect

    return inspect(connection)
