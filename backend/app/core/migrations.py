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


def _index_exists(connection: Connection, name: str) -> bool:
    """Check whether an index with ``name`` already exists.

    Used by migrations that need to be idempotent on both
    PostgreSQL and SQLite, neither of which supports a
    ``CREATE INDEX IF NOT EXISTS`` form with a partial WHERE
    clause that works uniformly on both engines.
    """
    dialect = connection.dialect.name
    if dialect == "postgresql":
        row = connection.execute(
            text("SELECT 1 FROM pg_indexes WHERE indexname = :n"),
            {"n": name},
        ).fetchone()
        return row is not None
    row = connection.execute(
        text("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :n"),
        {"n": name},
    ).fetchone()
    return row is not None


def _create_index_dialect_aware(
    connection: Connection,
    *,
    name: str,
    create_sql: str,
) -> None:
    """Create ``create_sql`` if no index with ``name`` exists.

    The caller supplies the dialect-correct DDL.  We avoid
    ``IF NOT EXISTS`` because SQLite does not support it for
    partial indexes.
    """
    if _index_exists(connection, name):
        return
    connection.execute(text(create_sql))


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
    # The name ``uq_memory_analysis_batches_one_active`` matches the
    # SQLAlchemy model so ``Base.metadata.create_all`` is a no-op on
    # fresh databases.  The index uses a dialect-aware form:
    # PostgreSQL keeps the WHERE clause; SQLite ignores the partial
    # predicate (the app enforces the active-state invariant
    # process-locally as a fallback) but the index still exists.
    dialect = connection.dialect.name
    if dialect == "postgresql":
        _create_index_dialect_aware(
            connection,
            name="uq_memory_analysis_batches_one_active",
            create_sql=(
                "CREATE UNIQUE INDEX uq_memory_analysis_batches_one_active "
                "ON memory_analysis_batches (case_id, evidence_id) "
                "WHERE status IN ('queued', 'running')"
            ),
        )
    else:
        # SQLite: a plain non-partial unique index is enough because
        # the test path enforces the active-state invariant.  We
        # exclude the WHERE clause to keep the index valid on
        # SQLite.  The application-level guard in
        # ``find_active_batch`` is the authoritative check.
        _create_index_dialect_aware(
            connection,
            name="uq_memory_analysis_batches_one_active",
            create_sql=(
                "CREATE UNIQUE INDEX uq_memory_analysis_batches_one_active "
                "ON memory_analysis_batches (case_id, evidence_id)"
            ),
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


@register(10, "memory_symbol_preparation_reconciliation")
def _v10_memory_symbol_preparation_reconciliation(connection: Connection) -> None:
    """Expand ``memory_symbol_preparations`` for the v1 reconciliation
    sprint.

    Adds columns used by the stale-queue cleanup and the effective
    state resolution:

    * ``last_heartbeat_at`` - the worker last touched this row
    * ``current_step``     - human-readable step label
    * ``progress_percent`` - 0..100, with a 0 meaning unknown
    * ``source_of_truth``  - the fact that pinned the current state
                             (e.g. ``successful_metadata_run``)
    * ``reconciled_at``    - when the reconciliation last touched the
                             row
    * ``active``           - boolean; only one row per evidence can
                             be active at a time

    The partial unique index on ``evidence_id WHERE active = true``
    enforces the "one active preparation per evidence" guarantee
    on PostgreSQL.  On SQLite the WHERE clause is ignored but the
    index still exists.
    """
    dialect = connection.dialect.name
    # ``ADD COLUMN IF NOT EXISTS`` is PostgreSQL 9.6+ syntax.  SQLite
    # has no equivalent on ``ALTER TABLE``; it raises a syntax error
    # instead of a "duplicate column" error.  Use dialect-aware
    # SQL: PostgreSQL keeps the idempotent ``IF NOT EXISTS`` form;
    # SQLite inspects ``PRAGMA table_info`` to decide whether the
    # column already exists before issuing ``ADD COLUMN``.
    def _add_column_if_missing(
        column_name: str,
        column_type_sql: str,
        not_null: bool = False,
        default_sql: str = "",
    ) -> None:
        if dialect == "postgresql":
            clauses = [column_type_sql]
            if not_null:
                clauses.append("NOT NULL")
            if default_sql:
                clauses.append(f"DEFAULT {default_sql}")
            column_def = " ".join(clauses)
            connection.execute(
                text(
                    "ALTER TABLE memory_symbol_preparations "
                    f"ADD COLUMN IF NOT EXISTS {column_name} {column_def}"
                )
            )
            return
        # SQLite: check the column catalog first.
        existing = {
            str(row[1])  # PRAGMA table_info: name is column index 1
            for row in connection.execute(
                text("PRAGMA table_info(memory_symbol_preparations)")
            ).fetchall()
        }
        if column_name in existing:
            return
        clauses = [column_type_sql]
        if not_null:
            clauses.append("NOT NULL")
        if default_sql:
            clauses.append(f"DEFAULT {default_sql}")
        column_def = " ".join(clauses)
        connection.execute(
            text(
                "ALTER TABLE memory_symbol_preparations "
                f"ADD COLUMN {column_name} {column_def}"
            )
        )

    def _create_index_if_missing(index_name: str, create_sql: str) -> None:
        if dialect == "postgresql":
            connection.execute(text(create_sql))
            return
        # SQLite: check sqlite_master for an existing index.
        existing = {
            str(row[0])  # SELECT name: name is column index 0
            for row in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'index'")
            ).fetchall()
        }
        if index_name in existing:
            return
        connection.execute(text(create_sql))

    _add_column_if_missing("last_heartbeat_at", "TIMESTAMP")
    _add_column_if_missing("current_step", "VARCHAR(64)")
    _add_column_if_missing(
        "progress_percent", "INTEGER", not_null=True, default_sql="0",
    )
    _add_column_if_missing("source_of_truth", "VARCHAR(64)")
    _add_column_if_missing("reconciled_at", "TIMESTAMP")
    _add_column_if_missing(
        "active", "BOOLEAN", not_null=True, default_sql="TRUE",
    )
    _create_index_if_missing(
        "ix_memory_symbol_preparations_active",
        "CREATE INDEX ix_memory_symbol_preparations_active ON memory_symbol_preparations (active)",
    )
    # Partial unique index: one active preparation per evidence.
    # The IF NOT EXISTS clause is supported by PostgreSQL 9.5+ and
    # silently ignored by SQLite when the index already exists.
    _create_index_if_missing(
        "uq_memory_symbol_prep_active_evidence",
        "CREATE UNIQUE INDEX uq_memory_symbol_prep_active_evidence "
        "ON memory_symbol_preparations (evidence_id) WHERE active = TRUE",
    )


@register(11, "memory_analysis_batches_last_advanced_run_id_uuid")
def _v11_batches_last_advanced_run_id_uuid(connection: Connection) -> None:
    """Align ``memory_analysis_batches.last_advanced_run_id`` to native UUID.

    Sprint: Memory Batch UUID Schema Alignment & Live Run-All Closure v1.

    The original migration v2 declared this column as VARCHAR(64),
    but a later patch changed the SQLAlchemy model to a
    ``String(64)`` while the live PostgreSQL column had already
    been created as ``uuid`` by the v2 of an earlier deployment.
    The mismatch caused every ``INSERT`` into
    ``memory_analysis_batches`` to fail with::

        column "last_advanced_run_id" is of type uuid but
        expression is of type character varying

    The migration v11 is idempotent:

    * Inspects the actual column type in the live database.
    * If the column is already ``uuid`` (or a UUID-compatible
      type on SQLite) the migration is a no-op.
    * If the column is ``character varying`` (PostgreSQL) the
      migration casts the existing data to ``uuid`` using
      ``USING NULLIF(col, '')::uuid`` so that empty strings are
      normalised to NULL before the cast.  Any non-UUID value is
      logged and converted to NULL with a warning, never silently
      dropped.
    * If the column is missing entirely (e.g. legacy deployment
      pre-v2) the migration adds it as a native UUID.

    The migration also reconciles ``memory_scan_runs.batch_id`` and
    the secondary FK columns in case a deployment ended up with
    a VARCHAR(64) variant.
    """
    inspector = _inspector_for(connection)
    if "memory_analysis_batches" not in inspector.get_table_names():
        return

    def _column_type(table: str, column: str) -> str | None:
        cols = {c["name"]: c for c in inspector.get_columns(table)}
        col = cols.get(column)
        if col is None:
            return None
        return str(col.get("type"))

    def _column_nullable(table: str, column: str) -> bool:
        cols = {c["name"]: c for c in inspector.get_columns(table)}
        col = cols.get(column)
        if col is None:
            return True
        return bool(col.get("nullable", True))

    dialect = connection.dialect.name
    is_postgres = dialect == "postgresql"

    # 1) memory_analysis_batches.last_advanced_run_id
    existing_type = _column_type("memory_analysis_batches", "last_advanced_run_id")
    if existing_type is None:
        # Column missing (legacy pre-v2).  Add it as native UUID.
        if is_postgres:
            connection.execute(
                text("ALTER TABLE memory_analysis_batches "
                     "ADD COLUMN last_advanced_run_id UUID")
            )
        else:
            # SQLite: TEXT is the closest portable type.  The
            # application treats the value as a UUID string.
            connection.execute(
                text("ALTER TABLE memory_analysis_batches "
                     "ADD COLUMN last_advanced_run_id VARCHAR(64)")
            )
    elif is_postgres and (
        existing_type.lower() in ("character varying", "varchar")
        or existing_type.lower().startswith("varchar(")
        or existing_type.lower().startswith("character varying(")
    ):
        # Detect non-UUID values before casting.
        rows = connection.execute(
            text(
                "SELECT last_advanced_run_id FROM memory_analysis_batches "
                "WHERE last_advanced_run_id IS NOT NULL "
                "AND last_advanced_run_id <> '' "
                "AND last_advanced_run_id::text !~* "
                "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
            )
        ).fetchall()
        invalid = [str(r[0]) for r in rows]
        for bad in invalid:
            logger.warning(
                "migration v11: invalid UUID in "
                "memory_analysis_batches.last_advanced_run_id -> NULL: %r",
                bad,
            )
        # NULLIF + ::uuid cast.  Empty strings become NULL; invalid
        # UUID strings have already been replaced with NULL via the
        # UPDATE below so the cast itself only sees valid values.
        if invalid:
            connection.execute(
                text(
                    "UPDATE memory_analysis_batches "
                    "SET last_advanced_run_id = NULL "
                    "WHERE last_advanced_run_id IS NOT NULL "
                    "AND last_advanced_run_id::text !~* "
                    "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
                )
            )
        # Empty strings -> NULL before the cast to avoid PG error.
        connection.execute(
            text(
                "UPDATE memory_analysis_batches "
                "SET last_advanced_run_id = NULL "
                "WHERE last_advanced_run_id = ''"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE memory_analysis_batches "
                "ALTER COLUMN last_advanced_run_id TYPE UUID "
                "USING NULLIF(last_advanced_run_id, '')::uuid"
            )
        )
    # On SQLite we keep the existing TEXT representation; the
    # application-level Python type already handles strings.

    # 2) memory_scan_runs.batch_id (defensive: any deployment
    # that started with the legacy in-place DDL may have it as
    # TEXT).  On PostgreSQL, align to native UUID.
    if "memory_scan_runs" in inspector.get_table_names():
        btype = _column_type("memory_scan_runs", "batch_id")
        if btype is not None and is_postgres and (
            btype.lower() in ("character varying", "varchar", "text")
            or btype.lower().startswith("varchar(")
            or btype.lower().startswith("character varying(")
        ):
            # Drop and re-add the FK if needed so the type can change.
            connection.execute(
                text(
                    "ALTER TABLE memory_scan_runs "
                    "DROP CONSTRAINT IF EXISTS memory_scan_runs_batch_id_fkey"
                )
            )
            rows = connection.execute(
                text(
                    "SELECT batch_id FROM memory_scan_runs "
                    "WHERE batch_id IS NOT NULL AND batch_id <> '' "
                    "AND batch_id::text !~* "
                    "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
                )
            ).fetchall()
            for r in rows:
                logger.warning(
                    "migration v11: invalid UUID in "
                    "memory_scan_runs.batch_id -> NULL: %r", r[0],
                )
            if rows:
                connection.execute(
                    text(
                        "UPDATE memory_scan_runs SET batch_id = NULL "
                        "WHERE batch_id IS NOT NULL AND batch_id::text !~* "
                        "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
                    )
                )
            connection.execute(
                text(
                    "UPDATE memory_scan_runs SET batch_id = NULL "
                    "WHERE batch_id = ''"
                )
            )
            connection.execute(
                text(
                    "ALTER TABLE memory_scan_runs "
                    "ALTER COLUMN batch_id TYPE UUID "
                    "USING NULLIF(batch_id, '')::uuid"
                )
            )
            # Re-add the FK.
            connection.execute(
                text(
                    "ALTER TABLE memory_scan_runs "
                    "ADD CONSTRAINT memory_scan_runs_batch_id_fkey "
                    "FOREIGN KEY (batch_id) REFERENCES memory_analysis_batches(id) "
                    "ON DELETE SET NULL"
                )
            )
    # ``last_advanced_run_id`` MUST remain nullable: a brand new
    # batch is created with no run yet advanced.
    nullable = _column_nullable("memory_analysis_batches", "last_advanced_run_id")
    if is_postgres and not nullable:
        connection.execute(
            text(
                "ALTER TABLE memory_analysis_batches "
                "ALTER COLUMN last_advanced_run_id DROP NOT NULL"
            )
        )


@register(12, "memory_symbol_preparations_queue_name")
def _v12_preparations_queue_name(connection: Connection) -> None:
    """Add ``memory_symbol_preparations.queue_name`` for the v1
    OS-agnostic preparation sprint.

    The preparation row records the queue that owns the worker
    task.  Without it the diagnostics endpoint cannot tell
    whether the API and the memory-worker are listening on the
    same queue.
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_preparations" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("memory_symbol_preparations")}
    if "queue_name" not in existing:
        connection.execute(
            text("ALTER TABLE memory_symbol_preparations "
                 "ADD COLUMN queue_name VARCHAR(64)")
        )


@register(13, "memory_symbol_requirements_nullable_source_fks")
def _v13_requirements_nullable_source_fks(connection: Connection) -> None:
    """Make ``source_run_id`` and ``source_plugin_run_id`` nullable
    on ``memory_symbol_requirements`` so bounded discovery can
    persist a requirement without fabricating scan/plugin run rows.

    The foreign-key constraints are preserved for non-null values
    (real analysis provenance).  The model-level ``nullable=True``
    handles SQLite (always created fresh); this migration only
    touches real PostgreSQL deployments.
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_requirements" not in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    if dialect != "postgresql":
        return

    cols_by_name = {
        c["name"]: c for c in inspector.get_columns("memory_symbol_requirements")
    }
    for col_name in ("source_run_id", "source_plugin_run_id"):
        col = cols_by_name.get(col_name)
        if col is None:
            continue
        if not bool(col.get("nullable", True)):
            connection.execute(
                text(
                    f"ALTER TABLE memory_symbol_requirements "
                    f"ALTER COLUMN {col_name} DROP NOT NULL"
                )
            )
            logger.info(
                "v13: made memory_symbol_requirements.%s nullable", col_name
            )


@register(14, "memory_symbol_acquisitions_observed_identity")
def _v14_acquisitions_observed_identity(connection: Connection) -> None:
    """Add observed-identity columns to ``memory_symbol_acquisitions``.

    The managed exact Windows symbol acquisition flow must record
    the GUID, age and architecture the Microsoft symbol server
    actually returned, so the operator can see whether the
    download disagrees with the requirement without inspecting
    the symbol-fetcher logs.  All three columns are nullable so
    legacy rows that never reached ``validating_pdb`` are
    preserved untouched.

    * ``observed_pdb_guid``  - 32 hex chars (uppercase) from the
                                downloaded PDB info stream.
    * ``observed_pdb_age``   - integer from the downloaded PDB info
                                stream.
    * ``observed_architecture`` - "x64" / "x86" / "arm64".

    The migration is idempotent: it only adds columns that are
    missing.
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_acquisitions" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("memory_symbol_acquisitions")}
    additions = [
        ("observed_pdb_guid", "VARCHAR(32)"),
        ("observed_pdb_age", "INTEGER"),
        ("observed_architecture", "VARCHAR(32)"),
    ]
    for column_name, column_type in additions:
        if column_name not in existing:
            connection.execute(
                text(
                    f"ALTER TABLE memory_symbol_acquisitions "
                    f"ADD COLUMN {column_name} {column_type}"
                )
            )
            logger.info(
                "v14: added memory_symbol_acquisitions.%s", column_name
            )


@register(15, "memory_symbol_recovery_sources")
def _v15_recovery_sources(connection: Connection) -> None:
    """Add the recovery-sources table and the cache provenance columns.

    The Exact Symbol Recovery Sources v1 feature lets
    administrators configure additional recovery paths (corporate
    symbol server, manual PDB/ISF import, offline package) when
    the Microsoft public symbol path cannot supply an exact
    matching PDB.  Each cached symbol must also record truthful
    provenance so the UI can show ``Microsoft public`` /
    ``Corporate symbol server`` / ``Administrator-imported PDB``
    / ``Administrator-imported ISF`` / ``Offline package`` to
    analysts without exposing internal URLs or secrets.

    * New table ``memory_symbol_recovery_sources`` stores the
      administrator-configured corporate symbol servers.  Only
      safe metadata is stored; the secret itself is never
      persisted on the row.
    * ``memory_cached_symbols`` gains:
        - ``provenance_source_type`` (String 32)
        - ``provenance_source_name`` (String 128)
        - ``provenance_acquired_at`` (timestamp)
        - ``provenance_actor`` (String 128)
    * Existing ``MemoryCachedSymbol`` rows are back-filled with
      ``provenance_source_type = "microsoft_public"`` and
      ``provenance_source_name = "Microsoft public"`` so the UI
      can always render a label.
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_recovery_sources" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE memory_symbol_recovery_sources ("
                "id VARCHAR(36) PRIMARY KEY, "
                "source_type VARCHAR(32) NOT NULL, "
                "name VARCHAR(128) NOT NULL, "
                "enabled BOOLEAN NOT NULL DEFAULT 1, "
                "priority INTEGER NOT NULL DEFAULT 100, "
                "host VARCHAR(255), "
                "port INTEGER, "
                "path_prefix VARCHAR(512), "
                "tls_required BOOLEAN NOT NULL DEFAULT 1, "
                "credential_secret_name VARCHAR(128), "
                "configured_by VARCHAR(128) NOT NULL DEFAULT 'server-operator', "
                "note VARCHAR(512), "
                "metadata_json JSON NOT NULL DEFAULT '{}', "
                "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_memory_recovery_source_type_name "
                "ON memory_symbol_recovery_sources (source_type, name)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_source_type "
                "ON memory_symbol_recovery_sources (source_type)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_source_enabled "
                "ON memory_symbol_recovery_sources (enabled)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_source_priority "
                "ON memory_symbol_recovery_sources (priority)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_source_enabled_priority "
                "ON memory_symbol_recovery_sources (enabled, priority)"
            )
        )
        logger.info("v15: created memory_symbol_recovery_sources")

    if "memory_symbol_recovery_attempts" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE memory_symbol_recovery_attempts ("
                "id VARCHAR(36) PRIMARY KEY, "
                "requirement_id VARCHAR(36) NOT NULL, "
                "case_id VARCHAR(36) NOT NULL, "
                "evidence_id VARCHAR(36) NOT NULL, "
                "source_id VARCHAR(36), "
                "source_type VARCHAR(32) NOT NULL, "
                "source_label VARCHAR(128) NOT NULL, "
                "status VARCHAR(32) NOT NULL, "
                "error_code VARCHAR(64), "
                "sanitized_message VARCHAR(512), "
                "metadata_json JSON NOT NULL DEFAULT '{}', "
                "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_attempt_requirement "
                "ON memory_symbol_recovery_attempts (requirement_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_attempt_case_evidence "
                "ON memory_symbol_recovery_attempts (case_id, evidence_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_attempt_source_type "
                "ON memory_symbol_recovery_attempts (source_type)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_memory_recovery_attempt_status "
                "ON memory_symbol_recovery_attempts (status)"
            )
        )
        logger.info("v15: created memory_symbol_recovery_attempts")

    if "memory_cached_symbols" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("memory_cached_symbols")}
        cache_additions = [
            ("provenance_source_type", "VARCHAR(32)"),
            ("provenance_source_name", "VARCHAR(128)"),
            ("provenance_actor", "VARCHAR(128)"),
        ]
        for column_name, column_type in cache_additions:
            if column_name not in existing:
                connection.execute(
                    text(
                        f"ALTER TABLE memory_cached_symbols "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                logger.info(
                    "v15: added memory_cached_symbols.%s", column_name
                )
        # Back-fill provenance for legacy rows so the UI can always
        # render a non-empty label.
        connection.execute(
            text(
                "UPDATE memory_cached_symbols "
                "SET provenance_source_type = 'microsoft_public', "
                "    provenance_source_name = 'Microsoft public' "
                "WHERE provenance_source_type IS NULL "
                "   OR provenance_source_type = ''"
            )
        )
        # ``provenance_acquired_at`` mirrors ``created_at`` for
        # legacy rows; new writes set it explicitly.
        existing = {c["name"] for c in inspector.get_columns("memory_cached_symbols")}
        if "provenance_acquired_at" not in existing:
            connection.execute(
                text(
                    "ALTER TABLE memory_cached_symbols "
                    "ADD COLUMN provenance_acquired_at TIMESTAMP"
                )
            )
        connection.execute(
            text(
                "UPDATE memory_cached_symbols "
                "SET provenance_acquired_at = created_at "
                "WHERE provenance_acquired_at IS NULL"
            )
        )


@register(16, "memory_symbol_recovery_attempts_active_uniqueness")
def _v16_recovery_attempts_active_uniqueness(connection: Connection) -> None:
    """Add ``terminal_at`` column and a partial unique index that
    enforces "at most one active attempt per
    ``(requirement_id, source_type)`` tuple".

    The ``terminal_at`` column is NULL while the attempt is
    active and is set to the wall-clock time when the attempt
    reaches a terminal state (``succeeded`` / ``failed`` /
    ``skipped``).  The partial unique index guarantees the
    invariant even across multiple backend processes / workers
    / restarts.

    The migration is idempotent: each step is gated on a
    pre-condition (column existence, index existence).  Legacy
    rows are back-filled with a sentinel ``terminal_at`` value
    so they do not block new active attempts.
    """
    inspector = _inspector_for(connection)
    if "memory_symbol_recovery_attempts" not in inspector.get_table_names():
        return
    existing = {
        c["name"] for c in inspector.get_columns("memory_symbol_recovery_attempts")
    }
    if "terminal_at" not in existing:
        connection.execute(
            text(
                "ALTER TABLE memory_symbol_recovery_attempts "
                "ADD COLUMN terminal_at TIMESTAMP"
            )
        )
        logger.info(
            "v16: added memory_symbol_recovery_attempts.terminal_at"
        )
    # Back-fill legacy rows so the partial unique index can
    # be created without a "duplicate" error.
    connection.execute(
        text(
            "UPDATE memory_symbol_recovery_attempts "
            "SET terminal_at = created_at "
            "WHERE terminal_at IS NULL"
        )
    )
    # Idempotent index creation.  PostgreSQL supports
    # ``CREATE UNIQUE INDEX IF NOT EXISTS`` and partial
    # indexes (``WHERE terminal_at IS NULL``).  SQLite does
    # NOT support ``IF NOT EXISTS`` for indexes reliably, so
    # we check the inspector first and fall back to a regular
    # helper index.
    dialect = connection.dialect.name
    existing_indexes = {
        ix["name"] for ix in inspector.get_indexes(
            "memory_symbol_recovery_attempts"
        )
    }
    try:
        if dialect == "postgresql":
            if "uq_memory_recovery_attempt_active" not in existing_indexes:
                connection.execute(
                    text(
                        "CREATE UNIQUE INDEX "
                        "uq_memory_recovery_attempt_active "
                        "ON memory_symbol_recovery_attempts "
                        "(requirement_id, source_type) "
                        "WHERE terminal_at IS NULL"
                    )
                )
        else:
            if "ix_memory_recovery_attempt_active" not in existing_indexes:
                connection.execute(
                    text(
                        "CREATE INDEX "
                        "ix_memory_recovery_attempt_active "
                        "ON memory_symbol_recovery_attempts "
                        "(requirement_id, source_type, terminal_at)"
                    )
                )
        logger.info(
            "v16: ensured active-attempt index on "
            "memory_symbol_recovery_attempts (requirement_id, "
            "source_type) WHERE terminal_at IS NULL"
        )
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "v16: active-attempt index not created on %s (%s); "
            "application enforces the invariant instead",
            dialect, exc,
        )


@register(17, "memory_experimental_mismatched_symbol_analysis")
def _v17_experimental_mismatched_symbol_analysis(connection: Connection) -> None:
    """Add the experimental mismatched-symbol analysis trust domain.

    The feature is opt-in via the ``MEMORY_SYMBOL_EXPERIMENTAL_ENABLED``
    server-side flag (default False).  The database is migrated even
    when the flag is off so that the schema is stable; the
    application-level gates prevent any untrusted data from being
    created or consumed when the flag is False.

    The migration is idempotent and only adds objects that are
    missing.  The schema is engineered so a partial unique index
    enforces "at most one active candidate per requirement" and so
    that the existing exact-symbol flow is unaffected.

    Additions:

    * ``memory_cached_symbols`` gains:

        - ``cache_classification`` (VARCHAR 32, default ``exact``)
        - ``required_pdb_name`` / ``required_pdb_guid`` /
          ``required_pdb_age`` / ``required_architecture`` (NULL for
          exact rows)

    * ``memory_scan_runs`` gains:

        - ``analysis_mode`` (VARCHAR 32, default ``validated``)
        - ``trust_level`` (VARCHAR 32, default ``validated``)
        - ``symbol_match_type`` (VARCHAR 32, default ``exact``)
        - ``experimental_run_id`` (FK ``memory_experimental_runs.id``)

    * ``memory_plugin_runs`` gains:

        - ``analysis_mode`` (VARCHAR 32, default ``validated``)
        - ``trust_level`` (VARCHAR 32, default ``validated``)

    * New table ``memory_experimental_symbol_candidates`` storing the
      operator-supplied mismatched symbol and its required identity.
      A partial unique index enforces "at most one active candidate
      per requirement".

    * New table ``memory_experimental_runs`` storing the
      acknowledgement, the canary phase outcome, the requested
      profile set, and the deletion/audit fields.
    """
    inspector = _inspector_for(connection)
    dialect = connection.dialect.name

    # 1. ``memory_cached_symbols`` additions
    if "memory_cached_symbols" in inspector.get_table_names():
        existing = {
            c["name"] for c in inspector.get_columns("memory_cached_symbols")
        }
        additions = [
            ("cache_classification", "VARCHAR(32) NOT NULL DEFAULT 'exact'"),
            ("required_pdb_name", "VARCHAR(128)"),
            ("required_pdb_guid", "VARCHAR(32)"),
            ("required_pdb_age", "INTEGER"),
            ("required_architecture", "VARCHAR(32)"),
        ]
        for column_name, column_type in additions:
            if column_name not in existing:
                connection.execute(
                    text(
                        f"ALTER TABLE memory_cached_symbols "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                logger.info(
                    "v17: added memory_cached_symbols.%s", column_name
                )
        # Index for fast "list experimental candidates" lookups.
        existing_indexes = {
            ix["name"] for ix in inspector.get_indexes("memory_cached_symbols")
        }
        if "ix_memory_cached_symbols_classification" not in existing_indexes:
            try:
                with connection.begin_nested():
                    connection.execute(
                        text(
                            "CREATE INDEX ix_memory_cached_symbols_classification "
                            "ON memory_cached_symbols (cache_classification)"
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                logger.info(
                    "v17: classification index not created on %s (%s); "
                    "application falls back to a full table scan",
                    dialect, exc,
                )

    # 2. ``memory_scan_runs`` additions
    if "memory_scan_runs" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("memory_scan_runs")}
        additions = [
            ("analysis_mode", "VARCHAR(32) NOT NULL DEFAULT 'validated'"),
            ("trust_level", "VARCHAR(32) NOT NULL DEFAULT 'validated'"),
            ("symbol_match_type", "VARCHAR(32) NOT NULL DEFAULT 'exact'"),
        ]
        for column_name, column_type in additions:
            if column_name not in existing:
                connection.execute(
                    text(
                        f"ALTER TABLE memory_scan_runs "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                logger.info("v17: added memory_scan_runs.%s", column_name)
        for column_name, value in (
            ("analysis_mode", "validated"),
            ("trust_level", "validated"),
            ("symbol_match_type", "exact"),
        ):
            if column_name in {c["name"] for c in inspector.get_columns("memory_scan_runs")}:
                connection.execute(
                    text(
                        f"UPDATE memory_scan_runs SET {column_name} = :value WHERE {column_name} IS NULL"
                    ),
                    {"value": value},
                )
        if "experimental_run_id" not in existing:
            connection.execute(
                text(
                    "ALTER TABLE memory_scan_runs "
                    "ADD COLUMN experimental_run_id VARCHAR(36)"
                )
            )
            logger.info("v17: added memory_scan_runs.experimental_run_id")
        existing_indexes = {
            ix["name"] for ix in inspector.get_indexes("memory_scan_runs")
        }
        for ix_name, ix_cols in (
            ("ix_memory_scan_runs_mode", "(analysis_mode)"),
            ("ix_memory_scan_runs_trust", "(trust_level)"),
            ("ix_memory_scan_runs_match", "(symbol_match_type)"),
        ):
            if ix_name not in existing_indexes:
                try:
                    with connection.begin_nested():
                        connection.execute(
                            text(
                                f"CREATE INDEX {ix_name} "
                                f"ON memory_scan_runs {ix_cols}"
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.info(
                        "v17: %s not created on %s (%s)",
                        ix_name, dialect, exc,
                    )
        if "ix_memory_scan_runs_experimental" not in existing_indexes:
            try:
                with connection.begin_nested():
                    connection.execute(
                        text(
                            "CREATE INDEX ix_memory_scan_runs_experimental "
                            "ON memory_scan_runs (experimental_run_id)"
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                logger.info(
                    "v17: experimental_run_id index not created on %s (%s)",
                    dialect, exc,
                )

    # 3. ``memory_plugin_runs`` additions
    if "memory_plugin_runs" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("memory_plugin_runs")}
        for column_name, column_type in (
            ("analysis_mode", "VARCHAR(32) NOT NULL DEFAULT 'validated'"),
            ("trust_level", "VARCHAR(32) NOT NULL DEFAULT 'validated'"),
        ):
            if column_name not in existing:
                connection.execute(
                    text(
                        f"ALTER TABLE memory_plugin_runs "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                logger.info("v17: added memory_plugin_runs.%s", column_name)
        for column_name, value in (
            ("analysis_mode", "validated"),
            ("trust_level", "validated"),
        ):
            if column_name in {c["name"] for c in inspector.get_columns("memory_plugin_runs")}:
                connection.execute(
                    text(
                        f"UPDATE memory_plugin_runs SET {column_name} = :value WHERE {column_name} IS NULL"
                    ),
                    {"value": value},
                )
        existing_indexes = {
            ix["name"] for ix in inspector.get_indexes("memory_plugin_runs")
        }
        for ix_name, ix_cols in (
            ("ix_memory_plugin_runs_mode", "(analysis_mode)"),
            ("ix_memory_plugin_runs_trust", "(trust_level)"),
        ):
            if ix_name not in existing_indexes:
                try:
                    with connection.begin_nested():
                        connection.execute(
                            text(
                                f"CREATE INDEX {ix_name} "
                                f"ON memory_plugin_runs {ix_cols}"
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.info(
                        "v17: %s not created on %s (%s)",
                        ix_name, dialect, exc,
                    )

    # 4. New table ``memory_experimental_symbol_candidates``.
    if "memory_experimental_symbol_candidates" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE memory_experimental_symbol_candidates ("
                "id VARCHAR(36) PRIMARY KEY, "
                "case_id VARCHAR(36) NOT NULL REFERENCES cases(id) ON DELETE CASCADE, "
                "evidence_id VARCHAR(36) NOT NULL REFERENCES evidences(id) ON DELETE CASCADE, "
                "requirement_id VARCHAR(36) NOT NULL REFERENCES memory_symbol_requirements(id) ON DELETE CASCADE, "
                "cached_symbol_id VARCHAR(36) NOT NULL REFERENCES memory_cached_symbols(id) ON DELETE CASCADE, "
                "required_pdb_name VARCHAR(128) NOT NULL, "
                "required_pdb_guid VARCHAR(32) NOT NULL, "
                "required_pdb_age INTEGER NOT NULL, "
                "required_architecture VARCHAR(32) NOT NULL, "
                "observed_pdb_name VARCHAR(128) NOT NULL, "
                "observed_pdb_guid VARCHAR(32) NOT NULL, "
                "observed_pdb_age INTEGER NOT NULL, "
                "observed_architecture VARCHAR(32) NOT NULL, "
                "symbol_match_type VARCHAR(32) NOT NULL, "
                "symbol_warning VARCHAR(255) NOT NULL, "
                "provenance_source_type VARCHAR(32) NOT NULL DEFAULT 'operator_cli_pdb', "
                "provenance_source_name VARCHAR(128) NOT NULL DEFAULT 'Operator CLI', "
                "provenance_actor VARCHAR(128) NOT NULL DEFAULT 'server-operator', "
                "source_host_path VARCHAR(512), "
                "pdb_sha256 VARCHAR(64) NOT NULL, "
                "isf_sha256 VARCHAR(64) NOT NULL, "
                "isf_validation_status VARCHAR(32) NOT NULL DEFAULT 'validated', "
                "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "revoked_at TIMESTAMP, "
                "revoked_by VARCHAR(128), "
                "revocation_reason VARCHAR(512), "
                "metadata_json JSON NOT NULL DEFAULT '{}'"
                ")"
            )
        )
        for ix_name, ix_cols in (
            (
                "ix_memory_exp_candidate_case_evidence",
                "(case_id, evidence_id)",
            ),
            (
                "ix_memory_exp_candidate_requirement",
                "(requirement_id)",
            ),
            (
                "ix_memory_exp_candidate_cached_symbol",
                "(cached_symbol_id)",
            ),
            (
                "ix_memory_exp_candidate_revoked",
                "(revoked_at)",
            ),
        ):
            try:
                with connection.begin_nested():
                    connection.execute(
                        text(f"CREATE INDEX {ix_name} ON memory_experimental_symbol_candidates {ix_cols}")
                    )
            except Exception as exc:  # noqa: BLE001
                logger.info(
                    "v17: %s not created on %s (%s)",
                    ix_name, dialect, exc,
                )
        # Partial unique index: at most one active candidate per
        # requirement.
        try:
            with connection.begin_nested():
                if dialect == "postgresql":
                    connection.execute(
                        text(
                            "CREATE UNIQUE INDEX uq_memory_exp_candidate_active_requirement "
                            "ON memory_experimental_symbol_candidates (requirement_id) "
                            "WHERE revoked_at IS NULL"
                        )
                    )
                else:
                    connection.execute(
                        text(
                            "CREATE UNIQUE INDEX uq_memory_exp_candidate_active_requirement "
                            "ON memory_experimental_symbol_candidates "
                            "(requirement_id, revoked_at)"
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "v17: candidate active index not created on %s (%s); "
                "application enforces the invariant",
                dialect, exc,
            )

    # 5. New table ``memory_experimental_runs``.
    if "memory_experimental_runs" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE memory_experimental_runs ("
                "id VARCHAR(36) PRIMARY KEY, "
                "case_id VARCHAR(36) NOT NULL REFERENCES cases(id) ON DELETE CASCADE, "
                "evidence_id VARCHAR(36) NOT NULL REFERENCES evidences(id) ON DELETE CASCADE, "
                "candidate_id VARCHAR(36) NOT NULL REFERENCES memory_experimental_symbol_candidates(id) ON DELETE CASCADE, "
                "requirement_id VARCHAR(36) NOT NULL REFERENCES memory_symbol_requirements(id) ON DELETE CASCADE, "
                "cached_symbol_id VARCHAR(36) NOT NULL REFERENCES memory_cached_symbols(id) ON DELETE CASCADE, "
                "status VARCHAR(32) NOT NULL DEFAULT 'acknowledgement_required', "
                "acknowledgement_actor VARCHAR(128), "
                "acknowledgement_at TIMESTAMP, "
                "acknowledgement_warning_version VARCHAR(64), "
                "acknowledgement_required_pdb_name VARCHAR(128), "
                "acknowledgement_required_pdb_guid VARCHAR(32), "
                "acknowledgement_required_pdb_age INTEGER, "
                "acknowledgement_required_architecture VARCHAR(32), "
                "acknowledgement_observed_pdb_name VARCHAR(128), "
                "acknowledgement_observed_pdb_guid VARCHAR(32), "
                "acknowledgement_observed_pdb_age INTEGER, "
                "acknowledgement_observed_architecture VARCHAR(32), "
                "acknowledgement_warning_text TEXT, "
                "canary_status VARCHAR(32) NOT NULL DEFAULT 'pending', "
                "canary_started_at TIMESTAMP, "
                "canary_completed_at TIMESTAMP, "
                "canary_score DOUBLE PRECISION, "
                "canary_checks JSON NOT NULL DEFAULT '[]', "
                "canary_summary JSON NOT NULL DEFAULT '{}', "
                "canary_override_required BOOLEAN NOT NULL DEFAULT false, "
                "canary_override_at TIMESTAMP, "
                "canary_override_actor VARCHAR(128), "
                "canary_override_reason VARCHAR(512), "
                "requested_profiles JSON NOT NULL DEFAULT '[]', "
                "canary_profiles JSON NOT NULL DEFAULT '[]', "
                "canary_worker_task_id VARCHAR(255), "
                "full_worker_task_id VARCHAR(255), "
                "profiles_queued INTEGER NOT NULL DEFAULT 0, "
                "profiles_completed INTEGER NOT NULL DEFAULT 0, "
                "profiles_failed INTEGER NOT NULL DEFAULT 0, "
                "profiles_cancelled INTEGER NOT NULL DEFAULT 0, "
                "started_at TIMESTAMP, "
                "completed_at TIMESTAMP, "
                "cancelled_at TIMESTAMP, "
                "cancelled_by VARCHAR(128), "
                "cancellation_reason VARCHAR(512), "
                "deleted_at TIMESTAMP, "
                "deleted_by VARCHAR(128), "
                "deletion_reason VARCHAR(512), "
                "audit_metadata_json JSON NOT NULL DEFAULT '{}', "
                "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
        )
        for ix_name, ix_cols in (
            ("ix_memory_exp_run_case", "(case_id)"),
            ("ix_memory_exp_run_evidence", "(evidence_id)"),
            ("ix_memory_exp_run_case_evidence", "(case_id, evidence_id)"),
            ("ix_memory_exp_run_candidate", "(candidate_id)"),
            ("ix_memory_exp_run_requirement", "(requirement_id)"),
            ("ix_memory_exp_run_cached_symbol", "(cached_symbol_id)"),
            ("ix_memory_exp_run_status", "(status)"),
            ("ix_memory_exp_run_canary", "(canary_status)"),
            ("ix_memory_exp_run_deleted", "(deleted_at)"),
        ):
            try:
                with connection.begin_nested():
                    connection.execute(
                        text(f"CREATE INDEX {ix_name} ON memory_experimental_runs {ix_cols}")
                    )
            except Exception as exc:  # noqa: BLE001
                logger.info(
                    "v17: %s not created on %s (%s)",
                    ix_name, dialect, exc,
                )
        try:
            with connection.begin_nested():
                if dialect == "postgresql":
                    connection.execute(
                        text(
                            "CREATE UNIQUE INDEX uq_memory_exp_run_active_evidence "
                            "ON memory_experimental_runs (case_id, evidence_id) "
                            "WHERE deleted_at IS NULL AND status NOT IN "
                            "('candidate_unavailable','cancelled','deleted','completed_untrusted','partial_untrusted','failed_untrusted','canary_failed','canary_inconclusive')"
                        )
                    )
                else:
                    connection.execute(
                        text(
                            "CREATE UNIQUE INDEX uq_memory_exp_run_active_evidence "
                            "ON memory_experimental_runs (case_id, evidence_id) "
                            "WHERE deleted_at IS NULL AND status NOT IN "
                            "('candidate_unavailable','cancelled','deleted','completed_untrusted','partial_untrusted','failed_untrusted','canary_failed','canary_inconclusive')"
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            logger.info("v17: active experimental run uniqueness not created on %s (%s)", dialect, exc)

    if dialect == "postgresql":
        try:
            with connection.begin_nested():
                connection.execute(
                    text(
                        "ALTER TABLE memory_scan_runs "
                        "ADD CONSTRAINT fk_memory_scan_runs_experimental_run "
                        "FOREIGN KEY (experimental_run_id) REFERENCES memory_experimental_runs(id) ON DELETE SET NULL"
                    )
                )
        except Exception:
            pass

    # 6. Backfill: every existing MemoryScanRun and MemoryPluginRun is
    # implicitly validated / exact.  SQLite stores booleans as
    # integers; ALTER TABLE DEFAULT takes care of legacy rows.  The
    # application-level invariants on cache_classification and on
    # the unique index on experimental candidates are the
    # authoritative gates.
    logger.info(
        "v17: experimental mismatched-symbol analysis migration complete"
    )


def _inspector_for(connection: Connection):
    from sqlalchemy import inspect

    return inspect(connection)


# ---------------------------------------------------------------------------
# v18: Volatility-native compatibility probe table
# ---------------------------------------------------------------------------


@register(18, "volatility_native_probe_table")
def _v18_native_probe(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    existing_tables = inspector.get_table_names()

    if "memory_native_probes" not in existing_tables:
        connection.execute(
            text(
                """
                CREATE TABLE memory_native_probes (
                    id VARCHAR NOT NULL,
                    case_id VARCHAR NOT NULL,
                    evidence_id VARCHAR NOT NULL,
                    requirement_id VARCHAR NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'queued',
                    queue_job_id VARCHAR(128),
                    vol_version VARCHAR(64),
                    plugin VARCHAR(128) NOT NULL DEFAULT 'windows.pslist.PsList',
                    exit_code INTEGER,
                    output_row_count INTEGER,
                    output_hash VARCHAR(128),
                    sanitized_error VARCHAR(1024),
                    structural_validation JSON,
                    heartbeat_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (id),
                    CONSTRAINT fk_native_probe_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
                    CONSTRAINT fk_native_probe_evidence FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE CASCADE,
                    CONSTRAINT fk_native_probe_requirement FOREIGN KEY (requirement_id) REFERENCES memory_symbol_requirements(id) ON DELETE CASCADE
                )
                """
            )
        )
        logger.info("v18: created memory_native_probes table")

    # Create indexes (idempotent via savepoints)
    for index_sql, index_name in [
        (
            "CREATE INDEX IF NOT EXISTS ix_memory_native_probe_evidence "
            "ON memory_native_probes (case_id, evidence_id)",
            "ix_memory_native_probe_evidence",
        ),
        (
            "CREATE INDEX IF NOT EXISTS ix_memory_native_probe_status "
            "ON memory_native_probes (status)",
            "ix_memory_native_probe_status",
        ),
    ]:
        try:
            savepoint = connection.begin_nested()
            connection.execute(text(index_sql))
            savepoint.commit()
        except Exception as exc:
            savepoint.rollback()
            logger.info(
                "v18: index %s not created on %s (%s)",
                index_name, connection.engine.dialect.name, exc,
            )

    # Partial unique index: one active probe per evidence
    dialect = connection.engine.dialect.name
    if dialect == "sqlite":
        active_index_sql = (
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_memory_native_probe_active "
            "ON memory_native_probes (evidence_id) "
            "WHERE status IN ('queued', 'running')"
        )
    else:
        active_index_sql = (
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_memory_native_probe_active "
            "ON memory_native_probes (evidence_id) "
            "WHERE status IN ('queued', 'running')"
        )
    try:
        savepoint = connection.begin_nested()
        connection.execute(text(active_index_sql))
        savepoint.commit()
    except Exception as exc:
        savepoint.rollback()
        logger.info(
            "v18: active probe uniqueness not created on %s (%s)",
            dialect, exc,
        )

    logger.info("v18: volatility native probe table migration complete")


# ---------------------------------------------------------------------------
# v19: Audit orphan memory_upload evidence references (no FK yet)
# ---------------------------------------------------------------------------


MEMORY_UPLOAD_ORPHAN_PREFLIGHT_SQL = """
SELECT
    mu.id,
    mu.case_id,
    mu.evidence_id,
    mu.status,
    mu.created_at
FROM memory_uploads mu
LEFT JOIN evidences e ON e.id = mu.evidence_id
WHERE mu.evidence_id IS NOT NULL
  AND mu.evidence_id != ''
  AND e.id IS NULL
"""


MEMORY_UPLOAD_ORPHAN_PREFLIGHT_POSTGRES_SQL = """
SELECT
    mu.id,
    mu.case_id,
    mu.evidence_id,
    mu.status,
    mu.created_at
FROM memory_uploads mu
LEFT JOIN evidences e ON e.id = CAST(mu.evidence_id AS uuid)
WHERE mu.evidence_id IS NOT NULL
  AND mu.evidence_id != ''
  AND e.id IS NULL
"""


@register(19, "memory_uploads_evidence_audit")
def _v19_memory_upload_evidence_audit(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    existing_tables = inspector.get_table_names()
    if "memory_uploads" not in existing_tables or "evidences" not in existing_tables:
        logger.info("v19: memory_uploads/evidences table missing, skipping upload evidence audit")
        return

    dialect = connection.dialect.name
    preflight_sql = (
        MEMORY_UPLOAD_ORPHAN_PREFLIGHT_POSTGRES_SQL
        if dialect == "postgresql"
        else MEMORY_UPLOAD_ORPHAN_PREFLIGHT_SQL
    )

    orphan_rows = []
    try:
        with connection.begin_nested():
            orphan_rows = connection.execute(text(preflight_sql)).fetchall()
    except Exception as exc:  # noqa: BLE001
        logger.info("v19: orphan preflight query failed (%s)", exc)

    logger.info("v19: memory_uploads orphan evidence reference count=%s", len(orphan_rows))

    if not _index_exists(connection, "ix_memory_upload_case_evidence"):
        _create_index_dialect_aware(
            connection,
            name="ix_memory_upload_case_evidence",
            create_sql="CREATE INDEX ix_memory_upload_case_evidence ON memory_uploads (case_id, evidence_id)",
        )


@register(20, "memory_upload_sessions_resumable_fields")
def _v20_memory_upload_sessions_resumable_fields(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "memory_uploads" not in inspector.get_table_names():
        return

    existing = {c["name"] for c in inspector.get_columns("memory_uploads")}
    column_defs = {
        "expected_sha256": "VARCHAR(128)",
        "chunk_size_bytes": "BIGINT NOT NULL DEFAULT 0",
        "total_chunks": "INTEGER NOT NULL DEFAULT 0",
        "received_chunk_count": "INTEGER NOT NULL DEFAULT 0",
        "expires_at": "TIMESTAMP",
        "finalized_at": "TIMESTAMP",
    }
    for column_name, column_type in column_defs.items():
        if column_name in existing:
            continue
        connection.execute(
            text(
                f"ALTER TABLE memory_uploads ADD COLUMN {column_name} {column_type}"
            )
        )

    _create_index_dialect_aware(
        connection,
        name="ix_memory_uploads_expires_at",
        create_sql="CREATE INDEX ix_memory_uploads_expires_at ON memory_uploads (expires_at)",
    )
