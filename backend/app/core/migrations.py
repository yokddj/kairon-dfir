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
            exists = connection.execute(
                text("SELECT 1 FROM pg_indexes WHERE indexname = :idx"),
                {"idx": index_name},
            ).fetchone()
            if not exists:
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


# ---------------------------------------------------------------------------
# v21: Host-aware findings columns and assignment_history table
# ---------------------------------------------------------------------------


@register(21, "host_scope_findings_and_assignment_history")
def _v21_host_scope_findings_and_assignment_history(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    dialect = connection.dialect.name

    if "findings" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("findings")}
        additions = [
            ("primary_host_id", "VARCHAR"),
            ("related_host_ids", "JSONB" if dialect == "postgresql" else "JSON"),
            ("host_scope", "VARCHAR DEFAULT 'single_host'"),
        ]
        for column_name, column_type in additions:
            if column_name not in existing:
                if column_name == "related_host_ids":
                    connection.execute(
                        text(
                            f"ALTER TABLE findings ADD COLUMN {column_name} {column_type} DEFAULT '[]'"
                        )
                    )
                elif column_name == "host_scope":
                    connection.execute(
                        text(
                            f"ALTER TABLE findings ADD COLUMN {column_name} VARCHAR DEFAULT 'single_host'"
                        )
                    )
                else:
                    connection.execute(
                        text(
                            f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}"
                        )
                    )
                logger.info("v21: added findings.%s", column_name)

    if "assignment_history" not in inspector.get_table_names():
        connection.execute(
            text(
                """
                CREATE TABLE assignment_history (
                    id UUID PRIMARY KEY,
                    evidence_id UUID NOT NULL,
                    case_id VARCHAR NOT NULL,
                    previous_host_id UUID,
                    new_host_id UUID,
                    previous_status VARCHAR,
                    new_status VARCHAR,
                    method VARCHAR,
                    confidence VARCHAR,
                    actor VARCHAR,
                    reason TEXT,
                    created_at VARCHAR
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_assignment_history_case_id "
                "ON assignment_history (case_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_assignment_history_evidence_id "
                "ON assignment_history (evidence_id)"
            )
        )
        logger.info("v21: created assignment_history table")


# ---------------------------------------------------------------------------
# v22: Authentication infrastructure — users, sessions, case_access, audit
# ---------------------------------------------------------------------------


@register(22, "auth_users_sessions_caseaccess_audit")
def _v22_auth_infrastructure(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    dialect = connection.dialect.name
    jsonb_type = "JSONB" if dialect == "postgresql" else "JSON"

    if "users" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS users ("
                "id VARCHAR PRIMARY KEY, "
                "username VARCHAR UNIQUE NOT NULL, "
                "email VARCHAR, "
                "display_name VARCHAR, "
                "password_hash VARCHAR NOT NULL, "
                "is_active BOOLEAN NOT NULL DEFAULT TRUE, "
                "is_admin BOOLEAN NOT NULL DEFAULT FALSE, "
                "created_at VARCHAR, "
                "updated_at VARCHAR, "
                "last_login_at VARCHAR, "
                "password_changed_at VARCHAR"
                ")"
            )
        )
        try:
            connection.execute(
                text("CREATE INDEX ix_users_username ON users (username)")
            )
        except Exception:
            pass
        logger.info("v22: created users table")

    if "sessions" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS sessions ("
                "id VARCHAR PRIMARY KEY, "
                "user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE, "
                "token_hash VARCHAR UNIQUE NOT NULL, "
                "created_at VARCHAR, "
                "expires_at VARCHAR NOT NULL, "
                "revoked_at VARCHAR, "
                "ip_address VARCHAR, "
                "user_agent VARCHAR"
                ")"
            )
        )
        try:
            connection.execute(
                text("CREATE INDEX ix_sessions_user_id ON sessions (user_id)")
            )
        except Exception:
            pass
        try:
            connection.execute(
                text("CREATE INDEX ix_sessions_token_hash ON sessions (token_hash)")
            )
        except Exception:
            pass
        logger.info("v22: created sessions table")

    if "case_access" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS case_access ("
                "id VARCHAR PRIMARY KEY, "
                "case_id VARCHAR NOT NULL, "
                "user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE, "
                "role VARCHAR NOT NULL DEFAULT 'viewer', "
                "granted_by VARCHAR, "
                "created_at VARCHAR"
                ")"
            )
        )
        try:
            connection.execute(
                text("CREATE INDEX ix_case_access_case_id ON case_access (case_id)")
            )
        except Exception:
            pass
        try:
            connection.execute(
                text("CREATE INDEX ix_case_access_user_id ON case_access (user_id)")
            )
        except Exception:
            pass
        try:
            connection.execute(
                text("CREATE INDEX ix_case_access_case_user ON case_access (case_id, user_id)")
            )
        except Exception:
            pass
        logger.info("v22: created case_access table")

    if "audit_events" not in inspector.get_table_names():
        connection.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS audit_events ("
                "id VARCHAR PRIMARY KEY, "
                "occurred_at VARCHAR, "
                "actor_user_id VARCHAR, "
                "action VARCHAR NOT NULL, "
                "resource_type VARCHAR, "
                "resource_id VARCHAR, "
                "case_id VARCHAR, "
                "result VARCHAR, "
                "ip_address VARCHAR, "
                "user_agent VARCHAR, "
                f"metadata_json {jsonb_type}"
                ")"
            )
        )
        for idx_name, idx_cols in (
            ("ix_audit_events_occurred_at", "occurred_at"),
            ("ix_audit_events_actor_user_id", "actor_user_id"),
            ("ix_audit_events_action", "action"),
            ("ix_audit_events_case_id", "case_id"),
        ):
            try:
                connection.execute(
                    text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON audit_events ({idx_cols})")
                )
            except Exception:
                pass
        logger.info("v22: created audit_events table")


@register(23, "evidence_integrity_chain_of_custody")
def _v23_evidence_integrity_chain_of_custody(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    tables = set(inspector.get_table_names())
    dialect = connection.dialect.name
    if "evidences" in tables:
        existing = {c["name"] for c in inspector.get_columns("evidences")}
        column_defs = {
            "mime_type": "VARCHAR(255)",
            "detected_type": "VARCHAR(255)",
            "uploaded_by_user_id": "VARCHAR",
            "uploaded_at": "TIMESTAMP",
            "first_seen_at": "TIMESTAMP",
            "last_processed_at": "TIMESTAMP",
            "integrity_status": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
            "integrity_checked_at": "TIMESTAMP",
            "notes": "VARCHAR(2048)",
        }
        for column_name, column_type in column_defs.items():
            if column_name not in existing:
                connection.execute(text(f"ALTER TABLE evidences ADD COLUMN {column_name} {column_type}"))
        if "uploaded_at" not in existing:
            connection.execute(text("UPDATE evidences SET uploaded_at = created_at WHERE uploaded_at IS NULL"))
        if dialect == "postgresql":
            connection.execute(text("ALTER TABLE evidences ALTER COLUMN uploaded_at SET DEFAULT CURRENT_TIMESTAMP"))
            connection.execute(text("ALTER TABLE evidences ALTER COLUMN uploaded_at SET NOT NULL"))
            connection.execute(text("ALTER TABLE evidences ALTER COLUMN sha256 DROP NOT NULL"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidences_uploaded_by_user_id ON evidences (uploaded_by_user_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidences_integrity_status ON evidences (integrity_status)"))

    if "evidence_custody_events" not in tables:
        pk_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
        json_type = "JSONB" if dialect == "postgresql" else "JSON"
        connection.execute(
            text(
                f"""
                CREATE TABLE evidence_custody_events (
                    id {pk_type} PRIMARY KEY,
                    evidence_id {pk_type} NOT NULL,
                    event_type VARCHAR(64) NOT NULL,
                    actor_user_id VARCHAR,
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    summary VARCHAR(512) NOT NULL,
                    details_json {json_type} NOT NULL DEFAULT '{{}}',
                    FOREIGN KEY(evidence_id) REFERENCES evidences(id) ON DELETE CASCADE,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
                )
                """
            )
        )
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_evidence_id ON evidence_custody_events (evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_event_type ON evidence_custody_events (event_type)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_timestamp ON evidence_custody_events (timestamp)"))


# ---------------------------------------------------------------------------
# v24: Evidence custody enum values for host assignment events
# ---------------------------------------------------------------------------


@register(24, "evidence_custody_host_assignment_event_types")
def _v24_evidence_custody_host_assignment_event_types(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        return

    enum_exists = connection.execute(
        text("SELECT 1 FROM pg_type WHERE typname = 'evidencecustodyeventtype'")
    ).fetchone()
    if not enum_exists:
        return

    for value in ("host_assigned", "host_unassigned", "host_created", "host_assignment_changed"):
        connection.execute(text(f"ALTER TYPE evidencecustodyeventtype ADD VALUE IF NOT EXISTS '{value}'"))


# ---------------------------------------------------------------------------
# v25: Case management metadata
# ---------------------------------------------------------------------------


@register(25, "case_management_metadata")
def _v25_case_management_metadata(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "cases" not in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    existing = {c["name"] for c in inspector.get_columns("cases")}

    if dialect == "postgresql" and "status" in existing:
        connection.execute(text("ALTER TABLE cases ALTER COLUMN status TYPE VARCHAR(32) USING status::text"))
    if "priority" not in existing:
        connection.execute(text("ALTER TABLE cases ADD COLUMN priority VARCHAR(32) NOT NULL DEFAULT 'medium'"))
    if "case_notes" not in existing:
        connection.execute(text("ALTER TABLE cases ADD COLUMN case_notes TEXT"))
    if "management_tags" not in existing:
        tags_type = "JSONB" if dialect == "postgresql" else "JSON"
        default_value = "'[]'::jsonb" if dialect == "postgresql" else "'[]'"
        connection.execute(text(f"ALTER TABLE cases ADD COLUMN management_tags {tags_type} NOT NULL DEFAULT {default_value}"))

    connection.execute(text("UPDATE cases SET status = 'active' WHERE status = 'open' OR status IS NULL"))
    connection.execute(text("UPDATE cases SET priority = 'medium' WHERE priority IS NULL OR priority = ''"))


@register(26, "findings_notes_v1")
def _v26_findings_notes_v1(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "findings" not in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    existing = {c["name"] for c in inspector.get_columns("findings")}

    if dialect == "postgresql" and "status" in existing:
        connection.execute(text("ALTER TABLE findings ALTER COLUMN status TYPE VARCHAR(32) USING status::text"))
    if dialect == "postgresql" and "severity" in existing:
        connection.execute(text("ALTER TABLE findings ALTER COLUMN severity TYPE VARCHAR(32) USING severity::text"))

    column_defs = {
        "linked_evidence_id": "UUID",
        "linked_host_id": "UUID",
        "linked_artifact_id": "UUID",
        "linked_artifact_family": "VARCHAR(128)",
        "linked_artifact_type": "VARCHAR(128)",
        "source_view": "VARCHAR(128)",
        "created_by": "VARCHAR(128)",
        "archived_at": "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(text(f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}"))

    connection.execute(text("UPDATE findings SET status = 'draft' WHERE status IS NULL OR status = ''"))
    connection.execute(text("UPDATE findings SET status = 'archived' WHERE status = 'suppressed' AND archived_at IS NOT NULL"))
    if dialect == "postgresql":
        connection.execute(text("UPDATE findings SET linked_evidence_id = evidence_id WHERE linked_evidence_id IS NULL AND evidence_id IS NOT NULL"))
    else:
        connection.execute(text("UPDATE findings SET linked_evidence_id = evidence_id WHERE linked_evidence_id IS NULL AND evidence_id IS NOT NULL"))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_linked_evidence_id ON findings (linked_evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_linked_host_id ON findings (linked_host_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_linked_artifact_id ON findings (linked_artifact_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_archived_at ON findings (archived_at)"))


@register(27, "finding_from_artifact_source")
def _v27_finding_from_artifact_source(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "findings" not in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    existing = {c["name"] for c in inspector.get_columns("findings")}
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    column_defs = {
        "linked_event_id": "VARCHAR(255)",
        "source_route": "VARCHAR(1024)",
        "source_timestamp": "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP",
        "source_label": "VARCHAR(255)",
        "source_summary": "TEXT",
        "source_snapshot_json": json_type,
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(text(f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_linked_event_id ON findings (linked_event_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_source_timestamp ON findings (source_timestamp)"))


@register(28, "evidence_platform_selection")
def _v28_evidence_platform_selection(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "evidences" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("evidences")}
    column_defs = {
        "provided_platform": "VARCHAR(32) NOT NULL DEFAULT 'auto'",
        "detected_platform": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "effective_platform": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(text(f"ALTER TABLE evidences ADD COLUMN {column_name} {column_type}"))
    connection.execute(text("UPDATE evidences SET provided_platform = 'auto' WHERE provided_platform IS NULL OR provided_platform = ''"))
    connection.execute(text("UPDATE evidences SET detected_platform = 'unknown' WHERE detected_platform IS NULL OR detected_platform = '' OR detected_platform = 'auto'"))
    connection.execute(text("UPDATE evidences SET effective_platform = CASE WHEN provided_platform IS NOT NULL AND provided_platform NOT IN ('', 'auto') THEN provided_platform WHEN detected_platform IS NOT NULL AND detected_platform NOT IN ('', 'auto') THEN detected_platform ELSE 'unknown' END WHERE effective_platform IS NULL OR effective_platform = '' OR effective_platform = 'auto'"))


@register(29, "disk_image_ingestion")
def _v29_disk_image_ingestion(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    tables = set(inspector.get_table_names())
    if "disk_images" not in tables:
        connection.execute(
            text(
                f"""
                CREATE TABLE disk_images (
                    id {id_type} PRIMARY KEY,
                    evidence_id {id_type} NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
                    original_filename VARCHAR(512) NOT NULL,
                    format VARCHAR(64) NOT NULL,
                    size_bytes BIGINT NOT NULL DEFAULT 0,
                    sha256 VARCHAR(128),
                    segment_count INTEGER NOT NULL DEFAULT 1,
                    status VARCHAR(64) NOT NULL DEFAULT 'uploaded',
                    metadata_json {json_type} NOT NULL DEFAULT '{{}}',
                    tool_metadata {json_type} NOT NULL DEFAULT '{{}}',
                    warnings_json {json_type} NOT NULL DEFAULT '[]',
                    error_json {json_type} NOT NULL DEFAULT '{{}}',
                    created_at {timestamp_type} NOT NULL,
                    updated_at {timestamp_type} NOT NULL
                )
                """
            )
        )
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_disk_images_evidence_id ON disk_images (evidence_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_disk_images_format ON disk_images (format)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_disk_images_status ON disk_images (status)"))
    if "disk_volumes" not in tables:
        connection.execute(
            text(
                f"""
                CREATE TABLE disk_volumes (
                    id {id_type} PRIMARY KEY,
                    disk_image_id {id_type} NOT NULL REFERENCES disk_images(id) ON DELETE CASCADE,
                    partition_index INTEGER NOT NULL DEFAULT 0,
                    offset_bytes BIGINT NOT NULL DEFAULT 0,
                    length_bytes BIGINT NOT NULL DEFAULT 0,
                    partition_type VARCHAR(128),
                    filesystem_type VARCHAR(64),
                    label VARCHAR(255),
                    uuid VARCHAR(128),
                    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
                    readable BOOLEAN NOT NULL DEFAULT FALSE,
                    status VARCHAR(64) NOT NULL DEFAULT 'discovered',
                    warnings_json {json_type} NOT NULL DEFAULT '[]',
                    error_json {json_type} NOT NULL DEFAULT '{{}}',
                    metadata_json {json_type} NOT NULL DEFAULT '{{}}',
                    created_at {timestamp_type} NOT NULL,
                    updated_at {timestamp_type} NOT NULL
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_disk_volumes_disk_image_id ON disk_volumes (disk_image_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_disk_volumes_status ON disk_volumes (status)"))
    if "os_installations" not in tables:
        connection.execute(
            text(
                f"""
                CREATE TABLE os_installations (
                    id {id_type} PRIMARY KEY,
                    disk_volume_id {id_type} NOT NULL REFERENCES disk_volumes(id) ON DELETE CASCADE,
                    platform VARCHAR(32) NOT NULL,
                    hostname VARCHAR(255),
                    version VARCHAR(255),
                    distro VARCHAR(255),
                    root_path VARCHAR(1024) NOT NULL DEFAULT '/',
                    confidence VARCHAR(32) NOT NULL DEFAULT 'medium',
                    detection_reasons {json_type} NOT NULL DEFAULT '[]',
                    metadata_json {json_type} NOT NULL DEFAULT '{{}}',
                    created_at {timestamp_type} NOT NULL,
                    updated_at {timestamp_type} NOT NULL
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_os_installations_disk_volume_id ON os_installations (disk_volume_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_os_installations_platform ON os_installations (platform)"))
    if "artifacts" in tables:
        existing = {c["name"] for c in inspector.get_columns("artifacts")}
        additions = {
            "disk_image_id": f"{id_type} REFERENCES disk_images(id) ON DELETE SET NULL",
            "disk_volume_id": f"{id_type} REFERENCES disk_volumes(id) ON DELETE SET NULL",
            "os_installation_id": f"{id_type} REFERENCES os_installations(id) ON DELETE SET NULL",
            "original_source_path": "VARCHAR(4096)",
            "logical_source_path": "VARCHAR(4096)",
            "acquisition_method": "VARCHAR(128)",
        }
        for column_name, column_type in additions.items():
            if column_name not in existing:
                connection.execute(text(f"ALTER TABLE artifacts ADD COLUMN {column_name} {column_type}"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_artifacts_disk_image_id ON artifacts (disk_image_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_artifacts_disk_volume_id ON artifacts (disk_volume_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_artifacts_os_installation_id ON artifacts (os_installation_id)"))


@register(30, "evidence_upload_sessions_resumable_state")
def _v30_evidence_upload_sessions_resumable_state(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    if "evidence_upload_sessions" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("evidence_upload_sessions")}
    column_defs = {
        "expected_size_bytes": "BIGINT",
        "bytes_received": "BIGINT NOT NULL DEFAULT 0",
        "last_activity_at": "TIMESTAMP",
    }
    for column_name, column_type in column_defs.items():
        if column_name not in existing:
            connection.execute(text(f"ALTER TABLE evidence_upload_sessions ADD COLUMN {column_name} {column_type}"))
    connection.execute(text("UPDATE evidence_upload_sessions SET bytes_received = size_bytes WHERE bytes_received = 0 AND size_bytes > 0"))


@register(31, "evidence_operations")
def _v31_evidence_operations(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    tables = set(inspector.get_table_names())
    if "evidence_operations" in tables:
        return
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    connection.execute(text(f"""
        CREATE TABLE evidence_operations (
            id {id_type} PRIMARY KEY,
            case_id {id_type} NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            upload_session_id {id_type} REFERENCES evidence_upload_sessions(id) ON DELETE SET NULL,
            evidence_id {id_type} REFERENCES evidences(id) ON DELETE SET NULL,
            kind VARCHAR(64) NOT NULL,
            status VARCHAR(32) NOT NULL,
            stage VARCHAR(64) NOT NULL DEFAULT 'created',
            owner VARCHAR(32) NOT NULL DEFAULT 'backend',
            progress INTEGER,
            bytes_received BIGINT,
            expected_size_bytes BIGINT,
            started_at {timestamp_type},
            completed_at {timestamp_type},
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            metadata_json {json_type} NOT NULL DEFAULT {json_default},
            created_at {timestamp_type} NOT NULL,
            updated_at {timestamp_type} NOT NULL
        )
    """))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operations_case_id ON evidence_operations (case_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operations_upload_session_id ON evidence_operations (upload_session_id)"))
    connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_operations_upload_session_kind ON evidence_operations (upload_session_id, kind)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operations_evidence_id ON evidence_operations (evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operations_kind ON evidence_operations (kind)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operations_status ON evidence_operations (status)"))


@register(32, "evidence_operation_jobs")
def _v32_evidence_operation_jobs(connection: Connection) -> None:
    inspector = _inspector_for(connection)
    tables = set(inspector.get_table_names())
    if "evidence_operation_jobs" in tables:
        return
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    connection.execute(text(f"""
        CREATE TABLE evidence_operation_jobs (
            id {id_type} PRIMARY KEY,
            operation_id {id_type} NOT NULL REFERENCES evidence_operations(id) ON DELETE CASCADE,
            case_id {id_type} NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id {id_type} REFERENCES evidences(id) ON DELETE SET NULL,
            upload_session_id {id_type} REFERENCES evidence_upload_sessions(id) ON DELETE SET NULL,
            job_type VARCHAR(64) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'queued',
            progress INTEGER,
            owner VARCHAR(32) NOT NULL DEFAULT 'worker',
            rq_job_id VARCHAR(128),
            dedupe_key VARCHAR(128) NOT NULL,
            started_at {timestamp_type},
            finished_at {timestamp_type},
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            metadata_json {json_type} NOT NULL DEFAULT {json_default},
            created_at {timestamp_type} NOT NULL,
            updated_at {timestamp_type} NOT NULL,
            CONSTRAINT uq_evidence_operation_jobs_dedupe UNIQUE (operation_id, job_type, dedupe_key)
        )
    """))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_operation_id ON evidence_operation_jobs (operation_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_case_id ON evidence_operation_jobs (case_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_evidence_id ON evidence_operation_jobs (evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_upload_session_id ON evidence_operation_jobs (upload_session_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_job_type ON evidence_operation_jobs (job_type)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_status ON evidence_operation_jobs (status)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_operation_jobs_rq_job_id ON evidence_operation_jobs (rq_job_id)"))


# ---------------------------------------------------------------------------
# v33: assignment_history.evidence_id cascades on evidence deletion
# ---------------------------------------------------------------------------


@register(33, "assignment_history_evidence_cascade_delete")
def _v33_assignment_history_evidence_cascade_delete(connection: Connection) -> None:
    """DELETE /api/evidences/{id} deletes the evidence's OpenSearch events and
    on-disk files unconditionally, then deletes the Evidence row last. The v21
    migration created assignment_history.evidence_id without ON DELETE CASCADE
    (and a fresh install's Base.metadata.create_all follows the ORM model,
    which had the same gap), so any evidence with host-assignment history hit
    a ForeignKeyViolation on that final step -- leaving an orphaned Evidence
    row with no files or indexed data behind it. Recreate the constraint with
    ON DELETE CASCADE so the delete is atomic again.
    """
    if connection.dialect.name != "postgresql":
        return
    inspector = _inspector_for(connection)
    if "assignment_history" not in inspector.get_table_names():
        return
    for fk in inspector.get_foreign_keys("assignment_history"):
        if fk.get("constrained_columns") == ["evidence_id"]:
            constraint_name = fk.get("name")
            if constraint_name:
                connection.execute(text(f'ALTER TABLE assignment_history DROP CONSTRAINT "{constraint_name}"'))
            break
    connection.execute(
        text(
            "ALTER TABLE assignment_history "
            "ADD CONSTRAINT assignment_history_evidence_id_fkey "
            "FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE CASCADE"
        )
    )


# ---------------------------------------------------------------------------
# v34: host_facts -- generic Host Facts foundation, first consumer: timezone
# ---------------------------------------------------------------------------


@register(34, "host_facts")
def _v34_host_facts(connection: Connection) -> None:
    """Introduce the Host Facts abstraction: a small, connected table of
    per-source observations (fact type, value, normalized value, source
    artifact, parser, confidence, status, provenance) that future facts
    (hostname, boot time, network interfaces, locale, ...) reuse alongside
    the first consumer, host.timezone. It does not duplicate evidence --
    each row references its case/evidence/artifact rather than copying
    file content, and the full observation stays searchable as a normal
    indexed event via the artifact's own family (e.g. linux_timezone).
    """
    inspector = _inspector_for(connection)
    if "host_facts" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    connection.execute(text(f"""
        CREATE TABLE host_facts (
            id {id_type} PRIMARY KEY,
            case_id {id_type} NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id {id_type} NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
            artifact_id {id_type} REFERENCES artifacts(id) ON DELETE SET NULL,
            host_id {id_type} REFERENCES case_hosts(id) ON DELETE SET NULL,
            fact_type VARCHAR(64) NOT NULL,
            source_kind VARCHAR(64) NOT NULL,
            parser VARCHAR(128) NOT NULL,
            source_path VARCHAR(2048),
            raw_value TEXT,
            normalized_value VARCHAR(255),
            confidence VARCHAR(16) NOT NULL DEFAULT 'medium',
            status VARCHAR(32) NOT NULL DEFAULT 'observed',
            observed_at {timestamp_type},
            event_id VARCHAR(64),
            fingerprint VARCHAR(64) NOT NULL,
            provenance {json_type} NOT NULL DEFAULT {json_default},
            created_at {timestamp_type} NOT NULL,
            updated_at {timestamp_type} NOT NULL
        )
    """))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_case_id ON host_facts (case_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_evidence_id ON host_facts (evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_artifact_id ON host_facts (artifact_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_host_id ON host_facts (host_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_fact_type ON host_facts (fact_type)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_normalized_value ON host_facts (normalized_value)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_status ON host_facts (status)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_event_id ON host_facts (event_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_fingerprint ON host_facts (fingerprint)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_facts_case_host_type ON host_facts (case_id, host_id, fact_type)"))


# ---------------------------------------------------------------------------
# v35: host_user_facts -- Host User Inventory, sibling to host_facts
# ---------------------------------------------------------------------------


@register(35, "host_user_facts")
def _v35_host_user_facts(connection: Connection) -> None:
    """Introduce Host User Inventory: one row per per-account observation
    (passwd/shadow/lastlog/group), correlated into one inventory entry per
    username at read time (see app.services.host_users.resolve_host_users).
    A sibling to host_facts rather than a reuse of it -- these rows bundle
    several fields produced together by one artifact line (a passwd line
    already carries uid/gid/home/shell/gecos together) instead of a single
    normalized_value, and are scoped by username (nullable, for
    group_definition rows) rather than fact_type alone. Never stores
    password hashes or raw shadow content -- password_status is a
    locked/set/empty classification computed once at parse time.
    """
    inspector = _inspector_for(connection)
    if "host_user_facts" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "TIMESTAMP"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    connection.execute(text(f"""
        CREATE TABLE host_user_facts (
            id {id_type} PRIMARY KEY,
            case_id {id_type} NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id {id_type} NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
            artifact_id {id_type} REFERENCES artifacts(id) ON DELETE SET NULL,
            host_id {id_type} REFERENCES case_hosts(id) ON DELETE SET NULL,
            username VARCHAR(255),
            source_kind VARCHAR(32) NOT NULL,
            parser VARCHAR(128) NOT NULL,
            source_path VARCHAR(2048),
            uid VARCHAR(32),
            primary_gid VARCHAR(32),
            gecos VARCHAR(255),
            home VARCHAR(1024),
            shell VARCHAR(255),
            password_status VARCHAR(16),
            last_login_at {timestamp_type},
            last_login_source_ip VARCHAR(64),
            last_login_terminal VARCHAR(64),
            group_name VARCHAR(255),
            group_gid VARCHAR(32),
            observed_at {timestamp_type},
            event_id VARCHAR(64),
            fingerprint VARCHAR(64) NOT NULL,
            provenance {json_type} NOT NULL DEFAULT {json_default},
            created_at {timestamp_type} NOT NULL,
            updated_at {timestamp_type} NOT NULL
        )
    """))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_case_id ON host_user_facts (case_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_evidence_id ON host_user_facts (evidence_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_artifact_id ON host_user_facts (artifact_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_host_id ON host_user_facts (host_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_username ON host_user_facts (username)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_source_kind ON host_user_facts (source_kind)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_event_id ON host_user_facts (event_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_fingerprint ON host_user_facts (fingerprint)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_host_user_facts_case_host_user ON host_user_facts (case_id, host_id, username)"))


@register(36, "case_investigation_phase_override")
def _v36_case_investigation_phase_override(connection: Connection) -> None:
    """Add ``cases.investigation_phase_override`` for the manual
    INVESTIGATE/REPORT workflow actions ("Start investigation" / "Generate
    report").

    UPLOAD/PREPARE/ANALYZE stay fully automatic (derived from evidence and
    indexing counts, see ``app.services.case_state.derive_case_investigation_state``).
    INVESTIGATE and REPORT no longer auto-activate from candidate timeline
    items, marked events, findings or official timeline entries -- they now
    require this explicit, persisted analyst decision. NULL means no
    override (the case stays at investigation_ready once automatically
    ready); ``'investigating'`` and ``'report'`` are the only other values,
    set via the existing ``PATCH /cases/{case_id}`` endpoint.

    Existing cases that previously auto-computed into
    investigation_in_progress or report_ready are intentionally NOT
    backfilled: they reset to investigation_ready and the analyst
    re-confirms with a single click. This is a one-time, non-destructive
    display reset -- no findings, timeline items or other data are
    affected.
    """
    inspector = _inspector_for(connection)
    if "cases" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("cases")}
    if "investigation_phase_override" not in existing:
        connection.execute(text("ALTER TABLE cases ADD COLUMN investigation_phase_override VARCHAR(32)"))


@register(37, "host_user_facts_windows_identity_columns")
def _v37_host_user_facts_windows_identity_columns(connection: Connection) -> None:
    """Add the three columns Windows local-account producers (SAM,
    ProfileList -- see app.ingest.raw_parsers.sam_identity_parser /
    profile_list_parser) need on ``host_user_facts``, alongside the
    Linux-only columns v35 already created:

    * ``id_kind`` (VARCHAR(16), nullable) -- "uid" | "rid" | NULL. Records
      which local-identifier concept produced ``uid`` on this row, so the
      API/UI can label it correctly without any platform check of their
      own. NULL on every pre-existing Linux row (passwd never set it) --
      resolve_host_users() treats a NULL id_kind exactly like any other
      "missing" field, never inferring it after the fact.
    * ``account_status`` (VARCHAR(16), nullable) -- a normalized
      classification ("active" | "disabled" | "locked" | NULL) computed
      once at parse time by each producer from its OWN reliable signal
      (Linux: shadow password_status; Windows: SAM's real F-value control-
      flag bits). NULL on every pre-existing row of either platform --
      account_status used to be derived ad hoc at read time from
      password_status alone (pre-refactor); existing rows simply have no
      value here until the evidence that produced them is reprocessed.
      This is intentional, not a data-loss bug: the raw password_status
      column (and every other pre-existing column) is completely
      unaffected and keeps resolving exactly as before.
    * ``attributes`` (JSON/JSONB, NOT NULL, default ``{}``) -- producer-
      specific extras with no cross-platform column (Windows RID/SID,
      non-secret SAM control-flag labels, logon_count, bad_password_count,
      last_password_set, ProfileList profile_state). Mirrors how
      host_facts.provenance holds producer-specific extras without
      widening that table's own schema. Never holds password hashes,
      bootkey material, or any other secret -- see
      app.ingest.windows.sam_identity's module docstring and
      tests/test_sam_identity_security.py for the enforced contract.

    Idempotent (skips columns that already exist, same pattern as v1/v34)
    and purely additive: no existing host_user_facts row is read, altered
    or deleted. A database that already has these columns (e.g. a fresh
    install where Base.metadata.create_all() created the table with the
    current model) is a no-op here.
    """
    inspector = _inspector_for(connection)
    if "host_user_facts" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("host_user_facts")}
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    json_default = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
    if "id_kind" not in existing:
        connection.execute(text("ALTER TABLE host_user_facts ADD COLUMN id_kind VARCHAR(16)"))
    if "account_status" not in existing:
        connection.execute(text("ALTER TABLE host_user_facts ADD COLUMN account_status VARCHAR(16)"))
    if "attributes" not in existing:
        connection.execute(
            text(f"ALTER TABLE host_user_facts ADD COLUMN attributes {json_type} NOT NULL DEFAULT {json_default}")
        )


@register(38, "memory_evidence_linux_symbol_links")
def _v38_memory_evidence_linux_symbol_links(connection: Connection) -> None:
    """Memory Preparation Phase 3: async Linux ISF validation job AND,
    once VALID, the persistent evidence <-> ISF link.

    Linux memory symbols are prebuilt Volatility ISF tables promoted into
    a filesystem cache keyed by ``cache_key``
    (app.services.memory.linux_symbols.LinuxSymbolIdentity.cache_key) --
    there is no Windows-style DB "requirement" table for Linux to attach
    a per-evidence link to (see memory_evidence_symbol_links, v8, for the
    Windows equivalent). This table is that missing link.

    Validation runs on the memory-worker (the only process with
    read-write access to the shared cache; the backend API container's
    mount is read-only), so this row also tracks the job lifecycle:
    ``status`` moves queued -> validating -> one of
    valid/invalid/unsupported/validation_failed. Only once
    ``status == 'valid'`` do the cache_key/isf_path/sha256/identity_*
    columns represent an active, promoted link -- hence they are
    nullable. ``evidence_id`` is unique -- at most one row per evidence;
    re-validating updates the existing row rather than creating a
    duplicate. Several evidences may share the same ``cache_key``.
    """
    inspector = _inspector_for(connection)
    if "memory_evidence_linux_symbol_links" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    json_type = "JSONB" if dialect == "postgresql" else "JSON"
    id_type = "UUID" if dialect == "postgresql" else "VARCHAR(36)"
    connection.execute(text(f"""
        CREATE TABLE memory_evidence_linux_symbol_links (
            id {id_type} PRIMARY KEY,
            case_id {id_type} NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id {id_type} NOT NULL UNIQUE REFERENCES evidences(id) ON DELETE CASCADE,
            status VARCHAR(32) NOT NULL DEFAULT 'queued',
            staging_path VARCHAR(1024),
            worker_task_id VARCHAR(128),
            expected_identity_json {json_type},
            detected_identity_json {json_type},
            reason VARCHAR(512),
            cached BOOLEAN NOT NULL DEFAULT FALSE,
            cache_key VARCHAR(64),
            isf_path VARCHAR(1024),
            sha256 VARCHAR(64),
            identity_display VARCHAR(512),
            identity_json {json_type},
            link_source VARCHAR(32) NOT NULL DEFAULT 'evidence_scoped_upload',
            queued_at TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
    """))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_memory_evidence_linux_symbol_links_case_id ON memory_evidence_linux_symbol_links (case_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_memory_evidence_linux_symbol_links_cache_key ON memory_evidence_linux_symbol_links (cache_key)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_memory_evidence_linux_symbol_links_status ON memory_evidence_linux_symbol_links (status)"))
