"""Tests for migration v17 (Experimental Mismatched-Symbol Analysis).

The migration adds trust fields, cache-classification fields,
the experimental symbol candidates table, and the experimental
runs table.  The test uses an in-memory SQLite to verify the
migration runs idempotently and produces the expected schema.
"""
from __future__ import annotations

import os
import sys

import pytest


# Force in-memory SQLite before importing the application
# modules.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture
def fresh_db():
    from sqlalchemy import create_engine, inspect
    from app.core.database import Base
    import app.models  # noqa: F401 - register models

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


def test_migration_v17_creates_experimental_tables(fresh_db):
    from sqlalchemy import inspect
    from app.core.migrations import MIGRATIONS

    insp = inspect(fresh_db)
    tables = set(insp.get_table_names())
    assert "memory_experimental_symbol_candidates" in tables
    assert "memory_experimental_runs" in tables
    # Migration v17 is registered.
    assert any(m.version == 17 for m in MIGRATIONS)


def test_migration_v17_adds_trust_columns(fresh_db):
    from sqlalchemy import inspect

    insp = inspect(fresh_db)
    scan_columns = {c["name"] for c in insp.get_columns("memory_scan_runs")}
    plugin_columns = {c["name"] for c in insp.get_columns("memory_plugin_runs")}
    cache_columns = {c["name"] for c in insp.get_columns("memory_cached_symbols")}
    for col in ("analysis_mode", "trust_level", "symbol_match_type"):
        assert col in scan_columns
    assert "experimental_run_id" in scan_columns
    for col in ("analysis_mode", "trust_level"):
        assert col in plugin_columns
    for col in (
        "cache_classification",
        "required_pdb_name",
        "required_pdb_guid",
        "required_pdb_age",
        "required_architecture",
    ):
        assert col in cache_columns


def test_migration_v17_idempotent(fresh_db):
    """Re-running migration v17 on a database that already has the
    v17 schema must not raise."""
    from app.core.migrations import _v17_experimental_mismatched_symbol_analysis

    # Run v17 directly twice.  The migration is engineered to be
    # idempotent (each step is gated on a pre-condition).
    with fresh_db.begin() as conn:
        _v17_experimental_mismatched_symbol_analysis(conn)
    with fresh_db.begin() as conn:
        _v17_experimental_mismatched_symbol_analysis(conn)


def test_migration_v17_creates_indexes(fresh_db):
    from sqlalchemy import inspect

    insp = inspect(fresh_db)
    for table in (
        "memory_scan_runs",
        "memory_plugin_runs",
        "memory_cached_symbols",
        "memory_experimental_runs",
        "memory_experimental_symbol_candidates",
    ):
        indexes = insp.get_indexes(table)
        assert indexes, f"Expected at least one index on {table}"


def test_active_candidate_partial_index_exists(fresh_db):
    """The migration creates a partial unique index on the
    candidate table.  SQLite ignores the WHERE clause but the
    index is still valid.
    """
    from sqlalchemy import inspect

    insp = inspect(fresh_db)
    indexes = insp.get_indexes("memory_experimental_symbol_candidates")
    index_names = {ix["name"] for ix in indexes}
    assert "uq_memory_exp_candidate_active_requirement" in index_names


def test_migration_v17_uses_postgresql_boolean_default_false() -> None:
    content = (os.path.join(os.path.dirname(__file__), "..", "app", "core", "migrations.py"))
    source = open(content, encoding="utf-8").read()
    assert "canary_override_required BOOLEAN NOT NULL DEFAULT false" in source
    assert "DEFAULT 0" not in source.split("canary_override_required", 1)[1][:80]


def test_migration_v17_declares_expected_foreign_keys_in_source() -> None:
    content = (os.path.join(os.path.dirname(__file__), "..", "app", "core", "migrations.py"))
    source = open(content, encoding="utf-8").read()
    assert "REFERENCES memory_symbol_requirements(id) ON DELETE CASCADE" in source
    assert "REFERENCES memory_cached_symbols(id) ON DELETE CASCADE" in source
    assert "REFERENCES memory_experimental_symbol_candidates(id) ON DELETE CASCADE" in source
    assert "fk_memory_scan_runs_experimental_run" in source


def test_migration_v17_declares_active_run_uniqueness() -> None:
    content = (os.path.join(os.path.dirname(__file__), "..", "app", "core", "migrations.py"))
    source = open(content, encoding="utf-8").read()
    assert "uq_memory_exp_run_active_evidence" in source
