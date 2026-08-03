"""Tests for migration v37 (host_user_facts_windows_identity_columns).

The migration adds id_kind, account_status and attributes to
host_user_facts -- the three columns Windows local-account producers
(SAM, ProfileList) need, which pre-date this sprint's schema. Two
scenarios are covered:

1. Clean install: Base.metadata.create_all() already creates the table
   with the current model (including the three columns) -- the migration
   must be a pure no-op there (test_migration_v37_idempotent_on_fresh_db).
2. Real upgrade: a database whose host_user_facts predates v37 (simulated
   by dropping the three columns after create_all -- the standard way to
   reproduce "an older deployment's schema" without a historical database
   dump) must gain the columns via run_migrations(), keep every existing
   row intact with NULL/{} defaults, and be idempotent on a second run.
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture
def fresh_db():
    from sqlalchemy import create_engine
    from app.core.database import Base
    import app.models  # noqa: F401 - register models

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


def test_migration_v37_is_registered() -> None:
    from app.core.migrations import MIGRATIONS

    assert any(m.version == 37 for m in MIGRATIONS)


def test_migration_v37_idempotent_on_fresh_db(fresh_db) -> None:
    """create_all() already produced the current schema (the three
    columns exist) -- re-running v37's up() directly must be a no-op,
    never raise, never duplicate a column."""
    from app.core.migrations import _v37_host_user_facts_windows_identity_columns

    with fresh_db.begin() as conn:
        _v37_host_user_facts_windows_identity_columns(conn)
    with fresh_db.begin() as conn:
        _v37_host_user_facts_windows_identity_columns(conn)

    from sqlalchemy import inspect
    insp = inspect(fresh_db)
    columns = {c["name"] for c in insp.get_columns("host_user_facts")}
    assert {"id_kind", "account_status", "attributes"}.issubset(columns)


def _drop_v37_columns(engine) -> None:
    """Simulate a pre-v37 schema: strip the three columns this migration
    adds. This is test setup to reach the "before" state, not a
    production fix -- the real fix is exercised via run_migrations()."""
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE host_user_facts DROP COLUMN id_kind"))
        conn.execute(text("ALTER TABLE host_user_facts DROP COLUMN account_status"))
        conn.execute(text("ALTER TABLE host_user_facts DROP COLUMN attributes"))


def test_migration_v37_upgrades_a_pre_existing_database(fresh_db) -> None:
    """Full upgrade-path proof: old schema + a real pre-existing Linux
    row -> run_migrations() adds the columns, the row survives untouched,
    the API/resolver still work, a second run is fully idempotent."""
    from sqlalchemy import inspect, text
    from sqlalchemy.orm import sessionmaker
    from app.core.migrations import run_migrations
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
    from app.services.host_users import create_host_user_fact_observations, resolve_host_users

    _drop_v37_columns(fresh_db)
    insp = inspect(fresh_db)
    columns_before = {c["name"] for c in insp.get_columns("host_user_facts")}
    assert not {"id_kind", "account_status", "attributes"} & columns_before

    Session = sessionmaker(bind=fresh_db, future=True)
    setup_db = Session()
    case_id = "e1e1e1e1-1111-4111-8111-e1e1e1e1e1e1"
    evidence_id = "e2e2e2e2-2222-4222-8222-e2e2e2e2e2e2"
    row_id = "e3e3e3e3-3333-4333-8333-e3e3e3e3e3e3"
    setup_db.add(Case(id=case_id, name="old-case", description=None))
    setup_db.add(Evidence(
        id=evidence_id, case_id=case_id, original_filename="disk.E01", stored_path="/tmp/disk.E01",
        original_path="/tmp/disk.E01", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.disk_image, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=None,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    ))
    setup_db.commit()
    setup_db.close()

    # SQLite-only quirk: PostgreSQL's UUID(as_uuid=False) type -- used for
    # every id/FK column via UUIDMixin -- normalizes to a hyphen-stripped
    # 32-char form via its bind_processor on non-native (SQLite) dialects.
    # The ORM applies that automatically on every typed comparison
    # (resolve_host_users()'s `HostUserFact.case_id == case_id`), but a
    # raw text() INSERT does not know the column's type and stores
    # whatever string it's given. Storing the same stripped form here is
    # what makes the row visible to a later ORM-filtered query on SQLite
    # -- irrelevant on real PostgreSQL, where this test's sibling
    # (the interactive isolated-temp-DB proof in the delivery report)
    # uses genuinely native UUID values with no such mismatch.
    with fresh_db.begin() as conn:
        conn.execute(text("""
            INSERT INTO host_user_facts (id, case_id, evidence_id, username, source_kind, parser,
                uid, primary_gid, gecos, home, shell, password_status, fingerprint, provenance,
                created_at, updated_at)
            VALUES (:id, :case_id, :evidence_id, 'alice', 'passwd', 'linux_identity_raw',
                '1000', '1000', 'Alice', '/home/alice', '/bin/bash', NULL, 'old-fingerprint', '{}',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """), {"id": row_id.replace("-", ""), "case_id": case_id.replace("-", ""), "evidence_id": evidence_id.replace("-", "")})

    applied_first = run_migrations(fresh_db)
    assert 37 in applied_first

    insp = inspect(fresh_db)
    columns_after = {c["name"] for c in insp.get_columns("host_user_facts")}
    assert {"id_kind", "account_status", "attributes"}.issubset(columns_after)

    with fresh_db.connect() as conn:
        row = conn.execute(text(
            "SELECT username, uid, home, id_kind, account_status, attributes FROM host_user_facts WHERE id = :id"
        ), {"id": row_id.replace("-", "")}).fetchone()
    assert row is not None, "the pre-existing row must survive the migration"
    assert row[0] == "alice"
    assert row[1] == "1000"
    assert row[2] == "/home/alice"
    assert row[3] is None, "id_kind must never be backfilled for a pre-existing row"
    assert row[4] is None, "account_status must never be backfilled for a pre-existing row"

    db = Session()
    entries = resolve_host_users(db, case_id=case_id, evidence_id=evidence_id)
    assert len(entries) == 1
    assert entries[0]["username"] == "alice"
    assert entries[0]["identity"]["uid"]["preferred_value"] == "1000"
    assert entries[0]["identity"]["id_kind"]["status"] == "missing"
    assert entries[0]["account_status"]["status"] == "missing"
    db.close()

    # A Windows reprocess coexists with the untouched old row.
    db = Session()
    win_doc = {"host_user_fact": {
        "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
        "account_status": "active", "attributes": {"rid": "1001"},
        "parser": "windows_sam_identity", "source_file": "SAM",
    }}
    create_host_user_fact_observations(db, case_id=case_id, evidence_id=evidence_id, artifact_id=None, host_id=None, observed_at=None, documents=[win_doc])
    by_user = {e["username"]: e for e in resolve_host_users(db, case_id=case_id, evidence_id=evidence_id)}
    assert set(by_user.keys()) == {"alice", "bob"}
    assert by_user["bob"]["identity"]["id_kind"]["preferred_value"] == "rid"
    assert by_user["alice"]["identity"]["id_kind"]["status"] == "missing"
    db.close()

    applied_second = run_migrations(fresh_db)
    assert applied_second == [], "second startup must apply nothing -- fully idempotent"
    with fresh_db.connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM host_user_facts")).scalar()
    assert count == 2, "no duplication or data loss on the second startup"
