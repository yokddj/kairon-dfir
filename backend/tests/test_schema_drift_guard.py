"""A tripwire for schema changes that existing deployments would never receive.

The schema is created by `Base.metadata.create_all()` and evolved by the
versioned migrations in `app.core.migrations`. create_all() only ever creates
*missing tables*: it never adds a column to a table that already exists. So a
new column on an existing model reaches a fresh install and silently skips
every deployment already in the field, where the code then queries a column the
database does not have.

Nothing catches that today, because the code and the models agree with each
other -- only a real, already-migrated database disagrees, and by then a case is
already loaded into it.

This test fails whenever the models stop matching the committed snapshot. It is
a tripwire, not a proof: the fix is to write the migration and then update the
snapshot in the same commit, so a reviewer sees both together.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.database import Base
import app.models  # noqa: F401 - importing registers every model on Base

SNAPSHOT_PATH = Path(__file__).parent / "schema_snapshot.json"

REGENERATE_HINT = (
    "\n\nIf this change is intentional:\n"
    "  1. Add a migration in backend/app/core/migrations.py with the next\n"
    "     @register(version, name) so deployed databases receive it too.\n"
    "     A new *table* needs no migration -- create_all() handles that.\n"
    "     A new or changed *column* on an existing table always does.\n"
    "  2. Refresh the snapshot in the same commit:\n"
    "     python -c \"import json,pathlib;from app.core.database import Base;"
    "import app.models;"
    "pathlib.Path('tests/schema_snapshot.json').write_text("
    "json.dumps({n:sorted(t.columns.keys()) for n,t in sorted(Base.metadata.tables.items())},"
    "indent=2,sort_keys=True)+chr(10))\"\n"
)


def current_schema() -> dict[str, list[str]]:
    return {name: sorted(table.columns.keys()) for name, table in sorted(Base.metadata.tables.items())}


def stored_schema() -> dict[str, list[str]]:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def test_the_snapshot_exists_and_is_not_empty():
    stored = stored_schema()
    assert stored, "the snapshot is the baseline; an empty one guards nothing"
    assert len(stored) > 40, "the snapshot looks truncated rather than current"


def test_no_column_was_added_to_an_existing_table_without_notice():
    """The dangerous case: deployed databases never get this column."""
    stored = stored_schema()
    current = current_schema()

    added: list[str] = []
    for table, columns in current.items():
        if table not in stored:
            continue  # a brand new table; create_all() handles it everywhere
        new_columns = sorted(set(columns) - set(stored[table]))
        added.extend(f"{table}.{column}" for column in new_columns)

    assert not added, (
        "These columns exist on the models but not in the committed snapshot, "
        "so every already-deployed database is missing them:\n  "
        + "\n  ".join(added)
        + REGENERATE_HINT
    )


def test_no_column_was_removed_without_notice():
    """A dropped column still exists in deployed databases and in old rows."""
    stored = stored_schema()
    current = current_schema()

    removed: list[str] = []
    for table, columns in stored.items():
        if table not in current:
            continue
        gone = sorted(set(columns) - set(current[table]))
        removed.extend(f"{table}.{column}" for column in gone)

    assert not removed, (
        "These columns are in the snapshot but no longer on the models:\n  "
        + "\n  ".join(removed)
        + REGENERATE_HINT
    )


def test_a_dropped_table_is_noticed():
    stored = stored_schema()
    current = current_schema()

    dropped = sorted(set(stored) - set(current))

    assert not dropped, (
        "These tables are in the snapshot but no longer on the models: "
        f"{dropped}.{REGENERATE_HINT}"
    )


def test_a_new_table_is_reported_but_is_not_a_deployment_hazard():
    """New tables are safe -- create_all() creates them on every start."""
    stored = stored_schema()
    current = current_schema()

    added_tables = sorted(set(current) - set(stored))

    assert not added_tables, (
        f"New tables since the snapshot: {added_tables}. These are safe for "
        "deployed databases, but refresh the snapshot so it keeps guarding the "
        f"rest.{REGENERATE_HINT}"
    )


@pytest.mark.parametrize(
    "table",
    ["cases", "evidences", "findings", "users"],
    ids=lambda name: f"core_table_{name}",
)
def test_core_tables_are_covered_by_the_snapshot(table):
    """If the snapshot ever stops covering these, it has silently stopped working."""
    assert table in stored_schema(), f"{table} is missing from the snapshot"
