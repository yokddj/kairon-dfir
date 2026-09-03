"""Whether the live database still matches the models the code expects.

The schema is created by `Base.metadata.create_all()` and evolved by the
versioned migrations in `app.core.migrations`. create_all() only creates
*missing tables*; it never adds a column to an existing one. So a deployment
that skipped a migration -- or ran a build whose migration failed -- keeps
serving until some request touches the missing column and fails with an opaque
database error, usually in the middle of an investigation.

Reporting the mismatch directly turns that into something an operator can see
and fix before it bites.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def check_schema_drift(engine: Engine, metadata: Any | None = None) -> dict[str, Any]:
    """Compare the live schema against the models.

    Only columns the models expect and the database lacks are treated as a
    problem: an extra column left behind by an old release is harmless, and
    reporting it would train operators to ignore this check.

    ``metadata`` defaults to the application's own; it is a parameter so the
    check can be exercised against a described schema without patching imports.
    """
    if metadata is None:
        from app.core.database import Base
        import app.models  # noqa: F401 - importing registers every model

        metadata = Base.metadata

    try:
        inspector = inspect(engine)
        live_tables = set(inspector.get_table_names())
    except Exception as exc:  # noqa: BLE001 - a diagnostic must not raise
        logger.warning("Could not inspect the database schema: %s", exc)
        return {
            "status": "unknown",
            "checked": False,
            "reason": f"Could not inspect the database: {exc}",
            "missing_tables": [],
            "missing_columns": [],
        }

    model_tables = dict(metadata.tables)
    missing_tables = sorted(set(model_tables) - live_tables)

    missing_columns: list[str] = []
    for name in sorted(set(model_tables) & live_tables):
        try:
            live_columns = {column["name"] for column in inspector.get_columns(name)}
        except Exception:  # noqa: BLE001 - skip a table we cannot read
            continue
        for column in sorted(set(model_tables[name].columns.keys()) - live_columns):
            missing_columns.append(f"{name}.{column}")

    healthy = not missing_tables and not missing_columns
    return {
        "status": "ok" if healthy else "drifted",
        "checked": True,
        "missing_tables": missing_tables,
        "missing_columns": missing_columns,
        "detail": (
            "The database matches the models."
            if healthy
            else (
                "The database is missing schema the code expects. Requests that touch "
                "it will fail. Restart the backend to apply pending migrations; if that "
                "does not clear it, a migration is missing for this change."
            )
        ),
    }


def log_schema_drift(engine: Engine, metadata: Any | None = None) -> dict[str, Any]:
    """Run the check at startup so a drifted deployment says so in its logs."""
    result = check_schema_drift(engine, metadata)
    if result["status"] == "drifted":
        logger.error(
            "Database schema drift: missing tables=%s missing columns=%s",
            result["missing_tables"],
            result["missing_columns"],
        )
    return result
