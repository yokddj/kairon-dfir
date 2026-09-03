"""Reporting a database that no longer matches the models."""

from __future__ import annotations

from sqlalchemy import Column, MetaData, String, Table

from app.services.schema_health import check_schema_drift, log_schema_drift


class FakeInspector:
    def __init__(self, tables: dict[str, list[str]], explode: bool = False):
        self._tables = tables
        self._explode = explode

    def get_table_names(self):
        if self._explode:
            raise RuntimeError("connection refused")
        return list(self._tables)

    def get_columns(self, name):
        return [{"name": column} for column in self._tables.get(name, [])]


def _patch(monkeypatch, inspector, model_tables):
    """Describe the models the check should expect, and what the database has."""
    import app.services.schema_health as module

    monkeypatch.setattr(module, "inspect", lambda engine: inspector)
    metadata = MetaData()
    for name, columns in model_tables.items():
        Table(name, metadata, *[Column(column, String) for column in columns])
    return metadata


def test_a_matching_database_is_reported_healthy(monkeypatch):
    live = {"cases": ["id", "name"], "evidences": ["id", "sha256"]}
    metadata = _patch(monkeypatch, FakeInspector(live), live)

    result = check_schema_drift(object(), metadata)

    assert result["status"] == "ok"
    assert result["missing_columns"] == []
    assert result["missing_tables"] == []


def test_a_column_the_models_expect_but_the_database_lacks_is_reported(monkeypatch):
    """The exact failure a skipped migration produces."""
    live = {"cases": ["id", "name"], "evidences": ["id"]}
    models = {"cases": ["id", "name"], "evidences": ["id", "sha256"]}
    metadata = _patch(monkeypatch, FakeInspector(live), models)

    result = check_schema_drift(object(), metadata)

    assert result["status"] == "drifted"
    assert result["missing_columns"] == ["evidences.sha256"]
    assert "will fail" in result["detail"]


def test_a_missing_table_is_reported(monkeypatch):
    live = {"cases": ["id"]}
    models = {"cases": ["id"], "findings": ["id", "title"]}
    metadata = _patch(monkeypatch, FakeInspector(live), models)

    result = check_schema_drift(object(), metadata)

    assert result["missing_tables"] == ["findings"]
    assert result["status"] == "drifted"


def test_an_extra_column_left_by_an_old_release_is_not_an_alarm(monkeypatch):
    """Reporting harmless leftovers would train operators to ignore this."""
    live = {"cases": ["id", "name", "legacy_column"]}
    models = {"cases": ["id", "name"]}
    metadata = _patch(monkeypatch, FakeInspector(live), models)

    result = check_schema_drift(object(), metadata)

    assert result["status"] == "ok"


def test_an_unreachable_database_reports_unknown_rather_than_healthy(monkeypatch):
    """Never claim the schema is fine when it could not be read."""
    metadata = _patch(monkeypatch, FakeInspector({}, explode=True), {"cases": ["id"]})

    result = check_schema_drift(object(), metadata)

    assert result["status"] == "unknown"
    assert result["checked"] is False
    assert "connection refused" in result["reason"]


def test_the_check_never_raises(monkeypatch):
    """A diagnostic that crashes the app would be worse than the problem."""
    import app.services.schema_health as module

    monkeypatch.setattr(module, "inspect", lambda engine: (_ for _ in ()).throw(RuntimeError("boom")))
    metadata = MetaData()
    Table("cases", metadata, Column("id", String))

    assert check_schema_drift(object(), metadata)["status"] == "unknown"


def test_startup_logging_surfaces_drift(monkeypatch, caplog):
    live = {"cases": ["id"]}
    models = {"cases": ["id", "added_later"]}
    metadata = _patch(monkeypatch, FakeInspector(live), models)

    with caplog.at_level("ERROR"):
        result = log_schema_drift(object(), metadata)

    assert result["status"] == "drifted"
    assert any("schema drift" in record.message.lower() for record in caplog.records)


def test_startup_logging_is_quiet_when_healthy(monkeypatch, caplog):
    live = {"cases": ["id"]}
    metadata = _patch(monkeypatch, FakeInspector(live), live)

    with caplog.at_level("ERROR"):
        log_schema_drift(object(), metadata)

    assert not [r for r in caplog.records if "drift" in r.message.lower()]
