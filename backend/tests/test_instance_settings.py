"""Instance settings saved from the UI: a closed list, validated, logged, and laid over the
environment when a service starts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_system
from app.core import instance_settings
from app.core.app_settings import TUNABLE_SETTING_KEYS, SETTING_META
from app.core.config import Settings, get_settings
from app.core.database import Base, get_db
from app.models.activity import AppActivityEvent
from app.models.app_setting import AppSetting

settings = get_settings()


@pytest.fixture()
def env(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    monkeypatch.setattr(settings, "auth_enabled", False)
    app = FastAPI()
    app.include_router(routes_system.router)
    app.dependency_overrides[get_db] = lambda: db
    return db, TestClient(app)


def _entry(body: dict, key: str) -> dict:
    return next(item for item in body["settings"] if item["key"] == key)


def test_every_setting_is_a_settings_field_outside_the_other_lists() -> None:
    fields = Settings.model_fields
    for item in instance_settings.INSTANCE_SETTINGS:
        assert item.field in fields, item.key
        assert item.key not in TUNABLE_SETTING_KEYS and item.key not in SETTING_META, item.key
    for key, _reason in instance_settings.READ_ONLY_SETTINGS:
        assert key.lower() in fields and key not in instance_settings.BY_KEY, key


def test_saving_a_value_needs_a_restart_and_is_logged(env) -> None:
    db, client = env
    response = client.patch("/api/admin/instance-settings", json={"settings": {"BACKEND_LOG_LEVEL": "DEBUG"}})
    assert response.status_code == 200
    entry = _entry(response.json(), "BACKEND_LOG_LEVEL")
    assert entry["override"] == "DEBUG" and entry["running_value"] == settings.backend_log_level
    assert entry["pending_restart"] is (settings.backend_log_level != "DEBUG")
    assert "docker compose restart backend worker" in response.json()["restart_command"]
    row = db.get(AppSetting, "BACKEND_LOG_LEVEL")
    assert row.category == "instance" and row.value == "DEBUG"
    event = db.query(AppActivityEvent).one()
    assert event.activity_type == "instance_settings_changed" and "BACKEND_LOG_LEVEL" in event.message

    # null goes back to .env.
    response = client.patch("/api/admin/instance-settings", json={"settings": {"BACKEND_LOG_LEVEL": None}})
    assert _entry(response.json(), "BACKEND_LOG_LEVEL")["override"] is None
    assert db.get(AppSetting, "BACKEND_LOG_LEVEL") is None


def test_a_live_setting_applies_without_restart(env) -> None:
    db, client = env
    response = client.patch("/api/admin/instance-settings", json={"settings": {"UPDATE_CHECK_ENABLED": False}})
    entry = _entry(response.json(), "UPDATE_CHECK_ENABLED")
    assert entry["running_value"] is False and entry["pending_restart"] is False
    assert instance_settings.effective_value(db, "UPDATE_CHECK_ENABLED") is False


@pytest.mark.parametrize(
    "payload",
    [
        {"S3_SOURCE_ENABLED": True},  # kept in .env on purpose
        {"POSTGRES_PASSWORD": "x"},
        {"INGEST_BATCH_SIZE": 500},  # belongs to the performance settings
        {"BACKEND_LOG_LEVEL": "LOUD"},
        {"MAX_ARCHIVE_DEPTH": 0},
        {"MAX_ARCHIVE_DEPTH": "5"},
        {"DISK_IMAGE_INGEST_ENABLED": "yes"},
    ],
)
def test_invalid_or_unlisted_values_change_nothing(env, payload) -> None:
    db, client = env
    request = {"BACKEND_LOG_LEVEL": "DEBUG", **payload}
    response = client.patch("/api/admin/instance-settings", json={"settings": request})
    assert response.status_code == 400
    assert db.query(AppSetting).count() == 0 and db.query(AppActivityEvent).count() == 0


def test_read_only_gates_are_shown_not_editable(env) -> None:
    _db, client = env
    body = client.get("/api/admin/instance-settings").json()
    keys = {item["key"] for item in body["read_only"]}
    assert {"S3_SOURCE_ENABLED", "AZURE_BLOB_SOURCE_ENABLED", "DFIR_ALLOW_HOST_PATH_IMPORT"} <= keys
    assert not keys & {item["key"] for item in body["settings"]}


@pytest.mark.parametrize("is_admin, expected", [(False, 403), (True, 200)])
def test_only_administrators(env, monkeypatch, is_admin, expected) -> None:
    _db, client = env
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr("app.services.auth_dependencies.get_current_user", lambda request, db: SimpleNamespace(is_admin=is_admin, username="analyst"))
    assert client.get("/api/admin/instance-settings").status_code == expected
    assert client.patch("/api/admin/instance-settings", json={"settings": {"BACKEND_LOG_LEVEL": "INFO"}}).status_code == expected
    assert client.get("/api/system/update-status").status_code in ({403} if expected == 403 else {200})


def test_saved_values_are_laid_over_the_environment_at_start(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'settings.db'}"
    engine = create_engine(url, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    instance_settings.store_override(db, "MAX_ARCHIVE_DEPTH", 9)
    instance_settings.store_override(db, "MEMORY_WINDOWS_DEFAULT_ENGINE", "volatility")
    # A row of another category with a listed name is not an instance setting.
    db.add(AppSetting(key="BACKEND_LOG_LEVEL", value="DEBUG", category="runtime"))
    db.commit()
    db.close()

    class _Settings(Settings):
        @property
        def database_url(self) -> str:  # type: ignore[override]
            return url

    applied = instance_settings.apply_overrides(_Settings(), _Settings)
    assert applied.max_archive_depth == 9 and applied.memory_windows_default_engine == "volatility"
    assert applied.backend_log_level == Settings().backend_log_level


def test_an_unreachable_database_keeps_the_environment() -> None:
    class _Settings(Settings):
        @property
        def database_url(self) -> str:  # type: ignore[override]
            return "postgresql+psycopg://user:pass@127.0.0.1:1/none"

    base = _Settings()
    assert instance_settings.apply_overrides(base, _Settings) is base
