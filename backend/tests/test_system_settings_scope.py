"""The generic settings API only changes tuning/deployment values, and only for administrators."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_system
from app.core.app_settings import get_setting, set_setting
from app.core.config import get_settings
from app.core.database import Base, get_db

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


def test_tunable_settings_can_be_changed(env) -> None:
    db, client = env
    response = client.patch("/api/system/settings", json={"settings": {"INGEST_BATCH_SIZE": 500}})
    assert response.status_code == 200 and response.json()["updated"] == ["INGEST_BATCH_SIZE"]
    assert get_setting(db, "INGEST_BATCH_SIZE") == 500


@pytest.mark.parametrize("key", ["AI_ASSISTANT", "S3_SOURCE", "SOMETHING_ELSE"])
def test_feature_configuration_cannot_be_written_through_it(env, key) -> None:
    db, client = env
    set_setting(db, "S3_SOURCE", {"endpoint_url": "https://s3.example", "access_key_id": "AKIA"})
    response = client.patch("/api/system/settings", json={"settings": {"INGEST_BATCH_SIZE": 500, key: {"endpoint_url": "https://attacker.example"}}})
    assert response.status_code == 400 and key in response.json()["detail"]
    # Nothing of the request is applied.
    assert get_setting(db, "S3_SOURCE")["endpoint_url"] == "https://s3.example"
    assert get_setting(db, "INGEST_BATCH_SIZE") != 500


def test_reset_keeps_feature_configuration(env) -> None:
    db, client = env
    set_setting(db, "AI_ASSISTANT", {"enabled": True})
    set_setting(db, "S3_SOURCE", {"access_key_id": "AKIA"})
    set_setting(db, "INGEST_BATCH_SIZE", 500)
    response = client.post("/api/system/settings/reset")
    assert response.status_code == 200 and response.json()["updated"] == ["INGEST_BATCH_SIZE"]
    assert get_setting(db, "AI_ASSISTANT") == {"enabled": True} and get_setting(db, "S3_SOURCE") == {"access_key_id": "AKIA"}


@pytest.mark.parametrize("is_admin, expected", [(False, 403), (True, 200)])
def test_only_administrators_change_or_reset_settings(env, monkeypatch, is_admin, expected) -> None:
    _db, client = env
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr("app.services.auth_dependencies.get_current_user", lambda request, db: SimpleNamespace(is_admin=is_admin))
    assert client.patch("/api/system/settings", json={"settings": {"INGEST_BATCH_SIZE": 500}}).status_code == expected
    assert client.post("/api/system/settings/reset").status_code == expected



@pytest.mark.parametrize(
    "method, path, body",
    [
        ("patch", "/api/admin/performance", {"profile": "balanced"}),
        ("post", "/api/admin/performance/apply", {"profile": "balanced"}),
        ("post", "/api/admin/performance/apply-profile", {"profile": "balanced"}),
        ("post", "/api/admin/performance/apply-recommended", {}),
        ("post", "/api/admin/performance/restart", {"services": []}),
    ],
)
def test_only_administrators_change_performance(env, monkeypatch, method, path, body) -> None:
    _db, client = env
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr("app.services.auth_dependencies.get_current_user", lambda request, db: SimpleNamespace(is_admin=False))
    assert getattr(client, method)(path, json=body).status_code == 403
