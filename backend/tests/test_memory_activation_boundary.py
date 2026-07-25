"""Tests for the Memory activation boundary (architecture backlog P0).

Proves, at the application level, that ``settings.memory_enabled`` is the
sole authority for:

* whether Memory's routers are mounted at all;
* whether Memory's startup reconciliation hooks run;
* whether Memory-specific behavior in the shared evidence API executes;
* what the capability-state endpoint reports;

and that the Core Platform (a dependency-free endpoint, plus the shared
evidence API's non-Memory behavior) is unaffected either way.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence
from app.core.config import Settings
from app.core.database import Base, get_db
from app.models.case import Case


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Configuration default
# ---------------------------------------------------------------------------


def test_memory_enabled_defaults_true_for_backward_compatibility(monkeypatch):
    """Existing deployments never set MEMORY_ENABLED; the default must
    preserve today's behavior (Memory has always been mounted)."""
    monkeypatch.delenv("MEMORY_ENABLED", raising=False)
    assert Settings().memory_enabled is True


# ---------------------------------------------------------------------------
# Application composition: router mounting
#
# Router mounting happens at module-import time in app.main, so proving it
# genuinely responds to MEMORY_ENABLED requires building the app fresh with
# a given environment. A separate subprocess (rather than importlib.reload
# in-process) is used deliberately: reloading app.main/routes_evidence in
# the same process mutates shared module objects that other test files
# also import, which is a real cross-test pollution risk in a full-suite
# run. A subprocess gives each variant a clean interpreter instead.
# ---------------------------------------------------------------------------


_PROBE_SCRIPT = """
import json

from fastapi.testclient import TestClient

from app.main import app
from app.api import routes_memory, routes_memory_experimental, routes_memory_recovery

memory_paths = set()
for module in (routes_memory, routes_memory_experimental, routes_memory_recovery):
    memory_paths.update(route.path for route in module.router.routes)
app_paths = {route.path for route in app.routes}

client = TestClient(app)
health = client.get("/health")
capabilities = client.get("/api/system/capabilities")

print(json.dumps({
    "memory_paths_declared": bool(memory_paths),
    "memory_paths_mounted": memory_paths <= app_paths,
    "memory_paths_absent": app_paths.isdisjoint(memory_paths),
    "health_status": health.status_code,
    "health_body": health.json(),
    "capabilities_status": capabilities.status_code,
    "capabilities_body": capabilities.json(),
}))
"""


def _probe_fresh_app(tmp_path: Path, *, memory_enabled: bool | None) -> dict:
    env = os.environ.copy()
    env["KAIRON_AUTH_ENABLED"] = "false"
    env["BACKEND_DATA_DIR"] = str(tmp_path / "data")
    env["BACKEND_TEMP_DIR"] = str(tmp_path / "data" / "tmp")
    if memory_enabled is None:
        env.pop("MEMORY_ENABLED", None)
    else:
        env["MEMORY_ENABLED"] = "true" if memory_enabled else "false"

    result = subprocess.run(
        [sys.executable, "-c", _PROBE_SCRIPT],
        cwd=str(BACKEND_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"probe subprocess failed:\\n{result.stdout}\\n{result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_memory_routers_not_mounted_when_disabled(tmp_path):
    probe = _probe_fresh_app(tmp_path, memory_enabled=False)
    assert probe["memory_paths_declared"], "expected the Memory routers to declare at least one route"
    assert probe["memory_paths_absent"]


def test_memory_routers_mounted_when_enabled(tmp_path):
    probe = _probe_fresh_app(tmp_path, memory_enabled=True)
    assert probe["memory_paths_mounted"]


def test_core_endpoint_available_when_memory_disabled(tmp_path):
    probe = _probe_fresh_app(tmp_path, memory_enabled=False)
    assert probe["health_status"] == 200
    assert probe["health_body"] == {"status": "ok"}


def test_capability_state_reports_disabled(tmp_path):
    probe = _probe_fresh_app(tmp_path, memory_enabled=False)
    assert probe["capabilities_status"] == 200
    assert probe["capabilities_body"] == {"memory": {"enabled": False}}


def test_capability_state_reports_enabled(tmp_path):
    probe = _probe_fresh_app(tmp_path, memory_enabled=True)
    assert probe["capabilities_status"] == 200
    assert probe["capabilities_body"] == {"memory": {"enabled": True}}


def test_memory_enabled_unset_defaults_to_current_behavior(tmp_path):
    """MEMORY_ENABLED left unset (every existing deployment) must match
    today's behavior: Memory mounted, capability reported enabled."""
    probe = _probe_fresh_app(tmp_path, memory_enabled=None)
    assert probe["memory_paths_mounted"]
    assert probe["capabilities_body"] == {"memory": {"enabled": True}}


# ---------------------------------------------------------------------------
# Startup composition: reconciliation hooks
# ---------------------------------------------------------------------------


def _patch_non_memory_startup_side_effects(monkeypatch, main):
    """Neutralize every non-Memory startup side effect so on_startup()
    can run without a live DB/OpenSearch/Redis, while leaving the
    Memory-gating logic itself untouched."""
    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "ensure_events_indices_safe_settings", lambda: None)
    monkeypatch.setattr(main, "auto_bootstrap_dashboards", lambda: None)

    from app.services import bootstrap as bootstrap_module
    monkeypatch.setattr(bootstrap_module, "bootstrap_admin", lambda: False)

    from app.services import evidence_operations
    monkeypatch.setattr(evidence_operations, "reconcile_evidence_operations", lambda db: {})

    from app.services import job_watchdog
    monkeypatch.setattr(job_watchdog, "reconcile_stale_ingests", lambda db: {})

    from app.core import database as database_module
    monkeypatch.setattr(database_module, "SessionLocal", lambda: MagicMock())


def test_memory_startup_hooks_not_called_when_disabled(monkeypatch):
    import app.main as main

    monkeypatch.setattr(main.settings, "memory_enabled", False)
    _patch_non_memory_startup_side_effects(monkeypatch, main)

    reconcile_called = MagicMock()
    cleanup_called = MagicMock()
    monkeypatch.setattr(main, "_reconcile_memory_startup_state", reconcile_called)
    monkeypatch.setattr(main, "_cleanup_memory_upload_sessions_startup", cleanup_called)

    main.on_startup()

    reconcile_called.assert_not_called()
    cleanup_called.assert_not_called()


def test_memory_startup_hooks_called_when_enabled(monkeypatch):
    import app.main as main

    monkeypatch.setattr(main.settings, "memory_enabled", True)
    _patch_non_memory_startup_side_effects(monkeypatch, main)

    reconcile_called = MagicMock()
    cleanup_called = MagicMock()
    monkeypatch.setattr(main, "_reconcile_memory_startup_state", reconcile_called)
    monkeypatch.setattr(main, "_cleanup_memory_upload_sessions_startup", cleanup_called)

    main.on_startup()

    reconcile_called.assert_called_once()
    cleanup_called.assert_called_once()


# ---------------------------------------------------------------------------
# Shared evidence API integration paths
# ---------------------------------------------------------------------------


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id=CASE_ID):
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _evidence_client(db, monkeypatch, *, memory_enabled: bool) -> TestClient:
    monkeypatch.setattr(routes_evidence.settings, "memory_enabled", memory_enabled)
    test_app = FastAPI()
    test_app.include_router(routes_evidence.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def test_probe_memory_image_returns_404_when_disabled(monkeypatch):
    db = _db()
    _case(db)
    client = _evidence_client(db, monkeypatch, memory_enabled=False)

    resp = client.post(
        f"/api/cases/{CASE_ID}/evidences/probe-memory-image",
        params={"evidence_id": "whatever"},
    )

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Memory Analysis capability is not available on this server."


def test_confirm_memory_type_returns_404_when_disabled(monkeypatch):
    db = _db()
    _case(db)
    client = _evidence_client(db, monkeypatch, memory_enabled=False)

    resp = client.post(
        f"/api/cases/{CASE_ID}/evidences/some-evidence-id/confirm-memory-type",
        json={},
    )

    assert resp.status_code == 404
    assert resp.json()["detail"]["error_code"] == "MEMORY_CAPABILITY_DISABLED"


def test_probe_memory_image_falls_through_to_existing_behavior_when_enabled(monkeypatch):
    db = _db()
    client = _evidence_client(db, monkeypatch, memory_enabled=True)

    resp = client.post(
        "/api/cases/does-not-exist/evidences/probe-memory-image",
        params={"evidence_id": "x"},
    )

    # The capability gate does not fire; behavior is unchanged from
    # before this PR (falls through to the existing "Case not found").
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Case not found."


def test_confirm_memory_type_falls_through_to_existing_behavior_when_enabled(monkeypatch):
    db = _db()
    client = _evidence_client(db, monkeypatch, memory_enabled=True)

    resp = client.post(
        "/api/cases/does-not-exist/evidences/some-evidence-id/confirm-memory-type",
        json={},
    )

    assert resp.status_code == 404
    assert resp.json()["detail"]["error_code"] == "EVIDENCE_NOT_FOUND"
