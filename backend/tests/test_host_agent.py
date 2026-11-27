"""The host agent: the backend only writes requests it accepts, and the agent on the host carries out
only the two fixed actions, never while jobs run. The agent script runs here against fake docker
and git commands."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_system
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.models.activity import AppActivityEvent
from app.services import host_agent

REPO = Path(__file__).resolve().parents[2]
AGENT_SCRIPT = REPO / "scripts" / "kairon-agent.sh"
settings = get_settings()


@pytest.fixture()
def agent_dir(tmp_path, monkeypatch):
    directory = tmp_path / "agent"
    (directory / "requests").mkdir(parents=True)
    monkeypatch.setattr(host_agent, "AGENT_DIR", directory)
    monkeypatch.setattr(host_agent, "active_jobs", lambda: {"total": 0, "queues": {}})
    return directory


def _beat(directory: Path, age: float = 1) -> None:
    (directory / "heartbeat.json").write_text(json.dumps({"seen_at": time.time() - age, "busy": ""}))


@pytest.fixture()
def client(agent_dir, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    monkeypatch.setattr(settings, "auth_enabled", False)
    app = FastAPI()
    app.include_router(routes_system.router)
    app.dependency_overrides[get_db] = lambda: db
    return db, TestClient(app)


def test_actions_are_offered_only_while_the_agent_is_alive(agent_dir) -> None:
    assert host_agent.agent_alive()["available"] is False
    _beat(agent_dir, age=5)
    assert host_agent.agent_alive()["available"] is True
    _beat(agent_dir, age=120)
    assert host_agent.agent_alive()["available"] is False


def test_an_accepted_request_is_written_and_logged(client, agent_dir) -> None:
    db, http = client
    _beat(agent_dir)
    response = http.post("/api/admin/host-agent/requests", json={"action": "restart", "services": ["worker", "backend"]})
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "queued" and body["services"] == ["backend", "worker"]
    text = (agent_dir / "requests" / f"{body['id']}.req").read_text()
    assert "action=restart" in text and "services=backend worker" in text
    assert db.query(AppActivityEvent).one().activity_type == "host_agent_restart_requested"
    # One at a time.
    assert http.post("/api/admin/host-agent/requests", json={"action": "upgrade"}).status_code == 409


@pytest.mark.parametrize(
    "payload, setup, reason",
    [
        ({"action": "upgrade"}, "no_agent", "not running"),
        ({"action": "upgrade"}, "jobs", "queued or running"),
        ({"action": "upgrade"}, "redis_down", "Could not check"),
        ({"action": "shell", "services": []}, None, "Unknown action"),
        ({"action": "restart", "services": ["postgres"]}, None, "must be among"),
        ({"action": "restart", "services": []}, None, "must be among"),
    ],
)
def test_refused_requests_write_nothing(client, agent_dir, monkeypatch, payload, setup, reason) -> None:
    _db, http = client
    if setup != "no_agent":
        _beat(agent_dir)
    if setup == "jobs":
        monkeypatch.setattr(host_agent, "active_jobs", lambda: {"total": 2, "queues": {"dfir-ingest": 2}})
    if setup == "redis_down":
        def boom():
            raise ConnectionError("redis down")
        monkeypatch.setattr(host_agent, "active_jobs", boom)
    response = http.post("/api/admin/host-agent/requests", json=payload)
    assert response.status_code == 409 and reason in response.json()["detail"]
    assert list((agent_dir / "requests").glob("*.req")) == []


@pytest.mark.parametrize("is_admin, expected", [(False, 403), (True, 200)])
def test_only_administrators(client, monkeypatch, is_admin, expected) -> None:
    _db, http = client
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr("app.services.auth_dependencies.get_current_user", lambda request, db: SimpleNamespace(is_admin=is_admin, username="u"))
    assert http.get("/api/admin/host-agent").status_code == expected


def test_jobs_count_running_ones_and_queued_ones_a_worker_will_run(monkeypatch) -> None:
    import rq
    import rq.registry

    queued = {"dfir-ingest": 2, "memory-native-probe": 278}
    running = {"dfir-ingest": ["job-1"], "memory": ["job-2"]}
    monkeypatch.setattr(host_agent, "_queue_names", lambda: ["dfir-ingest", "memory", "memory-native-probe"])
    monkeypatch.setattr(rq, "Worker", SimpleNamespace(all=lambda connection: [SimpleNamespace(queues=[SimpleNamespace(name="dfir-ingest"), SimpleNamespace(name="memory")])]))
    monkeypatch.setattr(rq, "Queue", lambda name, connection: SimpleNamespace(count=queued.get(name, 0)))
    monkeypatch.setattr(rq.registry, "StartedJobRegistry", lambda name, connection: SimpleNamespace(get_job_ids=lambda: running.get(name, [])))
    # No worker listens to memory-native-probe: its 278 queued jobs never run.
    assert host_agent.active_jobs() == {"total": 4, "queues": {"dfir-ingest": 3, "memory": 1}}


# ---- The agent script itself -------------------------------------------------------------------

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_CALLS"
if [[ "$*" == *"active-jobs"* ]]; then cat "$FAKE_JOBS"; exit 0; fi
exit 0
"""
FAKE_GIT = """#!/usr/bin/env bash
if [[ "$*" == *"status --porcelain"* ]]; then cat "$FAKE_GIT_STATUS"; exit 0; fi
if [[ "$*" == *"rev-parse"* ]]; then echo abcdef123456; exit 0; fi
exit 0
"""


@pytest.fixture()
def fake_host(tmp_path):
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    root = tmp_path / "kairon"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(AGENT_SCRIPT, root / "scripts" / "kairon-agent.sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.txt"
    calls.touch()
    for name, body in (("docker", FAKE_DOCKER), ("git", FAKE_GIT)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    for name in ("dfir-backup.sh", "upgrade.sh"):
        script = root / "scripts" / name
        script.write_text(f'#!/usr/bin/env bash\necho "{name} $*" >> "$FAKE_CALLS"\n')
        script.chmod(0o755)
    (tmp_path / "jobs").write_text("0\n")
    (tmp_path / "git_status").write_text("")
    agent = root / "agent"
    (agent / "requests").mkdir(parents=True)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_CALLS": str(calls),
        "FAKE_JOBS": str(tmp_path / "jobs"),
        "FAKE_GIT_STATUS": str(tmp_path / "git_status"),
        "KAIRON_AGENT_POLL_SECONDS": "0.1",
    }

    def run(request_lines: list[str], request_id: str = "20261127T120000Z-abcdef12") -> dict:
        (agent / "requests" / f"{request_id}.req").write_text("\n".join(request_lines) + "\n")
        subprocess.run(["bash", str(root / "scripts" / "kairon-agent.sh"), "--once"], env=env, check=True, timeout=60, capture_output=True)
        return json.loads((agent / "status" / f"{request_id}.json").read_text())

    return SimpleNamespace(run=run, calls=calls, jobs=tmp_path / "jobs", git_status=tmp_path / "git_status", agent=agent)


def test_agent_restarts_only_the_listed_services(fake_host) -> None:
    status = fake_host.run(["action=restart", "services=backend worker"])
    assert status["state"] == "done" and status["exit_code"] == 0
    assert "docker compose restart backend worker" in fake_host.calls.read_text()
    assert json.loads((fake_host.agent / "heartbeat.json").read_text())["seen_at"] > 0


def test_agent_upgrades_with_a_backup_first(fake_host) -> None:
    status = fake_host.run(["action=upgrade"])
    calls = fake_host.calls.read_text().splitlines()
    assert status["state"] == "done" and "abcdef123456" in status["message"]
    backup = next(index for index, line in enumerate(calls) if line.startswith("dfir-backup.sh --db-only"))
    upgrade = next(index for index, line in enumerate(calls) if line.startswith("upgrade.sh"))
    assert backup < upgrade


def test_agent_refuses_while_jobs_run_or_with_local_changes(fake_host) -> None:
    fake_host.jobs.write_text("3\n")
    status = fake_host.run(["action=upgrade"], "20261127T120000Z-00000001")
    assert status["state"] == "refused" and "3 job(s)" in status["message"]
    fake_host.jobs.write_text("0\n")
    fake_host.git_status.write_text(" M backend/app/main.py\n")
    status = fake_host.run(["action=upgrade"], "20261127T120000Z-00000002")
    assert status["state"] == "refused" and "local changes" in status["message"]
    assert "upgrade.sh" not in fake_host.calls.read_text()


@pytest.mark.parametrize(
    "lines",
    [
        ["action=restart", "services=backend; rm -rf /"],
        ["action=restart", "services=postgres"],
        ["action=sh"],
        ["action=upgrade", "command=curl evil"],
    ],
)
def test_agent_rejects_anything_else(fake_host, lines) -> None:
    status = fake_host.run(lines)
    assert status["state"] == "refused"
    assert "restart" not in fake_host.calls.read_text() and "upgrade.sh" not in fake_host.calls.read_text()
