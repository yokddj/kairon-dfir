"""The crash-dump copy for Volatility is made, and removed, only on the analyst's request."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.services.memory import volatility_view
from app.services.memory.volatility_runner import VolatilityRunnerError


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    case_id, evidence_id = str(uuid.uuid4()), str(uuid.uuid4())
    image = tmp_path / "PhysicalMemory.dd"
    image.write_bytes(b"raw")
    with Session() as db:
        db.add(Case(id=case_id, name="Case"))
        db.add(Evidence(id=evidence_id, case_id=case_id, original_filename=image.name, stored_path=str(image), evidence_type=EvidenceType.memory_dump, size_bytes=10 * 2**30, metadata_json={"volatility_layer_missing": {"plugin": "windows.info"}}))
        db.commit()
    monkeypatch.setattr(get_settings(), "memory_output_dir", str(tmp_path / "out"))
    monkeypatch.setattr(get_settings(), "memory_upload_min_free_space_bytes", 0)
    monkeypatch.setattr("app.core.database.SessionLocal", Session)
    monkeypatch.setattr("app.services.memory.evidence_access.validate_current_process_evidence_access", lambda evidence, settings: SimpleNamespace(path=image))
    queued: list[tuple[str, str]] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_volatility_view", lambda evidence_id, action: queued.append((evidence_id, action)) or "job")
    return SimpleNamespace(Session=Session, evidence_id=evidence_id, case_id=case_id, queued=queued, tmp_path=tmp_path)


def _evidence(env, db):
    return db.get(Evidence, env.evidence_id)


def test_status_offers_the_copy_with_its_size_only_when_needed(env):
    with env.Session() as db:
        state = volatility_view.status(_evidence(env, db))
    assert state["needed"] is True and state["status"] == "none"
    assert state["estimated_bytes"] == int(10 * 2**30 * 1.2)


def test_request_queues_it_and_refuses_a_second_one(env):
    with env.Session() as db:
        assert volatility_view.request_copy(db, _evidence(env, db), user="analyst")["status"] == "queued"
        with pytest.raises(volatility_view.VolatilityViewError):
            volatility_view.request_copy(db, _evidence(env, db), user="analyst")
    assert env.queued == [(env.evidence_id, "create")]


def test_the_worker_writes_it_when_the_disk_has_room_and_removes_it_on_request(env, monkeypatch):
    def crashdump(source, target, work_dir, **_kwargs):
        target.write_bytes(b"PAGEDU64")
        return 8

    monkeypatch.setattr("app.services.memory.memprocfs_runner.run_crashdump", crashdump)
    monkeypatch.setattr(volatility_view.shutil, "disk_usage", lambda _p: SimpleNamespace(free=10**15))
    assert volatility_view.run_volatility_view(env.evidence_id, "create")["status"] == "created"
    dump = env.tmp_path / "out" / "evidence" / env.case_id / env.evidence_id / "memory" / "volatility-view" / "memory.dmp"
    assert dump.is_file()
    with env.Session() as db:
        assert _evidence(env, db).metadata_json["volatility_view"]["status"] == "created"
    volatility_view.run_volatility_view(env.evidence_id, "remove")
    assert not dump.exists()
    with env.Session() as db:
        assert "volatility_view" not in _evidence(env, db).metadata_json


def test_no_copy_without_room_and_failures_are_reported(env, monkeypatch):
    monkeypatch.setattr(volatility_view.shutil, "disk_usage", lambda _p: SimpleNamespace(free=2**30))
    monkeypatch.setattr("app.services.memory.memprocfs_runner.run_crashdump", lambda *_a, **_k: pytest.fail("no room"))
    result = volatility_view.run_volatility_view(env.evidence_id, "create")
    assert result["status"] == "skipped_disk_space" and "GiB" in result["message"]

    def broken(*_a, **_k):
        raise VolatilityRunnerError("MEMORY_OUTPUT_WRITE_FAILED", "The crash-dump copy could not be written (disk full or not writable).")

    monkeypatch.setattr(volatility_view.shutil, "disk_usage", lambda _p: SimpleNamespace(free=10**15))
    monkeypatch.setattr("app.services.memory.memprocfs_runner.run_crashdump", broken)
    result = volatility_view.run_volatility_view(env.evidence_id, "create")
    assert result["status"] == "failed" and "could not be written" in result["message"]
