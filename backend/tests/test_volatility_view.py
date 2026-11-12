"""What the evidence page says about Volatility reading the image; old crash-dump copies are removed on request."""

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
    monkeypatch.setattr("app.core.database.SessionLocal", Session)
    queued: list[tuple[str, str]] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_volatility_view", lambda evidence_id, action: queued.append((evidence_id, action)) or "job")
    return SimpleNamespace(Session=Session, evidence_id=evidence_id, case_id=case_id, queued=queued, tmp_path=tmp_path)


def _evidence(env, db):
    return db.get(Evidence, env.evidence_id)


def _update(env, **metadata):
    with env.Session() as db:
        evidence = _evidence(env, db)
        evidence.metadata_json = {**(evidence.metadata_json or {}), **metadata}
        db.commit()


def test_the_page_speaks_only_when_volatility_cannot_read_the_image(env):
    with env.Session() as db:
        state = volatility_view.status(_evidence(env, db))
    assert state["needed"] is True and state["status"] == "none" and state["layer"] is None
    _update(env, volatility_layer={"page_map_offset": 0x1AE000, "source": "MemProcFS"})
    with env.Session() as db:
        state = volatility_view.status(_evidence(env, db))
    assert state["needed"] is False and state["layer"] == {"page_map_offset": "0x1ae000", "source": "MemProcFS"}


def test_an_old_copy_is_removed_on_request(env):
    dump = env.tmp_path / "out" / "evidence" / env.case_id / env.evidence_id / "memory" / "volatility-view" / "memory.dmp"
    dump.parent.mkdir(parents=True)
    dump.write_bytes(b"PAGEDU64")
    _update(env, volatility_view={"status": "created", "bytes": 8})
    with env.Session() as db:
        assert volatility_view.status(_evidence(env, db))["status"] == "created"
        assert volatility_view.request_removal(db, _evidence(env, db), user="analyst")["status"] == "removing"
        with pytest.raises(volatility_view.VolatilityViewError):
            volatility_view.request_removal(db, _evidence(env, db), user="analyst")
    assert env.queued == [(env.evidence_id, "remove")]
    assert volatility_view.run_volatility_view(env.evidence_id, "remove")["status"] == "removed"
    assert not dump.exists()
    with env.Session() as db:
        assert "volatility_view" not in _evidence(env, db).metadata_json


def test_no_copy_is_made_any_more(env):
    assert volatility_view.run_volatility_view(env.evidence_id, "create")["status"] == "unsupported_action"
    assert not hasattr(volatility_view, "request_copy")
