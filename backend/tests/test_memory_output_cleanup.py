"""Deleting a case or a memory evidence removes its memory outputs (runs, crash-dump copy), which
live in the memory worker's own directory, and any left behind by earlier deletions."""

from __future__ import annotations

import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.workers import tasks


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_cleanup_removes_deleted_evidence_and_orphans_and_keeps_live_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "memory_output_dir", str(tmp_path))
    Session = _session()
    live_case, live_evidence, deleted_evidence, orphan_case = (str(uuid.uuid4()) for _ in range(4))
    with Session() as db:
        db.add(Case(id=live_case, name="Live"))
        db.add(Evidence(id=live_evidence, case_id=live_case, original_filename="m.raw", stored_path="/x", evidence_type=EvidenceType.memory_dump, size_bytes=1))
        db.commit()
    root = tmp_path / "evidence"
    for case_id, evidence_id in ((live_case, live_evidence), (live_case, deleted_evidence), (orphan_case, str(uuid.uuid4()))):
        view = root / case_id / evidence_id / "memory" / "volatility-view"
        view.mkdir(parents=True)
        (view / "memory.dmp").write_bytes(b"PAGEDU64")
    monkeypatch.setattr(tasks, "SessionLocal", Session)

    result = tasks.run_memory_output_cleanup(live_case, deleted_evidence)

    assert (root / live_case / live_evidence / "memory" / "volatility-view" / "memory.dmp").is_file()
    assert not (root / live_case / deleted_evidence).exists()
    assert not (root / orphan_case).exists()
    assert sorted(result["removed"]) == sorted([f"{live_case}/{deleted_evidence}", orphan_case])


def test_cleanup_ignores_ids_that_are_not_uuids(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "memory_output_dir", str(tmp_path))
    (tmp_path / "evidence" / "keep").mkdir(parents=True)
    monkeypatch.setattr(tasks, "SessionLocal", _session())
    assert tasks.run_memory_output_cleanup("../..", None) == {"removed": []}
    assert (tmp_path / "evidence" / "keep").is_dir()
