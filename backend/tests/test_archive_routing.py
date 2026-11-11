"""Which uploaded archives go to raw-collection discovery and which are extracted whole.

Discovery reads only the triage artifacts it recognizes, so a file it does not know -- a memory
image -- is never looked at. An archive whose paths look like a collection (Users/..., Windows/...)
but holds nothing discovery can parse, or one the analyst marked as a compressed memory capture,
must be extracted whole so its files are classified.
"""

from __future__ import annotations

import zipfile
from types import SimpleNamespace

import pytest

from app.models.evidence import EvidenceType
from tests.test_ad1_image import _FakeSession


def _upload_zip(monkeypatch, tmp_path, members: dict[str, bytes], **kwargs):
    from fastapi import UploadFile

    from app.api import routes_evidence
    from app.core.config import get_settings
    from app.core.storage import build_evidence_root
    from app.models.case import Case

    monkeypatch.setattr(get_settings(), "backend_data_dir", tmp_path / "data")
    stored = build_evidence_root("case-1", "ev-1") / "original" / "capture.zip"
    stored.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(stored, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    monkeypatch.setattr(routes_evidence, "save_upload", lambda case_id, file: ("ev-1", stored, stored.stat().st_size, "ab" * 32))
    monkeypatch.setattr(routes_evidence, "find_duplicate_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(routes_evidence, "_persist_generic_ingest_plan", lambda db, evidence: evidence)
    db = _FakeSession(Case(id="case-1", name="Case 1"))
    upload = UploadFile(filename="capture.zip", file=SimpleNamespace())
    return routes_evidence._upload_evidence_impl("case-1", upload, False, None, "raw", "single_file", db, **kwargs)


TRIAGE = {"C/Users/analyst/NTUSER.DAT": b"regf" + b"\0" * 64, "C/Users/analyst/Desktop/PhysicalMemory.dd": b"\0" * 64}
ONLY_MEMORY = {"C/Users/analyst/Desktop/PhysicalMemory.dd": b"\0" * 64}


def test_a_triage_collection_still_goes_to_discovery(monkeypatch, tmp_path):
    evidence = _upload_zip(monkeypatch, tmp_path, TRIAGE)
    assert evidence.evidence_type == EvidenceType.velociraptor_zip


@pytest.mark.parametrize(
    ("members", "kwargs"),
    [
        pytest.param(ONLY_MEMORY, {}, id="collection-paths-but-nothing-discovery-parses"),
        pytest.param(TRIAGE, {"extract_whole_archive": True}, id="analyst-marked-it-a-compressed-memory-capture"),
    ],
)
def test_archives_whose_files_must_be_classified_are_extracted_whole(monkeypatch, tmp_path, members, kwargs):
    evidence = _upload_zip(monkeypatch, tmp_path, members, **kwargs)
    assert evidence.evidence_type != EvidenceType.velociraptor_zip
    assert not (evidence.metadata_json or {}).get("velociraptor_discovery")
    assert bool((evidence.metadata_json or {}).get("register_bundled_memory")) == bool(kwargs.get("extract_whole_archive"))
