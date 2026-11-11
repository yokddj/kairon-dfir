"""Direct Microsoft download of a missing Windows kernel symbol (MEMORY_SYMBOL_DIRECT_DOWNLOAD_ENABLED)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import get_settings
from app.services.memory import symbol_recovery
from app.services.memory.symbol_fetcher import SymbolFetchError
from tests.test_memory_recovery_sources import _make_case, _make_evidence, _make_requirement, _synthetic_pdb, db  # noqa: F401

GUID = "D801A9AFC0FB7761380800F708633DEA"


@pytest.fixture()
def download_enabled(tmp_path, monkeypatch):
    (tmp_path / "cache").mkdir()
    monkeypatch.setenv("MEMORY_SYMBOL_CACHE_ROOT", str(tmp_path / "cache"))
    monkeypatch.setenv("MEMORY_SYMBOL_DIRECT_DOWNLOAD_ENABLED", "true")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


def test_disabled_by_default(db, monkeypatch):  # noqa: F811
    monkeypatch.delenv("MEMORY_SYMBOL_DIRECT_DOWNLOAD_ENABLED", raising=False)
    get_settings.cache_clear()
    case = _make_case(db)
    req = _make_requirement(db, case_id=case.id, evidence_id=_make_evidence(db, case.id).id)
    monkeypatch.setattr(symbol_recovery, "download_official_pdb", lambda *a, **k: pytest.fail("must not reach the network"))
    result = symbol_recovery.download_microsoft_symbol(db, requirement_id=req.id)
    assert result.error_code == "SYMBOL_DIRECT_DOWNLOAD_DISABLED"
    get_settings.cache_clear()


def test_downloads_the_exact_pdb_and_promotes_it_like_an_import(db, download_enabled, monkeypatch):  # noqa: F811
    case = _make_case(db)
    req = _make_requirement(db, case_id=case.id, evidence_id=_make_evidence(db, case.id).id, pdb_guid=GUID)
    asked = {}

    def fake_download(identity, partial_path, **kwargs):
        asked.update(name=identity.pdb_name, guid=identity.guid, age=identity.age, host=kwargs["initial_host"])
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        _synthetic_pdb(partial_path, pdb_name="ntkrnlmp.pdb", guid=GUID, age=1)
        return {"bytes": partial_path.stat().st_size}

    promoted = {}

    def fake_promote(db, *, requirement, staged_pdb, source_type, source_name, actor):
        promoted.update(source_type=source_type, exists=Path(staged_pdb).is_file())
        return symbol_recovery.RecoveryResult(status=symbol_recovery.RECOVERY_TERMINAL_READY, requirement_id=requirement.id, cached_symbol_id="cached-1")

    monkeypatch.setattr(symbol_recovery, "download_official_pdb", fake_download)
    monkeypatch.setattr(symbol_recovery, "_promote_staged_pdb", fake_promote)
    result = symbol_recovery.download_microsoft_symbol(db, requirement_id=req.id)
    assert result.status == symbol_recovery.RECOVERY_TERMINAL_READY
    assert asked == {"name": "ntkrnlmp.pdb", "guid": GUID, "age": 1, "host": "msdl.microsoft.com"}
    assert promoted == {"source_type": "microsoft_public", "exists": True}


def test_a_failed_download_leaves_nothing_behind(db, download_enabled, monkeypatch):  # noqa: F811
    case = _make_case(db)
    req = _make_requirement(db, case_id=case.id, evidence_id=_make_evidence(db, case.id).id, pdb_guid=GUID)
    staged: list[Path] = []

    def failing(identity, partial_path, **kwargs):
        staged.append(partial_path)
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        partial_path.write_bytes(b"partial")
        raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol download failed.", retryable=True)

    monkeypatch.setattr(symbol_recovery, "download_official_pdb", failing)
    result = symbol_recovery.download_microsoft_symbol(db, requirement_id=req.id)
    assert result.error_code == "SYMBOL_DOWNLOAD_FAILED"
    assert staged and not staged[0].exists()
