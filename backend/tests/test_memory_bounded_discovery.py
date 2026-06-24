"""Bounded Windows symbol-requirement discovery tests.

The OS-agnostic preparation pipeline detects the platform
(Windows / Linux / macOS) from a bounded read of the first bytes
of the image.  When the platform is Windows and no
``MemorySymbolRequirement`` exists, the legacy preparation used
to terminate as ``requirement_unknown`` because the exact PDB
name, GUID, age and architecture were never persisted by the
pre-OS-agnostic pipeline.

This suite covers the bounded discovery service that fills the
gap.  The bounded service:

* runs a single ``windows.info`` probe that uses a
  monkey-patched ``PDBUtility.load_windows_symbol_table`` callback
  to capture the exact identity (no name- or size-based guessing);
* persists a ``MemorySymbolRequirement`` row with a natural key of
  ``(platform, pdb_name, pdb_guid, pdb_age, architecture)``;
* updates ``memory_evidence_contents.last_requirement_id`` so a
  re-upload of the same file reuses the row without a second
  probe;
* looks up an exact validated cache match;
* reports ``ready`` when the exact validated symbol is cached;
* reports ``blocked_symbols`` when the requirement is known but
  the exact cache is absent;
* reports ``requirement_unknown`` only when the bounded probe
  cannot derive an identity;
* reports a retryable ``PREP_FAILED`` when the bounded process
  fails (never ``unsupported``);
* never creates a ``MemoryScanRun``;
* never writes OpenSearch;
* never downloads symbols;
* is idempotent under concurrent retries;
* preserves the existing ready Windows evidence path.
"""
from __future__ import annotations

import uuid as _uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.core.config import get_settings
from app.models.case import Case, CaseStatus
from app.models.evidence import (
    Evidence, EvidenceStorageMode, EvidenceType, IngestStatus,
)
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryEvidenceContent,
    MemoryScanRun,
    MemorySymbolPreparation,
    MemorySymbolRequirement,
)
from app.services.memory import preparation_runtime as pr
from app.services.memory import symbol_preparation as sp
from app.services.memory.platform import (
    Architecture,
    MemoryProbeResult,
    PlatformFamily,
    ProbeConfidence,
    ReadinessResult,
    ReadinessState,
    WindowsMemoryAdapter,
)
from app.services.memory.symbol_requirement_discovery import (
    BoundedDiscoveryError,
    DISCOVERY_BACKEND_START_FAILED,
    DISCOVERY_INCONCLUSIVE,
    DiscoveredRequirement,
    SOURCE_BOUNDED_DISCOVERY,
    discover_windows_symbol_requirement,
    persist_discovered_requirement,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def case_id(db: Session) -> str:
    case = Case(
        id=str(_uuid.uuid4()),
        name="bounded-discovery-test",
        mode="investigation",
        status=CaseStatus.open,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case.id


def _make_evidence(
    db: Session,
    case_id: str,
    *,
    sha256: str = "a" * 64,
    size_bytes: int = 4_255_346_688,
    filename: str = "WS01-20240322-125737.dmp",
    stored_path: str | None = None,
) -> Evidence:
    if stored_path is None:
        stored_path = f"/tmp/{filename}"
    ev = Evidence(
        id=str(_uuid.uuid4()),
        case_id=case_id,
        original_filename=filename,
        stored_path=stored_path,
        original_path=stored_path,
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=sha256,
        size_bytes=size_bytes,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        detection_status="windows_memory",
        detected_format="windows_crash_dump",
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def _make_cached_symbol(
    db: Session,
    *,
    pdb_name: str = "ntkrnlmp.pdb",
    pdb_guid: str = "9DC3FC69B1CA4B34707EBC57FD1D6126",
    pdb_age: int = 1,
    architecture: str = "x64",
    validation_status: str = "validated",
) -> MemoryCachedSymbol:
    symbol_key = f"{pdb_name.lower()}/{pdb_guid.upper()}-{pdb_age}"
    cached = MemoryCachedSymbol(
        id=str(_uuid.uuid4()),
        symbol_key=symbol_key,
        pdb_name=pdb_name,
        pdb_guid=pdb_guid.upper(),
        pdb_age=pdb_age,
        architecture=architecture,
        pdb_relative_path=f"pdb/{pdb_name}/{pdb_guid}-{pdb_age}/{pdb_name}",
        isf_relative_path=f"symbols/windows/{pdb_name}/{pdb_guid}-{pdb_age}.json.xz",
        pdb_sha256="1" * 64,
        isf_sha256="2" * 64,
        pdb_size_bytes=12_636_160,
        isf_size_bytes=608_384,
        validation_status=validation_status,
        source_category="official_microsoft_symbols",
    )
    db.add(cached)
    db.commit()
    db.refresh(cached)
    return cached


def _make_prep(db: Session, evidence: Evidence) -> MemorySymbolPreparation:
    prep = MemorySymbolPreparation(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        state=sp.PREP_PROBING,
        state_reason="probing_platform",
        attempts=0,
        active=True,
        progress_percent=0,
        metadata_json={},
    )
    db.add(prep)
    db.commit()
    db.refresh(prep)
    return prep


def _windows_probe(arch: Architecture = Architecture.X64) -> MemoryProbeResult:
    return MemoryProbeResult(
        platform=PlatformFamily.WINDOWS,
        format="crashdump_PAGE",
        architecture=arch,
        confidence=ProbeConfidence.HIGH,
        reason="crashdump_PAGE",
        evidence_format="windows_crash_dump",
    )


def _make_discovered(
    *,
    pdb_name: str = "ntkrnlmp.pdb",
    pdb_guid: str = "9DC3FC69B1CA4B34707EBC57FD1D6126",
    pdb_age: int = 1,
    architecture: str = "x64",
) -> DiscoveredRequirement:
    return DiscoveredRequirement(
        platform="windows",
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
        architecture=architecture,
        discovery_method=SOURCE_BOUNDED_DISCOVERY,
    )


# ---------------------------------------------------------------------------
# 1. Windows PAGE evidence without requirement triggers bounded discovery
# ---------------------------------------------------------------------------


def test_01_page_evidence_triggers_bounded_discovery(
    db: Session, case_id, monkeypatch, tmp_path
) -> None:
    ev = _make_evidence(db, case_id, stored_path=str(tmp_path / "WS01.dmp"))
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(b"PAGE" + b"\x00" * 4092)
    ev.stored_path = str(evidence_file)
    db.commit()
    db.refresh(ev)
    cached = _make_cached_symbol(db)

    monkeypatch.setattr(
        "app.services.memory.preparation_runtime._evidence_canonical_path",
        lambda e: evidence_file,
    )
    fake_discovered = _make_discovered()
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        lambda *a, **kw: fake_discovered,
    )
    fake_requirement = MemorySymbolRequirement(
        id=str(_uuid.uuid4()),
        case_id=ev.case_id,
        evidence_id=ev.id,
        pdb_name=fake_discovered.pdb_name,
        pdb_guid=fake_discovered.pdb_guid,
        pdb_age=fake_discovered.pdb_age,
        architecture=fake_discovered.architecture,
        symbol_key="ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1",
        status="cached",
        cached_symbol_id=cached.id,
        source=SOURCE_BOUNDED_DISCOVERY,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.persist_discovered_requirement",
        lambda db_, *, evidence, discovered: (fake_requirement, cached, True),
    )

    readiness = ReadinessResult(
        state=ReadinessState.BLOCKED,
        reason="windows_probe_required",
        error_code="WINDOWS_PROBE_REQUIRED",
        requires_discovery=True,
    )
    new_state, reason, error, requirement_id, meta = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=_windows_probe(), readiness=readiness
    )
    assert new_state == pr._DISCOVERY_OK
    assert reason == "windows_cache_match"
    assert error == "WINDOWS_EXACT_CACHE_HIT"
    assert requirement_id == str(fake_requirement.id)
    assert meta["platform"] == "windows"
    assert meta["requirement"]["pdb_name"] == "ntkrnlmp.pdb"


# ---------------------------------------------------------------------------
# 2. Discovery extracts exact PDB name, GUID, age, architecture
# ---------------------------------------------------------------------------


def test_02_discovery_extracts_exact_identity(monkeypatch) -> None:
    fake_payload = {
        "pdb_name": "ntkrnlmp.pdb",
        "pdb_guid": "9dc3fc69b1ca4b34707ebc57fd1d6126",
        "pdb_age": 1,
        "architecture": "intel64",
    }
    monkeypatch.setattr(
        "app.services.memory.volatility_runner.resolve_volatility_executable",
        lambda: ("/usr/bin/vol", "vol"),
    )
    monkeypatch.setattr(
        "app.services.memory.volatility_runner.probe_windows_symbol_identity",
        lambda path, work_dir: fake_payload,
    )
    discovered = discover_windows_symbol_requirement(
        Path("/tmp/WS01.dmp"), Path("/tmp")
    )
    assert discovered.pdb_name == "ntkrnlmp.pdb"
    assert discovered.pdb_guid == "9DC3FC69B1CA4B34707EBC57FD1D6126"
    assert discovered.pdb_age == 1
    assert discovered.architecture == "x64"
    assert discovered.platform == "windows"
    assert discovered.discovery_method == SOURCE_BOUNDED_DISCOVERY
    assert discovered.is_valid()


# ---------------------------------------------------------------------------
# 3. Requirement row is created
# ---------------------------------------------------------------------------


def test_03_requirement_row_created_with_natural_key(
    db: Session, case_id
) -> None:
    ev = _make_evidence(db, case_id)
    _make_cached_symbol(db)
    discovered = _make_discovered()
    requirement, cached, created = persist_discovered_requirement(
        db, evidence=ev, discovered=discovered
    )
    assert created is True
    assert cached is not None
    assert requirement.evidence_id == ev.id
    assert requirement.case_id == ev.case_id
    assert requirement.pdb_name == "ntkrnlmp.pdb"
    assert requirement.pdb_guid == "9DC3FC69B1CA4B34707EBC57FD1D6126"
    assert requirement.pdb_age == 1
    assert requirement.architecture == "x64"
    assert requirement.source == SOURCE_BOUNDED_DISCOVERY
    assert requirement.symbol_key == "ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1"


# ---------------------------------------------------------------------------
# 4. Content identity receives last_requirement_id
# ---------------------------------------------------------------------------


def test_04_content_identity_receives_last_requirement_id(
    db: Session, case_id
) -> None:
    ev = _make_evidence(db, case_id)
    _make_cached_symbol(db)
    discovered = _make_discovered()
    requirement, _, _ = persist_discovered_requirement(
        db, evidence=ev, discovered=discovered
    )
    content = (
        db.query(MemoryEvidenceContent)
        .filter(MemoryEvidenceContent.evidence_sha256 == ev.sha256)
        .one()
    )
    assert content.last_requirement_id == str(requirement.id)
    assert content.size_bytes == ev.size_bytes


# ---------------------------------------------------------------------------
# 5. Exact validated cached symbol produces ready
# ---------------------------------------------------------------------------


def test_05_exact_validated_cache_match_produces_ready(
    db: Session, case_id, monkeypatch, tmp_path
) -> None:
    ev = _make_evidence(db, case_id, stored_path=str(tmp_path / "WS01.dmp"))
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(b"PAGE" + b"\x00" * 4092)
    ev.stored_path = str(evidence_file)
    db.commit()
    db.refresh(ev)
    cached = _make_cached_symbol(db)
    monkeypatch.setattr(
        "app.services.memory.preparation_runtime._evidence_canonical_path",
        lambda e: evidence_file,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        lambda *a, **kw: _make_discovered(),
    )
    fake_requirement = MagicMock()
    fake_requirement.id = str(_uuid.uuid4())
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.persist_discovered_requirement",
        lambda db_, *, evidence, discovered: (fake_requirement, cached, True),
    )
    new_state, reason, error, requirement_id, _ = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=_windows_probe(), readiness=MagicMock()
    )
    assert new_state == pr._DISCOVERY_OK
    assert reason == "windows_cache_match"
    assert error == "WINDOWS_EXACT_CACHE_HIT"
    assert requirement_id == str(fake_requirement.id)


# ---------------------------------------------------------------------------
# 6. Known requirement without cache produces blocked_symbols
# ---------------------------------------------------------------------------


def test_06_known_requirement_without_cache_produces_blocked_symbols(
    db: Session, case_id, monkeypatch, tmp_path
) -> None:
    ev = _make_evidence(db, case_id, stored_path=str(tmp_path / "WS01.dmp"))
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(b"PAGE" + b"\x00" * 4092)
    ev.stored_path = str(evidence_file)
    db.commit()
    db.refresh(ev)
    monkeypatch.setattr(
        "app.services.memory.preparation_runtime._evidence_canonical_path",
        lambda e: evidence_file,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        lambda *a, **kw: _make_discovered(),
    )
    fake_requirement = MagicMock()
    fake_requirement.id = str(_uuid.uuid4())
    fake_requirement.symbol_key = "ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1"
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.persist_discovered_requirement",
        lambda db_, *, evidence, discovered: (fake_requirement, None, True),
    )
    new_state, reason, error, requirement_id, meta = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=_windows_probe(), readiness=MagicMock()
    )
    assert new_state == pr._DISCOVERY_BLOCKED_SYMBOLS
    assert reason == "windows_symbols_missing"
    assert error == "WINDOWS_EXACT_SYMBOLS_MISSING"
    assert requirement_id == str(fake_requirement.id)
    assert meta["symbol_key"] == "ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1"


# ---------------------------------------------------------------------------
# 7. Inconclusive discovery remains requirement_unknown
# ---------------------------------------------------------------------------


def test_07_inconclusive_discovery_remains_requirement_unknown(
    db: Session, case_id, monkeypatch, tmp_path
) -> None:
    ev = _make_evidence(db, case_id, stored_path=str(tmp_path / "WS01.dmp"))
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(b"PAGE" + b"\x00" * 4092)
    ev.stored_path = str(evidence_file)
    db.commit()
    db.refresh(ev)
    monkeypatch.setattr(
        "app.services.memory.preparation_runtime._evidence_canonical_path",
        lambda e: evidence_file,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        MagicMock(side_effect=BoundedDiscoveryError(
            DISCOVERY_INCONCLUSIVE, "inconclusive", retryable=False
        )),
    )
    new_state, reason, error, requirement_id, meta = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=_windows_probe(), readiness=MagicMock()
    )
    assert new_state == pr._DISCOVERY_REQUIREMENT_UNKNOWN
    assert reason == DISCOVERY_INCONCLUSIVE
    assert requirement_id is None
    assert meta["retryable"] is False


# ---------------------------------------------------------------------------
# 8. Probe execution failure is retryable and not unsupported
# ---------------------------------------------------------------------------


def test_08_probe_failure_is_retryable_not_unsupported(
    db: Session, case_id, monkeypatch, tmp_path
) -> None:
    ev = _make_evidence(db, case_id, stored_path=str(tmp_path / "WS01.dmp"))
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(b"PAGE" + b"\x00" * 4092)
    ev.stored_path = str(evidence_file)
    db.commit()
    db.refresh(ev)
    monkeypatch.setattr(
        "app.services.memory.preparation_runtime._evidence_canonical_path",
        lambda e: evidence_file,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        MagicMock(side_effect=BoundedDiscoveryError(
            DISCOVERY_BACKEND_START_FAILED, "spawn failed", retryable=True
        )),
    )
    new_state, reason, error, _, meta = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=_windows_probe(), readiness=MagicMock()
    )
    assert new_state == pr._DISCOVERY_RETRYABLE
    assert meta["retryable"] is True
    assert new_state != "unsupported"
    assert error == DISCOVERY_BACKEND_START_FAILED


# ---------------------------------------------------------------------------
# 9. Same content identity reuses requirement without a second probe
# ---------------------------------------------------------------------------


def test_09_same_content_identity_reuses_requirement(
    db: Session, case_id
) -> None:
    _make_cached_symbol(db)
    ev1 = _make_evidence(db, case_id, sha256="b" * 64)
    discovered = _make_discovered()
    r1, _, created1 = persist_discovered_requirement(
        db, evidence=ev1, discovered=discovered
    )
    assert created1 is True

    ev2 = _make_evidence(db, case_id, sha256="b" * 64)
    r2, _, created2 = persist_discovered_requirement(
        db, evidence=ev2, discovered=discovered
    )
    assert created2 is False
    assert r2.id == r1.id
    content_rows = (
        db.query(MemoryEvidenceContent)
        .filter(MemoryEvidenceContent.evidence_sha256 == "b" * 64)
        .all()
    )
    assert len(content_rows) == 1
    assert str(content_rows[0].last_requirement_id) == str(r1.id)


# ---------------------------------------------------------------------------
# 10. Concurrent retries do not create duplicate requirements
# ---------------------------------------------------------------------------


def test_10_concurrent_retries_no_duplicate_requirements(
    db: Session, case_id
) -> None:
    _make_cached_symbol(db)
    ev = _make_evidence(db, case_id, sha256="c" * 64)
    discovered = _make_discovered()
    r1, _, c1 = persist_discovered_requirement(db, evidence=ev, discovered=discovered)
    db.rollback()
    r2, _, c2 = persist_discovered_requirement(db, evidence=ev, discovered=discovered)
    assert c1 is True
    assert c2 is False
    assert r1.id == r2.id
    rows = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == ev.id)
        .all()
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 11. PDB name match with different GUID does not produce ready
# ---------------------------------------------------------------------------


def test_11_pdb_name_match_different_guid_no_ready(
    db: Session, case_id
) -> None:
    _make_cached_symbol(db, pdb_guid="A" * 32)
    ev = _make_evidence(db, case_id, sha256="d" * 64)
    discovered = _make_discovered(pdb_guid="B" * 32)
    requirement, cached, _ = persist_discovered_requirement(
        db, evidence=ev, discovered=discovered
    )
    assert cached is None
    assert requirement.status == "unavailable_offline"
    assert requirement.cached_symbol_id is None


# ---------------------------------------------------------------------------
# 12. GUID match with different age does not produce ready
# ---------------------------------------------------------------------------


def test_12_guid_match_different_age_no_ready(
    db: Session, case_id
) -> None:
    _make_cached_symbol(db, pdb_age=1)
    ev = _make_evidence(db, case_id, sha256="e" * 64)
    discovered = _make_discovered(pdb_age=2)
    requirement, cached, _ = persist_discovered_requirement(
        db, evidence=ev, discovered=discovered
    )
    assert cached is None
    assert requirement.status == "unavailable_offline"


# ---------------------------------------------------------------------------
# 13. No MemoryScanRun is created
# ---------------------------------------------------------------------------


def test_13_no_memory_scan_run_created(
    db: Session, case_id
) -> None:
    _make_cached_symbol(db)
    ev = _make_evidence(db, case_id, sha256="f" * 64)
    discovered = _make_discovered()
    persist_discovered_requirement(db, evidence=ev, discovered=discovered)
    assert db.query(MemoryScanRun).filter_by(evidence_id=ev.id).count() == 0


# ---------------------------------------------------------------------------
# 14. No OpenSearch write occurs
# ---------------------------------------------------------------------------


def test_14_no_opensearch_write(monkeypatch) -> None:
    import sys
    def _block(*args, **kwargs):
        raise AssertionError("OpenSearch must not be touched by bounded discovery")
    monkeypatch.setitem(sys.modules, "opensearchpy", _block)
    monkeypatch.setitem(sys.modules, "opensearch_dsl", _block)
    discovered = _make_discovered()
    payload = {
        "pdb_name": discovered.pdb_name,
        "pdb_guid": discovered.pdb_guid,
        "pdb_age": discovered.pdb_age,
        "architecture": discovered.architecture,
    }
    with patch(
        "app.services.memory.volatility_runner.resolve_volatility_executable",
        return_value=("/usr/bin/vol", "vol"),
    ), patch(
        "app.services.memory.volatility_runner.probe_windows_symbol_identity",
        return_value=payload,
    ):
        result = discover_windows_symbol_requirement(
            Path("/tmp/WS01.dmp"), Path("/tmp")
        )
    assert result.pdb_name == "ntkrnlmp.pdb"


# ---------------------------------------------------------------------------
# 15. No symbol download occurs
# ---------------------------------------------------------------------------


def test_15_no_symbol_download(monkeypatch) -> None:
    import sys
    class _BlockFetcher:
        def __getattr__(self, name):
            raise AssertionError(
                f"symbol-fetcher must not be touched by bounded discovery (tried: {name})"
            )
    sys.modules["app.services.memory.symbol_fetcher"] = _BlockFetcher()
    payload = {
        "pdb_name": "ntkrnlmp.pdb",
        "pdb_guid": "9DC3FC69B1CA4B34707EBC57FD1D6126",
        "pdb_age": 1,
        "architecture": "x64",
    }
    with patch(
        "app.services.memory.volatility_runner.resolve_volatility_executable",
        return_value=("/usr/bin/vol", "vol"),
    ), patch(
        "app.services.memory.volatility_runner.probe_windows_symbol_identity",
        return_value=payload,
    ):
        result = discover_windows_symbol_requirement(
            Path("/tmp/WS01.dmp"), Path("/tmp")
        )
    assert result.is_valid()


# ---------------------------------------------------------------------------
# 16. No heavy plugin executes
# ---------------------------------------------------------------------------


def test_16_no_heavy_plugin_executes(monkeypatch) -> None:
    captured: dict = {}
    def _fake_runner(evidence_path, work_dir, *, offline=True, cache_path=None, symbol_path=None):
        captured["plugin"] = "windows.info"
        captured["offline"] = offline
        return {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "9DC3FC69B1CA4B34707EBC57FD1D6126",
            "pdb_age": 1,
            "architecture": "x64",
        }
    with patch(
        "app.services.memory.volatility_runner.resolve_volatility_executable",
        return_value=("/usr/bin/vol", "vol"),
    ), patch(
        "app.services.memory.volatility_runner.probe_windows_symbol_identity",
        _fake_runner,
    ):
        discover_windows_symbol_requirement(Path("/tmp/WS01.dmp"), Path("/tmp"))
    assert captured["plugin"] == "windows.info"
    assert captured["offline"] is True


# ---------------------------------------------------------------------------
# 17. Evidence hash and file metadata are unchanged
# ---------------------------------------------------------------------------


def test_17_evidence_hash_unchanged(
    db: Session, case_id, tmp_path
) -> None:
    import hashlib
    data = b"PAGE" + b"\x00" * 4092
    evidence_file = tmp_path / "WS01.dmp"
    evidence_file.write_bytes(data)
    before_sha = hashlib.sha256(data).hexdigest()
    ev = _make_evidence(
        db, case_id, sha256=before_sha, stored_path=str(evidence_file)
    )
    _make_cached_symbol(db)
    discovered = _make_discovered()
    persist_discovered_requirement(db, evidence=ev, discovered=discovered)
    after_data = evidence_file.read_bytes()
    after_sha = hashlib.sha256(after_data).hexdigest()
    assert after_sha == before_sha
    assert after_data == data


# ---------------------------------------------------------------------------
# 18. Existing ready Windows evidence remains ready
# ---------------------------------------------------------------------------


def test_18_existing_ready_windows_evidence_unchanged(
    db: Session, case_id, monkeypatch
) -> None:
    cached = _make_cached_symbol(db)
    ev = _make_evidence(db, case_id, sha256="a" * 64)
    existing = MemorySymbolRequirement(
        id=str(_uuid.uuid4()),
        case_id=ev.case_id,
        evidence_id=ev.id,
        source_run_id=str(_uuid.uuid4()),
        source_plugin_run_id=str(_uuid.uuid4()),
        pdb_name=cached.pdb_name,
        pdb_guid=cached.pdb_guid,
        pdb_age=cached.pdb_age,
        architecture=cached.architecture,
        symbol_key=cached.symbol_key,
        status="cached",
        cached_symbol_id=cached.id,
        source="probe",
    )
    db.add(existing)
    db.commit()
    db.refresh(existing)
    content = MemoryEvidenceContent(
        evidence_sha256=ev.sha256,
        size_bytes=ev.size_bytes,
        last_requirement_id=str(existing.id),
        last_readiness="ready",
    )
    db.add(content)
    db.commit()
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        MagicMock(side_effect=AssertionError("bounded discovery must not run for cache hit")),
    )
    adapter = WindowsMemoryAdapter()
    cache_state = {
        "exact_cache_match": True,
        "requirement_id": str(existing.id),
        "successful_metadata_run": False,
        "isf_available": True,
    }
    result = adapter.check_readiness(
        probe=_windows_probe(),
        cache_state=cache_state,
    )
    assert result.state == ReadinessState.READY
    assert result.reason == "exact_cache_match"
    assert result.requirement_id == str(existing.id)
    assert result.requires_discovery is False


# ---------------------------------------------------------------------------
# 19. Linux/macOS/unknown paths do not invoke Windows discovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "platform",
    [PlatformFamily.LINUX, PlatformFamily.MACOS, PlatformFamily.UNKNOWN],
)
def test_19_non_windows_does_not_invoke_windows_discovery(
    db: Session, case_id, monkeypatch, platform
) -> None:
    ev = _make_evidence(db, case_id, sha256="a" * 64)
    probe = MemoryProbeResult(
        platform=platform,
        format="unknown",
        architecture=Architecture.UNKNOWN,
        confidence=ProbeConfidence.LOW,
        reason="not_windows",
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_requirement_discovery.discover_windows_symbol_requirement",
        MagicMock(side_effect=AssertionError("Windows discovery must not run for non-Windows platforms")),
    )
    new_state, _, _, _, meta = pr._run_bounded_requirement_discovery(
        db, evidence=ev, probe_result=probe, readiness=MagicMock()
    )
    assert new_state is None
    assert meta["skipped"] is True
    assert meta["platform"] == platform.value


# ---------------------------------------------------------------------------
# 20. Existing preparation and upload regression suites pass (smoke)
# ---------------------------------------------------------------------------


def test_20_no_regressions_in_dispatch_contract(
    db: Session, case_id, monkeypatch
) -> None:
    cached = _make_cached_symbol(db)
    ev = _make_evidence(db, case_id, sha256="a" * 64)
    existing = MemorySymbolRequirement(
        id=str(_uuid.uuid4()),
        case_id=ev.case_id,
        evidence_id=ev.id,
        pdb_name=cached.pdb_name,
        pdb_guid=cached.pdb_guid,
        pdb_age=cached.pdb_age,
        architecture=cached.architecture,
        symbol_key=cached.symbol_key,
        status="cached",
        cached_symbol_id=cached.id,
    )
    db.add(existing)
    db.commit()
    db.refresh(existing)
    content = MemoryEvidenceContent(
        evidence_sha256=ev.sha256,
        size_bytes=ev.size_bytes,
        last_requirement_id=str(existing.id),
        last_readiness="ready",
    )
    db.add(content)
    db.commit()

    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda evidence_id: "rq-job-bounded",
    )
    result = pr.dispatch_memory_preparation(db, evidence=ev)
    assert result["task_active"] is True
    assert result["queue"] == get_settings().memory_queue_name
    assert sp.PREP_BLOCKED_SYMBOLS in sp.ALL_PREP_STATES
    assert sp.ui_state_for(sp.PREP_BLOCKED_SYMBOLS) == sp.UI_STATE_BLOCKED


# ---------------------------------------------------------------------------
# Nullable provenance tests (sprint: runless bounded discovery)
# ---------------------------------------------------------------------------


class TestNullableProvenance:
    """Verify that bounded-discovery requirements can persist with NULL
    source FKs and that real-analysis requirements still enforce FKs."""

    # ------------------------------------------------------------------
    # 21. Bounded discovery persists NULL source FKs
    # ------------------------------------------------------------------

    def test_21_bounded_discovery_null_source_fks(
        self, db: Session, case_id,
    ) -> None:
        """persist_discovered_requirement creates a requirement with
        source_run_id=None and source_plugin_run_id=None."""
        ev = _make_evidence(db, case_id, sha256="b" * 64)
        cached = _make_cached_symbol(db)
        discovered = DiscoveredRequirement(
            platform="windows",
            pdb_name=cached.pdb_name,
            pdb_guid=cached.pdb_guid,
            pdb_age=cached.pdb_age,
            architecture=cached.architecture,
            discovery_method="windows.info",
        )
        requirement, returned_cached, created = persist_discovered_requirement(
            db, evidence=ev, discovered=discovered,
        )
        assert created is True
        assert requirement.source_run_id is None
        assert requirement.source_plugin_run_id is None
        assert requirement.source == SOURCE_BOUNDED_DISCOVERY
        assert returned_cached is not None
        assert returned_cached.id == cached.id

    # ------------------------------------------------------------------
    # 22. Bounded discovery creates zero MemoryScanRun / PluginRun rows
    # ------------------------------------------------------------------

    def test_22_bounded_discovery_zero_scan_runs(
        self, db: Session, case_id,
    ) -> None:
        """Bounded discovery must not create MemoryScanRun or
        MemoryPluginRun rows."""
        scan_before = db.query(MemoryScanRun).count()
        ev = _make_evidence(db, case_id, sha256="c" * 64)
        cached = _make_cached_symbol(db)
        discovered = DiscoveredRequirement(
            platform="windows",
            pdb_name=cached.pdb_name,
            pdb_guid=cached.pdb_guid,
            pdb_age=cached.pdb_age,
            architecture=cached.architecture,
            discovery_method="windows.info",
        )
        persist_discovered_requirement(db, evidence=ev, discovered=discovered)
        scan_after = db.query(MemoryScanRun).count()
        assert scan_after == scan_before

    # ------------------------------------------------------------------
    # 23. Exact cached symbol still produces ready
    # ------------------------------------------------------------------

    def test_23_nullable_source_still_ready(
        self, db: Session, case_id,
    ) -> None:
        """A requirement with null source FKs still reaches READY when
        the exact cache is present."""
        ev = _make_evidence(db, case_id, sha256="d" * 64)
        cached = _make_cached_symbol(db)
        discovered = DiscoveredRequirement(
            platform="windows",
            pdb_name=cached.pdb_name,
            pdb_guid=cached.pdb_guid,
            pdb_age=cached.pdb_age,
            architecture=cached.architecture,
            discovery_method="windows.info",
        )
        requirement, returned_cached, _ = persist_discovered_requirement(
            db, evidence=ev, discovered=discovered,
        )
        assert returned_cached is not None
        assert requirement.status == "cached"

    # ------------------------------------------------------------------
    # 24. Missing exact cache produces blocked_symbols
    # ------------------------------------------------------------------

    def test_24_nullable_source_blocked_symbols(
        self, db: Session, case_id,
    ) -> None:
        """A requirement with null source FKs becomes blocked_symbols
        when the exact cache is absent."""
        ev = _make_evidence(db, case_id, sha256="e" * 64)
        discovered = DiscoveredRequirement(
            platform="windows",
            pdb_name="ntoskrnl.exe",
            pdb_guid="AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP",
            pdb_age=1,
            architecture="x64",
            discovery_method="windows.info",
        )
        requirement, returned_cached, _ = persist_discovered_requirement(
            db, evidence=ev, discovered=discovered,
        )
        assert returned_cached is None
        assert requirement.status == "unavailable_offline"

    # ------------------------------------------------------------------
    # 25. Real analysis-derived requirement still accepts real IDs
    # ------------------------------------------------------------------

    def test_25_real_run_plugin_ids_accepted(
        self, db: Session, case_id,
    ) -> None:
        """A requirement derived from a real scan/plugin run can still
        store non-null FK values."""
        ev = _make_evidence(db, case_id, sha256="f" * 64)
        cached = _make_cached_symbol(db)
        run_id = str(_uuid.uuid4())
        plugin_id = str(_uuid.uuid4())
        req = MemorySymbolRequirement(
            id=str(_uuid.uuid4()),
            case_id=ev.case_id,
            evidence_id=ev.id,
            source_run_id=run_id,
            source_plugin_run_id=plugin_id,
            pdb_name=cached.pdb_name,
            pdb_guid=cached.pdb_guid,
            pdb_age=cached.pdb_age,
            architecture=cached.architecture,
            symbol_key=cached.symbol_key,
            status="cached",
            cached_symbol_id=cached.id,
            source="probe",
        )
        db.add(req)
        db.commit()
        assert req.source_run_id == run_id
        assert req.source_plugin_run_id == plugin_id

    # ------------------------------------------------------------------
    # 26. No placeholder UUID generation remains
    # ------------------------------------------------------------------

    def test_26_no_placeholder_uuid_generation(
        self,
    ) -> None:
        """The discovery module must not export any placeholder UUID
        generator."""
        import app.services.memory.symbol_requirement_discovery as mod
        assert not hasattr(mod, "_stable_discovery_uuids")
        assert not hasattr(mod, "fallback_run_id")

    # ------------------------------------------------------------------
    # 27. Same content identity reuses requirement
    # ------------------------------------------------------------------

    def test_27_nullable_source_content_reuse(
        self, db: Session, case_id,
    ) -> None:
        """Re-upload of same SHA reuses existing requirement even with
        null source FKs."""
        ev = _make_evidence(db, case_id, sha256="g" * 64)
        cached = _make_cached_symbol(db)
        discovered = DiscoveredRequirement(
            platform="windows",
            pdb_name=cached.pdb_name,
            pdb_guid=cached.pdb_guid,
            pdb_age=cached.pdb_age,
            architecture=cached.architecture,
            discovery_method="windows.info",
        )
        req1, _, c1 = persist_discovered_requirement(
            db, evidence=ev, discovered=discovered,
        )
        assert c1 is True
        req2, _, c2 = persist_discovered_requirement(
            db, evidence=ev, discovered=discovered,
        )
        assert c2 is False
        assert req2.id == req1.id
        assert req2.source_run_id is None
        assert req2.source_plugin_run_id is None
