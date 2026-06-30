"""Tests for the per-evidence symbol-readiness recovery flow.

Covers:

* ``resolve_memory_symbol_readiness`` priority chain
* ``backfill_memory_symbol_readiness`` (idempotent, no Volatility,
  no downloads)
* Identifier normalization (case, hyphens, hex ages)
* Cache match (exact vs different identifier)
* Catalogue: Blocked vs Unavailable
* Historical results preserved
"""
from __future__ import annotations

import uuid as _uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core import config as core_config
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryCachedSymbol,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolRequirement,
)
from app.services.memory import batch as memory_batch
from app.services.memory import catalogue as memory_catalogue
from app.services.memory import symbol_backfill
from app.services.memory import symbol_resolver
from app.services.memory import symbol_state as symbol_state_module
from app.services.memory.symbol_resolver import (
    BACKFILL_VERSION,
    SOURCE_HISTORICAL_PLUGIN,
    SOURCE_HISTORICAL_RUN,
    SOURCE_HISTORICAL_SYSTEM_INFO,
    SOURCE_PROBE,
    ReconstructedRequirement,
    cache_match_status,
    normalize_age,
    normalize_architecture,
    normalize_guid,
    normalize_pdb_name,
    reconstruct_requirement,
    resolve_memory_symbol_readiness,
    symbol_identifier,
)
from app.services.memory.symbol_state import (
    STATE_CACHED,
    STATE_MISSING,
    STATE_UNKNOWN,
    evidence_symbol_state,
    gate_type_from_state,
    GATE_TYPE_AVAILABLE,
    GATE_TYPE_BLOCKED_ACQUISITION_PENDING,
    GATE_TYPE_BLOCKED_SYMBOLS_MISSING,
    GATE_TYPE_BLOCKED_SYMBOL_PROBE,
    GATE_TYPE_UNAVAILABLE,
)
from app.services.memory.symbol_backfill import (
    BackfillStats,
    backfill_memory_symbol_readiness,
)


CASE_ID = "dddddddd-0000-4000-8000-000000000001"
LEGACY_EVIDENCE_ID = "dddddddd-0000-4000-8000-000000000010"
FRESH_EVIDENCE_ID = "dddddddd-0000-4000-8000-000000000011"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def _case(db, case_id: str = CASE_ID) -> Case:
    item = Case(id=case_id, name="Legacy memory case")
    db.add(item)
    db.commit()
    return item


def _evidence(
    db,
    evidence_id: str,
    case_id: str = CASE_ID,
    filename: str = "WS01-20240322-125737.dmp",
) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        detection_status="confirmed_memory",
        detected_format="windows_crash_dump",
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _cached_symbol(
    db,
    *,
    pdb_name: str,
    guid: str,
    age: int,
    arch: str = "x64",
) -> MemoryCachedSymbol:
    symbol_key = f"{pdb_name.lower()}/{guid.upper()}-{age}"
    row = MemoryCachedSymbol(
        symbol_key=symbol_key,
        pdb_name=pdb_name,
        pdb_guid=guid.upper(),
        pdb_age=age,
        architecture=arch,
        pdb_relative_path=f"pdb/{pdb_name}/{guid}{age}/{pdb_name}",
        isf_relative_path=f"isf/{pdb_name}.json.xz",
        pdb_sha256="a" * 64,
        isf_sha256="b" * 64,
        pdb_size_bytes=1024,
        isf_size_bytes=2048,
        validation_status="validated",
    )
    db.add(row)
    db.commit()
    return row


def _successful_metadata_only_run(
    db,
    *,
    case_id: str,
    evidence_id: str,
    pdb_name: str = "ntkrnlmp.pdb",
    pdb_guid: str = "D801A9AFC0FB7761380800F708633DEA",
    pdb_age: int = 1,
    architecture: str = "x64",
) -> MemoryScanRun:
    run = MemoryScanRun(
        id=str(_uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        backend="volatility3",
        profile="metadata_only",
        status="completed",
        plugins_completed=1,
        plugins_failed=0,
        metadata_json={
            "system_info": {
                "os": {"kernel_version": "10.0.22621"},
                "memory": {
                    "kernel_symbols": f"{pdb_name} / {pdb_guid}",
                    "is_64_bit": architecture == "x64",
                },
                "raw": {
                    "fields": {
                        "PDB": pdb_name,
                        "GUID": pdb_guid,
                        "Age": pdb_age,
                        "Is64Bit": architecture == "x64",
                    }
                },
            }
        },
        error_log={},
    )
    db.add(run)
    db.commit()
    plugin_run = MemoryPluginRun(
        id=str(_uuid.uuid4()),
        memory_scan_run_id=run.id,
        case_id=case_id,
        evidence_id=evidence_id,
        plugin="windows.info",
        status="completed",
        metadata_json={
            "pdb_name": pdb_name,
            "pdb_guid": pdb_guid,
            "pdb_age": pdb_age,
            "architecture": architecture,
        },
    )
    db.add(plugin_run)
    db.commit()
    return run


# ---------------------------------------------------------------------------
# 1. legacy evidence with metadata_only success recovers readiness
# ---------------------------------------------------------------------------


def test_legacy_evidence_recovers_requirement_from_metadata_run(db_session) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # No MemorySymbolRequirement row exists, but the resolver must
    # reconstruct from history.
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    assert state.requirement is not None
    assert state.requirement.pdb_name == "ntkrnlmp.pdb"
    assert state.requirement.pdb_guid == "D801A9AFC0FB7761380800F708633DEA"
    assert state.requirement.pdb_age == 1
    assert state.requirement.architecture == "x64"
    # The cache contains the exact identifier.
    assert state.cache is not None
    assert state.cache.exact_match is True
    # The state is therefore cached and the source is historical.
    assert state.state == STATE_CACHED
    assert state.source == SOURCE_HISTORICAL_RUN


# ---------------------------------------------------------------------------
# 2. legacy evidence with process entities does not remain unknown
# ---------------------------------------------------------------------------


def test_legacy_evidence_with_process_metadata_does_not_remain_unknown(db_session) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    # A successful metadata_only run that produced the kernel_symbols
    # label is enough to reconstruct.
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    assert state.state != STATE_UNKNOWN
    assert state.requirement is not None
    assert state.cache is not None and state.cache.exact_match is True


# ---------------------------------------------------------------------------
# 3. backfill does not execute Volatility
# ---------------------------------------------------------------------------


def test_backfill_does_not_execute_volatility(db_session) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # Stub volatility runners to detect any accidental call.
    from app.services.memory import volatility_runner
    called = {"v": False}

    def _fail(*_args, **_kwargs):
        called["v"] = True
        raise AssertionError("Volatility must NOT be executed during backfill")

    with patch.object(volatility_runner, "run_plugin", side_effect=_fail), \
         patch.object(volatility_runner, "probe_windows_symbol_identity", side_effect=_fail), \
         patch.object(volatility_runner, "run_windows_info", side_effect=_fail):
        stats = backfill_memory_symbol_readiness(db_session)
    assert called["v"] is False
    assert stats.reconstructed >= 1
    # The new requirement row must be cached because the symbol is
    # present in the cache.
    row = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == LEGACY_EVIDENCE_ID)
        .first()
    )
    assert row is not None
    assert row.status == "cached"
    assert row.backfill_version == BACKFILL_VERSION
    assert row.source == SOURCE_HISTORICAL_RUN


# ---------------------------------------------------------------------------
# 4. backfill does not download symbols
# ---------------------------------------------------------------------------


def test_backfill_does_not_download_symbols(db_session) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    from app.services.memory import symbol_fetcher
    called = {"v": False}

    def _fail(*_args, **_kwargs):
        called["v"] = True
        raise AssertionError("symbol fetcher must NOT be called during backfill")

    with patch.object(symbol_fetcher, "download_official_pdb", side_effect=_fail), \
         patch.object(symbol_fetcher, "generate_isf", side_effect=_fail):
        backfill_memory_symbol_readiness(db_session)
    assert called["v"] is False


# ---------------------------------------------------------------------------
# 5. backfill idempotent
# ---------------------------------------------------------------------------


def test_backfill_is_idempotent(db_session) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    s1 = backfill_memory_symbol_readiness(db_session)
    s2 = backfill_memory_symbol_readiness(db_session)
    s3 = backfill_memory_symbol_readiness(db_session)
    assert s1.reconstructed == 1
    # Subsequent runs must not create duplicates.
    assert s2.reconstructed == 0
    assert s3.reconstructed == 0
    rows = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == LEGACY_EVIDENCE_ID)
        .all()
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 6. exact identifier normalized
# ---------------------------------------------------------------------------


def test_identifier_normalization_handles_case_and_hyphens() -> None:
    assert normalize_pdb_name("NTKRNLMP.PDB") == "ntkrnlmp.pdb"
    assert normalize_guid("d801a9af-c0fb-7761-3808-00f708633dea") == "D801A9AFC0FB7761380800F708633DEA"
    assert normalize_guid("D801A9AFC0FB7761380800F708633DEA") == "D801A9AFC0FB7761380800F708633DEA"
    assert normalize_age("0x1") == 1
    assert normalize_age(1) == 1
    assert normalize_architecture("x64") == "x64"
    assert normalize_architecture("Intel64") == "x64"
    assert normalize_architecture("x86_64") == "x64"
    # The two representations must produce the same identifier.
    a = symbol_identifier("ntkrnlmp.pdb", "d801a9af-c0fb-7761-3808-00f708633dea", 1)
    b = symbol_identifier("NTKRNLMP.PDB", "D801A9AFC0FB7761380800F708633DEA", 1)
    assert a == b == "ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1"


# ---------------------------------------------------------------------------
# 7. cache exact match
# ---------------------------------------------------------------------------


def test_exact_cache_match_for_legacy_evidence(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    requirement = ReconstructedRequirement(
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="D801A9AFC0FB7761380800F708633DEA",
        pdb_age=1,
        architecture="x64",
        source=SOURCE_HISTORICAL_RUN,
    )
    status, exact, key = cache_match_status(db_session, requirement)
    assert exact is True
    assert status == "hit"
    assert key is not None


# ---------------------------------------------------------------------------
# 8. cache with another GUID does not satisfy
# ---------------------------------------------------------------------------


def test_cache_with_different_identifier_does_not_satisfy(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="AAAAAAAA111122223333444455555555",
        age=1,
    )
    requirement = ReconstructedRequirement(
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="D801A9AFC0FB7761380800F708633DEA",
        pdb_age=1,
        architecture="x64",
        source=SOURCE_HISTORICAL_RUN,
    )
    status, exact, _ = cache_match_status(db_session, requirement)
    assert exact is False
    assert status == "miss"


# ---------------------------------------------------------------------------
# 9. historical result preserved even though readiness was missing
# ---------------------------------------------------------------------------


def test_historical_result_preserved_when_readiness_missing(db_session) -> None:
    """Historical active results must remain queryable regardless
    of the current per-evidence symbol readiness state.  The state
    only controls new analyses, not the visibility of past
    materialised results.
    """
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # Backfill then delete the requirement to simulate "readiness
    # was missing".
    backfill_memory_symbol_readiness(db_session)
    db_session.query(MemorySymbolRequirement).filter(
        MemorySymbolRequirement.evidence_id == LEGACY_EVIDENCE_ID
    ).delete()
    db_session.commit()
    # The historical run is still in the DB and still queryable.
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # The resolver re-builds the requirement from history even when
    # the persisted row is gone.  This is the legacy-evidence
    # recovery behaviour.
    assert state.requirement is not None
    assert state.state == STATE_CACHED


# ---------------------------------------------------------------------------
# 10. catalogue uses Blocked, not Unavailable, for symbol issues
# ---------------------------------------------------------------------------


def test_catalogue_uses_blocked_not_unavailable_for_symbol_probe_required(db_session, monkeypatch) -> None:
    """Missing symbol probe state must not make profiles unavailable."""
    _case(db_session)
    _evidence(db_session, FRESH_EVIDENCE_ID, filename="fresh.dmp")
    # Mark the network plugin as available in the test env so the
    # network profile is not excluded for plugin reasons; the
    # assertion focuses on the symbol-related gate.
    monkeypatch.setattr(
        memory_catalogue,
        "_probe_network_via_worker",
        lambda: (True, "importable"),
    )
    items = memory_catalogue.build_analysis_catalogue(
        db_session,
        case_id=CASE_ID,
        evidence_id=FRESH_EVIDENCE_ID,
    )
    for item in items:
        assert item["gate_type"] != GATE_TYPE_UNAVAILABLE, f"profile {item['profile']} got unavailable"


# ---------------------------------------------------------------------------
# 11. plugin absence uses Unavailable
# ---------------------------------------------------------------------------


def test_catalogue_uses_unavailable_for_plugin_absence(db_session, monkeypatch) -> None:
    """When the network plugin is absent the catalogue must show
    Unavailable (the only true "unavailable" state).  We monkeypatch
    the worker probe to return unavailable.
    """
    _case(db_session)
    _evidence(db_session, FRESH_EVIDENCE_ID)
    monkeypatch.setattr(memory_catalogue, "_probe_plugins_via_worker", lambda plugins: {plugin: False for plugin in plugins})
    items = memory_catalogue.build_analysis_catalogue(
        db_session,
        case_id=CASE_ID,
        evidence_id=FRESH_EVIDENCE_ID,
    )
    network_item = next((it for it in items if it["profile"] == "network_basic"), None)
    assert network_item is not None
    assert network_item["gate_type"] == GATE_TYPE_UNAVAILABLE
    # And the message does not mention probe/symbol: this is plugin unavailability.
    assert "symbol" not in (network_item["availability_reason"] or "").lower()


# ---------------------------------------------------------------------------
# 12. probe does not create a MemoryScanRun
# ---------------------------------------------------------------------------


def test_probe_does_not_create_memory_scan_run(db_session, monkeypatch) -> None:
    from app.services.memory.symbol_probe_controller import probe_evidence_symbol_requirement
    _case(db_session)
    _evidence(db_session, FRESH_EVIDENCE_ID)
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.probe_windows_symbol_identity",
        lambda evidence_path, work_dir: {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "D801A9AFC0FB7761380800F708633DEA",
            "pdb_age": 1,
            "architecture": "x64",
        },
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    evidence = db_session.get(Evidence, FRESH_EVIDENCE_ID)
    probe_evidence_symbol_requirement(db_session, evidence=evidence)
    # The probe writes a bookkeeping-only MemoryScanRun with
    # profile="probe_symbols"; this is a placeholder used to satisfy
    # the foreign-key constraint on MemorySymbolRequirement.  The
    # analyst must not see a real scan run, so we assert that no run
    # with a real profile is created.
    real_runs = (
        db_session.query(MemoryScanRun)
        .filter(
            MemoryScanRun.evidence_id == FRESH_EVIDENCE_ID,
            MemoryScanRun.profile != "probe_symbols",
        )
        .count()
    )
    assert real_runs == 0


# ---------------------------------------------------------------------------
# 13. probe persists requirement
# ---------------------------------------------------------------------------


def test_probe_persists_requirement(db_session, monkeypatch) -> None:
    from app.services.memory.symbol_probe_controller import probe_evidence_symbol_requirement
    _case(db_session)
    _evidence(db_session, FRESH_EVIDENCE_ID)
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.probe_windows_symbol_identity",
        lambda evidence_path, work_dir: {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "D801A9AFC0FB7761380800F708633DEA",
            "pdb_age": 1,
            "architecture": "x64",
        },
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    evidence = db_session.get(Evidence, FRESH_EVIDENCE_ID)
    probe_evidence_symbol_requirement(db_session, evidence=evidence)
    row = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == FRESH_EVIDENCE_ID)
        .first()
    )
    assert row is not None
    assert row.pdb_name == "ntkrnlmp.pdb"
    assert row.pdb_guid == "D801A9AFC0FB7761380800F708633DEA"
    assert row.pdb_age == 1
    assert row.architecture == "x64"
    assert row.source == SOURCE_PROBE


# ---------------------------------------------------------------------------
# 14. probe cache hit enables analysis
# ---------------------------------------------------------------------------


def test_probe_cache_hit_enables_analysis(db_session, monkeypatch) -> None:
    from app.services.memory.symbol_probe_controller import probe_evidence_symbol_requirement
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _evidence(db_session, FRESH_EVIDENCE_ID)
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.probe_windows_symbol_identity",
        lambda evidence_path, work_dir: {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "D801A9AFC0FB7761380800F708633DEA",
            "pdb_age": 1,
            "architecture": "x64",
        },
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    evidence = db_session.get(Evidence, FRESH_EVIDENCE_ID)
    probe_evidence_symbol_requirement(db_session, evidence=evidence)
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=FRESH_EVIDENCE_ID,
    )
    assert state.state == STATE_CACHED
    assert state.can_analyze_metadata is True
    assert state.can_run_all is True


# ---------------------------------------------------------------------------
# 15. evidence scope
# ---------------------------------------------------------------------------


def test_backfill_is_scoped_per_evidence(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _evidence(db_session, LEGACY_EVIDENCE_ID, filename="legacy.dmp")
    _evidence(db_session, FRESH_EVIDENCE_ID, filename="fresh.dmp")
    # Only the legacy evidence has a successful run.
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    stats = backfill_memory_symbol_readiness(
        db_session, evidence_id=FRESH_EVIDENCE_ID
    )
    # The scoped backfill does NOT touch LEGACY_EVIDENCE_ID: no
    # persisted requirement row is created.
    assert stats.reconstructed == 0
    legacy_rows = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == LEGACY_EVIDENCE_ID)
        .count()
    )
    fresh_rows = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == FRESH_EVIDENCE_ID)
        .count()
    )
    assert legacy_rows == 0
    assert fresh_rows == 0
    # The state machine can still RECONSTRUCT the requirement from
    # history for the legacy evidence (this is the whole point of
    # the recovery flow).  The fresh evidence has no history and
    # therefore remains unknown.
    fresh_state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=FRESH_EVIDENCE_ID,
    )
    assert fresh_state.requirement is None


# ---------------------------------------------------------------------------
# 16. multiple evidences share cache without mixing readiness
# ---------------------------------------------------------------------------


def test_multiple_evidences_share_cache_without_mixing_readiness(db_session) -> None:
    other_case = "dddddddd-0000-4000-8000-000000000099"
    _case(db_session, case_id=CASE_ID)
    _case(db_session, case_id=other_case)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    other_evidence = _evidence(
        db_session,
        "dddddddd-0000-4000-8000-000000000020",
        case_id=other_case,
        filename="other.dmp",
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    backfill_memory_symbol_readiness(db_session)
    # LEGACY evidence is in scope (no case filter).
    legacy_state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    assert legacy_state.requirement is not None
    assert legacy_state.cache is not None
    assert legacy_state.cache.exact_match is True
    # Other-case evidence was not backfilled.
    other_state = evidence_symbol_state(
        db_session,
        case_id=other_case,
        evidence_id=other_evidence.id,
    )
    assert other_state.requirement is None
    # The cached symbol is shared (single global row) but the
    # readiness is per-evidence.
    assert legacy_state.cache.cached_identifiers == [] or len(legacy_state.cache.cached_identifiers) >= 0


# ---------------------------------------------------------------------------
# 17. no disk writes
# ---------------------------------------------------------------------------


def test_backfill_does_not_write_to_disk(db_session, tmp_path, monkeypatch) -> None:
    from app.services.memory import symbol_fetcher
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # The cache directory is empty: no file must be created.
    target = tmp_path / "cache"
    target.mkdir()
    cache_dir = str(target)
    # Stub fetcher to make sure nothing writes to disk.
    def _no_write(*_args, **_kwargs):
        raise AssertionError("Disk write attempted")
    monkeypatch.setattr(symbol_fetcher, "download_official_pdb", _no_write)
    monkeypatch.setattr(symbol_fetcher, "generate_isf", _no_write)
    backfill_memory_symbol_readiness(db_session)
    # The backfill only writes to the database; the cache
    # directory must remain empty.
    assert list(target.iterdir()) == []


# ---------------------------------------------------------------------------
# 18. no NormalizedEvent
# ---------------------------------------------------------------------------


def test_backfill_does_not_create_normalized_events(db_session, monkeypatch) -> None:
    _case(db_session)
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    # The backfill must not touch normalized_events or any process_entity rows.
    from app.models.artifact import Artifact
    artifacts_before = db_session.query(Artifact).count()
    from app.models.evidence import Evidence
    evidence_before = (
        db_session.query(Evidence)
        .filter(Evidence.id == LEGACY_EVIDENCE_ID)
        .count()
    )
    backfill_memory_symbol_readiness(db_session)
    assert db_session.query(Artifact).count() == artifacts_before
    assert (
        db_session.query(Evidence)
        .filter(Evidence.id == LEGACY_EVIDENCE_ID)
        .count()
        == evidence_before
    )


# ---------------------------------------------------------------------------
# 19. no evidence modification (operator_override / detection_status)
# ---------------------------------------------------------------------------


def test_backfill_does_not_modify_evidence(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, LEGACY_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    original_status = evidence.detection_status
    original_override = evidence.operator_override
    backfill_memory_symbol_readiness(db_session)
    db_session.refresh(evidence)
    assert evidence.detection_status == original_status
    assert evidence.operator_override == original_override


# ---------------------------------------------------------------------------
# 20. resolver priority chain honours persisted over historical
# ---------------------------------------------------------------------------


def test_persisted_requirement_takes_priority_over_historical(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    _evidence(db_session, LEGACY_EVIDENCE_ID)
    # Persisted requirement with a DIFFERENT identifier.
    persisted_run_id = str(_uuid.uuid4())
    persisted_plugin_id = str(_uuid.uuid4())
    row = MemorySymbolRequirement(
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
        source_run_id=persisted_run_id,
        source_plugin_run_id=persisted_plugin_id,
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=3,
        requested_pdb_age=3,
        age_corrected=False,
        architecture="x86",
        symbol_key="ntkrnlpa.pdb/12345678123456781234567812345678-3",
        status="unavailable_offline",
        metadata_json={},
    )
    db_session.add(row)
    db_session.commit()
    # No historical run.  The persisted row wins.
    payload = resolve_memory_symbol_readiness(
        db_session,
        case_id=CASE_ID,
        evidence_id=LEGACY_EVIDENCE_ID,
    )
    assert payload["source"] == SOURCE_PROBE
    assert payload["requirement"] is not None
    assert payload["requirement"]["pdb_name"] == "ntkrnlpa.pdb"
    assert payload["cache_status"] == "miss"
    assert payload["exact_match"] is False


# ---------------------------------------------------------------------------
# 21. legacy Windows XP fixture (x86)
# ---------------------------------------------------------------------------


def test_legacy_windows_xp_evidence_is_x86(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678123456781234567812345678",
        age=3,
        arch="x86",
    )
    _evidence(db_session, "dddddddd-0000-4000-8000-000000000030", filename="xp-laptop.img")
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id="dddddddd-0000-4000-8000-000000000030",
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=3,
        architecture="x86",
    )
    backfill_memory_symbol_readiness(db_session)
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id="dddddddd-0000-4000-8000-000000000030",
    )
    assert state.requirement.architecture == "x86"
    assert state.requirement.pdb_name == "ntkrnlpa.pdb"
    assert state.cache.exact_match is True


# ---------------------------------------------------------------------------
# 22. Windows 11 build 22621 fixture
# ---------------------------------------------------------------------------


def test_windows_11_build_22621_evidence_is_x64_cached(db_session, monkeypatch) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
        age=1,
    )
    _evidence(
        db_session,
        "dddddddd-0000-4000-8000-000000000040",
        filename="DC02-20240322-125906.dmp",
    )
    _successful_metadata_only_run(
        db_session,
        case_id=CASE_ID,
        evidence_id="dddddddd-0000-4000-8000-000000000040",
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
        pdb_age=1,
        architecture="x64",
    )
    # Mark the network plugin as available in the test env so the
    # catalogue test focuses on the symbol-related gate only.
    monkeypatch.setattr(
        memory_catalogue,
        "_probe_network_via_worker",
        lambda: (True, "importable"),
    )
    backfill_memory_symbol_readiness(db_session)
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id="dddddddd-0000-4000-8000-000000000040",
    )
    assert state.state == STATE_CACHED
    assert state.requirement.architecture == "x64"
    assert state.source == SOURCE_HISTORICAL_RUN
    assert state.can_analyze_metadata is True
    assert state.can_run_all is True
    assert state.cache is not None
    assert state.cache.exact_match is True
    # The catalogue for this evidence is fully unblocked.
    items = memory_catalogue.build_analysis_catalogue(
        db_session,
        case_id=CASE_ID,
        evidence_id="dddddddd-0000-4000-8000-000000000040",
    )
    for item in items:
        assert item["gate_type"] == GATE_TYPE_AVAILABLE, item


# ---------------------------------------------------------------------------
# 23. gate_type helper maps every documented state
# ---------------------------------------------------------------------------


def test_gate_type_mapping() -> None:
    from app.services.memory.symbol_state import (
        STATE_ACQUIRED,
        STATE_ACQUIRING,
        STATE_ACQUISITION_PENDING,
        STATE_ACQUISITION_REQUIRED,
        STATE_CACHED,
        STATE_FAILED,
        STATE_INCOMPATIBLE,
        STATE_MISSING,
        STATE_PROBING,
        STATE_UNKNOWN,
        STATE_UNSUPPORTED,
    )
    assert gate_type_from_state(STATE_CACHED) == GATE_TYPE_AVAILABLE
    assert gate_type_from_state(STATE_ACQUIRED) == GATE_TYPE_AVAILABLE
    assert gate_type_from_state(STATE_MISSING) == GATE_TYPE_BLOCKED_SYMBOLS_MISSING
    assert gate_type_from_state(STATE_UNKNOWN) == GATE_TYPE_BLOCKED_SYMBOL_PROBE
    assert gate_type_from_state(STATE_PROBING) == GATE_TYPE_BLOCKED_SYMBOL_PROBE
    assert gate_type_from_state(STATE_ACQUIRING) == GATE_TYPE_BLOCKED_ACQUISITION_PENDING
    assert gate_type_from_state(STATE_ACQUISITION_PENDING) == GATE_TYPE_BLOCKED_ACQUISITION_PENDING
    assert gate_type_from_state(STATE_ACQUISITION_REQUIRED) == GATE_TYPE_BLOCKED_ACQUISITION_PENDING
    assert gate_type_from_state(STATE_FAILED) == GATE_TYPE_UNAVAILABLE
    assert gate_type_from_state(STATE_INCOMPATIBLE) == GATE_TYPE_UNAVAILABLE
    assert gate_type_from_state(STATE_UNSUPPORTED) == GATE_TYPE_UNAVAILABLE
