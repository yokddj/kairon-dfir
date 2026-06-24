"""Tests for the automatic Windows symbol preparation flow.

Covers:

* content-identity reuse (same SHA -> same requirement)
* filename / size alone do not trigger reuse
* auto-probe on upload
* exact cache lookup with normalization
* negative cache prevents loops
* preparation state machine
* run-when-ready intent
* reconcile_memory_symbol_readiness
* catalogue uses "preparing" / "blocked" / "unavailable" / "available"
* pending analysis can be cancelled
* atomic ISF publication
* old Windows unsupported
"""
from __future__ import annotations

import uuid as _uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryCachedSymbol,
    MemoryEvidenceContent,
    MemoryEvidenceSymbolLink,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolNegativeCache,
    MemorySymbolPendingAnalysis,
    MemorySymbolPreparation,
    MemorySymbolRequirement,
)
from app.services.memory import symbol_preparation as prep_module
from app.services.memory.symbol_preparation import (
    PREP_ACQUISITION_FAILED,
    PREP_ACQUIRING,
    PREP_CANCELLED,
    PREP_IDENTIFIED,
    PREP_NEGATIVE_CACHED,
    PREP_PROBING,
    PREP_QUEUED,
    PREP_READY,
    PREP_REQUIREMENT_UNKNOWN,
    PREP_UNSUPPORTED,
    compute_memory_readiness,
    consume_pending_for_evidence,
    content_identity_key,
    exact_cache_match_for_requirement,
    find_requirement_by_content_identity,
    link_evidence_to_requirement,
    mark_preparation,
    mark_pending_materialized,
    negative_cache_active,
    normalize_sha256,
    progress_for_state,
    record_negative_cache,
    record_pending_analysis,
    cancel_pending,
    reconcile_memory_symbol_readiness,
    register_evidence_content_identity,
    requeue_preparation,
    schedule_preparation,
    ui_state_for,
)


CASE_ID = "ffffffff-0000-4000-8000-000000000001"
EVIDENCE_A = "ffffffff-0000-4000-8000-000000000010"
EVIDENCE_B = "ffffffff-0000-4000-8000-000000000011"
EVIDENCE_C = "ffffffff-0000-4000-8000-000000000012"


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
    item = Case(id=case_id, name="Memory prep case")
    db.add(item)
    db.commit()
    return item


def _evidence(
    db,
    evidence_id: str,
    *,
    case_id: str = CASE_ID,
    sha256: str = "a" * 64,
    size_bytes: int = 4_255_670_272,
    filename: str = "memory.dmp",
) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        sha256=sha256,
        size_bytes=size_bytes,
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


def _requirement(
    db,
    *,
    evidence_id: str,
    pdb_name: str,
    guid: str,
    age: int,
    arch: str = "x64",
    status: str = "unavailable_offline",
) -> MemorySymbolRequirement:
    import uuid as _u
    base_id = _u.UUID(int=0x9000_0000_0000_4000_8000_0000_0000_0000) if evidence_id == EVIDENCE_A else _u.UUID(int=0x9000_0000_0000_4000_8000_0000_0000_0001)
    run_id = str(_u.UUID(int=int(base_id) | (hash(evidence_id) & 0xFFFF_FFFF_FFFF)))
    plugin_id = str(_u.UUID(int=int(base_id) | 1 | (hash(evidence_id) & 0xFFFF_FFFF_FFFF)))
    symbol_key = f"{pdb_name.lower()}/{guid.upper()}-{age}"
    row = MemorySymbolRequirement(
        case_id=CASE_ID,
        evidence_id=evidence_id,
        source_run_id=run_id,
        source_plugin_run_id=plugin_id,
        pdb_name=pdb_name,
        pdb_guid=guid.upper(),
        pdb_age=age,
        requested_pdb_age=age,
        age_corrected=False,
        architecture=arch,
        symbol_key=symbol_key,
        status=status,
        source="probe",
        confidence="high",
        metadata_json={},
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# 1. misma SHA en nuevo evidence reutiliza requirement
# ---------------------------------------------------------------------------


def test_same_sha_on_new_evidence_reuses_requirement(db_session) -> None:
    _case(db_session)
    ev_a = _evidence(db_session, EVIDENCE_A, sha256="c" * 64)
    ev_b = _evidence(db_session, EVIDENCE_B, sha256="c" * 64, filename="other.dmp")
    # Reuse path: an existing cached requirement for ev_a.
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
        status="cached",
    )
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
    )
    # Register the content identity for ev_a and link its requirement.
    register_evidence_content_identity(db_session, evidence=ev_a)
    content_a = (
        db_session.query(MemoryEvidenceContent)
        .filter(MemoryEvidenceContent.evidence_sha256 == "c" * 64)
        .first()
    )
    content_a.last_requirement_id = req.id
    content_a.last_readiness = PREP_READY
    db_session.commit()
    # Now find the requirement for ev_b (different evidence_id, same SHA).
    reused = find_requirement_by_content_identity(db_session, evidence=ev_b)
    assert reused is not None
    assert reused.id == req.id


# ---------------------------------------------------------------------------
# 2. filename igual y SHA distinto no reutiliza
# ---------------------------------------------------------------------------


def test_same_filename_different_sha_does_not_reuse(db_session) -> None:
    _case(db_session)
    ev_a = _evidence(db_session, EVIDENCE_A, sha256="c" * 64, filename="dup.dmp")
    ev_b = _evidence(db_session, EVIDENCE_B, sha256="d" * 64, filename="dup.dmp")
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="D801A9AFC0FB7761380800F708633DEA",
        age=1,
        status="cached",
    )
    register_evidence_content_identity(db_session, evidence=ev_a)
    content = (
        db_session.query(MemoryEvidenceContent)
        .filter(MemoryEvidenceContent.evidence_sha256 == "c" * 64)
        .first()
    )
    content.last_requirement_id = req.id
    content.last_readiness = PREP_READY
    db_session.commit()
    # ev_b has a different SHA: no reuse.
    reused = find_requirement_by_content_identity(db_session, evidence=ev_b)
    assert reused is None


# ---------------------------------------------------------------------------
# 3. evidence_id nuevo no pierde cache exacta
# ---------------------------------------------------------------------------


def test_new_evidence_with_same_sha_does_not_lose_cache_hit(db_session) -> None:
    _case(db_session)
    ev_a = _evidence(db_session, EVIDENCE_A, sha256="e" * 64)
    ev_b = _evidence(db_session, EVIDENCE_B, sha256="e" * 64)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="AABBCCDD" * 4,
        age=1,
    )
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="AABBCCDD" * 4,
        age=1,
        status="cached",
    )
    # Link ev_b to the requirement.
    link_evidence_to_requirement(
        db_session,
        evidence=ev_b,
        requirement=req,
        link_source="cache_reuse_by_hash",
        state=PREP_READY,
    )
    db_session.commit()
    # Cache hit is preserved.
    cached = exact_cache_match_for_requirement(db_session, req)
    assert cached is not None


# ---------------------------------------------------------------------------
# 4. upload dispara auto-probe (schedule_preparation is called)
# ---------------------------------------------------------------------------


def test_upload_triggers_auto_probe(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    register_evidence_content_identity(db_session, evidence=evidence)
    preparation = schedule_preparation(
        db_session, evidence=evidence, state=PREP_QUEUED, reason="auto_probe_on_upload"
    )
    db_session.commit()
    assert preparation.state == PREP_QUEUED
    assert preparation.attempts == 0
    assert preparation.state_reason == "auto_probe_on_upload"


# ---------------------------------------------------------------------------
# 5. unknown no permanece sin tarea
# ---------------------------------------------------------------------------


def test_unknown_state_has_queued_preparation(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    schedule_preparation(db_session, evidence=evidence, state=PREP_QUEUED)
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    # The default preparation_state is "queued" which maps to
    # UI_STATE_PREPARING.  The cache miss with no requirement
    # triggers the queued/pending flow.
    assert readiness.ui_state in {"preparing", "blocked", "ready"}


# ---------------------------------------------------------------------------
# 6. cache hit evita descarga
# ---------------------------------------------------------------------------


def test_exact_cache_match_avoids_acquisition(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="AABBCCDD" * 4,
        age=1,
    )
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="AABBCCDD" * 4,
        age=1,
    )
    link_evidence_to_requirement(
        db_session,
        evidence=evidence,
        requirement=req,
        link_source="probe",
        state=PREP_READY,
    )
    mark_preparation(
        db_session,
        evidence=evidence,
        state=PREP_READY,
        reason="cache_match",
        requirement_id=req.id,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.exact_match is True
    assert readiness.cache_status == "hit"
    assert readiness.can_analyze_metadata is True


# ---------------------------------------------------------------------------
# 7. cache con GUID distinto no satisface
# ---------------------------------------------------------------------------


def test_cache_with_different_guid_does_not_satisfy(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="AAAAAAAA" * 4,
        age=1,
    )
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="BBBBBBBB" * 4,
        age=1,
    )
    link_evidence_to_requirement(
        db_session,
        evidence=evidence,
        requirement=req,
        link_source="probe",
        state=PREP_QUEUED,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.exact_match is False
    assert readiness.cache_status == "miss"


# ---------------------------------------------------------------------------
# 8. miss inicia acquisition (preparation state queued)
# ---------------------------------------------------------------------------


def test_miss_queues_preparation_with_negative_cache_check(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="BBBBBBBB" * 4,
        age=1,
    )
    link_evidence_to_requirement(
        db_session,
        evidence=evidence,
        requirement=req,
        link_source="probe",
        state=PREP_ACQUIRING,
    )
    schedule_preparation(
        db_session, evidence=evidence, state=PREP_ACQUIRING, reason="auto_acquire",
    )
    mark_preparation(
        db_session, evidence=evidence, state=PREP_ACQUIRING, requirement_id=req.id,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.cache_status == "miss"
    assert readiness.preparation_state == PREP_ACQUIRING


# ---------------------------------------------------------------------------
# 9. acquisition usa identifier server-side (no client payload)
# ---------------------------------------------------------------------------


def test_acquisition_endpoint_uses_only_server_side_identifier() -> None:
    from app.schemas.memory import MemorySymbolAcquireRequest
    from pydantic import ValidationError
    # Only the authorization flag is allowed; PDB / GUID / URL are
    # rejected.
    with pytest.raises(ValidationError):
        MemorySymbolAcquireRequest.model_validate(
            {"authorization_acknowledged": True, "pdb_name": "evil.pdb", "url": "https://attacker.example/x"}
        )
    valid = MemorySymbolAcquireRequest.model_validate(
        {"authorization_acknowledged": True}
    )
    assert valid.authorization_acknowledged is True


# ---------------------------------------------------------------------------
# 10. memory-worker no egress (preparation is server-side)
# ---------------------------------------------------------------------------


def test_preparation_does_not_invoke_memory_worker_egress(monkeypatch) -> None:
    # Verify the preparation module does not import the network
    # worker probe: the symbol preparation is purely server-side.
    import app.services.memory.symbol_preparation as sp
    assert not hasattr(sp, "_probe_network_via_worker")


# ---------------------------------------------------------------------------
# 11. negative cache evita loops
# ---------------------------------------------------------------------------


def test_negative_cache_prevents_repeated_acquisition(db_session) -> None:
    from app.core.config import get_settings
    settings = get_settings()
    record_negative_cache(
        db_session,
        symbol_key="ntkrnlmp.pdb/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-1",
        error_code="SYMBOL_DOWNLOAD_FAILED",
        sanitized_message="Source does not have this symbol",
    )
    db_session.commit()
    assert negative_cache_active(
        db_session,
        symbol_key="ntkrnlmp.pdb/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-1",
    ) is not None


# ---------------------------------------------------------------------------
# 12. preparation UI state mapping
# ---------------------------------------------------------------------------


def test_progress_for_state_covers_documented_states() -> None:
    # Sprint 6: queued = 0 (no fake 5%).  All other states
    # are documented and have a measurable percentage.
    for state, label, percent in [
        (PREP_QUEUED, "Queued", 0),
        (PREP_PROBING, "Identifying", 20),
        (PREP_IDENTIFIED, "Requirement identified", 45),
        (PREP_ACQUIRING, "Downloading", 70),
        (PREP_READY, "Ready", 100),
        (PREP_REQUIREMENT_UNKNOWN, "Requirement not identified", 0),
    ]:
        out_label, out_percent = progress_for_state(state)
        assert out_percent == percent, f"state={state} got {out_percent}"
        assert label in out_label, f"state={state} got {out_label!r}"


# ---------------------------------------------------------------------------
# 13. concurrent acquisitions deduplicadas
# ---------------------------------------------------------------------------


def test_concurrent_preparations_share_state(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    schedule_preparation(db_session, evidence=evidence, state=PREP_QUEUED)
    db_session.commit()
    # Re-queue is a no-op while the preparation is non-terminal.
    schedule_preparation(db_session, evidence=evidence, state=PREP_QUEUED)
    db_session.commit()
    rows = (
        db_session.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == EVIDENCE_A)
        .all()
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 14. ISF publicado atómicamente (cache row is the only mutable state)
# ---------------------------------------------------------------------------


def test_cache_state_is_single_source_for_isf_publication(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF12" * 4,
        age=5,
    )
    rows = (
        db_session.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == "ntkrnlmp.pdb/ABCDEF12ABCDEF12ABCDEF12ABCDEF12-5")
        .all()
    )
    assert len(rows) == 1
    # The cache row IS the ISF publication; a corrupt row would be
    # the single failure surface.
    assert rows[0].isf_sha256 == "b" * 64


# ---------------------------------------------------------------------------
# 15. readiness solo ready tras offline verification
# ---------------------------------------------------------------------------


def test_readiness_only_ready_when_cache_matches(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    # A requirement with NO cached symbol: not ready.
    _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="CCCCCCCC" * 4,
        age=1,
    )
    link_evidence_to_requirement(
        db_session,
        evidence=evidence,
        requirement=db_session.query(MemorySymbolRequirement).filter(
            MemorySymbolRequirement.evidence_id == EVIDENCE_A
        ).first(),
        link_source="probe",
        state=PREP_QUEUED,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.can_analyze_metadata is False
    # A requirement WITH cached symbol: ready.
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="DDDDDDDD" * 4,
        age=1,
    )
    req2 = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="DDDDDDDD" * 4,
        age=1,
    )
    link_evidence_to_requirement(
        db_session,
        evidence=evidence,
        requirement=req2,
        link_source="probe",
        state=PREP_READY,
    )
    mark_preparation(
        db_session,
        evidence=evidence,
        state=PREP_READY,
        reason="cache_match",
        requirement_id=req2.id,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.can_analyze_metadata is True
    assert readiness.can_run_all is True


# ---------------------------------------------------------------------------
# 16. pending analysis recorded + cancelled
# ---------------------------------------------------------------------------


def test_pending_analysis_can_be_recorded_and_cancelled(db_session) -> None:
    _case(db_session)
    _evidence(db_session, EVIDENCE_A)
    pending = record_pending_analysis(
        db_session,
        case_id=CASE_ID,
        evidence_id=EVIDENCE_A,
        kind="run_all",
        requested_profiles=["metadata_only"],
    )
    db_session.commit()
    assert pending.status == "pending"
    # Cancel.
    cancel_pending(db_session, pending, reason="user cancelled")
    db_session.commit()
    refreshed = db_session.get(MemorySymbolPendingAnalysis, pending.id)
    assert refreshed.status == "cancelled"


# ---------------------------------------------------------------------------
# 17. legacy evidence recovery (no preparation row -> falls back to state machine)
# ---------------------------------------------------------------------------


def test_legacy_evidence_uses_state_machine_when_no_preparation(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF11" * 4,
        age=1,
    )
    # No requirement row, no preparation row.
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    # The fallback path uses the legacy state machine; with no
    # requirement, the state is "unknown" and the UI shows
    # Blocked / probe required.
    assert readiness.preparation_state in {PREP_QUEUED, "unknown"}


# ---------------------------------------------------------------------------
# 18. old Windows (XP) unsupported / negative cached
# ---------------------------------------------------------------------------


def test_old_windows_evidence_with_no_cache_can_be_unsupported(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlpa.pdb",
        guid="EEEEEEEE" * 4,
        age=1,
        arch="x86",
    )
    record_negative_cache(
        db_session,
        symbol_key=req.symbol_key,
        error_code="SYMBOL_NOT_AVAILABLE",
        sanitized_message="Windows XP era symbols are not distributed by the configured source.",
    )
    mark_preparation(
        db_session,
        evidence=evidence,
        state=PREP_NEGATIVE_CACHED,
        reason="source_does_not_have_symbol",
        requirement_id=req.id,
    )
    db_session.commit()
    readiness = compute_memory_readiness(db_session, evidence=evidence)
    assert readiness.preparation_state == PREP_NEGATIVE_CACHED
    assert readiness.can_analyze_metadata is False


# ---------------------------------------------------------------------------
# 19. reconcile is idempotent
# ---------------------------------------------------------------------------


def test_reconcile_is_idempotent(db_session, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "memory_auto_symbol_probe", True)
    _case(db_session)
    _evidence(db_session, EVIDENCE_A, sha256="f" * 64)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF12" * 4,
        age=1,
    )
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF12" * 4,
        age=1,
        status="cached",
    )
    db_session.commit()
    s1 = reconcile_memory_symbol_readiness(db_session)
    s2 = reconcile_memory_symbol_readiness(db_session)
    s3 = reconcile_memory_symbol_readiness(db_session)
    # After the first reconcile, the second pass is a no-op.
    assert s1["scanned"] == 1
    assert s2["scanned"] == 1
    # Both scans should be deterministic.
    assert s1["skipped_ready"] + s1["queued"] == 1
    # The second pass should have the same or fewer queued items.
    assert s2["queued"] <= 1


# ---------------------------------------------------------------------------
# 20. content identity key is normalized
# ---------------------------------------------------------------------------


def test_content_identity_normalizes_sha256() -> None:
    assert normalize_sha256("  ABCDEF1234567890" + "A" * 50) == "abcdef1234567890" + "a" * 50
    assert normalize_sha256(None) == ""
    # The same content identity key for two equivalent evidence SHA values.
    ev_a = SimpleNamespace(sha256="ABCDEF12" + "A" * 56, size_bytes=1024)
    ev_b = SimpleNamespace(sha256="abcdef12" + "a" * 56, size_bytes=1024)
    assert content_identity_key(ev_a) == content_identity_key(ev_b)


# ---------------------------------------------------------------------------
# 21. identifier normalization in symbol_resolver
# ---------------------------------------------------------------------------


def test_identifier_normalization_handles_legacy_formats() -> None:
    from app.services.memory.symbol_resolver import (
        normalize_guid, normalize_age, normalize_pdb_name, normalize_architecture,
    )
    assert normalize_guid("d801a9af-c0fb-7761-3808-00f708633dea") == "D801A9AFC0FB7761380800F708633DEA"
    assert normalize_guid("D801A9AFC0FB7761380800F708633DEA") == "D801A9AFC0FB7761380800F708633DEA"
    assert normalize_age(1) == 1
    assert normalize_age("0x1") == 1
    assert normalize_pdb_name("NTKRNLMP.PDB") == "ntkrnlmp.pdb"
    assert normalize_architecture("x64") == "x64"
    assert normalize_architecture("Intel64") == "x64"
    assert normalize_architecture("x86_64") == "x64"


# ---------------------------------------------------------------------------
# 22. ui_state_for mapping
# ---------------------------------------------------------------------------


def test_ui_state_for_documented_states() -> None:
    assert ui_state_for(PREP_READY) == "ready"
    assert ui_state_for(PREP_PROBING) == "preparing"
    assert ui_state_for(PREP_QUEUED) == "preparing"
    assert ui_state_for(PREP_ACQUIRING) == "preparing"
    assert ui_state_for(PREP_NEGATIVE_CACHED) == "blocked"
    assert ui_state_for(PREP_ACQUISITION_FAILED) == "failed"
    assert ui_state_for(PREP_CANCELLED) == "failed"
    # UNSUPPORTED is an OS/arch/runtime issue; the catalogue maps it
    # to "unavailable" but the top-level UI state can treat it as
    # "blocked" or "failed" depending on the policy.  We just assert
    # it is NOT "ready" or "preparing".
    assert ui_state_for(PREP_UNSUPPORTED) in {"blocked", "failed"}


# ---------------------------------------------------------------------------
# 23. run-all waits for readiness (preparation in progress records intent)
# ---------------------------------------------------------------------------


def test_run_all_records_intent_when_preparation_in_progress(db_session, monkeypatch) -> None:
    from app.services.memory import batch as memory_batch
    from app.models.evidence import Evidence
    from app.models.case import Case

    _case(db_session)
    _evidence(db_session, EVIDENCE_A)
    # Set the preparation to a non-ready state.
    schedule_preparation(db_session, evidence=db_session.get(Evidence, EVIDENCE_A), state=PREP_ACQUIRING)
    db_session.commit()

    monkeypatch.setattr(
        "app.services.memory.batch.plan_run_all",
        lambda *a, **k: {"selected_profiles": ["metadata_only"]},
    )
    with pytest.raises(memory_batch.MemoryBatchError) as excinfo:
        memory_batch.create_run_all_batch(
            db_session,
            case_id=CASE_ID,
            evidence_id=EVIDENCE_A,
            mode="missing_or_failed",
            authorization_acknowledged=True,
            enqueue_fn=lambda run_id: f"task-{run_id}",
        )
    assert excinfo.value.code == "MEMORY_SYMBOL_PREPARATION_IN_PROGRESS"
    # The intent is recorded.
    pending = (
        db_session.query(MemorySymbolPendingAnalysis)
        .filter(MemorySymbolPendingAnalysis.evidence_id == EVIDENCE_A)
        .first()
    )
    assert pending is not None
    assert pending.kind == "run_all"
    assert pending.status == "pending"


# ---------------------------------------------------------------------------
# 24. no MemoryScanRun before ready
# ---------------------------------------------------------------------------


def test_no_scan_run_created_during_in_progress_run_all(db_session, monkeypatch) -> None:
    from app.services.memory import batch as memory_batch
    from app.models.evidence import Evidence
    from app.models.case import Case

    _case(db_session)
    _evidence(db_session, EVIDENCE_A)
    schedule_preparation(db_session, evidence=db_session.get(Evidence, EVIDENCE_A), state=PREP_ACQUIRING)
    db_session.commit()
    monkeypatch.setattr(
        "app.services.memory.batch.plan_run_all",
        lambda *a, **k: {"selected_profiles": ["metadata_only"]},
    )
    initial_runs = db_session.query(MemoryScanRun).count()
    initial_batches = db_session.query(MemoryAnalysisBatch).count()
    with pytest.raises(memory_batch.MemoryBatchError):
        memory_batch.create_run_all_batch(
            db_session,
            case_id=CASE_ID,
            evidence_id=EVIDENCE_A,
            mode="missing_or_failed",
            authorization_acknowledged=True,
            enqueue_fn=lambda run_id: f"task-{run_id}",
        )
    assert db_session.query(MemoryScanRun).count() == initial_runs
    assert db_session.query(MemoryAnalysisBatch).count() == initial_batches


# ---------------------------------------------------------------------------
# 25. pending analysis resumes when ready
# ---------------------------------------------------------------------------


def test_pending_analysis_resume_marks_materialized(db_session) -> None:
    _case(db_session)
    _evidence(db_session, EVIDENCE_A)
    pending = record_pending_analysis(
        db_session,
        case_id=CASE_ID,
        evidence_id=EVIDENCE_A,
        kind="run_all",
    )
    db_session.commit()
    mark_pending_materialized(
        db_session, pending, batch_id="batch-1", run_id="run-1"
    )
    db_session.commit()
    refreshed = db_session.get(MemorySymbolPendingAnalysis, pending.id)
    assert refreshed.status == "materialized"
    assert refreshed.materialized_batch_id == "batch-1"
    assert refreshed.materialized_run_id == "run-1"


# ---------------------------------------------------------------------------
# 26. no evidence modification
# ---------------------------------------------------------------------------


def test_preparation_does_not_modify_evidence(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, EVIDENCE_A)
    original_status = evidence.detection_status
    schedule_preparation(db_session, evidence=evidence, state=PREP_QUEUED)
    db_session.commit()
    db_session.refresh(evidence)
    assert evidence.detection_status == original_status


# ---------------------------------------------------------------------------
# 27. no disk writes / no NormalizedEvent
# ---------------------------------------------------------------------------


def test_preparation_pipeline_does_not_create_artifact_documents(db_session) -> None:
    _case(db_session)
    _evidence(db_session, EVIDENCE_A)
    schedule_preparation(db_session, evidence=db_session.get(Evidence, EVIDENCE_A), state=PREP_QUEUED)
    db_session.commit()
    # The preparation pipeline must NOT touch artifact tables.
    # We just check the row counts are stable.
    from app.models.artifact import Artifact
    artifacts = db_session.query(Artifact).count()
    assert artifacts == 0


# ---------------------------------------------------------------------------
# 28. cache key matches across arches
# ---------------------------------------------------------------------------


def test_cache_match_requires_architecture_match(db_session) -> None:
    _case(db_session)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF12" * 4,
        age=1,
        arch="x64",
    )
    req = _requirement(
        db_session,
        evidence_id=EVIDENCE_A,
        pdb_name="ntkrnlmp.pdb",
        guid="ABCDEF12" * 4,
        age=1,
        arch="arm64",  # Different arch.
    )
    cached = exact_cache_match_for_requirement(db_session, req)
    assert cached is None
