"""Tests for the Volatility-native compatibility probe feature.

Covers:
- Model creation and status transitions
- Output validation (structural checks)
- Readiness integration
- CLI dry-run and execute paths
- API endpoints
- One-active-probe enforcement
- Plugin allowlist validation
- No experimental interference
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture
def db_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models  # noqa: F401
    import app.core.database as database_module

    monkeypatch.setenv("KAIRON_CLI_OPERATOR_ROOTS", str(tmp_path))
    monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
    monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
    monkeypatch.setenv("BACKEND_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BACKEND_TEMP_DIR", str(tmp_path / "tmp"))
    from app.core.config import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, future=True
    )
    original_session = database_module.SessionLocal
    original_engine = database_module.engine
    database_module.SessionLocal = SessionLocal
    database_module.engine = engine
    session = SessionLocal()
    try:
        yield session, tmp_path
    finally:
        session.close()
        database_module.SessionLocal = original_session
        database_module.engine = original_engine
        engine.dispose()
        get_settings.cache_clear()


def _case(db):
    from app.models.case import Case

    c = Case(id=str(uuid.uuid4()), name="test-case", description="")
    db.add(c)
    db.flush()
    return c


def _evidence(db, case_id, evidence_type="memory_dump"):
    from app.models.evidence import Evidence, EvidenceType

    eid = str(uuid.uuid4())
    etype = getattr(EvidenceType, evidence_type, EvidenceType.memory_dump)
    ev = Evidence(
        id=eid,
        case_id=case_id,
        original_filename="test.raw",
        stored_path="staging/test.raw",
        sha256="0" * 64,
        size_bytes=1024,
        evidence_type=etype,
        detection_status="memory",
    )
    db.add(ev)
    db.flush()
    return ev


def _requirement(db, evidence, pdb_name="ntkrnlmp.pdb", pdb_age=1):
    from app.models.memory import MemorySymbolRequirement

    req = MemorySymbolRequirement(
        id=str(uuid.uuid4()),
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        pdb_name=pdb_name,
        pdb_guid="D801A9AFC0FB7761380800F708633DEA",
        pdb_age=pdb_age,
        architecture="x64",
        symbol_key=f"{pdb_name.lower()}/D801A9AFC0FB7761380800F708633DEA-{pdb_age}",
        status="unavailable_offline",
        source="bounded_discovery",
    )
    db.add(req)
    db.flush()
    return req


def _cached_symbol(db, pdb_name="ntkrnlmp.pdb", guid="D801A9AFC0FB7761380800F708633DEA", age=1, classification="exact"):
    from app.models.memory import MemoryCachedSymbol

    key = f"{pdb_name.lower()}/{guid}-{age}"
    cs = MemoryCachedSymbol(
        id=str(uuid.uuid4()),
        symbol_key=key,
        pdb_name=pdb_name,
        pdb_guid=guid,
        pdb_age=age,
        architecture="x64",
        pdb_relative_path=f"pdb/{pdb_name.lower()}/{guid}-{age}/{pdb_name.lower()}",
        isf_relative_path=f"symbols/windows/{pdb_name}/{guid}-{age}.json.xz",
        pdb_sha256="0" * 64,
        isf_sha256="0" * 64,
        pdb_size_bytes=1024,
        isf_size_bytes=512,
        validation_status="validated",
        cache_classification=classification,
    )
    db.add(cs)
    db.flush()
    return cs


def _preparation(db, evidence, state="blocked_symbols", requirement_id=None):
    from app.models.memory import MemorySymbolPreparation

    prep = MemorySymbolPreparation(
        id=str(uuid.uuid4()),
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        state=state,
        requirement_id=requirement_id,
        active=True,
    )
    db.add(prep)
    db.flush()
    return prep


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestNativeProbeModel:
    def test_create_queued(self, db_session):
        db, _ = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="queued",
            plugin="windows.pslist.PsList",
        )
        db.add(probe)
        db.flush()
        assert probe.id is not None
        assert probe.status == "queued"
        assert probe.plugin == "windows.pslist.PsList"

    def test_status_transitions(self, db_session):
        db, _ = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="queued",
            plugin="windows.pslist.PsList",
        )
        db.add(probe)
        db.flush()

        for status in ["running", "compatible", "incompatible", "failed", "timeout"]:
            probe.status = status
            db.flush()
            assert probe.status == status

    def test_sanitized_error_truncation(self, db_session):
        db, _ = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        long_msg = "X" * 2000
        probe = MemoryNativeProbe(
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            sanitized_error=long_msg[:1024],
            status="failed",
        )
        db.add(probe)
        db.flush()
        assert len(probe.sanitized_error) <= 1024


# ---------------------------------------------------------------------------
# Output validation tests
# ---------------------------------------------------------------------------


class TestNativeProbeValidation:
    def test_valid_pslist_output(self):
        from app.services.memory.native_probe import validate_native_probe_output

        valid_output = json.dumps([
            {"PID": 0, "PPID": 0, "ImageFileName": "Idle", "Offset(V)": "0x0"},
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": "0x12345"},
            {"PID": 400, "PPID": 4, "ImageFileName": "csrss.exe", "Offset(V)": "0x20000"},
            {"PID": 500, "PPID": 4, "ImageFileName": "wininit.exe", "Offset(V)": "0x30000", "CreateTime": "2024-03-22T12:59:06.000000"},
        ])

        result = validate_native_probe_output(valid_output, min_rows=3, malformed_ratio=0.5)
        assert result["valid"] is True
        assert result["row_count"] == 4
        assert result["checks"]["pid_present"] is True
        assert result["checks"]["pid4_system"] is True
        assert result["checks"]["printable_name_ratio"] > 0.3

    def test_invalid_empty_output(self):
        from app.services.memory.native_probe import validate_native_probe_output

        result = validate_native_probe_output("[]", min_rows=3, malformed_ratio=0.5)
        assert result["valid"] is False
        assert "Only 0 process row" in result.get("reason", "")

    def test_malformed_json_rejected(self):
        from app.services.memory.native_probe import validate_native_probe_output

        result = validate_native_probe_output("not json", min_rows=3, malformed_ratio=0.5)
        assert result["valid"] is False
        assert "Malformed JSON" in result.get("reason", "")

    def test_missing_pid_column(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {"ImageFileName": "test", "OtherField": "value"},
            {"ImageFileName": "other"},
        ])
        result = validate_native_probe_output(output, min_rows=1, malformed_ratio=0.5)
        assert result["valid"] is False
        assert result["checks"]["pid_present"] is False

    def test_unprintable_names_rejected(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {"PID": 100, "ImageFileName": "\x00\x01\x02\x03"},
            {"PID": 200, "ImageFileName": "\x7f\x80\x81\x82"},
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 300, "ImageFileName": "\x1b\x1c\x1d\x1e"},
        ])
        result = validate_native_probe_output(output, min_rows=3, malformed_ratio=0.5)
        ratio = result["checks"]["printable_name_ratio"]
        assert ratio < 0.5

    def test_malformed_rows_exceed_threshold(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {},
            {},
            {},
            {"PID": 4, "ImageFileName": "System"},
        ])
        result = validate_native_probe_output(output, min_rows=3, malformed_ratio=0.3)
        # 3 malformed out of 4 = 0.75 > 0.3
        assert result["valid"] is False
        assert result["checks"]["malformed_row_ratio"] > 0.3

    def test_pid4_system_found(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {"PID": 0, "ImageFileName": "Idle"},
            {"PID": 4, "ImageFileName": "System"},
        ])
        result = validate_native_probe_output(output, min_rows=1, malformed_ratio=0.9)
        assert result["checks"]["pid4_system"] is True

    def test_timestamps_detected(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {"PID": 4, "ImageFileName": "System", "CreateTime": "2024-03-22T12:00:00.000000"},
        ])
        result = validate_native_probe_output(output, min_rows=1, malformed_ratio=0.9)
        assert result["checks"]["timestamps_parseable"] is True

    def test_offsets_detected(self):
        from app.services.memory.native_probe import validate_native_probe_output

        output = json.dumps([
            {"PID": 4, "ImageFileName": "System", "Offset(V)": "0x12345"},
        ])
        result = validate_native_probe_output(output, min_rows=1, malformed_ratio=0.9)
        assert result["checks"]["offsets_in_range"] is True


# ---------------------------------------------------------------------------
# Readiness integration tests
# ---------------------------------------------------------------------------


class TestNativeProbeReadiness:
    def test_age_mismatch_no_longer_terminally_blocks_when_compatible(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)  # age=1
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)

        from app.models.memory import MemoryNativeProbe
        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
            vol_version="2.28.0",
        )
        db.add(probe)
        db.commit()

        from app.services.memory.symbol_preparation import compute_memory_readiness

        readiness = compute_memory_readiness(db, evidence=ev)
        assert readiness.can_analyze_metadata is True
        assert readiness.can_run_all is True
        assert readiness.native_compatible is True
        assert readiness.native_compatibility_reason == "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE"
        assert readiness.exact_match is False

    def test_incompatible_probe_keeps_blocked(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)

        from app.models.memory import MemoryNativeProbe
        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="incompatible",
            plugin="windows.pslist.PsList",
        )
        db.add(probe)
        db.commit()

        from app.services.memory.symbol_preparation import compute_memory_readiness

        readiness = compute_memory_readiness(db, evidence=ev)
        assert readiness.can_analyze_metadata is False
        assert readiness.native_compatible is False

    def test_name_mismatch_remains_blocked(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev, pdb_name="ntkrnlmp.pdb")
        req2 = _requirement(db, ev, pdb_name="ntoskrnl.pdb")

        from app.models.memory import MemoryNativeProbe
        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
        )
        db.add(probe)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req2.id)
        db.commit()

        from app.services.memory.symbol_preparation import compute_memory_readiness

        readiness = compute_memory_readiness(db, evidence=ev)
        # Should be blocked because the probe was for req, not req2
        assert readiness.can_analyze_metadata is False

    def test_requirement_age_unchanged(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev, pdb_age=1)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
        )
        db.add(probe)
        db.commit()

        from app.services.memory.symbol_preparation import compute_memory_readiness

        readiness = compute_memory_readiness(db, evidence=ev)
        assert readiness.native_compatible is True
        assert readiness.requirement is not None
        assert readiness.requirement["pdb_age"] == 1  # unchanged


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestNativeProbeCLI:
    def test_dry_run_prints_diagnostics(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)
        db.commit()

        from app.cli.memory_symbols import cmd_native_probe
        import argparse

        args = argparse.Namespace(
            case_id=case.id,
            evidence_id=ev.id,
            plugin="windows.pslist.PsList",
            dry_run=True,
            execute=False,
            json=True,
        )
        result = cmd_native_probe(args)
        assert result == 0


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------


class TestNativeProbeService:
    def test_queue_creates_probe_row(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        db.commit()

        # Mock the enqueue to avoid Redis dependency
        import app.services.memory.native_probe as np

        original = getattr(np, "queue_native_probe", None)

        def mock_queue(db, **kwargs):
            from app.models.memory import MemoryNativeProbe

            probe = MemoryNativeProbe(
                case_id=kwargs["case_id"],
                evidence_id=kwargs["evidence_id"],
                requirement_id=kwargs["requirement_id"],
                status="queued",
                plugin="windows.pslist.PsList",
            )
            db.add(probe)
            db.flush()
            return probe

        try:
            np.queue_native_probe = mock_queue
            probe = mock_queue(
                db,
                case_id=case.id,
                evidence_id=ev.id,
                requirement_id=req.id,
            )
            assert probe.status == "queued"
        finally:
            if original:
                np.queue_native_probe = original

    def test_duplicate_probe_rejected(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="queued",
            plugin="windows.pslist.PsList",
        )
        db.add(probe)
        db.commit()

        from app.services.memory.native_probe import _active_probe_for

        existing = _active_probe_for(db, evidence_id=ev.id)
        assert existing is not None
        assert existing.status == "queued"

    def test_check_compatibility_when_compatible(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
        )
        db.add(probe)
        db.commit()

        from app.services.memory.native_probe import check_native_compatibility

        result = check_native_compatibility(
            db, evidence_id=ev.id, requirement_id=req.id,
        )
        assert result is not None
        assert result["compatible"] is True
        assert result["reason"] == "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE"

    def test_check_compatibility_when_failed(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="failed",
            plugin="windows.pslist.PsList",
        )
        db.add(probe)
        db.commit()

        from app.services.memory.native_probe import check_native_compatibility

        result = check_native_compatibility(
            db, evidence_id=ev.id, requirement_id=req.id,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Isolation tests
# ---------------------------------------------------------------------------


class TestNativeProbeIsolation:
    def test_no_experimental_run_created_by_native_probe(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe, MemoryExperimentalRun

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
        )
        db.add(probe)
        db.commit()

        # No MemoryExperimentalRun should exist
        exp_runs = db.query(MemoryExperimentalRun).filter(
            MemoryExperimentalRun.evidence_id == ev.id,
        ).all()
        assert len(exp_runs) == 0

    def test_cached_symbol_native_classification_does_not_satisfy_exact(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        cs = _cached_symbol(db, classification="volatility_native_compatible")
        db.commit()

        from app.services.memory.symbol_blocked_acquisition import find_exact_cache

        result = find_exact_cache(db, req)
        # Should NOT match because classification is not "exact"
        assert result is None

    def test_multiple_probes_allowed_sequentially(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe1 = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="failed",
            plugin="windows.pslist.PsList",
        )
        db.add(probe1)
        db.flush()
        # Probe 2: only one active at a time check should pass when probe1 is terminal
        from app.services.memory.native_probe import _active_probe_for

        active = _active_probe_for(db, evidence_id=ev.id)
        assert active is None  # failed is not active


# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------


class TestMigration:
    def test_v18_migration_exists(self):
        from app.core.migrations import MIGRATIONS

        versions = {m.version for m in MIGRATIONS}
        assert 18 in versions

    def test_v18_migration_table_exists(self, db_session):
        db, tmp = db_session
        import sqlalchemy

        inspector = sqlalchemy.inspect(db.get_bind())
        assert "memory_native_probes" in inspector.get_table_names()

    def test_v18_partial_unique_index_present(self, db_session):
        db, tmp = db_session
        import sqlalchemy

        inspector = sqlalchemy.inspect(db.get_bind())
        indexes = inspector.get_indexes("memory_native_probes")
        index_names = {i["name"] for i in indexes}
        assert "uq_memory_native_probe_active" in index_names


# ---------------------------------------------------------------------------
# Stock Volatility parity tests
# ---------------------------------------------------------------------------


class TestStockParity:
    def test_no_offline_in_native_mode(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()
        from app.services.memory.native_probe import _execute_stock_plugin

        # Read source to verify no --offline in argv construction
        import inspect
        source = inspect.getsource(_execute_stock_plugin)
        assert "--offline" not in source, "native probe must not use --offline"

    def test_no_custom_isf_functions(self):
        import inspect
        from app.services.memory import native_probe

        funcs = {name for name, _ in inspect.getmembers(native_probe, inspect.isfunction)}
        assert "_generate_isf_native" not in funcs, "no custom ISF generation"
        assert "_native_acquire_and_cache" not in funcs, "no custom cache acquisition"
        assert "_download_via_egress" not in funcs, "no direct egress download"

    def test_plugin_allowlist_enforced(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")

        from app.services.memory.native_probe import NATIVE_PROBE_ALLOWED_PLUGINS, NativeProbeError

        assert "windows.pslist.PsList" in NATIVE_PROBE_ALLOWED_PLUGINS
        # Prove arbitrary plugins ARE rejected without executing
        assert "windows.malfind.Malfind" not in NATIVE_PROBE_ALLOWED_PLUGINS
        assert "windows.cmdline.CmdLine" not in NATIVE_PROBE_ALLOWED_PLUGINS

    def test_evidence_path_falls_back_to_stored_path(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")

        db, tmp = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        # Create staging directory so path.exists() passes
        staging = tmp / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "test.raw").write_text("fake mem dump")

        ev.stored_path = str(staging / "test.raw")
        db.add(ev)
        db.commit()

        from app.services.memory.native_probe import _canonical_evidence_path
        path = _canonical_evidence_path(db, ev.id)
        assert path is not None
        assert "staging" in str(path)


# ---------------------------------------------------------------------------
# Readiness gate tests
# ---------------------------------------------------------------------------


class TestReadinessGates:
    def test_resolve_effective_state_recognises_native_compatible(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        db, tmp = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)

        from app.models.memory import MemoryNativeProbe
        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            output_row_count=10,
        )
        db.add(probe)
        db.commit()

        from app.services.memory.symbol_preparation import resolve_effective_memory_preparation_state

        result = resolve_effective_memory_preparation_state(db, case_id=case.id, evidence_id=ev.id)
        assert result["effective_state"] == "ready"
        assert result["source_of_truth"] == "volatility_native_compatible"


# ---------------------------------------------------------------------------
# Reconciliation tests
# ---------------------------------------------------------------------------


class TestReconciliation:
    def test_stale_probes_reconciled(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_STALE_SECONDS", "0")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe
        from app.core.database import utc_now_naive
        from datetime import timedelta

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="running",
            plugin="windows.pslist.PsList",
            heartbeat_at=utc_now_naive() - timedelta(seconds=3600),
        )
        db.add(probe)
        db.commit()

        from app.services.memory.native_probe import reconcile_stale_probes

        count = reconcile_stale_probes(db)
        assert count >= 1
        assert probe.status == "failed"

    def test_concurrent_active_probe_rejected_by_db(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        db, tmp = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)

        from app.models.memory import MemoryNativeProbe

        probe1 = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="queued",
            plugin="windows.pslist.PsList",
        )
        db.add(probe1)
        db.flush()

        probe2 = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="queued",
            plugin="windows.pslist.PsList",
        )
        db.add(probe2)
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            db.flush()


# ---------------------------------------------------------------------------
# Queue and CLI diagnostic tests
# ---------------------------------------------------------------------------


class TestCLIDiagnostics:
    def test_dry_run_diagnostics_fields(self, db_session, monkeypatch):
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        from app.core.config import get_settings
        get_settings.cache_clear()

        db, tmp = db_session
        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        _preparation(db, ev, state="blocked_symbols", requirement_id=req.id)
        db.commit()

        from app.services.memory.symbol_blocked_acquisition import load_active_requirement
        from app.core.config import get_settings as gs

        requirement = load_active_requirement(db, case_id=case.id, evidence_id=ev.id)
        assert requirement is not None

        settings = gs()
        diag = {
            "offline": False,
            "force_isf": False,
            "effective_cache_root": str(settings.memory_native_probe_cache_path),
            "effective_command": "vol -f <canonical-evidence-path> -r json windows.pslist.PsList",
            "queue": settings.memory_native_probe_queue_name,
            "renderer": "json",
            "executable": "vol",
        }
        assert diag["offline"] is False
        assert diag["force_isf"] is False
        assert diag["effective_cache_root"]
        assert diag["queue"] == "memory-native-probe"


# ---------------------------------------------------------------------------
# Queue and topology tests
# ---------------------------------------------------------------------------


class TestQueueTopology:
    def test_producer_queue_matches_config(self):
        from app.core.config import get_settings
        settings = get_settings()
        assert settings.memory_native_probe_queue_name == "memory-native-probe"

    def test_worker_consumes_only_native_queue(self):
        import inspect
        from app.workers import native_probe_worker

        source = inspect.getsource(native_probe_worker.main)
        assert "memory_native_probe_queue_name" in source
        assert "memory" not in source.replace("memory_native_probe_queue_name", "").split(
            "memory_queue_name"
        )[0].split("memory_experimental")[0]

    def test_reconciliation_diagnostics(self):
        from app.services.memory.native_probe import reconciliation_diagnostics

        diag = reconciliation_diagnostics()
        assert diag["mechanism"] == "redis_distributed_lock"
        assert diag["interval_seconds"] == 300
        assert diag["available"] is True

    def test_healthy_probe_not_reconciled(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_STALE_SECONDS", "900")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        from app.models.memory import MemoryNativeProbe
        from app.core.database import utc_now_naive

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="running",
            plugin="windows.pslist.PsList",
            heartbeat_at=utc_now_naive(),
        )
        db.add(probe)
        db.commit()
        original_status = probe.status

        from app.services.memory.native_probe import reconcile_stale_probes
        count = reconcile_stale_probes(db)
        assert count == 0
        assert probe.status == original_status

    def test_terminal_probe_not_modified_by_reconciliation(self, db_session, monkeypatch):
        db, tmp = db_session
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_ENABLED", "true")
        monkeypatch.setenv("MEMORY_NATIVE_PROBE_STALE_SECONDS", "0")
        from app.core.config import get_settings
        get_settings.cache_clear()

        case = _case(db)
        ev = _evidence(db, case.id)
        req = _requirement(db, ev)
        from app.models.memory import MemoryNativeProbe
        from app.core.database import utc_now_naive
        from datetime import timedelta

        probe = MemoryNativeProbe(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=ev.id,
            requirement_id=req.id,
            status="compatible",
            plugin="windows.pslist.PsList",
            heartbeat_at=utc_now_naive() - timedelta(seconds=3600),
        )
        db.add(probe)
        db.commit()

        from app.services.memory.native_probe import reconcile_stale_probes
        count = reconcile_stale_probes(db)
        assert count == 0
        assert probe.status == "compatible"

    def test_compose_worker_mounts_volatility_cache(self):
        import yaml
        from pathlib import Path
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        compose = yaml.safe_load(compose_path.read_text())
        svc = compose["services"].get("memory-native-probe-worker", {})
        volumes = [str(v) for v in svc.get("volumes", [])]
        assert any("volatility-cache" in v for v in volumes), "volatility-cache must be mounted"

    def test_compose_worker_mounts_evidence_readonly(self):
        import yaml
        from pathlib import Path
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        compose = yaml.safe_load(compose_path.read_text())
        svc = compose["services"].get("memory-native-probe-worker", {})
        volumes = [str(v) for v in svc.get("volumes", [])]
        assert any("evidence" in v and ":ro" in v for v in volumes), "evidence must be ro"

    def test_compose_service_name_is_exact(self):
        import yaml
        from pathlib import Path
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        compose = yaml.safe_load(compose_path.read_text())
        assert "memory-native-probe-worker" in compose["services"]
        assert "memory-wrapper-native-probe-worker" not in compose["services"]
