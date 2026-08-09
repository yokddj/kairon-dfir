"""Tests for app.services.memory.preparation (Memory Evidence Preparation, phase 1).

Covers three tiers:

1. Pure model tests (PreparationState, MemoryEvidencePreparation.to_dict).
2. Adapter unit tests -- WindowsPreparationAdapter / LinuxPreparationAdapter
   given a hand-built MemoryAnalysisPlan + MemoryProbeResult, independent
   of the full orchestrator and (for Windows) with
   evidence_symbol_readiness monkeypatched so the state-mapping logic is
   tested in isolation from the Windows symbol-cache DB schema.
3. End-to-end get_preparation_status() tests against a real SQLite-backed
   Evidence row and real evidence files on disk (same fixture style as
   tests/test_memory_platform_routing.py), proving the whole orchestration
   path -- platform probe, build_memory_analysis_plan, adapter dispatch --
   works together for both platforms without mocking the choke point
   itself.

None of these tests exercise any route, worker task, or frontend code --
this package is not wired into anything yet.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryScanRun
from app.services.memory.analysis_plan import MemoryAnalysisPlan
from app.services.memory.capability_registry import MemoryCapability
from app.services.memory.platform import Architecture, MemoryProbeResult, PlatformFamily, ProbeConfidence, ReadinessState
from app.services.memory.preparation import (
    MemoryEvidencePreparation,
    MemoryPreparationError,
    PreparationState,
    get_preparation_status,
)
from app.services.memory.preparation.adapters import (
    LinuxPreparationAdapter,
    WindowsPreparationAdapter,
    _capability_requires_symbols,
    _map_readiness,
)

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id: str = CASE_ID) -> None:
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _evidence(
    db,
    *,
    evidence_id: str = EVIDENCE_ID,
    case_id: str = CASE_ID,
    filename: str = "dump.raw",
    stored_path: str,
    detection_status: str | None = "confirmed_memory",
    operator_override: bool = False,
    detected_format: str | None = None,
    evidence_type: EvidenceType = EvidenceType.memory_dump,
    size_bytes: int = 4096,
) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=filename,
        stored_path=stored_path,
        original_path=stored_path,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=size_bytes,
        ingest_status=IngestStatus.completed,
        detected_host=None,
        detection_status=detection_status,
        operator_override=operator_override,
        detected_format=detected_format,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _write(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _linux_evidence_identity() -> dict:
    return {"linux_symbol_identity": {"architecture": "x64", "kernel_release": "6.8.0-test", "build_id": "build-a"}}


def _plan(
    *,
    platform: PlatformFamily,
    readiness: ReadinessState,
    eligible: tuple[MemoryCapability, ...] = (),
    symbol_status: dict | None = None,
    reason: str = "",
) -> MemoryAnalysisPlan:
    return MemoryAnalysisPlan(
        evidence_id=EVIDENCE_ID,
        detected_platform=platform,
        platform_confidence=ProbeConfidence.HIGH,
        platform_signals="test",
        framework="volatility3",
        readiness=readiness,
        readiness_reason=reason,
        eligible_capabilities=eligible,
        symbol_status=symbol_status or {},
    )


def _probe(*, platform: PlatformFamily = PlatformFamily.WINDOWS, architecture: Architecture = Architecture.X64) -> MemoryProbeResult:
    return MemoryProbeResult(platform=platform, format="test", architecture=architecture, confidence=ProbeConfidence.HIGH, reason="test")


# ---------------------------------------------------------------------------
# 1. Pure model tests
# ---------------------------------------------------------------------------


class TestModel:
    def test_preparation_state_has_exactly_the_six_required_values(self):
        assert {member.value for member in PreparationState} == {
            "inspecting",
            "ready",
            "symbols_required",
            "awaiting_user",
            "blocked",
            "failed",
        }

    def test_to_dict_shape(self):
        prep = MemoryEvidencePreparation(
            evidence_id=EVIDENCE_ID,
            platform=PlatformFamily.LINUX,
            architecture=Architecture.X64,
            readiness=PreparationState.READY,
            requires_symbols=True,
            can_start_analysis=True,
            human_message="ok",
        )
        assert prep.to_dict() == {
            "evidence_id": EVIDENCE_ID,
            "platform": "linux",
            "architecture": "x64",
            "readiness": "ready",
            "requires_symbols": True,
            "can_start_analysis": True,
            "human_message": "ok",
        }

    def test_is_frozen(self):
        prep = MemoryEvidencePreparation(
            evidence_id=EVIDENCE_ID, platform=PlatformFamily.LINUX, architecture=Architecture.UNKNOWN,
            readiness=PreparationState.READY, requires_symbols=False, can_start_analysis=True, human_message="ok",
        )
        with pytest.raises(Exception):
            prep.readiness = PreparationState.BLOCKED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 2. Adapter unit tests
# ---------------------------------------------------------------------------


class TestReadinessMapping:
    @pytest.mark.parametrize(
        ("state", "expected"),
        [
            (ReadinessState.READY, PreparationState.READY),
            (ReadinessState.PARTIALLY_READY, PreparationState.READY),
            (ReadinessState.BLOCKED_SYMBOLS, PreparationState.SYMBOLS_REQUIRED),
            (ReadinessState.PLATFORM_UNKNOWN, PreparationState.INSPECTING),
            (ReadinessState.PLATFORM_UNSUPPORTED, PreparationState.BLOCKED),
            (ReadinessState.PROFILE_UNAVAILABLE, PreparationState.BLOCKED),
            (ReadinessState.FRAMEWORK_UNAVAILABLE, PreparationState.BLOCKED),
            (ReadinessState.BLOCKED, PreparationState.BLOCKED),
            (ReadinessState.INVALID_EVIDENCE, PreparationState.FAILED),
            (ReadinessState.FAILED, PreparationState.FAILED),
        ],
    )
    def test_every_existing_readiness_state_maps_to_one_of_the_six(self, state, expected):
        assert _map_readiness(state) is expected


class TestCapabilityRequiresSymbols:
    def test_windows_processes_requires_symbols(self):
        assert _capability_requires_symbols(PlatformFamily.WINDOWS, (MemoryCapability.PROCESSES,)) is True

    def test_linux_processes_requires_symbols_today(self):
        # Verified against the real capability registry: no Linux entry
        # currently opts out of requires_symbols (see the design report).
        assert _capability_requires_symbols(PlatformFamily.LINUX, (MemoryCapability.PROCESSES,)) is True

    def test_empty_eligible_set_never_requires_symbols(self):
        assert _capability_requires_symbols(PlatformFamily.WINDOWS, ()) is False


class TestWindowsPreparationAdapter:
    def test_ready_plan_with_offline_cache_hit_is_ready(self, monkeypatch: pytest.MonkeyPatch):
        from app.services.memory import symbol_control

        monkeypatch.setattr(
            symbol_control,
            "evidence_symbol_readiness",
            lambda db, case_id, evidence_id, **kw: {"symbols_required": True, "can_analyze_offline": True},
        )
        plan = _plan(platform=PlatformFamily.WINDOWS, readiness=ReadinessState.READY, eligible=(MemoryCapability.PROCESSES,))
        result = WindowsPreparationAdapter().describe(plan, _probe(), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.READY
        assert result.can_start_analysis is True
        assert result.requires_symbols is True
        assert "already available" in result.human_message

    def test_ready_plan_but_symbols_not_cached_becomes_symbols_required(self, monkeypatch: pytest.MonkeyPatch):
        from app.services.memory import symbol_control

        monkeypatch.setattr(
            symbol_control,
            "evidence_symbol_readiness",
            lambda db, case_id, evidence_id, **kw: {"symbols_required": True, "can_analyze_offline": False},
        )
        plan = _plan(platform=PlatformFamily.WINDOWS, readiness=ReadinessState.READY, eligible=(MemoryCapability.PROCESSES,))
        result = WindowsPreparationAdapter().describe(plan, _probe(), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.SYMBOLS_REQUIRED
        assert result.can_start_analysis is False

    def test_blocked_symbols_plan_never_calls_evidence_symbol_readiness(self, monkeypatch: pytest.MonkeyPatch):
        """Windows readiness=READY is the only branch that consults the
        Windows symbol cache -- a plan that never reached READY (e.g.
        platform mismatch) must not waste a DB round trip."""
        from app.services.memory import symbol_control

        def _fail(*a, **k):
            raise AssertionError("must not be called")

        monkeypatch.setattr(symbol_control, "evidence_symbol_readiness", _fail)
        plan = _plan(platform=PlatformFamily.WINDOWS, readiness=ReadinessState.PLATFORM_UNSUPPORTED)
        result = WindowsPreparationAdapter().describe(plan, _probe(), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.BLOCKED

    def test_platform_unknown_is_inspecting(self):
        plan = _plan(platform=PlatformFamily.WINDOWS, readiness=ReadinessState.PLATFORM_UNKNOWN)
        result = WindowsPreparationAdapter().describe(plan, _probe(platform=PlatformFamily.UNKNOWN), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))
        assert result.readiness is PreparationState.INSPECTING
        assert result.can_start_analysis is False


class TestLinuxPreparationAdapter:
    def test_ready_plan_is_ready_without_a_second_readiness_call(self):
        plan = _plan(platform=PlatformFamily.LINUX, readiness=ReadinessState.READY, eligible=(MemoryCapability.PROCESSES,))
        result = LinuxPreparationAdapter().describe(plan, _probe(platform=PlatformFamily.LINUX), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.READY
        assert result.can_start_analysis is True
        assert result.requires_symbols is True

    def test_blocked_symbols_with_unknown_kernel_identity_gets_specific_message(self):
        plan = _plan(
            platform=PlatformFamily.LINUX,
            readiness=ReadinessState.BLOCKED_SYMBOLS,
            eligible=(MemoryCapability.PROCESSES,),
            symbol_status={"reason_code": "kernel_identity_unknown"},
        )
        result = LinuxPreparationAdapter().describe(plan, _probe(platform=PlatformFamily.LINUX), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.SYMBOLS_REQUIRED
        assert result.can_start_analysis is False
        assert "kernel identity" in result.human_message

    def test_blocked_symbols_with_known_identity_gets_generic_symbols_message(self):
        plan = _plan(
            platform=PlatformFamily.LINUX,
            readiness=ReadinessState.BLOCKED_SYMBOLS,
            eligible=(MemoryCapability.PROCESSES,),
            symbol_status={"reason_code": "symbols_unavailable"},
        )
        result = LinuxPreparationAdapter().describe(plan, _probe(platform=PlatformFamily.LINUX), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))

        assert result.readiness is PreparationState.SYMBOLS_REQUIRED
        assert "ISF" in result.human_message

    def test_never_claims_symbols_optional_for_linux_today(self):
        """Regression guard for the explicit 'do not invent this' requirement:
        with every Linux capability requiring symbols (real, current
        registry state), requires_symbols must be True whenever a Linux
        capability is eligible -- never silently False."""
        plan = _plan(platform=PlatformFamily.LINUX, readiness=ReadinessState.READY, eligible=(MemoryCapability.PROCESSES, MemoryCapability.NETWORK))
        result = LinuxPreparationAdapter().describe(plan, _probe(platform=PlatformFamily.LINUX), db=object(), evidence=SimpleNamespace(id=EVIDENCE_ID, case_id=CASE_ID))
        assert result.requires_symbols is True


# ---------------------------------------------------------------------------
# 3. End-to-end get_preparation_status() tests
# ---------------------------------------------------------------------------


class TestGetPreparationStatusEndToEnd:
    def test_evidence_not_found_raises(self):
        db = _db()
        with pytest.raises(MemoryPreparationError):
            get_preparation_status(db, "does-not-exist")

    def test_non_memory_evidence_raises(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "disk.E01", b"\x00" * 64)
        _evidence(db, stored_path=str(path), evidence_type=EvidenceType.disk_image)
        with pytest.raises(MemoryPreparationError):
            get_preparation_status(db, EVIDENCE_ID)

    def test_probable_disk_is_blocked(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "maybe-disk.raw", b"\x00" * 64)
        _evidence(db, stored_path=str(path), detection_status="probable_disk")

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.readiness is PreparationState.BLOCKED
        assert result.can_start_analysis is False

    def test_ambiguous_raw_without_confirmation_awaits_user(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "ambiguous.raw", b"\x00" * 64)
        _evidence(db, stored_path=str(path), detection_status="ambiguous_raw", operator_override=False)

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.readiness is PreparationState.AWAITING_USER
        assert result.can_start_analysis is False

    def test_ambiguous_raw_with_operator_override_proceeds_past_the_gate(self, tmp_path: Path):
        """Confirmed evidence must fall through to real platform/readiness
        assessment instead of staying stuck on AWAITING_USER forever."""
        db = _db()
        _case(db)
        path = _write(tmp_path, "confirmed.raw", b"\x00" * 4096)
        _evidence(db, stored_path=str(path), detection_status="ambiguous_raw", operator_override=True)

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.readiness is not PreparationState.AWAITING_USER

    def test_linux_evidence_with_no_isf_cached_is_symbols_required(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from app.services.memory import analysis_plan as analysis_plan_module

        cache_root = tmp_path / "volatility-cache"
        (cache_root / "symbols" / "windows").mkdir(parents=True)
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))

        db = _db()
        _case(db)
        path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
        _evidence(db, stored_path=str(path), detected_format="elf_core")

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.LINUX
        assert result.readiness is PreparationState.SYMBOLS_REQUIRED
        assert result.can_start_analysis is False
        assert result.requires_symbols is True

    def test_linux_evidence_with_isf_cached_is_ready(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from app.services.memory import analysis_plan as analysis_plan_module
        from app.services.memory.linux_symbols import import_linux_isf

        cache_root = tmp_path / "volatility-cache"
        linux_symbols = cache_root / "symbols" / "linux"
        linux_symbols.mkdir(parents=True)
        source_isf = tmp_path / "some-kernel.json"
        source_isf.write_text(
            '{"metadata":{"linux":{"kernel_release":"6.8.0-test","architecture":"x64","build_id":"build-a"}},"symbols":{},"types":{}}'
        )
        import_linux_isf(
            source_isf,
            original_filename="some-kernel.json",
            settings=SimpleNamespace(
                memory_native_probe_cache_path=cache_root,
                memory_linux_symbol_manual_import_enabled=True,
                memory_linux_symbol_isf_upload_max_bytes=1024 * 1024,
            ),
        )
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))

        db = _db()
        _case(db)
        path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
        evidence = _evidence(db, stored_path=str(path), detected_format="elf_core")
        evidence.metadata_json = _linux_evidence_identity()
        db.commit()

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.LINUX
        assert result.readiness is PreparationState.READY
        assert result.can_start_analysis is True

    def test_windows_evidence_with_clean_history_is_ready(self, tmp_path: Path):
        """No prior failed scan run and no symbol requirement row at all
        means evidence_symbol_readiness() legitimately reports
        can_analyze_offline=True (nothing has ever proven symbols are
        missing) -- this is real, existing behavior, not something this
        phase invents."""
        db = _db()
        _case(db)
        path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
        _evidence(db, stored_path=str(path))

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.WINDOWS
        assert result.readiness is PreparationState.READY
        assert result.can_start_analysis is True

    def test_windows_evidence_with_prior_symbol_failure_is_symbols_required(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
        _evidence(db, stored_path=str(path))
        db.add(MemoryScanRun(case_id=CASE_ID, evidence_id=EVIDENCE_ID, error_log={"code": "SYMBOLS_UNAVAILABLE"}))
        db.commit()

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.WINDOWS
        assert result.readiness is PreparationState.SYMBOLS_REQUIRED
        assert result.can_start_analysis is False

    def test_unknown_platform_is_inspecting_not_blocked_or_failed(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "ambiguous-but-confirmed.raw", b"\x00" * 4096)
        _evidence(db, stored_path=str(path), detection_status="confirmed_memory")

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.UNKNOWN
        assert result.readiness is PreparationState.INSPECTING
        assert result.can_start_analysis is False

    def test_macos_evidence_is_blocked_not_symbols_required(self, tmp_path: Path):
        """A recognized-but-capability-registry-unsupported platform is a
        structural block, never confused with a missing-symbols outcome."""
        db = _db()
        _case(db)
        path = _write(tmp_path, "macos.img", b"Mach-O" + b"\x00" * 4090)
        _evidence(db, stored_path=str(path))

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.platform is PlatformFamily.MACOS
        assert result.readiness is PreparationState.BLOCKED

    def test_result_is_always_evidence_scoped(self, tmp_path: Path):
        db = _db()
        _case(db)
        path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
        _evidence(db, stored_path=str(path))

        result = get_preparation_status(db, EVIDENCE_ID)

        assert result.evidence_id == EVIDENCE_ID
