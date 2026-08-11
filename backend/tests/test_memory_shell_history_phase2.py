"""Linux Shell History Phase 2: profile + catalogue + platform availability.

Phase 1 (see test_memory_shell_history.py) built the family end-to-end at
the storage/search/timeline layer but deliberately did not create a real
profile. This phase adds shell_history_basic as a genuine, selectable
profile -- resolved exclusively through capability_registry (never a
PROFILE_PLUGINS entry), correctly available on Linux and correctly
unavailable on Windows, exposed in the catalogue and FAMILY_ORDER, and
excluded from run-all and initial analysis.
"""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.core.config import Settings
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.memory import catalogue as catalogue_module
from app.services.memory.analysis_plan import MemoryAnalysisPlan
from app.services.memory.capability_registry import MemoryCapability
from app.services.memory.catalogue import PROFILE_CATALOGUE, build_analysis_catalogue
from app.services.memory.counts import FAMILY_ORDER
from app.services.memory.execution import PROFILE_CAPABILITY, PROFILE_PLUGINS, backend_readiness, resolve_profile_plugins
from app.services.memory.platform import PlatformFamily, ProbeConfidence, ReadinessState
from app.services.memory.validation import MemoryExecutionValidationError


def _settings_with_process_profiles_enabled() -> Settings:
    base = Settings()
    object.__setattr__(base, "memory_process_profile_enabled", True)
    return base


@pytest.fixture(autouse=True)
def _enable_process_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    # resolve_profile_plugins (execution.py) and _plan_capability_registry_profile
    # (catalogue.py) each resolve settings through a different reference --
    # both must be patched or shell_history_basic (a "process profile", not
    # metadata_only) raises PROCESS_PROFILE_DISABLED before this phase's own
    # logic is even reached.
    monkeypatch.setattr(backend_readiness, "get_settings", _settings_with_process_profiles_enabled)
    monkeypatch.setattr(catalogue_module, "get_settings", _settings_with_process_profiles_enabled)


# ---------------------------------------------------------------------------
# 1. Profile registration
# ---------------------------------------------------------------------------


def test_shell_history_basic_registered_in_profile_capability() -> None:
    assert PROFILE_CAPABILITY["shell_history_basic"] == MemoryCapability.SHELL_HISTORY


def test_shell_history_basic_has_no_profile_plugins_entry() -> None:
    """Must resolve exclusively via capability_registry -- never a flat
    plugin list hardcoded in execution.PROFILE_PLUGINS."""
    assert "shell_history_basic" not in PROFILE_PLUGINS


def _plan(platform: PlatformFamily, *, eligible: tuple = (), selected: tuple = ()) -> MemoryAnalysisPlan:
    return MemoryAnalysisPlan(
        evidence_id="ev-1",
        detected_platform=platform,
        platform_confidence=ProbeConfidence.HIGH,
        platform_signals="test",
        framework="volatility3",
        readiness=ReadinessState.READY,
        readiness_reason="test",
        eligible_capabilities=eligible,
        selected_plugins=selected,
    )


def test_linux_resolves_exactly_linux_bash() -> None:
    plan = _plan(PlatformFamily.LINUX, eligible=(MemoryCapability.SHELL_HISTORY,), selected=("linux.bash",))
    assert resolve_profile_plugins("shell_history_basic", plan=plan) == ["linux.bash"]


def test_windows_resolves_to_nothing() -> None:
    plan = _plan(PlatformFamily.WINDOWS, eligible=(), selected=())
    with pytest.raises(MemoryExecutionValidationError) as exc_info:
        resolve_profile_plugins("shell_history_basic", plan=plan)
    assert exc_info.value.code == "PROFILE_CAPABILITY_UNAVAILABLE"


def test_plan_none_returns_empty_list_not_a_crash() -> None:
    assert resolve_profile_plugins("shell_history_basic", plan=None) == []


def test_unknown_profile_still_rejected() -> None:
    with pytest.raises(MemoryExecutionValidationError) as exc_info:
        resolve_profile_plugins("not_a_real_profile", plan=None)
    assert exc_info.value.code == "UNKNOWN_PROFILE"


# ---------------------------------------------------------------------------
# 2. Regression: no linux.sockstat, no processes plugins, other profiles
#    unchanged
# ---------------------------------------------------------------------------


def test_shell_history_never_selects_sockstat_or_process_plugins() -> None:
    plan = _plan(PlatformFamily.LINUX, eligible=(MemoryCapability.SHELL_HISTORY,), selected=("linux.bash",))
    resolved = resolve_profile_plugins("shell_history_basic", plan=plan)
    assert "linux.sockstat" not in resolved
    assert "linux.pslist" not in resolved
    assert "linux.pstree" not in resolved
    assert resolved == ["linux.bash"]


def test_other_profiles_plugin_lists_unchanged() -> None:
    assert PROFILE_PLUGINS["metadata_only"] == ["windows.info"]
    assert PROFILE_PLUGINS["processes_basic"] == ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]
    assert PROFILE_PLUGINS["network_basic"] == ["windows.netscan", "windows.netstat"]
    assert PROFILE_PLUGINS["suspicious_memory"] == ["windows.malfind", "windows.vadinfo"]
    assert "shell_history_basic" not in PROFILE_PLUGINS


# ---------------------------------------------------------------------------
# 3. Allowed profiles (config)
# ---------------------------------------------------------------------------


def test_allowed_profiles_includes_shell_history_basic() -> None:
    settings = Settings()
    assert "shell_history_basic" in settings.allowed_memory_profiles
    # The other 8 stay present -- this is additive, not a replacement.
    for profile in ("metadata_only", "processes_basic", "processes_extended", "network_basic", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"):
        assert profile in settings.allowed_memory_profiles


def test_defaults_env_and_setup_sh_include_shell_history_basic() -> None:
    """Every source of truth for allowed profiles must agree -- a profile
    allowed by the Python default but rejected by the deployed env file
    (or vice versa) is exactly the kind of drift Phase 1's audit caught
    in config/defaults.env (it was stale relative to the Python default
    even before this phase)."""
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    defaults_env = (repo_root / "config" / "defaults.env").read_text()
    setup_sh = (repo_root / "scripts" / "setup.sh").read_text()
    assert "shell_history_basic" in [line for line in defaults_env.splitlines() if line.startswith("MEMORY_ALLOWED_PROFILES=")][0]
    assert "shell_history_basic" in [line for line in setup_sh.splitlines() if line.startswith("MEMORY_ALLOWED_PROFILES=")][0]


# ---------------------------------------------------------------------------
# 4. Catalogue: DB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _make_case(db: Session) -> Case:
    case = Case(id=str(uuid4()), name="Shell History Phase 2", description="", status="open", mode="investigation")
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str, *, filename: str = "a.mem") -> Evidence:
    evidence = Evidence(
        id=str(uuid4()),
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=str(uuid4()),
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        path_validation={},
        ingest_source={},
        error_log={},
    )
    db.add(evidence)
    db.commit()
    return evidence


def test_shell_history_basic_is_in_the_catalogue() -> None:
    profiles = [item["profile"] for item in PROFILE_CATALOGUE]
    assert "shell_history_basic" in profiles
    entry = next(item for item in PROFILE_CATALOGUE if item["profile"] == "shell_history_basic")
    assert entry["title"] == "Shell History"
    assert entry["family"] == "shell_history"
    # linux.bash carries an explicit 1800s timeout (heap scan) -- the
    # catalogue must not claim "Fast" and mislead the analyst.
    assert entry["cost_label"] != "Fast"
    assert entry["est_duration_seconds"] == 1800


def test_catalogue_marks_shell_history_available_for_linux_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    fake_plan = _plan(PlatformFamily.LINUX, eligible=(MemoryCapability.SHELL_HISTORY,), selected=("linux.bash",))
    with patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=fake_plan), \
         patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["available"] is True
    assert item["gate_type"] == "available"
    assert item["plugins"] == ["linux.bash"]


def test_catalogue_marks_shell_history_unavailable_for_windows_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    fake_plan = _plan(PlatformFamily.WINDOWS, eligible=(), selected=())
    with patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=fake_plan), \
         patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["available"] is False
    assert item["gate_type"] == "unavailable"
    assert item["plugins"] == []
    assert "windows" in (item["availability_reason"] or "")
    # No fabricated Windows producer (windows.cmdscan/consoles) -- see
    # capability_registry.py, which has no CapabilityPluginSpec for
    # MemoryCapability.SHELL_HISTORY on PlatformFamily.WINDOWS.
    assert "windows.cmdscan" not in item["plugins"]
    assert "windows.consoles" not in item["plugins"]


def test_catalogue_other_profiles_unaffected_by_shell_history_addition(db: Session) -> None:
    """The 8 original profiles must keep using their platform-blind
    PROFILE_PLUGINS path unchanged -- only a profile absent from
    PROFILE_PLUGINS takes the new capability-registry branch."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    assert len(catalogue) == len(PROFILE_CATALOGUE) == 9
    network = next(i for i in catalogue if i["profile"] == "network_basic")
    assert network["plugins"] == ["windows.netscan", "windows.netstat"]


def test_catalogue_handles_missing_evidence_gracefully(db: Session) -> None:
    """If evidence somehow cannot be loaded, the capability-registry
    branch must degrade to unavailable, not raise and break the whole
    catalogue listing for every other profile."""
    case = _make_case(db)
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id="does-not-exist")
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["available"] is False


# ---------------------------------------------------------------------------
# 5. FAMILY_ORDER / active-result / counts
# ---------------------------------------------------------------------------


def test_shell_history_in_family_order_after_processes() -> None:
    assert "shell_history" in FAMILY_ORDER
    assert FAMILY_ORDER.index("shell_history") == FAMILY_ORDER.index("processes") + 1


def test_family_order_length_matches_catalogue_growth() -> None:
    # system_info, processes, shell_history, modules, handles,
    # kernel_modules, drivers, suspicious_regions, network, raw_observations
    assert len(FAMILY_ORDER) == 10


# ---------------------------------------------------------------------------
# 6. Initial analysis stays processes_basic only
# ---------------------------------------------------------------------------


def test_initial_analysis_profile_constant_is_unchanged() -> None:
    """MemoryInitialAnalysisAction.tsx is not touched by this phase; this
    is the backend-side half of that guarantee: create_memory_metadata_run's
    default profile is still metadata_only, never shell_history_basic."""
    from app.services.memory.execution import create_memory_metadata_run
    import inspect

    signature = inspect.signature(create_memory_metadata_run)
    assert signature.parameters["profile"].default == "metadata_only"


def test_start_memory_scan_request_default_profile_unchanged() -> None:
    from app.schemas.memory import MemoryStartScanRequest

    assert MemoryStartScanRequest().profile == "metadata_only"


# ---------------------------------------------------------------------------
# 7. Run-all is unaffected (documented, not modified)
# ---------------------------------------------------------------------------


def test_run_all_profiles_does_not_include_shell_history_basic() -> None:
    """RUN_ALL_PROFILES in batch.py is a separate, manually-curated tuple
    -- NOT derived from PROFILE_CATALOGUE. Adding shell_history_basic to
    the catalogue does not add it to run-all; it would need to be added
    to RUN_ALL_PROFILES explicitly in a future phase."""
    from app.services.memory.batch import RUN_ALL_PROFILES

    assert "shell_history_basic" not in RUN_ALL_PROFILES
    assert set(RUN_ALL_PROFILES) == {
        "metadata_only",
        "processes_basic",
        "processes_extended",
        "network_basic",
        "modules_basic",
        "handles_basic",
        "kernel_basic",
        "suspicious_memory",
    }
