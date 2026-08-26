"""Registry consistency guards for the Memory analysis catalogue.

Sprint 3 (Memory Technical Debt Cleanup) audit found that Memory's
several parallel "which profile/plugin/platform" registries (
``PROFILE_CATALOGUE``, ``PROFILE_CAPABILITY``, ``PROFILE_PLUGINS``,
``capability_registry``, ``Settings.allowed_memory_profiles``) are
largely consistent today, but nothing pins that down -- the one real
drift found (network_basic's ``supported_os_families`` claiming
Windows-only after Sprint 1 added real Linux support) went unnoticed
for a full sprint. Per the user's explicit preference, this adds
central consistency tests rather than a structural rewrite.
"""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.memory.analysis_plan import MemoryAnalysisPlan
from app.services.memory.capability_registry import MemoryCapability
from app.services.memory.catalogue import PROFILE_CATALOGUE, _supported_os_families, build_analysis_catalogue
from app.services.memory.execution import PROFILE_CAPABILITY
from app.services.memory.platform import PlatformFamily, ProbeConfidence, ReadinessState


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_case(db: Session) -> Case:
    case = Case(id=str(uuid4()), name="registry-consistency", mode="investigation")
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str, *, filename: str = "ev.dmp") -> Evidence:
    ev = Evidence(
        id=str(uuid4()),
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db.add(ev)
    db.commit()
    return ev


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


def _settings_with_process_profiles_enabled(*, allowed_profiles: str | None = None) -> Settings:
    base = get_settings()
    object.__setattr__(base, "memory_process_profile_enabled", True)
    if allowed_profiles is not None:
        object.__setattr__(base, "memory_allowed_profiles", allowed_profiles)
    return base


# ---------------------------------------------------------------------------
# 1. Every catalogue profile has a real capability mapping
# ---------------------------------------------------------------------------


def test_every_catalogue_profile_exists_in_profile_capability() -> None:
    for profile_def in PROFILE_CATALOGUE:
        assert profile_def["profile"] in PROFILE_CAPABILITY, (
            f"{profile_def['profile']} is in PROFILE_CATALOGUE but has no "
            f"PROFILE_CAPABILITY entry -- it can never resolve a plugin."
        )


# ---------------------------------------------------------------------------
# 2. supported_os_families (as actually returned by the API) matches the
#    platforms that genuinely have a capability_registry producer -- this
#    is the exact guard that would have caught network_basic's drift.
# ---------------------------------------------------------------------------


def test_supported_os_families_matches_real_capability_registry_producers() -> None:
    from app.services.memory.capability_registry import resolved_plugins_for_capability

    for profile_def in PROFILE_CATALOGUE:
        profile = profile_def["profile"]
        capability = PROFILE_CAPABILITY[profile]
        expected = {
            platform.value
            for platform in (PlatformFamily.WINDOWS, PlatformFamily.LINUX, PlatformFamily.MACOS)
            if resolved_plugins_for_capability(platform, capability)
        }
        actual = set(_supported_os_families(profile))
        assert actual == expected, f"{profile}: supported_os_families {actual} != real producers {expected}"


def test_network_basic_supported_os_families_includes_linux() -> None:
    """The exact drift this sprint found and fixed: network_basic's
    displayed platform support must reflect Sprint 1's real Linux
    support (linux.sockstat), not the pre-Sprint-1 Windows-only claim."""
    assert set(_supported_os_families("network_basic")) == {"windows", "linux"}


def test_shell_history_basic_supported_os_families_includes_windows_and_linux() -> None:
    assert set(_supported_os_families("shell_history_basic")) == {"windows", "linux"}


# ---------------------------------------------------------------------------
# 3. allowed_memory_profiles' own hardcoded set must not drift from
#    PROFILE_CATALOGUE's real profile list.
# ---------------------------------------------------------------------------


def test_allowed_memory_profiles_accepts_every_catalogue_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    catalogue_profiles = {item["profile"] for item in PROFILE_CATALOGUE}
    settings = get_settings()
    object.__setattr__(settings, "memory_allowed_profiles", ",".join(sorted(catalogue_profiles)))
    assert set(settings.allowed_memory_profiles) == catalogue_profiles, (
        "Settings.allowed_memory_profiles' internal allow-list has drifted from "
        "PROFILE_CATALOGUE -- a real profile would be silently rejected even "
        "if an operator explicitly requested it."
    )


# ---------------------------------------------------------------------------
# 4-7. Real per-platform catalogue resolution for the two capability-only /
# capability-aware-despite-legacy profiles this sprint touched.
# ---------------------------------------------------------------------------


def test_network_basic_catalogue_shows_linux_sockstat_on_linux_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    linux_plan = _plan(PlatformFamily.LINUX, eligible=(MemoryCapability.NETWORK,), selected=("linux.sockstat",))
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=linux_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "network_basic")
    assert item["plugins"] == ["linux.sockstat"]
    assert item["available"] is True


def test_network_basic_catalogue_shows_real_windows_plugins_on_windows_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    windows_plan = _plan(PlatformFamily.WINDOWS, eligible=(MemoryCapability.NETWORK,), selected=("windows.netscan", "windows.netstat"))
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=windows_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "network_basic")
    assert item["plugins"] == ["windows.netscan", "windows.netstat"]
    assert item["available"] is True


def test_shell_history_basic_catalogue_shows_linux_bash_on_linux_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    linux_plan = _plan(PlatformFamily.LINUX, eligible=(MemoryCapability.SHELL_HISTORY,), selected=("linux.bash",))
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=linux_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["plugins"] == ["linux.bash"]
    assert item["available"] is True


def test_shell_history_basic_catalogue_shows_windows_consoles_on_windows_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    windows_plan = _plan(PlatformFamily.WINDOWS, eligible=(MemoryCapability.SHELL_HISTORY,), selected=("windows.consoles",))
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=windows_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["plugins"] == ["windows.consoles"]
    assert item["available"] is True


def test_shell_history_basic_catalogue_stays_unavailable_when_evidence_plan_finds_nothing_eligible(db: Session) -> None:
    """Not a structural Windows gap -- capability_registry does have a
    windows.consoles producer for MemoryCapability.SHELL_HISTORY (see the
    test above). This covers a per-evidence plan that itself resolved no
    eligible capability."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    windows_plan = _plan(PlatformFamily.WINDOWS, eligible=(), selected=())
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=windows_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "shell_history_basic")
    assert item["available"] is False
    assert item["plugins"] == []
