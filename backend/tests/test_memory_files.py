"""Memory Files: browsable windows.filescan preview list.

Mirrors the shell_history_basic (windows.consoles) buildout: a
capability-registry-only profile (files_basic -> MemoryCapability.FILES
-> windows.filescan on Windows, no Linux producer), persisting the full
filescan result as a searchable memory_file_object family instead of
discarding it the way the separate on-demand "recover this exact file"
action (app.services.memory.file_extraction) already does per request.
"""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.memory import catalogue as catalogue_module
from app.services.memory.active_result import FAMILY_RESOLUTION, resolve_active_memory_result
from app.services.memory.analysis_plan import MemoryAnalysisPlan
from app.services.memory.capability_registry import MemoryCapability
from app.services.memory.catalogue import PROFILE_CATALOGUE, _supported_os_families, build_analysis_catalogue
from app.services.memory.counts import FAMILY_TO_DOCUMENT_TYPE
from app.services.memory.execution import (
    PROFILE_CAPABILITY,
    PROFILE_PLUGINS,
    _normalize_artifact_payload,
    backend_readiness,
    resolve_profile_plugins,
)
from app.services.memory.platform import PlatformFamily, ProbeConfidence, ReadinessState
from app.services.memory.validation import MemoryExecutionValidationError


CASE = "case-files"
EVIDENCE = "ev-files"
RUN = "run-files"


def _settings_with_process_profiles_enabled() -> Settings:
    base = Settings()
    object.__setattr__(base, "memory_process_profile_enabled", True)
    return base


@pytest.fixture(autouse=True)
def _enable_process_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    # resolve_profile_plugins (execution.py) and _plan_capability_registry_profile
    # (catalogue.py) each resolve settings through a different reference --
    # both must be patched or files_basic (a "process profile", not
    # metadata_only) raises PROCESS_PROFILE_DISABLED before this test's own
    # logic is even reached. Mirrors test_memory_shell_history_phase2.py.
    monkeypatch.setattr(backend_readiness, "get_settings", _settings_with_process_profiles_enabled)
    monkeypatch.setattr(catalogue_module, "get_settings", _settings_with_process_profiles_enabled)


def _filescan_rows() -> list[dict]:
    return [
        {"Offset": "0x1000", "Name": "\\Windows\\System32\\cmd.exe"},
        {"Offset": "0x2000", "Name": "\\Users\\victim\\Desktop\\f\\p.ps1"},
    ]


# ---------------------------------------------------------------------------
# Normalizer dispatch
# ---------------------------------------------------------------------------


def test_windows_filescan_no_longer_falls_into_unsupported_artifact_plugin() -> None:
    result = _normalize_artifact_payload(
        "windows.filescan",
        _filescan_rows(),
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:windows.filescan",
    )
    assert not any("unsupported_artifact_plugin" in w for w in result["warnings"])
    assert result["items"][0]["document_type"] == "memory_file_object"


def test_windows_filescan_n_rows_yields_n_items() -> None:
    result = _normalize_artifact_payload(
        "windows.filescan",
        _filescan_rows(),
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:windows.filescan",
    )
    assert result["accepted_count"] == 2
    names = {item["name"] for item in result["items"]}
    assert names == {"\\Windows\\System32\\cmd.exe", "\\Users\\victim\\Desktop\\f\\p.ps1"}
    assert all(item["platform"] == "windows" for item in result["items"])
    assert all(item["process_entity_id"] is None for item in result["items"])


def test_windows_filescan_zero_rows_is_completed_empty_not_an_error() -> None:
    result = _normalize_artifact_payload(
        "windows.filescan",
        [],
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:windows.filescan",
    )
    assert result["raw_count"] == 0
    assert result["accepted_count"] == 0
    assert result["items"] == []
    assert result["warnings"] == []


def test_windows_filescan_row_missing_name_is_dropped_not_silently_lost() -> None:
    rows = [{"Offset": "0x1000", "Name": None}, {"Offset": None, "Name": ""}]
    result = _normalize_artifact_payload(
        "windows.filescan",
        rows,
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:windows.filescan",
    )
    assert result["raw_count"] == 2
    assert result["accepted_count"] == 0
    assert result["dropped_count"] == 2
    assert "filescan_row_missing_name" in result["warnings"]


def test_windows_filescan_duplicate_offset_and_name_collapses_to_one_document() -> None:
    """Offset+Name is the identity (no PID exists for a file object) --
    the same file object reported twice in one run must not duplicate."""
    rows = [
        {"Offset": "0x1000", "Name": "\\Windows\\System32\\cmd.exe"},
        {"Offset": "0x1000", "Name": "\\Windows\\System32\\cmd.exe"},
    ]
    result = _normalize_artifact_payload(
        "windows.filescan",
        rows,
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:windows.filescan",
    )
    assert result["accepted_count"] == 2
    document_ids = {item["document_id"] for item in result["items"]}
    assert len(document_ids) == 1


# ---------------------------------------------------------------------------
# Capability registration / profile resolution
# ---------------------------------------------------------------------------


def test_files_basic_registered_in_profile_capability() -> None:
    assert PROFILE_CAPABILITY["files_basic"] == MemoryCapability.FILES


def test_files_basic_has_no_profile_plugins_entry() -> None:
    assert "files_basic" not in PROFILE_PLUGINS


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


def test_windows_resolves_windows_info_then_windows_filescan() -> None:
    """windows.info is prepended: FILES depends_on IDENTIFICATION, same
    dependency-expansion PROCESSES/SHELL_HISTORY already use."""
    from app.services.memory.capability_registry import resolved_plugins_for_capability

    assert resolved_plugins_for_capability(PlatformFamily.WINDOWS, MemoryCapability.FILES) == ["windows.info", "windows.filescan"]


def test_windows_resolves_exactly_windows_filescan_via_resolve_profile_plugins() -> None:
    plan = _plan(PlatformFamily.WINDOWS, eligible=(MemoryCapability.FILES,), selected=("windows.filescan",))
    assert resolve_profile_plugins("files_basic", plan=plan) == ["windows.filescan"]


def test_linux_has_no_files_producer() -> None:
    from app.services.memory.capability_registry import resolved_plugins_for_capability

    assert resolved_plugins_for_capability(PlatformFamily.LINUX, MemoryCapability.FILES) == []


def test_files_basic_unknown_profile_check_still_works() -> None:
    with pytest.raises(MemoryExecutionValidationError) as exc_info:
        resolve_profile_plugins("not_a_real_profile", plan=None)
    assert exc_info.value.code == "UNKNOWN_PROFILE"


# ---------------------------------------------------------------------------
# Allowed profiles (config)
# ---------------------------------------------------------------------------


def test_allowed_profiles_includes_files_basic() -> None:
    settings = Settings()
    assert "files_basic" in settings.allowed_memory_profiles


def test_allowed_plugins_includes_windows_filescan() -> None:
    settings = Settings()
    assert "windows.filescan" in settings.allowed_memory_plugins


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _make_case(db: Session) -> Case:
    case = Case(id=str(uuid4()), name="Files Feature", description="", status="open", mode="investigation")
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str) -> Evidence:
    evidence = Evidence(
        id=str(uuid4()),
        case_id=case_id,
        original_filename="a.mem",
        stored_path="/tmp/a.mem",
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


def test_files_basic_is_in_the_catalogue() -> None:
    profiles = [item["profile"] for item in PROFILE_CATALOGUE]
    assert "files_basic" in profiles
    entry = next(item for item in PROFILE_CATALOGUE if item["profile"] == "files_basic")
    assert entry["title"] == "Files"
    assert entry["family"] == "files"
    assert entry["cost_label"] != "Fast"


def test_files_basic_supported_os_families_is_windows_only() -> None:
    assert set(_supported_os_families("files_basic")) == {"windows"}


def test_catalogue_shows_windows_filescan_on_windows_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    fake_plan = _plan(PlatformFamily.WINDOWS, eligible=(MemoryCapability.FILES,), selected=("windows.filescan",))
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=fake_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "files_basic")
    assert item["available"] is True
    assert item["plugins"] == ["windows.filescan"]


def test_catalogue_stays_unavailable_on_linux_evidence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    linux_plan = _plan(PlatformFamily.LINUX, eligible=(), selected=())
    settings = _settings_with_process_profiles_enabled()
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}), \
         patch("app.services.memory.catalogue.build_memory_analysis_plan", return_value=linux_plan), \
         patch("app.services.memory.catalogue.get_settings", return_value=settings):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    item = next(i for i in catalogue if i["profile"] == "files_basic")
    assert item["available"] is False
    assert item["plugins"] == []


# ---------------------------------------------------------------------------
# Family resolution / active-result
# ---------------------------------------------------------------------------


def test_files_is_a_registered_family() -> None:
    assert "files" in FAMILY_RESOLUTION
    rules = FAMILY_RESOLUTION["files"]
    assert rules["evidence_id_required"] is True
    assert "memory_file_object" in rules["fallback_doc_types"]


def test_files_to_document_type_mapping() -> None:
    assert FAMILY_TO_DOCUMENT_TYPE["files"] == "memory_file_object"


def test_files_no_run_is_not_analyzed(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="files")
    assert result["analysis_state"] == "not_analyzed"
    assert result["active_run"] is None


# ---------------------------------------------------------------------------
# Run-all stays unaffected (documented, not modified) -- files_basic is a
# heavy, image-wide, on-demand-style scan, same reasoning as
# shell_history_basic staying out of the bulk "run everything" pass.
# ---------------------------------------------------------------------------


def test_run_all_profiles_does_not_include_files_basic() -> None:
    from app.services.memory.batch import RUN_ALL_PROFILES

    assert "files_basic" not in RUN_ALL_PROFILES
