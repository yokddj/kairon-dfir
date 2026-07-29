"""Regression coverage for platform-aware memory plugin routing.

Covers the sprint that fixed Linux memory evidence running Windows
Volatility plugins. app.services.memory.analysis_plan.build_memory_analysis_plan
is the single choke point between platform detection
(app.services.memory.platform) and plugin selection
(app.services.memory.capability_registry); these tests pin down its
mandatory guarantees:

* Linux evidence never selects a windows.* plugin.
* Windows evidence never selects a linux.* plugin.
* Unknown-platform evidence selects nothing and is never silently
  treated as Windows.
* A platform mismatch is recorded with a typed reason distinct from a
  genuine missing-symbols outcome.
* app.services.memory.execution.resolve_profile_plugins enforces the
  same gate for the existing (Windows-shaped) profile API.

Evidence fixtures here are synthetic, generic byte patterns (real
Volatility magic-byte signatures or plain zero bytes) -- never a CTF
image, filename, hostname, or IP.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.memory.analysis_plan import build_memory_analysis_plan
from app.services.memory.capability_registry import (
    MEMORY_CAPABILITY_REGISTRY,
    MemoryCapability,
    SkipReason,
    resolved_plugins_for_capability,
)
from app.services.memory.execution import (
    PROFILE_CAPABILITY,
    PROFILE_PLUGINS,
    MemoryExecutionValidationError,
    resolve_profile_plugins,
)
from app.services.memory.platform import PlatformFamily, ProbeConfidence, ReadinessState


def _evidence(*, id_: str = "ev-1", detected_format: str | None = None, original_filename: str = "sample.img") -> SimpleNamespace:
    return SimpleNamespace(
        id=id_,
        detected_format=detected_format,
        original_filename=original_filename,
        display_name=None,
        filename=None,
        stored_path="/nonexistent-evidence-path",
        metadata_json={},
    )


def _linux_evidence_identity() -> dict:
    return {"linux_symbol_identity": {"architecture": "x64", "kernel_release": "6.8.0-test", "build_id": "build-a"}}


def _write(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# build_memory_analysis_plan: the mandatory routing guarantees
# ---------------------------------------------------------------------------


def test_linux_evidence_never_selects_windows_plugins(tmp_path: Path) -> None:
    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")

    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    assert plan.detected_platform == PlatformFamily.LINUX
    assert plan.selected_plugins, "expected at least one selected Linux plugin"
    assert all(not plugin.startswith("windows.") for plugin in plan.selected_plugins)
    assert all(plugin.startswith("linux.") for plugin in plan.selected_plugins)


def test_windows_evidence_never_selects_linux_plugins(tmp_path: Path) -> None:
    path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
    evidence = _evidence(detected_format=None)

    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    assert plan.detected_platform == PlatformFamily.WINDOWS
    assert plan.selected_plugins, "expected at least one selected Windows plugin"
    assert all(not plugin.startswith("linux.") for plugin in plan.selected_plugins)
    assert all(plugin.startswith("windows.") for plugin in plan.selected_plugins)


def test_windows_plan_never_calls_linux_symbol_resolver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import analysis_plan as analysis_plan_module

    def _fail(*args, **kwargs):
        raise AssertionError("Windows planning must not call Linux symbol resolution")

    monkeypatch.setattr(analysis_plan_module, "resolve_linux_symbols", _fail)
    path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
    evidence = _evidence(detected_format=None)

    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    assert plan.detected_platform == PlatformFamily.WINDOWS
    assert all(plugin.startswith("windows.") for plugin in plan.selected_plugins)


def test_unknown_platform_selects_no_plugins_and_never_defaults_to_windows(tmp_path: Path) -> None:
    path = _write(tmp_path, "ambiguous.raw", b"\x00" * 4096)
    evidence = _evidence(detected_format=None)

    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    assert plan.detected_platform == PlatformFamily.UNKNOWN
    assert plan.readiness == ReadinessState.PLATFORM_UNKNOWN
    assert plan.selected_plugins == ()
    assert plan.eligible_capabilities == ()


def test_invalid_evidence_path_selects_no_plugins(tmp_path: Path) -> None:
    """A storage-access failure must degrade to "no plugins", not a guess."""
    evidence = SimpleNamespace(
        id="ev-invalid",
        detected_format=None,
        original_filename="unreadable.dmp",
        display_name=None,
        filename=None,
        stored_path=str(tmp_path / "does-not-exist.dmp"),
        storage_mode=None,
    )

    plan = build_memory_analysis_plan(evidence)

    assert plan.detected_platform in (PlatformFamily.UNKNOWN,)
    assert plan.readiness in (ReadinessState.INVALID_EVIDENCE, ReadinessState.PLATFORM_UNKNOWN)
    assert plan.selected_plugins == ()


def test_macos_evidence_selects_no_plugins_but_is_distinguished_from_unknown(tmp_path: Path) -> None:
    path = _write(tmp_path, "macos.img", b"Mach-O" + b"\x00" * 4090)
    evidence = _evidence(detected_format=None)

    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    assert plan.detected_platform == PlatformFamily.MACOS
    assert plan.readiness == ReadinessState.PLATFORM_UNSUPPORTED
    assert plan.selected_plugins == ()


def test_requesting_a_capability_absent_for_the_platform_is_platform_mismatch_not_symbols(tmp_path: Path) -> None:
    """Phase 4 requirement: an incompatible plugin must be recorded as a
    platform mismatch, never confused with a genuine symbols-unavailable
    outcome."""
    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")

    plan = build_memory_analysis_plan(
        evidence,
        canonical_path=path,
        requested_capabilities=[MemoryCapability.HANDLES],  # Windows-only capability
    )

    assert plan.detected_platform == PlatformFamily.LINUX
    assert plan.eligible_capabilities == ()
    assert plan.ineligible_capabilities == ((MemoryCapability.HANDLES, SkipReason.PLATFORM_MISMATCH),)
    assert plan.readiness != ReadinessState.BLOCKED_SYMBOLS


def test_linux_process_capability_reports_blocked_symbols_when_no_isf_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real, verified readiness: with no Linux ISF cache on disk, a
    genuinely-eligible Linux capability must be reported as
    symbol-blocked rather than silently claimed ready."""
    from app.services.memory import analysis_plan as analysis_plan_module

    cache_root = tmp_path / "volatility-cache"
    (cache_root / "symbols" / "windows").mkdir(parents=True)  # Windows populated, Linux absent
    monkeypatch.setattr(
        analysis_plan_module,
        "get_settings",
        lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root),
    )

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")

    plan = build_memory_analysis_plan(evidence, canonical_path=path, requested_capabilities=[MemoryCapability.PROCESSES])

    assert plan.detected_platform == PlatformFamily.LINUX
    assert MemoryCapability.PROCESSES in plan.eligible_capabilities
    assert plan.readiness == ReadinessState.BLOCKED_SYMBOLS
    assert plan.symbol_status["reason_code"] == "kernel_identity_unknown"
    assert "linux.pslist" in plan.selected_plugins


def test_linux_process_capability_reports_unavailable_when_identity_known_but_cache_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import analysis_plan as analysis_plan_module

    cache_root = tmp_path / "volatility-cache"
    (cache_root / "symbols" / "linux").mkdir(parents=True)
    monkeypatch.setattr(
        analysis_plan_module,
        "get_settings",
        lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root),
    )

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")
    evidence.metadata_json = _linux_evidence_identity()

    plan = build_memory_analysis_plan(evidence, canonical_path=path, requested_capabilities=[MemoryCapability.PROCESSES])

    assert plan.readiness == ReadinessState.BLOCKED_SYMBOLS
    assert plan.symbol_status["reason_code"] == "symbols_unavailable"


def test_linux_process_readiness_distinguishes_plugins_from_missing_symbols(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routes_memory import _memory_capability_readiness
    from app.services.memory import analysis_plan as analysis_plan_module

    cache_root = tmp_path / "volatility-cache"
    (cache_root / "symbols" / "windows").mkdir(parents=True)
    monkeypatch.setattr(
        analysis_plan_module,
        "get_settings",
        lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root),
    )

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")
    evidence.metadata_json = _linux_evidence_identity()
    plan = build_memory_analysis_plan(evidence, canonical_path=path, requested_capabilities=[MemoryCapability.PROCESSES])

    readiness = _memory_capability_readiness(
        plan,
        {
            "supported_plugins": ["linux.pslist", "linux.pstree"],
            "plugins": {
                "linux.pslist": {"state": "available"},
                "linux.pstree": {"state": "available"},
            },
        },
        {"can_analyze": True},
    )

    processes = readiness["processes"]
    assert processes["registered"] is True
    assert processes["framework_plugin_available"] is True
    assert processes["platform_supported"] is True
    assert processes["evidence_supported"] is True
    assert processes["symbols_required"] is True
    assert processes["symbols_found"] is False
    assert processes["ready"] is False
    assert processes["reason"] == "symbols_unavailable"


def test_linux_process_capability_ready_when_isf_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import analysis_plan as analysis_plan_module
    from app.services.memory.linux_symbols import import_linux_isf

    cache_root = tmp_path / "volatility-cache"
    linux_symbols = cache_root / "symbols" / "linux"
    linux_symbols.mkdir(parents=True)
    source_isf = tmp_path / "some-kernel.json"
    source_isf.write_text('{"metadata":{"linux":{"kernel_release":"6.8.0-test","architecture":"x64","build_id":"build-a"}},"symbols":{},"types":{}}')
    import_linux_isf(
        source_isf,
        original_filename="some-kernel.json",
        settings=SimpleNamespace(
            memory_native_probe_cache_path=cache_root,
            memory_linux_symbol_manual_import_enabled=True,
            memory_linux_symbol_isf_upload_max_bytes=1024 * 1024,
        ),
    )
    monkeypatch.setattr(
        analysis_plan_module,
        "get_settings",
        lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root),
    )

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")
    evidence.metadata_json = _linux_evidence_identity()

    plan = build_memory_analysis_plan(evidence, canonical_path=path, requested_capabilities=[MemoryCapability.PROCESSES])

    assert plan.readiness == ReadinessState.READY
    assert "6.8.0-test" in plan.symbol_status["symbol_identity"]


def test_linux_process_readiness_exposes_symbol_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api import routes_memory
    from app.services.memory import analysis_plan as analysis_plan_module
    from app.services.memory.linux_symbols import import_linux_isf

    cache_root = tmp_path / "volatility-cache"
    source_isf = tmp_path / "kernel.json"
    source_isf.write_text('{"metadata":{"linux":{"kernel_release":"6.8.0-test","architecture":"x64","build_id":"build-a"}},"symbols":{},"types":{}}')
    settings = SimpleNamespace(
        memory_native_probe_cache_path=cache_root,
        memory_linux_symbol_manual_import_enabled=True,
        memory_linux_symbol_external_download_enabled=False,
        memory_linux_symbol_isf_upload_max_bytes=1024 * 1024,
    )
    import_linux_isf(source_isf, original_filename="kernel.json", settings=settings)
    monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: settings)
    monkeypatch.setattr(routes_memory, "get_settings", lambda: settings)

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")
    evidence.metadata_json = _linux_evidence_identity()
    plan = build_memory_analysis_plan(evidence, canonical_path=path, requested_capabilities=[MemoryCapability.PROCESSES])
    readiness = routes_memory._memory_capability_readiness(
        plan,
        {"supported_plugins": ["linux.pslist", "linux.pstree"]},
        {"can_analyze": True},
    )

    processes = readiness["processes"]
    assert processes["symbols_found"] is True
    assert processes["symbol_source"] == "manual_upload"
    assert "6.8.0-test" in processes["symbol_identity"]
    assert processes["manual_upload_available"] is True
    assert processes["external_download_enabled"] is False
    assert processes["reason_code"] == "ready"


# ---------------------------------------------------------------------------
# Capability registry: no plugin is declared under the wrong platform
# ---------------------------------------------------------------------------


def test_registry_never_binds_a_windows_plugin_name_to_linux_or_vice_versa() -> None:
    for spec in MEMORY_CAPABILITY_REGISTRY:
        if spec.platform == PlatformFamily.WINDOWS:
            assert spec.plugin.startswith("windows."), spec.plugin
        elif spec.platform == PlatformFamily.LINUX:
            assert not spec.plugin.startswith("windows."), spec.plugin


def test_resolved_plugins_for_capability_reproduces_legacy_profile_plugins_exactly() -> None:
    """resolved_plugins_for_capability(WINDOWS, ...) must exactly
    reconstruct every existing profile's plugin list and order -- the
    registry replaces execution.PROFILE_PLUGINS as the source of truth,
    it must not silently change behavior for the platform that already
    worked."""
    for profile, capability in PROFILE_CAPABILITY.items():
        resolved = resolved_plugins_for_capability(PlatformFamily.WINDOWS, capability)
        assert resolved == PROFILE_PLUGINS[profile], profile


# ---------------------------------------------------------------------------
# execution.resolve_profile_plugins: the existing profile-based API
# ---------------------------------------------------------------------------


def test_resolve_profile_plugins_maps_process_profile_to_linux_process_capability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import Settings
    from app.services.memory import backend_readiness

    enabled_settings = Settings()
    object.__setattr__(enabled_settings, "memory_process_profile_enabled", True)
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: enabled_settings)

    path = _write(tmp_path, "linux.img", b"\x7fELF" + b"\x00" * 4092)
    evidence = _evidence(detected_format="elf_core")
    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    plugins = resolve_profile_plugins("processes_basic", plan=plan)

    assert plugins == ["linux.pslist", "linux.pstree"]
    assert all(not plugin.startswith("windows.") for plugin in plugins)


def test_resolve_profile_plugins_rejects_windows_profile_for_unknown_plan(tmp_path: Path) -> None:
    path = _write(tmp_path, "ambiguous.raw", b"\x00" * 4096)
    evidence = _evidence(detected_format=None)
    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    with pytest.raises(MemoryExecutionValidationError) as exc_info:
        resolve_profile_plugins("metadata_only", plan=plan)

    assert exc_info.value.code == "PROFILE_CAPABILITY_UNAVAILABLE"
    # The unknown platform must never be silently substituted for Windows.
    assert plan.detected_platform != PlatformFamily.WINDOWS


def test_resolve_profile_plugins_accepts_windows_profile_for_windows_plan(tmp_path: Path) -> None:
    path = _write(tmp_path, "windows.dmp", b"PAGEDU64" + b"\x00" * 4088)
    evidence = _evidence(detected_format=None)
    plan = build_memory_analysis_plan(evidence, canonical_path=path)

    plugins = resolve_profile_plugins("metadata_only", plan=plan)

    assert plugins == ["windows.info"]
