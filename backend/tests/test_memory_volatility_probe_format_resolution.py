"""Regression test for a real, always-reproducing memory-analysis stall.

Found investigating a case whose 5GB raw memory dump (`memdump.mem` -- a
plain physical-memory acquisition with no self-describing magic bytes,
unlike a crash dump/hiberfil/VMware snapshot) sat at ingest_status
"completed" with zero artifacts and a memory_symbol_preparations row stuck
at state="platform_not_identified" after 14 identical retries.

Root cause: preparation_runtime.py's worker-side probe correctly identifies
the platform via probe_memory_platform(..., use_volatility_fallback=True)
-- confirmed directly against the real evidence: `vol ... windows.info`
succeeds and reports a real Windows 10 x64 kernel. That result gets
persisted onto evidence.detected_format as "volatility_windows.info" (see
_run_volatility_plugin_bounded's `format=f"volatility_{plugin}"`
convention). The very next step in the same preparation run then calls
probe_memory_platform() *again*, this time without the Volatility fallback
(stage 4 skipped), relying entirely on stage 2 (detected_format) to resolve
the platform from that persisted string -- but PLATFORM_RESOLVING_FORMATS
had no entry for "volatility_windows.info" (or "volatility_linux.pslist"),
so stage 2 fell through, platform stayed UNKNOWN, and the readiness check
routed to UnsupportedMemoryAdapter -- PLATFORM_NOT_IDENTIFIED -- forever,
deterministically, on every single retry, despite the platform genuinely
being known and already recorded.
"""

from __future__ import annotations

from pathlib import Path

from app.services.memory.platform import (
    Architecture,
    PlatformFamily,
    ProbeConfidence,
    get_adapter_for_probe,
    probe_memory_platform,
)


def test_probe_memory_platform_resolves_a_persisted_volatility_windows_format(tmp_path: Path) -> None:
    image = tmp_path / "raw.mem"
    image.write_bytes(b"\x00" * 8192)  # no magic bytes -- stage 1 is UNKNOWN

    result = probe_memory_platform(
        canonical_path=image,
        detected_format="volatility_windows.info",
        use_volatility_fallback=False,
    )

    assert result.platform is PlatformFamily.WINDOWS
    assert result.architecture is Architecture.X64
    assert result.confidence is ProbeConfidence.MEDIUM
    assert result.reason == "detected_format:volatility_windows.info"


def test_probe_memory_platform_resolves_a_persisted_volatility_linux_format(tmp_path: Path) -> None:
    image = tmp_path / "raw.mem"
    image.write_bytes(b"\x00" * 8192)

    result = probe_memory_platform(
        canonical_path=image,
        detected_format="volatility_linux.pslist",
        use_volatility_fallback=False,
    )

    assert result.platform is PlatformFamily.LINUX


def test_resolved_volatility_windows_format_routes_to_the_windows_adapter(tmp_path: Path) -> None:
    """The actual failure mode: get_adapter_for_probe must not fall back to
    UnsupportedMemoryAdapter (PLATFORM_NOT_IDENTIFIED) once the platform is
    already known from a persisted Volatility probe format."""
    image = tmp_path / "raw.mem"
    image.write_bytes(b"\x00" * 8192)

    probe_result = probe_memory_platform(
        canonical_path=image,
        detected_format="volatility_windows.info",
        use_volatility_fallback=False,
    )
    adapter = get_adapter_for_probe(probe_result)

    assert adapter.platform is PlatformFamily.WINDOWS
