"""Regression tests for the symbol-independent Linux kernel banner scan.

Context: `linux.pslist` (Volatility's cheapest real Linux plugin) requires
compatible ISF symbols to already be cached just to walk kernel structures
at all -- for a never-before-seen kernel (no symbols cached yet) it always
fails, regardless of whether the image really is Linux. That is a genuine
circular dependency: you need symbols to identify the kernel, but you need
to identify the kernel to know which symbols to ask for. Before this fix,
a raw/headerless dump (e.g. a VMware .vmem with no magic-byte signature)
with no pre-cached symbols could never be classified as Linux at all.

The fix adds `_bounded_linux_banner_scan`: a direct, bounded scan of the
raw image bytes for the embedded Linux kernel banner string ("Linux
version X.Y.Z-... #N ...", from init/version.c/linux_banner) -- the same
zero-symbols technique real forensic tooling (`strings | grep "Linux
version"`) uses to identify an unknown kernel -- plus a `probe_memory_platform`
stage-2 branch that reuses a persisted `linux_banner_scan` detected_format
without re-scanning the image.
"""
from __future__ import annotations

from pathlib import Path

from app.services.memory.platform import (
    Architecture,
    PlatformFamily,
    ProbeConfidence,
    _bounded_linux_banner_scan,
    probe_memory_platform,
)


def test_banner_scan_finds_kernel_release_at_arbitrary_offset(tmp_path: Path) -> None:
    image = tmp_path / "raw.vmem"
    banner = b"Linux version 6.5.0-41-generic (buildd@lcy02-amd64-119) (x86_64-linux-gnu-gcc-12) #41-Ubuntu SMP PREEMPT_DYNAMIC\x00"
    # Real dumps put the kernel's data section at an arbitrary physical
    # offset, not at the start of the file.
    padding = b"\x00" * (3 * 1024 * 1024)
    image.write_bytes(padding + banner + padding)

    result = _bounded_linux_banner_scan(image)

    assert result is not None
    assert result.platform is PlatformFamily.LINUX
    assert result.format == "linux_banner_scan"
    assert result.architecture is Architecture.X64
    assert result.confidence is ProbeConfidence.MEDIUM
    assert result.reason == "linux_banner_scan:6.5.0-41-generic"


def test_banner_scan_returns_none_when_no_banner_present(tmp_path: Path) -> None:
    image = tmp_path / "not_linux.vmem"
    image.write_bytes(b"\x00" * (1024 * 1024))

    assert _bounded_linux_banner_scan(image) is None


def test_banner_scan_returns_none_for_missing_file(tmp_path: Path) -> None:
    assert _bounded_linux_banner_scan(tmp_path / "does-not-exist.vmem") is None


def test_probe_memory_platform_reuses_persisted_banner_scan_format(tmp_path: Path) -> None:
    """Stage 2: a prior worker-side banner-scan success, persisted onto the
    evidence as detected_format="linux_banner_scan", must resolve to Linux
    on a later call -- even from the backend process, where Volatility 3 is
    not installed and the stage-4 fallback is a no-op."""
    image = tmp_path / "raw.vmem"
    image.write_bytes(b"\x00" * 8192)  # no magic bytes -- stage 1 is UNKNOWN

    result = probe_memory_platform(
        canonical_path=image,
        detected_format="linux_banner_scan",
        use_volatility_fallback=False,
    )

    assert result.platform is PlatformFamily.LINUX
    assert result.reason == "detected_format:linux_banner_scan"


def test_probe_memory_platform_stays_unknown_without_banner_or_format_hint(tmp_path: Path) -> None:
    image = tmp_path / "raw.vmem"
    image.write_bytes(b"\x00" * 8192)

    result = probe_memory_platform(
        canonical_path=image,
        detected_format=None,
        use_volatility_fallback=False,
    )

    assert result.platform is PlatformFamily.UNKNOWN
