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


def test_raw_candidate_does_not_resolve_a_platform() -> None:
    """"raw_candidate" is what the ingest detector writes when it finds no
    signature in the first 1 MiB. It is a non-answer, so it must not sit in
    the table that lets a stored format resolve a platform on its own -- that
    membership is what decides whether the worker probe may overwrite it."""
    from app.services.memory.platform import PLATFORM_RESOLVING_FORMATS

    assert "raw_candidate" not in PLATFORM_RESOLVING_FORMATS
    assert "linux_banner_scan" in PLATFORM_RESOLVING_FORMATS


def test_probe_memory_platform_stays_unknown_for_raw_candidate(tmp_path: Path) -> None:
    """A Linux raw dump is stored as detected_format="raw_candidate". On its
    own that must leave the platform unknown, so the deeper banner scan is the
    thing that identifies the image."""
    image = tmp_path / "victoria.img"
    image.write_bytes(b"\x00" * 8192)

    result = probe_memory_platform(
        canonical_path=image,
        detected_format="raw_candidate",
        use_volatility_fallback=False,
    )

    assert result.platform is PlatformFamily.UNKNOWN


def test_worker_probe_overwrites_an_inconclusive_stored_format() -> None:
    """The regression this file's raw_candidate cases describe: the worker
    probe identified Linux from the kernel banner, but the stored
    "raw_candidate" was non-empty, so its result was discarded and the static
    re-probe reported PLATFORM_NOT_IDENTIFIED on every one of many retries."""
    from app.services.memory.preparation_runtime import _probe_may_overwrite_detected_format

    assert _probe_may_overwrite_detected_format("raw_candidate", "linux") is True
    assert _probe_may_overwrite_detected_format(None, "linux") is True
    assert _probe_may_overwrite_detected_format("", "linux") is True

    # A format that already identifies a platform stands.
    assert _probe_may_overwrite_detected_format("linux_banner_scan", "linux") is False
    assert _probe_may_overwrite_detected_format("windows_crash_dump", "windows") is False

    # An inconclusive probe never overwrites anything.
    assert _probe_may_overwrite_detected_format("raw_candidate", "unknown") is False
    assert _probe_may_overwrite_detected_format("raw_candidate", None) is False


def test_banner_scan_carries_the_kernel_identity_it_read(tmp_path: Path) -> None:
    """The scan already reads the release and the full banner out of the
    image. They must travel as fields, because they are what lets an uploaded
    ISF be checked against this dump -- encoding them only inside the
    human-readable reason string left the identity unavailable, readiness
    stuck on kernel_identity_unknown, and any ISF accepted unchecked."""
    image = tmp_path / "raw.img"
    banner = b"Linux version 2.6.26-2-686 (Debian 2.6.26-29) (dannf@debian.org) #1 SMP\x00"
    image.write_bytes(b"\x00" * (2 * 1024 * 1024) + banner)

    result = _bounded_linux_banner_scan(image)

    assert result is not None
    assert result.kernel_release == "2.6.26-2-686"
    assert result.kernel_banner is not None
    assert result.kernel_banner.startswith("Linux version 2.6.26-2-686")


def test_recorded_kernel_identity_is_read_back_as_a_required_identity(tmp_path: Path) -> None:
    """The shape execute_memory_preparation writes must be the shape
    expected_linux_identity_from_evidence reads, or resolve_linux_symbols
    still has nothing to match an uploaded ISF against."""
    from types import SimpleNamespace

    from app.services.memory.linux_symbols import expected_linux_identity_from_evidence

    evidence = SimpleNamespace(
        metadata_json={
            "linux_kernel": {
                "kernel_release": "2.6.26-2-686",
                "banner": "Linux version 2.6.26-2-686 (Debian 2.6.26-29)",
                "architecture": "x86",
            }
        }
    )

    identity = expected_linux_identity_from_evidence(evidence)

    assert identity is not None
    assert identity.kernel_release == "2.6.26-2-686"
    assert identity.banner is not None


def test_no_recorded_kernel_identity_stays_unknown() -> None:
    from types import SimpleNamespace

    from app.services.memory.linux_symbols import expected_linux_identity_from_evidence

    assert expected_linux_identity_from_evidence(SimpleNamespace(metadata_json={})) is None
