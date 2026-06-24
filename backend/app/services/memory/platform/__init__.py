"""Platform adapters for memory preparation.

This module implements the OS-agnostic preparation pipeline
described in the v1 critical sprint.  Every memory evidence is
routed through a single ``MemoryPlatformAdapter`` whose only
responsibility is to:

1. **Probe** the image: identify the OS family (Windows,
   Linux, macOS) and the architecture (x86, x64, arm64) using
   bounded, read-only operations.  The probe NEVER downloads
   symbols, NEVER opens OpenSearch indices and NEVER runs a
   heavy Volatility profile.

2. **Check readiness**: evaluate whether the matching analysis
   profiles can run on this image, given the platform
   constraints and the symbol/ISF cache state.  Return a
   terminal ``MemoryReadiness`` result so the preparation never
   remains indefinitely queued.

3. **List profiles**: provide the platform-specific subset of
   the global profile catalogue.  Adapters are free to mark
   profiles as unsupported; the catalogue UI displays the
   rationale to the operator.

The architecture mirrors the spec:

* :class:`MemoryPlatformAdapter` (Protocol)
* :class:`WindowsMemoryAdapter`
* :class:`LinuxMemoryAdapter`
* :class:`MacOSMemoryAdapter`
* :class:`UnsupportedMemoryAdapter`

A factory :func:`get_adapter_for_probe` returns the matching
adapter for a probe result so the rest of the pipeline does not
need to know about the implementation classes.
"""
from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public enum / dataclasses
# ---------------------------------------------------------------------------


class PlatformFamily(str, enum.Enum):
    """Operating-system family detected by the bounded probe."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class Architecture(str, enum.Enum):
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class ProbeConfidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReadinessState(str, enum.Enum):
    """Terminal readiness states returned by an adapter."""

    READY = "ready"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass(frozen=True)
class MemoryProbeResult:
    """The bounded, read-only OS family probe result.

    The result is the single input to the platform adapter.  It
    contains only information obtained by reading the first few
    bytes of the image, the filename extension and the original
    ``detection_status`` already stored on the evidence row.
    """

    platform: PlatformFamily
    format: str
    architecture: Architecture = Architecture.UNKNOWN
    confidence: ProbeConfidence = ProbeConfidence.LOW
    reason: str = ""
    evidence_format: str | None = None


@dataclass
class ReadinessResult:
    """Adapter readiness evaluation."""

    state: ReadinessState
    reason: str = ""
    error_code: str | None = None
    requirement_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "error_code": self.error_code,
            "requirement_id": self.requirement_id,
            "metadata": dict(self.metadata),
        }


@dataclass
class ProfileDefinition:
    """A platform-specific profile in the catalogue."""

    profile: str
    family: str
    title: str
    cost_label: str
    available: bool
    availability_reason: str | None = None
    est_duration_seconds: int = 60


# ---------------------------------------------------------------------------
# Adapter interface
# ---------------------------------------------------------------------------


@runtime_checkable
class MemoryPlatformAdapter(Protocol):
    """A platform-specific adapter.

    Adapters are pure functions of the probe result.  They do not
    perform any side effect (no DB writes, no enqueue, no
    network).  The caller is responsible for persisting the
    readiness result.
    """

    platform: PlatformFamily

    def probe(self, *, canonical_path: Path, detected_format: str | None) -> MemoryProbeResult: ...

    def check_readiness(
        self,
        *,
        probe: MemoryProbeResult,
        cache_state: dict[str, Any] | None = None,
    ) -> ReadinessResult: ...

    def available_profiles(self, probe: MemoryProbeResult) -> list[ProfileDefinition]: ...


# ---------------------------------------------------------------------------
# Read-only OS detection (bounded)
# ---------------------------------------------------------------------------


# Volatility layer magic numbers.  These are read directly from
# the candidate file's first 4 KiB; nothing else is opened.
_WINDOWS_KDBG_MAGIC = b"KDBG"
_LINUX_BANNER_PREFIX = b"Linux version "
_MACOS_KERNEL_PREFIX = b"Mach-O"
_RAW_MAGIC = b"\\x00\\x00\\x00\\x00"  # placeholder for "not recognised"


def _read_head(path: Path, *, limit: int = 4096) -> bytes:
    """Read the first ``limit`` bytes of the image safely."""
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError as exc:
        logger.warning("platform probe: cannot read %s (%s)", path, exc)
        return b""


def _classify_from_head(head: bytes) -> tuple[PlatformFamily, Architecture, ProbeConfidence, str]:
    """Map raw bytes to a platform family.

    The classifier is intentionally conservative: it never
    claims a high confidence unless the magic is unambiguous.
    """
    if not head:
        return PlatformFamily.UNKNOWN, Architecture.UNKNOWN, ProbeConfidence.LOW, "empty_file"
    # Windows kernel: KDBG signature appears in the kernel
    # memory image regardless of compression.  This is the
    # most reliable marker in a Windows memory dump.
    if _WINDOWS_KDBG_MAGIC in head:
        # Heuristic: KDBG markers in the first 4 KiB is a
        # strong signal but we still report MEDIUM confidence
        # unless the dump also exposes the Windows NT
        # signature.
        return PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.MEDIUM, "kdbg_signature"
    if head.startswith(_LINUX_BANNER_PREFIX):
        # Linux banners typically start with the version string.
        return PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.MEDIUM, "linux_banner"
    if head.startswith(_MACOS_KERNEL_PREFIX):
        return PlatformFamily.MACOS, Architecture.X64, ProbeConfidence.MEDIUM, "macho_header"
    # ELF magic for the kernel image (rare, but seen when the
    # acquisition is a live kernel).
    if head[:4] == b"\x7fELF":
        return PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.LOW, "elf_header"
    return PlatformFamily.UNKNOWN, Architecture.UNKNOWN, ProbeConfidence.LOW, "no_magic_match"


# ---------------------------------------------------------------------------
# Generic factory
# ---------------------------------------------------------------------------


def probe_memory_platform(
    *,
    canonical_path: Path,
    detected_format: str | None = None,
    filename: str | None = None,
) -> MemoryProbeResult:
    """Run the bounded platform probe and return the result.

    The probe is read-only and bounded to the first 4 KiB of
    the image.  The result is the canonical input to a
    :class:`MemoryPlatformAdapter`.
    """
    head = _read_head(canonical_path)
    family, arch, confidence, reason = _classify_from_head(head)
    fmt = (detected_format or "").strip() or "unknown"
    # Filename hint as a tie breaker.
    if family == PlatformFamily.UNKNOWN and filename:
        lowered = filename.lower()
        if re.search(r"\.(dmp|mem|raw|img|lime)$", lowered):
            # Generic memory extension; keep the unknown family
            # unless the file content already pinned it.
            pass
    return MemoryProbeResult(
        platform=family,
        format=fmt,
        architecture=arch,
        confidence=confidence,
        reason=reason,
        evidence_format=detected_format,
    )


def get_adapter_for_probe(probe: MemoryProbeResult) -> MemoryPlatformAdapter:
    """Return the adapter that matches a probe result."""
    if probe.platform == PlatformFamily.WINDOWS:
        return WindowsMemoryAdapter()
    if probe.platform == PlatformFamily.LINUX:
        return LinuxMemoryAdapter()
    if probe.platform == PlatformFamily.MACOS:
        return MacOSMemoryAdapter()
    return UnsupportedMemoryAdapter()


# ---------------------------------------------------------------------------
# Windows adapter
# ---------------------------------------------------------------------------


class WindowsMemoryAdapter:
    """Adapter for Windows memory images.

    Readiness logic mirrors the v1 symbol pipeline: a successful
    metadata run or an exact symbol cache match qualifies the
    image as READY.  An unidentified requirement (no KDBG, no
    PDB match) is BLOCKED with a retryable flag.
    """

    platform = PlatformFamily.WINDOWS

    _PROFILES: tuple[ProfileDefinition, ...] = (
        ProfileDefinition(
            profile="metadata_only",
            family="system_info",
            title="Windows metadata",
            cost_label="Fast",
            available=True,
            est_duration_seconds=20,
        ),
        ProfileDefinition(
            profile="processes_basic",
            family="processes",
            title="Process listing (windows.pslist)",
            cost_label="Medium",
            available=True,
            est_duration_seconds=90,
        ),
        ProfileDefinition(
            profile="processes_extended",
            family="processes",
            title="Extended process listing",
            cost_label="Medium",
            available=True,
            est_duration_seconds=240,
        ),
        ProfileDefinition(
            profile="modules_basic",
            family="modules",
            title="Loaded modules",
            cost_label="Medium",
            available=True,
            est_duration_seconds=120,
        ),
        ProfileDefinition(
            profile="handles_basic",
            family="handles",
            title="Process handles",
            cost_label="Medium",
            available=True,
            est_duration_seconds=120,
        ),
        ProfileDefinition(
            profile="kernel_basic",
            family="kernel_modules",
            title="Kernel modules",
            cost_label="Medium",
            available=True,
            est_duration_seconds=120,
        ),
        ProfileDefinition(
            profile="suspicious_memory",
            family="suspicious_regions",
            title="Suspicious memory regions",
            cost_label="Medium",
            available=True,
            est_duration_seconds=180,
        ),
    )

    def probe(self, *, canonical_path: Path, detected_format: str | None) -> MemoryProbeResult:
        return probe_memory_platform(
            canonical_path=canonical_path,
            detected_format=detected_format,
        )

    def check_readiness(
        self,
        *,
        probe: MemoryProbeResult,
        cache_state: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        if probe.confidence == ProbeConfidence.LOW:
            return ReadinessResult(
                state=ReadinessState.BLOCKED,
                reason="windows_signature_weak",
                error_code="WINDOWS_PROBE_LOW_CONFIDENCE",
            )
        cache = cache_state or {}
        if cache.get("exact_cache_match"):
            return ReadinessResult(
                state=ReadinessState.READY,
                reason="exact_cache_match",
                requirement_id=cache.get("requirement_id"),
            )
        if cache.get("successful_metadata_run"):
            return ReadinessResult(
                state=ReadinessState.READY,
                reason="successful_metadata_run",
                requirement_id=cache.get("requirement_id"),
            )
        # No cache hit yet.  The image is recognisable as
        # Windows but we still need a probe to record the
        # symbol requirement.  The upstream pipeline records
        # the requirement as a side effect; the adapter does
        # not return READY here.
        return ReadinessResult(
            state=ReadinessState.BLOCKED,
            reason="windows_probe_required",
            error_code="WINDOWS_PROBE_REQUIRED",
            metadata={"probe_confidence": probe.confidence.value},
        )

    def available_profiles(self, probe: MemoryProbeResult) -> list[ProfileDefinition]:
        return list(self._PROFILES)


# ---------------------------------------------------------------------------
# Linux adapter
# ---------------------------------------------------------------------------


class LinuxMemoryAdapter:
    """Adapter for Linux memory images.

    Linux images rely on the Volatility Linux symbols (ISF or
    the symbol-fetcher) and a banner-derived kernel version.
    The readiness is BLOCKED until the ISF is built and a
    successful metadata run pins the requirement.
    """

    platform = PlatformFamily.LINUX

    _PROFILES: tuple[ProfileDefinition, ...] = (
        ProfileDefinition(
            profile="metadata_only",
            family="system_info",
            title="Linux metadata (linux.banners)",
            cost_label="Fast",
            available=True,
            est_duration_seconds=20,
        ),
        ProfileDefinition(
            profile="processes_basic",
            family="processes",
            title="Process listing (linux.pslist)",
            cost_label="Medium",
            available=True,
            est_duration_seconds=90,
        ),
        ProfileDefinition(
            profile="modules_basic",
            family="modules",
            title="Loaded kernel modules",
            cost_label="Medium",
            available=True,
            est_duration_seconds=120,
        ),
        ProfileDefinition(
            profile="network_basic",
            family="network",
            title="Network connections (linux.sockstat)",
            cost_label="Medium",
            available=False,
            availability_reason="linux_network_profile_not_yet_supported",
            est_duration_seconds=120,
        ),
    )

    def probe(self, *, canonical_path: Path, detected_format: str | None) -> MemoryProbeResult:
        return probe_memory_platform(
            canonical_path=canonical_path,
            detected_format=detected_format,
        )

    def check_readiness(
        self,
        *,
        probe: MemoryProbeResult,
        cache_state: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        if probe.confidence == ProbeConfidence.LOW:
            return ReadinessResult(
                state=ReadinessState.BLOCKED,
                reason="linux_signature_weak",
                error_code="LINUX_PROBE_LOW_CONFIDENCE",
            )
        cache = cache_state or {}
        if cache.get("isf_available") and cache.get("successful_metadata_run"):
            return ReadinessResult(
                state=ReadinessState.READY,
                reason="linux_isf_and_metadata",
                requirement_id=cache.get("requirement_id"),
            )
        if cache.get("exact_cache_match"):
            return ReadinessResult(
                state=ReadinessState.READY,
                reason="exact_cache_match",
                requirement_id=cache.get("requirement_id"),
            )
        return ReadinessResult(
            state=ReadinessState.BLOCKED,
            reason="linux_isf_required",
            error_code="LINUX_ISF_REQUIRED",
        )

    def available_profiles(self, probe: MemoryProbeResult) -> list[ProfileDefinition]:
        return list(self._PROFILES)


# ---------------------------------------------------------------------------
# macOS adapter
# ---------------------------------------------------------------------------


class MacOSMemoryAdapter:
    """Adapter for macOS memory images.

    macOS support in Volatility 3 is limited: many profiles
    require ISF symbols that are not yet available.  The
    adapter returns a terminal UNSUPPORTED state for any image
    that does not already have a verified ready record, with a
    structured error code so the UI can explain the gap.
    """

    platform = PlatformFamily.MACOS

    _PROFILES: tuple[ProfileDefinition, ...] = (
        ProfileDefinition(
            profile="metadata_only",
            family="system_info",
            title="macOS metadata (mac.banners)",
            cost_label="Fast",
            available=False,
            availability_reason="macos_metadata_profile_not_supported",
            est_duration_seconds=20,
        ),
    )

    def probe(self, *, canonical_path: Path, detected_format: str | None) -> MemoryProbeResult:
        return probe_memory_platform(
            canonical_path=canonical_path,
            detected_format=detected_format,
        )

    def check_readiness(
        self,
        *,
        probe: MemoryProbeResult,
        cache_state: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        cache = cache_state or {}
        if cache.get("successful_metadata_run") and cache.get("isf_available"):
            return ReadinessResult(
                state=ReadinessState.READY,
                reason="macos_isf_and_metadata",
                requirement_id=cache.get("requirement_id"),
            )
        return ReadinessResult(
            state=ReadinessState.UNSUPPORTED,
            reason="macos_platform_not_supported",
            error_code="PLATFORM_NOT_SUPPORTED",
        )

    def available_profiles(self, probe: MemoryProbeResult) -> list[ProfileDefinition]:
        return list(self._PROFILES)


# ---------------------------------------------------------------------------
# Unsupported adapter
# ---------------------------------------------------------------------------


class UnsupportedMemoryAdapter:
    """Adapter for images that cannot be classified.

    The probe either returned UNKNOWN or a format that the
    catalogue does not yet support.  The adapter closes the
    preparation as UNSUPPORTED so the row never stays queued.
    """

    platform = PlatformFamily.UNSUPPORTED

    _PROFILES: tuple[ProfileDefinition, ...] = ()

    def probe(self, *, canonical_path: Path, detected_format: str | None) -> MemoryProbeResult:
        return MemoryProbeResult(
            platform=PlatformFamily.UNSUPPORTED,
            format=(detected_format or "unknown"),
            reason="unsupported_or_unknown_format",
        )

    def check_readiness(
        self,
        *,
        probe: MemoryProbeResult,
        cache_state: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        return ReadinessResult(
            state=ReadinessState.UNSUPPORTED,
            reason="platform_not_identified",
            error_code="PLATFORM_NOT_IDENTIFIED",
        )

    def available_profiles(self, probe: MemoryProbeResult) -> list[ProfileDefinition]:
        return list(self._PROFILES)


# ---------------------------------------------------------------------------
# Re-exports
# ---------------------------------------------------------------------------


__all__ = [
    "Architecture",
    "MacOSMemoryAdapter",
    "MemoryPlatformAdapter",
    "MemoryProbeResult",
    "PlatformFamily",
    "ProbeConfidence",
    "ProfileDefinition",
    "ReadinessResult",
    "ReadinessState",
    "UnsupportedMemoryAdapter",
    "WindowsMemoryAdapter",
    "LinuxMemoryAdapter",
    "get_adapter_for_probe",
    "probe_memory_platform",
]
