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
import struct
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
    # Bounded requirement discovery: the adapter or the
    # discovery service has the exact symbol requirement, the
    # operator must seed the cache or approve a managed
    # acquisition.  Distinct from ``BLOCKED`` (the readiness
    # itself is OK) and from ``UNSUPPORTED`` (the platform is
    # Windows in every outcome).
    BLOCKED_SYMBOLS = "blocked_symbols"
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
    # When True, the preparation runtime should run a bounded
    # discovery step (e.g. a windows.info probe) to obtain the
    # exact symbol requirement before persisting a terminal
    # state.  Adapters that can already see a cache hit or a
    # persisted requirement leave this False; the runtime
    # short-circuits to ``ready`` or ``blocked`` without
    # re-running the probe.
    requires_discovery: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "error_code": self.error_code,
            "requirement_id": self.requirement_id,
            "metadata": dict(self.metadata),
            "requires_discovery": self.requires_discovery,
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


# Volatility layer magic numbers and format signatures.  These are
# read directly from the candidate file's first 4 KiB; nothing else
# is opened.
_WINDOWS_KDBG_MAGIC = b"KDBG"
_WINDOWS_CRASHDUMP_SIGNATURES: list[bytes] = [
    b"PAGE",
    b"DU64",
    b"MPHD",
    b"MAVS",
]
_HIBERNATION_SIGNATURES: list[bytes] = [
    b"HIBR",
    b"PAGEPG",
]
_LIME_MAGIC_BYTES = struct.pack("<I", 0x4C694D45)  # "LiME" little-endian
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

    The classifier recognises Windows crash dump signatures,
    Windows hibernation, KDBG kernel markers, LiME, ELF core,
    Linux banners and Mach-O macOS images.
    """
    if not head:
        return PlatformFamily.UNKNOWN, Architecture.UNKNOWN, ProbeConfidence.LOW, "empty_file"
    # Windows crash dump signatures (PAGE, DU64, MPHD, MAVS).
    # These are the canonical 4-byte identifiers at offset 0.
    for sig in _WINDOWS_CRASHDUMP_SIGNATURES:
        if head[:4] == sig:
            arch = Architecture.X64 if sig in (b"DU64",) else Architecture.UNKNOWN
            return PlatformFamily.WINDOWS, arch, ProbeConfidence.HIGH, f"crashdump_{sig.decode()}"
    # Windows hibernation file.
    for sig in _HIBERNATION_SIGNATURES:
        if head[:4] == sig:
            return PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.MEDIUM, "hibernation_signature"
    # LiME Linux memory format.
    if len(head) >= 4 and head[:4] == _LIME_MAGIC_BYTES:
        return PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.HIGH, "lime_signature"
    # ELF core dump.
    if head[:4] == b"\x7fELF":
        return PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.LOW, "elf_header"
    # Windows kernel: KDBG signature appears in the kernel
    # memory image regardless of compression.  This is a
    # strong marker in a Windows memory dump.
    if _WINDOWS_KDBG_MAGIC in head:
        return PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.MEDIUM, "kdbg_signature"
    # Linux banners typically start with the version string.
    if head.startswith(_LINUX_BANNER_PREFIX):
        return PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.MEDIUM, "linux_banner"
    # Mach-O header for macOS kernel images.
    if head.startswith(_MACOS_KERNEL_PREFIX):
        return PlatformFamily.MACOS, Architecture.X64, ProbeConfidence.MEDIUM, "macho_header"
    return PlatformFamily.UNKNOWN, Architecture.UNKNOWN, ProbeConfidence.LOW, "no_magic_match"


# ---------------------------------------------------------------------------
# Historical SHA-based classification
# ---------------------------------------------------------------------------


def _historical_platform_by_sha(sha256: str) -> tuple[PlatformFamily, Architecture, ProbeConfidence, str] | None:
    """Check whether the same SHA has a prior successful Windows metadata run.

    Returns ``(WINDOWS, X64, HIGH, "historical_sha")`` when the
    content digest matches a prior completed ``windows.info`` run.
    This prevents re-probing evidence that was already classified.
    """
    from app.core.database import SessionLocal
    from app.models.evidence import Evidence
    from app.models.memory import MemoryScanRun

    db = SessionLocal()
    try:
        prior = (
            db.query(Evidence)
            .filter(
                Evidence.sha256 == sha256,
                Evidence.evidence_type == "memory_dump",
            )
            .order_by(Evidence.created_at.desc())
            .first()
        )
        if prior is None:
            return None
        if prior.id is None:
            return None
        metadata_run = (
            db.query(MemoryScanRun)
            .filter(
                MemoryScanRun.evidence_id == prior.id,
                MemoryScanRun.profile.in_(["windows.info", "metadata_only"]),
                MemoryScanRun.status.in_(["completed", "completed_with_errors"]),
                MemoryScanRun.plugins_completed >= 1,
            )
            .order_by(MemoryScanRun.created_at.desc())
            .first()
        )
        if metadata_run is not None:
            return (PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.HIGH, "historical_sha")
        return None
    finally:
        db.close()


def _bounded_volatility_fallback(canonical_path: Path) -> MemoryProbeResult | None:
    """Run a bounded Volatility probe when static detection is inconclusive.

    The probe runs ``windows.info`` with a short timeout, no network,
    no symbol download, and no MemoryScanRun creation.  It returns a
    **WINDOWS** result if Volatility successfully constructs a Windows
    layer (regardless of symbol cache state), **LINUX** if a Linux
    banner is found, or **None** when the result is inconclusive or
    Volatility is unavailable.

    This fallback is only effective in the memory-worker process where
    Volatility 3 is installed.
    """
    try:
        import volatility3  # noqa: F401 – guard against missing dependency
    except ImportError:
        return None

    import subprocess
    import tempfile

    from app.core.config import get_settings
    from app.services.memory.volatility_runner import (
        VolatilityRunnerError,
        resolve_volatility_executable,
        run_plugin,
    )

    try:
        executable, _ = resolve_volatility_executable()
    except (VolatilityRunnerError, Exception):  # noqa: BLE001
        return None

    tmpdir = tempfile.mkdtemp(suffix="_vol_probe")
    try:
        work_dir = Path(tmpdir)
        work_dir.mkdir(parents=True, exist_ok=True)

        # Attempt Windows probe first.
        win_result = _run_volatility_plugin_bounded(
            "windows.info", executable, canonical_path, work_dir
        )
        if win_result is not None:
            return win_result

        # Fall back to Linux banner probe.
        linux_result = _run_volatility_plugin_bounded(
            "linux.banners", executable, canonical_path, work_dir
        )
        if linux_result is not None:
            return linux_result

        return None
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _run_volatility_plugin_bounded(
    plugin: str,
    executable: str,
    evidence_path: Path,
    work_dir: Path,
) -> MemoryProbeResult | None:
    """Run a single Volatility plugin and return a platform verdict.

    Returns ``None`` when the plugin fails or produces no usable
    classification.
    """
    import subprocess

    settings = get_settings()
    timeout = min(30, int(getattr(settings, "memory_plugin_timeout_seconds", 120)))

    env = dict(_minimal_volatility_env())
    argv = [
        executable,
        "--offline",
        "-f",
        str(evidence_path),
        "-r",
        "json",
        plugin,
    ]

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            shell=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    stdout = (result.stdout or b"").decode("utf-8", errors="replace")
    stderr = (result.stderr or b"").decode("utf-8", errors="replace").lower()
    combined_lower = (stdout + "\n" + stderr).lower()

    if "windows" in combined_lower and ("layer" in combined_lower or "ntoskrnl" in combined_lower or "windows" in stdout):
        return MemoryProbeResult(
            platform=PlatformFamily.WINDOWS,
            format=f"volatility_{plugin}",
            architecture=Architecture.X64,
            confidence=ProbeConfidence.MEDIUM,
            reason=f"volatility_{plugin}_windows",
        )

    if "linux_banner" in combined_lower or ("linux" in combined_lower and "banner" in combined_lower):
        return MemoryProbeResult(
            platform=PlatformFamily.LINUX,
            format=f"volatility_{plugin}",
            architecture=Architecture.X64,
            confidence=ProbeConfidence.MEDIUM,
            reason=f"volatility_{plugin}_linux",
        )

    # ``no suitable layer`` or ``unsupported image`` → inconclusive.
    return None


def _minimal_volatility_env() -> dict[str, str]:
    """Build a minimal environment for the Volatility subprocess.

    Copies PATH and XDG_CACHE_HOME from the current process so the
    worker's symbol cache and offline mode work correctly.
    """
    env: dict[str, str] = {}
    for key in ("PATH", "HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP"):
        value = __import__("os").environ.get(key)
        if value:
            env[key] = value
    env["VOLATILITY_OFFLINE"] = "1"
    return env


# ---------------------------------------------------------------------------
# Generic factory
# ---------------------------------------------------------------------------


def probe_memory_platform(
    *,
    canonical_path: Path,
    detected_format: str | None = None,
    filename: str | None = None,
    use_volatility_fallback: bool = False,
    evidence: Any | None = None,
) -> MemoryProbeResult:
    """Run the bounded platform probe and return the result.

    Detection stages (short-circuits on first match):

    1. **Magic bytes** — reads the first 4 KiB and checks for
       Windows crash dump, hibernation, LiME, ELF, KDBG, Linux
       banner, and Mach‑O signatures.

    2. **detected_format** — when the upload probe already
       classified the file, reuse its verdict as a strong signal.
       Known format strings: ``windows_crash_dump``,
       ``hibernation``, ``lime``, ``elf_core``, ``vmware_vmem``.

    3. **Historical SHA** — if the same content digest has a
       prior successful preparation or metadata run, reuse its
       platform classification.

    4. **Volatility fallback** (worker only) — when
       ``use_volatility_fallback=True`` and Volatility 3 is
       importable, run a bounded ``windows.info`` / ``linux.banners``
       probe to identify the OS family.  No MemoryScanRun is
       created; no symbols are downloaded; no network access.

    The probe is always read-only and bounded.
    """
    head = _read_head(canonical_path)
    family, arch, confidence, reason = _classify_from_head(head)
    fmt = (detected_format or "").strip() or "unknown"

    # Stage 2: detected_format (upload probe result).
    if family == PlatformFamily.UNKNOWN and detected_format:
        fmt_lower = detected_format.lower().strip()
        if fmt_lower in ("windows_crash_dump",):
            family, arch, confidence = PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.HIGH
            reason = f"detected_format:{fmt_lower}"
        elif fmt_lower in ("hibernation",):
            family, arch, confidence = PlatformFamily.WINDOWS, Architecture.X64, ProbeConfidence.MEDIUM
            reason = f"detected_format:{fmt_lower}"
        elif fmt_lower in ("lime",):
            family, arch, confidence = PlatformFamily.LINUX, Architecture.X64, ProbeConfidence.HIGH
            reason = f"detected_format:{fmt_lower}"
        elif fmt_lower in ("elf_core",):
            family, arch, confidence = PlatformFamily.LINUX, Architecture.UNKNOWN, ProbeConfidence.MEDIUM
            reason = f"detected_format:{fmt_lower}"
        elif fmt_lower in ("vmware_vmem",):
            family, arch, confidence = PlatformFamily.WINDOWS, Architecture.UNKNOWN, ProbeConfidence.MEDIUM
            reason = f"detected_format:{fmt_lower}"

    # Stage 3: Historical SHA match (prior successful preparation).
    if family == PlatformFamily.UNKNOWN and evidence is not None:
        from app.models.evidence import Evidence as _Evidence
        if isinstance(evidence, _Evidence):
            sha = getattr(evidence, "sha256", None)
            if sha:
                hist = _historical_platform_by_sha(sha)
                if hist is not None:
                    family, arch, confidence, reason = hist

    # Stage 4: Volatility bounded fallback (worker process only).
    if family == PlatformFamily.UNKNOWN and use_volatility_fallback:
        vol_result = _bounded_volatility_fallback(canonical_path)
        if vol_result is not None:
            return vol_result

    # Filename hint as a tie breaker (never changes UNKNOWN).
    if family == PlatformFamily.UNKNOWN and filename:
        lowered = filename.lower()
        if re.search(r"\.(dmp|mem|raw|img|lime)$", lowered):
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
        # symbol requirement.  The preparation runtime runs a
        # bounded ``windows.info`` discovery step, persists the
        # requirement, and re-evaluates the cache.
        return ReadinessResult(
            state=ReadinessState.BLOCKED,
            reason="windows_probe_required",
            error_code="WINDOWS_PROBE_REQUIRED",
            metadata={"probe_confidence": probe.confidence.value},
            requires_discovery=True,
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

    The probe returned UNKNOWN — the OS family could not be
    determined.  The adapter closes the preparation as
    ``platform_not_identified`` so the UI can distinguish
    "unsupported OS" from "could not determine OS".
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
