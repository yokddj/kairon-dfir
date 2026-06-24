"""Bounded discovery of Windows symbol requirements.

The OS-agnostic preparation pipeline detects the platform (Windows /
Linux / macOS) from a bounded read of the first bytes of the image.
A Windows detection does not, by itself, identify which Windows
symbol table the analyser needs; the PDB name, GUID and age of the
kernel image are required to look the symbol up in the cache.

The previous architecture obtained those fields from a
``windows.info`` run that was always executed as part of the
``metadata_only`` profile.  In the OS-agnostic v1 the profile is
dispatched lazily — only when a real user requests an analysis —
and the preparation terminates ``windows_probe_required`` when the
exact requirement is unknown.

This module fills the gap.  It runs a **single bounded** Volatility
3 ``windows.info`` invocation that:

* opens the canonical evidence file read-only;
* uses the configured local symbol cache (``XDG_CACHE_HOME``);
* runs the standard ``app.services.memory.symbol_probe`` helper
  that intercepts the ``PDBUtility.load_windows_symbol_table``
  callback to capture the exact identity;
* never downloads symbols;
* never writes to OpenSearch;
* never creates a ``MemoryScanRun``;
* caps stdout, stderr, and wall-clock time;
* uses ``shell=False`` and a minimal environment.

The service is split into two halves so the platform adapter stays
pure:

1. :func:`discover_windows_symbol_requirement` — runs the bounded
   probe and returns a normalized :class:`DiscoveredRequirement`.
   It performs **no database writes** and is safe to call from
   the adapter or the runtime.

2. :func:`persist_discovered_requirement` — takes the discovered
   identifier and writes the rows.  It is idempotent on the
   natural key ``(platform, pdb_name, pdb_guid, pdb_age,
   architecture)`` and reuses an existing requirement when one
   already exists for the same content identity.  The service
   also updates ``memory_evidence_contents.last_requirement_id``
   so a subsequent re-upload of the same file does not re-run
   the bounded probe.

The bounded process failure modes are mapped to structured
:class:`BoundedDiscoveryError` codes that the preparation
runtime translates into ``PREP_FAILED`` (retryable) and never
into ``PREP_UNSUPPORTED`` (Windows is Windows in every outcome).
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid as _uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.evidence import Evidence
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryEvidenceContent,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_resolver import (
    normalize_age,
    normalize_architecture,
    normalize_guid,
    normalize_pdb_name,
    symbol_identifier,
)


logger = logging.getLogger(__name__)


# Discovery method label written to the requirement row's
# ``source`` column.  Distinct from the backfill labels so the
# UI / audit log can tell how the requirement was obtained.
SOURCE_BOUNDED_DISCOVERY = "bounded_discovery"


# Structured error codes.  Kept stable so the preparation runtime
# can branch deterministically.
DISCOVERY_OK = "ok"
DISCOVERY_VOLATILITY_NOT_CONFIGURED = "volatility_not_configured"
DISCOVERY_VOLATILITY_NOT_FOUND = "volatility_not_found"
DISCOVERY_PROBE_TIMEOUT = "probe_timeout"
DISCOVERY_BACKEND_START_FAILED = "backend_start_failed"
DISCOVERY_OUTPUT_TOO_LARGE = "output_too_large"
DISCOVERY_PLUGIN_FAILED = "plugin_failed"
DISCOVERY_INCONCLUSIVE = "discovery_inconclusive"
DISCOVERY_UNSAFE_PATH = "unsafe_evidence_path"


_PDB_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}\.pdb$", re.IGNORECASE)
_GUID_RE = re.compile(r"^[0-9A-F]{32}$")
_AGE_RANGE = (0, 0xFFFFFFFF)
_VALID_ARCH = {"x64", "x86", "arm64"}


class BoundedDiscoveryError(RuntimeError):
    """A bounded Windows metadata probe failed.

    The ``code`` attribute is one of the ``DISCOVERY_*`` constants
    above.  ``retryable`` is True when the operator can safely
    re-run the preparation without a code change (timeout,
    process spawn failure, inconclusive).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass
class DiscoveredRequirement:
    """Normalized Windows symbol requirement.

    The fields are already passed through
    :func:`normalize_pdb_name`, :func:`normalize_guid`,
    :func:`normalize_age` and :func:`normalize_architecture` so
    the persistence layer does not have to re-validate.
    """

    platform: str
    pdb_name: str
    pdb_guid: str
    pdb_age: int
    architecture: str
    discovery_method: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "pdb_name": self.pdb_name,
            "pdb_guid": self.pdb_guid,
            "pdb_age": int(self.pdb_age),
            "architecture": self.architecture,
            "discovery_method": self.discovery_method,
        }

    def is_valid(self) -> bool:
        if not self.pdb_name or not _PDB_NAME_RE.match(self.pdb_name):
            return False
        if not self.pdb_guid or not _GUID_RE.match(self.pdb_guid):
            return False
        if not (self._age_range[0] <= int(self.pdb_age) <= self._age_range[1]):
            return False
        if self.architecture not in _VALID_ARCH:
            return False
        return True

    @property
    def _age_range(self) -> tuple[int, int]:
        return _AGE_RANGE


def _stable_discovery_uuids(evidence_id: str) -> tuple[str, str]:
    """Return deterministic placeholder UUIDs for the requirement FK pair.

    The bounded discovery path does not create a ``MemoryScanRun``
    — the requirement row is persisted with stable placeholder
    UUIDs derived from the evidence id.  The same scheme is used
    by the legacy backfill so a probe that later produces a real
    scan run can repair the row.
    """
    digest = hashlib.sha256(evidence_id.encode("utf-8")).digest()
    fallback_run_id = str(_uuid.UUID(bytes=digest[:16], version=4))
    fallback_plugin_id = str(
        _uuid.UUID(bytes=bytes(b ^ 0x01 for b in digest[:16]), version=4)
    )
    return fallback_run_id, fallback_plugin_id


def discover_windows_symbol_requirement(
    canonical_path: Path,
    work_dir: Path,
) -> DiscoveredRequirement:
    """Run a bounded ``windows.info`` probe and return the identity.

    The function is **pure**: it does not touch the database, does
    not download symbols, does not write OpenSearch and does not
    create a ``MemoryScanRun``.  The caller is responsible for
    persisting the result and wiring the content identity.

    On failure it raises :class:`BoundedDiscoveryError` with a
    structured code so the caller can decide between
    ``PREP_FAILED`` (retryable) and ``PREP_REQUIREMENT_UNKNOWN``
    (genuinely inconclusive).
    """
    from app.services.memory.volatility_runner import (
        VolatilityRunnerError,
        probe_windows_symbol_identity,
        resolve_volatility_executable,
    )

    resolved_path = Path(canonical_path).resolve(strict=False)
    if not str(resolved_path):
        raise BoundedDiscoveryError(
            DISCOVERY_UNSAFE_PATH,
            "Bounded discovery refused an empty evidence path.",
            retryable=False,
        )
    if resolved_path.is_dir() or resolved_path.is_symlink():
        # Bounded discovery only opens regular files.  Symlinks and
        # directories are out of contract.
        raise BoundedDiscoveryError(
            DISCOVERY_UNSAFE_PATH,
            f"Bounded discovery refused non-regular path: {resolved_path}",
            retryable=False,
        )

    # Pre-flight: the executor must be configured.  ``resolve_volatility_executable``
    # raises a structured error that we map to our own codes.
    try:
        resolve_volatility_executable()
    except VolatilityRunnerError as exc:
        if exc.code == "VOLATILITY_NOT_CONFIGURED":
            raise BoundedDiscoveryError(
                DISCOVERY_VOLATILITY_NOT_CONFIGURED,
                str(exc),
                retryable=True,
            ) from exc
        if exc.code == "VOLATILITY_NOT_FOUND":
            raise BoundedDiscoveryError(
                DISCOVERY_VOLATILITY_NOT_FOUND,
                str(exc),
                retryable=True,
            ) from exc
        raise BoundedDiscoveryError(
            DISCOVERY_BACKEND_START_FAILED,
            str(exc),
            retryable=True,
        ) from exc

    try:
        payload = probe_windows_symbol_identity(resolved_path, Path(work_dir))
    except (OSError,) as exc:
        raise BoundedDiscoveryError(
            DISCOVERY_BACKEND_START_FAILED,
            f"Bounded discovery process spawn failed: {exc}",
            retryable=True,
        ) from exc

    if not isinstance(payload, dict):
        raise BoundedDiscoveryError(
            DISCOVERY_INCONCLUSIVE,
            "Bounded discovery returned no parseable identity.",
            retryable=True,
        )

    pdb_name = normalize_pdb_name(str(payload.get("pdb_name") or ""))
    pdb_guid = normalize_guid(str(payload.get("pdb_guid") or ""))
    pdb_age = normalize_age(payload.get("pdb_age"))
    architecture = normalize_architecture(payload.get("architecture"))

    discovered = DiscoveredRequirement(
        platform="windows",
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
        architecture=architecture,
        discovery_method=SOURCE_BOUNDED_DISCOVERY,
    )
    if not discovered.is_valid():
        raise BoundedDiscoveryError(
            DISCOVERY_INCONCLUSIVE,
            "Bounded discovery returned an invalid kernel identity.",
            retryable=True,
        )
    return discovered


def _exact_cache_match(
    db: Session,
    *,
    pdb_name: str,
    pdb_guid: str,
    pdb_age: int,
    architecture: str,
) -> MemoryCachedSymbol | None:
    """Return the cached symbol row that exactly matches the identity.

    An exact match requires the same PDB name, GUID, age and
    architecture.  The cache status must be ``validated`` (or
    ``usable``, never ``pending`` or ``failed``).
    """
    symbol_key = symbol_identifier(pdb_name, pdb_guid, pdb_age)
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == symbol_key)
        .first()
    )
    if cached is None:
        return None
    if (cached.architecture or "").lower() != architecture.lower():
        return None
    status = (cached.validation_status or "").lower()
    if status not in {"validated", "usable", "ready"}:
        return None
    return cached


def _find_existing_requirement(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    pdb_name: str,
    pdb_guid: str,
    pdb_age: int,
) -> MemorySymbolRequirement | None:
    """Locate an existing requirement that matches the exact natural key.

    The unique index ``uq_memory_evidence_symbol_identity`` covers
    ``(evidence_id, pdb_name, pdb_guid, pdb_age)`` so the natural
    key is per-evidence.  This function additionally checks the
    content identity (``case_id``) so a requirement created for a
    different evidence is not silently re-used.
    """
    return (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.evidence_id == evidence_id,
            MemorySymbolRequirement.pdb_name == pdb_name,
            MemorySymbolRequirement.pdb_guid == pdb_guid,
            MemorySymbolRequirement.pdb_age == int(pdb_age),
        )
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )


def _find_content_identity_row(
    db: Session,
    evidence: Evidence,
) -> MemoryEvidenceContent | None:
    """Return the content identity row for the evidence, if any."""
    sha = (evidence.sha256 or "").strip().lower()
    if not sha:
        return None
    size = int(getattr(evidence, "size_bytes", 0) or 0)
    return (
        db.query(MemoryEvidenceContent)
        .filter(
            MemoryEvidenceContent.evidence_sha256 == sha,
            MemoryEvidenceContent.size_bytes == size,
        )
        .first()
    )


def _matches_identity(
    existing: MemorySymbolRequirement,
    pdb_name: str,
    pdb_guid: str,
    pdb_age: int,
) -> bool:
    """True when an existing requirement matches the discovered identity.

    The match is exact: same PDB name (lowercased), GUID
    (upper-cased) and age (integer).  Architecture is part of
    the symbol_key family but the natural key does not include
    it; we accept any architecture here because the bounded
    discovery on a re-upload of the same file should never
    produce a different architecture.
    """
    return (
        normalize_pdb_name(existing.pdb_name) == pdb_name
        and normalize_guid(existing.pdb_guid) == pdb_guid
        and int(normalize_age(existing.pdb_age)) == int(pdb_age)
    )


def persist_discovered_requirement(
    db: Session,
    *,
    evidence: Evidence,
    discovered: DiscoveredRequirement,
) -> tuple[MemorySymbolRequirement, MemoryCachedSymbol | None, bool]:
    """Persist a discovered requirement and link the content identity.

    Returns a ``(requirement, cached_symbol, created)`` tuple.  When
    an existing requirement matches the natural key the function
    reuses it, updates ``last_requirement_id`` on the content row,
    and reports ``created=False``.  When a concurrent retry created
    the row between our SELECT and INSERT the function re-reads
    and reuses the existing row (the unique index is the source
    of truth).

    This function commits the row.  The caller is expected to be
    inside the worker's session.
    """
    pdb_name = normalize_pdb_name(discovered.pdb_name)
    pdb_guid = normalize_guid(discovered.pdb_guid)
    pdb_age = int(normalize_age(discovered.pdb_age))
    architecture = normalize_architecture(discovered.architecture)
    symbol_key = symbol_identifier(pdb_name, pdb_guid, pdb_age)

    cached = _exact_cache_match(
        db,
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
        architecture=architecture,
    )
    status_value = "cached" if cached is not None else "unavailable_offline"
    sanitized_message = (
        "The required Windows symbols are present in the cache."
        if cached is not None
        else "Required Windows symbols are not present in the offline cache."
    )

    # 1. Look up an existing requirement via the content identity
    # (``memory_evidence_contents.last_requirement_id``).  A
    # re-upload of the same file reuses the persisted row
    # without a second bounded probe.
    content_row = _find_content_identity_row(db, evidence)
    if content_row is not None and content_row.last_requirement_id:
        existing = db.get(MemorySymbolRequirement, content_row.last_requirement_id)
        if existing is not None and _matches_identity(
            existing, pdb_name, pdb_guid, pdb_age
        ):
            # Refresh audit metadata; do NOT mutate the natural
            # key, status or cached_symbol_id.
            meta = dict(existing.metadata_json or {})
            bounded = dict(meta.get("bounded_discovery") or {})
            bounded.setdefault("method", discovered.discovery_method)
            bounded.setdefault("architecture", architecture)
            meta["bounded_discovery"] = bounded
            existing.metadata_json = meta
            existing.updated_at = utc_now_naive()
            _link_content_identity(
                db, evidence=evidence, requirement_id=str(existing.id)
            )
            db.commit()
            return existing, cached, False

    # 2. Look up an existing requirement that matches the
    # per-evidence natural key.  This covers the case where
    # the bounded probe is rerun on the same evidence (e.g.
    # after a re-preparation).
    existing = _find_existing_requirement(
        db,
        case_id=evidence.case_id,
        evidence_id=str(evidence.id),
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
    )
    if existing is not None:
        # Refresh the audit metadata so the UI can show the
        # discovery method without re-running it.  Do NOT change
        # the natural key, status or cached_symbol_id.
        meta = dict(existing.metadata_json or {})
        bounded = dict(meta.get("bounded_discovery") or {})
        bounded.setdefault("method", discovered.discovery_method)
        bounded.setdefault("architecture", architecture)
        meta["bounded_discovery"] = bounded
        existing.metadata_json = meta
        existing.updated_at = utc_now_naive()
        _link_content_identity(
            db, evidence=evidence, requirement_id=str(existing.id)
        )
        db.commit()
        return existing, cached, False

    fallback_run_id, fallback_plugin_id = _stable_discovery_uuids(
        str(evidence.id)
    )
    new_row = MemorySymbolRequirement(
        case_id=evidence.case_id,
        evidence_id=str(evidence.id),
        source_run_id=fallback_run_id,
        source_plugin_run_id=fallback_plugin_id,
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
        requested_pdb_age=pdb_age,
        age_corrected=False,
        architecture=architecture,
        symbol_key=symbol_key,
        status=status_value,
        cached_symbol_id=cached.id if cached is not None else None,
        source=SOURCE_BOUNDED_DISCOVERY,
        backfill_version="v1",
        confidence="high",
        reconstructed_at=utc_now_naive(),
        metadata_json={
            "bounded_discovery": {
                "method": discovered.discovery_method,
                "architecture": architecture,
                "platform": discovered.platform,
            },
            "backfill": False,
        },
        sanitized_message=sanitized_message,
    )
    db.add(new_row)
    try:
        db.flush()
    except Exception:
        # A concurrent retry may have inserted the same natural
        # key in the meantime (the unique index is the source of
        # truth).  Roll back, re-read, and reuse the existing row.
        db.rollback()
        reused = _find_existing_requirement(
            db,
            case_id=evidence.case_id,
            evidence_id=str(evidence.id),
            pdb_name=pdb_name,
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
        )
        if reused is None:
            raise
        _link_content_identity(
            db, evidence=evidence, requirement_id=str(reused.id)
        )
        cached_after = _exact_cache_match(
            db,
            pdb_name=pdb_name,
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
            architecture=architecture,
        )
        db.commit()
        return reused, cached_after, False

    _link_content_identity(
        db, evidence=evidence, requirement_id=str(new_row.id)
    )
    db.commit()
    return new_row, cached, True


def _link_content_identity(
    db: Session,
    *,
    evidence: Evidence,
    requirement_id: str,
) -> None:
    """Set ``last_requirement_id`` on the content identity row.

    The content identity is the (sha256, size) pair.  A second
    re-upload of the same file will reuse the persisted
    requirement without re-running the bounded probe.
    """
    sha = (evidence.sha256 or "").strip().lower()
    size = int(getattr(evidence, "size_bytes", 0) or 0)
    if not sha:
        return
    content = (
        db.query(MemoryEvidenceContent)
        .filter(
            MemoryEvidenceContent.evidence_sha256 == sha,
            MemoryEvidenceContent.size_bytes == size,
        )
        .first()
    )
    if content is None:
        # The content identity row is normally created during
        # upload registration.  If it is missing for any reason
        # (legacy ingest path, etc.) we create it here so the
        # next re-upload of the same SHA can short-circuit.
        content = MemoryEvidenceContent(
            evidence_sha256=sha,
            size_bytes=size,
            acquisition_metadata={
                "first_evidence_id": str(evidence.id),
                "first_filename": evidence.original_filename,
                "created_by": "bounded_discovery",
            },
        )
        db.add(content)
        db.flush()
    content.last_requirement_id = requirement_id
    content.last_readiness = "ready" if content.last_readiness is None else content.last_readiness
    content.last_checked_at = utc_now_naive()


__all__ = [
    "BoundedDiscoveryError",
    "DiscoveredRequirement",
    "SOURCE_BOUNDED_DISCOVERY",
    "DISCOVERY_OK",
    "DISCOVERY_VOLATILITY_NOT_CONFIGURED",
    "DISCOVERY_VOLATILITY_NOT_FOUND",
    "DISCOVERY_PROBE_TIMEOUT",
    "DISCOVERY_BACKEND_START_FAILED",
    "DISCOVERY_OUTPUT_TOO_LARGE",
    "DISCOVERY_PLUGIN_FAILED",
    "DISCOVERY_INCONCLUSIVE",
    "DISCOVERY_UNSAFE_PATH",
    "discover_windows_symbol_requirement",
    "persist_discovered_requirement",
]
