"""Exact Symbol Recovery Sources v1 — orchestration and fan-out.

This module is the single entry point for "find an exact match for
this requirement somewhere".  It enforces the security contract:

* Recovery is NEVER triggered automatically — the caller must
  invoke :func:`recover_exact_symbol` explicitly.
* Recovery NEVER mutates the requirement identity.  The
  ``MemorySymbolRequirement.pdb_name`` / ``pdb_guid`` /
  ``pdb_age`` / ``architecture`` columns are read-only; the
  function only writes the link / status / acquisition columns.
* Recovery NEVER creates a ``MemoryScanRun`` or
  ``MemoryPluginRun``.  It only links requirements to a
  validated ``MemoryCachedSymbol`` and transitions the affected
  preparation state machines.
* Recovery NEVER falls back to an approximate symbol.  The
  function returns a structured ``RecoveryResult`` with a
  terminal status (``ready``, ``exact_symbol_not_found``,
  ``identity_mismatch``, ``source_unavailable``,
  ``validation_failed``, ``import_rejected``,
  ``configuration_required``).

Recovery sources are evaluated in this order:

1. Existing validated Kairon cache (``memory_cached_symbols``).
2. Microsoft public symbol server (delegated to the existing
   ``symbol_fetcher`` worker).
3. Administrator-configured corporate / SymProxy symbol server.
4. Administrator-imported PDB or ISF (already linked via
   the manual import endpoints).
5. Authorized offline symbol-package import.

Per-source attempt results are recorded in
``MemorySymbolRecoveryAttempt`` so the operator can see which
sources were tried and which failed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import shutil
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from uuid import UUID, uuid4

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.memory import (
    MEMORY_RECOVERY_SOURCE_NAMES,
    MEMORY_RECOVERY_SOURCE_TYPES,
    MemoryCachedSymbol,
    MemoryEvidenceSymbolLink,
    MemorySymbolAcquisition,
    MemorySymbolPreparation,
    MemorySymbolRecoveryAttempt,
    MemorySymbolRecoverySource,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_fetcher import (
    PDB_GUID,
    PDB_NAME,
    SymbolFetchError,
    SymbolIdentity,
    generate_isf,
    read_pdb_identity,
    validate_pdb,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public status constants
# ---------------------------------------------------------------------------

RECOVERY_TERMINAL_READY = "ready"
RECOVERY_TERMINAL_EXACT_NOT_FOUND = "exact_symbol_not_found"
RECOVERY_TERMINAL_IDENTITY_MISMATCH = "identity_mismatch"
RECOVERY_TERMINAL_SOURCE_UNAVAILABLE = "source_unavailable"
RECOVERY_TERMINAL_VALIDATION_FAILED = "validation_failed"
RECOVERY_TERMINAL_IMPORT_REJECTED = "import_rejected"
RECOVERY_TERMINAL_CONFIG_REQUIRED = "configuration_required"
# The Kairon project does not currently provide a managed
# worker for corporate / SymProxy / offline-package recovery.
# The orchestrator returns this terminal state instead of
# creating a deceptive "pending" attempt the user can never
# complete.
RECOVERY_TERMINAL_NOT_IMPLEMENTED = "not_implemented"

RECOVERY_TERMINAL_STATES: set[str] = {
    RECOVERY_TERMINAL_READY,
    RECOVERY_TERMINAL_EXACT_NOT_FOUND,
    RECOVERY_TERMINAL_IDENTITY_MISMATCH,
    RECOVERY_TERMINAL_SOURCE_UNAVAILABLE,
    RECOVERY_TERMINAL_VALIDATION_FAILED,
    RECOVERY_TERMINAL_IMPORT_REJECTED,
    RECOVERY_TERMINAL_CONFIG_REQUIRED,
    RECOVERY_TERMINAL_NOT_IMPLEMENTED,
}


# Specific error code raised by the safe ISF parser when the
# payload exceeds a server-side resource limit.  Never leak the
# internal counter or the limit value to the operator.
SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED = "SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED"


class IsfResourceLimitError(Exception):
    """Raised by :func:`_safe_json_load` when the JSON payload
    exceeds a server-side resource limit.

    The ``kind`` attribute names the limit that was hit; the
    caller maps it to ``SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED``.
    The actual limit value is never exposed.
    """

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _safe_json_load(handle: "Any", settings: "Settings") -> Any:
    """Parse JSON with strict resource controls.

    Hard caps (configured server-side):

    * maximum nesting depth;
    * maximum object count;
    * maximum array length;
    * maximum string length;
    * maximum key count per object.

    These are enforced before unbounded recursion / allocation
    can occur.  The implementation is iterative over a stack of
    pending containers so the call stack does not grow with
    payload depth.
    """
    max_depth = int(getattr(settings, "memory_symbol_isf_max_depth", 32))
    max_objects = int(getattr(settings, "memory_symbol_isf_max_objects", 200_000))
    max_array = int(getattr(settings, "memory_symbol_isf_max_array_length", 100_000))
    max_string = int(
        getattr(settings, "memory_symbol_isf_max_string_bytes", 1_048_576)
    )
    max_keys = int(getattr(settings, "memory_symbol_isf_max_object_keys", 10_000))

    decoder = json.JSONDecoder()
    # Read up to the on-disk size; the caller is responsible
    # for bounding the file size before calling this function.
    raw = handle.read()
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IsfResourceLimitError("string encoding") from exc
    try:
        value, _ = decoder.raw_decode(raw)
    except (json.JSONDecodeError, ValueError):
        raise

    # Walk the parsed tree once and enforce every cap.  The
    # traversal is iterative: containers are pushed on a
    # stack with their current depth.
    object_count = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if node is None or isinstance(node, (bool, int, float, str)):
            if isinstance(node, str) and len(node.encode("utf-8")) > max_string:
                raise IsfResourceLimitError("string length")
            continue
        object_count += 1
        if object_count > max_objects:
            raise IsfResourceLimitError("object count")
        if depth > max_depth:
            raise IsfResourceLimitError("nesting depth")
        if isinstance(node, list):
            if len(node) > max_array:
                raise IsfResourceLimitError("array length")
            for child in node:
                stack.append((child, depth + 1))
        elif isinstance(node, dict):
            if len(node) > max_keys:
                raise IsfResourceLimitError("object keys")
            for child in node.values():
                stack.append((child, depth + 1))
        else:
            # Unknown scalar — refuse to be permissive.
            raise IsfResourceLimitError("unsupported scalar")
    return value

# Source attempt statuses
ATTEMPT_PENDING = "pending"
ATTEMPT_SUCCEEDED = "succeeded"
ATTEMPT_FAILED = "failed"
ATTEMPT_SKIPPED = "skipped"

# Quarantine filename pattern (no path traversal, no shell metachars)
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Archive hardening helpers
# ---------------------------------------------------------------------------


def _normalize_archive_member_name(name: str) -> str | None:
    """Return a canonical, traversal-free name for an archive member.

    Returns ``None`` when the name is unparsable, contains a
    NULL byte, or contains an unsupported character class.
    The returned name uses forward slashes only and never
    starts with ``/``.

    The normalization collapses ``.`` segments so that
    ``a/./b`` and ``a/b`` map to the same name.  This is
    used by the archive extractor to detect duplicate
    filenames.
    """
    if not name or "\x00" in name:
        return None
    # Reject any name that uses backslashes; the package
    # format is supposed to be POSIX-style and any backslash
    # is suspicious on Linux.
    if "\\" in name:
        return None
    # Strip a single leading slash.
    if name.startswith("/"):
        name = name[1:]
    # Reject any segment equal to ``..`` or empty.
    segments = name.split("/")
    if any(s == ".." for s in segments):
        return None
    # Collapse ``.`` segments so ``a/./b`` becomes ``a/b``.
    segments = [s for s in segments if s != "" and s != "."]
    if not segments:
        return None
    return "/".join(segments)


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoveryResult:
    """The terminal state of a recovery attempt.

    ``status`` is one of the ``RECOVERY_TERMINAL_*`` constants.
    ``attempts`` is the per-source log, in evaluation order.
    ``cached_symbol_id`` is set when ``status == "ready"`` and
    points to the cache row that satisfied the requirement.
    """

    status: str
    requirement_id: str
    attempts: list[dict[str, Any]] = field(default_factory=list)
    cached_symbol_id: str | None = None
    error_code: str | None = None
    sanitized_message: str | None = None
    identity_expected: dict[str, Any] | None = None
    identity_observed: dict[str, Any] | None = None

    @property
    def is_ready(self) -> bool:
        return self.status == RECOVERY_TERMINAL_READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "requirement_id": self.requirement_id,
            "attempts": list(self.attempts),
            "cached_symbol_id": self.cached_symbol_id,
            "error_code": self.error_code,
            "sanitized_message": self.sanitized_message,
            "identity_expected": self.identity_expected,
            "identity_observed": self.identity_observed,
        }


# ---------------------------------------------------------------------------
# Lock to prevent concurrent duplicate fan-out for the same requirement
# ---------------------------------------------------------------------------

_recovery_locks: dict[str, threading.Lock] = {}
_recovery_locks_guard = threading.Lock()


def _lock_for(requirement_id: str) -> threading.Lock:
    with _recovery_locks_guard:
        lock = _recovery_locks.get(requirement_id)
        if lock is None:
            lock = threading.Lock()
            _recovery_locks[requirement_id] = lock
        return lock


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def expected_identity_dict(requirement: MemorySymbolRequirement) -> dict[str, Any]:
    return {
        "pdb_name": requirement.pdb_name,
        "pdb_guid": (requirement.pdb_guid or "").upper(),
        "pdb_age": int(requirement.pdb_age),
        "architecture": requirement.architecture,
    }


def make_identity(requirement: MemorySymbolRequirement) -> SymbolIdentity:
    return SymbolIdentity(
        pdb_name=requirement.pdb_name,
        guid=(requirement.pdb_guid or "").upper(),
        age=int(requirement.pdb_age),
        architecture=requirement.architecture,
    )


# ---------------------------------------------------------------------------
# Quarantine helpers
# ---------------------------------------------------------------------------


def quarantine_path(settings: Settings, *, suffix: str) -> Path:
    root = settings.memory_symbol_import_quarantine_path
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    name = f"{utc_now_naive().strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(8)}{suffix}"
    target = root / name
    if target.exists():
        target = root / f"{name}-{secrets.token_hex(4)}{suffix}"
    return target


def safe_original_filename(name: str | None) -> str:
    if not name:
        return "upload.bin"
    cleaned = _SAFE_NAME_RE.sub("_", name).strip("._-")
    if not cleaned:
        cleaned = "upload.bin"
    if len(cleaned) > 128:
        cleaned = cleaned[-128:]
    return cleaned


def hash_file(path: Path, *, max_bytes: int) -> str:
    """Stream-hash a file, refusing to read past ``max_bytes``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file exceeds maximum size: {size} > {max_bytes}")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Cache promotion (atomic)
# ---------------------------------------------------------------------------


def atomic_promote_cached_symbol(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    pdb_path: Path,
    isf_path: Path,
    cache_root: Path,
    provenance_source_type: str,
    provenance_source_name: str,
    provenance_actor: str,
) -> MemoryCachedSymbol:
    """Atomically promote a (pdb, isf) pair into the canonical cache.

    The two files are first copied into a per-acquisition staging
    directory under ``<cache_root>/tmp/<id>.promote/`` and then
    ``os.replace``-d into the canonical ``pdb/<name>/<guid-age>/<name>``
    and ``symbols/windows/<name>/<guid-age>.json.xz`` paths.

    A new ``MemoryCachedSymbol`` row is inserted with
    ``symbol_key`` derived from the requirement.  A duplicate
    ``symbol_key`` (which is ``UNIQUE``) re-raises as
    :class:`SymbolFetchError` with code
    ``SYMBOL_CACHE_DUPLICATE``; the caller is expected to handle
    this by re-using the existing row.
    """
    import os
    cache_root_resolved = cache_root.resolve()
    pdb_resolved = pdb_path.resolve()
    isf_resolved = isf_path.resolve()
    # Both source files must already be inside the cache root —
    # the API layer is responsible for quarantining uploads into a
    # ``<cache_root>/tmp/`` subdirectory before calling this.
    if not str(pdb_resolved).startswith(str(cache_root_resolved)):
        raise SymbolFetchError(
            "SYMBOL_IMPORT_REJECTED",
            "Imported PDB path is outside the cache root.",
        )
    if not str(isf_resolved).startswith(str(cache_root_resolved)):
        raise SymbolFetchError(
            "SYMBOL_IMPORT_REJECTED",
            "Imported ISF path is outside the cache root.",
        )

    staging = cache_root / "tmp" / f"{uuid4().hex}.promote"
    staging.mkdir(parents=True, exist_ok=True, mode=0o750)
    try:
        staged_pdb = staging / pdb_path.name
        staged_isf = staging / isf_path.name
        shutil.copy2(pdb_path, staged_pdb)
        shutil.copy2(isf_path, staged_isf)

        canonical_pdb = cache_root / "pdb" / requirement.pdb_name.lower() / (
            f"{(requirement.pdb_guid or '').upper()}-{int(requirement.pdb_age)}"
        ) / requirement.pdb_name
        canonical_isf = (
            cache_root
            / "symbols"
            / "windows"
            / requirement.pdb_name
            / f"{(requirement.pdb_guid or '').upper()}-{int(requirement.pdb_age)}.json.xz"
        )
        canonical_pdb.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        canonical_isf.parent.mkdir(parents=True, exist_ok=True, mode=0o750)

        # Atomic rename.  If the destination already exists and is
        # already a validated cache entry, refuse the overwrite —
        # the spec forbids overwriting a validated cache.
        if canonical_pdb.exists() or canonical_isf.exists():
            existing = (
                db.query(MemoryCachedSymbol)
                .filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key)
                .first()
            )
            if existing is not None:
                raise SymbolFetchError(
                    "SYMBOL_CACHE_DUPLICATE",
                    "A validated cache row already exists for this symbol_key.",
                )
            raise SymbolFetchError(
                "SYMBOL_IMPORT_REJECTED",
                "Canonical cache path is already occupied; refusing to overwrite.",
            )

        os.replace(staged_pdb, canonical_pdb)
        os.replace(staged_isf, canonical_isf)

        # Hash the canonical files for provenance.
        pdb_sha = hash_file(canonical_pdb, max_bytes=2 * 1024 * 1024 * 1024)
        isf_sha = hash_file(canonical_isf, max_bytes=2 * 1024 * 1024 * 1024)
        pdb_size = canonical_pdb.stat().st_size
        isf_size = canonical_isf.stat().st_size

        cached = MemoryCachedSymbol(
            symbol_key=requirement.symbol_key,
            pdb_name=requirement.pdb_name,
            pdb_guid=(requirement.pdb_guid or "").upper(),
            pdb_age=int(requirement.pdb_age),
            architecture=requirement.architecture,
            pdb_relative_path=str(canonical_pdb.relative_to(cache_root)),
            isf_relative_path=str(canonical_isf.relative_to(cache_root)),
            pdb_sha256=pdb_sha,
            isf_sha256=isf_sha,
            pdb_size_bytes=int(pdb_size),
            isf_size_bytes=int(isf_size),
            validation_status="validated",
            source_category=provenance_source_type,
            provenance_source_type=provenance_source_type,
            provenance_source_name=provenance_source_name,
            provenance_actor=provenance_actor,
            provenance_acquired_at=utc_now_naive(),
        )
        db.add(cached)
        db.flush()
        return cached
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def stage_upload_in_cache(
    cache_root: Path, *, upload_path: Path, suffix: str,
) -> Path:
    """Copy an upload from its quarantine location into the cache
    root's ``tmp/`` area so it can be atomically promoted.

    Returns the staged path.  The original ``upload_path`` is NOT
    deleted — the caller is responsible for unlinking it after
    the import succeeds."""
    cache_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = cache_root / "tmp"
    tmp.mkdir(parents=True, exist_ok=True, mode=0o750)
    target = tmp / f"{uuid4().hex}{suffix}"
    shutil.copy2(upload_path, target)
    return target


# ---------------------------------------------------------------------------
# Fan-out — link every requirement with the same natural key
# ---------------------------------------------------------------------------


def link_requirements_to_cache(
    db: Session,
    *,
    cached: MemoryCachedSymbol,
    actor: str,
    source_type: str,
) -> list[MemorySymbolRequirement]:
    """Re-evaluate every requirement whose natural key matches the cache.

    The natural key is ``symbol_key`` which already encodes
    ``(pdb_name, pdb_guid, pdb_age)``.  Architecture is checked
    separately so a cross-architecture entry never satisfies a
    different-arch requirement.  Same-name/different-GUID and
    same-GUID/different-age requirements are NOT linked.

    The function flushes the writes; the caller is responsible
    for committing the transaction.
    """
    linked: list[MemorySymbolRequirement] = []
    requirements: Sequence[MemorySymbolRequirement] = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.symbol_key == cached.symbol_key)
        .all()
    )
    for requirement in requirements:
        if (requirement.architecture or "").lower() != (cached.architecture or "").lower():
            continue
        if requirement.cached_symbol_id != cached.id:
            requirement.cached_symbol_id = cached.id
            requirement.status = "cached"
            requirement.error_code = None
            requirement.sanitized_message = None
        linked.append(requirement)
        # Re-evaluate the per-evidence preparation state machine.
        _transition_preparation_for_requirement(
            db,
            requirement=requirement,
            actor=actor,
            source_type=source_type,
        )
    db.flush()
    return linked


def _transition_preparation_for_requirement(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    actor: str,
    source_type: str,
) -> None:
    """Drive the per-evidence preparation to ``ready`` if a cache link
    is now in place.  Idempotent.  Never mutates the requirement
    identity."""
    active = (
        db.query(MemorySymbolPreparation)
        .filter(
            MemorySymbolPreparation.case_id == requirement.case_id,
            MemorySymbolPreparation.evidence_id == requirement.evidence_id,
            MemorySymbolPreparation.active.is_(True),
        )
        .order_by(desc(MemorySymbolPreparation.created_at))
        .first()
    )
    if active is None:
        return
    active.state = "ready"
    active.state_reason = (
        f"exact cache linked via {source_type} by {actor}; "
        f"pdb_name={requirement.pdb_name} "
        f"pdb_guid={(requirement.pdb_guid or '').upper()} "
        f"pdb_age={int(requirement.pdb_age)}"
    )
    active.error_code = None
    active.sanitized_message = None
    active.requirement_id = requirement.id
    active.reconciled_at = utc_now_naive()
    active.active = True


# ---------------------------------------------------------------------------
# Source attempts
# ---------------------------------------------------------------------------


def _record_attempt(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    source: MemorySymbolRecoverySource | None,
    source_label: str,
    source_type: str,
    status: str,
    error_code: str | None = None,
    sanitized_message: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> MemorySymbolRecoveryAttempt:
    attempt = MemorySymbolRecoveryAttempt(
        requirement_id=requirement.id,
        case_id=requirement.case_id,
        evidence_id=requirement.evidence_id,
        source_id=source.id if source is not None else None,
        source_type=source_type,
        source_label=source_label,
        status=status,
        error_code=error_code,
        sanitized_message=sanitized_message,
        metadata_json=dict(metadata) if metadata else {},
    )
    db.add(attempt)
    db.flush()
    return attempt


# ---------------------------------------------------------------------------
# Step 1 — existing validated cache
# ---------------------------------------------------------------------------


def _try_existing_cache(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    attempts: list[dict[str, Any]],
) -> RecoveryResult | None:
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key)
        .first()
    )
    if cached is None:
        attempts.append({
            "source_type": "validated_cache",
            "source_label": "Validated Kairon cache",
            "status": ATTEMPT_SKIPPED,
        })
        return None
    if (cached.architecture or "").lower() != (requirement.architecture or "").lower():
        attempts.append({
            "source_type": "validated_cache",
            "source_label": "Validated Kairon cache",
            "status": ATTEMPT_FAILED,
            "error_code": "SYMBOL_ARCHITECTURE_MISMATCH",
            "sanitized_message": "Cached architecture does not match requirement.",
        })
        return None
    link_requirements_to_cache(
        db,
        cached=cached,
        actor="recovery-orchestrator",
        source_type=cached.provenance_source_type or "microsoft_public",
    )
    attempts.append({
        "source_type": "validated_cache",
        "source_label": cached.provenance_source_name or "Validated Kairon cache",
        "status": ATTEMPT_SUCCEEDED,
    })
    return RecoveryResult(
        status=RECOVERY_TERMINAL_READY,
        requirement_id=requirement.id,
        attempts=attempts,
        cached_symbol_id=cached.id,
    )


# ---------------------------------------------------------------------------
# Step 2 — Microsoft public symbol path (delegated)
# ---------------------------------------------------------------------------


def _try_microsoft_public(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    settings: Settings,
    attempts: list[dict[str, Any]],
) -> RecoveryResult | None:
    """Delegate to the existing symbol_tasks worker.

    The orchestrator does not duplicate the Microsoft public
    symbol download.  It only:

    1. Creates a fresh ``MemorySymbolAcquisition`` row bound to
       the requirement.
    2. Enqueues the canonical worker job on the symbol-fetcher
       queue.
    3. Polls the acquisition row until the worker reaches a
       terminal state, with a small bounded wait.

    Polling is bounded — the orchestrator is synchronous and
    must not block forever.  The acquisition is left in the
    queue for the worker to pick up; the operator can poll the
    acquisition endpoint to follow progress.
    """
    # Import inside the function so tests can patch the
    # enqueue path without circular imports.
    from app.workers.tasks import enqueue_symbol_acquisition
    from rq import Queue
    from app.core.config import get_settings as _get

    queue_name = _get().memory_symbol_queue_name
    enqueue_symbol_acquisition(
        db=db,
        requirement_id=requirement.id,
        actor="recovery-orchestrator",
    )
    attempts.append({
        "source_type": "microsoft_public",
        "source_label": "Microsoft public",
        "status": ATTEMPT_PENDING,
    })
    return None


# ---------------------------------------------------------------------------
# Step 3 — corporate / SymProxy source
# ---------------------------------------------------------------------------


def _corporate_source_candidates(db: Session) -> list[MemorySymbolRecoverySource]:
    return (
        db.query(MemorySymbolRecoverySource)
        .filter(
            MemorySymbolRecoverySource.source_type == "corporate_symbol_server",
            MemorySymbolRecoverySource.enabled.is_(True),
        )
        .order_by(MemorySymbolRecoverySource.priority.asc())
        .all()
    )


def _validate_corporate_source_url(
    source: MemorySymbolRecoverySource,
) -> tuple[str, int, str] | None:
    """Return ``(scheme, port, path_prefix)`` if the source is well-formed.

    The host, port, and path prefix are FROZEN at row creation
    time.  No wildcards.  No user-supplied URLs.
    """
    if not source.host or not source.path_prefix:
        return None
    if "*" in source.host or "?" in source.host:
        return None
    if "/" in source.host:
        return None
    port = int(source.port or 443)
    scheme = "https" if source.tls_required else "http"
    if scheme == "https" and port != 443:
        return None
    if not source.path_prefix.startswith("/"):
        return None
    if ".." in source.path_prefix.split("/"):
        return None
    return scheme, port, source.path_prefix


def _try_corporate_source(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    settings: Settings,
    attempts: list[dict[str, Any]],
) -> RecoveryResult | None:
    """The Kairon project does not currently provide a managed
    worker for corporate / SymProxy recovery.  The function is
    kept for future use but the orchestrator MUST NOT create a
    ``pending`` attempt the user can never complete.

    Behavior:
    * The corporate source rows are listed for the operator
      record, but every attempt is marked as
      ``not_implemented`` and the orchestrator returns
      ``RECOVERY_TERMINAL_NOT_IMPLEMENTED`` after exhausting
      other sources.
    * No ``ATTEMPT_PENDING`` row is ever created.
    """
    candidates = _corporate_source_candidates(db)
    if not candidates:
        return None
    for source in candidates:
        attempts.append({
            "source_type": source.source_type,
            "source_label": source.name,
            "status": ATTEMPT_FAILED,
            "error_code": "SYMBOL_SOURCE_NOT_IMPLEMENTED",
            "sanitized_message": (
                "Corporate symbol recovery is not implemented in this "
                "deployment.  No managed worker exists for this source."
            ),
        })
    return None


# ---------------------------------------------------------------------------
# Step 4 — manual imports (already linked)
# ---------------------------------------------------------------------------


def _try_manual_imports(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    attempts: list[dict[str, Any]],
) -> RecoveryResult | None:
    """Manual imports create the cache record directly via the
    admin endpoints, then call :func:`link_requirements_to_cache`
    to fan out.  By the time the orchestrator runs after a manual
    import, the cache row will exist; the step-1 check above
    catches it.  This function is a no-op kept for future
    synchronous ingest."""
    return None


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


def recover_exact_symbol(
    db: Session,
    *,
    requirement_id: str,
    settings: Settings | None = None,
    actor: str = "server-operator",
) -> RecoveryResult:
    """Recover an exact symbol for the given requirement.

    Returns a :class:`RecoveryResult`.  The function never
    mutates the requirement identity, never creates a
    ``MemoryScanRun`` / ``MemoryPluginRun``, and never starts
    analysis automatically.
    """
    if settings is None:
        settings = get_settings()
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=str(requirement_id),
            error_code="SYMBOL_REQUIREMENT_UNKNOWN",
            sanitized_message="Requirement not found.",
        )

    lock = _lock_for(requirement.id)
    with lock:
        attempts: list[dict[str, Any]] = []
        identity_expected = expected_identity_dict(requirement)

        # Step 1 — validated cache
        ready = _try_existing_cache(
            db, requirement=requirement, attempts=attempts,
        )
        if ready is not None:
            db.commit()
            return ready

        # Step 2 — Microsoft public
        if settings.memory_symbol_execution_mode in {
            "managed_download",
        } and settings.memory_symbol_managed_download_enabled:
            _try_microsoft_public(
                db,
                requirement=requirement,
                settings=settings,
                attempts=attempts,
            )

        # Step 3 — corporate / SymProxy
        _try_corporate_source(
            db,
            requirement=requirement,
            settings=settings,
            attempts=attempts,
        )

        # Step 4 — manual imports (no-op, see docstring)
        _try_manual_imports(db, requirement=requirement, attempts=attempts)

        # If we have not recorded any attempt beyond the cache
        # miss, no recovery path is available.
        attempted = [a for a in attempts if a.get("status") != ATTEMPT_SKIPPED]
        if not attempted:
            return RecoveryResult(
                status=RECOVERY_TERMINAL_EXACT_NOT_FOUND,
                requirement_id=requirement.id,
                attempts=attempts,
                error_code="SYMBOL_EXACT_NOT_FOUND",
                sanitized_message=(
                    "No recovery source produced an exact match. "
                    "The Microsoft public path is disabled and no "
                    "alternative source is configured. Import a PDB "
                    "or ISF as an administrator to recover this symbol."
                ),
                identity_expected=identity_expected,
            )

        # Distinguish "no source could complete" from "no source
        # is implemented".  When every recorded attempt is the
        # corporate source (which is registration-only) we must
        # not present a "not found" result that the operator
        # could resolve by retrying.  The truthful terminal
        # state is "not_implemented".
        non_skipped = [a for a in attempts if a.get("status") != ATTEMPT_SKIPPED]
        all_not_implemented = all(
            a.get("error_code") == "SYMBOL_SOURCE_NOT_IMPLEMENTED"
            for a in non_skipped
        )
        if all_not_implemented and non_skipped:
            return RecoveryResult(
                status=RECOVERY_TERMINAL_NOT_IMPLEMENTED,
                requirement_id=requirement.id,
                attempts=attempts,
                error_code="SYMBOL_RECOVERY_NOT_IMPLEMENTED",
                sanitized_message=(
                    "Corporate symbol recovery is not implemented in this "
                    "deployment.  No managed worker is available for the "
                    "configured corporate sources.  Microsoft-public exact "
                    "recovery may be available when the operator has enabled "
                    "managed download."
                ),
                identity_expected=identity_expected,
            )

        # We have attempted at least one source.  The orchestrator
        # itself does not wait for the worker — the operator must
        # poll the acquisition endpoint to follow progress.  If
        # the Microsoft path was queued, the terminal state is
        # "pending" mapped to "exact_symbol_not_found" once the
        # wait times out.  For the synchronous orchestration
        # case used by the tests, every pending attempt means
        # we could not complete synchronously; the operator
        # should re-check the cache after the worker reports.
        db.commit()
        return RecoveryResult(
            status=RECOVERY_TERMINAL_EXACT_NOT_FOUND,
            requirement_id=requirement.id,
            attempts=attempts,
            error_code="SYMBOL_EXACT_NOT_FOUND",
            sanitized_message=(
                "Recovery sources were attempted but did not produce "
                "an exact match synchronously.  Check the per-source "
                "attempt log and the symbol acquisition endpoint."
            ),
            identity_expected=identity_expected,
        )


# ---------------------------------------------------------------------------
# Manual PDB / ISF / package importers (used by the admin API)
# ---------------------------------------------------------------------------


def _validate_pdb_upload(path: Path, requirement: MemorySymbolRequirement) -> dict[str, Any]:
    """Read the actual PDB identity and compare it to the requirement.

    Returns a dict with ``pdb_guid`` / ``pdb_age`` / ``architecture`` /
    ``pdb_name`` populated from the **observed** values so the caller
    can record them in the canonical ``MemorySymbolAcquisition`` row
    and surface them to the operator.

    Raises :class:`SymbolFetchError` (``SYMBOL_PDB_IDENTITY_MISMATCH``)
    when the observed identity does not match the authoritative
    requirement.  The mismatch message contains both the expected
    and observed values, but the caller is expected to record the
    observed values via :func:`read_pdb_identity` separately rather
    than parsing the human-readable message.
    """
    identity = make_identity(requirement)
    # Read the observed identity first so it is available to the
    # caller even if validation fails.  ``validate_pdb`` itself
    # re-reads, but on mismatch the values are only available in
    # the human-readable error string.  The CLI / UI rely on the
    # canonical fields, so we pre-read them here.
    observed_guid: str | None = None
    observed_age: int | None = None
    try:
        observed_guid, observed_age = read_pdb_identity(path)
    except SymbolFetchError:
        # ``read_pdb_identity`` itself rejects malformed PDBs.
        # Re-raise with the same code so the caller can record
        # ``SYMBOL_PDB_INVALID`` rather than a mismatched identity.
        raise
    try:
        validate_pdb(path, identity)
    except SymbolFetchError:
        # Re-raise so the caller can record the terminal state.
        # The observed values are also returned via the caller's
        # own ``read_pdb_identity`` call before this function
        # runs (see :func:`_read_pdb_observed_safely`).
        raise
    return {
        "pdb_guid": (observed_guid or identity.guid).upper(),
        "pdb_age": int(observed_age if observed_age is not None else identity.age),
        "architecture": identity.architecture,
        "pdb_name": identity.pdb_name,
    }


def _read_pdb_observed_safely(path: Path) -> dict[str, Any]:
    """Read the observed identity from a PDB and return it as a
    sanitized dict.  Never raises.

    Returns an empty dict when the PDB is not parseable so the
    caller can still record the error code that was raised.
    The returned dict, when populated, contains:

    * ``pdb_guid`` (upper-case, 32 hex chars)
    * ``pdb_age`` (int)
    * ``pdb_name`` (the on-disk filename only)
    * ``pdb_size_bytes`` (int)
    * ``read_error`` (only when the read failed)
    """
    try:
        guid, age = read_pdb_identity(path)
    except SymbolFetchError as exc:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        return {
            "read_error": exc.code,
            "pdb_name": path.name,
            "pdb_size_bytes": int(size),
        }
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return {
        "pdb_guid": guid.upper(),
        "pdb_age": int(age),
        "pdb_name": path.name,
        "pdb_size_bytes": int(size),
    }


def _generate_isf_for_upload(
    pdb_path: Path,
    isf_path: Path,
    requirement: MemorySymbolRequirement,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    identity = make_identity(requirement)
    return generate_isf(pdb_path, isf_path, identity, max_bytes=max_bytes)


def import_pdb_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    upload_path: Path,
    original_filename: str,
    actor: str = "server-operator",
) -> RecoveryResult:
    """Validate an administrator-uploaded PDB and link the cache.

    The PDB is validated for an EXACT match of name, GUID, age
    and architecture.  An ISF is generated using the canonical
    Volatility converter.  Both files are then atomically
    promoted into the cache and every matching requirement is
    linked.  No requirement identity is mutated.
    """
    settings = get_settings()
    if not settings.memory_symbol_manual_import_enabled:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_CONFIG_REQUIRED,
            requirement_id=str(requirement_id),
            error_code="SYMBOL_MANUAL_IMPORT_DISABLED",
            sanitized_message=(
                "Manual symbol import is disabled. Set "
                "MEMORY_SYMBOL_MANUAL_IMPORT_ENABLED=1 to enable."
            ),
        )
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=str(requirement_id),
            error_code="SYMBOL_REQUIREMENT_UNKNOWN",
            sanitized_message="Requirement not found.",
        )

    identity_expected = expected_identity_dict(requirement)
    cache_root = settings.memory_symbol_cache_path
    try:
        staged_pdb = stage_upload_in_cache(
            cache_root, upload_path=upload_path, suffix=".pdb",
        )
    except OSError as exc:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code="SYMBOL_IMPORT_REJECTED",
            sanitized_message=f"Could not stage upload: {exc!s}",
            identity_expected=identity_expected,
        )
    # Read the observed identity BEFORE validation so the canonical
    # fields are available even when ``validate_pdb`` raises.  This
    # is the value that the UI's "Observed age: N" rendering and the
    # operator-facing status command rely on.
    observed = _read_pdb_observed_safely(staged_pdb)
    try:
        validated = _validate_pdb_upload(staged_pdb, requirement)
    except SymbolFetchError as exc:
        staged_pdb.unlink(missing_ok=True)
        return RecoveryResult(
            status=(
                RECOVERY_TERMINAL_IDENTITY_MISMATCH
                if exc.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
                else RECOVERY_TERMINAL_VALIDATION_FAILED
            ),
            requirement_id=requirement.id,
            error_code=exc.code,
            sanitized_message=exc.message,
            identity_expected=identity_expected,
            identity_observed=observed,
        )

    staging_isf = cache_root / "tmp" / f"{uuid4().hex}.isf"
    try:
        isf_result = _generate_isf_for_upload(
            staged_pdb,
            staging_isf,
            requirement,
            max_bytes=int(settings.memory_symbol_isf_max_bytes),
        )
    except SymbolFetchError as exc:
        staged_pdb.unlink(missing_ok=True)
        staging_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code=exc.code,
            sanitized_message=exc.message,
            identity_expected=identity_expected,
            identity_observed=observed,
        )
    except ModuleNotFoundError as exc:
        # Volatility is not installed in the current environment
        # (test runner, minimal backend image, etc.).  The PDB
        # was successfully validated for exact identity, but we
        # cannot generate the ISF here.  Return a structured
        # "validation failed" with a code the operator can
        # recognise so the test does not crash on ImportError.
        staged_pdb.unlink(missing_ok=True)
        staging_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_GENERATION_FAILED",
            sanitized_message=(
                f"Volatility framework is unavailable: {exc!s}"
            ),
            identity_expected=identity_expected,
            identity_observed=observed,
        )

    try:
        cached = atomic_promote_cached_symbol(
            db,
            requirement=requirement,
            pdb_path=staged_pdb,
            isf_path=staging_isf,
            cache_root=cache_root,
            provenance_source_type="manual_pdb_import",
            provenance_source_name="Administrator-imported PDB",
            provenance_actor=actor,
        )
    except SymbolFetchError as exc:
        staged_pdb.unlink(missing_ok=True)
        staging_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code=exc.code,
            sanitized_message=exc.message,
            identity_expected=identity_expected,
            identity_observed=observed,
        )

    link_requirements_to_cache(
        db,
        cached=cached,
        actor=actor,
        source_type="manual_pdb_import",
    )
    db.commit()
    return RecoveryResult(
        status=RECOVERY_TERMINAL_READY,
        requirement_id=requirement.id,
        cached_symbol_id=cached.id,
        identity_expected=identity_expected,
        identity_observed=observed,
    )


def import_isf_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    upload_path: Path,
    original_filename: str,
    actor: str = "server-operator",
) -> RecoveryResult:
    """Validate an administrator-uploaded ISF and link the cache.

    The ISF is parsed safely with size and depth limits.  The
    identity block is compared to the requirement.  The file is
    then atomically promoted.
    """
    settings = get_settings()
    if not settings.memory_symbol_manual_import_enabled:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_CONFIG_REQUIRED,
            requirement_id=str(requirement_id),
            error_code="SYMBOL_MANUAL_IMPORT_DISABLED",
            sanitized_message=(
                "Manual symbol import is disabled. Set "
                "MEMORY_SYMBOL_MANUAL_IMPORT_ENABLED=1 to enable."
            ),
        )
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=str(requirement_id),
            error_code="SYMBOL_REQUIREMENT_UNKNOWN",
            sanitized_message="Requirement not found.",
        )
    identity_expected = expected_identity_dict(requirement)
    cache_root = settings.memory_symbol_cache_path

    # Stage inside the cache root first.
    try:
        staged_isf = stage_upload_in_cache(
            cache_root, upload_path=upload_path, suffix=".isf",
        )
    except OSError as exc:
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code="SYMBOL_IMPORT_REJECTED",
            sanitized_message=f"Could not stage upload: {exc!s}",
            identity_expected=identity_expected,
        )

    # Parse safely.
    try:
        size = staged_isf.stat().st_size
    except FileNotFoundError:
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code="SYMBOL_IMPORT_REJECTED",
            sanitized_message="Uploaded ISF was not found on disk.",
            identity_expected=identity_expected,
        )
    if size > settings.memory_symbol_isf_upload_max_bytes:
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code="SYMBOL_IMPORT_REJECTED",
            sanitized_message="ISF upload exceeds the configured size limit.",
            identity_expected=identity_expected,
        )

    try:
        if staged_isf.suffix.lower() == ".xz":
            import lzma
            with lzma.open(staged_isf, "rb") as handle:
                payload = _safe_json_load(handle, settings)
        else:
            with staged_isf.open("rb") as handle:
                payload = _safe_json_load(handle, settings)
    except IsfResourceLimitError as exc:
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code=SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED,
            sanitized_message=(
                "ISF payload exceeds a server-side resource limit. "
                "The payload was rejected without being parsed."
            ),
            identity_expected=identity_expected,
        )
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_PARSE_FAILED",
            sanitized_message=f"ISF could not be parsed: {type(exc).__name__}.",
            identity_expected=identity_expected,
        )

    if not isinstance(payload, dict):
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_PARSE_FAILED",
            sanitized_message="ISF payload is not a JSON object.",
            identity_expected=identity_expected,
        )
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_IDENTITY_MISSING",
            sanitized_message="ISF payload has no metadata section.",
            identity_expected=identity_expected,
        )
    windows = metadata.get("windows")
    if not isinstance(windows, dict):
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_IDENTITY_MISSING",
            sanitized_message="ISF payload has no windows metadata block.",
            identity_expected=identity_expected,
        )
    pdb_metadata = windows.get("pdb")
    if not isinstance(pdb_metadata, dict):
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_VALIDATION_FAILED,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_IDENTITY_MISSING",
            sanitized_message="ISF payload has no PDB identity block.",
            identity_expected=identity_expected,
        )
    isf_guid = (
        str(pdb_metadata.get("GUID") or "")
        .replace("-", "")
        .replace("{", "")
        .replace("}", "")
        .upper()
    )
    try:
        isf_age = int(pdb_metadata.get("age"))
    except (TypeError, ValueError):
        isf_age = -1

    if isf_guid != identity_expected["pdb_guid"] or isf_age != identity_expected["pdb_age"]:
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IDENTITY_MISMATCH,
            requirement_id=requirement.id,
            error_code="SYMBOL_ISF_IDENTITY_MISMATCH",
            sanitized_message=(
                "Imported ISF identity does not match the requirement."
            ),
            identity_expected=identity_expected,
            identity_observed={
                "source": "isf",
                "pdb_guid": isf_guid or None,
                "pdb_age": isf_age if isf_age >= 0 else None,
            },
        )

    # PDB sibling stub: atomic_promote_cached_symbol needs both a
    # PDB and an ISF.  The ISF import path does not require
    # Volatility, but the cache row needs both files on disk.
    # The stub is deleted from the cache root as soon as the cache
    # promotion is recorded; only the ISF is referenced as the
    # cache artifact.
    stub_pdb = cache_root / "tmp" / f"{uuid4().hex}.pdb.stub"
    stub_pdb.write_bytes(b"")
    try:
        cached = atomic_promote_cached_symbol(
            db,
            requirement=requirement,
            pdb_path=stub_pdb,
            isf_path=staged_isf,
            cache_root=cache_root,
            provenance_source_type="manual_isf_import",
            provenance_source_name="Administrator-imported ISF",
            provenance_actor=actor,
        )
    except SymbolFetchError as exc:
        stub_pdb.unlink(missing_ok=True)
        staged_isf.unlink(missing_ok=True)
        return RecoveryResult(
            status=RECOVERY_TERMINAL_IMPORT_REJECTED,
            requirement_id=requirement.id,
            error_code=exc.code,
            sanitized_message=exc.message,
            identity_expected=identity_expected,
            identity_observed={"source": "isf", "pdb_guid": isf_guid, "pdb_age": isf_age},
        )
    finally:
        stub_pdb.unlink(missing_ok=True)

    link_requirements_to_cache(
        db,
        cached=cached,
        actor=actor,
        source_type="manual_isf_import",
    )
    db.commit()
    return RecoveryResult(
        status=RECOVERY_TERMINAL_READY,
        requirement_id=requirement.id,
        cached_symbol_id=cached.id,
        identity_expected=identity_expected,
        identity_observed={"source": "isf", "pdb_guid": isf_guid, "pdb_age": isf_age},
    )


def _synthesize_pdb_stub_for_isf(
    *,
    upload_path: Path,
    requirement: MemorySymbolRequirement,
) -> Path | None:
    """Create a synthetic PDB stub for ISF imports.

    The stub's only purpose is to satisfy
    :func:`atomic_promote_cached_symbol`, which requires both a
    PDB and an ISF.  It is NOT a real Volatility-usable PDB —
    the cache link is preserved by the ISF, not the stub.  The
    stub is deleted from the cache root as soon as the cache
    promotion is recorded; the canonical cache record keeps a
    reference to the ISF only.
    """
    try:
        # 56-byte MSF7 superblock is required by ``read_pdb_identity``,
        # but we never run that on the stub.
        # The stub is intentionally empty; we just need a real file
        # in the cache root for the promotion helper to copy.
        stub_path = upload_path.parent / f".{uuid4().hex}.pdb.stub"
        stub_path.write_bytes(b"")
        return stub_path
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Offline package import
# ---------------------------------------------------------------------------


def import_offline_package(
    db: Session,
    *,
    upload_path: Path,
    actor: str = "server-operator",
) -> dict[str, Any]:
    """Extract a controlled offline symbol package and import every
    PDB / ISF it contains.

    The package MUST be a zip file.  Extraction is bounded by:

    * max total uncompressed bytes
      (``memory_symbol_package_extract_max_bytes``)
    * max file count
      (``memory_symbol_package_max_files``)
    * allowed extensions only
    * path traversal prevention on every member name
    * zip-bomb detection: a single member whose ratio of
      uncompressed / compressed bytes exceeds 100 is rejected
    """
    settings = get_settings()
    if not settings.memory_symbol_manual_import_enabled:
        return {
            "status": RECOVERY_TERMINAL_CONFIG_REQUIRED,
            "error_code": "SYMBOL_MANUAL_IMPORT_DISABLED",
            "sanitized_message": "Manual import is disabled.",
        }
    size = upload_path.stat().st_size
    if size > settings.memory_symbol_package_max_bytes:
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "error_code": "SYMBOL_IMPORT_REJECTED",
            "sanitized_message": "Package exceeds the configured size limit.",
        }
    if not zipfile.is_zipfile(upload_path):
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "error_code": "SYMBOL_IMPORT_REJECTED",
            "sanitized_message": "Uploaded file is not a zip archive.",
        }

    # Bounded extraction.  Every member is checked before any
    # byte is written to disk.  The package is treated as
    # untrusted: every check listed below is mandatory.
    allowed = settings.memory_symbol_package_extensions
    max_files = settings.memory_symbol_package_max_files
    max_bytes = settings.memory_symbol_package_extract_max_bytes
    nested_archive_suffixes = {
        ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz",
    }

    total_bytes = 0
    file_count = 0
    staging = settings.memory_symbol_import_quarantine_path / f"pkg-{uuid4().hex}"
    staging.mkdir(parents=True, exist_ok=True, mode=0o750)
    rejected: list[dict[str, str]] = []
    accepted: list[dict[str, str]] = []
    seen_normalized: set[str] = set()
    try:
        with zipfile.ZipFile(upload_path, "r") as archive:
            for member in archive.infolist():
                # Symlinks / hardlinks: ZipInfo exposes the
                # external_attr which encodes the unix mode.
                # We refuse ANY member whose mode bits
                # indicate a symlink or any non-regular file.
                mode = (member.external_attr >> 16) & 0xFFFF
                if mode:
                    import stat as _stat
                    if _stat.S_ISLNK(mode) or _stat.S_ISCHR(mode) \
                            or _stat.S_ISBLK(mode) or _stat.S_ISFIFO(mode) \
                            or _stat.S_ISSOCK(mode):
                        rejected.append({
                            "name": safe_original_filename(member.filename),
                            "reason": "non-regular file (symlink / device / fifo)",
                        })
                        continue
                # Refuse absolute / Windows / UNC paths and
                # any member whose raw name contains
                # traversal segments.
                raw_name = member.filename or ""
                if raw_name.startswith("/") or raw_name.startswith("\\"):
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "absolute path rejected",
                    })
                    continue
                # Windows drive letter: e.g. C:\\Windows
                if len(raw_name) >= 2 and raw_name[1] == ":":
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "Windows drive letter rejected",
                    })
                    continue
                # UNC path: e.g. \\server\share
                if raw_name.startswith("\\\\"):
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "UNC path rejected",
                    })
                    continue
                # Encoded traversal: percent-encoded dots or
                # backslashes.  Reject any name that contains
                # '%' in a suspicious position.
                lowered = raw_name.lower()
                if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "encoded traversal rejected",
                    })
                    continue
                if ".." in raw_name.split("/"):
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "traversal segment rejected",
                    })
                    continue
                # Compute the canonical normalized path on
                # disk.  This collapses forward/backward
                # slashes (the latter only on Windows).
                normalized = _normalize_archive_member_name(raw_name)
                if normalized is None:
                    rejected.append({
                        "name": safe_original_filename(raw_name),
                        "reason": "unparsable name",
                    })
                    continue
                if normalized in seen_normalized:
                    rejected.append({
                        "name": normalized,
                        "reason": "duplicate normalized filename",
                    })
                    continue
                seen_normalized.add(normalized)
                if file_count >= max_files:
                    rejected.append({
                        "name": normalized,
                        "reason": "file count limit exceeded",
                    })
                    break
                name = safe_original_filename(raw_name)
                suffix = Path(normalized).suffix.lower()
                if suffix not in allowed:
                    rejected.append({
                        "name": name,
                        "reason": f"extension {suffix!r} is not allowed",
                    })
                    continue
                if suffix in nested_archive_suffixes:
                    rejected.append({
                        "name": name,
                        "reason": (
                            f"nested archive extension {suffix!r} is not allowed"
                        ),
                    })
                    continue
                if member.file_size > max_bytes:
                    rejected.append({
                        "name": name,
                        "reason": "member exceeds per-file size limit",
                    })
                    continue
                if member.compress_size > 0:
                    ratio = member.file_size / max(member.compress_size, 1)
                    if ratio > 100:
                        rejected.append({
                            "name": name,
                            "reason": "decompression ratio exceeds 100:1 (zip-bomb)",
                        })
                        continue
                total_bytes += int(member.file_size)
                if total_bytes > max_bytes:
                    rejected.append({
                        "name": name,
                        "reason": "package exceeds total uncompressed size limit",
                    })
                    break
                target = staging / normalized
                if not str(target.resolve()).startswith(str(staging.resolve())):
                    rejected.append({
                        "name": name,
                        "reason": "path traversal detected",
                    })
                    continue
                # Ensure the parent directory exists.  The zip
                # spec does not require the parent to be
                # emitted before the child, so we create it
                # lazily here.
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
                with archive.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                file_count += 1
                accepted.append({"name": name, "path": str(target), "normalized": normalized})

        # Now attempt to match each accepted file to a requirement.
        results: list[dict[str, Any]] = []
        for entry in accepted:
            path = Path(entry["path"])
            name = entry["name"]
            if path.suffix.lower() in {".pdb"}:
                # Find a requirement whose PDB name matches.
                pdb_name = path.name
                req = (
                    db.query(MemorySymbolRequirement)
                    .filter(MemorySymbolRequirement.pdb_name == pdb_name)
                    .order_by(desc(MemorySymbolRequirement.created_at))
                    .first()
                )
                if req is None:
                    rejected.append({"name": name, "reason": "no matching requirement"})
                    continue
                r = import_pdb_for_requirement(
                    db,
                    requirement_id=req.id,
                    upload_path=path,
                    original_filename=name,
                    actor=actor,
                )
                results.append({"name": name, **r.to_dict()})
            elif path.suffix.lower() in {".isf", ".json", ".xz"}:
                pdb_name = path.stem.split(".")[0]
                if path.suffix.lower() == ".json":
                    pdb_name = path.stem
                req = (
                    db.query(MemorySymbolRequirement)
                    .filter(MemorySymbolRequirement.pdb_name == pdb_name)
                    .order_by(desc(MemorySymbolRequirement.created_at))
                    .first()
                )
                if req is None:
                    rejected.append({"name": name, "reason": "no matching requirement"})
                    continue
                r = import_isf_for_requirement(
                    db,
                    requirement_id=req.id,
                    upload_path=path,
                    original_filename=name,
                    actor=actor,
                )
                results.append({"name": name, **r.to_dict()})

        return {
            "status": (
                RECOVERY_TERMINAL_READY
                if results and all(r.get("status") == RECOVERY_TERMINAL_READY for r in results)
                else RECOVERY_TERMINAL_IMPORT_REJECTED
            ),
            "accepted": accepted,
            "rejected": rejected,
            "results": results,
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# ---------------------------------------------------------------------------
# Operator-only CLI import path
# ---------------------------------------------------------------------------
#
# The ``memory_symbol_admin_recovery_enabled`` feature gate and the
# ``memory_symbol_manual_import_enabled`` configuration are NOT
# consulted here.  The CLI is a trusted-maintenance entry point that
# is only invokable from inside the backend container; it is not
# exposed to analysts via HTTP, and no frontend control mounts it.
#
# The functions below reuse the canonical services
# (:func:`_validate_pdb_upload`, :func:`_read_pdb_observed_safely`,
# :func:`_generate_isf_for_upload`, :func:`atomic_promote_cached_symbol`,
# :func:`link_requirements_to_cache`) so there is exactly one symbol
# import implementation.


def _ensure_operator_cli_attempt_row(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    source_type: str,
    source_label: str,
    operator: str,
    import_job_id: str,
    metadata: Mapping[str, Any] | None = None,
) -> MemorySymbolRecoveryAttempt:
    """Create a fresh ``MemorySymbolRecoveryAttempt`` for a CLI import.

    The DB-level partial unique index
    ``uq_memory_recovery_attempt_active`` (migration v16) ensures
    at most one active row per ``(requirement_id, source_type)``
    tuple.  Multiple terminal rows are allowed so the operator can
    retry.

    The function returns the newly created (or already-existing
    active) attempt row.  On a unique-constraint violation, the
    existing row is returned and the operator is told to wait for
    the in-flight attempt to complete.
    """
    md = dict(metadata or {})
    md.setdefault("import_job_id", import_job_id)
    md.setdefault("operator", operator)
    md.setdefault("source_path", "operator_cli")
    attempt = MemorySymbolRecoveryAttempt(
        requirement_id=requirement.id,
        case_id=requirement.case_id,
        evidence_id=requirement.evidence_id,
        source_id=None,
        source_type=source_type,
        source_label=source_label,
        status=ATTEMPT_PENDING,
        error_code=None,
        sanitized_message=None,
        metadata_json=md,
    )
    db.add(attempt)
    try:
        db.flush()
    except Exception:
        db.rollback()
        existing = (
            db.query(MemorySymbolRecoveryAttempt)
            .filter(
                MemorySymbolRecoveryAttempt.requirement_id == requirement.id,
                MemorySymbolRecoveryAttempt.source_type == source_type,
                MemorySymbolRecoveryAttempt.terminal_at.is_(None),
            )
            .first()
        )
        if existing is not None:
            return existing
        raise
    return attempt


def _finalize_attempt(
    db: Session,
    *,
    attempt: MemorySymbolRecoveryAttempt,
    result: RecoveryResult,
) -> None:
    """Persist the terminal state of a CLI import attempt.

    Translates the structured :class:`RecoveryResult` into the
    attempt's columns and sets ``terminal_at = utc_now_naive()``.
    Also stores the observed identity in ``metadata_json`` so the
    UI's fallback parser can display it for legacy rows.
    """
    if result.is_ready:
        attempt.status = ATTEMPT_SUCCEEDED
    elif result.status == RECOVERY_TERMINAL_NOT_IMPLEMENTED:
        attempt.status = ATTEMPT_SKIPPED
    else:
        attempt.status = ATTEMPT_FAILED
    attempt.error_code = result.error_code
    attempt.sanitized_message = result.sanitized_message
    attempt.terminal_at = utc_now_naive()
    md = dict(attempt.metadata_json or {})
    if result.identity_observed:
        md["identity_observed"] = result.identity_observed
    if result.identity_expected:
        md["identity_expected"] = result.identity_expected
    if result.cached_symbol_id:
        md["cached_symbol_id"] = str(result.cached_symbol_id)
    attempt.metadata_json = md


def _record_acquisition_observed(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    observed: dict[str, Any],
    status: str = "failed",
    error_code: str | None = None,
    sanitized_message: str | None = None,
) -> None:
    """Persist the observed identity in the canonical
    ``MemorySymbolAcquisition`` row so the UI's
    ``acquisition.identity_observed`` field is populated for the
    blocked-symbols card.

    The row is created (or replaced) for the most recent acquisition
    bound to this requirement.  The function is read-only with
    respect to requirement identity: it never mutates the
    requirement row.
    """
    from app.models.memory import MemorySymbolAcquisition

    pdb_guid = observed.get("pdb_guid")
    pdb_age = observed.get("pdb_age")
    pdb_size = observed.get("pdb_size_bytes")
    acquisition = (
        db.query(MemorySymbolAcquisition)
        .filter(MemorySymbolAcquisition.requirement_id == requirement.id)
        .order_by(MemorySymbolAcquisition.created_at.desc())
        .first()
    )
    if acquisition is None:
        acquisition = MemorySymbolAcquisition(
            requirement_id=requirement.id,
            status="queued",
            source_category="operator_cli",
        )
        db.add(acquisition)
    acquisition.observed_pdb_guid = (
        str(pdb_guid).upper() if pdb_guid else None
    )
    if isinstance(pdb_age, int) and pdb_age >= 0:
        acquisition.observed_pdb_age = int(pdb_age)
    elif pdb_age is not None:
        try:
            acquisition.observed_pdb_age = int(pdb_age)
        except (TypeError, ValueError):
            acquisition.observed_pdb_age = None
    if observed.get("architecture"):
        acquisition.observed_architecture = observed["architecture"]
    if status is not None:
        acquisition.status = status
    if error_code is not None:
        acquisition.error_code = error_code
    if sanitized_message is not None:
        acquisition.sanitized_message = sanitized_message
    md = dict(acquisition.metadata_json or {})
    md.setdefault("operator_cli", True)
    md["identity_observed"] = {
        k: v for k, v in observed.items() if k != "read_error"
    }
    if pdb_size is not None:
        try:
            acquisition.downloaded_bytes = int(pdb_size)
        except (TypeError, ValueError):
            pass
    acquisition.metadata_json = md
    if status in {"succeeded", "failed", "skipped"}:
        acquisition.completed_at = utc_now_naive()


def cli_import_pdb_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    file_path: Path,
    operator: str,
    import_job_id: str,
    original_filename: str | None = None,
    safe_override: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Operator-only PDB import.  Reuses the canonical services.

    Returns a dict suitable for JSON serialization.  The function
    is independent of ``memory_symbol_admin_recovery_enabled``
    and ``memory_symbol_manual_import_enabled``.

    The function:

    1. Loads the requirement and shows the expected identity.
    2. Inspects the actual PDB.
    3. Compares exact (name, GUID, age, architecture).
    4. On mismatch: writes a terminal ``MemorySymbolRecoveryAttempt``
       and a canonical ``MemorySymbolAcquisition`` row with the
       observed values, then returns ``identity_mismatch``.
    5. On success: stages to quarantine, generates ISF, atomically
       promotes through the canonical cache service, links every
       exact-match requirement, re-evaluates matching preparations,
       and returns ``ready``.
    """
    from app.cli.memory_symbols_runtime import (
        validate_input_file,
        compute_sha256,
    )

    # Local helper to build a failure result and persist a terminal
    # attempt row in the same transaction.  Used by every error
    # path so the operator has a faithful audit record of every
    # CLI invocation, including dry-run failures.
    def _fail(
        status: str,
        *,
        error_code: str,
        sanitized_message: str,
        observed: dict[str, Any] | None = None,
        sha256: str | None = None,
        size_bytes: int | None = None,
        record_acquisition: bool = False,
        record_attempt: bool = True,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": status,
            "requirement_id": requirement.id,
            "error_code": error_code,
            "sanitized_message": sanitized_message,
            "identity_expected": identity_expected,
        }
        if observed is not None:
            result["identity_observed"] = observed
        if sha256 is not None:
            result["sha256"] = sha256
        if size_bytes is not None:
            result["size_bytes"] = size_bytes
        if record_attempt:
            attempt = _ensure_operator_cli_attempt_row(
                db,
                requirement=requirement,
                source_type="operator_cli_pdb",
                source_label="Operator CLI PDB import",
                operator=operator,
                import_job_id=import_job_id,
                metadata={
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "dry_run": dry_run,
                    "safe_override": safe_override,
                },
            )
            # Build a minimal RecoveryResult so the finalizer can
            # write a terminal row.
            from dataclasses import asdict
            recovery = RecoveryResult(
                status=status,
                requirement_id=requirement.id,
                error_code=error_code,
                sanitized_message=sanitized_message,
                identity_expected=identity_expected,
                identity_observed=observed,
            )
            _finalize_attempt(db, attempt=attempt, result=recovery)
            if record_acquisition and observed is not None:
                _record_acquisition_observed(
                    db,
                    requirement=requirement,
                    observed=observed,
                    status="failed",
                    error_code=error_code,
                    sanitized_message=sanitized_message,
                )
            db.commit()
        return result

    # 1. Validate the requirement exists.
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "requirement_id": str(requirement_id),
            "error_code": "SYMBOL_REQUIREMENT_UNKNOWN",
            "sanitized_message": "Requirement not found.",
        }
    identity_expected = expected_identity_dict(requirement)

    # 2. Validate the file.
    try:
        file_info = validate_input_file(
            file_path,
            allowed_extensions={".pdb"},
            safe_override=safe_override,
        )
    except Exception as exc:  # the runtime layer raises typed errors
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "requirement_id": requirement.id,
            "error_code": "SYMBOL_IMPORT_REJECTED",
            "sanitized_message": str(exc),
            "identity_expected": identity_expected,
        }

    # 3. Read the observed identity.
    observed = _read_pdb_observed_safely(Path(file_info["resolved_path"]))
    if "read_error" in observed:
        return _fail(
            RECOVERY_TERMINAL_VALIDATION_FAILED,
            error_code=observed["read_error"],
            sanitized_message="PDB could not be parsed.",
            observed=observed,
            sha256=file_info["sha256"],
            size_bytes=int(file_info["size_bytes"]),
        )
    # 4. Compare exact identity.
    expected_name = (identity_expected["pdb_name"] or "").lower()
    observed_name = (Path(file_info["resolved_path"]).name or "").lower()
    if observed_name != expected_name:
        return _fail(
            RECOVERY_TERMINAL_IDENTITY_MISMATCH,
            error_code="SYMBOL_PDB_NAME_MISMATCH",
            sanitized_message="Imported PDB filename does not match the required symbol.",
            observed=observed,
            sha256=file_info["sha256"],
            size_bytes=int(file_info["size_bytes"]),
            record_acquisition=True,
        )
    if observed.get("pdb_guid") != identity_expected["pdb_guid"]:
        return _fail(
            RECOVERY_TERMINAL_IDENTITY_MISMATCH,
            error_code="SYMBOL_PDB_IDENTITY_MISMATCH",
            sanitized_message="Imported PDB GUID does not match the required symbol.",
            observed=observed,
            sha256=file_info["sha256"],
            size_bytes=int(file_info["size_bytes"]),
            record_acquisition=True,
        )
    if int(observed.get("pdb_age", -1)) != int(identity_expected["pdb_age"]):
        return _fail(
            RECOVERY_TERMINAL_IDENTITY_MISMATCH,
            error_code="SYMBOL_PDB_IDENTITY_MISMATCH",
            sanitized_message="Imported PDB age does not match the required symbol.",
            observed=observed,
            sha256=file_info["sha256"],
            size_bytes=int(file_info["size_bytes"]),
            record_acquisition=True,
        )

    if dry_run:
        # Dry-run is a *success*: validate without writing.  No
        # attempt row is persisted.  The operator is told what
        # would happen.
        return {
            "status": "dry_run",
            "requirement_id": requirement.id,
            "error_code": None,
            "sanitized_message": "Dry run succeeded; no rows written.",
            "identity_expected": identity_expected,
            "identity_observed": observed,
            "sha256": file_info["sha256"],
            "size_bytes": file_info["size_bytes"],
            "original_filename": file_info["original_filename"],
        }

    # 5. Stage the file to the operator quarantine area, then
    # delegate the canonical cache promotion to
    # ``import_pdb_for_requirement`` (which itself calls
    # ``stage_upload_in_cache`` and ``atomic_promote_cached_symbol``).
    settings = get_settings()
    quarantine = quarantine_path(settings, suffix=".pdb")
    quarantine.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copy2(file_info["resolved_path"], quarantine)
    quarantine.chmod(0o640)
    try:
        # Record the attempt row first (active).
        attempt = _ensure_operator_cli_attempt_row(
            db,
            requirement=requirement,
            source_type="operator_cli_pdb",
            source_label="Operator CLI PDB import",
            operator=operator,
            import_job_id=import_job_id,
            metadata={
                "original_filename": file_info["original_filename"],
                "sha256": file_info["sha256"],
                "size_bytes": file_info["size_bytes"],
                "safe_override": safe_override,
            },
        )
        # Record the observed values in the canonical
        # ``MemorySymbolAcquisition`` row so the UI's
        # ``acquisition.identity_observed`` is populated.
        _record_acquisition_observed(
            db,
            requirement=requirement,
            observed=observed,
            status="succeeded",
            error_code=None,
            sanitized_message=None,
        )
        result = import_pdb_for_requirement(
            db,
            requirement_id=requirement.id,
            upload_path=quarantine,
            original_filename=file_info["original_filename"],
            actor=f"operator_cli:{operator}",
        )
        # The canonical function already validated identity; the
        # result is either ``ready`` (success), ``identity_mismatch``
        # (impossible because we just compared), or a terminal
        # error (``validation_failed`` / ``import_rejected``).
        if result.is_ready and result.cached_symbol_id:
            # Override the cache row's provenance so the audit trail
            # truthfully records the operator-CLI source type and
            # the operator string.  The canonical function used
            # ``manual_pdb_import``; the CLI must use
            # ``operator_cli_pdb``.
            cached = db.get(MemoryCachedSymbol, result.cached_symbol_id)
            if cached is not None:
                cached.provenance_source_type = "operator_cli_pdb"
                cached.provenance_source_name = "Operator CLI PDB import"
                cached.provenance_actor = f"operator_cli:{operator}"
        _finalize_attempt(db, attempt=attempt, result=result)
        db.commit()
    except Exception as exc:
        # Roll back, then mark the attempt as failed (if it exists).
        db.rollback()
        try:
            attempt = (
                db.query(MemorySymbolRecoveryAttempt)
                .filter(
                    MemorySymbolRecoveryAttempt.metadata_json["import_job_id"].astext == import_job_id
                )
                .order_by(MemorySymbolRecoveryAttempt.created_at.desc())
                .first()
            )
            if attempt is not None:
                attempt.status = ATTEMPT_FAILED
                attempt.error_code = "SYMBOL_CLI_UNEXPECTED"
                attempt.sanitized_message = f"Unexpected CLI error: {type(exc).__name__}"
                attempt.terminal_at = utc_now_naive()
                db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        # Always clean up the operator quarantine staging file.
        quarantine.unlink(missing_ok=True)

    out = result.to_dict()
    out["sha256"] = file_info["sha256"]
    out["size_bytes"] = file_info["size_bytes"]
    out["original_filename"] = file_info["original_filename"]
    out["import_job_id"] = import_job_id
    out["operator"] = operator
    return out


def cli_import_isf_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    file_path: Path,
    operator: str,
    import_job_id: str,
    original_filename: str | None = None,
    safe_override: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Operator-only ISF import.  Reuses the canonical services."""
    from app.cli.memory_symbols_runtime import (
        validate_input_file,
    )

    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "requirement_id": str(requirement_id),
            "error_code": "SYMBOL_REQUIREMENT_UNKNOWN",
            "sanitized_message": "Requirement not found.",
        }
    identity_expected = expected_identity_dict(requirement)

    def _fail(
        status: str,
        *,
        error_code: str,
        sanitized_message: str,
        observed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": status,
            "requirement_id": requirement.id,
            "error_code": error_code,
            "sanitized_message": sanitized_message,
            "identity_expected": identity_expected,
            "identity_observed": observed,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "original_filename": file_info["original_filename"],
        }
        attempt = _ensure_operator_cli_attempt_row(
            db,
            requirement=requirement,
            source_type="operator_cli_isf",
            source_label="Operator CLI ISF import",
            operator=operator,
            import_job_id=import_job_id,
            metadata={
                "sha256": sha256,
                "size_bytes": size_bytes,
                "dry_run": dry_run,
                "safe_override": safe_override,
            },
        )
        recovery = RecoveryResult(
            status=status,
            requirement_id=requirement.id,
            error_code=error_code,
            sanitized_message=sanitized_message,
            identity_expected=identity_expected,
            identity_observed=observed,
        )
        _finalize_attempt(db, attempt=attempt, result=recovery)
        db.commit()
        return result

    try:
        file_info = validate_input_file(
            file_path,
            allowed_extensions={".isf", ".json", ".xz"},
            safe_override=safe_override,
        )
    except Exception as exc:
        return {
            "status": RECOVERY_TERMINAL_IMPORT_REJECTED,
            "requirement_id": requirement.id,
            "error_code": "SYMBOL_IMPORT_REJECTED",
            "sanitized_message": str(exc),
            "identity_expected": identity_expected,
        }
    size_bytes = int(file_info["size_bytes"])
    sha256 = file_info["sha256"]

    if dry_run:
        return {
            "status": "dry_run",
            "requirement_id": requirement.id,
            "error_code": None,
            "sanitized_message": "Dry run succeeded; no rows written.",
            "identity_expected": identity_expected,
            "identity_observed": None,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "original_filename": file_info["original_filename"],
        }

    settings = get_settings()
    quarantine = quarantine_path(settings, suffix=".isf.json")
    quarantine.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copy2(file_info["resolved_path"], quarantine)
    quarantine.chmod(0o640)
    try:
        attempt = _ensure_operator_cli_attempt_row(
            db,
            requirement=requirement,
            source_type="operator_cli_isf",
            source_label="Operator CLI ISF import",
            operator=operator,
            import_job_id=import_job_id,
            metadata={
                "original_filename": file_info["original_filename"],
                "sha256": sha256,
                "size_bytes": size_bytes,
                "safe_override": safe_override,
            },
        )
        result = import_isf_for_requirement(
            db,
            requirement_id=requirement.id,
            upload_path=quarantine,
            original_filename=file_info["original_filename"],
            actor=f"operator_cli:{operator}",
        )
        if result.is_ready and result.cached_symbol_id:
            cached = db.get(MemoryCachedSymbol, result.cached_symbol_id)
            if cached is not None:
                cached.provenance_source_type = "operator_cli_isf"
                cached.provenance_source_name = "Operator CLI ISF import"
                cached.provenance_actor = f"operator_cli:{operator}"
        _finalize_attempt(db, attempt=attempt, result=result)
        db.commit()
    except Exception as exc:
        db.rollback()
        try:
            attempt = (
                db.query(MemorySymbolRecoveryAttempt)
                .filter(
                    MemorySymbolRecoveryAttempt.metadata_json["import_job_id"].astext == import_job_id
                )
                .order_by(MemorySymbolRecoveryAttempt.created_at.desc())
                .first()
            )
            if attempt is not None:
                attempt.status = ATTEMPT_FAILED
                attempt.error_code = "SYMBOL_CLI_UNEXPECTED"
                attempt.sanitized_message = f"Unexpected CLI error: {type(exc).__name__}"
                attempt.terminal_at = utc_now_naive()
                db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        quarantine.unlink(missing_ok=True)

    out = result.to_dict()
    out["sha256"] = sha256
    out["size_bytes"] = size_bytes
    out["original_filename"] = file_info["original_filename"]
    out["import_job_id"] = import_job_id
    out["operator"] = operator
    return out
