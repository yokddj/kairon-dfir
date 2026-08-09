"""Evidence-scoped Linux ISF validation and association (Memory Preparation Phase 3).

This module is the orchestration layer on top of
app.services.memory.linux_symbols -- it knows about Evidence rows, the
database, the async job lifecycle, and the four-state validation
contract the API exposes (VALID / INVALID / UNSUPPORTED /
VALIDATION_FAILED). linux_symbols.py itself stays exactly what it was
before this phase: a platform-agnostic cache of prebuilt ISFs with no
knowledge of evidence, cases, the database, or async jobs. This module
deliberately does not re-implement any parsing/shape/decompression
validation -- it calls inspect_linux_isf() (read-only, never promotes,
run in an isolated subprocess so a timeout is real) and
import_linux_isf() (promotes) exactly as they exist, and only adds:

* the async job lifecycle (queued -> validating -> terminal state),
  persisted on app.models.memory.MemoryEvidenceLinuxSymbolLink so it
  survives a worker restart;
* the evidence <-> ISF compatibility comparison for THIS evidence;
* backfilling the evidence's confirmed kernel identity so that
  app.services.memory.analysis_plan's existing, untouched readiness
  computation (build_memory_analysis_plan -> resolve_linux_symbols)
  naturally reports READY on the next read -- no new "is this evidence
  ready" logic is introduced here.

Two entry points matter architecturally:

* create_linux_symbol_validation_job() runs in the BACKEND API process
  (read-only /volatility-cache mount). It only ever touches the
  evidence-scoped staging area (never the shared symbol cache) and a
  Postgres row.
* execute_linux_symbol_validation() runs on the MEMORY-WORKER (the only
  process with a read-write /volatility-cache mount -- see
  docker-compose.yml). This is the only function in this module that
  calls import_linux_isf() (which writes to the shared cache) or writes
  a "valid" terminal state.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.evidence import Evidence
from app.models.memory import MemoryEvidenceLinuxSymbolLink
from app.services.memory.linux_symbols import (
    LinuxSymbolError,
    LinuxSymbolIdentity,
    expected_linux_identity_from_evidence,
    import_linux_isf,
)

logger = logging.getLogger(__name__)

STATUS_QUEUED = "queued"
STATUS_VALIDATING = "validating"
STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_UNSUPPORTED = "unsupported"
STATUS_VALIDATION_FAILED = "validation_failed"

NON_TERMINAL_STATUSES = {STATUS_QUEUED, STATUS_VALIDATING}
TERMINAL_STATUSES = {STATUS_VALID, STATUS_INVALID, STATUS_UNSUPPORTED, STATUS_VALIDATION_FAILED}

# app.services.memory.linux_symbols.LinuxSymbolError.code -> the bucket
# this Phase 3 endpoint reports it under. A code missing from this map is
# a bug (see TestErrorCodeTaxonomy in tests/test_linux_symbols_security.py
# pinning every code linux_symbols.py can currently raise) -- it falls
# back to VALIDATION_FAILED rather than crashing the request.
_UNSUPPORTED_CODES = {"SYMBOL_UNSUPPORTED_PLATFORM", "SYMBOL_UNSUPPORTED_FORMAT"}
_ACCEPTED_EXTENSIONS = (".json", ".json.xz")


class DuplicateValidationJobError(ValueError):
    """Raised when a queued/validating job already exists for this evidence."""


@dataclass(frozen=True)
class LinuxSymbolValidationOutcome:
    validation_id: str
    status: str
    expected_identity: LinuxSymbolIdentity | dict | None
    detected_identity: LinuxSymbolIdentity | dict | None
    compatible: bool
    reason: str
    cached: bool
    cache_key: str | None


def has_accepted_isf_extension(filename: str) -> bool:
    lowered = (filename or "").strip().lower()
    return lowered.endswith(_ACCEPTED_EXTENSIONS)


def _identity_fields(identity: LinuxSymbolIdentity | dict | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    data = asdict(identity) if isinstance(identity, LinuxSymbolIdentity) else identity
    return {
        "architecture": data.get("architecture"),
        "kernel_release": data.get("kernel_release"),
        "banner": data.get("banner"),
        "build_id": data.get("build_id"),
    }


def _mismatch_reason(expected: LinuxSymbolIdentity, detected: LinuxSymbolIdentity) -> str:
    mismatched: list[str] = []
    for field in ("kernel_release", "architecture", "banner", "build_id"):
        expected_value = getattr(expected, field)
        detected_value = getattr(detected, field)
        if expected_value and detected_value and str(expected_value).strip().lower() != str(detected_value).strip().lower():
            mismatched.append(field)
        elif expected_value and not detected_value:
            mismatched.append(field)
    if not mismatched:
        return "The uploaded ISF does not match this evidence's kernel identity."
    return f"The uploaded ISF does not match this evidence's {', '.join(mismatched)}."


# ---------------------------------------------------------------------------
# Backend API process: enqueue only. Never touches /volatility-cache.
# ---------------------------------------------------------------------------


def create_linux_symbol_validation_job(
    db: Session,
    evidence: Evidence,
    *,
    staging_path: Path,
) -> MemoryEvidenceLinuxSymbolLink:
    """Create (or reuse) the job row for this evidence and mark it queued.

    Runs in the backend API process. Only ever writes to Postgres and
    reads the already-staged file's path -- never touches
    /volatility-cache, which this process cannot write to.

    Raises DuplicateValidationJobError if a queued/validating job already
    exists for this evidence (the caller should reject the new upload
    with a 409 rather than starting a second, concurrent validation of
    the same evidence).
    """
    existing = db.query(MemoryEvidenceLinuxSymbolLink).filter(
        MemoryEvidenceLinuxSymbolLink.evidence_id == evidence.id
    ).one_or_none()
    if existing is not None and existing.status in NON_TERMINAL_STATUSES:
        raise DuplicateValidationJobError(
            f"A Linux symbol validation is already {existing.status} for this evidence."
        )
    if existing is None:
        existing = MemoryEvidenceLinuxSymbolLink(case_id=evidence.case_id, evidence_id=evidence.id)
        db.add(existing)
    existing.status = STATUS_QUEUED
    existing.staging_path = str(staging_path)
    existing.reason = None
    existing.expected_identity_json = None
    existing.detected_identity_json = None
    existing.queued_at = utc_now_naive()
    existing.started_at = None
    existing.completed_at = None
    db.commit()
    db.refresh(existing)
    return existing


def get_linux_symbol_validation_status(db: Session, evidence_id: str, validation_id: str) -> LinuxSymbolValidationOutcome | None:
    """Read-only status lookup for the frontend's polling loop.

    Also performs lazy staleness reconciliation: a row stuck in
    queued/validating long past the worker's own timeout budget (the
    worker process itself may have died, e.g. an OOM-killed container --
    not just the isolated validation subprocess, which already has its
    own real kill path) is marked validation_failed here, on read,
    instead of requiring a separate scheduled sweep. Mirrors the
    staleness-detection *concept* in
    app.services.memory.preparation_runtime.reconcile_stale_preparations
    without its heartbeat/redispatch machinery, which this job does not
    need: a stale Linux ISF validation is never auto-retried, the
    analyst chooses another file.
    """
    job = db.query(MemoryEvidenceLinuxSymbolLink).filter(
        MemoryEvidenceLinuxSymbolLink.evidence_id == evidence_id,
        MemoryEvidenceLinuxSymbolLink.id == validation_id,
    ).one_or_none()
    if job is None:
        return None
    if job.status in NON_TERMINAL_STATUSES:
        _reconcile_if_stale(db, job)
    return _outcome_from_job(job)


def _reconcile_if_stale(db: Session, job: MemoryEvidenceLinuxSymbolLink) -> None:
    from app.core.config import get_settings

    settings = get_settings()
    budget = int(getattr(settings, "memory_linux_symbol_validation_timeout_seconds", 30))
    grace = int(getattr(settings, "memory_linux_symbol_validation_termination_grace_seconds", 5))
    stale_after = 2 * (budget + grace) + 30
    anchor = job.started_at or job.queued_at or job.created_at
    if anchor is None:
        return
    age = (utc_now_naive() - anchor).total_seconds()
    if age < stale_after:
        return
    logger.warning(
        "linux symbol validation job stale, marking validation_failed",
        extra={"job_id": job.id, "evidence_id": job.evidence_id, "age_seconds": age},
    )
    _cleanup_staging(job)
    job.status = STATUS_VALIDATION_FAILED
    job.reason = "Validation did not complete in time (worker may have restarted)."
    job.completed_at = utc_now_naive()
    db.commit()


def _outcome_from_job(job: MemoryEvidenceLinuxSymbolLink) -> LinuxSymbolValidationOutcome:
    return LinuxSymbolValidationOutcome(
        validation_id=job.id,
        status=job.status,
        expected_identity=job.expected_identity_json,
        detected_identity=job.detected_identity_json,
        compatible=job.status == STATUS_VALID,
        reason=job.reason or "",
        cached=bool(job.cached),
        cache_key=job.cache_key,
    )


def _cleanup_staging(job: MemoryEvidenceLinuxSymbolLink) -> None:
    if not job.staging_path:
        return
    try:
        Path(job.staging_path).unlink(missing_ok=True)
    except OSError:
        logger.warning("failed to clean up Linux ISF staging file", extra={"job_id": job.id, "path": job.staging_path})
    job.staging_path = None


# ---------------------------------------------------------------------------
# Memory-worker process only: the only place that reads a staged ISF,
# runs the isolated validation subprocess, and (on VALID) writes to the
# shared /volatility-cache.
# ---------------------------------------------------------------------------


def execute_linux_symbol_validation(job_id: str, *, db: Session | None = None) -> None:
    """Worker entry point (invoked by app.workers.tasks.run_linux_symbol_validation).

    Validates the staged ISF in an isolated subprocess (a real, killable
    OS process -- see app.services.memory.subprocess_isolation), compares
    identity, and -- only when compatible -- promotes it via the
    unmodified import_linux_isf() and persists the link. Every other
    outcome cleans up staging and leaves the shared cache and this
    evidence's readiness untouched.

    ``db`` is normally omitted in production (the real call from
    app.workers.tasks.run_linux_symbol_validation takes zero extra
    arguments) -- it exists so tests can inject an isolated session
    instead of this function opening its own connection to the
    globally-configured database.
    """
    from app.core.config import get_settings
    from app.core.database import SessionLocal

    settings = get_settings()
    owns_session = db is None
    db = db or SessionLocal()
    try:
        job = db.get(MemoryEvidenceLinuxSymbolLink, job_id)
        if job is None:
            logger.warning("linux symbol validation job vanished before execution", extra={"job_id": job_id})
            return
        evidence = db.get(Evidence, job.evidence_id)
        if evidence is None or not job.staging_path:
            _fail_job(db, job, STATUS_VALIDATION_FAILED, "The source evidence or staged file is no longer available.")
            return

        job.status = STATUS_VALIDATING
        job.started_at = utc_now_naive()
        db.commit()

        required_identity = expected_linux_identity_from_evidence(evidence)
        job.expected_identity_json = _identity_fields(required_identity)
        db.commit()

        staging_path = Path(job.staging_path)
        detected_identity, outcome_status, outcome_reason = _inspect_isolated(staging_path, settings=settings)

        if outcome_status is not None:
            _fail_job(db, job, outcome_status, outcome_reason)
            return

        assert detected_identity is not None  # for type-checkers; guaranteed by the branch above
        job.detected_identity_json = _identity_fields(detected_identity)
        db.commit()

        if not detected_identity.compatible_with(required_identity):
            reason = (
                _mismatch_reason(required_identity, detected_identity)
                if required_identity
                else "The uploaded ISF is not compatible with this evidence."
            )
            job.cache_key = detected_identity.cache_key
            _fail_job(db, job, STATUS_INVALID, reason)
            return

        _promote_and_link(db, job, evidence, staging_path=staging_path, identity=detected_identity, settings=settings)
    finally:
        if owns_session:
            db.close()


def _inspect_isolated(
    staging_path: Path, *, settings: Any
) -> tuple[LinuxSymbolIdentity | None, str | None, str]:
    """Run inspect_linux_isf() in an isolated subprocess with a real,
    enforceable timeout. Returns (identity, None, "") on success, or
    (None, outcome_status, reason) on any failure -- including a genuine
    timeout, which is reported as VALIDATION_FAILED, exactly like any
    other "could not validate this file" outcome.
    """
    import json
    import sys

    from app.services.memory.subprocess_isolation import SubprocessIsolationTimeout, run_isolated

    timeout_seconds = int(getattr(settings, "memory_linux_symbol_validation_timeout_seconds", 30))
    grace_seconds = int(getattr(settings, "memory_linux_symbol_validation_termination_grace_seconds", 5))
    max_bytes = int(getattr(settings, "memory_linux_symbol_isf_upload_max_bytes", 268435456))
    decompressed_max_bytes = int(getattr(settings, "memory_linux_symbol_isf_decompressed_max_bytes", 536870912))

    argv = [
        sys.executable,
        "-m",
        "app.services.memory.linux_symbols_validate_subprocess",
        str(staging_path),
        str(max_bytes),
        str(decompressed_max_bytes),
    ]
    try:
        result = run_isolated(argv, timeout_seconds=timeout_seconds, termination_grace_seconds=grace_seconds)
    except SubprocessIsolationTimeout:
        return None, STATUS_VALIDATION_FAILED, "Linux ISF validation exceeded the configured time limit and was terminated."

    if result.returncode != 0:
        logger.warning("linux ISF validation subprocess exited non-zero", extra={"returncode": result.returncode, "stderr": result.stderr[:4096].decode("utf-8", "replace")})
        return None, STATUS_VALIDATION_FAILED, "Linux ISF could not be validated."
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, STATUS_VALIDATION_FAILED, "Linux ISF could not be validated."
    if not payload.get("ok"):
        code = str(payload.get("code") or "SYMBOL_PARSE_FAILED")
        message = str(payload.get("message") or "Linux ISF could not be validated.")
        status = STATUS_UNSUPPORTED if code in _UNSUPPORTED_CODES else STATUS_VALIDATION_FAILED
        return None, status, message
    identity = LinuxSymbolIdentity(**payload["identity"])
    return identity, None, ""


def _promote_and_link(
    db: Session,
    job: MemoryEvidenceLinuxSymbolLink,
    evidence: Evidence,
    *,
    staging_path: Path,
    identity: LinuxSymbolIdentity,
    settings: Any,
) -> None:
    """Steps 3-8 of the atomic-promotion order: hash/dedup check (inside
    import_linux_isf), atomic cache write, link upsert, evidence metadata
    backfill, terminal status. Any failure from step 4 onward leaves the
    job in validation_failed rather than valid -- it is never left
    half-updated: the link fields and status are only written together,
    in the same DB transaction, after import_linux_isf() has already
    either fully succeeded or raised.
    """
    try:
        promoted = import_linux_isf(
            staging_path,
            original_filename=f"{job.id}.json",
            source=f"evidence_scoped_upload:{evidence.id}",
            settings=settings,
        )
    except LinuxSymbolError as exc:
        # A collision (a different ISF already occupies this cache_key) or
        # any other promotion-time rejection -- never reported as VALID.
        _fail_job(db, job, STATUS_VALIDATION_FAILED, exc.message)
        return

    job.cache_key = identity.cache_key
    job.isf_path = promoted.path
    job.sha256 = promoted.sha256
    job.identity_display = identity.display
    job.identity_json = asdict(identity)
    job.cached = bool(promoted.duplicate)
    job.status = STATUS_VALID
    job.reason = None
    job.completed_at = utc_now_naive()
    metadata = dict(evidence.metadata_json or {})
    metadata["linux_symbol_identity"] = _identity_fields(identity)
    evidence.metadata_json = metadata
    _cleanup_staging(job)
    db.commit()


def _fail_job(db: Session, job: MemoryEvidenceLinuxSymbolLink, status: str, reason: str) -> None:
    _cleanup_staging(job)
    job.status = status
    job.reason = reason
    job.completed_at = utc_now_naive()
    db.commit()


def get_linux_symbol_link(db: Session, evidence_id: str) -> MemoryEvidenceLinuxSymbolLink | None:
    """Return the active (status == valid) link row for this evidence, if any."""
    return db.query(MemoryEvidenceLinuxSymbolLink).filter(
        MemoryEvidenceLinuxSymbolLink.evidence_id == evidence_id,
        MemoryEvidenceLinuxSymbolLink.status == STATUS_VALID,
    ).one_or_none()
