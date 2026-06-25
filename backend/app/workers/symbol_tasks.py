from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.models.memory import (
    MemoryCachedSymbol,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_egress_client import (
    fetch_pdb_via_egress,
)
from app.services.memory.symbol_fetcher import (
    SymbolFetchError,
    SymbolIdentity,
    generate_isf,
    validate_pdb,
)

# ``SymbolFetchError`` is the single canonical structured acquisition
# exception; both the egress client and the in-fetcher mirror import
# it from :mod:`app.services.memory.symbol_fetcher`, so the worker's
# ``except SymbolFetchError`` catches every failure raised by either
# component.  No module-specific aliases are required.


def _within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def acquire_windows_symbol(acquisition_id: str, request_id: str) -> None:
    """Run a single managed acquisition via the symbol-egress-gateway.

    The acquisition_id identifies the MemorySymbolAcquisition row.
    The request_id identifies the MemorySymbolAcquisitionRequest whose
    approval was already consumed by symbol_control.queue_symbol_acquisition.
    """
    settings = get_settings()
    if not (settings.memory_symbol_managed_download_enabled and settings.memory_symbol_network_isolation_ready):
        raise RuntimeError("Symbol acquisition gates are not enabled.")
    if not settings.memory_symbol_egress_gateway_secret:
        raise RuntimeError("Symbol egress gateway secret is not configured.")
    root = settings.memory_symbol_cache_path.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    with SessionLocal() as db:
        acquisition = db.get(MemorySymbolAcquisition, acquisition_id)
        if acquisition is None:
            return
        request = db.get(MemorySymbolAcquisitionRequest, request_id)
        if request is None:
            acquisition.status = "failed"
            acquisition.error_code = "SYMBOL_REQUEST_MISSING"
            acquisition.sanitized_message = "The trusted symbol acquisition request no longer exists."
            acquisition.completed_at = utc_now_naive()
            db.commit()
            return
        requirement = db.get(MemorySymbolRequirement, acquisition.requirement_id)
        if requirement is None:
            acquisition.status = "failed"
            acquisition.error_code = "SYMBOL_REQUIREMENT_MISSING"
            acquisition.sanitized_message = "The trusted symbol requirement no longer exists."
            acquisition.completed_at = utc_now_naive()
            request.status = "failed"
            request.error_code = acquisition.error_code
            request.sanitized_message = acquisition.sanitized_message
            request.completed_at = utc_now_naive()
            db.commit()
            return
        # Reject fingerprint drift: never run an acquisition against a
        # different symbol identity than the one that was approved.
        from app.services.memory.symbol_approval import requirement_fingerprint
        if request.requirement_fingerprint != requirement_fingerprint(requirement):
            acquisition.status = "failed"
            acquisition.error_code = "SYMBOL_APPROVAL_FINGERPRINT_MISMATCH"
            acquisition.sanitized_message = "The approved fingerprint does not match the current requirement."
            acquisition.completed_at = utc_now_naive()
            request.status = "failed"
            request.error_code = acquisition.error_code
            request.sanitized_message = acquisition.sanitized_message
            request.completed_at = utc_now_naive()
            db.commit()
            return
        existing = db.query(MemoryCachedSymbol).filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key).first()
        if existing:
            acquisition.status, acquisition.validated, acquisition.cached = "completed", True, True
            acquisition.completed_at = utc_now_naive()
            requirement.status, requirement.cached_symbol_id = "cached", existing.id
            request.status = "completed"
            request.completed_at = utc_now_naive()
            request.sanitized_message = "The required symbol was already present in the cache."
            db.commit()
            return
        identity = SymbolIdentity(requirement.pdb_name, requirement.pdb_guid, requirement.pdb_age, requirement.architecture)
        identity.validate()
        safe_key = f"{identity.guid.upper()}-{identity.age}"
        partial = root / "tmp" / f"{acquisition.id}.pdb.partial"
        pdb_final = root / "pdb" / identity.pdb_name.lower() / safe_key / identity.pdb_name.lower()
        isf_final = root / "symbols" / "windows" / identity.pdb_name / f"{identity.guid.upper()}-{identity.age}.json.xz"
        for candidate in (partial, pdb_final, isf_final):
            if not _within(root, candidate.resolve(strict=False)) or candidate.is_symlink():
                raise RuntimeError("Unsafe symbol cache path.")
        acquisition.status = "downloading"
        request.status = "downloading"
        request.started_at = utc_now_naive()
        requirement.status = "acquiring"
        db.commit()
        try:
            usage = sum(item.stat().st_size for item in root.rglob("*") if item.is_file() and not item.is_symlink())
            if usage + int(settings.memory_symbol_download_max_bytes) > int(settings.memory_symbol_cache_max_bytes):
                raise SymbolFetchError("SYMBOL_CACHE_FULL", "The configured symbol cache capacity is insufficient.")
            result = fetch_pdb_via_egress(
                gateway_url=settings.memory_symbol_egress_gateway_url,
                secret=settings.memory_symbol_egress_gateway_secret,
                pdb_name=identity.pdb_name,
                guid=identity.guid,
                age=identity.age,
                timeout_seconds=int(settings.memory_symbol_egress_gateway_timeout_seconds),
                max_response_bytes=int(settings.memory_symbol_egress_max_response_bytes),
                partial_path=partial,
            )
            acquisition.status = "validating_pdb"
            request.status = "validating_pdb"
            acquisition.downloaded_bytes = int(result.bytes_received)
            request.downloaded_bytes = int(result.bytes_received)
            acquisition.pdb_sha256 = str(result.sha256)
            request.redirect_count = int(result.redirect_count)
            acquisition.metadata_json = {
                "redirect_count": int(result.redirect_count),
                "duration_ms": int(result.duration_ms),
                "source_category": "official_microsoft_symbols",
                "egress_gateway": settings.memory_symbol_egress_gateway_url,
            }
            db.commit()
            validation = validate_pdb(partial, identity)
            # The identity has been confirmed by the PDB parser; record
            # the observed identity in the acquisition row for audit and
            # proceed.  ``validate_pdb`` raises SYMBOL_PDB_IDENTITY_MISMATCH
            # on any GUID or age discrepancy; the requirement is never
            # silently rewritten.
            acquisition.observed_pdb_guid = str(validation["guid"])
            acquisition.observed_pdb_age = int(validation["age"])
            acquisition.observed_architecture = str(validation["architecture"])
            acquisition.metadata_json = {
                **(acquisition.metadata_json or {}),
                "identity_expected": {
                    "pdb_name": identity.pdb_name,
                    "pdb_guid": identity.guid.upper(),
                    "pdb_age": int(identity.age),
                    "architecture": identity.architecture,
                },
                "identity_observed": {
                    "pdb_guid": str(validation["guid"]),
                    "pdb_age": int(validation["age"]),
                    "architecture": str(validation["architecture"]),
                },
            }
            db.commit()
            pdb_final.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            if pdb_final.exists():
                partial.unlink(missing_ok=True)
            else:
                os.replace(partial, pdb_final)
            acquisition.status = "generating_isf"
            request.status = "generating_isf"
            db.commit()
            isf_result = generate_isf(pdb_final, isf_final, identity, max_bytes=int(settings.memory_symbol_isf_max_bytes))
            cached = MemoryCachedSymbol(
                symbol_key=requirement.symbol_key,
                pdb_name=identity.pdb_name,
                pdb_guid=identity.guid.upper(),
                pdb_age=identity.age,
                architecture=identity.architecture,
                pdb_relative_path=str(pdb_final.relative_to(root)),
                isf_relative_path=str(isf_final.relative_to(root)),
                pdb_sha256=str(result.sha256),
                isf_sha256=str(isf_result["sha256"]),
                pdb_size_bytes=int(result.bytes_received),
                isf_size_bytes=int(isf_result["bytes"]),
                provenance_source_type="microsoft_public",
                provenance_source_name="Microsoft public",
                provenance_actor="symbol-fetcher",
                provenance_acquired_at=utc_now_naive(),
            )
            db.add(cached)
            db.flush()
            acquisition.status, acquisition.validated, acquisition.cached = "completed", True, True
            acquisition.isf_sha256 = str(isf_result["sha256"])
            acquisition.completed_at = utc_now_naive()
            requirement.status, requirement.cached_symbol_id = "cached", cached.id
            request.status = "completed"
            request.completed_at = utc_now_naive()
            request.sanitized_message = "The required Windows symbol was acquired, validated, and cached."
            db.commit()
        except SymbolFetchError as exc:
            partial.unlink(missing_ok=True)
            acquisition.status = "timeout" if exc.code == "SYMBOL_EGRESS_TIMEOUT" else "failed"
            acquisition.error_code = exc.code
            acquisition.sanitized_message = exc.message
            acquisition.retryable = exc.retryable
            acquisition.completed_at = utc_now_naive()
            # On PDB identity mismatch, the downloaded file passed the
            # byte-level parser but reported a different GUID or age
            # than the requirement.  Surface the observed values in
            # the acquisition row so the operator can see exactly
            # what the symbol server returned.  A mismatch is a
            # deterministic failure: the same URL will always return
            # the same file, so ``retryable`` stays False.
            if exc.code == "SYMBOL_PDB_IDENTITY_MISMATCH" and partial.exists():
                try:
                    from app.services.memory.symbol_fetcher import read_pdb_identity
                    observed_guid, observed_age = read_pdb_identity(partial)
                    acquisition.observed_pdb_guid = str(observed_guid)
                    acquisition.observed_pdb_age = int(observed_age)
                except Exception:
                    pass
            acquisition.metadata_json = {
                **(acquisition.metadata_json or {}),
                "identity_expected": {
                    "pdb_name": identity.pdb_name,
                    "pdb_guid": identity.guid.upper(),
                    "pdb_age": int(identity.age),
                    "architecture": identity.architecture,
                },
            }
            if acquisition.observed_pdb_guid is not None:
                acquisition.metadata_json["identity_observed"] = {
                    "pdb_guid": str(acquisition.observed_pdb_guid),
                    "pdb_age": int(acquisition.observed_pdb_age) if acquisition.observed_pdb_age is not None else None,
                    "architecture": acquisition.observed_architecture,
                }
            request.status = acquisition.status
            request.error_code = acquisition.error_code
            request.sanitized_message = acquisition.sanitized_message
            request.completed_at = utc_now_naive()
            requirement.status = "failed"
            requirement.error_code = acquisition.error_code
            requirement.sanitized_message = acquisition.sanitized_message
            db.commit()
        except Exception as exc:  # noqa: BLE001
            import traceback
            tb = traceback.format_exc()
            partial.unlink(missing_ok=True)
            acquisition.status = "failed"
            acquisition.error_code = "SYMBOL_ACQUISITION_FAILED"
            acquisition.sanitized_message = f"The controlled symbol acquisition task failed: {type(exc).__name__}: {str(exc)[:256]}"
            acquisition.retryable = False
            acquisition.completed_at = utc_now_naive()
            acquisition.metadata_json = {**(acquisition.metadata_json or {}), "traceback": tb[-2048:]}
            request.status = "failed"
            request.error_code = acquisition.error_code
            request.sanitized_message = acquisition.sanitized_message
            request.completed_at = utc_now_naive()
            requirement.status = "failed"
            requirement.error_code = acquisition.error_code
            requirement.sanitized_message = acquisition.sanitized_message
            db.commit()
            # Also log to stderr for visibility
            import logging
            logging.getLogger("rq.worker").error("Symbol acquisition failed for %s: %s\n%s", acquisition.id, exc, tb)


def run_admin_pdb_import(import_id: str) -> None:
    """Process a queued administrator PDB import.

    The HTTP request records the job and returns 202.  This
    worker function performs the expensive steps: PDB identity
    validation, Volatility PDB-to-ISF generation, ISF schema
    validation, and atomic cache promotion.  All four steps
    are bounded by per-file and per-job resource limits.

    The ``import_id`` identifies a
    ``MemorySymbolRecoveryAttempt`` row (the orchestrator
    creates it in the ``pending`` state with the upload path
    in ``metadata_json``).
    """
    from sqlalchemy import desc
    from app.models.memory import (
        MemorySymbolRecoveryAttempt,
    )
    from app.services.memory.symbol_recovery import (
        RECOVERY_TERMINAL_NOT_IMPLEMENTED,
        RECOVERY_TERMINAL_READY,
        RECOVERY_TERMINAL_VALIDATION_FAILED,
        RECOVERY_TERMINAL_IMPORT_REJECTED,
        import_pdb_for_requirement,
    )
    db = SessionLocal()
    try:
        attempt = db.get(MemorySymbolRecoveryAttempt, str(import_id))
        if attempt is None:
            return
        metadata = dict(attempt.metadata_json or {})
        requirement_id = str(metadata.get("requirement_id") or "")
        upload_path = metadata.get("upload_path")
        original_filename = metadata.get("original_filename") or "upload.pdb"
        if not requirement_id or not upload_path:
            attempt.status = "failed"
            attempt.error_code = "SYMBOL_IMPORT_REJECTED"
            attempt.sanitized_message = "Queued import missing requirement_id or upload_path."
            attempt.terminal_at = utc_now_naive()
            db.commit()
            return
        from pathlib import Path
        upload = Path(str(upload_path))
        result = import_pdb_for_requirement(
            db,
            requirement_id=requirement_id,
            upload_path=upload,
            original_filename=str(original_filename),
            actor="admin-worker",
        )
        attempt.status = (
            "succeeded" if result.status == RECOVERY_TERMINAL_READY else "failed"
        )
        attempt.error_code = result.error_code
        attempt.sanitized_message = result.sanitized_message
        attempt.terminal_at = utc_now_naive()
        db.commit()
    finally:
        db.close()


def run_admin_isf_import(import_id: str) -> None:
    """Process a queued administrator ISF import.

    The HTTP request records the job and returns 202.  This
    worker performs the safe-parse validation, the identity
    check, and the atomic cache promotion.
    """
    from app.models.memory import (
        MemorySymbolRecoveryAttempt,
    )
    from app.services.memory.symbol_recovery import (
        RECOVERY_TERMINAL_READY,
        import_isf_for_requirement,
    )
    from pathlib import Path
    db = SessionLocal()
    try:
        attempt = db.get(MemorySymbolRecoveryAttempt, str(import_id))
        if attempt is None:
            return
        metadata = dict(attempt.metadata_json or {})
        requirement_id = str(metadata.get("requirement_id") or "")
        upload_path = metadata.get("upload_path")
        original_filename = metadata.get("original_filename") or "upload.isf"
        if not requirement_id or not upload_path:
            attempt.status = "failed"
            attempt.error_code = "SYMBOL_IMPORT_REJECTED"
            attempt.sanitized_message = "Queued import missing requirement_id or upload_path."
            attempt.terminal_at = utc_now_naive()
            db.commit()
            return
        upload = Path(str(upload_path))
        result = import_isf_for_requirement(
            db,
            requirement_id=requirement_id,
            upload_path=upload,
            original_filename=str(original_filename),
            actor="admin-worker",
        )
        attempt.status = (
            "succeeded" if result.status == RECOVERY_TERMINAL_READY else "failed"
        )
        attempt.error_code = result.error_code
        attempt.sanitized_message = result.sanitized_message
        attempt.terminal_at = utc_now_naive()
        db.commit()
    finally:
        db.close()


def run_admin_package_import(import_id: str) -> None:
    """Process a queued administrator offline package import."""
    from app.models.memory import (
        MemorySymbolRecoveryAttempt,
    )
    from app.services.memory.symbol_recovery import (
        RECOVERY_TERMINAL_READY,
        import_offline_package,
    )
    from pathlib import Path
    db = SessionLocal()
    try:
        attempt = db.get(MemorySymbolRecoveryAttempt, str(import_id))
        if attempt is None:
            return
        metadata = dict(attempt.metadata_json or {})
        upload_path = metadata.get("upload_path")
        if not upload_path:
            attempt.status = "failed"
            attempt.error_code = "SYMBOL_IMPORT_REJECTED"
            attempt.sanitized_message = "Queued import missing upload_path."
            attempt.terminal_at = utc_now_naive()
            db.commit()
            return
        upload = Path(str(upload_path))
        result = import_offline_package(
            db, upload_path=upload, actor="admin-worker",
        )
        status = result.get("status", "failed")
        attempt.status = (
            "succeeded" if status == RECOVERY_TERMINAL_READY else "failed"
        )
        attempt.error_code = result.get("error_code")
        attempt.sanitized_message = result.get("sanitized_message")
        attempt.terminal_at = utc_now_naive()
        db.commit()
    finally:
        db.close()
