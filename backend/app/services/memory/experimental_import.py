"""Operator-controlled experimental mismatched-symbol import flow.

This module creates a *separate* cache entry for a same-name /
same-GUID / different-age symbol candidate.  The exact symbol cache
lookup remains unchanged because the experimental cache row uses the
observed identity's symbol_key and is classified as
``experimental_candidate``.
"""
from __future__ import annotations

import json
import logging
import lzma
import os
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.cli.memory_symbols_runtime import validate_input_file
from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.memory import MemoryCachedSymbol, MemoryExperimentalSymbolCandidate, MemorySymbolRequirement
from app.services.memory.experimental_trust import (
    CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
    SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH,
    architectures_compatible,
    normalize_pdb_name,
)
from app.services.memory.symbol_fetcher import SymbolFetchError, SymbolIdentity, generate_isf, read_pdb_identity
from app.services.memory.symbol_recovery import IsfResourceLimitError, _safe_json_load, hash_file
from app.services.memory.symbol_resolver import symbol_identifier


logger = logging.getLogger(__name__)


class ExperimentalImportError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def experimental_cache_root() -> Path:
    settings = get_settings()
    return settings.backend_data_dir / "experimental-symbol-cache"


def _quarantine_root() -> Path:
    settings = get_settings()
    base = str(settings.memory_symbol_import_quarantine_root or "").strip()
    if base:
        return Path(base) / "experimental"
    return settings.backend_temp_dir / "symbol-import-quarantine" / "experimental"


def _ensure_regular_readable_file(path: Path) -> None:
    if not path.exists():
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_FILE_MISSING", "Experimental candidate file is missing from server-controlled storage.")
    if path.is_symlink() or not path.is_file():
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_FILE_INVALID", "Experimental candidate file is not a stable regular file.")


def _stage_to_quarantine(source: Path, *, suffix: str) -> Path:
    root = _quarantine_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    target = root / f"{uuid4().hex}{suffix}"
    shutil.copy2(source, target)
    os.chmod(target, 0o640)
    return target


def _cleanup_paths(*paths: Path | None) -> None:
    for path in paths:
        if path is None:
            continue
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)


def _parse_isf_payload(path: Path) -> dict[str, Any]:
    settings = get_settings()
    try:
        if path.suffix.lower() == ".xz":
            with lzma.open(path, "rb") as handle:
                payload = _safe_json_load(handle, settings)
        else:
            with path.open("rb") as handle:
                payload = _safe_json_load(handle, settings)
    except IsfResourceLimitError as exc:
        raise ExperimentalImportError(
            "EXPERIMENTAL_ISF_RESOURCE_LIMIT_EXCEEDED",
            "Experimental ISF payload exceeds a server-side resource limit.",
        ) from exc
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ExperimentalImportError(
            "EXPERIMENTAL_ISF_PARSE_FAILED",
            f"Experimental ISF could not be parsed: {type(exc).__name__}.",
        ) from exc
    if not isinstance(payload, dict):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_PARSE_FAILED", "Experimental ISF payload is not a JSON object.")
    return payload


def _read_isf_identity(path: Path, *, required_name: str) -> dict[str, Any]:
    payload = _parse_isf_payload(path)
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_IDENTITY_MISSING", "Experimental ISF payload has no metadata section.")
    windows = metadata.get("windows")
    if not isinstance(windows, dict):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_IDENTITY_MISSING", "Experimental ISF payload has no windows metadata block.")
    pdb_metadata = windows.get("pdb")
    if not isinstance(pdb_metadata, dict):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_IDENTITY_MISSING", "Experimental ISF payload has no PDB identity block.")
    guid = str(pdb_metadata.get("GUID") or "").replace("-", "").replace("{", "").replace("}", "").upper()
    try:
        age = int(pdb_metadata.get("age"))
    except (TypeError, ValueError):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_IDENTITY_MISSING", "Experimental ISF payload has no valid PDB age.") from None
    architecture = str(
        windows.get("architecture")
        or windows.get("arch")
        or metadata.get("architecture")
        or metadata.get("arch")
        or ""
    ).strip()
    observed_name = str(pdb_metadata.get("database") or required_name).strip() or required_name
    if not isinstance(payload.get("symbols"), dict) or not isinstance(payload.get("user_types"), dict):
        raise ExperimentalImportError("EXPERIMENTAL_ISF_SCHEMA_INVALID", "Experimental ISF is missing required Volatility sections.")
    return {
        "payload": payload,
        "pdb_name": observed_name,
        "pdb_guid": guid,
        "pdb_age": age,
        "architecture": architecture,
    }


def _validate_requirement(requirement: MemorySymbolRequirement) -> None:
    if requirement is None:
        raise ExperimentalImportError("EXPERIMENTAL_REQUIREMENT_MISSING", "Requirement not found.")


def _evaluate_eligibility(
    requirement: MemorySymbolRequirement,
    *,
    observed_name: str,
    observed_guid: str,
    observed_age: int,
    observed_architecture: str,
) -> dict[str, Any]:
    required_name = normalize_pdb_name(requirement.pdb_name)
    if normalize_pdb_name(observed_name) != required_name:
        raise ExperimentalImportError("EXPERIMENTAL_NAME_MISMATCH", "Candidate PDB name does not match the required symbol name.")
    if str(observed_guid or "").upper() != str(requirement.pdb_guid or "").upper():
        raise ExperimentalImportError("EXPERIMENTAL_GUID_MISMATCH", "Candidate GUID does not match the required symbol GUID.")
    if int(observed_age) == int(requirement.pdb_age):
        raise ExperimentalImportError("EXPERIMENTAL_EXACT_MATCH_NOT_ELIGIBLE", "Exact-age symbols must use the strict exact-symbol import path.")
    if not observed_guid or not observed_name:
        raise ExperimentalImportError("EXPERIMENTAL_IDENTITY_INCOMPLETE", "Candidate identity is incomplete.")
    if observed_architecture and not architectures_compatible(requirement.architecture, observed_architecture):
        raise ExperimentalImportError("EXPERIMENTAL_ARCHITECTURE_MISMATCH", "Candidate architecture is not compatible with the required architecture.")
    return {
        "required_identity": {
            "pdb_name": requirement.pdb_name,
            "pdb_guid": requirement.pdb_guid,
            "pdb_age": int(requirement.pdb_age),
            "architecture": requirement.architecture,
        },
        "observed_identity": {
            "pdb_name": observed_name,
            "pdb_guid": observed_guid,
            "pdb_age": int(observed_age),
            "architecture": observed_architecture or requirement.architecture,
        },
        "symbol_warning": (
            f"Same name and GUID, but age differs (required={int(requirement.pdb_age)}, observed={int(observed_age)})."
        ),
    }


def inspect_experimental_pdb_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    file_path: Path,
    safe_override: bool = False,
) -> dict[str, Any]:
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    _validate_requirement(requirement)
    file_info = validate_input_file(file_path, allowed_extensions={".pdb"}, safe_override=safe_override)
    observed_guid, observed_age = read_pdb_identity(Path(file_info["resolved_path"]))
    observed_name = Path(str(file_info["resolved_path"])).name
    verdict = _evaluate_eligibility(
        requirement,
        observed_name=observed_name,
        observed_guid=observed_guid,
        observed_age=observed_age,
        observed_architecture=requirement.architecture,
    )
    return {
        "status": "eligible",
        "requirement_id": requirement.id,
        "sha256": file_info["sha256"],
        "size_bytes": int(file_info["size_bytes"]),
        "original_filename": file_info["original_filename"],
        **verdict,
    }


def _experimental_relative_paths(requirement: MemorySymbolRequirement, observed_identity: dict[str, Any]) -> tuple[Path, Path]:
    observed_name = str(observed_identity["pdb_name"])
    observed_guid = str(observed_identity["pdb_guid"]).upper()
    observed_age = int(observed_identity["pdb_age"])
    key = f"{observed_guid}-{observed_age}"
    pdb_relative = Path("pdb") / observed_name.lower() / key / observed_name
    isf_relative = Path("symbols") / "windows" / requirement.pdb_name / f"{key}.json.xz"
    return pdb_relative, isf_relative


def _upsert_experimental_cache_row(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    observed_identity: dict[str, Any],
    pdb_relative: Path,
    isf_relative: Path,
    pdb_sha256: str,
    isf_sha256: str,
    pdb_size: int,
    isf_size: int,
    provenance_source_type: str,
    provenance_source_name: str,
    provenance_actor: str,
) -> MemoryCachedSymbol:
    observed_key = symbol_identifier(
        observed_identity["pdb_name"],
        observed_identity["pdb_guid"],
        int(observed_identity["pdb_age"]),
    )
    existing = db.query(MemoryCachedSymbol).filter(MemoryCachedSymbol.symbol_key == observed_key).first()
    if existing is not None:
        if existing.cache_classification != CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE:
            raise ExperimentalImportError(
                "EXPERIMENTAL_CACHE_CONFLICT",
                "A non-experimental cache row already exists for the observed symbol identity.",
            )
        existing.required_pdb_name = requirement.pdb_name
        existing.required_pdb_guid = requirement.pdb_guid
        existing.required_pdb_age = int(requirement.pdb_age)
        existing.required_architecture = requirement.architecture
        existing.pdb_relative_path = str(pdb_relative)
        existing.isf_relative_path = str(isf_relative)
        existing.pdb_sha256 = pdb_sha256
        existing.isf_sha256 = isf_sha256
        existing.pdb_size_bytes = int(pdb_size)
        existing.isf_size_bytes = int(isf_size)
        existing.validation_status = "usable"
        existing.provenance_source_type = provenance_source_type
        existing.provenance_source_name = provenance_source_name
        existing.provenance_actor = provenance_actor
        existing.provenance_acquired_at = utc_now_naive()
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing
    cached = MemoryCachedSymbol(
        symbol_key=observed_key,
        pdb_name=str(observed_identity["pdb_name"]),
        pdb_guid=str(observed_identity["pdb_guid"]).upper(),
        pdb_age=int(observed_identity["pdb_age"]),
        architecture=str(observed_identity["architecture"]),
        pdb_relative_path=str(pdb_relative),
        isf_relative_path=str(isf_relative),
        pdb_sha256=pdb_sha256,
        isf_sha256=isf_sha256,
        pdb_size_bytes=int(pdb_size),
        isf_size_bytes=int(isf_size),
        validation_status="usable",
        source_category="experimental_operator_import",
        provenance_source_type=provenance_source_type,
        provenance_source_name=provenance_source_name,
        provenance_actor=provenance_actor,
        provenance_acquired_at=utc_now_naive(),
        cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        required_pdb_name=requirement.pdb_name,
        required_pdb_guid=requirement.pdb_guid,
        required_pdb_age=int(requirement.pdb_age),
        required_architecture=requirement.architecture,
    )
    db.add(cached)
    db.commit()
    db.refresh(cached)
    return cached


def _candidate_snapshot(
    candidate: MemoryExperimentalSymbolCandidate,
    *,
    cached_symbol_id: str,
    required_identity: dict[str, Any],
    observed_identity: dict[str, Any],
) -> dict[str, Any]:
    return {
        "candidate_id": candidate.id,
        "cached_symbol_id": cached_symbol_id,
        "required_identity": required_identity,
        "observed_identity": observed_identity,
        "symbol_match_type": candidate.symbol_match_type,
        "symbol_warning": candidate.symbol_warning,
        "pdb_sha256": candidate.pdb_sha256,
        "isf_sha256": candidate.isf_sha256,
    }


def verify_candidate_integrity(
    db: Session,
    *,
    candidate: MemoryExperimentalSymbolCandidate,
) -> tuple[MemoryCachedSymbol, Path, Path]:
    cache = db.get(MemoryCachedSymbol, candidate.cached_symbol_id)
    if cache is None:
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate cache row is missing.")
    if cache.cache_classification != CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE:
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate cache row is no longer classified as experimental.")
    if not cache.pdb_sha256 or not cache.isf_sha256 or not cache.validation_status:
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate metadata is incomplete.")
    root = experimental_cache_root()
    pdb_path = root / cache.pdb_relative_path
    isf_path = root / cache.isf_relative_path
    _ensure_regular_readable_file(pdb_path)
    _ensure_regular_readable_file(isf_path)
    if hash_file(pdb_path, max_bytes=2 * 1024 * 1024 * 1024) != cache.pdb_sha256:
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate PDB hash no longer matches the stored provenance.")
    if hash_file(isf_path, max_bytes=2 * 1024 * 1024 * 1024) != cache.isf_sha256:
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate ISF hash no longer matches the stored provenance.")
    if cache.required_pdb_guid != candidate.required_pdb_guid or int(cache.required_pdb_age or -1) != int(candidate.required_pdb_age):
        raise ExperimentalImportError("EXPERIMENTAL_CANDIDATE_UNAVAILABLE", "Experimental candidate no longer matches the required identity snapshot.")
    return cache, pdb_path, isf_path


def _finalize_import(
    db: Session,
    *,
    requirement: MemorySymbolRequirement,
    observed_identity: dict[str, Any],
    staged_pdb: Path,
    staged_isf: Path,
    source_host_path: str,
    operator_label: str,
    provenance_source_type: str,
    provenance_source_name: str,
) -> dict[str, Any]:
    root = experimental_cache_root()
    pdb_relative, isf_relative = _experimental_relative_paths(requirement, observed_identity)
    final_pdb = root / pdb_relative
    final_isf = root / isf_relative
    final_pdb.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    final_isf.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.replace(staged_pdb, final_pdb)
    os.replace(staged_isf, final_isf)
    pdb_sha = hash_file(final_pdb, max_bytes=2 * 1024 * 1024 * 1024)
    isf_sha = hash_file(final_isf, max_bytes=2 * 1024 * 1024 * 1024)
    cached = _upsert_experimental_cache_row(
        db,
        requirement=requirement,
        observed_identity=observed_identity,
        pdb_relative=pdb_relative,
        isf_relative=isf_relative,
        pdb_sha256=pdb_sha,
        isf_sha256=isf_sha,
        pdb_size=final_pdb.stat().st_size,
        isf_size=final_isf.stat().st_size,
        provenance_source_type=provenance_source_type,
        provenance_source_name=provenance_source_name,
        provenance_actor=f"operator_cli:{operator_label}",
    )
    from app.services.memory.experimental_lifecycle import upsert_candidate

    candidate = upsert_candidate(
        db,
        case_id=requirement.case_id,
        evidence_id=requirement.evidence_id,
        requirement=requirement,
        cache=cached,
        source_host_path=source_host_path,
        actor=f"operator_cli:{operator_label}",
    )
    required_identity = {
        "pdb_name": requirement.pdb_name,
        "pdb_guid": requirement.pdb_guid,
        "pdb_age": int(requirement.pdb_age),
        "architecture": requirement.architecture,
    }
    return {
        "status": "ready",
        "requirement_id": requirement.id,
        **_candidate_snapshot(
            candidate,
            cached_symbol_id=cached.id,
            required_identity=required_identity,
            observed_identity=observed_identity,
        ),
    }


def cli_import_experimental_pdb_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    file_path: Path,
    operator_label: str,
    safe_override: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    _validate_requirement(requirement)
    inspection = inspect_experimental_pdb_for_requirement(
        db,
        requirement_id=requirement.id,
        file_path=file_path,
        safe_override=safe_override,
    )
    if dry_run:
        return {**inspection, "status": "dry_run", "sanitized_message": "Dry run succeeded; no rows written."}
    source = Path(str(validate_input_file(file_path, allowed_extensions={".pdb"}, safe_override=safe_override)["resolved_path"]))
    staged_pdb = staged_isf = None
    try:
        staged_pdb = _stage_to_quarantine(source, suffix=".pdb")
        identity = SymbolIdentity(
            inspection["observed_identity"]["pdb_name"],
            inspection["observed_identity"]["pdb_guid"],
            int(inspection["observed_identity"]["pdb_age"]),
            inspection["observed_identity"]["architecture"],
        )
        staged_isf = _quarantine_root() / f"{uuid4().hex}.json.xz"
        generate_isf(
            staged_pdb,
            staged_isf,
            identity,
            max_bytes=int(get_settings().memory_symbol_isf_max_bytes),
        )
        return _finalize_import(
            db,
            requirement=requirement,
            observed_identity=dict(inspection["observed_identity"]),
            staged_pdb=staged_pdb,
            staged_isf=staged_isf,
            source_host_path=str(source),
            operator_label=operator_label,
            provenance_source_type="operator_cli_experimental_pdb",
            provenance_source_name="Operator CLI experimental PDB import",
        )
    except (ExperimentalImportError, SymbolFetchError):
        raise
    finally:
        _cleanup_paths(staged_pdb, staged_isf)


def cli_import_experimental_isf_for_requirement(
    db: Session,
    *,
    requirement_id: str,
    file_path: Path,
    operator_label: str,
    safe_override: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    _validate_requirement(requirement)
    file_info = validate_input_file(file_path, allowed_extensions={".isf", ".json", ".xz"}, safe_override=safe_override)
    source = Path(str(file_info["resolved_path"]))
    observed = _read_isf_identity(source, required_name=requirement.pdb_name)
    observed_identity = _evaluate_eligibility(
        requirement,
        observed_name=str(observed["pdb_name"]),
        observed_guid=str(observed["pdb_guid"]),
        observed_age=int(observed["pdb_age"]),
        observed_architecture=str(observed["architecture"] or requirement.architecture),
    )["observed_identity"]
    result = {
        "status": "eligible",
        "requirement_id": requirement.id,
        "required_identity": {
            "pdb_name": requirement.pdb_name,
            "pdb_guid": requirement.pdb_guid,
            "pdb_age": int(requirement.pdb_age),
            "architecture": requirement.architecture,
        },
        "observed_identity": observed_identity,
        "sha256": file_info["sha256"],
        "size_bytes": int(file_info["size_bytes"]),
        "original_filename": file_info["original_filename"],
    }
    if dry_run:
        return {**result, "status": "dry_run", "sanitized_message": "Dry run succeeded; no rows written."}
    staged_pdb = staged_isf = None
    try:
        staged_isf = _quarantine_root() / f"{uuid4().hex}.json.xz"
        staged_isf.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        encoded_payload = json.dumps(observed["payload"], separators=(",", ":"), sort_keys=True).encode("utf-8")
        with lzma.open(staged_isf, "wb") as handle:
            handle.write(encoded_payload)
        os.chmod(staged_isf, 0o640)
        staged_pdb = _quarantine_root() / f"{uuid4().hex}.pdb.stub"
        staged_pdb.write_bytes(b"MSF 7.00\r\n\x1aDS\x00\x00\x00" + b"\x00" * 43)
        os.chmod(staged_pdb, 0o640)
        return _finalize_import(
            db,
            requirement=requirement,
            observed_identity=observed_identity,
            staged_pdb=staged_pdb,
            staged_isf=staged_isf,
            source_host_path=str(source),
            operator_label=operator_label,
            provenance_source_type="operator_cli_experimental_isf",
            provenance_source_name="Operator CLI experimental ISF import",
        )
    finally:
        _cleanup_paths(staged_pdb, staged_isf)


__all__ = [
    "ExperimentalImportError",
    "cli_import_experimental_isf_for_requirement",
    "cli_import_experimental_pdb_for_requirement",
    "experimental_cache_root",
    "inspect_experimental_pdb_for_requirement",
    "verify_candidate_integrity",
]
