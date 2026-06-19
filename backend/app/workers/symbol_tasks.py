from __future__ import annotations

import os
from pathlib import Path

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.models.memory import MemoryCachedSymbol, MemorySymbolAcquisition, MemorySymbolRequirement
from app.services.memory.symbol_fetcher import SymbolFetchError, SymbolIdentity, download_official_pdb, generate_isf, validate_pdb


def _within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def acquire_windows_symbol(request_id: str) -> None:
    settings = get_settings()
    if not (settings.memory_symbol_managed_download_enabled and settings.memory_symbol_network_isolation_ready):
        raise RuntimeError("Symbol acquisition gates are not enabled.")
    root = settings.memory_symbol_cache_path.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    with SessionLocal() as db:
        request = db.get(MemorySymbolAcquisition, request_id)
        if request is None:
            return
        requirement = db.get(MemorySymbolRequirement, request.requirement_id)
        if requirement is None:
            request.status = "failed"
            request.error_code = "SYMBOL_REQUIREMENT_MISSING"
            request.sanitized_message = "The trusted symbol requirement no longer exists."
            request.completed_at = utc_now_naive()
            db.commit()
            return
        existing = db.query(MemoryCachedSymbol).filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key).first()
        if existing:
            request.status, request.validated, request.cached = "completed", True, True
            request.completed_at = utc_now_naive()
            requirement.status, requirement.cached_symbol_id = "cached", existing.id
            db.commit()
            return
        identity = SymbolIdentity(requirement.pdb_name, requirement.pdb_guid, requirement.pdb_age, requirement.architecture)
        identity.validate()
        safe_key = f"{identity.guid.upper()}-{identity.age}"
        partial = root / "tmp" / f"{request.id}.pdb.partial"
        pdb_final = root / "pdb" / identity.pdb_name.lower() / safe_key / identity.pdb_name.lower()
        isf_final = root / "symbols" / "windows" / identity.pdb_name / f"{identity.guid.upper()}-{identity.age}.json.xz"
        for candidate in (partial, pdb_final, isf_final):
            if not _within(root, candidate.resolve(strict=False)) or candidate.is_symlink():
                raise RuntimeError("Unsafe symbol cache path.")
        request.status = "downloading"
        requirement.status = "acquiring"
        db.commit()
        try:
            usage = sum(item.stat().st_size for item in root.rglob("*") if item.is_file() and not item.is_symlink())
            if usage + int(settings.memory_symbol_download_max_bytes) > int(settings.memory_symbol_cache_max_bytes):
                raise SymbolFetchError("SYMBOL_CACHE_FULL", "The configured symbol cache capacity is insufficient.")
            result = download_official_pdb(
                identity,
                partial,
                initial_host=settings.memory_symbol_initial_host,
                redirect_suffixes=settings.memory_symbol_redirect_host_suffixes,
                connect_timeout=int(settings.memory_symbol_connect_timeout_seconds),
                total_timeout=int(settings.memory_symbol_download_timeout_seconds),
                max_redirects=int(settings.memory_symbol_max_redirects),
                max_bytes=int(settings.memory_symbol_download_max_bytes),
            )
            request.status = "validating_pdb"
            request.downloaded_bytes = int(result["bytes"])
            request.pdb_sha256 = str(result["sha256"])
            request.metadata_json = {"redirect_count": int(result["redirects"]), "duration_ms": int(result["duration_ms"]), "source_category": "official_microsoft_symbols"}
            db.commit()
            validate_pdb(partial, identity)
            pdb_final.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            if pdb_final.exists():
                partial.unlink(missing_ok=True)
            else:
                os.replace(partial, pdb_final)
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
                pdb_sha256=str(result["sha256"]),
                isf_sha256=str(isf_result["sha256"]),
                pdb_size_bytes=int(result["bytes"]),
                isf_size_bytes=int(isf_result["bytes"]),
            )
            db.add(cached)
            db.flush()
            request.status, request.validated, request.cached = "completed", True, True
            request.isf_sha256 = str(isf_result["sha256"])
            request.completed_at = utc_now_naive()
            requirement.status, requirement.cached_symbol_id = "cached", cached.id
            db.commit()
        except SymbolFetchError as exc:
            partial.unlink(missing_ok=True)
            request.status = "timeout" if exc.code == "SYMBOL_DOWNLOAD_TIMEOUT" else "failed"
            request.error_code = exc.code
            request.sanitized_message = exc.message
            request.retryable = exc.retryable
            request.completed_at = utc_now_naive()
            requirement.status = "failed"
            requirement.error_code = exc.code
            requirement.sanitized_message = exc.message
            db.commit()
        except Exception:
            partial.unlink(missing_ok=True)
            request.status = "failed"
            request.error_code = "SYMBOL_ACQUISITION_FAILED"
            request.sanitized_message = "The controlled symbol acquisition task failed."
            request.retryable = False
            request.completed_at = utc_now_naive()
            requirement.status = "failed"
            requirement.error_code = request.error_code
            requirement.sanitized_message = request.sanitized_message
            db.commit()
