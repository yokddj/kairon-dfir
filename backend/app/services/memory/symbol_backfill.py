"""Idempotent backfill of per-evidence Windows symbol readiness.

The previous sprint introduced a per-evidence symbol-readiness
state machine but it requires a ``MemorySymbolRequirement`` row to
exist for each evidence.  When an evidence was uploaded (or has
no record from the previous architecture) the state is
``unknown`` and the catalogue marks every profile as
``Unavailable`` for the wrong reason.

This module reconstructs the missing ``MemorySymbolRequirement``
rows from the historical evidence (prior successful
``metadata_only`` runs, prior ``windows.info`` plugin runs,
indexed ``memory_system_info`` documents) and persists them with
``source = "historical_run"`` or ``source = "cache_match"``.

The function NEVER executes Volatility, NEVER downloads symbols,
and NEVER overwrites an existing valid requirement.  When a row
already exists, it is left untouched.  When the cache contains
the exact identifier, the row is recorded as ``status=cached``
instead of ``status=unavailable_offline``.

CLI:

    python -m app.cli.memory_symbols backfill
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import (
    MemoryCachedSymbol,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_resolver import (
    BACKFILL_VERSION,
    SOURCE_CACHE_MATCH,
    SOURCE_HISTORICAL_PLUGIN,
    SOURCE_HISTORICAL_PROCESS,
    SOURCE_HISTORICAL_RUN,
    SOURCE_HISTORICAL_SYSTEM_INFO,
    SOURCE_PROBE,
    ReconstructedRequirement,
    cache_match_status,
    reconstruct_requirement,
    symbol_identifier,
)


logger = logging.getLogger(__name__)


@dataclass
class BackfillStats:
    scanned: int = 0
    reconstructed: int = 0
    skipped_existing: int = 0
    skipped_invalid: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned,
            "reconstructed": self.reconstructed,
            "skipped_existing": self.skipped_existing,
            "skipped_invalid": self.skipped_invalid,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "by_source": dict(self.by_source),
            "evidence_ids": list(self.evidence_ids),
        }


def backfill_memory_symbol_readiness(
    db: Session,
    *,
    case_id: str | None = None,
    evidence_id: str | None = None,
    backfill_version: str = BACKFILL_VERSION,
) -> BackfillStats:
    """Reconstruct missing ``MemorySymbolRequirement`` rows.

    Iterates every memory evidence in scope (optionally filtered by
    ``case_id`` and/or ``evidence_id``) and ensures the
    requirement is recorded.  Idempotent: re-running the backfill
    after it has been applied is a no-op (existing valid rows are
    never overwritten).
    """
    stats = BackfillStats()
    query = db.query(Evidence).filter(Evidence.evidence_type == EvidenceType.memory_dump)
    if case_id is not None:
        query = query.filter(Evidence.case_id == case_id)
    if evidence_id is not None:
        query = query.filter(Evidence.id == evidence_id)
    evidences: list[Evidence] = query.all()
    stats.scanned = len(evidences)
    for evidence in evidences:
        _backfill_one_evidence(
            db,
            evidence=evidence,
            stats=stats,
            backfill_version=backfill_version,
        )
    db.commit()
    return stats


def _backfill_one_evidence(
    db: Session,
    *,
    evidence: Evidence,
    stats: BackfillStats,
    backfill_version: str,
) -> None:
    existing = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == evidence.id)
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )
    if existing is not None and existing.symbol_key:
        stats.skipped_existing += 1
        return
    reconstructed = reconstruct_requirement(
        db, case_id=evidence.case_id, evidence_id=evidence.id
    )
    if reconstructed is None or not reconstructed.is_valid():
        stats.skipped_invalid += 1
        return
    symbol_key = symbol_identifier(
        reconstructed.pdb_name, reconstructed.pdb_guid, reconstructed.pdb_age
    )
    cache_status, exact_match, _ = cache_match_status(db, reconstructed)
    if exact_match:
        stats.cache_hits += 1
    else:
        stats.cache_misses += 1
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == symbol_key)
        .first()
    )
    new_row = MemorySymbolRequirement(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        source_run_id=reconstructed.source_run_id,
        source_plugin_run_id=reconstructed.source_plugin_run_id,
        pdb_name=reconstructed.pdb_name,
        pdb_guid=reconstructed.pdb_guid,
        pdb_age=int(reconstructed.pdb_age),
        requested_pdb_age=int(reconstructed.pdb_age),
        age_corrected=False,
        architecture=reconstructed.architecture,
        symbol_key=symbol_key,
        status="cached" if exact_match else "unavailable_offline",
        cached_symbol_id=cached.id if cached is not None else None,
        source=reconstructed.source,
        backfill_version=backfill_version,
        confidence=reconstructed.confidence,
        reconstructed_at=utc_now_naive(),
        metadata_json={
            "backfill": True,
            "source": reconstructed.source,
            "raw": reconstructed.raw or {},
        },
        sanitized_message=(
            "The required Windows symbols are present in the cache."
            if exact_match
            else "Required Windows symbols are not present in the offline cache."
        ),
    )
    db.add(new_row)
    db.flush()
    stats.reconstructed += 1
    stats.by_source[reconstructed.source] = stats.by_source.get(reconstructed.source, 0) + 1
    stats.evidence_ids.append(evidence.id)
    logger.info(
        "backfilled symbol requirement",
        extra={
            "evidence_id": evidence.id,
            "pdb_name": reconstructed.pdb_name,
            "source": reconstructed.source,
            "exact_match": exact_match,
            "backfill_version": backfill_version,
        },
    )


__all__ = [
    "BackfillStats",
    "backfill_memory_symbol_readiness",
]
