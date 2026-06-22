"""Reconstruct per-evidence Windows symbol readiness from history.

The previous sprint introduced a per-evidence symbol-readiness state
machine that requires a ``MemorySymbolRequirement`` row to exist for
each evidence.  When an evidence is uploaded fresh (or the row was
never created because the analyst never ran a probe), the state is
``unknown`` and every profile is marked unavailable.

This module reconstructs the requirement **read-only** from the
history of the case: prior successful ``metadata_only`` runs, prior
``MemoryPluginRun`` rows for ``windows.info``, the indexed
``memory_system_info`` documents, and the canonical process
metadata.  It NEVER executes Volatility, NEVER downloads symbols,
and NEVER deletes or replaces a valid existing requirement.

The single source of truth is the priority chain below.  A
reconstructed requirement is marked with ``source`` and
``confidence`` so the UI can show "Source: Historical successful
run" instead of "Source: Probe".

Identifier normalization
------------------------

Different parts of the system store the symbol identifier in
slightly different ways.  This module normalizes before comparing:

* PDB name: lowercased, trailing whitespace removed
* GUID:    uppercased, hyphens removed (32 hex chars)
* Age:     integer, hex strings decoded
* Architecture: lowercased, mapped to ``x64``/``x86``/``arm64``

The cache key format is ``f"{name.lower()}/{guid.upper()}-{age}"``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.evidence import Evidence
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolRequirement,
)


logger = logging.getLogger(__name__)


# Source labels for reconstructed requirements.
SOURCE_PROBE = "probe"
SOURCE_HISTORICAL_RUN = "historical_run"
SOURCE_HISTORICAL_PLUGIN = "historical_plugin_run"
SOURCE_HISTORICAL_SYSTEM_INFO = "historical_system_info"
SOURCE_HISTORICAL_PROCESS = "historical_process_metadata"
SOURCE_CACHE_MATCH = "cache_match"
SOURCE_NONE = "none"


# Backfill version.  Bump when the reconstruction logic changes so
# the operator can see "this row was reconstructed by backfill v2".
BACKFILL_VERSION = "v1"


def normalize_pdb_name(value: str | None) -> str:
    """Lowercase and strip the PDB name.  Accept ``None``."""
    if not value:
        return ""
    return str(value).strip().lower()


def normalize_guid(value: str | None) -> str:
    """Return the GUID as 32 uppercase hex chars, with hyphens removed.

    Accepts ``"D801A9AF-C0FB-7761-380800F708633DEA"`` and
    ``"d801a9afc0fb7761380800f708633dea"`` and returns
    ``"D801A9AFC0FB7761380800F708633DEA"``.
    """
    if not value:
        return ""
    s = str(value).strip().upper().replace("-", "").replace("{", "").replace("}", "")
    return s


def normalize_age(value: int | str | None) -> int:
    """Decode age as integer.  Accepts decimal ints and hex strings."""
    if value is None:
        return 0
    if isinstance(value, int):
        return int(value)
    s = str(value).strip().lower()
    if not s:
        return 0
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)


def normalize_architecture(value: str | bool | None) -> str:
    """Map any string/bool to ``x64``/``x86``/``arm64`` (default ``x64``).

    A boolean value is treated as the ``Is64Bit`` flag: ``True`` ->
    ``x64``, ``False`` -> ``x86``.  ``None`` and unparseable
    values default to ``x64`` (the most common case).
    """
    if value is None:
        return "x64"
    if isinstance(value, bool):
        return "x64" if value else "x86"
    s = str(value).strip().lower()
    if s in {"x64", "x86", "arm64"}:
        return s
    if s in {"true", "yes", "1"}:
        return "x64"
    if s in {"false", "no", "0"}:
        return "x86"
    if "64" in s and "arm" in s:
        return "arm64"
    if "64" in s:
        return "x64"
    if "86" in s or "32" in s or "i386" in s or "intel" in s:
        return "x86"
    return "x64"


def symbol_identifier(pdb_name: str, guid: str, age: int) -> str:
    """Return the canonical cache key for a normalized identifier."""
    return f"{normalize_pdb_name(pdb_name)}/{normalize_guid(guid)}-{normalize_age(age)}"


# ---------------------------------------------------------------------------
# Reconstruction sources
# ---------------------------------------------------------------------------


@dataclass
class ReconstructedRequirement:
    pdb_name: str
    pdb_guid: str
    pdb_age: int
    architecture: str
    source: str  # SOURCE_*
    source_run_id: str | None = None
    source_plugin_run_id: str | None = None
    confidence: str = "medium"
    raw: dict[str, Any] | None = None

    def is_valid(self) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}\.pdb", self.pdb_name, re.IGNORECASE):
            return False
        if not re.fullmatch(r"[0-9A-F]{32}", self.pdb_guid):
            return False
        if not 0 <= int(self.pdb_age) <= 0xFFFFFFFF:
            return False
        return self.architecture in {"x64", "x86", "arm64"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "pdb_name": self.pdb_name,
            "pdb_guid": self.pdb_guid,
            "pdb_age": int(self.pdb_age),
            "architecture": self.architecture,
            "source": self.source,
            "source_run_id": self.source_run_id,
            "source_plugin_run_id": self.source_plugin_run_id,
            "confidence": self.confidence,
        }


def _from_plugin_run_metadata(plugin_run: MemoryPluginRun) -> ReconstructedRequirement | None:
    """Recover from a ``MemoryPluginRun.metadata_json`` for windows.info."""
    meta = plugin_run.metadata_json or {}
    if not isinstance(meta, dict):
        return None
    pdb_name = meta.get("pdb_name") or meta.get("kernel_pdb")
    pdb_guid = meta.get("pdb_guid") or meta.get("kernel_guid")
    pdb_age = meta.get("pdb_age") or meta.get("kernel_age")
    architecture = meta.get("architecture") or meta.get("kernel_arch")
    if not (pdb_name and pdb_guid and pdb_age):
        return None
    return ReconstructedRequirement(
        pdb_name=normalize_pdb_name(pdb_name),
        pdb_guid=normalize_guid(pdb_guid),
        pdb_age=normalize_age(pdb_age),
        architecture=normalize_architecture(architecture),
        source=SOURCE_HISTORICAL_PLUGIN,
        source_run_id=plugin_run.memory_scan_run_id,
        source_plugin_run_id=plugin_run.id,
        confidence="high",
        raw=meta,
    )


def _from_run_metadata(run: MemoryScanRun) -> ReconstructedRequirement | None:
    """Recover from a ``MemoryScanRun.metadata_json`` for metadata_only."""
    meta = run.metadata_json or {}
    if not isinstance(meta, dict):
        return None
    sys_info = meta.get("system_info") if isinstance(meta.get("system_info"), dict) else None
    if not sys_info:
        return None
    kernel = (sys_info.get("os") or {})
    raw = (sys_info.get("raw") or {})
    fields = (raw.get("fields") or {})
    pdb_name = (
        meta.get("pdb_name")
        or fields.get("PDB")
        or fields.get("Kernel PDB")
        or kernel.get("kernel_pdb")
    )
    # Try to extract GUID + age from kernel_symbols label (set by the
    # windows.info normalizer).
    kernel_symbols = (sys_info.get("memory") or {}).get("kernel_symbols") or ""
    pdb_guid = meta.get("pdb_guid") or fields.get("GUID") or ""
    pdb_age = meta.get("pdb_age") or fields.get("Age") or 0
    if not pdb_name and kernel_symbols and "ntkrnl" in kernel_symbols.lower():
        pdb_name = "ntkrnlmp.pdb" if "ntkrnlmp" in kernel_symbols.lower() else "ntkrnlpa.pdb"
    if not pdb_guid and kernel_symbols:
        # kernel_symbols typically looks like "ntkrnlmp.pdb / GUID"
        m = re.search(r"[0-9A-F]{32}", kernel_symbols.upper())
        if m:
            pdb_guid = m.group(0)
    if not (pdb_name and pdb_guid):
        return None
    return ReconstructedRequirement(
        pdb_name=normalize_pdb_name(pdb_name),
        pdb_guid=normalize_guid(pdb_guid),
        pdb_age=normalize_age(pdb_age),
        architecture=normalize_architecture(fields.get("Is64Bit") if fields.get("Is64Bit") is not None else None),
        source=SOURCE_HISTORICAL_RUN,
        source_run_id=run.id,
        source_plugin_run_id=None,
        confidence="high",
        raw=meta,
    )


def _from_run_plugins(run: MemoryScanRun, db: Session) -> ReconstructedRequirement | None:
    """Recover from the most recent windows.info plugin run of a metadata_only run."""
    plugin = (
        db.query(MemoryPluginRun)
        .filter(
            MemoryPluginRun.memory_scan_run_id == run.id,
            MemoryPluginRun.plugin == "windows.info",
        )
        .order_by(MemoryPluginRun.created_at.desc())
        .first()
    )
    if plugin is None:
        return None
    return _from_plugin_run_metadata(plugin)


def _latest_successful_metadata_run(
    db: Session,
    case_id: str,
    evidence_id: str,
) -> MemoryScanRun | None:
    return (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == "metadata_only",
            MemoryScanRun.status == "completed",
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .first()
    )


def _latest_successful_run_with_windows_info(
    db: Session,
    case_id: str,
    evidence_id: str,
) -> MemoryScanRun | None:
    rows = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.status == "completed",
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .all()
    )
    for run in rows:
        plugin = (
            db.query(MemoryPluginRun)
            .filter(
                MemoryPluginRun.memory_scan_run_id == run.id,
                MemoryPluginRun.plugin == "windows.info",
                MemoryPluginRun.status == "completed",
            )
            .first()
        )
        if plugin is not None:
            return run
    return None


def _existing_requirement_row(
    db: Session,
    case_id: str,
    evidence_id: str,
) -> MemorySymbolRequirement | None:
    return (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.case_id == case_id,
            MemorySymbolRequirement.evidence_id == evidence_id,
        )
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def reconstruct_requirement(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> ReconstructedRequirement | None:
    """Reconstruct a requirement from history, in priority order.

    Priority chain:

    1. Latest successful ``metadata_only`` run
    2. Latest successful run that included ``windows.info``
    3. ``MemoryPluginRun.metadata_json`` of a recent windows.info
       plugin run (broader than metadata_only)
    4. ``MemoryScanRun.metadata_json`` of a metadata_only run that
       includes a normalized system_info block

    The function never returns an unparseable requirement.  When no
    source can be reconstructed, it returns ``None``.
    """
    run = _latest_successful_metadata_run(db, case_id, evidence_id)
    if run is not None:
        from_run = _from_run_metadata(run)
        if from_run is not None and from_run.is_valid():
            return from_run
        from_plugins = _from_run_plugins(run, db)
        if from_plugins is not None and from_plugins.is_valid():
            return from_plugins
    run2 = _latest_successful_run_with_windows_info(db, case_id, evidence_id)
    if run2 is not None and (run is None or run2.id != run.id):
        from_plugins = _from_run_plugins(run2, db)
        if from_plugins is not None and from_plugins.is_valid():
            return from_plugins
        from_run = _from_run_metadata(run2)
        if from_run is not None and from_run.is_valid():
            return from_run
    return None


def cache_match_status(
    db: Session,
    requirement: ReconstructedRequirement,
) -> tuple[str, bool, str | None]:
    """Return ``(cache_status, exact_match, matched_symbol_key)``."""
    symbol_key = symbol_identifier(requirement.pdb_name, requirement.pdb_guid, requirement.pdb_age)
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == symbol_key)
        .first()
    )
    if cached is not None and cached.architecture.lower() == requirement.architecture:
        return ("hit", True, symbol_key)
    return ("miss", False, symbol_key)


def resolve_memory_symbol_readiness(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    allow_probe: bool = False,
) -> dict[str, Any]:
    """Build the per-evidence symbol readiness payload.

    The result is a dict with the same shape as the symbol-state
    payload but augmented with ``source``, ``source_run_id``,
    ``reconstructed_at`` and ``backfill_version`` fields.  When
    the requirement is reconstructed from history, the source is
    ``historical_*`` and the confidence is set accordingly.

    ``allow_probe`` is reserved for the probe endpoint: when False
    (the default), the resolver never executes Volatility.
    """
    requirement_row = _existing_requirement_row(db, case_id, evidence_id)
    reconstructed: ReconstructedRequirement | None = None
    source = SOURCE_PROBE if requirement_row is not None else SOURCE_NONE
    confidence = "high" if requirement_row is not None else "none"
    if requirement_row is not None:
        reconstructed = ReconstructedRequirement(
            pdb_name=normalize_pdb_name(requirement_row.pdb_name),
            pdb_guid=normalize_guid(requirement_row.pdb_guid),
            pdb_age=normalize_age(requirement_row.pdb_age),
            architecture=normalize_architecture(requirement_row.architecture),
            source=SOURCE_PROBE,
            source_run_id=requirement_row.source_run_id,
            source_plugin_run_id=requirement_row.source_plugin_run_id,
            confidence="high",
            raw=requirement_row.metadata_json if hasattr(requirement_row, "metadata_json") else None,
        )
    else:
        reconstructed = reconstruct_requirement(db, case_id=case_id, evidence_id=evidence_id)
        if reconstructed is not None:
            source = reconstructed.source
            confidence = reconstructed.confidence
    cache_status = "unknown"
    exact_match = False
    required_identifier: str | None = None
    cached_identifiers: list[str] = []
    matched_pdb: str | None = None
    matched_guid: str | None = None
    matched_age: int | None = None
    matched_architecture: str | None = None
    if reconstructed is not None and reconstructed.is_valid():
        required_identifier = symbol_identifier(
            reconstructed.pdb_name, reconstructed.pdb_guid, reconstructed.pdb_age
        )
        cached_identifiers = sorted(
            row.symbol_key for row in db.query(MemoryCachedSymbol).all()
        )
        cache_status, exact_match, _ = cache_match_status(db, reconstructed)
        if exact_match:
            for row in db.query(MemoryCachedSymbol).all():
                if row.symbol_key == required_identifier and row.architecture.lower() == reconstructed.architecture:
                    matched_pdb = row.pdb_name
                    matched_guid = row.pdb_guid
                    matched_age = int(row.pdb_age)
                    matched_architecture = row.architecture
                    break
    return {
        "evidence_id": evidence_id,
        "source": source,
        "confidence": confidence,
        "reconstructed_at": utc_now_naive().isoformat() if reconstructed is not None and requirement_row is None else None,
        "backfill_version": BACKFILL_VERSION if requirement_row is None else None,
        "requirement": reconstructed.to_dict() if reconstructed is not None else None,
        "requirement_valid": reconstructed is not None and reconstructed.is_valid(),
        "cache_status": cache_status,
        "exact_match": exact_match,
        "required_identifier": required_identifier,
        "cached_identifiers": cached_identifiers,
        "matched_pdb": matched_pdb,
        "matched_guid": matched_guid,
        "matched_age": matched_age,
        "matched_architecture": matched_architecture,
        "allow_probe": allow_probe,
    }


__all__ = [
    "BACKFILL_VERSION",
    "SOURCE_CACHE_MATCH",
    "SOURCE_HISTORICAL_PLUGIN",
    "SOURCE_HISTORICAL_PROCESS",
    "SOURCE_HISTORICAL_RUN",
    "SOURCE_HISTORICAL_SYSTEM_INFO",
    "SOURCE_NONE",
    "SOURCE_PROBE",
    "ReconstructedRequirement",
    "cache_match_status",
    "normalize_age",
    "normalize_architecture",
    "normalize_guid",
    "normalize_pdb_name",
    "reconstruct_requirement",
    "resolve_memory_symbol_readiness",
    "symbol_identifier",
]
