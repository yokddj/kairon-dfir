"""Domain model for Memory Evidence Preparation.

This module defines ONLY the shape of "how ready is this memory evidence
to analyze" -- it never decides HOW to obtain what is missing. Windows
symbols are normally fetched through a managed, network-gated pipeline
(see app.services.memory.symbol_resolver / symbol_fetcher); Linux symbols
are a locally-supplied ISF with no fetch mechanism at all (see
app.services.memory.linux_symbols). Those are two genuinely different
*acquisition strategies* with different threat models -- this model does
not encode either of them, only the platform-agnostic question "is there
enough here to start analysis, and if not, what kind of gap is it."

Relationship to other "preparation"-named things in this codebase (read
this before assuming a duplicate exists):

- app.models.memory.MemorySymbolPreparation is a PERSISTED, Windows-wired
  state machine (queued -> probing -> ... -> ready) driven by
  app.services.memory.preparation_runtime, dispatched automatically on
  evidence upload and executed asynchronously by the memory-worker. It
  owns real side effects: DB rows, worker dispatch, heartbeats.
- app.services.memory.platform.WindowsMemoryAdapter / LinuxMemoryAdapter
  are the low-level probe/check_readiness/available_profiles adapters
  that preparation_runtime.py drives, keyed off a ``cache_state`` dict
  assembled from app.services.memory.symbol_preparation.

MemoryEvidencePreparation is neither of those. It is a pure, read-only,
synchronously-computed VALUE OBJECT: call app.services.memory.preparation
.get_preparation_status() and it tells you the current answer, computed
fresh from app.services.memory.analysis_plan.build_memory_analysis_plan()
and the existing symbol-readiness services, without persisting anything
or driving a background pipeline. Reconciling this with
MemorySymbolPreparation's asynchronous pipeline is a real, identified
question for a later phase -- deliberately not attempted here.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from app.services.memory.platform import Architecture, PlatformFamily


class PreparationState(str, enum.Enum):
    """Platform-agnostic verdict for one memory evidence item.

    Deliberately narrow (six values) and free of any platform-specific
    vocabulary -- no "pdb", no "isf", nothing Linux- or Windows-shaped.
    Each adapter (see app.services.memory.preparation.adapters) maps its
    platform's own richer signals onto exactly one of these.
    """

    # Kairon has not yet determined enough about this evidence (its
    # operating-system family, or whether an ambiguous probe verdict has
    # been confirmed) to say anything more specific.
    INSPECTING = "inspecting"
    # Analysis can start now with no further action.
    READY = "ready"
    # Analysis needs symbols/ISF Kairon does not currently have available
    # for this evidence's kernel/build identity.
    SYMBOLS_REQUIRED = "symbols_required"
    # Kairon needs an explicit decision from the analyst before it can
    # even assess readiness (e.g. an ambiguous_raw probe verdict that has
    # not been confirmed as memory yet) -- distinct from SYMBOLS_REQUIRED,
    # which is a technical gap, not a pending human decision.
    AWAITING_USER = "awaiting_user"
    # A structural reason analysis cannot proceed that is not "missing
    # symbols" and not "waiting on the user" (e.g. a recognized platform
    # Kairon's capability registry has no plugins for at all).
    BLOCKED = "blocked"
    # Something is concretely wrong with the evidence itself (unreadable,
    # corrupted, path resolution failed) rather than merely incomplete.
    FAILED = "failed"


@dataclass(frozen=True)
class MemoryEvidencePreparation:
    """Read-only preparation status for one memory evidence item.

    Every field here is either copied through from an existing service
    (platform, architecture) or derived by simple, documented composition
    over existing services (readiness, requires_symbols,
    can_start_analysis) -- see app.services.memory.preparation.adapters
    for exactly which existing calls produce each field. This dataclass
    itself contains no detection, readiness, or validation logic.
    """

    evidence_id: str
    platform: PlatformFamily
    architecture: Architecture
    readiness: PreparationState
    requires_symbols: bool
    can_start_analysis: bool
    human_message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "platform": self.platform.value,
            "architecture": self.architecture.value,
            "readiness": self.readiness.value,
            "requires_symbols": self.requires_symbols,
            "can_start_analysis": self.can_start_analysis,
            "human_message": self.human_message,
        }
