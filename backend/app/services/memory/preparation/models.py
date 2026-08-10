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

    The ``vmware_companion_*`` fields (Phase 2) are the one exception to
    "adapters produce every field": they are computed once, uniformly,
    by ``get_preparation_status`` itself -- deliberately outside both the
    Windows and Linux adapters -- because a VMware companion (.vmsn/
    .vmss) is a property of the *acquisition format*, not the guest OS.
    They all default to "no signal" so every existing adapter/early-return
    call site that does not pass them keeps working unchanged. They are
    purely informational: nothing here may ever flip ``can_start_analysis``
    from true to false -- a missing companion is a recommendation, never a
    gate.
    """

    evidence_id: str
    platform: PlatformFamily
    architecture: Architecture
    readiness: PreparationState
    requires_symbols: bool
    can_start_analysis: bool
    human_message: str
    has_vmware_companion: bool = False
    # Not part of the original 7-field request, but required for the
    # frontend's Replace/Remove actions to call
    # DELETE .../companions/{companion_id} without a second round trip to
    # GET companions to look the id up (the thing this phase's frontend
    # spec explicitly says not to do). Purely an identifier -- carries no
    # additional signal beyond what has_vmware_companion already exposes.
    vmware_companion_id: str | None = None
    vmware_companion_type: str | None = None
    vmware_companion_filename: str | None = None
    vmware_companion_sha256: str | None = None
    vmware_companion_size_bytes: int | None = None
    vmware_companion_recommended: bool = False
    vmware_companion_warning: str | None = None
    # Zero-result warning (Phase 2): the most recent plugin run's
    # VMWARE_METADATA_MAY_BE_REQUIRED warning, if any -- see
    # service._zero_result_warning_fields for why this rides on
    # Preparation rather than the family-results endpoints.
    zero_result_warning_code: str | None = None
    zero_result_warning_message: str | None = None
    zero_result_warning_plugin: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "platform": self.platform.value,
            "architecture": self.architecture.value,
            "readiness": self.readiness.value,
            "requires_symbols": self.requires_symbols,
            "can_start_analysis": self.can_start_analysis,
            "has_vmware_companion": self.has_vmware_companion,
            "vmware_companion_id": self.vmware_companion_id,
            "vmware_companion_type": self.vmware_companion_type,
            "vmware_companion_filename": self.vmware_companion_filename,
            "vmware_companion_sha256": self.vmware_companion_sha256,
            "vmware_companion_size_bytes": self.vmware_companion_size_bytes,
            "vmware_companion_recommended": self.vmware_companion_recommended,
            "vmware_companion_warning": self.vmware_companion_warning,
            "zero_result_warning_code": self.zero_result_warning_code,
            "zero_result_warning_message": self.zero_result_warning_message,
            "zero_result_warning_plugin": self.zero_result_warning_plugin,
            "human_message": self.human_message,
        }
