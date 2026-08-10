"""Memory Evidence Preparation: a platform-agnostic read-only status layer.

Public API (import from here, not from the submodules):

    from app.services.memory.preparation import get_preparation_status, MemoryEvidencePreparation, PreparationState

``get_preparation_status(db, evidence_id)`` returns a
``MemoryEvidencePreparation`` describing whether a memory_dump evidence
item is ready to analyze, without exposing how any platform obtains what
it's missing (see app.services.memory.preparation.models for why that
split matters and how this relates to the other, pre-existing
"preparation"-named things in this codebase).

Wired into ``GET /cases/{case_id}/memory/evidences/{evidence_id}/preparation``
(app/api/routes_memory.py) and consumed by the frontend's Memory
Preparation surfaces.
"""
from __future__ import annotations

from app.services.memory.preparation.models import MemoryEvidencePreparation, PreparationState
from app.services.memory.preparation.service import MemoryPreparationError, get_preparation_status

__all__ = [
    "MemoryEvidencePreparation",
    "MemoryPreparationError",
    "PreparationState",
    "get_preparation_status",
]
