"""Registry of post-finalize workflow handlers.

A chunked upload session's bytes-on-disk lifecycle (assemble, verify,
promote) is workflow-agnostic. What happens once the canonical file
exists is not: Memory registers a metadata-only Evidence row; Evidence
runs preflight, platform detection, promotion, and artifact ingestion.

This registry is the seam between the two. Phase 2.5 only registers the
Memory handler and routes Memory's own finalize call through it, proving
the interface end to end. Evidence registers its handler once it starts
consuming the shared finalize primitives (Phase 3+); nothing here assumes
that has happened.
"""
from __future__ import annotations

from typing import Any, Callable

WorkflowHandler = Callable[..., Any]

_HANDLERS: dict[str, WorkflowHandler] = {}


def register_workflow_handler(name: str, handler: WorkflowHandler) -> None:
    _HANDLERS[name] = handler


def get_workflow_handler(name: str) -> WorkflowHandler:
    try:
        return _HANDLERS[name]
    except KeyError as exc:
        raise LookupError(f"No upload workflow handler registered for {name!r}") from exc


def registered_workflows() -> list[str]:
    return sorted(_HANDLERS.keys())
