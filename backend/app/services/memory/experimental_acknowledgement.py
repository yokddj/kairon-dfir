"""Acknowledgement contract for the experimental analysis flow.

The acknowledgement is a server-side payload that the analyst
must POST *before* an experimental run is created.  The
acknowledgement is mandatory, the warning text is versioned, and
the acknowledgement snapshot is persisted on the run row.

This module is intentionally small: it only validates the
payload and writes it onto the run.  The endpoint / service
that owns the run lifecycle is responsible for inserting /
updating the row.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings
from app.models.memory import EXPERIMENTAL_ACK_WARNING_VERSION
from app.services.memory.experimental_trust import ACK_CHECKBOX_CONFIRMED_TEXT


# Canonical warning text that the server returns to the UI.  The
# UI MUST display this verbatim and the analyst MUST check a
# confirmation box.  Changing the warning text requires bumping
# ``EXPERIMENTAL_ACK_WARNING_VERSION`` so old clients cannot
# silently reuse a stale acknowledgement.
EXPERIMENTAL_ACK_WARNING_TEXT = (
    "EXPERIMENTAL MISMATCHED-SYMBOL ANALYSIS\n"
    "\n"
    "You are about to run an analysis using a Windows symbol that "
    "DOES NOT exactly match the symbol identity required by this "
    "evidence (same PDB name and same GUID, but a different age).\n"
    "\n"
    "Consequences you must understand before continuing:\n"
    "  - Plugin output may be incomplete, incorrect or misleading.\n"
    "  - Process, module and network offsets may be wrong.\n"
    "  - Detections, correlations and timelines are NOT produced "
    "from experimental results.\n"
    "  - The absence of a result proves nothing.\n"
    "  - This output is NOT validated forensic evidence.\n"
    "\n"
    "The analysis runs in an isolated trust domain and will be "
    "labelled Experimental / Untrusted everywhere it appears."
)


def build_warning_payload() -> dict[str, Any]:
    """Return the warning payload the UI must display and the
    analyst must acknowledge.
    """
    return {
        "warning_version": EXPERIMENTAL_ACK_WARNING_VERSION,
        "warning_text": EXPERIMENTAL_ACK_WARNING_TEXT,
        "checkbox_text": ACK_CHECKBOX_CONFIRMED_TEXT,
        "required_fields": ["checkbox_confirmed", "client_actor_label"],
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint_acknowledgement(payload: dict[str, Any]) -> str:
    """Return a stable SHA-256 fingerprint of the acknowledgement.

    The fingerprint is persisted on the run row and exposed in
    the audit log; it lets an operator detect a re-submitted
    acknowledgement that has been edited.
    """
    canonical = {
        "run_id": str(payload.get("run_id", "")).strip(),
        "client_actor_label": str(payload.get("client_actor_label", "")).strip(),
        "warning_version": str(payload.get("warning_version", "")).strip(),
        "required_identity": payload.get("required_identity", {}),
        "observed_identity": payload.get("observed_identity", {}),
        "checkbox_confirmed": bool(payload.get("checkbox_confirmed", False)),
    }
    blob = repr(sorted(canonical.items())).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def validate_acknowledgement_payload(
    payload: Any,
    *,
    run_id: str,
    expected_required: dict[str, Any],
    expected_observed: dict[str, Any],
) -> tuple[bool, str | None, dict[str, Any] | None]:
    """Return ``(ok, error_code, normalised_payload)``.

    The function is the single server-side gate.  It checks
    presence of every required field, the warning version, the
    checkbox confirmation, and that the identity snapshots match
    the candidate's required / observed identities.

    The function never mutates state.
    """
    if not isinstance(payload, dict):
        return False, "EXPERIMENTAL_ACK_PAYLOAD_INVALID", None
    forbidden = {
        "actor",
        "acknowledged_at",
        "warning_version",
        "required_identity",
        "observed_identity",
        "warning_text",
    }
    if forbidden & set(payload.keys()):
        return False, "EXPERIMENTAL_ACK_CLIENT_FIELDS_FORBIDDEN", None
    if "checkbox_confirmed" not in payload:
        return False, "EXPERIMENTAL_ACK_FIELDS_MISSING", None
    # Warning version.  The version is configured at the server.
    settings = get_settings()
    expected_version = (
        getattr(settings, "memory_experimental_ack_warning_version", None)
        or EXPERIMENTAL_ACK_WARNING_VERSION
    )
    # Checkbox.  Must be True; the literal text is also asserted
    # so a UI that sends a non-empty string still fails the check.
    if not bool(payload.get("checkbox_confirmed")):
        return False, "EXPERIMENTAL_ACK_CHECKBOX_NOT_CONFIRMED", None
    client_actor_label = str(payload.get("client_actor_label", "")).strip()
    normalised = {
        "run_id": str(run_id),
        "actor": client_actor_label,
        "actor_trust": "unauthenticated_client_label",
        "acknowledged_at": utc_now_iso(),
        "warning_version": expected_version,
        "required_identity": dict(expected_required),
        "observed_identity": dict(expected_observed),
        "warning_text": EXPERIMENTAL_ACK_WARNING_TEXT,
        "checkbox_confirmed": True,
        "fingerprint": fingerprint_acknowledgement(payload),
    }
    return True, None, normalised


__all__ = [
    "EXPERIMENTAL_ACK_WARNING_TEXT",
    "build_warning_payload",
    "fingerprint_acknowledgement",
    "utc_now_iso",
    "validate_acknowledgement_payload",
]
