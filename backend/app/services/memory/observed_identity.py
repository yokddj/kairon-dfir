"""Helpers to extract the observed identity from acquisition records.

The canonical location is the ``MemorySymbolAcquisition`` row's
``observed_pdb_guid`` / ``observed_pdb_age`` / ``observed_architecture``
columns.  New code MUST populate those columns.

This module is a *fallback* parser for legacy rows that predate the
canonical fields.  It extracts the observed identity from a
``sanitized_message`` that follows the canonical
``"expected GUID=... age=..., observed GUID=... age=..."`` shape
produced by :func:`app.services.memory.symbol_fetcher.validate_pdb`
and :func:`app.services.memory.symbol_fetcher.generate_isf`.

The parser is *only* used for legacy rows.  Production code
should rely on the canonical fields, not on the human-readable
message.
"""
from __future__ import annotations

import re
from typing import Any


# The observed identity is encoded in the message as
# "observed GUID=<32 hex chars> age=<int>.".  We match it
# defensively so a future change in the message format does not
# crash a UI render.
_OBSERVED_CLAUSE_RE = re.compile(
    r"observed\s+(?P<rest>[^.]*\.)"
)
_OBSERVED_GUID_RE = re.compile(
    r"observed\s+GUID\s*=\s*([0-9A-Fa-f]{32})"
)
_OBSERVED_AGE_IN_CLAUSE_RE = re.compile(
    r"observed\s+GUID\s*=\s*[0-9A-Fa-f]{32}\s+age\s*=\s*(-?\d+)"
)
_OBSERVED_ARCH_RE = re.compile(
    r"observed\s+architecture\s*=\s*(\S+)"
)


def parse_observed_identity_from_message(sanitized_message: str | None) -> dict[str, Any] | None:
    """Extract the observed identity from a canonical sanitized message.

    Returns a dict with ``pdb_guid`` (upper-cased, 32 hex chars),
    ``pdb_age`` (int), and ``architecture`` (string or None) when
    at least the GUID or the age is present.  Returns ``None``
    when the message is empty or does not match the canonical
    format.

    The canonical format is:

    ``expected GUID=<32 hex> age=<int>, observed GUID=<32 hex> age=<int>.``

    so we extract the age from the ``observed GUID=...`` clause
    specifically (not from the ``expected`` clause) by matching
    the full observed clause and then looking up the age inside
    it.

    This function is **only** used for legacy rows.  Production
    code must populate the canonical
    ``MemorySymbolAcquisition.observed_pdb_guid`` and
    ``observed_pdb_age`` columns.
    """
    if not sanitized_message:
        return None
    guid_match = _OBSERVED_GUID_RE.search(sanitized_message)
    # The age must be extracted from the *observed* clause, not
    # the expected clause.  Use the full-observed-clause regex
    # so we never read the wrong age.
    age_match = _OBSERVED_AGE_IN_CLAUSE_RE.search(sanitized_message)
    arch_match = _OBSERVED_ARCH_RE.search(sanitized_message)
    if guid_match is None and age_match is None and arch_match is None:
        return None
    out: dict[str, Any] = {}
    if guid_match is not None:
        out["pdb_guid"] = guid_match.group(1).upper()
    if age_match is not None:
        try:
            out["pdb_age"] = int(age_match.group(1))
        except (TypeError, ValueError):
            pass
    if arch_match is not None:
        out["architecture"] = arch_match.group(1)
    return out


__all__ = ["parse_observed_identity_from_message"]
