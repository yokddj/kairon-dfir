from __future__ import annotations

from typing import Any


OPENSEARCH_INTEGER_MIN = -(2**31)
OPENSEARCH_INTEGER_MAX = (2**31) - 1

_MISSING_PID_STRINGS = {"", "n/a", "na", "none", "null", "-"}


def normalize_pid(value: Any) -> int | None:
    """Normalize a Volatility PID/PPID for integer OpenSearch fields.

    Volatility output is not guaranteed to keep PID-like fields typed as
    integers.  This helper accepts only safe integral values within the
    current memory index mapping range and never raises for malformed input.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if OPENSEARCH_INTEGER_MIN <= value <= OPENSEARCH_INTEGER_MAX else None
    if isinstance(value, float):
        if not value.is_integer():
            return None
        candidate = int(value)
        return candidate if OPENSEARCH_INTEGER_MIN <= candidate <= OPENSEARCH_INTEGER_MAX else None
    if isinstance(value, str):
        text = value.strip()
        if text.lower() in _MISSING_PID_STRINGS:
            return None
        try:
            candidate = int(text, 0)
        except ValueError:
            return None
        return candidate if OPENSEARCH_INTEGER_MIN <= candidate <= OPENSEARCH_INTEGER_MAX else None
    return None
