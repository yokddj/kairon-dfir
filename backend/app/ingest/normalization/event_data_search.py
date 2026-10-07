"""Searchable values from Windows event data, shared by every EVTX-shaped parser.

windows.event_data is mapped with "enabled": false so that the hundreds of
distinct keys Windows uses across event types cannot blow the index field
limit. The side effect was that none of it was searchable: WorkstationName,
ShareName, RelativeTargetName and friends were visible in the event detail
panel yet returned zero hits when searched, which reads as "that value does
not exist in this case". Folding the values into search_text restores
searchability at no mapping cost.
"""

from __future__ import annotations

from collections.abc import Iterable

EVENT_DATA_SKIP_KEYS = frozenset({"raw_xml", "payload_columns", "event_data_summary"})
EVENT_DATA_PLACEHOLDERS = frozenset({"-", "--", "0x0", "0", "n/a", "null", "none", "%%1833", "%%1843"})
# Long enough for a full service ImagePath or process command line -- the most
# forensically valuable content in event_data -- while still excluding raw_xml
# style blobs. Set at 160 initially, which silently dropped exactly the command
# lines an analyst most wants to grep for.
EVENT_DATA_MAX_VALUE_CHARS = 512
EVENT_DATA_MAX_VALUES = 60


def searchable_values(items: Iterable[tuple[object, object]], *, limit: int = EVENT_DATA_MAX_VALUES) -> list[str]:
    """Bounded, de-noised, de-duplicated scalar values from (key, value) pairs."""
    seen: set[str] = set()
    values: list[str] = []
    for key, value in items:
        if len(values) >= limit:
            break
        if str(key).strip().lower() in EVENT_DATA_SKIP_KEYS:
            continue
        if isinstance(value, (dict, list)):
            continue
        text = str(value or "").strip()
        if not text or text.lower() in EVENT_DATA_PLACEHOLDERS:
            continue
        if len(text) > EVENT_DATA_MAX_VALUE_CHARS:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        values.append(text)
    return values


def windows_event_data_search_values(document: dict) -> list[str]:
    windows = document.get("windows")
    if not isinstance(windows, dict):
        return []
    event_data = windows.get("event_data")
    if not isinstance(event_data, dict):
        return []
    return searchable_values(event_data.items())
