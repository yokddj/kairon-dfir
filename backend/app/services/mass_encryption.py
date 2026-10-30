"""Built-in detection for files encrypted in bulk.

Ransomware that encrypts in place leaves the same mark whatever wrote it: within minutes, many
data files reappear under their own name plus one new extension (Memo.docx -> Memo.docx.enc,
report.pdf -> report.pdf.locked). Any file event with a name shows it -- MFT and USN records from
disk, MFT records MemProcFS recovers from memory -- so the check reads the evidence's indexed file
events rather than one parser's output.

One detection per host, appended extension and burst, linked to the first renamed file and listing
the others. Running the check again finds the same bursts and adds nothing, so an analyst's triage
of an earlier detection stays as it was.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

RULE_KEY = "possible_mass_file_encryption"
RULE_NAME = "Built-in: Possible mass file encryption"
# Extensions of files people keep: what ransomware goes after.
DATA_EXTENSIONS = (
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "odp", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3", "mp4", "avi", "mov", "zip", "rar", "7z",
    "sql", "mdb", "accdb", "db", "sqlite", "pst", "ost", "xml", "json", "psd", "dwg", "vsd", "vsdx", "eml", "msg",
)
# Extensions Windows and applications append to a document's name for their own bookkeeping: the
# Recent folder's shortcuts, downloads in progress, editor backups and temporary copies.
ROUTINE_APPENDED_EXTENSIONS = frozenset({
    "lnk", "url", "tmp", "temp", "bak", "old", "orig", "part", "partial", "crdownload", "download", "opdownload",
    "ini", "log", "lock", "swp", "sav", "backup", "metadata", "thumb", "ds_store",
})
_NAME = re.compile(r"^(?P<stem>.+)\.(?P<data>" + "|".join(DATA_EXTENSIONS) + r")\.(?P<appended>[a-z0-9_]{1,16})$", re.IGNORECASE)
_NAME_QUERY = r".+\.(" + "|".join(DATA_EXTENSIONS + tuple(ext.upper() for ext in DATA_EXTENSIONS)) + r")\.[A-Za-z0-9_]{1,16}"
MIN_FILES = 5
WINDOW_SECONDS = 600
MAX_EVENTS = 50000
# OpenSearch returns at most 10000 hits per request; the rest come page by page.
PAGE_SIZE = 5000
MAX_RELATED = 50
MAX_EXAMPLES = 5


def renamed_file(name: str | None) -> tuple[str, str] | None:
    """(original name, appended extension) for a data file name with an extension appended, or None."""
    match = _NAME.match(str(name or "").strip())
    if not match:
        return None
    appended = match["appended"].lower()
    if appended in ROUTINE_APPENDED_EXTENSIONS or appended in DATA_EXTENSIONS:
        return None
    return f"{match['stem']}.{match['data']}", appended


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def find_bursts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bursts of at least MIN_FILES distinct files, one host and one appended extension, each within
    WINDOW_SECONDS of the burst's first file. ``events`` are indexed documents."""
    groups: dict[tuple[str, str], dict[str, tuple[datetime, dict[str, Any]]]] = {}
    for event in events:
        file_data = event.get("file") or {}
        name = file_data.get("name") or str(file_data.get("path") or "").replace("/", "\\").rsplit("\\", 1)[-1]
        renamed = renamed_file(name)
        moment = _parse_time(event.get("@timestamp"))
        if not renamed or moment is None:
            continue
        path = str(file_data.get("path") or name).lower()
        host = str((event.get("host") or {}).get("name") or "")
        files = groups.setdefault((host, renamed[1]), {})
        # The earliest record of each file: created, then read and written again.
        if path not in files or moment < files[path][0]:
            files[path] = (moment, event)
    bursts = []
    for (host, appended), files in groups.items():
        ordered = sorted(files.values(), key=lambda item: item[0])
        start = 0
        while start < len(ordered):
            end = start
            while end + 1 < len(ordered) and (ordered[end + 1][0] - ordered[start][0]).total_seconds() <= WINDOW_SECONDS:
                end += 1
            members = ordered[start : end + 1]
            if len(members) >= MIN_FILES:
                bursts.append({"host": host, "extension": appended, "members": [event for _, event in members], "first": members[0][0], "last": members[-1][0]})
                start = end + 1
            else:
                start += 1
    return bursts


def _query_events(case_id: str, evidence_id: str) -> list[dict[str, Any]]:
    from app.core.opensearch import get_events_index, get_opensearch_client, index_exists

    client = get_opensearch_client(timeout_seconds=120)
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return []
    body: dict[str, Any] = {
        "size": PAGE_SIZE,
        "_source": ["event_id", "stable_event_id", "@timestamp", "file.name", "file.path", "host.name"],
        "query": {"bool": {"filter": [{"term": {"evidence_id": evidence_id}}, {"regexp": {"file.name": {"value": _NAME_QUERY}}}]}},
        "sort": [{"@timestamp": "asc"}, {"event_id": "asc"}],
    }
    events: list[dict[str, Any]] = []
    while len(events) < MAX_EVENTS:
        hits = (client.search(index=index, body=body).get("hits") or {}).get("hits") or []
        events.extend(hit.get("_source") or {} for hit in hits)
        if len(hits) < PAGE_SIZE:
            break
        body["search_after"] = hits[-1]["sort"]
    return events[:MAX_EVENTS]


def detect_mass_file_encryption(db: Session, *, case_id: str, evidence_id: str) -> int:
    """Create a detection for each burst the evidence's file events show that has none yet.
    Returns how many were created."""
    from app.core.config import get_settings
    from app.core.detections import create_detection_if_missing
    from app.core.opensearch import get_events_index
    from app.core.rules import load_builtin_detection_overrides

    # The switches every built-in detection honours.
    if not get_settings().auto_create_heuristic_detections or RULE_KEY in set(load_builtin_detection_overrides().get("disabled_rules", [])):
        return 0
    bursts = find_bursts(_query_events(case_id, evidence_id))
    created = 0
    for burst in bursts:
        members = burst["members"]
        first = members[0]
        names = [str((event.get("file") or {}).get("name") or "") for event in members]
        folders = {str((event.get("file") or {}).get("path") or "").replace("/", "\\").rsplit("\\", 1)[0].lower() for event in members}
        span = int((burst["last"] - burst["first"]).total_seconds())
        message = (
            f"{len(members)} data files reappeared with the extension .{burst['extension']} "
            f"in {len(folders)} folder{'s' if len(folders) != 1 else ''} within {span} s "
            f"(e.g. {', '.join(names[:MAX_EXAMPLES])})."
        )
        fingerprint = hashlib.sha256("|".join([case_id, "builtin", RULE_KEY, evidence_id, burst["host"], burst["extension"], str(first.get("event_id"))]).encode()).hexdigest()
        _, was_created = create_detection_if_missing(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=None,
            rule_id=None,
            rule_set_id=None,
            engine="builtin",
            source_engine="builtin",
            rule_name=RULE_NAME,
            severity="high",
            confidence=None,
            event_id=first.get("event_id"),
            event_index=get_events_index(case_id),
            opensearch_id=first.get("event_id"),
            target_type="event",
            target_path=(first.get("file") or {}).get("path"),
            matched_at=first.get("@timestamp"),
            message=message,
            host_name=burst["host"] or None,
            matched_stable_event_id=first.get("stable_event_id"),
            related_event_ids=[str(event["event_id"]) for event in members[:MAX_RELATED] if event.get("event_id")],
            mitre=["T1486"],
            tags=["ransomware", "impact"],
            dedup_fingerprint=fingerprint,
            raw={
                "builtin_rule_key": RULE_KEY,
                "match_reason": message,
                "appended_extension": burst["extension"],
                "file_count": len(members),
                "files": [str((event.get("file") or {}).get("path") or "") for event in members[:MAX_RELATED]],
                "first_seen": burst["first"].isoformat(),
                "last_seen": burst["last"].isoformat(),
            },
            commit=False,
        )
        created += int(bool(was_created))
    db.commit()
    if created:
        logger.info("mass file encryption detected", extra={"case_id": case_id, "evidence_id": evidence_id, "detections": created})
    return created
