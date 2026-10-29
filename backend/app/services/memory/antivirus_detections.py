"""Antivirus detections still in memory (Find Evil AV_DETECT), made readable.

MemProcFS reports each Defender detection event it finds in memory as one
line of text, for example::

    AV:[Windows Defender] EVENT:[2024-03-22T11:47:58.345Z DETECTIONEVENT
    MPSOURCE_SYSTEM Trojan:Win32/Example.A CmdLine:C:\\Tools\\x.exe arg;internalCmdLine:...]

A single detection appears several times (the detection event and each
DETECTION_ADD resource record), and the internal* entries carry opaque
blobs. This module parses the line into time, threat, detection source and
target (file, command line, AMSI scan...) and groups the records of one
detection, at read time, so it also works on images analysed before it existed.
Nothing is inferred beyond what the line says.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.core.opensearch import get_opensearch_client, get_memory_index

logger = logging.getLogger(__name__)

MAX_RECORDS = 500

_LINE = re.compile(
    r"^AV:\[(?P<engine>[^\]]*)\]\s*EVENT:\[(?P<time>\S+)\s+(?P<kind>\S+)\s+"
    r"(?:(?P<source>MPSOURCE_\w+)\s+)?(?P<threat>\S+)\s*(?P<rest>.*?)\]?\s*$",
    re.DOTALL,
)
# "file:", "CmdLine:", "amsi:", "process:", "regkey:", "behavior:"... as Defender names resources.
_TARGET = re.compile(r"(?P<kind>[A-Za-z]+):(?P<value>.*?)(?=;[A-Za-z]+:|\s+PropBag\b|;?\s*$)", re.DOTALL)

SOURCE_LABELS = {
    "MPSOURCE_REALTIME": "real-time protection",
    "MPSOURCE_SYSTEM": "system scan",
    "MPSOURCE_AMSI": "AMSI (script scan)",
    "MPSOURCE_IOAV": "download/attachment scan",
    "MPSOURCE_BEHAVIOR": "behaviour monitoring",
    "MPSOURCE_ONDEMAND": "on-demand scan",
}


def parse_av_detect(description: str | None) -> dict[str, Any] | None:
    """One AV_DETECT line as fields, or None when it is not in that format."""
    match = _LINE.match(str(description or "").strip())
    if not match:
        return None
    targets = [
        (item.group("kind"), item.group("value").strip().rstrip(";").strip())
        # The PropBag dump after the resources is not a resource.
        for item in _TARGET.finditer(re.split(r"\s+PropBag\b", match.group("rest"))[0])
    ]
    visible = [(kind, value) for kind, value in targets if value and not kind.lower().startswith("internal")]
    target_kind, target = visible[0] if visible else (None, None)
    source = match.group("source")
    return {
        "engine": match.group("engine").strip() or None,
        "time": match.group("time"),
        "record": match.group("kind"),
        "source": source,
        "source_label": SOURCE_LABELS.get(source or "", source.removeprefix("MPSOURCE_").lower() if source else None),
        "threat": match.group("threat"),
        "target_kind": target_kind.lower() if target_kind else None,
        "target": target,
    }


def group_detections(descriptions: list[str]) -> list[dict[str, Any]]:
    """Records of one detection (same threat and target) as one row with its
    first and last time and every detection source that reported it."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for description in descriptions:
        parsed = parse_av_detect(description)
        if not parsed or not parsed["target"]:
            continue
        key = (parsed["threat"], parsed["target_kind"] or "", parsed["target"])
        group = groups.setdefault(key, {
            "threat": parsed["threat"],
            "engine": parsed["engine"],
            "target_kind": parsed["target_kind"],
            "target": parsed["target"],
            "first_seen": parsed["time"],
            "last_seen": parsed["time"],
            "sources": [],
            "records": 0,
        })
        group["records"] += 1
        group["first_seen"] = min(group["first_seen"], parsed["time"])
        group["last_seen"] = max(group["last_seen"], parsed["time"])
        label = parsed["source_label"]
        if label and label not in group["sources"]:
            group["sources"].append(label)
    return sorted(groups.values(), key=lambda item: (item["first_seen"], item["threat"]))


def antivirus_detections(*, case_id: str, evidence_id: str, run_id: str) -> list[dict[str, Any]]:
    client = get_opensearch_client()
    body = {
        "size": MAX_RECORDS,
        "timeout": "10s",
        "_source": ["description"],
        "query": {"bool": {"filter": [
            {"term": {"document_type": "memory_findevil"}},
            {"term": {"scan_run_id.keyword": run_id}},
            {"term": {"evidence_id": evidence_id}},
            {"match": {"indicator_type": "AV_DETECT"}},
        ]}},
    }
    try:
        response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001 -- the rest of Find Evil still renders
        logger.warning("Find Evil antivirus detections unavailable", exc_info=True)
        return []
    hits = ((response.get("hits") or {}).get("hits")) or []
    return group_detections([str((hit.get("_source") or {}).get("description") or "") for hit in hits])
