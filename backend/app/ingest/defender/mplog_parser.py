from pathlib import Path
import re


INTERESTING_KEYWORDS = (
    "threat",
    "detection",
    "detected",
    "remediation",
    "quarantine",
    "blocked",
    "removed",
    "clean",
    "allowed",
    "resource",
    "path",
    "file:",
)


def parse_mplog_file(path: Path) -> tuple[list[dict], dict]:
    records: list[dict] = []
    lines_read = 0
    interesting_lines = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, line in enumerate(handle, start=1):
            lines_read += 1
            stripped = line.strip()
            if not stripped:
                continue
            lowered = stripped.lower()
            if not any(token in lowered for token in INTERESTING_KEYWORDS):
                continue
            interesting_lines += 1
            timestamp = None
            match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", stripped)
            if match:
                timestamp = match.group(1)
            threat = None
            threat_match = re.search(r"(?:Threat|Detected)\s*[:=]\s*([^\|,;]+)", stripped, flags=re.IGNORECASE)
            if threat_match:
                threat = threat_match.group(1).strip()
            action = None
            action_match = re.search(r"(?:Action|Remediation)\s*[:=]\s*([^\|,;]+)", stripped, flags=re.IGNORECASE)
            if action_match:
                action = action_match.group(1).strip()
            resource = None
            resource_match = re.search(r"(?:Resource|Path|file:)\s*[:=]?\s*([^\|]+)", stripped, flags=re.IGNORECASE)
            if resource_match:
                resource = resource_match.group(1).strip()
            records.append(
                {
                    "Timestamp": timestamp,
                    "Message": stripped,
                    "ThreatName": threat,
                    "Action": action,
                    "Resource": resource,
                    "SourceFile": path.name,
                    "LineNumber": line_number,
                }
            )
    return records, {
        "lines_read": lines_read,
        "interesting_lines": interesting_lines,
        "parsed_events": len(records),
        "skipped_lines": max(lines_read - interesting_lines, 0),
    }
