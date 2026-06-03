from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from uuid import uuid4

from app.models.forensic_activity import ForensicActivity


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def correlate_cloud_activity(activities: list[ForensicActivity], *, window_seconds: int = 3600) -> list[ForensicActivity]:
    cloud_items = [item for item in activities if item.activity_type in {"cloud_sync_root_observed", "cloud_file_activity", "cloud_sensitive_file_observed", "cloud_archive_created", "downloaded_to_cloud", "copied_to_cloud", "executable_from_cloud", "defender_detection_in_cloud"}]
    if not cloud_items:
        return activities

    by_root: dict[str, list[ForensicActivity]] = defaultdict(list)
    for item in cloud_items:
        root = str(item.key_fields.get("sync_root") or "")
        if root:
            by_root[root.lower()].append(item)

    new_activities: list[ForensicActivity] = []
    for root, items in by_root.items():
        file_events = [item for item in items if item.activity_type in {"cloud_file_activity", "cloud_sensitive_file_observed", "cloud_archive_created", "downloaded_to_cloud", "copied_to_cloud"}]
        if len(file_events) >= 3:
            related = sorted({event for item in file_events for event in item.related_events})
            refs = sorted({ref for item in file_events for ref in item.evidence_refs})
            reasons = sorted({reason for item in file_events for reason in item.suspicious_reasons} | {"Multiple files modified inside cloud sync folder in short time window"})
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="possible_cloud_staging",
                    title=f"Cloud staging candidate: {root}",
                    timestamp=file_events[-1].timestamp if file_events[-1].timestamp else file_events[0].timestamp,
                    host=file_events[0].host,
                    user=file_events[0].user,
                    summary="Multiple files were created or modified inside a cloud sync folder in a short time window. Treat as staging hypothesis, not proof of upload.",
                    severity="medium",
                    confidence=0.78,
                    tags=sorted({tag for item in file_events for tag in item.tags} | {"cloud_staging_candidate"}),
                    key_fields={
                        "provider": file_events[0].key_fields.get("provider"),
                        "sync_root": file_events[0].key_fields.get("sync_root"),
                        "file_count": len(file_events),
                    },
                    evidence_refs=refs,
                    related_events=related,
                    suspicious_reasons=reasons,
                )
            )
        has_copy = any(item.activity_type == "copied_to_cloud" for item in items)
        has_sensitive_or_archive = any(item.activity_type in {"cloud_sensitive_file_observed", "cloud_archive_created"} for item in items)
        if has_copy and has_sensitive_or_archive:
            related = sorted({event for item in items for event in item.related_events})
            refs = sorted({ref for item in items for ref in item.evidence_refs})
            reasons = sorted({reason for item in items for reason in item.suspicious_reasons} | {"Possible cloud exfiltration candidate"})
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="possible_cloud_exfiltration",
                    title=f"Possible cloud exfiltration candidate: {root}",
                    timestamp=items[-1].timestamp if items[-1].timestamp else items[0].timestamp,
                    host=items[0].host,
                    user=items[0].user,
                    summary="Copy or staging activity and sensitive/archive files were observed inside the same cloud sync root. This is a candidate, not confirmed upload.",
                    severity="medium",
                    confidence=0.84,
                    tags=sorted({tag for item in items for tag in item.tags} | {"possible_cloud_exfiltration"}),
                    key_fields={
                        "provider": items[0].key_fields.get("provider"),
                        "sync_root": items[0].key_fields.get("sync_root"),
                    },
                    evidence_refs=refs,
                    related_events=related,
                    suspicious_reasons=reasons,
                )
            )
    return activities + new_activities


__all__ = ["correlate_cloud_activity"]
