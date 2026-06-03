from __future__ import annotations

from uuid import uuid4

from app.analysis.activities import _normalized_name, _parse_iso
from app.models.forensic_activity import ForensicActivity


def correlate_autoruns_activity(activities: list[ForensicActivity], *, window_seconds: int = 86400) -> list[ForensicActivity]:
    persistence_items = [item for item in activities if item.activity_type in {"autorun_entry", "persistence", "service_created", "service_modified"} or "autoruns" in item.tags]
    downloads = [item for item in activities if item.activity_type in {"file_download", "background_download", "bits_downloaded_file", "powershell_download"}]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    defenders = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    new_activities: list[ForensicActivity] = []

    for item in persistence_items:
        persistence_ts = _parse_iso(item.timestamp)
        path_hint = _normalized_name(item.key_fields.get("path") or item.key_fields.get("command") or item.key_fields.get("image_path") or item.key_fields.get("process_path") or item.key_fields.get("file_path"))
        if not path_hint:
            continue
        for candidate in executions:
            candidate_path = _normalized_name(candidate.key_fields.get("process_path") or candidate.key_fields.get("command_line") or candidate.key_fields.get("file_path"))
            if not candidate_path or path_hint not in candidate_path and candidate_path not in path_hint:
                continue
            if persistence_ts and _parse_iso(candidate.timestamp):
                if abs((_parse_iso(candidate.timestamp) - persistence_ts).total_seconds()) > window_seconds:
                    continue
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="persisted_then_executed",
                    title=f"Persisted then executed: {item.key_fields.get('name') or item.title}",
                    timestamp=candidate.timestamp or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.94,
                    tags=sorted(set(item.tags + candidate.tags + ["persistence", "execution_related"])),
                    key_fields={**item.key_fields, "execution_event": candidate.id},
                    evidence_refs=sorted(set(item.evidence_refs + candidate.evidence_refs)),
                    related_events=sorted(set(item.related_events + candidate.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + candidate.suspicious_reasons)),
                )
            )
            break
        for candidate in defenders:
            candidate_path = _normalized_name(candidate.key_fields.get("path"))
            if not candidate_path or path_hint not in candidate_path and candidate_path not in path_hint:
                continue
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="persistence_detected_by_defender",
                    title=f"Persistent file detected by Defender: {item.key_fields.get('name') or item.title}",
                    timestamp=candidate.timestamp or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.95,
                    tags=sorted(set(item.tags + candidate.tags + ["defender_detected", "persistence"])),
                    key_fields={**item.key_fields, "defender_event": candidate.id},
                    evidence_refs=sorted(set(item.evidence_refs + candidate.evidence_refs)),
                    related_events=sorted(set(item.related_events + candidate.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + candidate.suspicious_reasons)),
                )
            )
            break
        for candidate in downloads:
            candidate_path = _normalized_name(candidate.key_fields.get("file_path") or candidate.key_fields.get("target_path"))
            if not candidate_path or path_hint not in candidate_path and candidate_path not in path_hint:
                continue
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_then_persisted",
                    title=f"Downloaded then persisted: {item.key_fields.get('name') or item.title}",
                    timestamp=item.timestamp or candidate.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.86,
                    tags=sorted(set(item.tags + candidate.tags + ["download", "persistence"])),
                    key_fields={**item.key_fields, "download_event": candidate.id, "download_domain": candidate.key_fields.get("domain")},
                    evidence_refs=sorted(set(item.evidence_refs + candidate.evidence_refs)),
                    related_events=sorted(set(item.related_events + candidate.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + candidate.suspicious_reasons)),
                )
            )
            break
    return activities + new_activities


__all__ = ["correlate_autoruns_activity"]
