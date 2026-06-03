from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import iter_case_events
from app.ingest.fingerprints import compute_event_fingerprint
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.timeline_bookmark import TimelineBookmark


def _event_scope(case_id: str, evidence_id: str) -> list[dict[str, Any]]:
    return list(iter_case_events(case_id, query={"term": {"evidence_id": evidence_id}}))


def _stable_event_id_for_event(event: dict[str, Any]) -> str | None:
    value = str(event.get("stable_event_id") or event.get("event_fingerprint") or "").strip()
    if value:
        return value
    try:
        return compute_event_fingerprint(event).stable_event_id
    except Exception:  # noqa: BLE001
        return None


def capture_reprocess_baseline(db: Session, evidence: Evidence) -> dict[str, Any]:
    events = _event_scope(evidence.case_id, evidence.id)
    event_map: dict[str, str] = {}
    stable_ids: list[str] = []
    for event in events:
        technical_id = str(event.get("id") or event.get("event_id") or "").strip()
        stable_id = _stable_event_id_for_event(event)
        if technical_id and stable_id:
            event_map[technical_id] = stable_id
            stable_ids.append(stable_id)

    bookmarks = db.query(TimelineBookmark).filter(TimelineBookmark.case_id == evidence.case_id).all()
    for bookmark in bookmarks:
        if bookmark.event_id in event_map and not bookmark.stable_event_id:
            bookmark.stable_event_id = event_map[bookmark.event_id]
            bookmark.remap_status = "current"

    detections = db.query(DetectionResult).filter(DetectionResult.case_id == evidence.case_id, DetectionResult.evidence_id == evidence.id).all()
    detection_status_by_fingerprint: dict[str, dict[str, Any]] = {}
    for detection in detections:
        if detection.event_id and not detection.matched_stable_event_id:
            detection.matched_stable_event_id = event_map.get(str(detection.event_id))
        if detection.dedup_fingerprint:
            detection_status_by_fingerprint[str(detection.dedup_fingerprint)] = {
                "status": detection.status,
                "analyst_note": detection.analyst_note,
            }

    findings = db.query(Finding).filter(Finding.case_id == evidence.case_id).all()
    for finding in findings:
        if finding.related_event_ids and not getattr(finding, "related_stable_event_ids", None):
            finding.related_stable_event_ids = [event_map.get(str(event_id), str(event_id)) for event_id in (finding.related_event_ids or []) if event_id]

    db.commit()
    return {
        "event_count": len(events),
        "stable_event_ids": sorted(set(stable_ids)),
        "old_event_id_to_stable_event_id": event_map,
        "detection_status_by_fingerprint": detection_status_by_fingerprint,
        "bookmark_count": len(bookmarks),
    }


def reconcile_reprocessed_evidence(db: Session, evidence: Evidence) -> dict[str, Any]:
    metadata = dict(evidence.metadata_json or {})
    baseline = dict(metadata.get("reconciliation_baseline") or {})
    events = _event_scope(evidence.case_id, evidence.id)
    stable_to_current: dict[str, dict[str, Any]] = {}
    collisions: list[str] = []
    for event in events:
        stable_id = _stable_event_id_for_event(event)
        if not stable_id:
            continue
        if stable_id in stable_to_current:
            collisions.append(stable_id)
        stable_to_current[stable_id] = {
            "event_id": str(event.get("event_id") or event.get("id") or ""),
            "opensearch_id": str(event.get("id") or event.get("event_id") or ""),
            "timestamp": event.get("@timestamp"),
        }

    key_events_remapped = 0
    key_events_stale = 0
    for bookmark in db.query(TimelineBookmark).filter(TimelineBookmark.case_id == evidence.case_id).all():
        stable_id = str(bookmark.stable_event_id or "").strip() or (baseline.get("old_event_id_to_stable_event_id") or {}).get(str(bookmark.event_id))
        if not stable_id:
            continue
        bookmark.stable_event_id = stable_id
        current = stable_to_current.get(stable_id)
        if current:
            if bookmark.event_id != current["event_id"]:
                key_events_remapped += 1
            bookmark.event_id = current["event_id"]
            bookmark.remap_status = "remapped" if (baseline.get("old_event_id_to_stable_event_id") or {}).get(str(bookmark.event_id)) != current["event_id"] else "current"
        else:
            bookmark.remap_status = "stale"
            key_events_stale += 1

    matched_existing = 0
    detections_created = 0
    stale_archived = 0
    detections = db.query(DetectionResult).filter(DetectionResult.case_id == evidence.case_id, DetectionResult.evidence_id == evidence.id).all()
    baseline_status = {str(key): value for key, value in dict(baseline.get("detection_status_by_fingerprint") or {}).items()}
    active_fingerprints: Counter[str] = Counter()
    for detection in detections:
        if detection.dedup_fingerprint:
            active_fingerprints[str(detection.dedup_fingerprint)] += 1
            if str(detection.dedup_fingerprint) in baseline_status:
                matched_existing += 1
                preserved = baseline_status[str(detection.dedup_fingerprint)]
                if preserved.get("status") not in {None, "", "stale"}:
                    detection.status = str(preserved["status"])
                if preserved.get("analyst_note") and not detection.analyst_note:
                    detection.analyst_note = preserved.get("analyst_note")
        stable_id = str(detection.matched_stable_event_id or "").strip()
        if stable_id and stable_id in stable_to_current:
            current = stable_to_current[stable_id]
            detection.event_id = current["event_id"] or detection.event_id
            detection.opensearch_id = current["opensearch_id"] or detection.opensearch_id
            if detection.status == "stale":
                detection.status = "new"
        elif detection.status == "stale":
            stale_archived += 1

    findings_matched_existing = 0
    findings_created = 0
    findings_stale_removed_or_archived = 0
    for finding in db.query(Finding).filter(Finding.case_id == evidence.case_id, Finding.source == "correlation_engine").all():
        stable_ids = [str(item) for item in (finding.related_stable_event_ids or []) if item]
        if stable_ids:
            findings_matched_existing += 1
            finding.related_event_ids = [stable_to_current[item]["event_id"] for item in stable_ids if item in stable_to_current]

    report = {
        "case_id": evidence.case_id,
        "evidence_id": evidence.id,
        "findings_matched_existing": findings_matched_existing,
        "findings_created": findings_created,
        "findings_stale_removed_or_archived": findings_stale_removed_or_archived,
        "detections_matched_existing": matched_existing,
        "detections_created": detections_created,
        "key_events_remapped": key_events_remapped,
        "key_events_stale": key_events_stale,
        "warnings": ["stable_event_id_collision_detected"] if collisions else [],
    }
    identity_report = {
        "case_id": evidence.case_id,
        "evidence_id": evidence.id,
        "fingerprint_version": "v1",
        "events_with_stable_id": len(stable_to_current),
        "events_missing_stable_id": max(len(events) - len(stable_to_current), 0),
        "best_effort_count": sum(1 for event in events if "fingerprint_best_effort" in (event.get("data_quality") or [])),
        "by_artifact_type": dict(Counter(str((event.get("artifact") or {}).get("type") or "unknown") for event in events)),
        "collision_count": len(set(collisions)),
        "collisions": sorted(set(collisions))[:20],
        "warnings": report["warnings"],
    }
    metadata["reconciliation_report"] = report
    metadata["event_identity_report"] = identity_report
    evidence.metadata_json = metadata
    db.commit()
    return {"reconciliation_report": report, "event_identity_report": identity_report}
