from collections.abc import Iterable
import time

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.artifact import Artifact
from app.models.evidence import Evidence
from app.models.detection_result import DetectionResult


def _normalize_detection_foreign_keys(
    db: Session,
    *,
    evidence_id: str | None,
    artifact_id: str | None,
) -> tuple[str | None, str | None]:
    cache = db.info.setdefault(
        "_detection_fk_cache",
        {
            "evidence": {},
            "artifact": {},
        },
    )

    artifact_evidence_id: str | None = None
    if artifact_id:
        artifact_cache = cache["artifact"]
        cached_artifact = artifact_cache.get(artifact_id)
        if cached_artifact is None:
            row = db.query(Artifact.id, Artifact.evidence_id).filter(Artifact.id == artifact_id).first()
            cached_artifact = str(row.evidence_id) if row else False
            artifact_cache[artifact_id] = cached_artifact
        if cached_artifact is False:
            artifact_id = None
        else:
            artifact_evidence_id = str(cached_artifact)

    if evidence_id:
        evidence_cache = cache["evidence"]
        cached_evidence = evidence_cache.get(evidence_id)
        if cached_evidence is None:
            cached_evidence = db.query(Evidence.id).filter(Evidence.id == evidence_id).first() is not None
            evidence_cache[evidence_id] = cached_evidence
        if not cached_evidence:
            evidence_id = None
            artifact_id = None

    if artifact_id and artifact_evidence_id:
        if evidence_id and evidence_id != artifact_evidence_id:
            artifact_id = None
        elif not evidence_id:
            evidence_id = artifact_evidence_id

    return evidence_id, artifact_id


def get_detection_unique(
    db: Session,
    *,
    case_id: str,
    rule_id: str | None,
    rule_set_id: str | None,
    event_id: str | None,
    opensearch_id: str | None,
    rule_name: str,
    dedup_fingerprint: str | None = None,
    target_path: str | None = None,
) -> DetectionResult | None:
    query = db.query(DetectionResult).filter(
        DetectionResult.case_id == case_id,
        DetectionResult.rule_name == rule_name,
        DetectionResult.deleted_at.is_(None),
    )
    if dedup_fingerprint is not None:
        existing = query.filter(DetectionResult.dedup_fingerprint == dedup_fingerprint).first()
        if existing:
            return existing
    if rule_id is not None:
        query = query.filter(DetectionResult.rule_id == rule_id)
    if rule_set_id is not None:
        query = query.filter(DetectionResult.rule_set_id == rule_set_id)
    if opensearch_id is not None:
        query = query.filter(DetectionResult.opensearch_id == opensearch_id)
    elif event_id is not None:
        query = query.filter(DetectionResult.event_id == event_id)
    elif target_path is not None:
        query = query.filter(DetectionResult.target_path == target_path)
    return query.first()


def get_existing_detection_keys(
    db: Session,
    *,
    case_id: str,
    dedup_fingerprints: Iterable[str],
    batch_size: int = 2000,
) -> dict[str, DetectionResult]:
    fingerprints = [str(item).strip() for item in dedup_fingerprints if str(item).strip()]
    if not fingerprints:
        return {}

    unique_fingerprints = sorted(set(fingerprints))
    existing: dict[str, DetectionResult] = {}
    effective_batch_size = max(int(batch_size or 2000), 100)
    for start in range(0, len(unique_fingerprints), effective_batch_size):
        batch = unique_fingerprints[start : start + effective_batch_size]
        rows = (
            db.query(DetectionResult)
            .filter(
                DetectionResult.case_id == case_id,
                DetectionResult.deleted_at.is_(None),
                DetectionResult.dedup_fingerprint.in_(batch),
            )
            .all()
        )
        existing.update(
            {
                str(row.dedup_fingerprint): row
                for row in rows
                if str(row.dedup_fingerprint or "").strip()
            }
        )
    return existing


def _apply_detection_payload_to_existing(existing: DetectionResult, payload: dict) -> None:
    existing.status = str(payload.get("status") or existing.status or "new")
    existing.event_id = payload.get("event_id")
    existing.event_index = payload.get("event_index")
    existing.opensearch_id = payload.get("opensearch_id")
    existing.evidence_id = payload.get("evidence_id")
    existing.artifact_id = payload.get("artifact_id")
    existing.target_path = payload.get("target_path")
    existing.matched_at = payload.get("matched_at")
    existing.matched_stable_event_id = payload.get("matched_stable_event_id")
    existing.matched_file_hash = payload.get("matched_file_hash")
    existing.matched_process_node_id = payload.get("matched_process_node_id")
    existing.host_name = payload.get("host_name")
    existing.message = payload.get("message")
    existing.matched_fields = payload.get("matched_fields") or {}
    existing.matched_strings = payload.get("matched_strings") or []
    existing.condition_summary = payload.get("condition_summary")
    existing.description = payload.get("description")
    existing.false_positives = payload.get("false_positives") or []
    existing.references = payload.get("references") or []
    existing.tags = payload.get("tags") or []
    existing.mitre = payload.get("mitre") or []
    existing.related_event_ids = payload.get("related_event_ids") or []
    existing.related_finding_ids = payload.get("related_finding_ids") or []
    existing.related_iocs = payload.get("related_iocs") or {}
    existing.risk_score = payload.get("risk_score")
    existing.engine_version = payload.get("engine_version")
    existing.data_quality = payload.get("data_quality") or []
    existing.raw = payload.get("raw") or {}


def _build_detection_payload(
    db: Session,
    payload: dict,
) -> dict:
    normalized = dict(payload)
    evidence_id, artifact_id = _normalize_detection_foreign_keys(
        db,
        evidence_id=normalized.get("evidence_id"),
        artifact_id=normalized.get("artifact_id"),
    )
    normalized["evidence_id"] = evidence_id
    normalized["artifact_id"] = artifact_id
    normalized["matched_fields"] = normalized.get("matched_fields") or {}
    normalized["matched_strings"] = normalized.get("matched_strings") or []
    normalized["false_positives"] = normalized.get("false_positives") or []
    normalized["references"] = normalized.get("references") or []
    normalized["tags"] = normalized.get("tags") or []
    normalized["mitre"] = normalized.get("mitre") or []
    normalized["related_event_ids"] = normalized.get("related_event_ids") or []
    normalized["related_finding_ids"] = normalized.get("related_finding_ids") or []
    normalized["related_iocs"] = normalized.get("related_iocs") or {}
    normalized["data_quality"] = normalized.get("data_quality") or []
    normalized["raw"] = normalized.get("raw") or {}
    normalized["status"] = normalized.get("status") or "new"
    return normalized


def create_detections_bulk_if_missing(
    db: Session,
    *,
    case_id: str,
    detection_payloads: list[dict],
    commit: bool = True,
    duplicate_lookup_batch_size: int = 2000,
    insert_batch_size: int = 1000,
) -> dict[str, object]:
    if not detection_payloads:
        return {
            "created": [],
            "duplicates": [],
            "created_count": 0,
            "duplicate_count": 0,
            "revived_stale_count": 0,
            "bulk_lookup_count": 0,
            "bulk_insert_batches": 0,
            "dedupe_time_ms": 0,
            "write_time_ms": 0,
        }

    prepared_payloads = [_build_detection_payload(db, payload) for payload in detection_payloads]
    fingerprint_payloads = [payload for payload in prepared_payloads if str(payload.get("dedup_fingerprint") or "").strip()]
    fallback_payloads = [payload for payload in prepared_payloads if not str(payload.get("dedup_fingerprint") or "").strip()]

    dedupe_started = time.perf_counter()
    existing_by_fingerprint = get_existing_detection_keys(
        db,
        case_id=case_id,
        dedup_fingerprints=[str(payload.get("dedup_fingerprint")) for payload in fingerprint_payloads],
        batch_size=duplicate_lookup_batch_size,
    )
    dedupe_time_ms = int((time.perf_counter() - dedupe_started) * 1000)

    created: list[DetectionResult] = []
    duplicates: list[DetectionResult] = []
    revived_stale_count = 0
    pending_objects: list[DetectionResult] = []

    for payload in fingerprint_payloads:
        fingerprint = str(payload.get("dedup_fingerprint") or "").strip()
        existing = existing_by_fingerprint.get(fingerprint)
        if existing:
            if existing.status == "stale":
                _apply_detection_payload_to_existing(existing, payload)
                revived_stale_count += 1
            duplicates.append(existing)
            continue
        detection = DetectionResult(**payload)
        pending_objects.append(detection)
        created.append(detection)

    write_started = time.perf_counter()
    bulk_insert_batches = 0
    try:
        if pending_objects:
            effective_insert_batch_size = max(int(insert_batch_size or 1000), 100)
            for start in range(0, len(pending_objects), effective_insert_batch_size):
                batch = pending_objects[start : start + effective_insert_batch_size]
                if not batch:
                    continue
                db.add_all(batch)
                bulk_insert_batches += 1
        for payload in fallback_payloads:
            detection, item_created = create_detection_if_missing(db, commit=False, **payload)
            if item_created:
                created.append(detection)
            else:
                duplicates.append(detection)
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        detail = str(exc).lower()
        if "evidences" not in detail and "artifacts" not in detail:
            raise
        created.clear()
        duplicates.clear()
        revived_stale_count = 0
        for payload in prepared_payloads:
            detection, item_created = create_detection_if_missing(db, commit=False, **payload)
            if item_created:
                created.append(detection)
            else:
                duplicates.append(detection)
        if commit:
            db.commit()
    write_time_ms = int((time.perf_counter() - write_started) * 1000)

    return {
        "created": created,
        "duplicates": duplicates,
        "created_count": len(created),
        "duplicate_count": len(duplicates),
        "revived_stale_count": revived_stale_count,
        "bulk_lookup_count": 0 if not fingerprint_payloads else max(1, (len(sorted(set(str(payload.get("dedup_fingerprint")) for payload in fingerprint_payloads if str(payload.get("dedup_fingerprint") or "").strip()))) + max(int(duplicate_lookup_batch_size or 2000), 100) - 1) // max(int(duplicate_lookup_batch_size or 2000), 100)),
        "bulk_insert_batches": bulk_insert_batches,
        "dedupe_time_ms": dedupe_time_ms,
        "write_time_ms": write_time_ms,
    }


def create_detection_if_missing(
    db: Session,
    *,
    case_id: str,
    evidence_id: str | None,
    artifact_id: str | None,
    rule_id: str | None,
    rule_set_id: str | None,
    engine: str,
    source_engine: str | None,
    rule_name: str,
    severity: str | None,
    confidence: float | None,
    event_id: str | None,
    event_index: str | None,
    opensearch_id: str | None,
    target_type: str,
    target_path: str | None,
    message: str | None,
    rule_title: str | None = None,
    rule_version: str | None = None,
    rule_author: str | None = None,
    rule_level: str | None = None,
    matched_at: str | None = None,
    matched_stable_event_id: str | None = None,
    matched_file_hash: str | None = None,
    matched_process_node_id: str | None = None,
    host_name: str | None = None,
    analyst_note: str | None = None,
    matched_fields: dict | None = None,
    matched_strings: list | None = None,
    condition_summary: str | None = None,
    description: str | None = None,
    false_positives: list | None = None,
    references: list | None = None,
    tags: list | None = None,
    mitre: list | None = None,
    related_event_ids: list | None = None,
    related_finding_ids: list | None = None,
    related_iocs: dict | None = None,
    risk_score: float | None = None,
    dedup_fingerprint: str | None = None,
    engine_version: str | None = None,
    data_quality: list | None = None,
    raw: dict | None = None,
    status: str = "new",
    commit: bool = True,
) -> tuple[DetectionResult, bool]:
    evidence_id, artifact_id = _normalize_detection_foreign_keys(db, evidence_id=evidence_id, artifact_id=artifact_id)
    existing = get_detection_unique(
        db,
        case_id=case_id,
        rule_id=rule_id,
        rule_set_id=rule_set_id,
        event_id=event_id,
        opensearch_id=opensearch_id,
        rule_name=rule_name,
        dedup_fingerprint=dedup_fingerprint,
        target_path=target_path,
    )
    if existing:
        if existing.status == "stale":
            _apply_detection_payload_to_existing(
                existing,
                {
                    "status": status,
                    "event_id": event_id,
                    "event_index": event_index,
                    "opensearch_id": opensearch_id,
                    "evidence_id": evidence_id,
                    "artifact_id": artifact_id,
                    "target_path": target_path,
                    "matched_at": matched_at,
                    "matched_stable_event_id": matched_stable_event_id,
                    "matched_file_hash": matched_file_hash,
                    "matched_process_node_id": matched_process_node_id,
                    "host_name": host_name,
                    "message": message,
                    "matched_fields": matched_fields,
                    "matched_strings": matched_strings,
                    "condition_summary": condition_summary,
                    "description": description,
                    "false_positives": false_positives,
                    "references": references,
                    "tags": tags,
                    "mitre": mitre,
                    "related_event_ids": related_event_ids,
                    "related_finding_ids": related_finding_ids,
                    "related_iocs": related_iocs,
                    "risk_score": risk_score,
                    "engine_version": engine_version,
                    "data_quality": data_quality,
                    "raw": raw,
                },
            )
            if commit:
                db.commit()
        return existing, False
    detection_payload = dict(
        case_id=case_id,
        evidence_id=evidence_id,
        artifact_id=artifact_id,
        rule_id=rule_id,
        rule_set_id=rule_set_id,
        engine=engine,
        source_engine=source_engine or engine,
        rule_name=rule_name,
        rule_title=rule_title,
        rule_version=rule_version,
        rule_author=rule_author,
        rule_level=rule_level,
        severity=severity,
        confidence=confidence,
        event_id=event_id,
        event_index=event_index,
        opensearch_id=opensearch_id,
        target_type=target_type,
        target_path=target_path,
        matched_at=matched_at,
        matched_stable_event_id=matched_stable_event_id,
        matched_file_hash=matched_file_hash,
        matched_process_node_id=matched_process_node_id,
        host_name=host_name,
        message=message,
        status=status,
        analyst_note=analyst_note,
        matched_fields=matched_fields or {},
        matched_strings=matched_strings or [],
        condition_summary=condition_summary,
        description=description,
        false_positives=false_positives or [],
        references=references or [],
        tags=tags or [],
        mitre=mitre or [],
        related_event_ids=related_event_ids or [],
        related_finding_ids=related_finding_ids or [],
        related_iocs=related_iocs or {},
        risk_score=risk_score,
        dedup_fingerprint=dedup_fingerprint,
        engine_version=engine_version,
        data_quality=data_quality or [],
        raw=raw or {},
    )
    detection = DetectionResult(**detection_payload)
    db.add(detection)
    if commit:
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            message = str(exc).lower()
            if (
                ("evidences" not in message and "artifacts" not in message)
                or (detection_payload.get("evidence_id") is None and detection_payload.get("artifact_id") is None)
            ):
                raise
            detection_payload["evidence_id"] = None
            detection_payload["artifact_id"] = None
            detection = DetectionResult(**detection_payload)
            db.add(detection)
            db.commit()
    return detection, True
