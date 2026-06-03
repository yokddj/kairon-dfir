from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from app.analysis.activities import _normalized_name, _parse_iso
from app.models.forensic_activity import ForensicActivity


def correlate_wmi_activity(activities: list[ForensicActivity], *, window_seconds: int = 86400) -> list[ForensicActivity]:
    filters = [item for item in activities if item.activity_type == "wmi_filter"]
    consumers = [item for item in activities if item.activity_type == "wmi_consumer"]
    bindings = [item for item in activities if item.activity_type == "wmi_binding"]
    powershell_items = [item for item in activities if item.activity_type.startswith("powershell")]
    defender_items = [item for item in activities if item.activity_type == "defender_detection"]
    execution_items = [item for item in activities if item.activity_type in {"program_execution", "execution_candidate"}]
    file_creations = [item for item in activities if item.activity_type == "file_created"]
    new_activities: list[ForensicActivity] = []

    for consumer in consumers:
        command_line = _normalized_name(consumer.key_fields.get("command_line"))
        script_preview = _normalized_name(consumer.key_fields.get("script_preview"))
        payload_path = _normalized_name(consumer.key_fields.get("executable_path") or consumer.key_fields.get("file_path"))
        host = _normalized_name(consumer.host)
        ts = _parse_iso(consumer.timestamp)

        if "encoded_powershell" in consumer.tags:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="wmi_encoded_powershell",
                    title=f"WMI encoded PowerShell: {consumer.title}",
                    timestamp=consumer.timestamp,
                    host=consumer.host,
                    user=consumer.user,
                    summary=consumer.summary,
                    severity=consumer.severity,
                    confidence=max(consumer.confidence, 0.84),
                    tags=sorted(set(consumer.tags + ["persistence"])),
                    key_fields=dict(consumer.key_fields),
                    evidence_refs=list(consumer.evidence_refs),
                    related_events=list(consumer.related_events),
                    suspicious_reasons=list(dict.fromkeys(consumer.suspicious_reasons)),
                )
            )
        if "active_script_consumer" in consumer.tags:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="wmi_script_consumer",
                    title=f"WMI script consumer: {consumer.title}",
                    timestamp=consumer.timestamp,
                    host=consumer.host,
                    user=consumer.user,
                    summary=consumer.summary,
                    severity=consumer.severity,
                    confidence=max(consumer.confidence, 0.8),
                    tags=sorted(set(consumer.tags + ["persistence"])),
                    key_fields=dict(consumer.key_fields),
                    evidence_refs=list(consumer.evidence_refs),
                    related_events=list(consumer.related_events),
                    suspicious_reasons=list(dict.fromkeys(consumer.suspicious_reasons)),
                )
            )
        if "download_command" in consumer.tags:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="wmi_download_command",
                    title=f"WMI download command: {consumer.title}",
                    timestamp=consumer.timestamp,
                    host=consumer.host,
                    user=consumer.user,
                    summary=consumer.summary,
                    severity=consumer.severity,
                    confidence=max(consumer.confidence, 0.82),
                    tags=sorted(set(consumer.tags + ["download"])),
                    key_fields=dict(consumer.key_fields),
                    evidence_refs=list(consumer.evidence_refs),
                    related_events=list(consumer.related_events),
                    suspicious_reasons=list(dict.fromkeys(consumer.suspicious_reasons)),
                )
            )

        matched_powershell = next(
            (
                candidate
                for candidate in powershell_items
                if _normalized_name(candidate.host) in {"", host}
                and any(token in _normalized_name(candidate.key_fields.get("command_line") or candidate.summary) for token in ["__eventfilter", "commandlineeventconsumer", "activescripteventconsumer", "__filtertoconsumerbinding", "new-ciminstance", "set-wmiinstance", "register-wmievent"])
            ),
            None,
        )
        matched_defender = next(
            (
                candidate
                for candidate in defender_items
                if _normalized_name(candidate.host) in {"", host}
                and payload_path
                and payload_path == _normalized_name(candidate.key_fields.get("path"))
            ),
            None,
        )
        matched_execution = next(
            (
                candidate
                for candidate in execution_items
                if _normalized_name(candidate.host) in {"", host}
                and payload_path
                and payload_path == _normalized_name(candidate.key_fields.get("process_path") or candidate.key_fields.get("file_path"))
                and (
                    not ts
                    or not _parse_iso(candidate.timestamp)
                    or _parse_iso(candidate.timestamp) >= (ts - timedelta(seconds=10))
                )
            ),
            None,
        )
        matched_creation = next(
            (
                candidate
                for candidate in file_creations
                if _normalized_name(candidate.host) in {"", host}
                and payload_path
                and payload_path == _normalized_name(candidate.key_fields.get("file_path"))
                and (
                    not ts
                    or not _parse_iso(candidate.timestamp)
                    or abs((_parse_iso(candidate.timestamp) - ts).total_seconds()) <= window_seconds
                )
            ),
            None,
        )
        if matched_powershell or matched_defender or matched_execution or matched_creation:
            reasons = list(consumer.suspicious_reasons)
            if matched_defender:
                reasons.append("Defender detected file referenced by WMI")
            if matched_execution:
                reasons.append("WMI consumer executable later observed/executed")
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="possible_wmi_execution",
                    title=f"Possible WMI execution: {consumer.title}",
                    timestamp=matched_execution.timestamp if matched_execution else consumer.timestamp,
                    host=consumer.host,
                    user=consumer.user,
                    summary=consumer.summary,
                    severity=consumer.severity,
                    confidence=0.94 if matched_execution or matched_defender else 0.74,
                    tags=sorted(set(consumer.tags + ["persistence", "execution_related"])),
                    key_fields={
                        **consumer.key_fields,
                        "powershell_event": matched_powershell.id if matched_powershell else None,
                        "defender_event": matched_defender.id if matched_defender else None,
                        "execution_event": matched_execution.id if matched_execution else None,
                        "file_creation_event": matched_creation.id if matched_creation else None,
                    },
                    evidence_refs=sorted(set(consumer.evidence_refs + (matched_powershell.evidence_refs if matched_powershell else []) + (matched_defender.evidence_refs if matched_defender else []) + (matched_execution.evidence_refs if matched_execution else []) + (matched_creation.evidence_refs if matched_creation else []))),
                    related_events=sorted(set(consumer.related_events + (matched_powershell.related_events if matched_powershell else []) + (matched_defender.related_events if matched_defender else []) + (matched_execution.related_events if matched_execution else []) + (matched_creation.related_events if matched_creation else []))),
                    suspicious_reasons=list(dict.fromkeys(reasons)),
                )
            )

    for binding in bindings:
        filter_name = _normalized_name(binding.key_fields.get("binding_filter") or binding.key_fields.get("filter_name"))
        consumer_name = _normalized_name(binding.key_fields.get("binding_consumer") or binding.key_fields.get("consumer_name"))
        filter_item = next((candidate for candidate in filters if filter_name and filter_name == _normalized_name(candidate.key_fields.get("filter_name") or candidate.key_fields.get("name"))), None)
        consumer_item = next((candidate for candidate in consumers if consumer_name and consumer_name == _normalized_name(candidate.key_fields.get("consumer_name") or candidate.key_fields.get("name"))), None)
        confidence = 0.92 if filter_item and consumer_item else 0.64
        tags = sorted(set(binding.tags + ["persistence", "wmi_persistence_candidate"]))
        reasons = list(binding.suspicious_reasons)
        if filter_item and consumer_item:
            reasons.append("WMI filter and consumer are bound")
        if consumer_item and "encoded_powershell" in consumer_item.tags:
            reasons.append("WMI command contains encoded PowerShell")
        new_activities.append(
            ForensicActivity(
                id=str(uuid4()),
                activity_type="wmi_persistence_candidate",
                title=f"WMI persistence candidate: {binding.title}",
                timestamp=binding.timestamp or (consumer_item.timestamp if consumer_item else filter_item.timestamp if filter_item else None),
                host=binding.host or (consumer_item.host if consumer_item else filter_item.host if filter_item else None),
                user=binding.user or (consumer_item.user if consumer_item else filter_item.user if filter_item else None),
                summary=binding.summary,
                severity="high" if confidence >= 0.9 and reasons else binding.severity,
                confidence=confidence,
                tags=tags,
                key_fields={
                    "namespace": binding.key_fields.get("namespace") or (filter_item.key_fields.get("namespace") if filter_item else consumer_item.key_fields.get("namespace") if consumer_item else None),
                    "filter_name": filter_item.key_fields.get("filter_name") if filter_item else binding.key_fields.get("binding_filter"),
                    "consumer_name": consumer_item.key_fields.get("consumer_name") if consumer_item else binding.key_fields.get("binding_consumer"),
                    "consumer_type": consumer_item.key_fields.get("consumer_type") if consumer_item else None,
                    "query": filter_item.key_fields.get("query") if filter_item else None,
                    "command_line": consumer_item.key_fields.get("command_line") if consumer_item else None,
                    "script_preview": consumer_item.key_fields.get("script_preview") if consumer_item else None,
                    "binding_status": "complete" if filter_item and consumer_item else "unresolved",
                },
                evidence_refs=sorted(set(binding.evidence_refs + (filter_item.evidence_refs if filter_item else []) + (consumer_item.evidence_refs if consumer_item else []))),
                related_events=sorted(set(binding.related_events + (filter_item.related_events if filter_item else []) + (consumer_item.related_events if consumer_item else []))),
                suspicious_reasons=list(dict.fromkeys(reasons)),
            )
        )

    return activities + new_activities


__all__ = ["correlate_wmi_activity"]
