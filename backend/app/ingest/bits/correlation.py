from __future__ import annotations

from datetime import timedelta
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from app.analysis.activities import _normalized_name, _parse_iso
from app.models.forensic_activity import ForensicActivity


def correlate_bits_activity(activities: list[ForensicActivity], *, window_seconds: int = 86400) -> list[ForensicActivity]:
    bits_items = [item for item in activities if item.activity_type in {"background_download", "bits_notify_persistence"}]
    suspicious_bits_items = [item for item in activities if item.activity_type == "suspicious_bits_job"]
    powershell_items = [item for item in activities if item.activity_type.startswith("powershell")]
    browser_items = [item for item in activities if item.activity_type == "file_download"]
    defender_items = [item for item in activities if item.activity_type == "defender_detection"]
    execution_items = [item for item in activities if item.activity_type in {"program_execution", "execution_candidate"}]
    file_creations = [item for item in activities if item.activity_type == "file_created"]
    new_activities: list[ForensicActivity] = []

    for item in bits_items:
        local_path = _normalized_name(item.key_fields.get("local_path") or item.key_fields.get("file_path"))
        remote_url = _normalized_name(item.key_fields.get("remote_url") or item.key_fields.get("url"))
        job_id = _normalized_name(item.key_fields.get("job_id"))
        local_name = ""
        if local_path:
            try:
                local_name = str(PureWindowsPath(local_path).name).lower()
            except Exception:  # noqa: BLE001
                local_name = Path(local_path.replace("\\", "/")).name.lower()
        host = _normalized_name(item.host)
        ts = _parse_iso(item.timestamp)
        if not local_path and not remote_url:
            continue

        related_suspicious_items = [
            candidate
            for candidate in suspicious_bits_items
            if (
                _normalized_name(candidate.key_fields.get("job_id")) == job_id
                or (
                    local_path
                    and local_path == _normalized_name(candidate.key_fields.get("local_path") or candidate.key_fields.get("file_path"))
                )
                or (
                    remote_url
                    and remote_url == _normalized_name(candidate.key_fields.get("remote_url") or candidate.key_fields.get("url"))
                )
            )
        ]

        matched_powershell = next(
            (
                candidate
                for candidate in powershell_items
                if _normalized_name(candidate.host) in {"", host}
                and any(token in str(candidate.key_fields.get("command_line") or "").lower() for token in ["start-bitstransfer", "bitsadmin", "background intelligent transfer", "add-bitsfile", "set-bitstransfer", "complete-bitstransfer"])
                and (
                    (
                        remote_url
                        and remote_url in _normalized_name(
                            candidate.key_fields.get("url")
                            or candidate.key_fields.get("command_line")
                            or candidate.summary
                        )
                    )
                    or (
                        local_path
                        and local_path in _normalized_name(
                            candidate.key_fields.get("command_line")
                            or candidate.summary
                        )
                    )
                )
            ),
            None,
        )
        matched_browser = next(
            (
                candidate
                for candidate in browser_items
                if _normalized_name(candidate.host) in {"", host}
                and (
                    (remote_url and remote_url == _normalized_name(candidate.key_fields.get("url")))
                    or (local_path and local_path == _normalized_name(candidate.key_fields.get("file_path")))
                )
            ),
            None,
        )
        matched_defender = next(
            (
                candidate
                for candidate in defender_items
                if _normalized_name(candidate.host) in {"", host}
                and local_path
                and local_path == _normalized_name(candidate.key_fields.get("path"))
            ),
            None,
        )
        matched_creation = next(
            (
                candidate
                for candidate in file_creations
                if _normalized_name(candidate.host) in {"", host}
                and local_path
                and local_path == _normalized_name(candidate.key_fields.get("file_path"))
                and (
                    not ts
                    or not _parse_iso(candidate.timestamp)
                    or abs((_parse_iso(candidate.timestamp) - ts).total_seconds()) <= window_seconds
                )
            ),
            None,
        )
        matched_execution = next(
            (
                candidate
                for candidate in execution_items
                if _normalized_name(candidate.host) in {"", host}
                and (
                    (
                        local_path
                        and local_path == _normalized_name(candidate.key_fields.get("process_path") or candidate.key_fields.get("file_path"))
                    )
                    or (
                        local_name
                        and local_name == _normalized_name(candidate.key_fields.get("process_name") or candidate.key_fields.get("file_name"))
                    )
                )
                and (
                    not ts
                    or not _parse_iso(candidate.timestamp)
                    or abs((_parse_iso(candidate.timestamp) - ts).total_seconds()) <= window_seconds
                )
            ),
            None,
        )
        if matched_execution is None and local_name:
            matched_execution = next(
                (
                    candidate
                    for candidate in execution_items
                    if _normalized_name(candidate.host) in {"", host}
                    and (
                        local_name in _normalized_name(candidate.title)
                        or local_name in _normalized_name(candidate.summary)
                        or local_name == _normalized_name(candidate.key_fields.get("process_name") or candidate.key_fields.get("file_name"))
                        or local_name == _normalized_name(candidate.key_fields.get("process_path")).rsplit("\\", 1)[-1]
                        or local_name == _normalized_name(candidate.key_fields.get("file_path")).rsplit("\\", 1)[-1]
                    )
                ),
                None,
            )

        if matched_powershell:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_powershell.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_powershell.related_events))
            item.tags = sorted(set(item.tags + matched_powershell.tags + ["powershell_correlated"]))
            item.confidence = max(item.confidence, 0.86)
            item.suspicious_reasons = sorted(set(item.suspicious_reasons + ["PowerShell command references BITS job"]))
            for sibling in related_suspicious_items:
                sibling.evidence_refs = sorted(set(sibling.evidence_refs + matched_powershell.evidence_refs))
                sibling.related_events = sorted(set(sibling.related_events + matched_powershell.related_events))
                sibling.tags = sorted(set(sibling.tags + matched_powershell.tags + ["powershell_correlated"]))
                sibling.confidence = max(sibling.confidence, 0.86)
                sibling.suspicious_reasons = sorted(set(sibling.suspicious_reasons + ["PowerShell command references BITS job"]))
        if matched_browser:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_browser.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_browser.related_events))
            item.tags = sorted(set(item.tags + matched_browser.tags + ["browser_correlated"]))
            item.confidence = max(item.confidence, 0.82)
        if matched_creation:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_creation.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_creation.related_events))
            item.tags = sorted(set(item.tags + matched_creation.tags + ["mft_correlated"]))
            item.confidence = max(item.confidence, 0.88)
        if matched_defender:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_defender.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_defender.related_events))
            item.tags = sorted(set(item.tags + matched_defender.tags + ["defender_correlated"]))
            item.confidence = max(item.confidence, 0.94)
            item.suspicious_reasons = sorted(set(item.suspicious_reasons + ["BITS local file later detected by Defender"]))
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="bits_download_detected_by_defender",
                    title=f"BITS download detected by Defender: {item.key_fields.get('file_name') or Path(str(item.key_fields.get('local_path') or '')).name or 'file'}",
                    timestamp=item.timestamp or matched_defender.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.94,
                    tags=sorted(set(item.tags + matched_defender.tags + ["download", "defender_correlated"])),
                    key_fields={**item.key_fields, "defender_event": (matched_defender.related_events[0] if matched_defender.related_events else matched_defender.id)},
                    evidence_refs=sorted(set(item.evidence_refs + matched_defender.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_defender.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_defender.suspicious_reasons)),
                )
            )
        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.95)
            item.suspicious_reasons = sorted(set(item.suspicious_reasons + ["BITS local file later executed"]))
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="bits_download_then_execute",
                    title=f"BITS download then execute: {item.key_fields.get('file_name') or Path(str(item.key_fields.get('local_path') or '')).name or 'file'}",
                    timestamp=matched_execution.timestamp or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.95,
                    tags=sorted(set(item.tags + matched_execution.tags + ["download", "execution_related"])),
                    key_fields={**item.key_fields, "execution_event": (matched_execution.related_events[0] if matched_execution.related_events else matched_execution.id)},
                    evidence_refs=sorted(set(item.evidence_refs + matched_execution.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_execution.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_execution.suspicious_reasons)),
                )
            )

    return activities + new_activities
