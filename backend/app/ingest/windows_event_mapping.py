from dataclasses import dataclass, field

from app.ingest.windows_event_catalog import CatalogMatch, classify_evtx_event


@dataclass
class EventClassification:
    category: str
    event_type: str
    severity: str
    tags: list[str] = field(default_factory=list)
    message_hint: str | None = None
    risk_score: int = 0
    action: str | None = None
    source_match: bool = True
    source_family: str = "generic"


def severity_to_risk_score(severity: str) -> int:
    return {"info": 0, "low": 20, "medium": 50, "high": 80, "critical": 100}.get(severity, 0)


def apply_tag_risk_adjustments(base_score: int, tags: list[str]) -> int:
    score = base_score
    increments = {
        "suspicious_process": 20,
        "suspicious_command": 25,
        "persistence": 20,
        "lateral_movement_candidate": 15,
        "possible_exfiltration": 25,
        "powershell": 10,
        "rdp": 5,
        "benign_microsoft_signed": -25,
        "known_good_windows_path": -20,
        "known_good_microsoft_task": -20,
        "known_good_windows_update": -25,
        "normal_onedrive_sync": -15,
        "informational_usb_only": -15,
        "weak_single_signal": -15,
    }
    for tag in tags:
        score += increments.get(tag, 0)
    return max(0, min(score, 100))


def risk_score_to_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _row_value(row: dict, *names: str) -> str:
    lowered = {str(key).replace("_", "").replace(" ", "").lower(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.replace("_", "").replace(" ", "").lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _to_classification(match: CatalogMatch) -> EventClassification:
    return EventClassification(
        category=match.category,
        event_type=match.event_type,
        severity=match.severity,
        tags=list(match.tags),
        risk_score=severity_to_risk_score(match.severity),
        action=match.action,
        source_match=match.source_match,
        source_family=match.source_family,
    )


def classify_windows_event(event_id: int | None, row: dict) -> EventClassification:
    provider = _row_value(row, "Provider", "ProviderName", "SourceName")
    channel = _row_value(row, "Channel", "LogName")
    return _to_classification(classify_evtx_event(event_id, channel, provider, row.get("Payload") if isinstance(row.get("Payload"), dict) else None))
