from datetime import datetime
import json
import re

from pydantic import AliasChoices, BaseModel, Field, field_validator

from app.models.finding import FindingSeverity, FindingStatus


TAG_PATTERN = re.compile(r"[^a-z0-9_.-]+")
SOURCE_SNAPSHOT_MAX_BYTES = 12_000


def normalize_finding_tags(values: list[str] | None) -> list[str]:
    if not values:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        tag = TAG_PATTERN.sub("-", str(value).strip().lower()).strip("-_.")
        if not tag:
            continue
        if len(tag) > 64:
            raise ValueError("finding tags must be 64 characters or fewer")
        if tag not in seen:
            seen.add(tag)
            normalized.append(tag)
    if len(normalized) > 25:
        raise ValueError("finding tags are limited to 25 values")
    return normalized


def validate_source_snapshot(value: dict | None) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("source_snapshot_json must be an object")
    try:
        size = len(json.dumps(value, default=str, ensure_ascii=False).encode("utf-8"))
    except TypeError as exc:
        raise ValueError("source_snapshot_json must be JSON serializable") from exc
    if size > SOURCE_SNAPSHOT_MAX_BYTES:
        raise ValueError("source_snapshot_json is too large")
    return value


class FindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, validation_alias=AliasChoices("description", "body"), max_length=20000)
    severity: FindingSeverity = FindingSeverity.info
    status: FindingStatus = FindingStatus.draft
    query: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    evidence_id: str | None = None
    linked_evidence_id: str | None = None
    linked_host_id: str | None = None
    linked_artifact_id: str | None = None
    linked_artifact_family: str | None = Field(default=None, max_length=128)
    linked_artifact_type: str | None = Field(default=None, max_length=128)
    linked_event_id: str | None = Field(default=None, max_length=255)
    source_view: str | None = Field(default=None, max_length=128)
    source_route: str | None = Field(default=None, max_length=1024)
    source_timestamp: datetime | None = None
    source_label: str | None = Field(default=None, max_length=255)
    source_summary: str | None = Field(default=None, max_length=4000)
    source_snapshot_json: dict | None = None
    created_by: str | None = Field(default=None, max_length=128)
    finding_type: str | None = None
    confidence: str | None = None
    source: str | None = None
    correlation_version: str | None = None
    fingerprint: str | None = None
    risk_score: int = 0
    time_start: datetime | None = None
    time_end: datetime | None = None
    timeline: list[dict] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    related_artifact_ids: list[str] = Field(default_factory=list)
    related_evidence_ids: list[str] = Field(default_factory=list)
    related_process_node_ids: list[str] = Field(default_factory=list)
    related_files: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)
    related_ips: list[str] = Field(default_factory=list)
    related_users: list[str] = Field(default_factory=list)
    related_hosts: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    recommended_triage: list[str] = Field(default_factory=list)
    data_quality: list[str] = Field(default_factory=list)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value):
        return normalize_finding_tags(value or [])

    @field_validator("source_snapshot_json")
    @classmethod
    def _validate_source_snapshot(cls, value):
        return validate_source_snapshot(value)


class FindingUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, validation_alias=AliasChoices("description", "body"), max_length=20000)
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    query: str | None = None
    event_ids: list[str] | None = None
    detection_ids: list[str] | None = None
    evidence_id: str | None = None
    linked_evidence_id: str | None = None
    linked_host_id: str | None = None
    linked_artifact_id: str | None = None
    linked_artifact_family: str | None = Field(default=None, max_length=128)
    linked_artifact_type: str | None = Field(default=None, max_length=128)
    linked_event_id: str | None = Field(default=None, max_length=255)
    source_view: str | None = Field(default=None, max_length=128)
    source_route: str | None = Field(default=None, max_length=1024)
    source_timestamp: datetime | None = None
    source_label: str | None = Field(default=None, max_length=255)
    source_summary: str | None = Field(default=None, max_length=4000)
    source_snapshot_json: dict | None = None
    created_by: str | None = Field(default=None, max_length=128)
    finding_type: str | None = None
    confidence: str | None = None
    source: str | None = None
    correlation_version: str | None = None
    fingerprint: str | None = None
    risk_score: int | None = None
    time_start: datetime | None = None
    time_end: datetime | None = None
    timeline: list[dict] | None = None
    related_event_ids: list[str] | None = None
    related_artifact_ids: list[str] | None = None
    related_evidence_ids: list[str] | None = None
    related_process_node_ids: list[str] | None = None
    related_files: list[str] | None = None
    related_domains: list[str] | None = None
    related_ips: list[str] | None = None
    related_users: list[str] | None = None
    related_hosts: list[str] | None = None
    reasons: list[str] | None = None
    tags: list[str] | None = None
    mitre: list[str] | None = None
    recommended_triage: list[str] | None = None
    data_quality: list[str] | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value):
        return None if value is None else normalize_finding_tags(value)

    @field_validator("source_snapshot_json")
    @classmethod
    def _validate_source_snapshot(cls, value):
        return validate_source_snapshot(value)


class FindingRead(BaseModel):
    id: str
    case_id: str
    title: str
    description: str | None
    body: str | None = None
    severity: FindingSeverity
    status: FindingStatus
    query: str | None
    event_ids: list[str]
    detection_ids: list[str]
    evidence_id: str | None
    linked_evidence_id: str | None = None
    linked_host_id: str | None = None
    linked_artifact_id: str | None = None
    linked_artifact_family: str | None = None
    linked_artifact_type: str | None = None
    linked_event_id: str | None = None
    source_view: str | None = None
    source_route: str | None = None
    source_timestamp: datetime | None = None
    source_label: str | None = None
    source_summary: str | None = None
    source_snapshot_json: dict | None = None
    created_by: str | None = None
    finding_type: str | None
    confidence: str | None
    source: str | None
    correlation_version: str | None
    fingerprint: str | None
    risk_score: int
    time_start: datetime | None
    time_end: datetime | None
    timeline: list[dict]
    related_event_ids: list[str]
    related_artifact_ids: list[str]
    related_evidence_ids: list[str]
    related_process_node_ids: list[str]
    related_files: list[str]
    related_domains: list[str]
    related_ips: list[str]
    related_users: list[str]
    related_hosts: list[str]
    reasons: list[str]
    tags: list[str]
    mitre: list[str]
    recommended_triage: list[str]
    data_quality: list[str]
    archived_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
