from datetime import datetime

from pydantic import BaseModel, Field

from app.models.finding import FindingSeverity, FindingStatus


class FindingCreate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: FindingSeverity = FindingSeverity.info
    status: FindingStatus = FindingStatus.new
    query: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    evidence_id: str | None = None
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


class FindingUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    query: str | None = None
    event_ids: list[str] | None = None
    detection_ids: list[str] | None = None
    evidence_id: str | None = None
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


class FindingRead(BaseModel):
    id: str
    case_id: str
    title: str
    description: str | None
    severity: FindingSeverity
    status: FindingStatus
    query: str | None
    event_ids: list[str]
    detection_ids: list[str]
    evidence_id: str | None
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
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
