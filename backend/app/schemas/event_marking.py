from datetime import datetime

from pydantic import BaseModel, Field


EVENT_MARKING_STATUSES = {"unreviewed", "reviewed", "suspicious", "important", "false_positive"}


class EventMarkingCreate(BaseModel):
    case_id: str | None = None
    evidence_id: str | None = None
    search_doc_id: str | None = None
    stable_event_id: str | None = None
    artifact_type: str | None = None
    timestamp: datetime | None = None
    host: str | None = None
    status: str = "suspicious"
    labels: list[str] = Field(default_factory=list)
    note: str | None = None
    finding_id: str | None = None
    created_by: str = "analyst"


class EventMarkingUpdate(BaseModel):
    status: str | None = None
    labels: list[str] | None = None
    note: str | None = None
    finding_id: str | None = None


class EventMarkingRead(BaseModel):
    id: str
    case_id: str
    evidence_id: str | None
    event_id: str
    search_doc_id: str | None
    stable_event_id: str | None
    artifact_type: str | None
    timestamp: datetime | None
    host: str | None
    status: str
    labels: list[str]
    note: str | None
    finding_id: str | None
    created_at: datetime
    updated_at: datetime
    created_by: str | None

    model_config = {"from_attributes": True}
