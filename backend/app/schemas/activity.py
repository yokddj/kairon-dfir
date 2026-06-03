from datetime import datetime

from pydantic import BaseModel, Field

from app.models.activity import ActivitySeverity


class ActivityRead(BaseModel):
    id: str
    case_id: str | None
    evidence_id: str | None
    actor: str | None
    activity_type: str
    severity: ActivitySeverity
    title: str
    message: str
    metadata: dict = Field(default_factory=dict, validation_alias="metadata_json")
    created_at: datetime

    model_config = {"from_attributes": True}
