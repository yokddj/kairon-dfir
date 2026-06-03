from datetime import datetime

from pydantic import BaseModel

from app.models.case import CaseMode, CaseStatus


class CaseCreate(BaseModel):
    name: str
    description: str | None = None
    status: CaseStatus = CaseStatus.open
    mode: CaseMode = CaseMode.investigation
    timezone: str | None = None


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: CaseStatus | None = None
    mode: CaseMode | None = None
    timezone: str | None = None


class CaseRead(BaseModel):
    id: str
    name: str
    description: str | None
    status: CaseStatus
    mode: CaseMode = CaseMode.investigation
    timezone: str | None = None
    detections_count: int = 0
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
