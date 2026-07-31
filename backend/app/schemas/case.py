from datetime import datetime
from typing import Literal
import re

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.case import CaseMode, CasePriority, CaseStatus


TAG_PATTERN = re.compile(r"[^a-z0-9_.-]+")


def normalize_case_status(value: str | CaseStatus | None) -> CaseStatus | None:
    if value is None or isinstance(value, CaseStatus):
        return value
    raw = str(value).strip().lower()
    if raw == "open":
        raw = "active"
    return CaseStatus(raw)


def normalize_case_tags(values: list[str] | None) -> list[str]:
    if not values:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        tag = TAG_PATTERN.sub("-", str(value).strip().lower()).strip("-_.")
        if not tag:
            continue
        if len(tag) > 64:
            raise ValueError("case tags must be 64 characters or fewer")
        if tag not in seen:
            seen.add(tag)
            normalized.append(tag)
    if len(normalized) > 25:
        raise ValueError("case tags are limited to 25 values")
    return normalized


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    status: CaseStatus = CaseStatus.active
    priority: CasePriority = CasePriority.medium
    tags: list[str] = Field(default_factory=list)
    case_notes: str | None = Field(default=None, max_length=12000)
    mode: CaseMode = CaseMode.investigation
    timezone: str | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, value):
        return normalize_case_status(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value):
        return normalize_case_tags(value or [])


class CaseUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    tags: list[str] | None = None
    case_notes: str | None = Field(default=None, max_length=12000)
    mode: CaseMode | None = None
    timezone: str | None = None
    # Manual INVESTIGATE/REPORT workflow override -- see
    # app.services.case_state.derive_case_investigation_state. UPLOAD/
    # PREPARE/ANALYZE are never set through this field; they stay automatic.
    investigation_phase_override: Literal["investigating", "report"] | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, value):
        return normalize_case_status(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value):
        return None if value is None else normalize_case_tags(value)


class CaseRead(BaseModel):
    id: str
    name: str
    description: str | None
    status: CaseStatus
    priority: CasePriority = CasePriority.medium
    tags: list[str] = Field(default_factory=list)
    case_notes: str | None = None
    mode: CaseMode = CaseMode.investigation
    timezone: str | None = None
    evidence_count: int = 0
    host_count: int = 0
    processing_summary: dict[str, int] = Field(default_factory=dict)
    detections_count: int = 0
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _from_case_model(cls, value):
        if hasattr(value, "management_tags"):
            return {
                "id": value.id,
                "name": value.name,
                "description": value.description,
                "status": value.status,
                "priority": value.priority,
                "tags": value.management_tags or [],
                "case_notes": value.case_notes,
                "mode": value.mode,
                "timezone": value.timezone,
                "evidence_count": getattr(value, "evidence_count", 0),
                "host_count": getattr(value, "host_count", 0),
                "processing_summary": getattr(value, "processing_summary", {}),
                "detections_count": getattr(value, "detections_count", 0),
                "findings_count": getattr(value, "findings_count", 0),
                "created_at": value.created_at,
                "updated_at": value.updated_at,
            }
        return value

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, value):
        return normalize_case_status(value)

    model_config = {"from_attributes": True}
