from pydantic import BaseModel, Field


class ForensicActivity(BaseModel):
    id: str
    activity_type: str
    title: str
    timestamp: str | None = None
    host: str | None = None
    user: str | None = None
    summary: str
    severity: str = "info"
    confidence: float = 0.5
    tags: list[str] = Field(default_factory=list)
    key_fields: dict = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    related_events: list[str] = Field(default_factory=list)
    suspicious_reasons: list[str] = Field(default_factory=list)
