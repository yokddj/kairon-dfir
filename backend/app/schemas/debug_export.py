from pydantic import BaseModel, Field

from app.schemas.event import SearchRequest


class DebugExportRequest(BaseModel):
    scope: str = Field(default="case")
    evidence_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    artifact_types: list[str] = Field(default_factory=list)
    include_raw_samples: bool = False
    include_raw_xml: bool = False
    include_source_paths: bool = True
    include_full_raw: bool = False
    max_events_per_type: int = Field(default=25, ge=1, le=250)
    max_field_length: int = Field(default=2000, ge=200, le=20000)
    redact_secrets: bool = True
    include_cached_semiauto: bool = True
    rebuild_semiauto_for_export: bool = False
    ui_context: dict = Field(default_factory=dict)
    search_request: SearchRequest | None = None
