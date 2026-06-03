from pydantic import BaseModel, Field

class FieldFilter(BaseModel):
    field: str
    operator: str = "eq"
    value: str | int | float | bool | None = None


class SearchFilters(BaseModel):
    artifact_type: list[str] = Field(default_factory=list)
    artifact_name: list[str] = Field(default_factory=list)
    event_category: list[str] = Field(default_factory=list)
    event_type: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    host: list[str] = Field(default_factory=list)
    user: list[str] = Field(default_factory=list)
    parser: list[str] = Field(default_factory=list)
    parser_backend: list[str] = Field(default_factory=list)
    backend_variant: list[str] = Field(default_factory=list)
    source_file: list[str] = Field(default_factory=list)
    exclude_artifact_type: list[str] = Field(default_factory=list)
    exclude_host: list[str] = Field(default_factory=list)
    exclude_user: list[str] = Field(default_factory=list)
    exclude_parser: list[str] = Field(default_factory=list)
    exclude_source_file: list[str] = Field(default_factory=list)
    exclude_query: str = ""
    severity: list[str] = Field(default_factory=list)
    evidence_id: list[str] = Field(default_factory=list)
    has_timestamp: bool | None = None
    time_from: str | None = None
    time_to: str | None = None
    event_id: list[str] = Field(default_factory=list)
    activity: list[str] = Field(default_factory=list)
    deleted_only: bool | None = None
    in_use_only: bool | None = None
    has_path: bool | None = None
    suspicious_paths_only: bool | None = None
    extension: list[str] = Field(default_factory=list)


class SearchRequest(BaseModel):
    case_id: str | None = None
    query: str = ""
    search_mode: str = "smart"
    filters: SearchFilters = Field(default_factory=SearchFilters)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)
    include_undated: bool = False
    include_low_value: bool = False
    include_low_confidence_timestamps: bool = False
    include_filesystem_timeline: bool = False
    sort_by: str = "@timestamp"
    sort_order: str = "desc"
    timezone: str | None = None


class SearchResponse(BaseModel):
    total: int
    total_relation: str = "eq"
    has_more: bool = False
    page: int
    page_size: int
    total_pages: int
    total_pages_visible: int = 0
    deep_pagination_supported: bool = False
    result_window_limit: int = 10000
    has_more_beyond_window: bool = False
    result_profile: dict = Field(default_factory=dict)
    items: list[dict]


class SiemRequest(BaseModel):
    case_id: str | None = None
    mode: str = "query_string"
    query: str = "*"
    dsl: dict | None = None
    timezone: str | None = None
    time_from: str | None = None
    time_to: str | None = None
    filters: list[FieldFilter] = Field(default_factory=list)
    page: int = 1
    page_size: int = Field(default=100, ge=1, le=200)
    sort_by: str = "@timestamp"
    sort_order: str = "desc"
