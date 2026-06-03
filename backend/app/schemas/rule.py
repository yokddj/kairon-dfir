from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.rule import RuleEngine
from app.models.rule_import_run import RuleImportRunStatus
from app.models.rule_run import RuleRunStatus


class RuleCreate(BaseModel):
    case_id: str | None = None
    name: str
    title: str | None = None
    engine: RuleEngine
    namespace: str | None = None
    source: str | None = None
    description: str | None = None
    author: str | None = None
    rule_version: str | None = None
    level: str | None = None
    content: str
    enabled: bool = True
    severity: str | None = None
    status: str = "valid"
    references: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    metadata_json: dict = Field(default_factory=dict)


class RuleUpdate(BaseModel):
    case_id: str | None = None
    name: str | None = None
    title: str | None = None
    engine: RuleEngine | None = None
    namespace: str | None = None
    source: str | None = None
    description: str | None = None
    author: str | None = None
    rule_version: str | None = None
    level: str | None = None
    content: str | None = None
    enabled: bool | None = None
    severity: str | None = None
    status: str | None = None
    references: list[str] | None = None
    false_positives: list[str] | None = None
    tags: list[str] | None = None
    mitre: list[str] | None = None
    validation_errors: list[str] | None = None
    metadata_json: dict | None = None


class RuleRead(BaseModel):
    id: str
    case_id: str | None
    rule_set_id: str | None
    name: str
    title: str | None
    engine: RuleEngine
    namespace: str | None
    source: str | None
    description: str | None
    author: str | None
    rule_version: str | None
    level: str | None
    content: str
    content_hash: str | None
    enabled: bool
    severity: str | None
    status: str
    references: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    tags: list[str]
    mitre: list[str] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleRunRead(BaseModel):
    id: str
    rule_id: str | None
    rule_set_id: str | None
    case_id: str
    evidence_id: str | None
    engine: str
    status: RuleRunStatus
    scope: str = "case"
    matched: int
    total_rules: int = 0
    processed_rules: int = 0
    total_events: int = 0
    scanned_events: int = 0
    total_files: int = 0
    created_detections: int
    duplicates: int
    scanned_files: int
    skipped_files: int
    current_phase: str | None = None
    heartbeat_at: str | None = None
    last_error: str | None = None
    cancel_requested: bool = False
    retried_from_run_id: str | None = None
    stale_reason: str | None = None
    elapsed_seconds: int | None = None
    percent_complete: float | None = None
    stale: bool = False
    can_cancel: bool = False
    can_retry: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list = Field(default_factory=list)
    metadata_json: dict = Field(default_factory=dict)
    started_at: str | None
    finished_at: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleEngineStatusRead(BaseModel):
    available: bool
    runs_on: str
    supported: str | None = None
    supports_rule_packs: bool | None = None
    scan_extracted: bool | None = None
    scan_originals: bool | None = None
    max_file_size_mb: int | None = None
    error: str | None = None


class DetectionRead(BaseModel):
    id: str
    case_id: str
    evidence_id: str | None
    artifact_id: str | None
    rule_id: str | None
    rule_set_id: str | None
    engine: str
    source_engine: str | None
    rule_name: str
    rule_title: str | None
    rule_version: str | None
    rule_author: str | None
    rule_level: str | None
    severity: str | None
    confidence: float | None
    event_id: str | None
    event_index: str | None
    opensearch_id: str | None
    target_type: str
    target_path: str | None
    matched_at: str | None
    matched_file_hash: str | None
    matched_process_node_id: str | None
    host_name: str | None
    message: str | None
    status: str
    analyst_note: str | None = None
    matched_fields: dict = Field(default_factory=dict)
    matched_strings: list = Field(default_factory=list)
    condition_summary: str | None = None
    description: str | None = None
    false_positives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)
    related_iocs: dict = Field(default_factory=dict)
    risk_score: float | None = None
    dedup_fingerprint: str | None = None
    engine_version: str | None = None
    data_quality: list[str] = Field(default_factory=list)
    raw: dict
    rule_run_id: str | None = None
    rule_import_run_id: str | None = None
    rule_source_pack: str | None = None
    orphaned_rule: bool = False
    created_at: datetime
    deleted_at: datetime | None = None
    archived_at: datetime | None = None

    model_config = {"from_attributes": True}


class DetectionUpdate(BaseModel):
    status: str | None = None
    confidence: float | None = None
    analyst_note: str | None = None


class DetectionBulkRequest(BaseModel):
    detection_ids: list[str] = Field(default_factory=list)
    action: str
    case_id: str | None = None
    engine: str | None = None
    severity: str | None = None
    status: str | None = None
    rule_name: str | None = None
    evidence_id: str | None = None
    has_linked_event: bool | None = None
    has_file_target: bool | None = None


class DetectionBulkFilterSet(BaseModel):
    case_id: str | None = None
    source: str | None = None
    engine: str | None = None
    rule_id: str | None = None
    rule_run_id: str | None = None
    import_run_id: str | None = None
    source_pack: str | None = None
    severity: str | None = None
    status: str | None = None
    rule_name: str | None = None
    evidence_id: str | None = None
    host: str | None = None
    user: str | None = None
    artifact_type: str | None = None
    source_file: str | None = None
    matched_object_type: str | None = None
    q: str | None = None
    has_linked_event: bool | None = None
    has_file_target: bool | None = None
    created_from: str | None = None
    created_to: str | None = None
    orphaned_only: bool | None = None
    run_type: str | None = None


class DetectionBulkPreviewRequest(BaseModel):
    mode: str = "selected"
    detection_ids: list[str] = Field(default_factory=list)
    filters: DetectionBulkFilterSet = Field(default_factory=DetectionBulkFilterSet)
    case_id: str | None = None
    rule_run_id: str | None = None
    rule_id: str | None = None
    import_run_id: str | None = None
    source_pack: str | None = None


class DetectionBulkActionRequestV2(BaseModel):
    action: str | None = None
    mode: str = "selected"
    detection_ids: list[str] = Field(default_factory=list)
    filters: DetectionBulkFilterSet = Field(default_factory=DetectionBulkFilterSet)
    case_id: str | None = None
    rule_run_id: str | None = None
    rule_id: str | None = None
    import_run_id: str | None = None
    source_pack: str | None = None
    confirm: str | None = None


class DetectionBulkRuleBreakdown(BaseModel):
    rule_id: str | None = None
    title: str
    count: int


class DetectionBulkRunBreakdown(BaseModel):
    rule_run_id: str
    count: int


class DetectionBulkPreviewResponse(BaseModel):
    matched: int = 0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: list[DetectionBulkRuleBreakdown] = Field(default_factory=list)
    by_run: list[DetectionBulkRunBreakdown] = Field(default_factory=list)
    orphaned_rule_count: int = 0
    protected_count: int = 0
    warnings: list[str] = Field(default_factory=list)


class DetectionBulkActionResponse(BaseModel):
    matched: int = 0
    updated: int = 0
    deleted: int = 0
    skipped: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    activity_id: str | None = None


class RuleRunRequest(BaseModel):
    case_id: str
    evidence_id: str | None = None
    mode: str = "events"
    dry_run: bool = False
    include_parsed_outputs: bool | None = None
    include_archives: bool | None = None
    include_text_outputs: bool | None = None
    max_file_size_mb: int | None = None


class SigmaSmokeRequest(BaseModel):
    case_id: str
    evidence_id: str | None = None
    host: str | None = None
    mode: str = "single_rule"
    rule_id: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    severity: str | None = None
    logsource: str | None = None
    tag: str | None = None
    keyword: str | None = None
    max_rules: int = 5
    max_detections_per_rule: int = 10
    max_events_per_rule: int = 5000


class SigmaSmokeRuleResult(BaseModel):
    rule_id: str
    rule_name: str
    title: str | None = None
    severity: str | None = None
    status: str
    reason: str | None = None
    matched: int = 0
    created_detections: int = 0
    duplicates: int = 0
    scanned_events: int = 0
    expected_logsource: dict = Field(default_factory=dict)
    field_mappings: dict = Field(default_factory=dict)
    required_fields: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    sample_detection_ids: list[str] = Field(default_factory=list)
    sample_event_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SigmaSmokeResponse(BaseModel):
    run_id: str | None = None
    run_type: str = "smoke"
    case_id: str
    evidence_id: str | None = None
    host: str | None = None
    mode: str
    preflight_only: bool = False
    max_rules: int = 5
    max_detections_per_rule: int = 10
    rules_selected: int = 0
    matched: int = 0
    no_match: int = 0
    skipped: int = 0
    unsupported: int = 0
    errors: int = 0
    created_detections: int = 0
    field_mapping_explanation: bool = True
    rules: list[SigmaSmokeRuleResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RulesRunRequest(BaseModel):
    mode: str | None = None
    rule_types: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    enabled_only: bool = True
    engine: str | None = None
    severity: str | None = None
    namespace: str | None = None
    scope: str = "all"
    evidence_id: str | None = None
    host: str | None = None
    time_from: str | None = None
    time_to: str | None = None
    selected_paths: list[str] = Field(default_factory=list)
    force: bool = False
    search: str | None = None
    include_disabled: bool = False
    enabled: bool | None = None
    include_parsed_outputs: bool | None = None
    include_archives: bool | None = None
    include_text_outputs: bool | None = None
    max_file_size_mb: int | None = None
    run_mode: str | None = None


class RuleImportResponse(BaseModel):
    import_run_id: str | None = None
    status: str = "completed"
    engine: str = "unknown"
    summary: dict[str, Any] = Field(default_factory=dict)
    source_name: str | None = None
    source_type: str | None = None
    pack_name: str | None = None
    total_files: int = 0
    processed_files: int = 0
    total_rules_found: int = 0
    imported_count: int
    updated_count: int = 0
    duplicate_count: int = 0
    imported_rules: int = 0
    imported_rule_sets: int = 0
    total_yara_rules_inside: int = 0
    compiled_count: int = 0
    unsupported_condition_count: int = 0
    compile_error_count: int = 0
    invalid_count: int = 0
    unsupported_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    sigma_rules_by_product: dict[str, int] = Field(default_factory=dict)
    sigma_rules_by_category: dict[str, int] = Field(default_factory=dict)
    skipped_count: int
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    invalid_items: list[dict] = Field(default_factory=list)
    unsupported_items: list[dict] = Field(default_factory=list)
    detected_engine_counts: dict[str, int] = Field(default_factory=dict)
    sample_imported: list[str] = Field(default_factory=list)
    rules: list[RuleRead] = Field(default_factory=list)
    rule_sets: list["RuleSetSummaryRead"] = Field(default_factory=list)


class RuleImportRunRead(BaseModel):
    id: str
    case_id: str | None = None
    engine: str
    source_name: str | None = None
    source_type: str
    uploaded_filename: str | None = None
    pack_name: str | None = None
    status: RuleImportRunStatus
    started_at: str | None = None
    finished_at: str | None = None
    cancelled_at: str | None = None
    elapsed_seconds: float | None = None
    total_files: int = 0
    processed_files: int = 0
    total_rules_found: int = 0
    processed_rules: int = 0
    imported_count: int = 0
    updated_count: int = 0
    duplicate_count: int = 0
    skipped_count: int = 0
    invalid_count: int = 0
    compiled_count: int = 0
    unsupported_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_phase: str | None = None
    current_file: str | None = None
    last_error: str | None = None
    cancel_requested: bool = False
    warnings_summary: list = Field(default_factory=list)
    errors_summary: list = Field(default_factory=list)
    created_rule_ids: list[str] = Field(default_factory=list)
    updated_rule_ids: list[str] = Field(default_factory=list)
    duplicate_rule_ids: list[str] = Field(default_factory=list)
    invalid_items: list[dict] = Field(default_factory=list)
    unsupported_items: list[dict] = Field(default_factory=list)
    import_options: dict = Field(default_factory=dict)
    details_json: dict = Field(default_factory=dict)
    progress_pct: float | None = None
    is_terminal: bool = False
    files_per_sec: float | None = None
    rules_per_sec: float | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleImportRunListResponse(BaseModel):
    total: int
    items: list[RuleImportRunRead] = Field(default_factory=list)


class RuleListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: list[RuleRead]


class RuleRunResponse(BaseModel):
    rule_id: str | None = None
    rule_set_id: str | None = None
    engine: str
    case_id: str
    matched: int
    created_detections: int
    duplicates: int
    skipped: bool = False
    error: str | None = None
    status: str = "queued"
    run_id: str | None = None


class RuleBulkActionRequest(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    mode: str = "selected"
    engine: str | None = None
    namespace: str | None = None
    severity: str | None = None
    import_run_id: str | None = None
    source_pack: str | None = None
    enabled: bool | None = None
    scope: str = "all"
    case_id: str | None = None
    search: str | None = None
    confirm: str | None = None


class RuleBulkDeleteResponse(BaseModel):
    matched: int = 0
    deleted: int = 0
    disabled: int = 0
    skipped: int = 0
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    affected_packs: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RuleBulkUpdateResponse(BaseModel):
    matched: int = 0
    updated: int = 0
    enabled: bool
    skipped: int = 0
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RuleBulkPreviewResponse(BaseModel):
    matched: int = 0
    protected: int = 0
    affected_packs: list[str] = Field(default_factory=list)
    by_engine: dict[str, int] = Field(default_factory=dict)
    by_source_pack: dict[str, int] = Field(default_factory=dict)


class RuleSetBulkDeleteRequest(BaseModel):
    pack_ids: list[str] = Field(default_factory=list)
    engine: str | None = None
    namespace: str | None = None
    enabled: bool | None = None
    scope: str = "all"
    case_id: str | None = None
    search: str | None = None
    import_run_id: str | None = None
    source_pack: str | None = None
    mode: str = "selected"
    confirm: str | None = None


class RuleRunActionResponse(BaseModel):
    ok: bool = True
    run: RuleRunRead
    message: str


class RuleRunBulkDeleteRequest(BaseModel):
    run_ids: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    engine: str | None = None
    case_id: str | None = None
    older_than_minutes: int | None = None
    mode: str = "selected"


class RuleRunBulkActionRequest(BaseModel):
    run_ids: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    engine: str | None = None
    case_id: str | None = None
    older_than_minutes: int | None = None
    mode: str = "selected"


class RuleRunBulkActionResponse(BaseModel):
    matched: int = 0
    updated: int = 0
    deleted: int = 0
    skipped: int = 0
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    created_run_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RuleSetSummaryRead(BaseModel):
    id: str
    case_id: str | None
    name: str
    engine: RuleEngine
    namespace: str | None
    description: str | None
    source_filename: str | None
    content_path: str | None
    rules_count: int
    enabled: bool
    severity: str | None
    tags: list[str]
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleSetListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: list[RuleSetSummaryRead]


class RuleSetRead(RuleSetSummaryRead):
    content: str


RuleImportResponse.model_rebuild()
