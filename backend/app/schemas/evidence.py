from datetime import datetime

from pydantic import BaseModel, model_validator

from app.models.evidence import EvidenceStorageMode, EvidenceType, IngestStatus, resolve_public_evidence_type


class EvidenceRead(BaseModel):
    id: str
    case_id: str
    original_filename: str
    stored_path: str
    original_path: str | None
    storage_mode: EvidenceStorageMode
    is_external: bool
    copy_to_storage: bool
    evidence_type: EvidenceType
    sha256: str
    size_bytes: int
    file_count: int | None
    ingest_status: IngestStatus
    display_status: str | None = None
    investigation_ready: bool = False
    searchable_documents_count: int = 0
    status_reason: str | None = None
    warning_count: int = 0
    error_count: int = 0
    last_successful_ingest_run_id: str | None = None
    provided_host: str | None = None
    detected_host: str | None
    detected_user: str | None
    source_tool: str | None
    path_validation: dict
    ingest_source: dict
    metadata_json: dict
    ingest_metadata: dict = {}
    parser_errors: list = []
    bulk_index_errors: list = []
    error_log: dict
    created_at: datetime
    processed_at: datetime | None

    model_config = {"from_attributes": True}

    @model_validator(mode="before")
    @classmethod
    def _populate_ingest_helpers(cls, value):
        if isinstance(value, dict):
            data = dict(value)
        else:
            data = {field: getattr(value, field, None) for field in cls.model_fields.keys() if hasattr(value, field)}
        metadata = dict(data.get("metadata_json") or {})
        error_log = dict(data.get("error_log") or {})
        data["provided_host"] = str(metadata.get("provided_host") or "").strip() or None
        data["display_status"] = str(metadata.get("display_status") or "").strip() or None
        data["investigation_ready"] = bool(metadata.get("investigation_ready"))
        data["searchable_documents_count"] = int(metadata.get("searchable_documents_count") or metadata.get("events_indexed") or 0)
        data["status_reason"] = str(metadata.get("status_reason") or "").strip() or None
        problematic_summary = metadata.get("problematic_artifacts_summary") if isinstance(metadata.get("problematic_artifacts_summary"), dict) else {}
        data["warning_count"] = int(
            metadata.get("warning_count")
            if metadata.get("warning_count") is not None
            else problematic_summary.get("indexed_with_warning")
            if problematic_summary
            else len(metadata.get("warnings") or [])
        )
        data["error_count"] = int(
            metadata.get("error_count")
            if metadata.get("error_count") is not None
            else problematic_summary.get("data_loss_expected_count")
            if problematic_summary
            else len(error_log.get("errors") or [])
        )
        data["last_successful_ingest_run_id"] = str(metadata.get("last_successful_ingest_run_id") or "").strip() or None
        data["evidence_type"] = resolve_public_evidence_type(
            data.get("evidence_type"),
            source_tool=data.get("source_tool"),
            metadata=metadata,
        )
        data["ingest_metadata"] = metadata
        parser_errors = error_log.get("errors") if isinstance(error_log.get("errors"), list) else []
        data["parser_errors"] = parser_errors
        data["bulk_index_errors"] = [item for item in parser_errors if "bulk" in str(item).lower() or "opensearch" in str(item).lower()]
        return data


class EvidenceRunRead(BaseModel):
    run_id: str
    run_type: str
    mode: str | None = None
    status: str
    phase: str | None = None
    progress: int | float | None = None
    current_artifact: str | None = None
    current_artifact_source: str | None = None
    artifact_progress: str | None = None
    artifacts_total: int | None = None
    artifacts_done: int | None = None
    artifacts_failed: int | None = None
    records_read: int | None = None
    records_indexed: int | None = None
    events_indexed: int | None = None
    records_per_sec: float | None = None
    tail_artifacts_total: int | None = None
    tail_artifacts_running: int | None = None
    tail_artifacts_queued: int | None = None
    tail_artifacts_completed: int | None = None
    tail_artifacts_failed: int | None = None
    tail_records_read: int | None = None
    tail_records_indexed: int | None = None
    tail_last_progress_at: str | None = None
    tail_records_per_sec: float | None = None
    tail_current_artifacts: list = []
    tail_slowest_artifacts: list = []
    tail_elapsed_seconds: float | None = None
    heartbeat_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_seconds: float | None = None
    last_error: str | None = None
    warnings: list = []
    selected_by_artifact_type: dict = {}
    selected_by_parser: dict = {}
    parsed_by_artifact_type: dict = {}
    failed_artifacts_count: int | None = None
    retry_profile: dict = {}
    items: list = []


class EvidenceRunQueuedResponse(BaseModel):
    accepted: bool = True
    evidence_id: str
    run_id: str
    status: str
    mode: str


class EvidenceBenchmarkRead(BaseModel):
    benchmark_id: str
    evidence_id: str
    case_id: str
    run_id: str | None = None
    label: str | None = None
    notes: str | None = None
    mode: str
    profile: str
    status: str
    requested_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    phase: str | None = None
    current_action: str | None = None
    current_selected_path: str | None = None
    last_progress_at: str | None = None
    last_progress_seconds_ago: float | None = None
    current_phase_stalled: bool | None = None
    stalled_phase_warning: str | None = None
    effective_parallelism: int | None = None
    effective_cpu_count: int | None = None
    memory_limit_source: str | None = None
    source_evidence_name: str | None = None
    total_duration_seconds: float | None = None
    time_to_first_artifact_ready: float | None = None
    time_to_first_parse_start: float | None = None
    time_to_first_event_indexed: float | None = None
    extracting_selected_seconds: float | None = None
    materialization_seconds: float | None = None
    parsing_seconds: float | None = None
    indexing_seconds: float | None = None
    db_seconds: float | None = None
    finalizer_seconds: float | None = None
    debug_export_seconds: float | None = None
    records_read: int | None = None
    records_indexed: int | None = None
    events_indexed: int | None = None
    artifacts_total: int | None = None
    selected_total: int | None = None
    artifacts_completed: int | None = None
    artifacts_failed: int | None = None
    artifacts_created_for_run: int | None = None
    artifacts_processed_for_run: int | None = None
    artifacts_failed_for_run: int | None = None
    problematic_count: int | None = None
    records_per_sec: float | None = None
    events_per_sec: float | None = None
    artifacts_per_sec: float | None = None
    metadata_opensearch_delta: int | None = None
    stale_data_error_seen: bool | None = None
    unique_violation_seen: bool | None = None
    timeout_count: int | None = None
    slow_artifacts_count: int | None = None
    phase_timings: list = []
    resource_samples: list = []
    by_parser: dict = {}
    bottleneck_report: dict = {}
    benchmark_options: dict = {}
    autopilot_enabled: bool | None = None
    attempts: list = []
    current_attempt: int | None = None
    watchdog_status: str | None = None
    last_watchdog_check_at: str | None = None
    watchdog_actions: list = []
    final_recommendation: str | None = None


class EvidenceBenchmarkQueuedResponse(BaseModel):
    accepted: bool = True
    benchmark_id: str
    evidence_id: str
    run_id: str
    status: str
    mode: str
    profile: str


class ArtifactRead(BaseModel):
    id: str
    case_id: str
    evidence_id: str
    name: str
    artifact_type: str
    source_path: str
    parser: str
    record_count: int
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}
