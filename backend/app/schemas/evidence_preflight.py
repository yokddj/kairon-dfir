from pydantic import BaseModel


class PreflightClassification(BaseModel):
    category: str
    format_key: str | None = None
    confidence: str
    reason: str
    chain: list[str] = []
    platform: str
    hostname: str | None = None
    distro: str | None = None
    version: str | None = None
    volumes: int | None = None
    installations: int | None = None
    expected_parsers: list[str] = []
    warnings: list[str] = []


class PreflightResourceCheck(BaseModel):
    file_size_bytes: int
    compressed_size_bytes: int | None = None
    estimated_extracted_bytes: int | None = None
    estimated_temp_storage_bytes: int | None = None
    estimated_final_size_bytes: int | None = None
    estimated_processing_seconds: int | None = None
    estimated_artifact_count: int | None = None
    detected_archive_depth: int | None = None
    detected_backing_chain_depth: int | None = None
    available_disk_space_bytes: int
    configured_upload_limit_bytes: int
    configured_extraction_limit_bytes: int
    configured_archive_depth_limit: int
    configured_backing_chain_limit: int
    temp_directory: str


class PreflightStatusCheck(BaseModel):
    label: str
    ok: bool
    detail: str


class PreflightDiagnostic(BaseModel):
    problem: str
    reason: str
    current_configuration: dict[str, str] = {}
    required_configuration: dict[str, str] = {}
    configuration_key: str | None = None
    configuration_file: str | None = None
    how_to_fix: list[str] = []


class PreflightReport(BaseModel):
    token: str
    original_filename: str
    classification: PreflightClassification
    pipeline_preview: list[str]
    resource_check: PreflightResourceCheck
    status: str  # "ready" | "warning" | "blocked"
    status_checks: list[PreflightStatusCheck]
    diagnostics: list[PreflightDiagnostic] = []
