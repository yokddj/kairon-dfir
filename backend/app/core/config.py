from functools import lru_cache
from pathlib import Path
import re

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_version: str = "0.1.0"
    app_vendor_id: str = "yokddj"
    app_build_channel: str = "evaluation"
    app_build_fingerprint: str = "kairon-dfir-evaluation"

    postgres_db: str = "dfir"
    postgres_user: str = "dfir"
    postgres_password: str = "dfir"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    redis_url: str = "redis://redis:6379/0"

    opensearch_host: str = "opensearch"
    opensearch_port: int = 9200
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    opensearch_ssl: bool = False
    opensearch_verify_certs: bool = False
    opensearch_index_prefix: str = "dfir-events"
    opensearch_memory_index_prefix: str = "dfir-memory"
    opensearch_dashboards_internal_url: str = "http://opensearch-dashboards:5601"
    opensearch_dashboards_public_url: str = "http://localhost:5601"
    opensearch_dashboards_username: str | None = None
    opensearch_dashboards_password: str | None = None
    opensearch_dashboards_index_pattern: str = "dfir-events-*"
    opensearch_dashboards_time_field: str = "@timestamp"
    opensearch_dashboards_enabled: bool = True
    dfir_auto_bootstrap_dashboards: bool = True
    report_brand_name: str = "Kairon DFIR"
    report_brand_subtitle: str = "Digital Forensics & Incident Response"
    report_brand_primary_color: str = "#0f172a"
    report_include_logo: bool = False
    report_logo_path: str = ""

    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    backend_cors_origins: str = "*"
    backend_cors_origin_regex: str = r".*"
    backend_max_upload_size: int = Field(default=2147483648)
    memory_analysis_enabled: bool = False
    volatility3_command: str = "vol"
    memprocfs_command: str = "memprocfs"
    memory_tools_auto_install_enabled: bool = False
    memory_allow_external_tool_execution: bool = False
    memory_backend_check_timeout_seconds: int = 10
    memory_backend_status_cache_seconds: int = 60
    memory_preferred_backend: str = "volatility3"
    memory_max_upload_size: int = 2147483648
    memory_job_timeout_seconds: int = 900
    memory_plugin_timeout_seconds: int = 600
    memory_plugin_output_max_bytes: int = 10485760
    memory_worker_concurrency: int = 1
    memory_allowed_plugins: str = "windows.info"
    memory_raw_output_retention_enabled: bool = True
    memory_symbol_network_access_enabled: bool = False
    backend_multipart_max_files: int = 10000
    backend_multipart_max_fields: int = 20000
    backend_multipart_max_part_size: int = 1048576
    backend_enable_experimental_folder_upload: bool = False
    backend_experimental_folder_upload_max_files: int = 2000
    backend_experimental_folder_upload_max_total_bytes: int = 2147483648
    backend_max_extracted_files: int = 50000
    backend_max_extracted_bytes: int = 10737418240
    backend_data_dir: Path = Path("/app/data")
    backend_temp_dir: Path = Path("/app/data/tmp")
    backend_log_level: str = "INFO"
    auto_create_heuristic_detections: bool = True
    mft_fast_path: bool = True
    ingest_batch_size: int = 1000
    ingest_job_timeout_seconds: int = 10800
    artifact_retry_job_timeout_seconds: int = 10800
    opensearch_bulk_docs: int = 1000
    opensearch_bulk_bytes: int = 10485760
    evtx_artifact_max_seconds: int = 180
    evtx_artifact_stall_seconds: int = 45
    evtx_long_tail_warning_seconds: int = 900
    evtx_no_progress_stall_seconds: int = 600
    evtx_max_active_runtime_seconds: int = 3600
    evtx_defer_after_seconds: int = 3600
    evtx_min_progress_delta_records: int = 100
    evtx_fast_max_records_per_file: int = 5000
    evtx_fast_max_seconds_per_file: int = 120
    evtx_fast_max_total_records: int = 25000
    evtx_fast_max_total_seconds: int = 600
    evtx_parser_backend: str = "auto"
    evtxecmd_executable: str = ""
    evtxecmd_dotnet_dll: str = "/opt/evtxecmd/EvtxECmd.dll"
    evtxecmd_timeout_seconds: int = 0
    mftecmd_dotnet_dll: str = "/opt/eztools/MFTECmd/MFTECmd.dll"
    mftecmd_timeout_seconds: int = 0
    srumecmd_dotnet_dll: str = "/opt/eztools/SrumECmd/SrumECmd.dll"
    srumecmd_timeout_seconds: int = 0
    mft_summary_max_records: int = 10000
    mft_summary_max_seconds: int = 1800
    opensearch_java_heap: str = "2g"
    backend_uvicorn_workers: int = 1
    max_parallel_artifacts: int = 1
    max_parallel_rule_runs: int = 1
    rule_run_stale_after_minutes: int = 10
    sigma_max_matches_per_rule: int = 5000
    sigma_max_detections_per_rule: int = 1000
    sigma_noisy_rule_threshold: int = 10000
    search_default_page_size: int = 50
    search_max_page_size: int = 200
    yara_max_file_size_mb: int = 100
    yara_scan_originals: bool = False
    yara_scan_extracted: bool = True
    yara_scan_raw_evidence: bool = True
    yara_scan_parsed_outputs: bool = False
    yara_scan_archives: bool = False
    yara_scan_text_outputs: bool = False
    dfir_allow_host_path_import: bool = False
    dfir_allowed_evidence_roots: str = "/mnt/evidence,/data/evidence,/cases"
    dfir_enable_demo_cases: bool = False
    dfir_enable_validation_features: bool = False
    dfir_default_case_mode: str = "investigation"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins(self) -> list[str]:
        value = self.backend_cors_origins.strip()
        if value == "*":
            return ["*"]
        return [origin.strip() for origin in value.split(",") if origin.strip()]

    @property
    def cors_origin_regex(self) -> str | None:
        value = self.backend_cors_origin_regex.strip()
        if not value:
            return None
        re.compile(value)
        return value

    @property
    def allow_host_path_import(self) -> bool:
        return bool(self.dfir_allow_host_path_import)

    @property
    def demo_cases_enabled(self) -> bool:
        return bool(self.dfir_enable_demo_cases)

    @property
    def validation_features_enabled(self) -> bool:
        return bool(self.dfir_enable_validation_features)

    @property
    def default_case_mode(self) -> str:
        mode = str(self.dfir_default_case_mode or "investigation").strip().lower()
        if mode in {"investigation", "demo", "training", "validation"}:
            return mode
        return "investigation"

    @property
    def preferred_memory_backend(self) -> str | None:
        backend = str(self.memory_preferred_backend or "").strip().lower()
        if backend in {"volatility3", "memprocfs"}:
            return backend
        return "volatility3"

    @property
    def allowed_memory_plugins(self) -> list[str]:
        values = self.memory_allowed_plugins
        if isinstance(values, str):
            plugins = [item.strip() for item in values.split(",") if item.strip()]
        else:
            plugins = [str(item).strip() for item in values if str(item).strip()]
        return [plugin for plugin in plugins if plugin == "windows.info"] or ["windows.info"]

    @property
    def allowed_evidence_roots(self) -> list[Path]:
        roots: list[Path] = []
        for value in self.dfir_allowed_evidence_roots.split(","):
            candidate = value.strip()
            if not candidate:
                continue
            roots.append(Path(candidate))
        return roots

    @property
    def build_notice(self) -> str:
        return "Internal evaluation build. Redistribution not authorized without permission."

    @property
    def build_identity(self) -> dict[str, str]:
        return {
            "app_version": self.app_version,
            "vendor_id": self.app_vendor_id,
            "build_channel": self.app_build_channel,
            "build_fingerprint": self.app_build_fingerprint,
            "notice": self.build_notice,
        }


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.backend_data_dir.mkdir(parents=True, exist_ok=True)
    settings.backend_temp_dir.mkdir(parents=True, exist_ok=True)
    (settings.backend_data_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (settings.backend_data_dir / "tmp").mkdir(parents=True, exist_ok=True)
    return settings
