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
    memory_upload_enabled: bool = False
    memory_upload_max_bytes: int = 2147483648
    memory_upload_chunk_size_bytes: int = 4194304
    memory_upload_staging_root: str = ""
    memory_upload_cleanup_age_seconds: int = 86400
    memory_upload_request_timeout_seconds: int = 0
    memory_upload_verification_timeout_seconds: int = 300
    memory_upload_finalization_timeout_seconds: int = 120
    memory_upload_stale_timeout_seconds: int = 900
    memory_upload_allowed_extensions: str = ".raw,.mem,.dmp,.dump,.bin,.img,.vmem,.lime"
    memory_job_timeout_seconds: int = 900
    memory_plugin_timeout_seconds: int = 600
    memory_plugin_output_max_bytes: int = 10485760
    memory_output_dir: str = ""
    memory_worker_mode: str = "external_command"
    memory_task_queue: str = "memory"
    memory_require_dedicated_worker: bool = True
    memory_worker_concurrency: int = 1
    memory_worker_uid: int = 10001
    memory_worker_gid: int = 10001
    memory_worker_container_name: str = "dfir_app-memory-worker-1"
    memory_evidence_shared_gid: int = 10001
    memory_allowed_plugins: str = (
        "windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,"
        "windows.netscan,windows.dlllist,windows.ldrmodules,windows.handles,"
        "windows.modules,windows.driverscan,windows.malfind"
    )
    memory_allowed_profiles: str = (
        "metadata_only,processes_basic,processes_extended,"
        "network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory"
    )
    memory_default_profile: str = "metadata_only"
    memory_process_profile_enabled: bool = False
    memory_max_process_rows: int = 100000
    memory_max_command_line_length: int = 16384
    memory_max_raw_field_length: int = 65536
    memory_raw_output_retention_enabled: bool = True
    memory_symbol_network_access_enabled: bool = False
    memory_symbol_mode: str = "offline_only"
    memory_symbol_managed_download_enabled: bool = False
    memory_symbol_allowed_hosts: str = ""
    memory_symbol_download_timeout_seconds: int = 180
    memory_symbol_connect_timeout_seconds: int = 15
    memory_symbol_max_redirects: int = 5
    memory_symbol_download_max_bytes: int = 1073741824
    memory_symbol_isf_max_bytes: int = 268435456
    memory_symbol_cache_max_bytes: int = 5368709120
    memory_symbol_cache_root: str = ""
    memory_symbol_download_concurrency: int = 1
    memory_symbol_task_queue: str = "memory-symbols"
    memory_symbol_partial_ttl_seconds: int = 86400
    memory_symbol_request_stale_seconds: int = 900
    memory_symbol_initial_host: str = "msdl.microsoft.com"
    memory_symbol_redirect_suffixes: str = ".blob.core.windows.net"
    # Egress gateway (symbol-fetcher -> symbol-egress-gateway -> Internet).
    # The fetcher never makes outbound connections except to the gateway.
    memory_symbol_egress_gateway_url: str = "http://symbol-egress-gateway:8443"
    memory_symbol_egress_gateway_secret: str = ""
    memory_symbol_egress_gateway_timeout_seconds: int = 60
    memory_symbol_egress_replay_window_seconds: int = 60
    memory_symbol_egress_max_response_bytes: int = 1073741824
    # Local-operator approval. Disabled by default.  When disabled, the CLI
    # refuses to approve requests.  This is an interim server-administrator
    # authorization mechanism, not a replacement for future application RBAC.
    memory_symbol_local_approval_enabled: bool = False
    memory_symbol_approval_ttl_seconds: int = 600
    memory_symbol_approval_single_use: bool = True
    # This is deliberately separate from feature enablement.  It may only be
    # true when deployment-level egress enforcement has been independently
    # verified; application URL checks are not a network sandbox.
    memory_symbol_network_isolation_ready: bool = False
    # Kairon does not currently provide authenticated administrator roles.
    # Keep the mutation unavailable until that control exists.
    memory_symbol_admin_authorization_enforced: bool = False
    memory_symbol_admin_authorization_required: bool = True
    # Automatic Windows symbol resolution: auto-probe on upload and
    # auto-acquire (managed, server-side) when the cache misses.
    # Both default to FALSE in the v1 stabilization sprint so the
    # minimal critical path is preserved.  When the operator
    # enables MEMORY_AUTO_PREPARATION the symbol probe and
    # acquisition are turned back on.
    memory_auto_symbol_probe: bool = True
    memory_auto_symbol_acquire: bool = False
    # Master switch for the entire post-registration automation
    # pipeline (probe, content identity, symbol preparation
    # enqueue, OpenSearch initialization, active-result
    # materialization).  When False, the memory upload lifecycle
    # only registers the Evidence row and never schedules
    # background work as part of the critical path.
    memory_auto_preparation: bool = True
    # Run all (sequential profile batch) is enabled in the v1
    # stabilization sprint.  The UI only exposes the action when
    # the evidence preparation is "ready" (effective_state=ready);
    # for non-ready evidences the per-profile Run actions remain
    # the only way to execute a memory profile.
    memory_run_all_enabled: bool = True
    # How long a preparation row may stay in queued / probing /
    # acquiring before reconciliation considers it stale.  The
    # reconciliation is gated by facts (a successful metadata run
    # always wins) but this threshold is the last-resort safety
    # net for queues that never produced a heartbeat.
    memory_preparation_stale_seconds: int = 600
    # Cap on concurrent managed acquisitions (per backend process).
    memory_symbol_max_concurrent_acquisitions: int = 1
    # How many times a single preparation can fail before it goes
    # into the "unsupported" terminal state.  The negative cache
    # also has a TTL below.
    memory_symbol_acquisition_retry_limit: int = 2
    # Negative cache TTL for symbols that the configured source
    # does not provide.  During this window the system will not
    # retry the acquisition.
    memory_symbol_negative_cache_ttl_seconds: int = 86400
    # How often the global reconciliation pass may run (seconds).
    memory_symbol_reconcile_interval_seconds: int = 300

    # --- Exact Symbol Recovery Sources v1 ---
    # Manual import: enabled only when an administrator is ready
    # to receive operator-supplied PDBs / ISFs / packages.  The
    # front-end does not control this; only server-side config.
    memory_symbol_manual_import_enabled: bool = False
    # Corporate / SymProxy source: enabled only when the operator
    # has configured at least one source row in
    # ``memory_symbol_recovery_sources``.  This flag is the master
    # switch.
    memory_symbol_corporate_source_enabled: bool = False
    # Allow automatic fallback across recovery sources.  When
    # ``False`` the orchestrator stops at the first failure; the
    # operator must explicitly re-trigger recovery.
    memory_symbol_automatic_fallback_enabled: bool = False
    # Maximum bytes for an administrator-uploaded PDB.
    memory_symbol_pdb_upload_max_bytes: int = 536870912  # 512 MiB
    # Maximum bytes for an administrator-uploaded ISF (JSON or
    # JSON.xz).
    memory_symbol_isf_upload_max_bytes: int = 268435456  # 256 MiB
    # Maximum bytes for an offline symbol package archive.
    memory_symbol_package_max_bytes: int = 1073741824  # 1 GiB
    # Maximum total uncompressed bytes the package extractor will
    # emit (zip-bomb protection).
    memory_symbol_package_extract_max_bytes: int = 5368709120  # 5 GiB
    # Maximum number of files in a single offline package.
    memory_symbol_package_max_files: int = 100
    # Allowed file extensions in an offline package.  No
    # executables, no scripts.
    memory_symbol_package_allowed_extensions: str = ".pdb,.isf,.json,.xz"
    # Quarantine directory for administrator imports.  Defaults
    # to ``<backend_temp_dir>/symbol-import-quarantine``.
    memory_symbol_import_quarantine_root: str = ""
    # Corporate symbol server connect/read timeouts.
    memory_symbol_corporate_connect_timeout_seconds: int = 15
    memory_symbol_corporate_read_timeout_seconds: int = 120

    # --- Hardening v1: explicit feature gates ---
    # The Kairon application does not currently provide a mature
    # authenticated administrator role.  Every administrative
    # recovery endpoint (manual PDB/ISF/package import, corporate
    # source configuration, recovery orchestration for non-Microsoft
    # sources) is gated on ``memory_symbol_admin_recovery_enabled``,
    # which defaults to ``False``.  When the flag is ``False`` the
    # endpoints return 404 (not 403) so the existence of the
    # feature is not advertised to untrusted callers.
    memory_symbol_admin_recovery_enabled: bool = False
    # Hard cap on the number of objects in a parsed ISF.  Defends
    # against maliciously nested JSON.
    memory_symbol_isf_max_objects: int = 200000
    # Hard cap on the maximum nesting depth of a parsed ISF.
    memory_symbol_isf_max_depth: int = 32
    # Hard cap on the maximum length of any string in the ISF.
    memory_symbol_isf_max_string_bytes: int = 1_048_576  # 1 MiB
    # Hard cap on the maximum number of keys in any object.
    memory_symbol_isf_max_object_keys: int = 10000
    # Hard cap on the maximum length of any array.
    memory_symbol_isf_max_array_length: int = 100000
    backend_multipart_max_files: int = 10000
    backend_multipart_max_fields: int = 20000
    backend_multipart_max_part_size: int = 1048576
    backend_enable_experimental_folder_upload: bool = False
    backend_experimental_folder_upload_max_files: int = 2000
    backend_experimental_folder_upload_max_total_bytes: int = 2147483648
    # Experimental Mismatched-Symbol Analysis v1.  When ``False``
    # (the default) the experimental endpoints return 404, the
    # operator CLI refuses to create candidates, and no
    # ``MemoryExperimentalSymbolCandidate`` / ``MemoryExperimentalRun``
    # rows can be created.  The flag is the single authoritative
    # switch for the entire trust domain boundary.
    memory_symbol_experimental_mismatch_enabled: bool = False
    # Worker queue for experimental analysis tasks.  Isolated from
    # the validated memory queue so experimental work cannot starve
    # validated analysis.
    memory_experimental_task_queue: str = "memory-experimental"
    # OpenSearch index prefix for the experimental results.  The
    # full index name is ``{prefix}-{case_id}``.
    opensearch_memory_experimental_index_prefix: str = "dfir-memory-experimental"
    # Per-run timeout (seconds) for the experimental canary and
    # full-run profile dispatch.  Defaults are conservative
    # ceilings; the worker task timeouts override them.
    memory_experimental_canary_timeout_seconds: int = 600
    memory_experimental_run_timeout_seconds: int = 3600
    # Acknowledgement contract.  The frontend must echo the
    # warning text verbatim.  The default is the canonical
    # "experimental-mismatch-ack-v1" string.
    memory_experimental_ack_warning_version: str = "experimental-mismatch-ack-v1"
    # Volatility-native compatibility probe.  When a Windows
    # requirement is blocked because the internal PDB parser reports
    # an age mismatch, the native probe runs the pinned Volatility
    # engine to test whether the symbol material is actually usable.
    # If Volatility succeeds, normal validated analysis can proceed
    # with readiness reason ``VOLATILITY_NATIVE_SYMBOL_COMPATIBLE``.
    memory_native_probe_enabled: bool = False
    memory_native_probe_timeout_seconds: int = 600
    memory_native_probe_max_output_bytes: int = 10485760
    memory_native_probe_plugin: str = "windows.pslist.PsList"
    memory_native_probe_malformed_row_ratio: float = 0.5
    memory_native_probe_min_process_rows: int = 3
    memory_native_probe_cache_root: str = "/volatility-cache/volatility3"
    memory_native_probe_task_queue: str = "memory-native-probe"
    memory_native_probe_stale_seconds: int = 900
    memory_native_probe_worker_concurrency: int = 1

    @property
    def memory_native_probe_cache_path(self) -> Path:
        value = str(self.memory_native_probe_cache_root or "").strip()
        return Path(value) if value else Path("/volatility-cache/volatility3")

    @property
    def memory_native_probe_queue_name(self) -> str:
        value = str(self.memory_native_probe_task_queue or "memory-native-probe").strip()
        return value if value else "memory-native-probe"
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
        allowed = {
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.psscan",
            "windows.cmdline",
            "windows.netscan",
            "windows.dlllist",
            "windows.ldrmodules",
            "windows.handles",
            "windows.modules",
            "windows.driverscan",
            "windows.malfind",
        }
        values = self.memory_allowed_plugins
        if isinstance(values, str):
            plugins = [item.strip() for item in values.split(",") if item.strip()]
        else:
            plugins = [str(item).strip() for item in values if str(item).strip()]
        return [plugin for plugin in plugins if plugin in allowed] or ["windows.info"]

    @property
    def allowed_memory_profiles(self) -> list[str]:
        allowed = {
            "metadata_only",
            "processes_basic",
            "processes_extended",
            "network_basic",
            "modules_basic",
            "handles_basic",
            "kernel_basic",
            "suspicious_memory",
        }
        profiles = [item.strip() for item in str(self.memory_allowed_profiles or "").split(",") if item.strip()]
        return [profile for profile in profiles if profile in allowed] or ["metadata_only"]

    @property
    def default_memory_profile(self) -> str:
        profile = str(self.memory_default_profile or "metadata_only").strip()
        return profile if profile in self.allowed_memory_profiles else "metadata_only"

    @property
    def memory_execution_mode(self) -> str:
        mode = str(self.memory_worker_mode or "external_command").strip().lower()
        return mode if mode in {"external_command", "dedicated_worker"} else "external_command"

    @property
    def memory_queue_name(self) -> str:
        value = str(self.memory_task_queue or "memory").strip()
        if not value or any(token in value for token in " ;&|`$<>\n\r/\\"):
            return "memory"
        return value

    @property
    def memory_experimental_queue_name(self) -> str:
        value = str(self.memory_experimental_task_queue or "memory-experimental").strip()
        if not value or any(token in value for token in " ;&|`$<>\n\r/\\"):
            return "memory-experimental"
        return value

    @property
    def opensearch_memory_experimental_index(self) -> str:
        """Default case-shared index for experimental results.

        A per-case index is created on demand by
        ``ensure_memory_experimental_index(case_id)``.  The
        prefix is shared with all per-case indices.
        """
        return str(self.opensearch_memory_experimental_index_prefix or "dfir-memory-experimental")

    @property
    def memory_output_root(self) -> Path | None:
        value = str(self.memory_output_dir or "").strip()
        return Path(value) if value else None

    @property
    def memory_symbol_cache_path(self) -> Path:
        value = str(self.memory_symbol_cache_root or "").strip()
        return Path(value) if value else self.backend_data_dir / "memory-symbol-cache"

    @property
    def memory_symbol_execution_mode(self) -> str:
        mode = str(self.memory_symbol_mode or "offline_only").strip().lower()
        return mode if mode in {"offline_only", "managed_download"} else "offline_only"

    @property
    def memory_symbol_hosts(self) -> list[str]:
        hosts: list[str] = []
        for raw in str(self.memory_symbol_allowed_hosts or "").split(","):
            host = raw.strip().lower().rstrip(".")
            if not host or "*" in host or "://" in host or "/" in host:
                continue
            if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
                hosts.append(host)
        return sorted(set(hosts))

    @property
    def memory_symbol_queue_name(self) -> str:
        value = str(self.memory_symbol_task_queue or "memory-symbols").strip()
        if not value or any(token in value for token in " ;&|`$<>\n\r/\\"):
            return "memory-symbols"
        return value

    @property
    def memory_symbol_redirect_host_suffixes(self) -> list[str]:
        suffixes: list[str] = []
        for raw in str(self.memory_symbol_redirect_suffixes or "").split(","):
            suffix = raw.strip().lower().rstrip(".")
            if not suffix.startswith(".") or "*" in suffix or "/" in suffix or ":" in suffix:
                continue
            if re.fullmatch(r"\.[a-z0-9](?:[a-z0-9.-]{0,250}[a-z0-9])?", suffix):
                suffixes.append(suffix)
        return sorted(set(suffixes))

    @property
    def memory_upload_staging_path(self) -> Path:
        value = str(self.memory_upload_staging_root or "").strip()
        return Path(value) if value else self.backend_temp_dir / "memory-uploads"

    @property
    def memory_upload_extensions(self) -> set[str]:
        values = str(self.memory_upload_allowed_extensions or "").split(",")
        extensions = {item.strip().lower() for item in values if item.strip()}
        return {item if item.startswith(".") else f".{item}" for item in extensions}

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

    # --- Exact Symbol Recovery Sources v1: computed properties ---

    @property
    def memory_symbol_package_extensions(self) -> set[str]:
        values = str(self.memory_symbol_package_allowed_extensions or "").split(",")
        extensions = {item.strip().lower() for item in values if item.strip()}
        return {item if item.startswith(".") else f".{item}" for item in extensions}

    @property
    def memory_symbol_import_quarantine_path(self) -> Path:
        value = str(self.memory_symbol_import_quarantine_root or "").strip()
        return Path(value) if value else self.backend_temp_dir / "symbol-import-quarantine"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.backend_data_dir.mkdir(parents=True, exist_ok=True)
    settings.backend_temp_dir.mkdir(parents=True, exist_ok=True)
    (settings.backend_data_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (settings.backend_data_dir / "tmp").mkdir(parents=True, exist_ok=True)
    return settings
