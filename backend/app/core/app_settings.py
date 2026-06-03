from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.app_setting import AppSetting


settings = get_settings()
ABSOLUTE_SEARCH_MAX_PAGE_SIZE = 200
ABSOLUTE_SEARCH_DEFAULT_PAGE_SIZE = 200

PERFORMANCE_PROFILE_KEY = "PERFORMANCE_PROFILE"

RUNTIME_DEFAULTS = {
    "INGEST_BATCH_SIZE": settings.ingest_batch_size,
    "OPENSEARCH_BULK_DOCS": settings.opensearch_bulk_docs,
    "OPENSEARCH_BULK_BYTES": settings.opensearch_bulk_bytes,
    "OPENSEARCH_BULK_TIMEOUT": 120,
    "OPENSEARCH_REFRESH_TIMEOUT": 120,
    "MAX_PARALLEL_ARTIFACTS": settings.max_parallel_artifacts,
    "MAX_PARALLEL_RULE_RUNS": settings.max_parallel_rule_runs,
    "SEARCH_DEFAULT_PAGE_SIZE": min(settings.search_default_page_size, ABSOLUTE_SEARCH_DEFAULT_PAGE_SIZE),
    "SEARCH_MAX_PAGE_SIZE": min(settings.search_max_page_size, ABSOLUTE_SEARCH_MAX_PAGE_SIZE),
    "AUTO_CREATE_HEURISTIC_DETECTIONS": settings.auto_create_heuristic_detections,
    "MFT_FAST_PATH": settings.mft_fast_path,
    "MOUNTED_PATH_SCAN_LIMIT": 5000,
    "PROCESS_GRAPH_MAX_NODES": 2000,
    "CORRELATION_MAX_EVENTS": 20000,
    "DEBUG_EXPORT_MAX_EVENTS": 25,
    "SIGMA_MAX_MATCHES_PER_RULE": settings.sigma_max_matches_per_rule,
    "SIGMA_MAX_DETECTIONS_PER_RULE": settings.sigma_max_detections_per_rule,
    "SIGMA_NOISY_RULE_THRESHOLD": settings.sigma_noisy_rule_threshold,
    "DETECTION_WRITE_BATCH_SIZE": 1000,
    "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE": 2000,
    "METADATA_UPDATE_THROTTLE_SECONDS": 3,
    "OPENSEARCH_DASHBOARDS_PUBLIC_URL": settings.opensearch_dashboards_public_url,
    "REPORT_BRAND_NAME": settings.report_brand_name,
    "REPORT_BRAND_SUBTITLE": settings.report_brand_subtitle,
    "REPORT_BRAND_PRIMARY_COLOR": settings.report_brand_primary_color,
    "REPORT_INCLUDE_LOGO": settings.report_include_logo,
    "REPORT_LOGO_PATH": settings.report_logo_path,
}

DEPLOYMENT_DEFAULTS = {
    "OPENSEARCH_JAVA_HEAP": settings.opensearch_java_heap,
    "BACKEND_UVICORN_WORKERS": settings.backend_uvicorn_workers,
    "WORKER_SCALE": 1,
    "DOCKER_CPU_LIMIT": None,
    "DOCKER_MEMORY_LIMIT": None,
}

PERFORMANCE_PROFILES = {
    "safe": {
        "INGEST_BATCH_SIZE": 250,
        "OPENSEARCH_BULK_DOCS": 250,
        "OPENSEARCH_BULK_BYTES": 2 * 1024 * 1024,
        "OPENSEARCH_BULK_TIMEOUT": 120,
        "OPENSEARCH_REFRESH_TIMEOUT": 120,
        "MAX_PARALLEL_ARTIFACTS": 1,
        "MAX_PARALLEL_RULE_RUNS": 1,
        "SEARCH_DEFAULT_PAGE_SIZE": 50,
        "SEARCH_MAX_PAGE_SIZE": 200,
        "AUTO_CREATE_HEURISTIC_DETECTIONS": True,
        "MFT_FAST_PATH": True,
        "MOUNTED_PATH_SCAN_LIMIT": 2000,
        "PROCESS_GRAPH_MAX_NODES": 1200,
        "CORRELATION_MAX_EVENTS": 10000,
        "DEBUG_EXPORT_MAX_EVENTS": 25,
        "OPENSEARCH_JAVA_HEAP": "2g",
        "BACKEND_UVICORN_WORKERS": 1,
        "WORKER_SCALE": 1,
        "DOCKER_CPU_LIMIT": None,
        "DOCKER_MEMORY_LIMIT": None,
    },
    "balanced": {
        **RUNTIME_DEFAULTS,
        **DEPLOYMENT_DEFAULTS,
    },
    "performance": {
        "INGEST_BATCH_SIZE": 1500,
        "OPENSEARCH_BULK_DOCS": 1500,
        "OPENSEARCH_BULK_BYTES": 16 * 1024 * 1024,
        "OPENSEARCH_BULK_TIMEOUT": 180,
        "OPENSEARCH_REFRESH_TIMEOUT": 180,
        "MAX_PARALLEL_ARTIFACTS": 2,
        "MAX_PARALLEL_RULE_RUNS": 2,
        "SEARCH_DEFAULT_PAGE_SIZE": 75,
        "SEARCH_MAX_PAGE_SIZE": 200,
        "AUTO_CREATE_HEURISTIC_DETECTIONS": True,
        "MFT_FAST_PATH": True,
        "MOUNTED_PATH_SCAN_LIMIT": 7500,
        "PROCESS_GRAPH_MAX_NODES": 3000,
        "CORRELATION_MAX_EVENTS": 30000,
        "DEBUG_EXPORT_MAX_EVENTS": 50,
        "SIGMA_MAX_MATCHES_PER_RULE": 7500,
        "SIGMA_MAX_DETECTIONS_PER_RULE": 2500,
        "SIGMA_NOISY_RULE_THRESHOLD": 10000,
        "DETECTION_WRITE_BATCH_SIZE": 2000,
        "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE": 4000,
        "METADATA_UPDATE_THROTTLE_SECONDS": 5,
        "OPENSEARCH_JAVA_HEAP": "4g",
        "BACKEND_UVICORN_WORKERS": 2,
        "WORKER_SCALE": 2,
        "DOCKER_CPU_LIMIT": None,
        "DOCKER_MEMORY_LIMIT": None,
    },
    "max": {
        "INGEST_BATCH_SIZE": 2000,
        "OPENSEARCH_BULK_DOCS": 2000,
        "OPENSEARCH_BULK_BYTES": 20 * 1024 * 1024,
        "OPENSEARCH_BULK_TIMEOUT": 240,
        "OPENSEARCH_REFRESH_TIMEOUT": 240,
        "MAX_PARALLEL_ARTIFACTS": 4,
        "MAX_PARALLEL_RULE_RUNS": 2,
        "SEARCH_DEFAULT_PAGE_SIZE": 100,
        "SEARCH_MAX_PAGE_SIZE": 200,
        "AUTO_CREATE_HEURISTIC_DETECTIONS": True,
        "MFT_FAST_PATH": True,
        "MOUNTED_PATH_SCAN_LIMIT": 10000,
        "PROCESS_GRAPH_MAX_NODES": 5000,
        "CORRELATION_MAX_EVENTS": 50000,
        "DEBUG_EXPORT_MAX_EVENTS": 100,
        "SIGMA_MAX_MATCHES_PER_RULE": 10000,
        "SIGMA_MAX_DETECTIONS_PER_RULE": 5000,
        "SIGMA_NOISY_RULE_THRESHOLD": 15000,
        "DETECTION_WRITE_BATCH_SIZE": 4000,
        "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE": 8000,
        "METADATA_UPDATE_THROTTLE_SECONDS": 8,
        "OPENSEARCH_JAVA_HEAP": "4g",
        "BACKEND_UVICORN_WORKERS": 2,
        "WORKER_SCALE": 4,
        "DOCKER_CPU_LIMIT": None,
        "DOCKER_MEMORY_LIMIT": None,
    },
}

SETTING_META: dict[str, dict[str, Any]] = {
    PERFORMANCE_PROFILE_KEY: {
        "category": "runtime",
        "description": "Named performance profile applied from the UI.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
        "allowed": ["safe", "balanced", "max", "custom"],
    },
    "INGEST_BATCH_SIZE": {
        "category": "runtime",
        "description": "Documents parsed per ingest chunk.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 50,
        "max": 10000,
    },
    "OPENSEARCH_BULK_DOCS": {
        "category": "runtime",
        "description": "Maximum documents per OpenSearch bulk request.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 5000,
    },
    "OPENSEARCH_BULK_BYTES": {
        "category": "runtime",
        "description": "Maximum bytes per OpenSearch bulk request.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1048576,
        "max": 52428800,
    },
    "OPENSEARCH_BULK_TIMEOUT": {
        "category": "runtime",
        "description": "OpenSearch bulk timeout in seconds.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 30,
        "max": 600,
    },
    "OPENSEARCH_REFRESH_TIMEOUT": {
        "category": "runtime",
        "description": "OpenSearch refresh timeout in seconds.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 30,
        "max": 600,
    },
    "MAX_PARALLEL_ARTIFACTS": {
        "category": "runtime",
        "description": "Maximum parallel artifact parsing workers.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1,
        "max": 8,
    },
    "MAX_PARALLEL_RULE_RUNS": {
        "category": "runtime",
        "description": "Maximum parallel rule execution workers.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1,
        "max": 8,
    },
    "SEARCH_DEFAULT_PAGE_SIZE": {
        "category": "runtime",
        "description": "Default page size for Search and Timeline.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 10,
        "max": 200,
    },
    "SEARCH_MAX_PAGE_SIZE": {
        "category": "runtime",
        "description": "Maximum page size accepted by API.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 50,
        "max": 200,
    },
    "AUTO_CREATE_HEURISTIC_DETECTIONS": {
        "category": "runtime",
        "description": "Create built-in heuristic detections from suspicious normalized events.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "bool",
    },
    "MFT_FAST_PATH": {
        "category": "runtime",
        "description": "Use the lightweight fast-path normalizer for large MFTECmd imports.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "bool",
    },
    "MOUNTED_PATH_SCAN_LIMIT": {
        "category": "runtime",
        "description": "Maximum files sampled when validating mounted directories.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 50000,
    },
    "PROCESS_GRAPH_MAX_NODES": {
        "category": "runtime",
        "description": "Upper bound for process graph nodes included in UI/debug workflows.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 20000,
    },
    "CORRELATION_MAX_EVENTS": {
        "category": "runtime",
        "description": "Maximum events considered by correlation engine passes.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1000,
        "max": 200000,
    },
    "DEBUG_EXPORT_MAX_EVENTS": {
        "category": "runtime",
        "description": "Default maximum events per type for debug export.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 5,
        "max": 250,
    },
    "SIGMA_MAX_MATCHES_PER_RULE": {
        "category": "runtime",
        "description": "Maximum candidate Sigma matches retrieved per rule before capping.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 50000,
    },
    "SIGMA_MAX_DETECTIONS_PER_RULE": {
        "category": "runtime",
        "description": "Maximum new detections written per Sigma rule before capping.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 50000,
    },
    "SIGMA_NOISY_RULE_THRESHOLD": {
        "category": "runtime",
        "description": "Threshold after which a Sigma rule is marked noisy in reports.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1000,
        "max": 100000,
    },
    "DETECTION_WRITE_BATCH_SIZE": {
        "category": "runtime",
        "description": "Bulk insert batch size for new detections written during Sigma and heuristic runs.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 10000,
    },
    "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE": {
        "category": "runtime",
        "description": "Bulk duplicate lookup batch size for detection deduplication queries.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 100,
        "max": 20000,
    },
    "METADATA_UPDATE_THROTTLE_SECONDS": {
        "category": "runtime",
        "description": "Minimum seconds between heavy metadata progress writes for long-running jobs.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "int",
        "min": 1,
        "max": 60,
    },
    "OPENSEARCH_JAVA_HEAP": {
        "category": "deployment",
        "description": "Desired OpenSearch JVM heap size.",
        "requires_restart": True,
        "restart_scope": "opensearch",
        "applies_immediately": False,
        "value_type": "string",
    },
    "BACKEND_UVICORN_WORKERS": {
        "category": "deployment",
        "description": "Desired uvicorn worker count.",
        "requires_restart": True,
        "restart_scope": "backend",
        "applies_immediately": False,
        "value_type": "int",
        "min": 1,
        "max": 16,
    },
    "WORKER_SCALE": {
        "category": "deployment",
        "description": "Desired docker compose worker scale.",
        "requires_restart": True,
        "restart_scope": "worker",
        "applies_immediately": False,
        "value_type": "int",
        "min": 1,
        "max": 16,
    },
    "DOCKER_CPU_LIMIT": {
        "category": "deployment",
        "description": "Desired Docker CPU limit.",
        "requires_restart": True,
        "restart_scope": "full_stack",
        "applies_immediately": False,
        "value_type": "string",
    },
    "DOCKER_MEMORY_LIMIT": {
        "category": "deployment",
        "description": "Desired Docker memory limit.",
        "requires_restart": True,
        "restart_scope": "full_stack",
        "applies_immediately": False,
        "value_type": "string",
    },
    "OPENSEARCH_DASHBOARDS_PUBLIC_URL": {
        "category": "runtime",
        "description": "Public OpenSearch Dashboards URL used in UI redirects. Leave empty to derive it from the current request host.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
    },
    "REPORT_BRAND_NAME": {
        "category": "runtime",
        "description": "Brand name displayed on generated PDF reports.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
    },
    "REPORT_BRAND_SUBTITLE": {
        "category": "runtime",
        "description": "Brand subtitle displayed on generated PDF reports.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
    },
    "REPORT_BRAND_PRIMARY_COLOR": {
        "category": "runtime",
        "description": "Primary hex color used for PDF report headings and accents.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
    },
    "REPORT_INCLUDE_LOGO": {
        "category": "runtime",
        "description": "Include a local logo in generated PDF reports when REPORT_LOGO_PATH is valid.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "bool",
    },
    "REPORT_LOGO_PATH": {
        "category": "runtime",
        "description": "Local logo path for PDF reports. Only trusted local paths under the backend data directory or static assets should be used.",
        "requires_restart": False,
        "restart_scope": "none",
        "applies_immediately": True,
        "value_type": "string",
    },
}


def _default_for(key: str) -> object:
    if key in RUNTIME_DEFAULTS:
        return RUNTIME_DEFAULTS[key]
    if key in DEPLOYMENT_DEFAULTS:
        return DEPLOYMENT_DEFAULTS[key]
    if key == PERFORMANCE_PROFILE_KEY:
        return "balanced"
    return None


def get_setting_meta(key: str) -> dict[str, Any]:
    return dict(SETTING_META.get(key, {}))


def get_setting(db: Session, key: str, default: object | None = None) -> object:
    item = db.get(AppSetting, key)
    if item is None:
        value = _default_for(key) if default is None else default
    else:
        value = item.value
    if key == "SEARCH_MAX_PAGE_SIZE" and value is not None:
        return min(int(value), ABSOLUTE_SEARCH_MAX_PAGE_SIZE)
    if key == "SEARCH_DEFAULT_PAGE_SIZE" and value is not None:
        return min(int(value), ABSOLUTE_SEARCH_DEFAULT_PAGE_SIZE)
    return value


def set_setting(db: Session, key: str, value: object) -> AppSetting:
    item = db.get(AppSetting, key)
    meta = get_setting_meta(key)
    category = str(meta.get("category") or "runtime")
    description = meta.get("description")
    requires_restart = bool(meta.get("requires_restart", False))
    if item is None:
        item = AppSetting(
            key=key,
            value=value,
            category=category,
            description=description,
            requires_restart=requires_restart,
            updated_at=utc_now_naive(),
        )
        db.add(item)
    else:
        item.value = value
        item.category = category
        item.description = description
        item.requires_restart = requires_restart
        item.updated_at = utc_now_naive()
    db.commit()
    db.refresh(item)
    return item


def list_settings(db: Session) -> dict[str, Any]:
    return {item.key: item.value for item in db.query(AppSetting).all()}


def get_effective_settings(db: Session) -> dict[str, Any]:
    combined = {**RUNTIME_DEFAULTS, **DEPLOYMENT_DEFAULTS, PERFORMANCE_PROFILE_KEY: "balanced"}
    for key in combined:
        combined[key] = get_setting(db, key)
    return combined


def load_runtime_settings(db: Session | None = None) -> dict[str, Any]:
    if db is None:
        return dict(RUNTIME_DEFAULTS)
    return {key: get_setting(db, key) for key in RUNTIME_DEFAULTS}


def get_performance_profile(db: Session) -> str:
    value = str(get_setting(db, PERFORMANCE_PROFILE_KEY, "balanced") or "balanced").lower()
    return value if value in {"safe", "balanced", "performance", "max", "custom"} else "balanced"


def reset_settings(db: Session) -> list[str]:
    keys = [item.key for item in db.query(AppSetting).all()]
    db.query(AppSetting).delete()
    db.commit()
    return keys
