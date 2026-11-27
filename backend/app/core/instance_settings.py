"""Instance settings an administrator may change from the UI instead of editing .env.

Each one is a Settings field read when a process starts. A value saved from the UI is stored in
app_settings (category "instance") and laid over the environment by get_settings() the next time
backend, worker or memory-worker start, so it applies after a restart of those services; the few
marked "live" are read from the database on every use instead. Removing the value goes back to
what .env (or config/defaults.env) says.

The list is closed on purpose. It leaves out:
- secrets, connection details, ports and URLs, and what docker compose itself reads (heap,
  replicas, profiles): those need the host;
- the switches that let the server reach outside the lab or the host's file system (S3 and Azure
  imports, symbol downloads, external tools, host path imports). They stay in .env so that a web
  session alone cannot open them; the UI shows their value, read-only;
- lists that upgrades migrate in .env (the memory plugin allowlists).

This module is imported by app.core.config.get_settings(), so it must not import app modules
that call get_settings() at import time (database, models); those are imported inside functions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.core.config import Settings

logger = logging.getLogger(__name__)

CATEGORY = "instance"
PYTHON_SERVICES = ("backend", "worker")
MEMORY_SERVICES = ("backend", "worker", "memory-worker")


@dataclass(frozen=True)
class InstanceSetting:
    key: str
    group: str
    label: str
    description: str
    value_type: str  # bool | int | choice
    unit: str | None = None  # bytes | seconds | minutes
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()
    services: tuple[str, ...] = PYTHON_SERVICES
    live: bool = False
    memory_only: bool = False
    field_name: str = field(default="")

    @property
    def field(self) -> str:
        return self.field_name or self.key.lower()


GIB = 1024**3

INSTANCE_SETTINGS: tuple[InstanceSetting, ...] = (
    InstanceSetting("UPDATE_CHECK_ENABLED", "general", "Check for updates", "Ask GitHub, at most every few hours while an administrator has the UI open, whether the branch this instance follows has new commits. Only the commit ids are sent.", "bool", live=True),
    InstanceSetting("BACKEND_LOG_LEVEL", "general", "Log level", "Detail of the backend and worker logs (docker compose logs).", "choice", choices=("DEBUG", "INFO", "WARNING", "ERROR"), services=MEMORY_SERVICES),
    InstanceSetting("WIZARD_ADVANCED_OPTIONS_ENABLED", "general", "Advanced wizard options", "Show the advanced options step of the evidence ingestion wizard.", "bool", services=("backend",)),
    InstanceSetting("INGEST_JOB_TIMEOUT_SECONDS", "ingest", "Ingest job timeout", "Longest an evidence ingest job may run before it is stopped.", "int", unit="seconds", minimum=600, maximum=7 * 86400),
    InstanceSetting("ARCHIVE_EXTRACTION_TIMEOUT_SECONDS", "ingest", "Archive extraction timeout", "Longest the extraction of one archive may take.", "int", unit="seconds", minimum=60, maximum=86400),
    InstanceSetting("MAX_ARCHIVE_DEPTH", "ingest", "Nested archive depth", "How many archives inside archives are extracted.", "int", minimum=1, maximum=20),
    InstanceSetting("BACKEND_MAX_EXTRACTED_FILES", "ingest", "Files extracted per evidence", "Most files extracted from one evidence before extraction stops.", "int", minimum=100, maximum=50_000_000),
    InstanceSetting("BACKEND_MAX_EXTRACTED_BYTES", "ingest", "Bytes extracted per evidence", "Most bytes extracted from one evidence before extraction stops.", "int", unit="bytes", minimum=GIB, maximum=64 * 1024 * GIB),
    InstanceSetting("RULE_RUN_STALE_AFTER_MINUTES", "ingest", "Stalled rule run after", "Minutes without progress after which a rule run is shown as stalled.", "int", unit="minutes", minimum=1, maximum=1440),
    InstanceSetting("DISK_IMAGE_INGEST_ENABLED", "disk", "Disk image ingest", "Accept disk images (E01, raw, VMDK...) as evidence.", "bool"),
    InstanceSetting("DISK_IMAGE_JOB_TIMEOUT_SECONDS", "disk", "Disk image job timeout", "Longest a disk image ingest job may run.", "int", unit="seconds", minimum=600, maximum=7 * 86400),
    InstanceSetting("DISK_FILE_EXPORT_MAX_FILES", "disk", "Files per export", "Most files one export from the file browser may contain.", "int", minimum=1, maximum=1_000_000),
    InstanceSetting("DISK_FILE_EXPORT_MAX_BYTES", "disk", "Bytes per export", "Most bytes one export from the file browser may contain.", "int", unit="bytes", minimum=1024**2, maximum=1024 * GIB),
    InstanceSetting("MEMORY_WINDOWS_DEFAULT_ENGINE", "memory", "Windows memory engine", "Engine of Windows memory analysis: MemProcFS (no kernel symbols needed) or Volatility.", "choice", choices=("memprocfs", "volatility"), services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_AUTO_PREPARATION", "memory", "Prepare memory images on upload", "Identify the operating system and check symbols as soon as a memory image arrives.", "bool", services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_RUN_ALL_ENABLED", "memory", "Run all analyses", "Offer the action that runs every analysis of a memory image.", "bool", services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_JOB_TIMEOUT_SECONDS", "memory", "Memory job timeout", "Longest one memory analysis job may run.", "int", unit="seconds", minimum=60, maximum=7 * 86400, services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_PLUGIN_TIMEOUT_SECONDS", "memory", "Memory plugin timeout", "Longest one Volatility plugin may run.", "int", unit="seconds", minimum=30, maximum=7 * 86400, services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_UPLOAD_MIN_FREE_SPACE_BYTES", "memory", "Free space kept on uploads", "A memory upload is refused when it would leave less free disk than this.", "int", unit="bytes", minimum=0, maximum=64 * 1024 * GIB, services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_UPLOAD_CASE_QUOTA_BYTES", "memory", "Memory uploads per case", "Most bytes of memory images one case may hold.", "int", unit="bytes", minimum=GIB, maximum=64 * 1024 * GIB, services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMPROCFS_CRASH_RETRY_ENABLED", "memory", "Retry MemProcFS crashes", "Run MemProcFS once more, under gdb, when it crashes while opening an image.", "bool", services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMPROCFS_YARA_ACCEPT_ELASTIC_LICENSE", "memory", "MemProcFS YARA rules (Elastic License 2.0)", "Use the YARA rules bundled with MemProcFS in Find Evil. Turning it on accepts the Elastic License 2.0 of those rules.", "bool", services=MEMORY_SERVICES, memory_only=True),
    InstanceSetting("MEMORY_LINUX_SYMBOL_MANUAL_IMPORT_ENABLED", "memory", "Upload Linux symbols", "Let administrators upload Linux symbol files (ISF or Volatility 2 profiles) for a memory image.", "bool", services=MEMORY_SERVICES, memory_only=True),
)

# Shown with their value but only changed in .env: each lets the server reach outside the lab or
# the host's file system.
READ_ONLY_SETTINGS: tuple[tuple[str, str], ...] = (
    ("S3_SOURCE_ENABLED", "Evidence from S3: the server downloads from outside the lab."),
    ("AZURE_BLOB_SOURCE_ENABLED", "Evidence from Azure Blob Storage: the server downloads from outside the lab."),
    ("MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED", "Symbol downloads from the internet."),
    ("MEMORY_AUTO_SYMBOL_ACQUIRE", "Automatic symbol downloads."),
    ("MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION", "Running external memory tools."),
    ("DFIR_ALLOW_HOST_PATH_IMPORT", "Importing evidence from paths of the host."),
    ("MEMORY_ANALYSIS_ENABLED", "Memory analysis needs the memory-worker container (scripts/setup.sh --memory)."),
)

BY_KEY = {item.key: item for item in INSTANCE_SETTINGS}
RESTART_KEYS = tuple(item.key for item in INSTANCE_SETTINGS if not item.live)


def load_overrides(database_url: str) -> dict[str, Any]:
    """Values saved from the UI for the settings read at start-up, straight from the database."""
    from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine, select
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.pool import NullPool

    table = Table(
        "app_settings",
        MetaData(),
        Column("key", String(128)),
        Column("value", JSON().with_variant(JSONB, "postgresql")),
        Column("category", String(64)),
    )
    connect_args = {"connect_timeout": 3} if database_url.startswith("postgresql") else {}
    engine = create_engine(database_url, poolclass=NullPool, connect_args=connect_args)
    try:
        with engine.connect() as connection:
            rows = connection.execute(select(table.c.key, table.c.value).where(table.c.category == CATEGORY, table.c.key.in_(RESTART_KEYS))).all()
    finally:
        engine.dispose()
    return {key: value for key, value in rows if value is not None}


def apply_overrides(base: "Settings", settings_class: type["Settings"]) -> "Settings":
    """Lays the values saved from the UI over the environment. Any failure keeps the environment:
    a database that is not up yet (first start, CLI on the host) or an invalid saved value must
    never stop a service from starting."""
    try:
        overrides = load_overrides(base.database_url)
    except Exception as exc:  # noqa: BLE001 - see docstring
        logger.info("Instance settings from the database not applied: %s", type(exc).__name__)
        return base
    if not overrides:
        return base
    values = {BY_KEY[key].field: value for key, value in overrides.items() if key in BY_KEY}
    try:
        settings = settings_class(**values)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Instance settings saved from the UI are invalid and were not applied: %s", exc)
        return base
    logger.info("Instance settings applied from the UI: %s", ", ".join(sorted(overrides)))
    return settings


def validate_value(item: InstanceSetting, value: Any) -> Any:
    """Returns the value to store, or raises ValueError with a message for the administrator."""
    if item.value_type == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{item.key} must be true or false")
        return value
    if item.value_type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{item.key} must be a whole number")
        if item.minimum is not None and value < item.minimum:
            raise ValueError(f"{item.key} must be at least {item.minimum}")
        if item.maximum is not None and value > item.maximum:
            raise ValueError(f"{item.key} must be at most {item.maximum}")
        return value
    if item.value_type == "choice":
        if value not in item.choices:
            raise ValueError(f"{item.key} must be one of: {', '.join(item.choices)}")
        return value
    raise ValueError(f"{item.key} cannot be changed")


def stored_overrides(db: "Session") -> dict[str, Any]:
    from app.models.app_setting import AppSetting

    rows = db.query(AppSetting).filter(AppSetting.category == CATEGORY, AppSetting.key.in_(list(BY_KEY))).all()
    return {row.key: row.value for row in rows if row.value is not None}


def store_override(db: "Session", key: str, value: Any) -> None:
    """Saves (or, with None, removes) a value. The caller commits."""
    from app.core.database import utc_now_naive
    from app.models.app_setting import AppSetting

    item = BY_KEY[key]
    row = db.get(AppSetting, key)
    if value is None:
        if row is not None:
            db.delete(row)
        return
    if row is None:
        db.add(AppSetting(key=key, value=value, category=CATEGORY, description=item.description, requires_restart=not item.live, updated_at=utc_now_naive()))
        return
    row.value = value
    row.category = CATEGORY
    row.requires_restart = not item.live
    row.updated_at = utc_now_naive()


def effective_value(db: "Session", key: str) -> Any:
    """The value in force now: for a live setting the saved one (else .env); for the others the one
    this process started with."""
    from app.core.config import get_settings

    item = BY_KEY[key]
    running = getattr(get_settings(), item.field)
    if not item.live:
        return running
    from app.models.app_setting import AppSetting

    row = db.get(AppSetting, key)
    if row is None or row.category != CATEGORY or row.value is None:
        return running
    try:
        return validate_value(item, row.value)
    except ValueError:
        return running


def describe(db: "Session") -> dict[str, Any]:
    from app.core.config import Settings, get_settings

    running_settings = get_settings()
    environment = Settings()
    overrides = stored_overrides(db)
    memory_enabled = bool(running_settings.memory_enabled)
    entries = []
    restart_services: set[str] = set()
    for item in INSTANCE_SETTINGS:
        if item.memory_only and not memory_enabled:
            continue
        env_value = getattr(environment, item.field)
        override = overrides.get(item.key)
        if item.live:
            running = effective_value(db, item.key)
            pending = False
        else:
            running = getattr(running_settings, item.field)
            pending = (override if override is not None else env_value) != running
        if pending:
            restart_services.update(item.services)
        entries.append(
            {
                "key": item.key,
                "group": item.group,
                "label": item.label,
                "description": item.description,
                "value_type": item.value_type,
                "unit": item.unit,
                "min": item.minimum,
                "max": item.maximum,
                "choices": list(item.choices),
                "env_value": env_value,
                "override": override,
                "running_value": running,
                "applies": "live" if item.live else "restart",
                "services": list(item.services),
                "pending_restart": pending,
            }
        )
    read_only = [
        {"key": key, "value": getattr(running_settings, key.lower(), None), "reason": reason}
        for key, reason in READ_ONLY_SETTINGS
    ]
    services = [name for name in ("backend", "worker", "memory-worker") if name in restart_services and (name != "memory-worker" or memory_enabled)]
    return {
        "settings": entries,
        "read_only": read_only,
        "restart_services": services,
        "restart_command": f"docker compose restart {' '.join(services)}" if services else None,
    }
