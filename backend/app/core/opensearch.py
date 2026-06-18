from collections.abc import Iterable
import copy
import logging
import re
import threading
import time

from opensearchpy import OpenSearch
from opensearchpy.exceptions import AuthorizationException, RequestError, TransportError
import orjson

from app.core.app_settings import load_runtime_settings
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.ingest.fingerprints import apply_event_fingerprint
from app.services.host_identity import apply_case_host_identity, get_host_identity_runtime_stats


logger = logging.getLogger(__name__)
settings = get_settings()
MAX_RAW_FIELD_CHARS = 8192
MAX_RAW_JSON_BYTES = 64 * 1024
INDEX_TOTAL_FIELDS_LIMIT = 2000
INDEX_MAX_DOCVALUE_FIELDS_SEARCH = 256
INDEX_QUERY_DEFAULT_FIELDS = ["search_text"]
SEARCH_TEXT_MAX_CHARS = 32 * 1024
_SEARCH_TEXT_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")
_SEARCH_TEXT_WHITESPACE = re.compile(r"\s+")


class OpenSearchIngestBlockedError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        reason: str = "infrastructure_blocked_opensearch",
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.details = dict(details or {})


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def _read_cluster_block(settings_payload: dict | None, key: str) -> bool:
    payload = dict(settings_payload or {})
    for scope in ("persistent", "transient", "defaults"):
        current = dict(payload.get(scope) or {})
        cluster = dict(current.get("cluster") or {})
        blocks = dict(cluster.get("blocks") or {})
        if key in blocks:
            return _as_bool(blocks.get(key))
    return False


def _read_index_block(settings_payload: dict | None, key: str) -> bool:
    payload = dict(settings_payload or {})
    for scope in ("persistent", "transient", "defaults"):
        current = dict(payload.get(scope) or {})
        index = dict(current.get("index") or {})
        blocks = dict(index.get("blocks") or {})
        if key in blocks:
            return _as_bool(blocks.get(key))
    return False


def get_opensearch_ingest_preflight(case_id: str | None = None) -> dict:
    index_name = get_events_index(case_id) if case_id else None
    snapshot = {
        "reachable": False,
        "cluster_status": "unreachable",
        "cluster_create_index_blocked": False,
        "cluster_write_blocked": False,
        "cluster_read_only_allow_delete": False,
        "target_index": index_name,
        "target_index_exists": None,
        "target_index_write_blocked": False,
        "target_index_read_only_allow_delete": False,
        "disk_allocation": [],
        "disk_watermark": None,
        "bulk_indexing_permitted": False,
        "ingest_writable": False,
        "blocking_reasons": [],
        "troubleshooting": [
            "GET /_cluster/settings?include_defaults=true",
            "GET /_cluster/health",
            "GET /_cat/allocation?v",
        ],
    }
    try:
        client = get_opensearch_client()
        health = client.cluster.health()
        settings_payload = client.cluster.get_settings(include_defaults=True)
        allocation = client.cat.allocation(format="json")
        snapshot["reachable"] = True
        snapshot["cluster_status"] = str(health.get("status") or "unknown").lower()
        snapshot["cluster_create_index_blocked"] = _read_cluster_block(settings_payload, "create_index")
        snapshot["cluster_write_blocked"] = _read_cluster_block(settings_payload, "write")
        snapshot["cluster_read_only_allow_delete"] = _read_cluster_block(settings_payload, "read_only_allow_delete")
        snapshot["disk_watermark"] = (
            ((health.get("cluster_name") and dict(settings_payload.get("persistent") or {})) or {}).get("cluster", {})
            .get("routing", {})
            .get("allocation", {})
            .get("disk", {})
            .get("watermark")
            or (((dict(settings_payload.get("defaults") or {})).get("cluster") or {}).get("routing") or {}).get("allocation", {}).get("disk", {}).get("watermark")
        )
        snapshot["disk_allocation"] = allocation if isinstance(allocation, list) else []
        if snapshot["cluster_status"] == "red":
            snapshot["blocking_reasons"].append("cluster_health_red")
        if snapshot["cluster_create_index_blocked"]:
            snapshot["blocking_reasons"].append("cluster_create_index_blocked")
        if snapshot["cluster_write_blocked"] or snapshot["cluster_read_only_allow_delete"]:
            snapshot["blocking_reasons"].append("cluster_write_blocked")

        if index_name:
            exists = bool(client.indices.exists(index=index_name))
            snapshot["target_index_exists"] = exists
            if exists:
                try:
                    index_settings = client.indices.get_settings(index=index_name)
                    concrete_settings = (
                        ((dict(index_settings.get(index_name) or {})).get("settings") or {}).get("index")
                        or {}
                    )
                    snapshot["target_index_write_blocked"] = _read_index_block(concrete_settings, "write")
                    snapshot["target_index_read_only_allow_delete"] = _read_index_block(concrete_settings, "read_only_allow_delete")
                    if snapshot["target_index_write_blocked"] or snapshot["target_index_read_only_allow_delete"]:
                        snapshot["blocking_reasons"].append("target_index_write_blocked")
                except Exception as exc:  # noqa: BLE001
                    snapshot["blocking_reasons"].append(f"target_index_settings_unavailable:{exc.__class__.__name__}")
            elif snapshot["cluster_create_index_blocked"]:
                snapshot["blocking_reasons"].append("missing_target_index_create_blocked")

        snapshot["bulk_indexing_permitted"] = not any(
            (
                snapshot["cluster_status"] == "red",
                snapshot["cluster_create_index_blocked"],
                snapshot["cluster_write_blocked"],
                snapshot["cluster_read_only_allow_delete"],
                snapshot["target_index_write_blocked"],
                snapshot["target_index_read_only_allow_delete"],
            )
        )
        snapshot["ingest_writable"] = bool(snapshot["reachable"]) and bool(snapshot["bulk_indexing_permitted"])
        return snapshot
    except Exception as exc:  # noqa: BLE001
        snapshot["blocking_reasons"].append(f"cluster_unreachable:{exc.__class__.__name__}")
        snapshot["error"] = f"{exc.__class__.__name__}: {exc}"
        return snapshot


def assert_opensearch_ingest_ready(case_id: str) -> dict:
    snapshot = get_opensearch_ingest_preflight(case_id)
    index_name = str(snapshot.get("target_index") or get_events_index(case_id))
    if not snapshot.get("ingest_writable"):
        raise OpenSearchIngestBlockedError(
            "OpenSearch is not writable or cannot create indices. Ingest has not started.",
            details=snapshot,
        )
    if snapshot.get("target_index_exists"):
        return snapshot
    client = get_opensearch_client()
    try:
        ensure_case_index(case_id)
    except OpenSearchIngestBlockedError as exc:
        raise exc
    except (AuthorizationException, RequestError, TransportError) as exc:
        lowered = str(exc).lower()
        reason = (
            "cluster_create_index_blocked"
            if "index_create_block_exception" in lowered or "create-index blocked" in lowered or "create index blocked" in lowered
            else "cluster_write_blocked"
            if "blocked by" in lowered or "read-only" in lowered or "read_only_allow_delete" in lowered
            else "opensearch_request_failed"
        )
        snapshot["blocking_reasons"].append(reason)
        snapshot["error"] = f"{exc.__class__.__name__}: {exc}"
        raise OpenSearchIngestBlockedError(
            "OpenSearch is not writable or cannot create indices. Ingest has not started.",
            details=snapshot,
        ) from exc
    except Exception as exc:  # noqa: BLE001
        snapshot["blocking_reasons"].append(f"case_index_preflight_failed:{exc.__class__.__name__}")
        snapshot["error"] = f"{exc.__class__.__name__}: {exc}"
        raise OpenSearchIngestBlockedError(
            "OpenSearch is not writable or cannot create indices. Ingest has not started.",
            details=snapshot,
        ) from exc
    snapshot["target_index_exists"] = bool(client.indices.exists(index=index_name))
    snapshot["bulk_indexing_permitted"] = True
    snapshot["ingest_writable"] = True
    return snapshot


def _debug_db_trace(function: str, *, db=None, case_id: str | None = None) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return
    connection_id = None
    if db is not None:
        try:
            connection = db.connection()
            connection_id = id(connection.connection)
        except Exception:  # noqa: BLE001
            connection_id = None
    logger.debug(
        "db_trace function=%s thread=%s thread_id=%s session_id=%s connection_id=%s case_id=%s",
        function,
        threading.current_thread().name,
        threading.get_ident(),
        id(db) if db is not None else None,
        connection_id,
        case_id,
    )


def _apply_safe_index_settings(client: OpenSearch, index: str) -> None:
    """Keep old case indices from failing bulk imports while new mappings stay strict.

    This is a compatibility safety net for indices created before raw/event_data were
    disabled. It does not fix an already-bloated mapping, but it prevents small
    dynamic additions from immediately breaking imports. New indices are protected
    by dynamic:false and enabled:false raw payload containers.
    """
    try:
        client.indices.put_settings(
            index=index,
            body={
                "index.mapping.total_fields.limit": INDEX_TOTAL_FIELDS_LIMIT,
                "index.max_docvalue_fields_search": INDEX_MAX_DOCVALUE_FIELDS_SEARCH,
                "index.query.default_field": INDEX_QUERY_DEFAULT_FIELDS,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not apply safe field limit to %s: %s", index, exc)


def ensure_events_indices_safe_settings() -> None:
    client = get_opensearch_client()
    _apply_safe_index_settings(client, get_events_index(None))


def get_opensearch_client(*, timeout_seconds: int | None = None) -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": settings.opensearch_host, "port": settings.opensearch_port}],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=settings.opensearch_ssl,
        verify_certs=settings.opensearch_verify_certs,
        timeout=int(timeout_seconds or 30),
    )


def get_events_index(case_id: str | None = None) -> str:
    suffix = case_id if case_id else "*"
    return f"{settings.opensearch_index_prefix}-{suffix}"


def get_memory_index(case_id: str) -> str:
    return f"{settings.opensearch_memory_index_prefix}-{case_id}"


def index_exists(client: OpenSearch, index: str) -> bool:
    try:
        return bool(client.indices.exists(index=index))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not verify index %s existence: %s", index, exc)
        return False


def get_index_health(client: OpenSearch, index: str) -> str:
    if not index_exists(client, index):
        return "missing"
    try:
        result = client.cluster.health(index=index, params={"level": "indices", "ignore_unavailable": "true"})
        status = result.get("status")
        if isinstance(status, str):
            return status.lower()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not fetch health for index %s: %s", index, exc)
    return "unknown"


def is_index_queryable(client: OpenSearch, index: str) -> bool:
    return get_index_health(client, index) not in {"red", "missing"}


def resolve_aggregatable_field(client: OpenSearch, index: str, field: str) -> str | None:
    candidates = [field] if field.endswith(".keyword") else [field, f"{field}.keyword"]
    for candidate in candidates:
        try:
            caps = client.field_caps(index=index, fields=[candidate], params={"ignore_unavailable": "true"})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not inspect field caps for %s on %s: %s", candidate, index, exc)
            continue
        for _, type_info in (caps.get("fields", {}).get(candidate) or {}).items():
            if isinstance(type_info, dict) and type_info.get("aggregatable"):
                return candidate
    return None


def ensure_case_index(case_id: str) -> str:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        try:
            client.indices.create(
                index=index,
                body={
                    "settings": {
                        "index.mapping.total_fields.limit": INDEX_TOTAL_FIELDS_LIMIT,
                        "index.max_docvalue_fields_search": INDEX_MAX_DOCVALUE_FIELDS_SEARCH,
                        "index.query.default_field": INDEX_QUERY_DEFAULT_FIELDS,
                    },
                    "mappings": {
                        "dynamic": False,
                        "properties": {
                        "id": {"type": "keyword"},
                        "event_id": {"type": "keyword"},
                        "stable_event_id": {"type": "keyword"},
                        "event_fingerprint": {"type": "keyword"},
                        "event_fingerprint_version": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "evidence_id": {"type": "keyword"},
                        "artifact_id": {"type": "keyword"},
                        "source_file": {"type": "keyword"},
                        "source_tool": {"type": "keyword"},
                        "source_format": {"type": "keyword"},
                        "@timestamp": {"type": "date"},
                        "timestamp_precision": {"type": "keyword"},
                        "timezone": {"type": "keyword"},
                        "timestamp_precision": {"type": "keyword"},
                        "timezone": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "risk_score": {"type": "integer"},
                        "raw_summary": {"type": "text"},
                        "search_text": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 32766},
                                "wildcard": {"type": "wildcard"},
                            },
                        },
                        "os": {"properties": {"type": {"type": "keyword"}, "version": {"type": "keyword"}}},
                        "event": {
                            "properties": {
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "provider": {"type": "keyword"},
                                "channel": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "timeline_include": {"type": "boolean"},
                                "message": {"type": "text"},
                            }
                        },
                        "artifact": {
                            "properties": {
                                "type": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "parser": {"type": "keyword"},
                                "parser_backend": {"type": "keyword"},
                                "backend_variant": {"type": "keyword"},
                                "default_backend": {"type": "boolean"},
                                "advanced_backend": {"type": "boolean"},
                                "supersedes_internal": {"type": "boolean"},
                                "source_artifact_fingerprint": {"type": "keyword"},
                                "source_path": {"type": "keyword"},
                            }
                        },
                        "backend_variant": {"type": "keyword"},
                        "parser_backend": {"type": "keyword"},
                        "host": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "hostname": {"type": "keyword"},
                                "ip": {"type": "keyword"},
                                "os": {"type": "keyword"},
                                "aliases": {"type": "keyword"},
                                "identity_id": {"type": "keyword"},
                                "identity_confidence": {"type": "keyword"},
                            }
                        },
                        "observed_host": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "hostname": {"type": "keyword"},
                            }
                        },
                        "user": {"properties": {"name": {"type": "keyword"}, "domain": {"type": "keyword"}, "sid": {"type": "keyword"}, "logon_id": {"type": "keyword"}}},
                        "source": {
                            "properties": {
                                "ip": {"type": "ip", "ignore_malformed": True},
                                "port": {"type": "integer", "ignore_malformed": True},
                                "hostname": {"type": "keyword"},
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip", "ignore_malformed": True},
                                "port": {"type": "integer", "ignore_malformed": True},
                                "hostname": {"type": "keyword"},
                            }
                        },
                        "object": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "server": {"type": "keyword"},
                            }
                        },
                        "access": {
                            "properties": {
                                "mask": {"type": "keyword"},
                                "list": {"type": "keyword"},
                                "accesses": {"type": "keyword"},
                                "reason": {"type": "text"},
                            }
                        },
                        "process": {
                            "properties": {
                                "entity_id": {"type": "keyword"},
                                "guid": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "display_name": {"type": "keyword"},
                                "pid": {"type": "keyword"},
                                "ppid": {"type": "keyword"},
                                "command_line": {"type": "text"},
                                "path": {"type": "keyword"},
                                "executable": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                                "application": {"type": "keyword"},
                                "parent_name": {"type": "keyword"},
                                "parent_path": {"type": "keyword"},
                                "parent_command_line": {"type": "text"},
                                "parent_entity_id": {"type": "keyword"},
                                "parent_pid": {"type": "keyword"},
                                "parent": {
                                    "properties": {
                                        "entity_id": {"type": "keyword"},
                                        "guid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "pid": {"type": "keyword"},
                                        "path": {"type": "keyword"},
                                        "executable": {"type": "keyword"},
                                        "command_line": {"type": "text"},
                                    }
                                },
                                "hash": {
                                    "properties": {
                                        "md5": {"type": "keyword"},
                                        "sha1": {"type": "keyword"},
                                        "sha256": {"type": "keyword"},
                                        "imphash": {"type": "keyword"},
                                    }
                                },
                                "integrity_level": {"type": "keyword"},
                                "token_elevation": {"type": "keyword"},
                            }
                        },
                        "parent": {
                            "properties": {
                                "process": {
                                    "properties": {
                                        "entity_id": {"type": "keyword"},
                                        "guid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "pid": {"type": "keyword"},
                                        "path": {"type": "keyword"},
                                        "executable": {"type": "keyword"},
                                        "command_line": {"type": "text"},
                                    }
                                }
                            }
                        },
                        "file": {
                            "properties": {
                                "path": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "extension": {"type": "keyword"},
                                "parent_path": {"type": "keyword"},
                                "size": {"type": "long"},
                                "sha1": {"type": "keyword"},
                                "sha256": {"type": "keyword"},
                                "hash_sha1": {"type": "keyword"},
                                "hash_sha256": {"type": "keyword"},
                                "md5": {"type": "keyword"},
                                "created": {"type": "date"},
                                "modified": {"type": "date"},
                                "accessed": {"type": "date"},
                                "mft_modified": {"type": "date"},
                                "changed": {"type": "date"},
                                "deleted": {"type": "keyword"},
                                "deleted_time": {"type": "date"},
                                "in_use": {"type": "boolean"},
                                "is_directory": {"type": "boolean"},
                                "attributes": {"type": "keyword"},
                                "ads": {"type": "keyword"},
                                "has_ads": {"type": "boolean"},
                                "source_path": {"type": "keyword"},
                            }
                        },
                        "download": {
                            "properties": {
                                "url": {"type": "keyword"},
                                "final_url": {"type": "keyword"},
                                "referrer": {"type": "keyword"},
                                "target_path": {"type": "keyword"},
                                "file_name": {"type": "keyword"},
                                "mime_type": {"type": "keyword"},
                                "total_bytes": {"type": "long"},
                                "received_bytes": {"type": "long"},
                                "state": {"type": "keyword"},
                            }
                        },
                        "filesystem": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "source": {"type": "keyword"},
                                "activity": {"type": "keyword"},
                                "reason": {"type": "keyword"},
                                "is_deleted": {"type": "boolean"},
                                "is_directory": {"type": "boolean"},
                                "is_ads": {"type": "boolean"},
                                "path_depth": {"type": "integer", "ignore_malformed": True},
                                "suspicious_path": {"type": "boolean"},
                                "timestomp_suspected": {"type": "boolean"},
                            }
                        },
                        "mft": {
                            "properties": {
                                "entry_number": {"type": "keyword"},
                                "sequence_number": {"type": "keyword"},
                                "reference_number": {"type": "keyword"},
                                "parent_entry_number": {"type": "keyword"},
                                "parent_sequence_number": {"type": "keyword"},
                                "parent_reference_number": {"type": "keyword"},
                                "in_use": {"type": "boolean"},
                                "file_name": {"type": "keyword"},
                                "full_path": {"type": "keyword"},
                                "parent_path": {"type": "keyword"},
                                "extension": {"type": "keyword"},
                                "file_size": {"type": "long"},
                                "file_attributes": {"type": "keyword"},
                                "has_ads": {"type": "boolean"},
                                "ads": {"type": "keyword"},
                                "si_created": {"type": "date"},
                                "si_modified": {"type": "date"},
                                "si_accessed": {"type": "date"},
                                "si_mft_modified": {"type": "date"},
                                "fn_created": {"type": "date"},
                                "fn_modified": {"type": "date"},
                                "fn_accessed": {"type": "date"},
                                "fn_mft_modified": {"type": "date"},
                                "object_id": {"type": "keyword"},
                                "reparse_target": {"type": "keyword"},
                                "zone_id": {"type": "keyword"},
                            }
                        },
                        "usn": {
                            "properties": {
                                "timestamp": {"type": "date"},
                                "file_reference": {"type": "keyword"},
                                "parent_file_reference": {"type": "keyword"},
                                "usn": {"type": "keyword"},
                                "reason": {"type": "keyword"},
                                "reasons": {"type": "keyword"},
                                "source_info": {"type": "keyword"},
                                "security_id": {"type": "keyword"},
                            }
                        },
                        "execution": {
                            "properties": {
                                "source": {"type": "keyword"},
                                "run_count": {"type": "integer", "ignore_malformed": True},
                                "first_run": {"type": "date"},
                                "last_run": {"type": "date"},
                                "last_runs": {"type": "date"},
                                "program_name": {"type": "keyword"},
                                "confidence": {"type": "keyword"},
                                "is_execution_confirmed": {"type": "boolean"},
                                "interpretation": {"type": "keyword"},
                                "first_seen": {"type": "date"},
                                "last_seen": {"type": "date"},
                                "last_modified": {"type": "date"},
                                "install_date": {"type": "date"},
                                "compile_time": {"type": "date"},
                                "focus_time": {"type": "integer", "ignore_malformed": True},
                            }
                        },
                        "prefetch": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "source_filename": {"type": "keyword"},
                                "executable_name": {"type": "keyword"},
                                "executable_path": {"type": "keyword"},
                                "prefetch_hash": {"type": "keyword"},
                                "hash": {"type": "keyword"},
                                "run_count": {"type": "integer", "ignore_malformed": True},
                                "last_run": {"type": "date"},
                                "last_runs": {"type": "date"},
                                "previous_runs": {"type": "date"},
                                "source_created": {"type": "date"},
                                "source_modified": {"type": "date"},
                                "source_accessed": {"type": "date"},
                                "version": {"type": "integer", "ignore_malformed": True},
                                "signature": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "text"},
                                "volume_serial_number": {"type": "keyword"},
                                "volume_device_path": {"type": "keyword"},
                                "volume_creation_time": {"type": "date"},
                                "volume_label": {"type": "keyword"},
                                "volume_serials": {"type": "keyword"},
                                "volume_names": {"type": "keyword"},
                                "volume_created_times": {"type": "date"},
                                "referenced_files": {"type": "keyword"},
                                "referenced_directories": {"type": "keyword"},
                                "directories": {"type": "keyword"},
                                "loaded_files_count": {"type": "integer", "ignore_malformed": True},
                                "referenced_files_count": {"type": "integer", "ignore_malformed": True},
                                "file_size": {"type": "long", "ignore_malformed": True},
                                "parse_warnings": {"type": "keyword"},
                            }
                        },
                        "browser": {
                            "properties": {
                                "browser": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "profile": {"type": "keyword"},
                                "profile_path": {"type": "keyword"},
                                "artifact_type": {"type": "keyword"},
                                "url": {"type": "keyword"},
                                "final_url": {"type": "keyword"},
                                "tab_url": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "domain": {"type": "keyword"},
                                "title": {"type": "text"},
                                "visit_count": {"type": "keyword"},
                                "typed_count": {"type": "keyword"},
                                "transition": {"type": "keyword"},
                                "search_terms": {"type": "text"},
                                "search_engine": {"type": "keyword"},
                                "download_path": {"type": "keyword"},
                                "download_start_time": {"type": "date"},
                                "download_end_time": {"type": "date"},
                                "download_state": {"type": "keyword"},
                                "danger_type": {"type": "keyword"},
                                "interrupt_reason": {"type": "keyword"},
                                "referrer": {"type": "keyword"},
                            }
                        },
                        "powershell": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "command": {"type": "text"},
                                "command_preview": {"type": "text"},
                                "line_number": {"type": "integer", "ignore_malformed": True},
                                "source_file": {"type": "keyword"},
                                "transcript_start_time": {"type": "date"},
                                "transcript_end_time": {"type": "date"},
                                "username": {"type": "keyword"},
                                "run_as": {"type": "keyword"},
                                "machine": {"type": "keyword"},
                                "host_application": {"type": "text"},
                                "process_id": {"type": "keyword"},
                                "ps_version": {"type": "keyword"},
                                "has_encoded_command": {"type": "boolean"},
                                "encoded_command": {"type": "text"},
                                "decoded_command_preview": {"type": "text"},
                                "has_download": {"type": "boolean"},
                                "has_iex": {"type": "boolean"},
                                "has_execution_policy_bypass": {"type": "boolean"},
                                "has_defender_tampering": {"type": "boolean"},
                                "has_persistence": {"type": "boolean"},
                                "urls": {"type": "keyword"},
                                "domains": {"type": "keyword"},
                                "paths": {"type": "keyword"},
                                "indicators": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "keyword"},
                            }
                        },
                        "url": {
                            "properties": {
                                "full": {"type": "keyword"},
                                "domain": {"type": "keyword"},
                                "scheme": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "query": {"type": "text"},
                            }
                        },
                        "download": {
                            "properties": {
                                "url": {"type": "keyword"},
                                "final_url": {"type": "keyword"},
                                "referrer": {"type": "keyword"},
                                "target_path": {"type": "keyword"},
                                "file_name": {"type": "keyword"},
                                "mime_type": {"type": "keyword"},
                                "total_bytes": {"type": "long"},
                                "received_bytes": {"type": "long"},
                                "state": {"type": "keyword"},
                                "danger_type": {"type": "keyword"},
                                "interrupt_reason": {"type": "keyword"},
                            }
                        },
                        "velociraptor": {
                            "properties": {
                                "collection_id": {"type": "keyword"},
                                "original_path": {"type": "keyword"},
                                "normalized_windows_path": {"type": "keyword"},
                                "artifact_category": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                            }
                        },
                        "object": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "server": {"type": "keyword"},
                            }
                        },
                        "access": {
                            "properties": {
                                "mask": {"type": "keyword"},
                                "list": {"type": "keyword"},
                                "accesses": {"type": "keyword"},
                                "reason": {"type": "text"},
                            }
                        },
                        "registry": {
                            "properties": {
                                "hive": {"type": "keyword"},
                                "hive_path": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "key_path": {"type": "keyword"},
                                "key": {"type": "keyword"},
                                "key_name": {"type": "keyword"},
                                "value_name": {"type": "keyword"},
                                "value_type": {"type": "keyword"},
                                "data": {"type": "text"},
                                "event_type": {"type": "keyword"},
                                "value_data": {"type": "text"},
                                "last_write": {"type": "date"},
                                "last_write_time": {"type": "date"},
                                "artifact_type": {"type": "keyword"},
                                "plugin": {"type": "keyword"},
                                "batch": {"type": "keyword"},
                            }
                        },
                        "folder": {
                            "properties": {
                                "path": {"type": "keyword"},
                            }
                        },
                        "mru": {
                            "properties": {
                                "order": {"type": "integer", "ignore_malformed": True},
                                "list": {"type": "keyword"},
                            }
                        },
                        "office": {
                            "properties": {
                                "app": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "trusted_document": {"type": "boolean"},
                                "macro_trust_possible": {"type": "boolean"},
                            }
                        },
                        "user_activity": {
                            "properties": {
                                "kind": {"type": "keyword"},
                                "application": {"type": "keyword"},
                                "activity_target": {"type": "keyword"},
                            }
                        },
                        "amcache": {
                            "properties": {
                                "program_id": {"type": "keyword"},
                                "program_name": {"type": "keyword"},
                                "program_version": {"type": "keyword"},
                                "publisher": {"type": "keyword"},
                                "product_name": {"type": "keyword"},
                                "product_version": {"type": "keyword"},
                                "file_id": {"type": "keyword"},
                                "file_name": {"type": "keyword"},
                                "file_path": {"type": "keyword"},
                                "path_hash": {"type": "keyword"},
                                "link_date": {"type": "date"},
                                "compile_time": {"type": "date"},
                                "install_date": {"type": "date"},
                                "uninstall_date": {"type": "date"},
                                "language": {"type": "keyword"},
                                "binary_type": {"type": "keyword"},
                                "is_os_component": {"type": "boolean"},
                                "key_path": {"type": "keyword"},
                                "key_last_write_time": {"type": "date"},
                                "source_file": {"type": "keyword"},
                            }
                        },
                        "shimcache": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "entry_number": {"type": "keyword"},
                                "position": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "last_modified_time": {"type": "date"},
                                "last_update": {"type": "date"},
                                "insert_flags": {"type": "keyword"},
                                "shim_flags": {"type": "keyword"},
                                "executed": {"type": "boolean"},
                                "control_set": {"type": "keyword"},
                                "key_path": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "keyword"},
                            }
                        },
                        "appcompat": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "last_modified": {"type": "date"},
                                "last_write_time": {"type": "date"},
                                "entry_number": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "interpretation": {"type": "keyword"},
                            }
                        },
                        "lnk": {
                            "properties": {
                                "source_file": {"type": "keyword"},
                                "target_path": {"type": "keyword"},
                                "target_id_absolute_path": {"type": "keyword"},
                                "local_path": {"type": "keyword"},
                                "common_path": {"type": "keyword"},
                                "relative_path": {"type": "keyword"},
                                "arguments": {"type": "text"},
                                "working_directory": {"type": "keyword"},
                                "icon_location": {"type": "keyword"},
                                "description": {"type": "text"},
                                "machine_id": {"type": "keyword"},
                                "drive_serial": {"type": "keyword"},
                                "drive_type": {"type": "keyword"},
                                "drive_serial_number": {"type": "keyword"},
                                "volume_label": {"type": "keyword"},
                                "volume_created": {"type": "date"},
                                "network_path": {"type": "keyword"},
                                "net_name": {"type": "keyword"},
                                "device_name": {"type": "keyword"},
                                "share_name": {"type": "keyword"},
                                "tracker_droid": {"type": "keyword"},
                                "tracker_birth_droid": {"type": "keyword"},
                                "droid": {"type": "keyword"},
                                "birth_droid": {"type": "keyword"},
                                "mac_address": {"type": "keyword"},
                                "target_created": {"type": "date"},
                                "target_modified": {"type": "date"},
                                "target_accessed": {"type": "date"},
                                "source_created": {"type": "date"},
                                "source_modified": {"type": "date"},
                                "source_accessed": {"type": "date"},
                                "effective_path": {"type": "keyword"},
                                "effective_path_source": {"type": "keyword"},
                                "display_name": {"type": "keyword"},
                                "is_partial_target": {"type": "boolean"},
                                "is_shell_target": {"type": "boolean"},
                                "file_size": {"type": "long", "ignore_malformed": True},
                                "file_attributes": {"type": "keyword"},
                                "mft_entry": {"type": "keyword"},
                                "mft_sequence": {"type": "keyword"},
                                "parse_warnings": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "keyword"},
                            }
                        },
                        "jumplist": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "app_id": {"type": "keyword"},
                                "app_name": {"type": "keyword"},
                                "app_description": {"type": "text"},
                                "app_id_description": {"type": "text"},
                                "destination_type": {"type": "keyword"},
                                "dest_list_version": {"type": "keyword"},
                                "destlist_last_accessed": {"type": "date"},
                                "destlist_access_count": {"type": "integer", "ignore_malformed": True},
                                "destlist_pin_status": {"type": "keyword"},
                                "entry_number": {"type": "keyword"},
                                "entry_id": {"type": "keyword"},
                                "stream_name": {"type": "keyword"},
                                "mru": {"type": "keyword"},
                                "pin_status": {"type": "keyword"},
                                "hostname": {"type": "keyword"},
                                "mac_address": {"type": "keyword"},
                                "interaction_count": {"type": "integer", "ignore_malformed": True},
                                "target_path": {"type": "keyword"},
                                "target_created": {"type": "date"},
                                "target_modified": {"type": "date"},
                                "target_accessed": {"type": "date"},
                                "effective_path": {"type": "keyword"},
                                "effective_path_source": {"type": "keyword"},
                                "display_name": {"type": "keyword"},
                                "local_path": {"type": "keyword"},
                                "common_path": {"type": "keyword"},
                                "relative_path": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                                "arguments": {"type": "text"},
                                "description": {"type": "text"},
                                "icon_location": {"type": "keyword"},
                                "last_accessed": {"type": "date"},
                                "last_modified": {"type": "date"},
                                "created": {"type": "date"},
                                "modified": {"type": "date"},
                                "accessed": {"type": "date"},
                                "birth_created": {"type": "date"},
                                "birth_modified": {"type": "date"},
                                "birth_accessed": {"type": "date"},
                                "drive_type": {"type": "keyword"},
                                "drive_serial_number": {"type": "keyword"},
                                "volume_label": {"type": "keyword"},
                                "network_path": {"type": "keyword"},
                                "net_name": {"type": "keyword"},
                                "device_name": {"type": "keyword"},
                                "share_name": {"type": "keyword"},
                                "machine_id": {"type": "keyword"},
                                "machine_mac_address": {"type": "keyword"},
                                "tracker_droid": {"type": "keyword"},
                                "tracker_birth_droid": {"type": "keyword"},
                                "droid": {"type": "keyword"},
                                "birth_droid": {"type": "keyword"},
                                "tracker_created": {"type": "date"},
                                "mft_entry": {"type": "keyword"},
                                "mft_sequence": {"type": "keyword"},
                                "file_attributes": {"type": "keyword"},
                                "parse_method": {"type": "keyword"},
                                "parse_warnings": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "text"},
                            }
                        },
                        "volume": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "guid": {"type": "keyword"},
                                "drive_letter": {"type": "keyword"},
                                "serial": {"type": "keyword"},
                                "label": {"type": "keyword"},
                                "drive_type": {"type": "keyword"},
                                "created": {"type": "date"},
                                "device_path": {"type": "keyword"},
                                "mounted_device": {"type": "keyword"},
                                "dos_device": {"type": "keyword"},
                            }
                        },
                        "usb": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "device_instance_id": {"type": "keyword"},
                                "parent_device_instance_id": {"type": "keyword"},
                                "hardware_id": {"type": "keyword"},
                                "compatible_ids": {"type": "keyword"},
                                "vendor": {"type": "keyword"},
                                "product": {"type": "keyword"},
                                "revision": {"type": "keyword"},
                                "serial": {"type": "keyword"},
                                "vid": {"type": "keyword"},
                                "pid": {"type": "keyword"},
                                "device_id": {"type": "keyword"},
                                "friendly_name": {"type": "keyword"},
                                "container_id": {"type": "keyword"},
                                "parent_id_prefix": {"type": "keyword"},
                                "class_guid": {"type": "keyword"},
                                "class_name": {"type": "keyword"},
                                "service": {"type": "keyword"},
                                "driver": {"type": "keyword"},
                                "driver_provider": {"type": "keyword"},
                                "driver_date": {"type": "keyword"},
                                "driver_version": {"type": "keyword"},
                                "inf_path": {"type": "keyword"},
                                "install_status": {"type": "keyword"},
                                "result_code": {"type": "keyword"},
                                "first_install_time": {"type": "date"},
                                "install_time": {"type": "date"},
                                "last_arrival_time": {"type": "date"},
                                "last_connected_time": {"type": "date"},
                                "last_removal_time": {"type": "date"},
                                "section_start_time": {"type": "date"},
                                "section_end_time": {"type": "date"},
                                "source_file": {"type": "keyword"},
                                "line_start": {"type": "integer", "ignore_malformed": True},
                                "line_end": {"type": "integer", "ignore_malformed": True},
                                "raw_instance_id": {"type": "keyword"},
                                "device_type": {"type": "keyword"},
                                "parse_warnings": {"type": "keyword"},
                            }
                        },
                        "bits": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "job_id": {"type": "keyword"},
                                "job_guid": {"type": "keyword"},
                                "display_name": {"type": "keyword"},
                                "description": {"type": "text"},
                                "owner": {"type": "keyword"},
                                "owner_sid": {"type": "keyword"},
                                "state": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "priority": {"type": "keyword"},
                                "remote_name": {"type": "keyword"},
                                "remote_url": {"type": "keyword"},
                                "local_name": {"type": "keyword"},
                                "local_path": {"type": "keyword"},
                                "file_list": {"type": "keyword"},
                                "files_total": {"type": "integer", "ignore_malformed": True},
                                "files_transferred": {"type": "integer", "ignore_malformed": True},
                                "bytes_total": {"type": "long", "ignore_malformed": True},
                                "bytes_transferred": {"type": "long", "ignore_malformed": True},
                                "creation_time": {"type": "date"},
                                "modification_time": {"type": "date"},
                                "transfer_completion_time": {"type": "date"},
                                "expiration_time": {"type": "date"},
                                "error_code": {"type": "keyword"},
                                "error_description": {"type": "text"},
                                "notify_cmd_line": {"type": "text"},
                                "notify_flags": {"type": "keyword"},
                                "retry_delay": {"type": "integer", "ignore_malformed": True},
                                "no_progress_timeout": {"type": "integer", "ignore_malformed": True},
                                "minimum_retry_delay": {"type": "integer", "ignore_malformed": True},
                                "source_file": {"type": "keyword"},
                                "raw_qmgr_path": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                            }
                        },
                        "cloud": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "provider": {"type": "keyword"},
                                "account": {"type": "keyword"},
                                "account_email": {"type": "keyword"},
                                "user": {"type": "keyword"},
                                "sync_root": {"type": "keyword"},
                                "local_path": {"type": "keyword"},
                                "remote_path": {"type": "keyword"},
                                "cloud_path": {"type": "keyword"},
                                "item_id": {"type": "keyword"},
                                "drive_id": {"type": "keyword"},
                                "resource_id": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "sync_status": {"type": "keyword"},
                                "hydration_status": {"type": "keyword"},
                                "pinned": {"type": "keyword"},
                                "shared": {"type": "keyword"},
                                "created_time": {"type": "date"},
                                "modified_time": {"type": "date"},
                                "accessed_time": {"type": "date"},
                                "deleted_time": {"type": "date"},
                                "last_sync_time": {"type": "date"},
                                "last_upload_time": {"type": "date"},
                                "last_download_time": {"type": "date"},
                                "direction": {"type": "keyword"},
                                "confidence": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "detection_method": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "text"},
                            }
                        },
                        "autoruns": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "entry_location": {"type": "keyword"},
                                "entry": {"type": "keyword"},
                                "enabled": {"type": "boolean"},
                                "profile": {"type": "keyword"},
                                "description": {"type": "text"},
                                "publisher": {"type": "keyword"},
                                "company": {"type": "keyword"},
                                "signer": {"type": "keyword"},
                                "signed": {"type": "boolean"},
                                "verified": {"type": "boolean"},
                                "image_path": {"type": "keyword"},
                                "launch_string": {"type": "text"},
                                "command_line": {"type": "text"},
                                "arguments": {"type": "text"},
                                "working_directory": {"type": "keyword"},
                                "hash_md5": {"type": "keyword"},
                                "hash_sha1": {"type": "keyword"},
                                "hash_sha256": {"type": "keyword"},
                                "pe_sha1": {"type": "keyword"},
                                "pe_sha256": {"type": "keyword"},
                                "virus_total": {"type": "keyword"},
                                "vt_detection": {"type": "integer"},
                                "vt_link": {"type": "keyword"},
                                "wow64": {"type": "boolean"},
                                "user": {"type": "keyword"},
                                "sid": {"type": "keyword"},
                                "timestamp": {"type": "date"},
                                "source_file": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "text"},
                            }
                        },
                        "persistence": {
                            "properties": {
                                "mechanism": {"type": "keyword"},
                                "location": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "command": {"type": "text"},
                                "path": {"type": "keyword"},
                                "enabled": {"type": "boolean"},
                                "scope": {"type": "keyword"},
                                "user": {"type": "keyword"},
                                "sid": {"type": "keyword"},
                                "confidence": {"type": "keyword"},
                                "source": {"type": "keyword"},
                            }
                        },
                        "wmi": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "namespace": {"type": "keyword"},
                                "class_name": {"type": "keyword"},
                                "instance_name": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "relpath": {"type": "keyword"},
                                "creator_sid": {"type": "keyword"},
                                "creator_user": {"type": "keyword"},
                                "filter_name": {"type": "keyword"},
                                "consumer_name": {"type": "keyword"},
                                "query": {"type": "text"},
                                "query_language": {"type": "keyword"},
                                "event_namespace": {"type": "keyword"},
                                "consumer_type": {"type": "keyword"},
                                "command_line_template": {"type": "text"},
                                "executable_path": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                                "script_text": {"type": "text"},
                                "script_preview": {"type": "text"},
                                "scripting_engine": {"type": "keyword"},
                                "binding_filter": {"type": "keyword"},
                                "binding_consumer": {"type": "keyword"},
                                "delivery_qos": {"type": "keyword"},
                                "maintain_security_context": {"type": "keyword"},
                                "kill_timeout": {"type": "keyword"},
                                "machine_name": {"type": "keyword"},
                                "max_queue_size": {"type": "keyword"},
                                "last_write_time": {"type": "date"},
                                "created_time": {"type": "date"},
                                "modified_time": {"type": "date"},
                                "source_file": {"type": "keyword"},
                                "repository_path": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "text"},
                            }
                        },
                        "shellbag": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "bag_path": {"type": "keyword"},
                                "absolute_path": {"type": "keyword"},
                                "shell_type": {"type": "keyword"},
                                "mru": {"type": "keyword"},
                                "slot": {"type": "keyword"},
                                "node_slot": {"type": "keyword"},
                                "mru_position": {"type": "keyword"},
                                "last_write": {"type": "date"},
                                "last_write_time": {"type": "date"},
                                "created": {"type": "date"},
                                "modified": {"type": "date"},
                                "accessed": {"type": "date"},
                                "first_interacted": {"type": "date"},
                                "last_interacted": {"type": "date"},
                                "mft_entry": {"type": "keyword"},
                                "mft_sequence": {"type": "keyword"},
                                "extension_block": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "hive_path": {"type": "keyword"},
                                "key_path": {"type": "keyword"},
                                "is_deleted": {"type": "boolean"},
                                "is_network_path": {"type": "boolean"},
                                "is_usb_path": {"type": "boolean"},
                                "is_control_panel": {"type": "boolean"},
                            }
                        },
                        "recycle_bin": {
                            "properties": {
                                "original_path": {"type": "keyword"},
                                "deleted_time": {"type": "date"},
                                "recovery_name": {"type": "keyword"},
                            }
                        },
                        "recycle": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "sid": {"type": "keyword"},
                                "user": {"type": "keyword"},
                                "original_path": {"type": "keyword"},
                                "original_file_name": {"type": "keyword"},
                                "original_size": {"type": "long", "ignore_malformed": True},
                                "deleted_time": {"type": "date"},
                                "i_file_path": {"type": "keyword"},
                                "r_file_path": {"type": "keyword"},
                                "has_i_file": {"type": "boolean"},
                                "has_r_file": {"type": "boolean"},
                                "pair_id": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "drive_letter": {"type": "keyword"},
                                "content_status": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                            }
                        },
                        "srum": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "table": {"type": "keyword"},
                                "application": {"type": "keyword"},
                                "app_id": {"type": "keyword"},
                                "app_name": {"type": "keyword"},
                                "package_name": {"type": "keyword"},
                                "user_sid": {"type": "keyword"},
                                "interface_luid": {"type": "keyword"},
                                "interface_guid": {"type": "keyword"},
                                "interface_profile": {"type": "keyword"},
                                "bytes_sent": {"type": "long", "ignore_malformed": True},
                                "bytes_received": {"type": "long", "ignore_malformed": True},
                                "bytes_total": {"type": "long", "ignore_malformed": True},
                                "foreground_bytes_sent": {"type": "long", "ignore_malformed": True},
                                "foreground_bytes_received": {"type": "long", "ignore_malformed": True},
                                "background_bytes_sent": {"type": "long", "ignore_malformed": True},
                                "background_bytes_received": {"type": "long", "ignore_malformed": True},
                                "network_profile": {"type": "keyword"},
                                "connected_time": {"type": "keyword"},
                                "duration": {"type": "keyword"},
                                "energy_usage": {"type": "keyword"},
                                "cycle_time": {"type": "keyword"},
                                "start_time": {"type": "date"},
                                "end_time": {"type": "date"},
                                "source_file": {"type": "keyword"},
                            }
                        },
                        "network": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "interface_name": {"type": "keyword"},
                                "interface_guid": {"type": "keyword"},
                                "interface_alias": {"type": "keyword"},
                                "interface_description": {"type": "keyword"},
                                "mac_address": {"type": "keyword"},
                                "ip_address": {"type": "ip", "ignore_malformed": True},
                                "ipv4": {"type": "ip", "ignore_malformed": True},
                                "ipv6": {"type": "keyword"},
                                "subnet": {"type": "keyword"},
                                "gateway": {"type": "ip", "ignore_malformed": True},
                                "dns_servers": {"type": "keyword"},
                                "dhcp_enabled": {"type": "boolean"},
                                "dhcp_server": {"type": "ip", "ignore_malformed": True},
                                "profile_name": {"type": "keyword"},
                                "profile_guid": {"type": "keyword"},
                                "network_category": {"type": "keyword"},
                                "source_ip": {"type": "ip", "ignore_malformed": True},
                                "destination_ip": {"type": "ip", "ignore_malformed": True},
                                "source_port": {"type": "integer", "ignore_malformed": True},
                                "destination_port": {"type": "integer", "ignore_malformed": True},
                                "protocol": {"type": "keyword"},
                                "direction": {"type": "keyword"},
                                "application": {"type": "keyword"},
                                "bytes_sent": {"type": "long", "ignore_malformed": True},
                                "bytes_received": {"type": "long", "ignore_malformed": True},
                                "bytes_total": {"type": "long", "ignore_malformed": True},
                                "domain": {"type": "keyword"},
                                "url": {"type": "keyword"},
                                "state": {"type": "keyword"},
                                "process_id": {"type": "keyword"},
                                "process_name": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "interface": {"type": "keyword"},
                                "profile": {"type": "keyword"},
                                "first_seen": {"type": "date"},
                                "last_seen": {"type": "date"},
                                "source_file": {"type": "keyword"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "keyword"},
                                "share_name": {"type": "keyword"},
                                "destination_hostname": {"type": "keyword"},
                                "share_local_path": {"type": "keyword"},
                                "relative_target_name": {"type": "keyword"},
                            }
                        },
                        "wlan": {
                            "properties": {
                                "ssid": {"type": "keyword"},
                                "ssid_hex": {"type": "keyword"},
                                "profile_name": {"type": "keyword"},
                                "profile_type": {"type": "keyword"},
                                "connection_mode": {"type": "keyword"},
                                "authentication": {"type": "keyword"},
                                "encryption": {"type": "keyword"},
                                "key_type": {"type": "keyword"},
                                "key_protected": {"type": "boolean"},
                                "key_material_present": {"type": "boolean"},
                                "auto_switch": {"type": "boolean"},
                                "mac_randomization": {"type": "keyword"},
                                "interface_guid": {"type": "keyword"},
                                "interface_description": {"type": "keyword"},
                                "bssid": {"type": "keyword"},
                                "signal_quality": {"type": "keyword"},
                                "connection_start": {"type": "date"},
                                "connection_end": {"type": "date"},
                                "reason": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                            }
                        },
                        "dns": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "query": {"type": "keyword"},
                                "question": {"properties": {"name": {"type": "keyword"}}},
                                "answers": {"type": "keyword"},
                                "domain": {"type": "keyword"},
                                "record_type": {"type": "keyword"},
                                "data": {"type": "keyword"},
                                "ip": {"type": "ip", "ignore_malformed": True},
                                "ttl": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "source": {"type": "keyword"},
                                "server": {"type": "keyword"},
                                "interface": {"type": "keyword"},
                                "timestamp": {"type": "date"},
                                "source_file": {"type": "keyword"},
                            }
                        },
                        "windows": {
                            "properties": {
                                "event_id": {"type": "integer"},
                                "channel": {"type": "keyword"},
                                "provider": {"type": "keyword"},
                                "computer": {"type": "keyword"},
                                "record_id": {"type": "keyword"},
                                "record_number": {"type": "keyword"},
                                "process_id": {"type": "keyword"},
                                "thread_id": {"type": "keyword"},
                                "opcode": {"type": "keyword"},
                                "level": {"type": "keyword"},
                                "keywords": {"type": "keyword"},
                                "event_data_summary": {"type": "text"},
                                "event_data": {"type": "object", "enabled": False},
                                "payload": {"type": "object", "enabled": False},
                                "raw_xml": {"type": "text"},
                                "logon_type": {"type": "keyword"},
                                "service_name": {"type": "keyword"},
                                "task_name": {"type": "keyword"},
                                "authentication_package": {"type": "keyword"},
                                "logon_process": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "sub_status": {"type": "keyword"},
                                "failure_reason": {"type": "keyword"},
                                "session_id": {"type": "keyword"},
                                "session_name": {"type": "keyword"},
                                "reason": {"type": "keyword"},
                            }
                        },
                        "ingest": {
                            "properties": {
                                "processed_at": {"type": "date"},
                            }
                        },
                        "detection": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "threat_name": {"type": "keyword"},
                                "threat_id": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "remediation_action": {"type": "keyword"},
                                "detection_source": {"type": "keyword"},
                                "product_name": {"type": "keyword"},
                                "engine_version": {"type": "keyword"},
                                "signature_version": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "resource": {"type": "keyword"},
                                "container_file": {"type": "keyword"},
                                "user": {"type": "keyword"},
                                "user_sid": {"type": "keyword"},
                                "timestamp": {"type": "date"},
                                "source_file": {"type": "keyword"},
                                "line_number": {"type": "integer", "ignore_malformed": True},
                                "error_code": {"type": "keyword"},
                            }
                        },
                        "task": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "uri": {"type": "keyword"},
                                "command": {"type": "keyword"},
                                "arguments": {"type": "text"},
                                "author": {"type": "keyword"},
                                "run_as": {"type": "keyword"},
                                "description": {"type": "text"},
                                "enabled": {"type": "boolean"},
                                "hidden": {"type": "boolean"},
                                "source_file": {"type": "keyword"},
                                "date": {"type": "date"},
                                "version": {"type": "keyword"},
                                "user_id": {"type": "keyword"},
                                "group_id": {"type": "keyword"},
                                "logon_type": {"type": "keyword"},
                                "run_level": {"type": "keyword"},
                                "actions": {"type": "object", "enabled": False},
                                "triggers": {"type": "object", "enabled": False},
                                "com_handler_class_id": {"type": "keyword"},
                                "com_handler_data": {"type": "text"},
                                "settings": {"type": "object", "enabled": False},
                                "trigger_summary": {"type": "text"},
                                "action_summary": {"type": "text"},
                                "artifact_type": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                            }
                        },
                        "service": {
                            "properties": {
                                "artifact_type": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "display_name": {"type": "keyword"},
                                "description": {"type": "text"},
                                "image_path": {"type": "keyword"},
                                "image_path_expanded": {"type": "keyword"},
                                "service_dll_expanded": {"type": "keyword"},
                                "start_type": {"type": "keyword"},
                                "start_type_raw": {"type": "integer", "ignore_malformed": True},
                                "service_type": {"type": "keyword"},
                                "service_type_raw": {"type": "integer", "ignore_malformed": True},
                                "error_control": {"type": "keyword"},
                                "object_name": {"type": "keyword"},
                                "account": {"type": "keyword"},
                                "group": {"type": "keyword"},
                                "depend_on_service": {"type": "keyword"},
                                "depend_on_group": {"type": "keyword"},
                                "failure_actions": {"type": "text"},
                                "required_privileges": {"type": "keyword"},
                                "launch_protected": {"type": "keyword"},
                                "service_sid_type": {"type": "keyword"},
                                "delayed_auto_start": {"type": "boolean"},
                                "trigger_info": {"type": "text"},
                                "service_dll": {"type": "keyword"},
                                "key_path": {"type": "keyword"},
                                "control_set": {"type": "keyword"},
                                "source_file": {"type": "keyword"},
                                "last_write": {"type": "date"},
                                "parser_status": {"type": "keyword"},
                                "timestamp_interpretation": {"type": "keyword"},
                            }
                        },
                        "powershell": {
                            "properties": {
                                "script_block_text": {"type": "text"},
                                "script_block_id": {"type": "keyword"},
                                "path": {"type": "keyword"},
                                "message_number": {"type": "keyword"},
                                "message_total": {"type": "keyword"},
                                "command_invocation": {"type": "text"},
                                "parameter_binding": {"type": "text"},
                                "payload": {"type": "text"},
                                "context_info": {"type": "text"},
                                "user": {"type": "keyword"},
                            }
                        },
                        "winrm": {
                            "properties": {
                                "shell_id": {"type": "keyword"},
                                "command_id": {"type": "keyword"},
                                "resource_uri": {"type": "keyword"},
                                "plugin": {"type": "keyword"},
                                "operation": {"type": "keyword"},
                            }
                        },
                        "suspicious_reasons": {"type": "keyword"},
                        "rule": {
                            "properties": {
                                "engine": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "namespace": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "tags": {"type": "keyword"},
                            }
                        },
                        "memory": {
                            "properties": {
                                "plugin": {"type": "keyword"},
                                "process_offset": {"type": "keyword"},
                                "virtual_address": {"type": "keyword"},
                            }
                        },
                        "linux": {"type": "object", "enabled": True},
                        "macos": {"type": "object", "enabled": True},
                        "raw": {"type": "object", "enabled": False},
                        "data_quality": {"type": "keyword"},
                    }
                }
                },
            )
        except (AuthorizationException, RequestError, TransportError) as exc:
            lowered = str(exc).lower()
            preflight = get_opensearch_ingest_preflight(case_id)
            preflight["error"] = f"{exc.__class__.__name__}: {exc}"
            if "index_create_block_exception" in lowered or "create-index blocked" in lowered or "create index blocked" in lowered:
                preflight["blocking_reasons"].append("cluster_create_index_blocked")
            elif "blocked by" in lowered or "read-only" in lowered or "read_only_allow_delete" in lowered:
                preflight["blocking_reasons"].append("cluster_write_blocked")
            raise OpenSearchIngestBlockedError(
                "OpenSearch is not writable or cannot create indices. Ingest has not started.",
                details=preflight,
            ) from exc
    else:
        try:
            client.indices.put_mapping(
                index=index,
                body={
                    "properties": {
                        "stable_event_id": {"type": "keyword"},
                        "event_fingerprint": {"type": "keyword"},
                        "event_fingerprint_version": {"type": "keyword"},
                        "event": {
                            "properties": {
                                "provider": {"type": "keyword"},
                                "channel": {"type": "keyword"},
                            }
                        },
                        "artifact": {
                            "properties": {
                                "parser_backend": {"type": "keyword"},
                                "backend_variant": {"type": "keyword"},
                                "default_backend": {"type": "boolean"},
                                "advanced_backend": {"type": "boolean"},
                                "supersedes_internal": {"type": "boolean"},
                                "source_artifact_fingerprint": {"type": "keyword"},
                            }
                        },
                        "backend_variant": {"type": "keyword"},
                        "parser_backend": {"type": "keyword"},
                        "host": {
                            "properties": {
                                "aliases": {"type": "keyword"},
                                "identity_id": {"type": "keyword"},
                                "identity_confidence": {"type": "keyword"},
                            }
                        },
                        "observed_host": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "hostname": {"type": "keyword"},
                            }
                        },
                        "process": {
                            "properties": {
                                "entity_id": {"type": "keyword"},
                                "guid": {"type": "keyword"},
                                "executable": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                                "parent_entity_id": {"type": "keyword"},
                                "parent_pid": {"type": "keyword"},
                                "parent": {
                                    "properties": {
                                        "entity_id": {"type": "keyword"},
                                        "guid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "pid": {"type": "keyword"},
                                        "path": {"type": "keyword"},
                                        "executable": {"type": "keyword"},
                                        "command_line": {"type": "text"},
                                    }
                                },
                                "hash": {
                                    "properties": {
                                        "md5": {"type": "keyword"},
                                        "sha1": {"type": "keyword"},
                                        "sha256": {"type": "keyword"},
                                        "imphash": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "parent": {
                            "properties": {
                                "process": {
                                    "properties": {
                                        "entity_id": {"type": "keyword"},
                                        "guid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "pid": {"type": "keyword"},
                                        "path": {"type": "keyword"},
                                        "executable": {"type": "keyword"},
                                        "command_line": {"type": "text"},
                                    }
                                }
                            }
                        },
                        "registry": {
                            "properties": {
                                "path": {"type": "keyword"},
                                "data": {"type": "text"},
                                "event_type": {"type": "keyword"},
                            }
                        },
                        "dns": {
                            "properties": {
                                "query": {"type": "keyword"},
                                "question": {"properties": {"name": {"type": "keyword"}}},
                                "answers": {"type": "keyword"},
                            }
                        },
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not update stable event mappings for %s: %s", index, exc)
        _apply_safe_index_settings(client, index)
    return index


def _truncate_large_value(value: object) -> object:
    if isinstance(value, str) and len(value) > MAX_RAW_FIELD_CHARS:
        return f"{value[:MAX_RAW_FIELD_CHARS]}...[truncated]"
    if isinstance(value, dict):
        return {key: _truncate_large_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_truncate_large_value(item) for item in value]
    return value


def sanitize_search_text(value: object, *, max_chars: int = SEARCH_TEXT_MAX_CHARS) -> tuple[str, list[str]]:
    flags: list[str] = []
    if value is None:
        return "", flags
    if isinstance(value, str):
        text = value
    elif isinstance(value, (list, tuple, set)):
        text = " | ".join(str(item) for item in value if item not in (None, ""))
        flags.append("search_text_sanitized")
    elif isinstance(value, dict):
        text = " | ".join(f"{key}={item}" for key, item in list(value.items())[:50] if item not in (None, ""))
        flags.append("search_text_sanitized")
    else:
        text = str(value)
        flags.append("search_text_sanitized")
    if "\x00" in text:
        text = text.replace("\x00", "")
        flags.append("search_text_removed_control_chars")
    cleaned = _SEARCH_TEXT_CONTROL_CHARS.sub(" ", text)
    if cleaned != text and "search_text_removed_control_chars" not in flags:
        flags.append("search_text_removed_control_chars")
    cleaned = _SEARCH_TEXT_WHITESPACE.sub(" ", cleaned).strip()
    if cleaned != text and "search_text_sanitized" not in flags:
        flags.append("search_text_sanitized")
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rstrip()
        flags.append("search_text_truncated")
    return cleaned, list(dict.fromkeys(flags))


def sanitize_document_for_index(document: dict) -> dict:
    sanitized = copy.deepcopy(document)
    raw_value = sanitized.get("raw")
    if raw_value is not None:
        raw_value = _truncate_large_value(raw_value)
        raw_bytes = len(orjson.dumps(raw_value))
        if raw_bytes > MAX_RAW_JSON_BYTES:
            if isinstance(raw_value, dict):
                trimmed = {}
                for key, value in raw_value.items():
                    trimmed[key] = value
                    if len(orjson.dumps(trimmed)) > MAX_RAW_JSON_BYTES // 2:
                        break
                raw_value = {"truncated": True, "kept_fields": trimmed, "note": "raw payload exceeded index limit and was reduced"}
            else:
                raw_value = {"truncated": True, "note": "raw payload exceeded index limit and was reduced"}
        sanitized["raw"] = raw_value
    search_text, search_flags = sanitize_search_text(sanitized.get("search_text"))
    sanitized["search_text"] = search_text
    if search_flags:
        dq = list(sanitized.get("data_quality") or [])
        dq.extend(search_flags)
        sanitized["data_quality"] = list(dict.fromkeys(str(item) for item in dq if item not in (None, "")))
    return sanitized


def _iter_bulk_chunks(index: str, documents: Iterable[dict], *, max_bulk_docs: int, max_bulk_bytes: int) -> Iterable[list[dict]]:
    chunk: list[dict] = []
    chunk_bytes = 0
    for document in documents:
        sanitized = sanitize_document_for_index(document)
        action = {"index": {"_index": index, "_id": sanitized["event_id"]}}
        action_bytes = len(orjson.dumps(action))
        doc_bytes = len(orjson.dumps(sanitized))
        item_bytes = action_bytes + doc_bytes
        if chunk and (len(chunk) >= max_bulk_docs * 2 or chunk_bytes + item_bytes > max_bulk_bytes):
            yield chunk
            chunk = []
            chunk_bytes = 0
        chunk.extend([action, sanitized])
        chunk_bytes += item_bytes
    if chunk:
        yield chunk


def _bulk_errors(response: dict) -> list[str]:
    if not response.get("errors"):
        return []
    errors: list[str] = []
    for item in response.get("items", []):
        action = item.get("index") or item.get("create") or item.get("update") or item.get("delete") or {}
        error = action.get("error")
        if error:
            doc_id = action.get("_id", "?")
            reason = error.get("reason") if isinstance(error, dict) else str(error)
            error_type = error.get("type") if isinstance(error, dict) else "bulk_error"
            errors.append(f"{doc_id}: {error_type}: {reason}")
            if len(errors) >= 20:
                break
    return errors


def _build_bulk_body(index: str, documents: Iterable[dict]) -> list[dict]:
    body: list[dict] = []
    for document in documents:
        sanitized = sanitize_document_for_index(document)
        body.extend([{"index": {"_index": index, "_id": sanitized["event_id"]}}, sanitized])
    return body


def _is_retryable_bulk_exception(exc: Exception) -> bool:
    text = f"{exc.__class__.__name__} {exc}".lower()
    return any(
        token in text
        for token in (
            "timeout",
            "timed out",
            "connectiontimeout",
            "readtimeouterror",
            "temporarily unavailable",
            "connection refused",
            "remote disconnected",
        )
    )


def _extract_docs_from_bulk_body(body: list[dict]) -> list[dict]:
    return [copy.deepcopy(item) for item in body[1::2]]


def _extract_doc_ids_from_bulk_body(body: list[dict]) -> list[str]:
    ids: list[str] = []
    for action in body[0::2]:
        index_meta = (action or {}).get("index") or {}
        doc_id = index_meta.get("_id")
        if doc_id:
            ids.append(str(doc_id))
    return ids


def _count_existing_doc_ids(client: OpenSearch, index: str, doc_ids: list[str]) -> int:
    if not doc_ids or not hasattr(client, "mget"):
        return 0
    try:
        response = client.mget(index=index, body={"ids": doc_ids})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not verify existing bulk ids for %s: %s", index, exc)
        return 0
    return sum(1 for item in (response.get("docs") or []) if item.get("found"))


def bulk_index_events_with_report(
    case_id: str,
    documents: Iterable[dict],
    *,
    index: str | None = None,
    client: OpenSearch | None = None,
    refresh: bool = True,
    max_bulk_docs: int | None = None,
    max_bulk_bytes: int | None = None,
    request_timeout: int = 120,
    attempts: int = 3,
    backoff_seconds: tuple[float, ...] = (2.0, 5.0, 10.0),
    apply_host_identity: bool = True,
    apply_fingerprint: bool = True,
) -> dict:
    index = index or ensure_case_index(case_id)
    if max_bulk_docs is None or max_bulk_bytes is None:
        with SessionLocal() as db:
            _debug_db_trace("bulk_index_events_with_report.runtime_settings", db=db, case_id=case_id)
            runtime = load_runtime_settings(db)
        max_bulk_docs = int(runtime["OPENSEARCH_BULK_DOCS"])
        max_bulk_bytes = int(runtime["OPENSEARCH_BULK_BYTES"])
    docs_list = list(documents)
    if apply_host_identity:
        with SessionLocal() as db:
            _debug_db_trace("bulk_index_events_with_report.host_identity", db=db, case_id=case_id)
            for document in docs_list:
                if isinstance(document, dict):
                    apply_case_host_identity(db, case_id, document)
                    apply_event_fingerprint(document)
            host_identity_stats = get_host_identity_runtime_stats(db)
    else:
        for document in docs_list:
            if isinstance(document, dict) and apply_fingerprint:
                apply_event_fingerprint(document)
        host_identity_stats = {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
            "warnings": ["host_identity_skipped_for_parallel_bulk"],
        }
    client = client or get_opensearch_client(timeout_seconds=request_timeout)
    report = {
        "attempted": bool(docs_list),
        "success": True,
        "timeouts": 0,
        "retries": 0,
        "chunk_size_initial": int(max_bulk_docs),
        "chunk_size_final": int(max_bulk_docs),
        "request_timeout": int(request_timeout),
        "documents_expected": len(docs_list),
        "documents_indexed": 0,
        "documents_recovered_after_timeout": 0,
        "warnings": [],
        "failed_items": [],
        "host_identity": {
            "upserts": int(host_identity_stats.get("upserts") or 0),
            "conflicts_recovered": int(host_identity_stats.get("conflicts_recovered") or 0),
            "host_identity_conflict_retries": int(host_identity_stats.get("host_identity_conflict_retries") or 0),
            "aliases_updated": int(host_identity_stats.get("aliases_updated") or 0),
        },
    }
    for warning in host_identity_stats.get("warnings") or []:
        if warning not in report["warnings"]:
            report["warnings"].append(warning)
    start = time.perf_counter()
    batches = 0
    max_attempts = max(int(attempts), 1)
    pending_chunks = [body for body in _iter_bulk_chunks(index, docs_list, max_bulk_docs=max_bulk_docs, max_bulk_bytes=max_bulk_bytes)]
    while pending_chunks:
        body = pending_chunks.pop(0)
        chunk_docs = _extract_docs_from_bulk_body(body)
        chunk_ids = _extract_doc_ids_from_bulk_body(body)
        chunk_attempt = 1
        while True:
            batches += 1
            try:
                response = client.bulk(body=body, refresh=refresh)
                failed_items = _bulk_errors(response)
                if failed_items:
                    report["failed_items"].extend(failed_items)
                    report["success"] = False
                    preview = "; ".join(report["failed_items"][:20])
                    raise RuntimeError(f"OpenSearch bulk indexing failed for {len(report['failed_items'])} item(s). First errors: {preview}")
                report["documents_indexed"] += len(chunk_docs)
                break
            except RuntimeError:
                raise
            except Exception as exc:  # noqa: BLE001
                if not _is_retryable_bulk_exception(exc):
                    raise
                report["timeouts"] += 1
                recovered_count = _count_existing_doc_ids(client, index, chunk_ids)
                if recovered_count >= len(chunk_ids):
                    report["documents_indexed"] += len(chunk_docs)
                    report["documents_recovered_after_timeout"] += len(chunk_docs)
                    report["warnings"].append("opensearch_bulk_timeout_recovered")
                    break
                if chunk_attempt >= max_attempts:
                    report["success"] = False
                    raise
                report["retries"] += 1
                report["warnings"].append("opensearch_bulk_retry_used")
                backoff = backoff_seconds[min(chunk_attempt - 1, max(len(backoff_seconds) - 1, 0))] if backoff_seconds else 0
                if backoff > 0:
                    time.sleep(backoff)
                if len(chunk_docs) > 1:
                    midpoint = max(1, len(chunk_docs) // 2)
                    split_docs = [chunk_docs[:midpoint], chunk_docs[midpoint:]]
                    split_docs = [items for items in split_docs if items]
                    report["chunk_size_final"] = min(report["chunk_size_final"], max(len(items) for items in split_docs))
                    replacement = [_build_bulk_body(index, items) for items in split_docs]
                    pending_chunks = replacement + pending_chunks
                    break
                body = _build_bulk_body(index, chunk_docs)
                chunk_attempt += 1
                continue
    elapsed = max(time.perf_counter() - start, 0.001)
    logger.info(
        "Indexed %s docs into %s in %s batches over %.2fs (%.2f docs/sec, retries=%s, timeouts=%s)",
        report["documents_indexed"],
        index,
        batches,
        elapsed,
        report["documents_indexed"] / elapsed,
        report["retries"],
        report["timeouts"],
    )
    return report


def bulk_index_events(
    case_id: str,
    documents: Iterable[dict],
    *,
    index: str | None = None,
    client: OpenSearch | None = None,
    refresh: bool = True,
    max_bulk_docs: int | None = None,
    max_bulk_bytes: int | None = None,
) -> int:
    report = bulk_index_events_with_report(
        case_id,
        documents,
        index=index,
        client=client,
        refresh=refresh,
        max_bulk_docs=max_bulk_docs,
        max_bulk_bytes=max_bulk_bytes,
    )
    if not report.get("success"):
        preview = "; ".join((report.get("failed_items") or [])[:20])
        raise RuntimeError(f"OpenSearch bulk indexing failed for {len(report.get('failed_items') or [])} item(s). First errors: {preview}")
    return int(report.get("documents_indexed") or 0)


def refresh_index(
    index: str,
    *,
    request_timeout: int = 60,
    attempts: int = 3,
    backoff_seconds: tuple[float, ...] = (2.0, 5.0, 10.0),
    raise_on_error: bool = True,
) -> dict:
    client = get_opensearch_client(timeout_seconds=request_timeout)
    report = {
        "attempted": True,
        "success": False,
        "timeout": False,
        "non_fatal": not raise_on_error,
        "attempts": 0,
        "request_timeout": int(request_timeout),
        "error_summary": None,
    }
    last_error: Exception | None = None
    max_attempts = max(int(attempts), 1)
    for attempt in range(1, max_attempts + 1):
        report["attempts"] = attempt
        try:
            client.indices.refresh(index=index)
            report["success"] = True
            report["timeout"] = False
            report["error_summary"] = None
            return report
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            error_name = exc.__class__.__name__
            error_text = str(exc)
            lowered = f"{error_name} {error_text}".lower()
            report["timeout"] = report["timeout"] or ("timeout" in lowered)
            report["error_summary"] = f"{error_name}: {error_text}"
            if attempt < max_attempts:
                backoff = backoff_seconds[min(attempt - 1, max(len(backoff_seconds) - 1, 0))] if backoff_seconds else 0
                if backoff > 0:
                    time.sleep(backoff)
                continue
            if raise_on_error:
                raise
            logger.warning(
                "Non-fatal OpenSearch refresh failure for %s after %s attempt(s): %s",
                index,
                attempt,
                report["error_summary"],
            )
            return report
    if raise_on_error and last_error is not None:
        raise last_error
    return report


def search_documents(index: str, body: dict) -> dict:
    client = get_opensearch_client()
    if not index_exists(client, index):
        return {"hits": {"total": {"value": 0}, "hits": []}}
    return client.search(index=index, body=body, params={"ignore_unavailable": "true"})


def count_documents(index: str, query: dict | None = None) -> dict:
    client = get_opensearch_client()
    if not index_exists(client, index):
        return {"count": 0, "relation": "eq", "source": "count_api"}
    body = {"query": query} if query else {"query": {"match_all": {}}}
    result = client.count(index=index, body=body, params={"ignore_unavailable": "true"})
    return {"count": int(result.get("count", 0)), "relation": "eq", "source": "count_api"}


def iter_case_events(case_id: str, query: dict | None = None, batch_size: int = 1000, max_docs: int = 100000) -> Iterable[dict]:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return []
    sort = [
        {"@timestamp": {"order": "asc", "missing": "_last"}},
        {"event_id": {"order": "asc", "missing": "_last"}},
    ]
    search_after: list | None = None
    yielded = 0

    def generator():
        nonlocal search_after, yielded
        while yielded < max_docs:
            body = {
                "size": batch_size,
                "sort": sort,
                "query": query or {"match_all": {}},
            }
            if search_after is not None:
                body["search_after"] = search_after
            result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                yielded += 1
                yield {"id": hit["_id"], **hit["_source"]}
                if yielded >= max_docs:
                    break
            search_after = hits[-1].get("sort")
            if len(hits) < batch_size:
                break

    return generator()


def fetch_event_by_id(case_id: str, event_id: str | None, *, event_index: str | None = None, opensearch_id: str | None = None) -> dict | None:
    client = get_opensearch_client()
    if event_index and opensearch_id:
        try:
            hit = client.get(index=event_index, id=opensearch_id, params={"ignore_unavailable": "true"})
            if hit and hit.get("_source", {}).get("case_id") == case_id:
                return {"id": hit["_id"], **hit["_source"]}
        except Exception:  # noqa: BLE001
            pass
    if not event_id:
        return None
    indices_to_try = [get_events_index(case_id), get_events_index(None)]
    search_bodies = [
        {
            "size": 1,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"case_id": case_id}},
                        {"term": {"event_id": event_id}},
                    ]
                }
            },
        },
        {
            "size": 1,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"case_id": case_id}},
                        {"term": {"event_id.keyword": event_id}},
                    ]
                }
            },
        },
    ]
    for index in indices_to_try:
        if not index_exists(client, index):
            continue
        for body in search_bodies:
            try:
                result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
            except Exception:  # noqa: BLE001
                continue
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                hit = hits[0]
                return {"id": hit["_id"], **hit["_source"]}
        try:
            hit = client.get(index=index, id=event_id, params={"ignore_unavailable": "true"})
        except Exception:  # noqa: BLE001
            hit = None
        if hit and hit.get("_source", {}).get("case_id") == case_id:
            return {"id": hit["_id"], **hit["_source"]}
    return None


def delete_events_by_evidence(evidence_id: str, case_id: str) -> int:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        logger.info("Case index %s does not exist while deleting evidence %s events", index, evidence_id)
        return 0
    try:
        result = client.delete_by_query(
            index=index,
            body={"query": {"term": {"evidence_id": evidence_id}}},
            params={"refresh": "true", "ignore_unavailable": "true"},
        )
        deleted = result.get("deleted", 0)
        logger.info("Deleted %s OpenSearch events for evidence %s in case %s", deleted, evidence_id, case_id)
        return deleted
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not delete OpenSearch events for evidence %s in case %s: %s", evidence_id, case_id, exc)
        return 0


def delete_case_index(case_id: str) -> bool:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        logger.info("Case index %s does not exist while deleting case %s", index, case_id)
        return False
    try:
        client.indices.delete(index=index, params={"ignore_unavailable": "true"})
        logger.info("Deleted OpenSearch index %s for case %s", index, case_id)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not delete OpenSearch index %s for case %s: %s", index, case_id, exc)
        return False
