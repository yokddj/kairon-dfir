from __future__ import annotations

from base64 import b64encode
import json
import logging
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from fastapi import Request as FastAPIRequest
from sqlalchemy.orm import Session

from app.core.app_settings import get_setting
from app.core.config import get_settings
from app.core.opensearch import count_documents, get_events_index, get_opensearch_client


logger = logging.getLogger(__name__)
settings = get_settings()

OPENSEARCH_DASHBOARDS_PUBLIC_URL_KEY = "OPENSEARCH_DASHBOARDS_PUBLIC_URL"
DEFAULT_DATA_VIEW_ID = "dfir-events"
DEFAULT_DATA_VIEW_NAME = "DFIR Events"
DEFAULT_DISCOVER_COLUMNS = [
    "@timestamp",
    "case_id",
    "evidence_id",
    "host.name",
    "artifact.type",
    "event.type",
    "process.name",
    "file.path",
    "user.name",
    "risk_score",
    "message",
    "source_file",
]


def _dashboard_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "osd-xsrf": "true",
    }
    username = settings.opensearch_dashboards_username or settings.opensearch_user
    password = settings.opensearch_dashboards_password or settings.opensearch_password
    if username and password:
        token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    return headers


def _dashboard_request(method: str, path: str, payload: dict | None = None, timeout: int = 5) -> tuple[int, object | None, str | None]:
    url = f"{settings.opensearch_dashboards_internal_url.rstrip('/')}{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=body, headers=_dashboard_headers(), method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else None, None
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        try:
            data = json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            data = raw or None
        return exc.code, data, raw or str(exc)
    except URLError as exc:
        return 0, None, str(exc)
    except Exception as exc:  # noqa: BLE001
        return 0, None, str(exc)


def dashboards_public_url(db: Session | None = None, request: FastAPIRequest | None = None) -> str:
    configured = str(get_setting(db, OPENSEARCH_DASHBOARDS_PUBLIC_URL_KEY, settings.opensearch_dashboards_public_url) if db else settings.opensearch_dashboards_public_url).strip()
    if not configured:
        if request is None:
            return ""
        parsed_internal = urlsplit(settings.opensearch_dashboards_internal_url)
        hostname = request.url.hostname or ""
        port = parsed_internal.port or 5601
        return urlunsplit((request.url.scheme, f"{hostname}:{port}", "", "", "")).rstrip("/")
    if request is None:
        return configured.rstrip("/")
    parsed = urlsplit(configured)
    hostname = (parsed.hostname or "").strip().lower()
    request_hostname = (request.url.hostname or "").strip().lower()
    if hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "opensearch-dashboards"}:
        port = parsed.port or 5601
        return urlunsplit((request.url.scheme, f"{request_hostname}:{port}", parsed.path.rstrip("/"), "", "")).rstrip("/")
    return configured.rstrip("/")


def _find_data_view(index_pattern: str) -> tuple[dict | None, list[str]]:
    warnings: list[str] = []
    search = quote(f'"{index_pattern}"')
    status, payload, error = _dashboard_request("GET", f"/api/saved_objects/_find?type=index-pattern&search_fields=title&search={search}&per_page=100")
    if status == 404:
        warnings.append("saved_objects_api_unavailable")
        return None, warnings
    if status in {401, 403}:
        warnings.append("dashboards_auth_failed")
        return None, warnings
    if status == 0:
        warnings.append("dashboards_unreachable")
        if error:
            warnings.append(error)
        return None, warnings
    if status >= 400:
        warnings.append("dashboards_query_failed")
        if error:
            warnings.append(error)
        return None, warnings
    for item in (payload or {}).get("saved_objects", []) if isinstance(payload, dict) else []:
        attributes = item.get("attributes") or {}
        if attributes.get("title") == index_pattern:
            return item, warnings
    return None, warnings


def _data_view_needs_repair(item: dict | None, *, index_pattern: str, time_field: str) -> bool:
    if not item:
        return False
    attributes = item.get("attributes") or {}
    return attributes.get("title") != index_pattern or attributes.get("timeFieldName") != time_field


def _data_view_payload(index_pattern: str, time_field: str) -> dict:
    return {
        "attributes": {
            "title": index_pattern,
            "name": DEFAULT_DATA_VIEW_NAME,
            "timeFieldName": time_field,
            "allowNoIndex": True,
        }
    }


def bootstrap_dashboards_data_view(*, repair: bool = False) -> dict:
    index_pattern = settings.opensearch_dashboards_index_pattern
    time_field = settings.opensearch_dashboards_time_field
    existing, warnings = _find_data_view(index_pattern)
    if existing and not repair and not _data_view_needs_repair(existing, index_pattern=index_pattern, time_field=time_field):
        return {
            "created": False,
            "updated": False,
            "data_view_id": existing.get("id"),
            "data_view_title": (existing.get("attributes") or {}).get("title", index_pattern),
            "time_field": (existing.get("attributes") or {}).get("timeFieldName", time_field),
            "message": "DFIR Events data view is ready",
            "warnings": warnings,
        }
    payload = _data_view_payload(index_pattern, time_field)
    if existing:
        data_view_id = existing.get("id") or DEFAULT_DATA_VIEW_ID
        status, response, error = _dashboard_request("POST", f"/api/saved_objects/index-pattern/{data_view_id}?overwrite=true", payload)
        if status >= 400 or status == 0:
            return {
                "created": False,
                "updated": False,
                "data_view_id": data_view_id,
                "data_view_title": index_pattern,
                "time_field": time_field,
                "message": "Could not repair DFIR Events data view",
                "warnings": warnings + ([error] if error else []),
            }
        return {
            "created": False,
            "updated": True,
            "data_view_id": (response or {}).get("id", data_view_id) if isinstance(response, dict) else data_view_id,
            "data_view_title": index_pattern,
            "time_field": time_field,
            "message": "DFIR Events data view is ready",
            "warnings": warnings,
        }
    status, response, error = _dashboard_request("POST", f"/api/saved_objects/index-pattern/{DEFAULT_DATA_VIEW_ID}", payload)
    if status >= 400 or status == 0:
        return {
            "created": False,
            "updated": False,
            "data_view_id": None,
            "data_view_title": index_pattern,
            "time_field": time_field,
            "message": "Could not create DFIR Events data view",
            "warnings": warnings + ([error] if error else []),
        }
    return {
        "created": True,
        "updated": False,
        "data_view_id": (response or {}).get("id", DEFAULT_DATA_VIEW_ID) if isinstance(response, dict) else DEFAULT_DATA_VIEW_ID,
        "data_view_title": index_pattern,
        "time_field": time_field,
        "message": "DFIR Events data view is ready",
        "warnings": warnings,
    }


def dashboards_admin_status(*, db: Session | None = None, request: FastAPIRequest | None = None) -> dict:
    index_pattern = settings.opensearch_dashboards_index_pattern
    time_field = settings.opensearch_dashboards_time_field
    public_url = dashboards_public_url(db, request)
    warnings: list[str] = []
    opensearch_available = True
    events_count = 0
    matching_indices: list[str] = []
    try:
        client = get_opensearch_client()
        matching_indices = list((client.indices.get(index=index_pattern, params={"ignore_unavailable": "true"}) or {}).keys())
        count_info = count_documents(get_events_index(None), None)
        events_count = int(count_info.get("count") or 0)
    except Exception as exc:  # noqa: BLE001
        opensearch_available = False
        warnings.append(f"opensearch_unavailable:{exc}")
    root_status, _, root_error = _dashboard_request("GET", "/api/status")
    dashboards_available = root_status in {200, 302}
    if not dashboards_available:
        if root_status in {401, 403}:
            warnings.append("dashboards_auth_failed")
        elif root_status == 0:
            warnings.append("dashboards_unreachable")
        else:
            warnings.append("dashboards_unavailable")
        if root_error:
            warnings.append(root_error)
    existing, find_warnings = _find_data_view(index_pattern)
    warnings.extend(find_warnings)
    data_view_exists = existing is not None
    data_view_id = existing.get("id") if existing else None
    data_view_title = (existing.get("attributes") or {}).get("title", index_pattern) if existing else index_pattern
    resolved_time_field = (existing.get("attributes") or {}).get("timeFieldName", time_field) if existing else time_field
    if existing and _data_view_needs_repair(existing, index_pattern=index_pattern, time_field=time_field):
        warnings.append("data_view_needs_repair")
    warnings = list(dict.fromkeys(warnings))
    return {
        "opensearch": {
            "available": opensearch_available,
            "events_index_pattern": index_pattern,
            "events_count": events_count,
            "indices": matching_indices,
        },
        "dashboards": {
            "available": dashboards_available,
            "url": public_url,
            "data_view_exists": data_view_exists,
            "data_view_id": data_view_id,
            "data_view_title": data_view_title,
            "time_field": resolved_time_field,
            "warnings": warnings,
            "recommended_columns": DEFAULT_DISCOVER_COLUMNS,
        },
    }


def auto_bootstrap_dashboards() -> None:
    if not settings.dfir_auto_bootstrap_dashboards:
        return
    try:
        result = bootstrap_dashboards_data_view(repair=False)
        logger.info("OpenSearch Dashboards bootstrap result: %s", result.get("message"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not auto-bootstrap OpenSearch Dashboards: %s", exc)
