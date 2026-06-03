import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette._utils import AwaitableOrContextManagerWrapper
from starlette.requests import Request

from app.api import routes_activity, routes_cases, routes_command_history, routes_email_artifacts, routes_evidence, routes_events, routes_findings, routes_hosts, routes_indicators, routes_motw, routes_persistence, routes_reports, routes_rules, routes_search, routes_system, routes_tags, routes_timeline, routes_velociraptor
from app.core.config import get_settings
from app.core.database import init_db
from app.core.opensearch import ensure_events_indices_safe_settings
from app.services.opensearch_dashboards import auto_bootstrap_dashboards


settings = get_settings()
logging.basicConfig(level=settings.backend_log_level)


_original_request_get_form = Request._get_form


async def _patched_request_get_form(
    self: Request,
    *,
    max_files: int | float = settings.backend_multipart_max_files,
    max_fields: int | float = settings.backend_multipart_max_fields,
    max_part_size: int = settings.backend_multipart_max_part_size,
):
    return await _original_request_get_form(
        self,
        max_files=max_files,
        max_fields=max_fields,
        max_part_size=max_part_size,
    )


def _patched_request_form(
    self: Request,
    *,
    max_files: int | float = settings.backend_multipart_max_files,
    max_fields: int | float = settings.backend_multipart_max_fields,
    max_part_size: int = settings.backend_multipart_max_part_size,
):
    return AwaitableOrContextManagerWrapper(
        self._get_form(max_files=max_files, max_fields=max_fields, max_part_size=max_part_size)
    )


Request._get_form = _patched_request_get_form
Request.form = _patched_request_form


app = FastAPI(title="Kairon DFIR API", version="0.1.0")
allow_all_origins = settings.cors_origins == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=not allow_all_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_cases.router)
app.include_router(routes_activity.router)
app.include_router(routes_command_history.router)
app.include_router(routes_email_artifacts.router)
app.include_router(routes_evidence.router)
app.include_router(routes_events.router)
app.include_router(routes_findings.router)
app.include_router(routes_hosts.router)
app.include_router(routes_indicators.router)
app.include_router(routes_motw.router)
app.include_router(routes_persistence.router)
app.include_router(routes_reports.router)
app.include_router(routes_rules.router)
app.include_router(routes_search.router)
app.include_router(routes_timeline.router)
app.include_router(routes_system.router)
app.include_router(routes_tags.router)
app.include_router(routes_velociraptor.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    ensure_events_indices_safe_settings()
    auto_bootstrap_dashboards()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
