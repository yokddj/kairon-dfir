import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette._utils import AwaitableOrContextManagerWrapper
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.api import routes_activity, routes_admin, routes_auth, routes_cases, routes_command_history, routes_email_artifacts, routes_evidence, routes_evidence_preflight, routes_events, routes_findings, routes_host_facts, routes_host_users, routes_hosts, routes_hunting, routes_indicators, routes_linux_auth, routes_motw, routes_persistence, routes_reports, routes_rules, routes_search, routes_system, routes_tags, routes_timeline, routes_velociraptor
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

# Public endpoints that don't require authentication
PUBLIC_PATH_PREFIXES = [
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/needs-setup",
    "/api/auth/setup",
    "/api/system/version",
    "/api/system/health",
    "/api/system/status",
    "/api/system/capabilities",
    "/api/docs",
    "/api/openapi.json",
    "/api/redoc",
]
PUBLIC_PATH_PREFIXES_SET = set(PUBLIC_PATH_PREFIXES)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip auth if disabled (e.g. during tests)
        if not settings.auth_enabled:
            return await call_next(request)
        
        path = request.url.path
        # Allow public paths
        for prefix in PUBLIC_PATH_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)
        # Allow OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)
        # Allow static files
        if path.startswith("/static") or path.startswith("/favicon"):
            return await call_next(request)
        
        # Check session for all other paths
        token = request.cookies.get("kairon_session")
        if not token:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
        
        from app.core.database import SessionLocal
        from app.services.auth_utils import hash_token
        from app.models.session import Session as UserSession
        from app.models.user import User
        from datetime import datetime, timezone
        
        db = SessionLocal()
        try:
            token_h = hash_token(token)
            session = db.query(UserSession).filter(
                UserSession.token_hash == token_h,
                UserSession.revoked_at == None,
            ).first()
            if not session:
                return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
            if session.expires_at < datetime.now(timezone.utc).isoformat():
                session.revoked_at = datetime.now(timezone.utc).isoformat()
                db.commit()
                return JSONResponse(status_code=401, content={"detail": "Session expired"})
            user = db.get(User, session.user_id)
            if not user or not user.is_active:
                return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
            # Store user in request state for route handlers
            request.state.user = user
        finally:
            db.close()
        
        return await call_next(request)


app.add_middleware(AuthMiddleware)

app.include_router(routes_admin.router)
app.include_router(routes_auth.router)
app.include_router(routes_cases.router)
app.include_router(routes_activity.router)
app.include_router(routes_command_history.router)
app.include_router(routes_email_artifacts.router)
app.include_router(routes_evidence.router)
app.include_router(routes_evidence_preflight.router)
app.include_router(routes_events.router)
app.include_router(routes_hunting.router)
app.include_router(routes_findings.router)
app.include_router(routes_host_facts.router)
app.include_router(routes_host_users.router)
app.include_router(routes_hosts.router)
app.include_router(routes_indicators.router)
app.include_router(routes_linux_auth.router)


def _configure_memory_capability(target_app: FastAPI) -> None:
    """Mount every router that belongs to the Memory capability.

    Called only when ``settings.memory_enabled`` is true. Imports are
    local so that disabling the capability keeps these route modules
    out of the process entirely, not merely unreachable.
    """
    from app.api import routes_memory, routes_memory_experimental, routes_memory_recovery

    target_app.include_router(routes_memory.router)
    target_app.include_router(routes_memory_experimental.router)
    target_app.include_router(routes_memory_recovery.router)


if settings.memory_enabled:
    _configure_memory_capability(app)

app.include_router(routes_motw.router)
app.include_router(routes_persistence.router)
app.include_router(routes_reports.router)
app.include_router(routes_rules.router)
app.include_router(routes_search.router)
app.include_router(routes_timeline.router)
app.include_router(routes_system.router)
app.include_router(routes_tags.router)
app.include_router(routes_velociraptor.router)


def _reconcile_memory_startup_state(logger: logging.Logger) -> None:
    """Run every Memory-specific startup reconciliation pass.

    Called only when ``settings.memory_enabled`` is true. Each pass is
    independently wrapped so a failure in one never prevents the API
    from starting, matching the original (unconditional) behavior.
    """
    from app.core.database import SessionLocal

    # Reconcile in-flight memory analysis batches so a restart
    # does not leave a batch with no next profile enqueued.
    from app.services.memory.batch import reconcile_memory_batches

    db = SessionLocal()
    try:
        reconcile_memory_batches(db)
    finally:
        db.close()
    # Recover per-evidence symbol readiness for legacy evidences.
    # The backfill is idempotent: it never overwrites an existing
    # valid requirement, never executes Volatility and never
    # downloads symbols.  A failure here MUST NOT prevent the API
    # from starting; we log and continue.
    from app.services.memory.symbol_backfill import backfill_memory_symbol_readiness
    from app.services.memory.symbol_preparation import reconcile_memory_symbol_readiness
    db = SessionLocal()
    try:
        stats = backfill_memory_symbol_readiness(db)
        if stats.reconstructed > 0:
            logger.info(
                "memory symbol readiness backfill reconstructed %d evidence(s)",
                stats.reconstructed,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory symbol readiness backfill skipped: %s", exc)
    finally:
        db.close()
    # New automatic pipeline: reconcile the preparation state for
    # every memory evidence.  This reuses cached requirements by
    # content identity and queues the probe for the rest.
    db = SessionLocal()
    try:
        prep_stats = reconcile_memory_symbol_readiness(db)
        if prep_stats.get("queued", 0) > 0 or prep_stats.get("skipped_ready", 0) > 0:
            logger.info(
                "memory symbol preparation reconcile: %s",
                prep_stats,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory symbol preparation reconcile skipped: %s", exc)
    finally:
        db.close()
    # Memory upload registration lifecycle: scan for uploads whose
    # canonical blob is preserved but whose Evidence row is missing
    # and re-queue them for the new /retry-registration endpoint.
    from app.services.memory.upload_lifecycle import (
        reconcile_memory_upload_lifecycles,
    )
    db = SessionLocal()
    try:
        lifecycle_stats = reconcile_memory_upload_lifecycles(db)
        if lifecycle_stats.get("requeued", 0) > 0:
            logger.info(
                "memory upload registration lifecycle reconcile: %s",
                lifecycle_stats,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory upload registration lifecycle reconcile skipped: %s", exc)
    finally:
        db.close()
    # Memory preparation state reconciliation: promote queued
    # preparations to ready when a successful metadata run exists,
    # mark rows stale when no task is alive and no metadata
    # succeeded, and deactivate duplicate active rows.  Bounded
    # by max_evidences so the startup pass stays predictable.
    from app.services.memory.symbol_preparation import (
        reconcile_memory_preparation_states,
    )
    db = SessionLocal()
    try:
        prep_reconcile = reconcile_memory_preparation_states(db, max_evidences=200)
        if (
            prep_reconcile.get("reconciled", 0) > 0
            or prep_reconcile.get("deactivated", 0) > 0
        ):
            logger.info(
                "memory preparation state reconciliation: %s",
                prep_reconcile,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory preparation state reconciliation skipped: %s", exc)
    finally:
        db.close()
    # Native probe stale reconciliation: queued probes with
    # missing jobs and running probes with expired heartbeats are
    # marked failed so retry is possible.
    from app.services.memory.native_probe import (
        reconcile_stale_probes,
        schedule_periodic_reconciliation_if_needed,
    )

    db = SessionLocal()
    try:
        stale_count = reconcile_stale_probes(db)
        if stale_count > 0:
            logger.info("native probe stale reconciliation: %d", stale_count)
    except Exception as exc:  # noqa: BLE001
        logger.warning("native probe stale reconciliation skipped: %s", exc)
    finally:
        db.close()

    try:
        scheduled = schedule_periodic_reconciliation_if_needed()
        if scheduled:
            logger.info("native probe periodic reconciliation scheduled")
    except Exception as exc:  # noqa: BLE001
        logger.warning("native probe periodic reconciliation scheduling skipped: %s", exc)


def _cleanup_memory_upload_sessions_startup(logger: logging.Logger) -> None:
    """Expire/purge stale Memory upload sessions at startup.

    Called only when ``settings.memory_enabled`` is true.
    """
    from app.core.database import SessionLocal
    from app.services.memory.upload_sessions import (
        cleanup_expired_memory_upload_sessions,
        schedule_periodic_cleanup_if_needed,
    )

    db = SessionLocal()
    try:
        upload_cleanup = cleanup_expired_memory_upload_sessions(db)
        if upload_cleanup.get("expired", 0) > 0 or upload_cleanup.get("purged", 0) > 0:
            logger.info("memory upload cleanup: %s", upload_cleanup)
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory upload cleanup skipped: %s", exc)
    finally:
        db.close()

    try:
        scheduled = schedule_periodic_cleanup_if_needed()
        if scheduled:
            logger.info("memory upload periodic cleanup scheduled")
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory upload periodic cleanup scheduling skipped: %s", exc)


@app.on_event("startup")
def on_startup() -> None:
    try:
        from app.services.bootstrap import bootstrap_admin
        created = bootstrap_admin()
        if created:
            import logging
            logger = logging.getLogger("uvicorn")
            logger.warning("Bootstrap admin created from environment variables. Remove KAIRON_BOOTSTRAP_ADMIN_* after setup.")
    except Exception as e:
        import logging
        logging.getLogger("uvicorn").error("Bootstrap admin failed: %s", e)

    init_db()
    ensure_events_indices_safe_settings()
    auto_bootstrap_dashboards()

    from app.core.database import SessionLocal

    import logging
    logger = logging.getLogger(__name__)

    if settings.memory_enabled:
        _reconcile_memory_startup_state(logger)

    from app.services.evidence_operations import reconcile_evidence_operations
    db = SessionLocal()
    try:
        evidence_stats = reconcile_evidence_operations(db)
        if any(evidence_stats.values()):
            logger.info("evidence lifecycle reconciliation: %s", evidence_stats)
    except Exception as exc:  # noqa: BLE001
        logger.warning("evidence lifecycle reconciliation skipped: %s", exc)
    finally:
        db.close()

    # Stale-ingest reconciliation: releases evidences left in pending/processing
    # by a worker that died without updating the row (e.g. the RQ work-horse
    # was OOM-killed mid-artifact). Also runs opportunistically whenever an
    # analyst opens an evidence's detail page (see maybe_reconcile_stale_ingest
    # in routes_evidence.get_evidence); this startup pass is the safety net
    # for evidences nobody is actively viewing.
    from app.services.job_watchdog import reconcile_stale_ingests
    db = SessionLocal()
    try:
        ingest_stats = reconcile_stale_ingests(db)
        if ingest_stats.get("reconciled", 0) > 0:
            logger.info("stale ingest reconciliation: %s", ingest_stats)
    except Exception as exc:  # noqa: BLE001
        logger.warning("stale ingest reconciliation skipped: %s", exc)
    finally:
        db.close()

    if settings.memory_enabled:
        _cleanup_memory_upload_sessions_startup(logger)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
