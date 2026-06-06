from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
import psutil
from redis import Redis
from rq import Queue, Worker
from rq.registry import FailedJobRegistry, FinishedJobRegistry, StartedJobRegistry
from sqlalchemy.orm import Session

from app.core.app_settings import DEPLOYMENT_DEFAULTS, PERFORMANCE_PROFILE_KEY, RUNTIME_DEFAULTS, SETTING_META, get_effective_settings, reset_settings, set_setting
from app.core.config import get_settings
from app.core.database import get_db
from app.core.opensearch import get_opensearch_client, get_opensearch_ingest_preflight
from app.core.performance import (
    DISK_CRITICAL_PERCENT,
    DISK_DEGRADED_PERCENT,
    apply_recommended_profile,
    build_recommendation_payload,
    manual_restart_instructions,
    performance_resources,
    performance_state,
    restart_plan,
    save_performance_profile,
)
from app.ingest.raw_parsers.evtxecmd_backend import detect_evtx_parser_backends
from app.services.parser_backend_evaluation import build_core_parser_backend_evaluation, detect_ez_tools
from app.services.opensearch_dashboards import bootstrap_dashboards_data_view, dashboards_admin_status
from app.services.task_registry import build_task_health_snapshot, build_task_registry_summary


router = APIRouter(tags=["system"])
settings = get_settings()


def _resolve_docs_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "docs",
        here.parents[3] / "docs",
        Path("/app/docs"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


DOCS_ROOT = _resolve_docs_root()
DOCS_CATALOG = [
    {"slug": "index", "title": "Índice", "summary": "Qué es la plataforma, flujo de trabajo y mapa de documentación.", "filename": "index.md"},
    {"slug": "feature-map", "title": "Feature map", "summary": "Capacidades actuales, estado, rutas, backends, limitaciones y próximos pasos.", "filename": "feature_map.md"},
    {"slug": "artifacts-matrix", "title": "Artifact support matrix", "summary": "Matriz de artefactos detectados, parseados, indexados, buscables y pendientes.", "filename": "artifacts_matrix.md"},
    {"slug": "parser-backends", "title": "Parser backends", "summary": "Backends estables, advanced, planned y tooling_missing.", "filename": "parser_backends.md"},
    {"slug": "api-summary", "title": "API summary", "summary": "Mapa de endpoints y workflows principales.", "filename": "api_summary.md"},
    {"slug": "user-guide", "title": "User guide", "summary": "Flujo de analista desde upload hasta reporte.", "filename": "user_guide.md"},
    {"slug": "search", "title": "Search workspace", "summary": "Búsqueda principal, frases de comandos, filtros, timeline y Artifact Views.", "filename": "search.md"},
    {"slug": "architecture", "title": "Arquitectura", "summary": "Frontend, backend, OpenSearch, almacenamiento y flujo de datos.", "filename": "architecture.md"},
    {"slug": "quickstart", "title": "Primeros pasos", "summary": "Cómo levantar la app, crear un caso y empezar a investigar.", "filename": "quickstart.md"},
    {"slug": "ingestion", "title": "Ingesta", "summary": "Qué ocurre al subir evidencia y cómo se detectan parsers y artefactos.", "filename": "ingestion.md"},
    {"slug": "artifacts", "title": "Artefactos soportados", "summary": "Qué evidencias se soportan hoy y qué aportan a la investigación.", "filename": "artifacts.md"},
    {"slug": "evtx", "title": "EVTX / EvtxECmd", "summary": "Fuente principal actual para eventos Windows y su normalización.", "filename": "evtx.md"},
    {"slug": "prefetch", "title": "Prefetch / PECmd", "summary": "Cómo se normaliza Prefetch parseado con PECmd y Prefetch raw nativo, y cómo se correlaciona con ejecución real.", "filename": "prefetch.md"},
    {"slug": "lnk", "title": "LNK / LECmd", "summary": "Cómo se normalizan accesos mediante shortcuts Windows y cómo se usan en el análisis.", "filename": "lnk.md"},
    {"slug": "jumplists", "title": "Jump Lists / JLECmd", "summary": "Cómo se normalizan documentos y accesos recientes por aplicación usando Jump Lists parseadas con JLECmd y automaticDestinations raw desde Velociraptor.", "filename": "jumplists.md"},
    {"slug": "registry", "title": "Registry / RECmd", "summary": "Cómo se normalizan artefactos de registro de Windows parseados con RECmd y cómo se usan para persistencia, ejecución y actividad de usuario.", "filename": "registry.md"},
    {"slug": "filesystem-mft-usn", "title": "Sistema de archivos / MFTECmd", "summary": "Cómo se normalizan $MFT y USN Journal parseados con MFTECmd y cómo se usan para actividad de archivos, borrados, ADS y posibles anomalías temporales.", "filename": "filesystem_mft_usn.md"},
    {"slug": "browser", "title": "Browser activity", "summary": "Cómo se normalizan historial, descargas y términos de búsqueda parseados de navegador y cómo se correlacionan con MFT, LNK, Prefetch, EVTX y Defender.", "filename": "browser.md"},
    {"slug": "velociraptor-ingest", "title": "Velociraptor ingest", "summary": "Cómo descubrir evidencias dentro de una colección Velociraptor y parsear directamente History/places.sqlite de navegador.", "filename": "velociraptor_ingest.md"},
    {"slug": "execution-artifacts", "title": "Execution artifacts", "summary": "Cómo se interpretan Amcache, ShimCache/AppCompatCache y RecentFileCache sin exagerar su significado forense.", "filename": "execution_artifacts.md"},
    {"slug": "srum", "title": "SRUM / SrumECmd", "summary": "Cómo se interpreta SRUM como uso de red por aplicación, volúmenes de bytes y actividad sospechosa sin afirmar conexiones exactas ni exfiltración confirmada.", "filename": "srum.md"},
    {"slug": "scheduled-tasks", "title": "Scheduled Tasks / Task Scheduler", "summary": "Cómo se interpretan XML y CSV de tareas programadas, su persistencia potencial y su correlación con EVTX, Prefetch y descargas.", "filename": "scheduled_tasks.md"},
    {"slug": "defender", "title": "Windows Defender Artifacts", "summary": "Cómo se interpretan DetectionHistory, MPLog y CSV/JSON de Defender, incluyendo acciones, remediación y correlaciones.", "filename": "defender.md"},
    {"slug": "powershell-artifacts", "title": "PowerShell artifacts", "summary": "Cómo se interpretan PSReadLine, transcripts y scripts PowerShell observados fuera de EVTX, incluyendo indicadores, correlaciones y limitaciones.", "filename": "powershell_artifacts.md"},
    {"slug": "semi-automatic-analysis", "title": "Análisis semiautomático", "summary": "Qué busca cada sección y de qué evidencias se alimenta.", "filename": "semi_automatic_analysis.md"},
    {"slug": "builtin-rules", "title": "Reglas builtin", "summary": "Builtin detections actuales, cómo interpretarlas y cómo desactivarlas.", "filename": "builtin_rules.md"},
    {"slug": "rule-authoring", "title": "Crear reglas", "summary": "Cómo añadir reglas heuristic, Sigma o YARA usando el formato real del proyecto.", "filename": "rule_authoring.md"},
    {"slug": "app-sections", "title": "Secciones de la app", "summary": "Qué hace cada página del sidebar y cómo usarla en una investigación.", "filename": "app_sections.md"},
    {"slug": "opensearch", "title": "OpenSearch", "summary": "Mapping, índices por caso, campos buscables y troubleshooting de indexación.", "filename": "opensearch.md"},
    {"slug": "troubleshooting", "title": "Troubleshooting", "summary": "Problemas frecuentes y qué comprobar cuando algo no aparece.", "filename": "troubleshooting.md"},
    {"slug": "demo-mvp", "title": "Demo MVP", "summary": "Guía operativa para enseñar el MVP con un caso sintético reproducible.", "filename": "demo/mvp-demo-guide.md"},
    {"slug": "demo-checklist", "title": "Demo Checklist", "summary": "Checklist técnica para validar que la demo está lista antes de presentarla.", "filename": "demo/mvp-demo-checklist.md"},
    {"slug": "kairon-lab01", "title": "Kairon Lab 01", "summary": "Laboratorio público de PowerShell sospechoso simulado basado en una colección Velociraptor.", "filename": "demo/kairon-lab01/README.md"},
    {"slug": "demo-readme", "title": "Demo mode", "summary": "Cómo usar modo demo sin incluir datasets concretos en main.", "filename": "demo/README.md"},
    {"slug": "generic-demo-guide", "title": "Generic demo guide", "summary": "Guía neutra para enseñar la plataforma con un dataset propio o sintético.", "filename": "demo/generic-demo-guide.md"},
    {"slug": "validation-readme", "title": "Validation features", "summary": "Uso genérico de Validation Matrix para QA/training con datasets importados.", "filename": "validation/README.md"},
    {"slug": "validation-matrix-format", "title": "Validation matrix format", "summary": "Formato recomendado para matrices de validación metadata-only.", "filename": "validation/validation-matrix-format.md"},
    {"slug": "beta-deployment", "title": "Beta deployment", "summary": "Guía de despliegue reproducible para beta privada controlada.", "filename": "deployment/beta-deployment.md"},
    {"slug": "beta-vs-demo-mode", "title": "Beta vs demo mode", "summary": "Separación entre investigaciones reales y funciones demo/validation.", "filename": "deployment/beta-vs-demo-mode.md"},
    {"slug": "backup-restore", "title": "Backup and restore", "summary": "Qué respaldar, cómo probar backups y cómo restaurar datos de la plataforma.", "filename": "deployment/backup-restore.md"},
    {"slug": "update-rollback", "title": "Update and rollback", "summary": "Procedimiento de actualización, smoke test y rollback para beta privada.", "filename": "deployment/update-rollback.md"},
    {"slug": "beta-troubleshooting", "title": "Beta troubleshooting", "summary": "Diagnóstico operativo de servicios, colas, disco, parsers y exposición de red.", "filename": "deployment/troubleshooting.md"},
    {"slug": "security", "title": "Security", "summary": "Advertencias de seguridad, manejo de secretos y reporte seguro de bugs.", "filename": "SECURITY.md"},
    {"slug": "known-limitations", "title": "Known limitations", "summary": "Limitaciones beta explícitas por parser, búsqueda, detecciones y despliegue.", "filename": "KNOWN_LIMITATIONS.md"},
    {"slug": "beta-notes", "title": "Beta notes", "summary": "Notas prácticas para testers de beta privada.", "filename": "BETA_NOTES.md"},
    {"slug": "roadmap", "title": "Roadmap", "summary": "Siguientes evidencias y prioridades recomendadas.", "filename": "roadmap.md"},
    {"slug": "documentation-maintenance", "title": "Mantenimiento de documentación", "summary": "Checklist para que la documentación no se quede atrás.", "filename": "maintenance/documentation-maintenance.md"},
]

DEMO_DOC_SLUGS = {
    "demo-mvp",
    "demo-checklist",
    "kairon-lab01",
    "demo-readme",
    "generic-demo-guide",
    "validation-readme",
    "validation-matrix-format",
}


def _visible_docs_catalog() -> list[dict]:
    if get_settings().demo_cases_enabled:
        return DOCS_CATALOG
    return [item for item in DOCS_CATALOG if item["slug"] not in DEMO_DOC_SLUGS]


def _queue_stats(connection: Redis, name: str) -> dict:
    queue = Queue(name, connection=connection)
    return {
        "queued": queue.count,
        "started": len(StartedJobRegistry(name, connection=connection)),
        "failed": len(FailedJobRegistry(name, connection=connection)),
        "finished": len(FinishedJobRegistry(name, connection=connection)),
    }


def _disk_status(used_percent: float) -> str:
    if used_percent >= DISK_CRITICAL_PERCENT:
        return "critical"
    if used_percent >= DISK_DEGRADED_PERCENT:
        return "degraded"
    return "healthy"


def _opensearch_watermark_risk(disk_used_percent: float, write_blocked: bool | None = None) -> str:
    if write_blocked or disk_used_percent >= DISK_CRITICAL_PERCENT:
        return "high"
    if disk_used_percent >= DISK_DEGRADED_PERCENT:
        return "medium"
    return "low"


@router.get("/api/system/status")
def system_status(db: Session = Depends(get_db)) -> dict:
    data_dir = Path(settings.backend_data_dir)
    disk = psutil.disk_usage(str(data_dir))
    vm = psutil.virtual_memory()
    connection = Redis.from_url(settings.redis_url)
    queues = {
        "dfir-ingest": _queue_stats(connection, "dfir-ingest"),
        "dfir-rules": _queue_stats(connection, "dfir-rules"),
        "dfir-analysis": _queue_stats(connection, "dfir-analysis"),
    }
    workers = Worker.all(connection=connection)
    opensearch_info = {
        "available": False,
        "cluster_status": "unknown",
        "heap_used_percent": None,
        "indices": 0,
        "docs_count": 0,
        "cluster_create_index_blocked": None,
        "cluster_write_blocked": None,
        "target_index_write_blocked": None,
        "target_index_read_only_allow_delete": None,
        "bulk_indexing_permitted": None,
        "ingest_writable": None,
        "blocking_reasons": [],
        "disk_allocation": [],
    }
    try:
        client = get_opensearch_client()
        health = client.cluster.health()
        indices = client.cat.indices(format="json")
        nodes = client.nodes.stats(metric="jvm")
        preflight = get_opensearch_ingest_preflight(None)
        heap_used_percent = None
        for node in (nodes.get("nodes") or {}).values():
            heap_used_percent = node.get("jvm", {}).get("mem", {}).get("heap_used_percent")
            if heap_used_percent is not None:
                break
        opensearch_info = {
            "available": True,
            "cluster_status": health.get("status", "unknown"),
            "heap_used_percent": heap_used_percent,
            "indices": len(indices),
            "docs_count": sum(int(item.get("docs.count", 0) or 0) for item in indices),
            "cluster_create_index_blocked": preflight.get("cluster_create_index_blocked"),
            "cluster_write_blocked": preflight.get("cluster_write_blocked") or preflight.get("cluster_read_only_allow_delete"),
            "target_index_write_blocked": preflight.get("target_index_write_blocked"),
            "target_index_read_only_allow_delete": preflight.get("target_index_read_only_allow_delete"),
            "bulk_indexing_permitted": preflight.get("bulk_indexing_permitted"),
            "ingest_writable": preflight.get("ingest_writable"),
            "blocking_reasons": list(preflight.get("blocking_reasons") or []),
            "disk_allocation": list(preflight.get("disk_allocation") or []),
            "write_blocked": bool(
                preflight.get("cluster_create_index_blocked")
                or preflight.get("cluster_write_blocked")
                or preflight.get("cluster_read_only_allow_delete")
                or preflight.get("target_index_write_blocked")
                or preflight.get("target_index_read_only_allow_delete")
            ),
            "watermark_risk": _opensearch_watermark_risk(
                float(disk.percent),
                bool(
                    preflight.get("cluster_create_index_blocked")
                    or preflight.get("cluster_write_blocked")
                    or preflight.get("cluster_read_only_allow_delete")
                    or preflight.get("target_index_write_blocked")
                    or preflight.get("target_index_read_only_allow_delete")
                ),
            ),
        }
    except Exception:  # noqa: BLE001
        pass
    effective = get_effective_settings(db)
    return {
        "cpu": {"percent": psutil.cpu_percent(interval=0.1), "count": psutil.cpu_count() or 1},
        "memory": {"total": vm.total, "used": vm.used, "percent": vm.percent},
        "disk": {
            "data_dir_total": disk.total,
            "data_dir_used": disk.used,
            "data_dir_free": disk.free,
            "data_dir_percent": disk.percent,
            "status": _disk_status(float(disk.percent)),
            "warning_threshold_percent": DISK_DEGRADED_PERCENT,
            "critical_threshold_percent": DISK_CRITICAL_PERCENT,
        },
        "queues": queues,
        "opensearch": opensearch_info,
        "evtx_parser_backends": detect_evtx_parser_backends(),
        "ez_parser_tools": detect_ez_tools(),
        "core_parser_backend_evaluation": build_core_parser_backend_evaluation(),
        "workers": {"active": len(workers), "known": [worker.name for worker in workers]},
        "settings": {
            "ingest_batch_size": effective["INGEST_BATCH_SIZE"],
            "opensearch_bulk_docs": effective["OPENSEARCH_BULK_DOCS"],
            "opensearch_bulk_bytes": effective["OPENSEARCH_BULK_BYTES"],
            "max_parallel_artifacts": effective["MAX_PARALLEL_ARTIFACTS"],
            "max_parallel_rule_runs": effective["MAX_PARALLEL_RULE_RUNS"],
        },
        "deployment": {
            "opensearch_java_heap": effective["OPENSEARCH_JAVA_HEAP"],
            "backend_uvicorn_workers": effective["BACKEND_UVICORN_WORKERS"],
            "worker_scale_hint": "Use docker compose up -d --scale worker=N",
        },
    }


@router.get("/api/system/task-registry")
def system_task_registry() -> dict:
    return build_task_registry_summary()


@router.get("/api/system/task-health")
def system_task_health() -> dict:
    return build_task_health_snapshot()


@router.get("/api/system/version")
def system_version() -> dict:
    return settings.build_identity


@router.get("/api/system/settings")
def system_settings(db: Session = Depends(get_db)) -> dict:
    effective = get_effective_settings(db)
    runtime = {key: effective[key] for key in RUNTIME_DEFAULTS}
    deployment = {key: effective[key] for key in DEPLOYMENT_DEFAULTS}
    meta = {
        key: {
            "category": value.get("category"),
            "description": value.get("description"),
            "requires_restart": bool(value.get("requires_restart")),
            "restart_scope": value.get("restart_scope", "none"),
            "applies_immediately": bool(value.get("applies_immediately", True)),
        }
        for key, value in SETTING_META.items()
        if key != PERFORMANCE_PROFILE_KEY
    }
    return {
        "runtime": runtime,
        "deployment": deployment,
        "meta": meta,
    }


@router.patch("/api/system/settings")
def patch_system_settings(payload: dict, db: Session = Depends(get_db)) -> dict:
    changed = payload.get("settings", {})
    updated = []
    runtime_applied = []
    requires_restart = []
    restart_scopes = []
    warnings = []
    for key, value in changed.items():
        set_setting(db, key, value)
        updated.append(key)
        meta = SETTING_META.get(key, {})
        if meta.get("applies_immediately", True):
            runtime_applied.append(key)
        else:
            requires_restart.append(key)
            restart_scope = meta.get("restart_scope", key)
            if restart_scope not in restart_scopes:
                restart_scopes.append(restart_scope)
    if "worker" in restart_scopes:
        warnings.append(f"Run: docker compose up -d --scale worker={changed.get('WORKER_SCALE')}")
    if "opensearch" in restart_scopes:
        warnings.append("Update desired OpenSearch heap and restart opensearch: docker compose up -d --force-recreate opensearch")
    effective = get_effective_settings(db)
    return {
        "updated": updated,
        "requires_restart": requires_restart,
        "restart_scopes": restart_scopes,
        "runtime_applied": runtime_applied,
        "warnings": warnings,
        "settings": effective,
    }


@router.post("/api/system/settings/reset")
def reset_system_settings(db: Session = Depends(get_db)) -> dict:
    reset = reset_settings(db)
    return {
        "updated": reset,
        "requires_restart": [],
        "runtime_applied": reset,
        "warnings": [],
        "settings": get_effective_settings(db),
    }


@router.get("/api/docs")
def list_docs() -> list[dict]:
    return [{"slug": item["slug"], "title": item["title"], "summary": item["summary"]} for item in _visible_docs_catalog()]


@router.get("/api/docs/{slug}")
def get_doc(slug: str) -> dict:
    for item in _visible_docs_catalog():
        if item["slug"] != slug:
            continue
        path = DOCS_ROOT / item["filename"]
        if not path.exists():
            return {
                "slug": item["slug"],
                "title": item["title"],
                "summary": item["summary"],
                "content": f"# Documento no encontrado\n\nNo se encontró `{item['filename']}` en la carpeta `docs/`.",
            }
        return {
            "slug": item["slug"],
            "title": item["title"],
            "summary": item["summary"],
            "content": path.read_text(encoding="utf-8"),
        }
    return {
        "slug": slug,
        "title": "Documento no encontrado",
        "summary": "El slug solicitado no existe en el catálogo de documentación.",
        "content": f"# Documento no encontrado\n\nNo existe documentación registrada para `{slug}`.",
    }


@router.get("/api/admin/performance")
def get_admin_performance(db: Session = Depends(get_db)) -> dict:
    return performance_state(db)


@router.patch("/api/admin/performance")
def patch_admin_performance(payload: dict, db: Session = Depends(get_db)) -> dict:
    try:
        return save_performance_profile(
            db,
            payload.get("profile") or "balanced",
            payload.get("settings") or {},
            confirm_max=bool(payload.get("confirm_max")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/admin/performance/apply")
def apply_admin_performance(payload: dict, db: Session = Depends(get_db)) -> dict:
    try:
        return save_performance_profile(
            db,
            payload.get("profile") or "balanced",
            payload.get("settings") or {},
            confirm_max=bool(payload.get("confirm_max")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/admin/performance/apply-profile")
def apply_admin_performance_profile(payload: dict, db: Session = Depends(get_db)) -> dict:
    try:
        return save_performance_profile(
            db,
            payload.get("profile") or "balanced",
            payload.get("settings") or {},
            confirm_max=bool(payload.get("confirm_max")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/admin/performance/apply-recommended")
def apply_admin_performance_recommended(payload: dict | None = None, db: Session = Depends(get_db)) -> dict:
    try:
        return apply_recommended_profile(db, confirm_max=bool((payload or {}).get("confirm_max")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/admin/performance/restart")
def restart_admin_performance(payload: dict) -> dict:
    try:
        return restart_plan(payload.get("services") or [])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/admin/performance/restart-instructions")
def admin_performance_restart_instructions(db: Session = Depends(get_db)) -> dict:
    state = performance_state(db)
    return manual_restart_instructions(list(state.get("services_to_restart") or []))


@router.get("/api/admin/opensearch-dashboards/status")
def admin_opensearch_dashboards_status(request: Request, db: Session = Depends(get_db)) -> dict:
    return dashboards_admin_status(db=db, request=request)


@router.post("/api/admin/opensearch-dashboards/bootstrap")
def admin_opensearch_dashboards_bootstrap(request: Request, payload: dict | None = None, db: Session = Depends(get_db)) -> dict:
    result = bootstrap_dashboards_data_view(repair=bool((payload or {}).get("repair")))
    return {**result, "status": dashboards_admin_status(db=db, request=request)}


@router.get("/api/admin/performance/recommendation")
def admin_performance_recommendation(db: Session = Depends(get_db)) -> dict:
    return performance_state(db)["recommendation"]


@router.get("/api/admin/performance/resources")
def admin_performance_resources(db: Session = Depends(get_db)) -> dict:
    return performance_resources(db)
