# Documentación Kairon DFIR

Esta documentación describe el estado real de la plataforma. Las capacidades parciales se etiquetan como `stable`, `partial`, `experimental`, `planned`, `unsupported` o `deprecated` (ver [artifacts/parser-coverage.md](artifacts/parser-coverage.md) para el significado exacto de cada estado).

## Empezar

- [getting-started/quickstart.md](getting-started/quickstart.md): arranque rápido.
- [getting-started/first-run.md](getting-started/first-run.md): primer arranque, creación del administrador y troubleshooting.
- [getting-started/roles-and-permissions.md](getting-started/roles-and-permissions.md): roles Administrator/Standard user.
- [getting-started/user_guide.md](getting-started/user_guide.md): flujo de analista de upload a reporte.
- [getting-started/windows-wsl.md](getting-started/windows-wsl.md): instalación en Windows vía WSL2.
- [getting-started/evaluation-guide.md](getting-started/evaluation-guide.md): qué probar y cómo dar feedback.
- [getting-started/demo_mvp.md](getting-started/demo_mvp.md): recorrido guiado end-to-end.

## Estado y mapas

- [roadmap.md](roadmap.md): roadmap por clasificación Core Platform / Core DFIR Capability / Preview / Strategic — fuente de verdad de madurez.
- [project_status.md](project_status.md): resumen de madurez del proyecto.
- [feature_map.md](feature_map.md): mapa de capacidades, estado, rutas, backends y limitaciones.
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md): limitaciones conocidas actuales.

## Arquitectura

- [architecture/overview.md](architecture/overview.md): resumen de arquitectura general y decisiones por familia de artefacto.
- [architecture/platform-architecture.md](architecture/platform-architecture.md): arquitectura multiplataforma, capabilities, registry de artefactos y flujo de UI.
- [architecture/information-architecture.md](architecture/information-architecture.md): registro de capacidades y navegación.
- [architecture/capability-registry.md](architecture/capability-registry.md): registro de capacidades server-side y rutas canónicas.
- [architecture/optional-capability-boundary.md](architecture/optional-capability-boundary.md): RFC/ADR — qué significa técnicamente que una capability sea opcional en Kairon (Memory hoy, AI en el futuro).
- [architecture/backlog.md](architecture/backlog.md): backlog de seguimiento de la revisión de arquitectura, con items verificables independientemente.
- [architecture/routing.md](architecture/routing.md): auditoría de rutas canónicas y redirects legacy.

## Evidencia

- [evidence/unified-evidence-ingestion.md](evidence/unified-evidence-ingestion.md): wizard guiado de 7 pasos (incluye Server Health Check) para añadir evidencia.
- [evidence/preflight-inspection.md](evidence/preflight-inspection.md): inspección de solo lectura antes de procesar.
- [evidence/disk-image-ingestion.md](evidence/disk-image-ingestion.md): ingestión read-only de imágenes RAW/EWF, volúmenes, OS detection y trazabilidad.
- [evidence/evidence-platforms.md](evidence/evidence-platforms.md): selección de plataforma de evidencia.
- [evidence/evidence-integrity.md](evidence/evidence-integrity.md): hashing SHA-256 y chain of custody.
- [evidence/host-information.md](evidence/host-information.md): Host Facts y Local Accounts — cobertura por plataforma, resolución de conflictos y qué se decodifica (y qué no) de SAM/ProfileList en Windows.
- [evidence/large_evidence.md](evidence/large_evidence.md): manejo de evidencia grande, rutas montadas.
- [evidence/processing-queue.md](evidence/processing-queue.md): cola de procesamiento por caso.
- [evidence/ingestion.md](evidence/ingestion.md): pipeline de ingesta.
- [evidence/velociraptor_ingest.md](evidence/velociraptor_ingest.md): discovery y parseo selectivo de colecciones Velociraptor.

## Artefactos y parsers

- [artifacts/parser-coverage.md](artifacts/parser-coverage.md): matriz canónica de estado de parsers, formatos, backends y limitaciones.
- [artifacts/evtx.md](artifacts/evtx.md)
- [artifacts/filesystem_mft_usn.md](artifacts/filesystem_mft_usn.md)
- [artifacts/defender.md](artifacts/defender.md)
- [artifacts/powershell_artifacts.md](artifacts/powershell_artifacts.md)
- [artifacts/prefetch.md](artifacts/prefetch.md)
- [artifacts/lnk.md](artifacts/lnk.md)
- [artifacts/jumplists.md](artifacts/jumplists.md)
- [artifacts/registry.md](artifacts/registry.md)
- [artifacts/srum.md](artifacts/srum.md)
- [artifacts/shellbags.md](artifacts/shellbags.md)
- [artifacts/browser.md](artifacts/browser.md)
- [artifacts/scheduled_tasks.md](artifacts/scheduled_tasks.md)
- [artifacts/usb.md](artifacts/usb.md)
- [artifacts/recycle_bin.md](artifacts/recycle_bin.md)
- [artifacts/autoruns.md](artifacts/autoruns.md)
- [artifacts/bits.md](artifacts/bits.md)
- [artifacts/cloud_sync.md](artifacts/cloud_sync.md)
- [artifacts/network.md](artifacts/network.md)
- [artifacts/wmi.md](artifacts/wmi.md)
- [artifacts/execution_artifacts.md](artifacts/execution_artifacts.md)

## Linux

- [linux/linux-support.md](linux/linux-support.md): soporte Linux completo — formatos de colección, auto-discovery, las 12 familias parseadas y limitaciones.

## Memory

- [memory/memory_analysis.md](memory/memory_analysis.md): estado, plugins y perfiles de Memory Analysis (Preview).
- [memory/memory_operations.md](memory/memory_operations.md): habilitación, worker opcional, build, configuración, aislamiento y troubleshooting.
- [memory/memory_upload.md](memory/memory_upload.md): subida dedicada de imágenes de memoria — flujo, límites, streaming y CLI de mantenimiento.
- [memory/memory_process_model.md](memory/memory_process_model.md): modelo canónico de entidades/observaciones de procesos.
- [memory/memory_process_graph.md](memory/memory_process_graph.md): UX del grafo de procesos.
- [memory/memory_runner_security.md](memory/memory_runner_security.md): modelo de amenazas del runner de Memory.
- [memory/memory_symbols.md](memory/memory_symbols.md): símbolos gestionados de Windows.
- [memory/memory_symbol_operator_approval.md](memory/memory_symbol_operator_approval.md): flujo de aprobación de operador para símbolos.
- [memory/symbol_egress_gateway.md](memory/symbol_egress_gateway.md): arquitectura del gateway de egress de símbolos.
- [memory/symbol_fetcher_security.md](memory/symbol_fetcher_security.md): modelo de amenazas del symbol-fetcher.

## Búsqueda e investigación

- [search-and-investigation/search.md](search-and-investigation/search.md): Search workspace, filtros, frases de comandos y Timeline.
- [search-and-investigation/timeline_reports.md](search-and-investigation/timeline_reports.md): timeline y reportes.
- [search-and-investigation/process_graph.md](search-and-investigation/process_graph.md): Execution Story / Process Graph.
- [search-and-investigation/findings-notes.md](search-and-investigation/findings-notes.md): notas y hallazgos investigativos.
- [search-and-investigation/findings_correlation.md](search-and-investigation/findings_correlation.md): taxonomía de findings auto-generados por correlación.
- [search-and-investigation/case-management.md](search-and-investigation/case-management.md): estados, prioridad, tags, archivado y filtros de casos.
- [search-and-investigation/app_sections.md](search-and-investigation/app_sections.md): índice de secciones de la UI.
- [search-and-investigation/semi_automatic_analysis.md](search-and-investigation/semi_automatic_analysis.md): catálogo de secciones de análisis semiautomático.
- [search-and-investigation/investigation-workflow.md](search-and-investigation/investigation-workflow.md): mecánica de scope/host-filtering entre vistas.

## Reglas

- [rules/rules_sigma_yara.md](rules/rules_sigma_yara.md): Sigma, YARA y detections.
- [rules/rule_authoring.md](rules/rule_authoring.md): cómo escribir reglas heurísticas/Sigma/YARA.
- [rules/builtin_rules.md](rules/builtin_rules.md): catálogo de detecciones builtin.

## Despliegue

- [deployment/deployment.md](deployment/deployment.md): guía canónica de despliegue — requisitos, variables de entorno, volúmenes, operación y seguridad.
- [deployment/deployment-modes.md](deployment/deployment-modes.md): modos localhost/lan/https.
- [deployment/deployment-remote.md](deployment/deployment-remote.md): runbook de despliegue remoto.
- [deployment/beta-vs-validation-mode.md](deployment/beta-vs-validation-mode.md): diferencia entre modo de despliegue normal y modo de validación/QA.
- [deployment/backup-restore.md](deployment/backup-restore.md): backup y restore.
- [deployment/update-rollback.md](deployment/update-rollback.md): actualización y rollback.
- [deployment/troubleshooting.md](deployment/troubleshooting.md): troubleshooting operativo/infraestructura.

## Operaciones

- [operations/troubleshooting.md](operations/troubleshooting.md): troubleshooting funcional de la aplicación.
- [operations/performance.md](operations/performance.md): perfiles de rendimiento.
- [operations/opensearch.md](operations/opensearch.md): mapping y comportamiento de OpenSearch.
- [operations/api_summary.md](operations/api_summary.md): mapa de alto nivel de endpoints.
- [operations/debug_export_pack.md](operations/debug_export_pack.md): catálogo del debug export pack.
- [operations/testing.md](operations/testing.md): suite de tests backend/frontend.
- [operations/demo_checklist.md](operations/demo_checklist.md): checklist de QA para demos.

## Validación

- [validation/README.md](validation/README.md): uso genérico de Validation Matrix para QA y datasets importados.
- [validation/validation-matrix-format.md](validation/validation-matrix-format.md): formato JSON de la matriz de validación.

## Releases

- [releases/0.9.0-beta.md](releases/0.9.0-beta.md): notas de la release 0.9.0-beta (histórico).
- [releases/RELEASE_CHECKLIST.md](releases/RELEASE_CHECKLIST.md): checklist de release (histórico, congelado en el ciclo 0.9.0-beta).

## Comunidad

- [../CONTRIBUTING.md](../CONTRIBUTING.md): cómo compilar, testear y proponer cambios.
- [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md): normas de la comunidad.
- [../SECURITY.md](../SECURITY.md): política de seguridad, límite de despliegue autoalojado y reporte de vulnerabilidades.
- [../LICENSE](../LICENSE) / [../NOTICE](../NOTICE): licencia AGPL-3.0 y avisos de terceros.
