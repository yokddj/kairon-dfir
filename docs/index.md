# Documentación Kairon DFIR

Esta documentación describe el estado real de la plataforma. Las capacidades parciales se etiquetan como `advanced`, `experimental`, `planned` o `tooling_missing`.

## Estado y mapas

- [feature_map.md](feature_map.md): mapa de capacidades, estado, rutas, backends y limitaciones.
- [artifacts_matrix.md](artifacts_matrix.md): matriz de artefactos detectados/parseados/indexados.
- [parser-coverage.md](parser-coverage.md): matriz estructurada de familias de parsers, formatos, campos, vistas y limitaciones.
- [platform-architecture.md](platform-architecture.md): arquitectura multiplataforma, capabilities, registry de artefactos y flujo de UI.
- [host-information.md](host-information.md): Host Facts y Local Accounts — cobertura por plataforma, resolución de conflictos y qué se decodifica (y qué no) de SAM/ProfileList en Windows.
- [disk-image-ingestion.md](disk-image-ingestion.md): ingestión read-only de imágenes RAW/EWF, volúmenes, OS detection y trazabilidad.
- [unified-evidence-ingestion.md](unified-evidence-ingestion.md): wizard guiado de 7 pasos (incluye Server Health Check) para añadir evidencia (disco, memoria, colección, carpeta o ruta existente) con una sola subida de red por evidencia.
- [preflight-inspection.md](preflight-inspection.md): inspección de solo lectura antes de procesar — clasificación, pipeline preview, chequeo de recursos y diagnósticos accionables.
- [parser_backends.md](parser_backends.md): backends activos, advanced y faltantes.
- [project_status.md](project_status.md): resumen de madurez del proyecto.

## Guías de uso

- [user_guide.md](user_guide.md): flujo de analista de upload a reporte.
- [case-management.md](case-management.md): estados, prioridad, tags, archivado y filtros de casos.
- [findings-notes.md](findings-notes.md): notas y hallazgos investigativos enlazados a casos, evidencias, hosts y artefactos.
- [quickstart.md](quickstart.md): arranque rápido.
- [search.md](search.md): Search workspace, filtros, frases de comandos y Timeline.
- [timeline_reports.md](timeline_reports.md): timeline y reportes.
- [process_graph.md](process_graph.md): Execution Story / Process Graph.
- [rules_sigma_yara.md](rules_sigma_yara.md): Sigma, YARA y detections.
- [validation/README.md](validation/README.md): uso genérico de Validation Matrix para QA y datasets importados.

## Artefactos y parsers

- [evtx.md](evtx.md)
- [filesystem_mft_usn.md](filesystem_mft_usn.md)
- [defender.md](defender.md)
- [powershell_artifacts.md](powershell_artifacts.md)
- [prefetch.md](prefetch.md)
- [lnk.md](lnk.md)
- [jumplists.md](jumplists.md)
- [registry.md](registry.md)
- [srum.md](srum.md)
- [shellbags.md](shellbags.md)
- [browser.md](browser.md)
- [scheduled_tasks.md](scheduled_tasks.md)
- [usb.md](usb.md)
- [recycle_bin.md](recycle_bin.md)

## Operaciones

- [deployment.md](deployment.md)
- [troubleshooting.md](troubleshooting.md)
- [performance.md](performance.md)
- [large_evidence.md](large_evidence.md)
- [testing.md](testing.md)
- [api_summary.md](api_summary.md)
- [opensearch.md](opensearch.md)

## Referencia técnica

- [architecture.md](architecture.md)
- [raw_parsers.md](raw_parsers.md)
- [ingestion.md](ingestion.md)
- [artifacts.md](artifacts.md)
- [debug_export_pack.md](debug_export_pack.md)
- [maintenance/documentation-maintenance.md](maintenance/documentation-maintenance.md)

## Arquitectura y decisiones

- [architecture/optional-capability-boundary.md](architecture/optional-capability-boundary.md): RFC/ADR — qué significa técnicamente que una capability sea opcional en Kairon (Memory hoy, AI en el futuro).
- [architecture/backlog.md](architecture/backlog.md): backlog de seguimiento de la revisión de arquitectura, con items verificables independientemente.

## Roadmap

- [roadmap.md](roadmap.md)

## Comunidad

- [../CONTRIBUTING.md](../CONTRIBUTING.md): cómo compilar, testear y proponer cambios.
- [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md): normas de la comunidad.
- [../SECURITY.md](../SECURITY.md): política de seguridad, límite de despliegue autoalojado y reporte de vulnerabilidades.
- [../LICENSE](../LICENSE) / [../NOTICE](../NOTICE): licencia AGPL-3.0 y avisos de terceros.
