# Debug Export Pack

## Qué es

ZIP reducido para validar ingest, normalización, correlación, process graph, detections y contexto de UI sin exponer toda la evidencia original.

## Cuándo usarlo

- timeline vacío o incompleto
- process graph inconsistente
- detections o rules dudosas
- regressions de volumen de eventos
- problemas de host attribution
- parsing parcial o data quality inesperada

## Scopes habituales

- `case`
- `evidence`
- `artifact_type`
- vistas de investigación concretas

## Reports principales

- `manifest.json`
- `ingest_summary.json`
- `discovery_candidates.json`
- `parser_audit.json`
- `normalized_events_sample.jsonl`
- `field_coverage_report.json`
- `dedup_report.json`
- `data_quality_report.json`
- `ui_context.json`

## Reports de investigación / correlación

- `correlation_findings_report.json`
- `event_identity_report.json`
- `reconciliation_report.json`
- `process_graph.json`
- `process_tree_report.json`
- `process_tree_sample_chains.jsonl`
- `noise_reduction_report.json`
- `host_attribution_report.json`
- `host_identity_report.json`
- `ingest_regression_report.json`

## Reports de reglas / detections

- `rules_run_report.json`
- `detections_report.json`
- `sigma_matches.jsonl`
- `yara_matches.jsonl`

## Reports de familias de artefactos

- `browser_parse_report.json`
- `defender_parse_report.json`
- `bits_parse_report.json`
- `usb_parse_report.json`
- `recycle_parse_report.json`
- `srum_parse_report.json`
- `wlan_parse_report.json`
- `dns_parse_report.json`
- `cloud_parse_report.json`
- `email_parse_report.json`
- `user_activity_parse_report.json`
- `ntfs_parse_report.json`
- `windows_ui_parse_report.json`
- `autoruns_parse_report.json`
- `lnk_parse_report.json`
- `prefetch_parse_report.json`
- `email_sample_events.jsonl`
- `user_activity_sample_events.jsonl`
- `ntfs_sample_events.jsonl`
- `windows_ui_sample_events.jsonl`

## Cómo leerlo

Orden recomendado:

1. `manifest.json`
2. `ingest_summary.json`
3. `parser_audit.json`
4. `data_quality_report.json`
5. `ingest_regression_report.json`
6. `host_attribution_report.json`
7. `host_identity_report.json`
8. `event_identity_report.json`
9. `reconciliation_report.json`
10. reports específicos de la vista problemática

## Qué no incluye por defecto

- evidencia raw pesada completa
- dumps completos de usuario
- export masivo no truncado de strings sensibles

## Notas

- Es un pack de validación, no un sustituto de la evidencia original.
- Los reports dependen del scope y de que existan datos de esa familia.
- `yara_matches.jsonl` puede estar vacío o incluir warning si YARA no aplicó a ese scope.
- `email_parse_report.json` resume mensajes, adjuntos, inventario de mailboxes y fallos SPF/DKIM/DMARC ya presentes en headers; no hace validación DNS externa.
- `user_activity_parse_report.json` resume actividad de UserAssist/BAM/RunMRU/TypedPaths/RecentDocs/Shellbags/Office MRU/TrustRecords y marca raw hives como inventory-only cuando no hubo export parseado.
- `ntfs_parse_report.json` resume Zone.Identifier, USN, `$LogFile`, `$I30`, shadow copies y raw NTFS inventory-only. `ntfs_sample_events.jsonl` ayuda a validar origen web, create/delete/rename y entradas borradas sin exportar toda la evidencia.
- `windows_ui_parse_report.json` resume thumbnails, notifications, ActivitiesCache, Windows.edb, EventTranscript, Office alerts y Office cache. `windows_ui_sample_events.jsonl` sirve para validar señales UI/local DB de alto valor sin incluir blobs binarios o texto completo sensible.
- `event_identity_report.json` resume cuántos eventos tienen `stable_event_id`, cuántos son best-effort, si hubo colisiones y cómo se repartieron por familia de artefacto.
- `host_identity_report.json` resume hosts canónicos, aliases, merges manuales, splits, candidatos pendientes y cobertura de `observed_host.name`.
- `reconciliation_report.json` resume qué pasó tras reprocess: findings/detections reconciliados, key events remapeados y referencias que quedaron stale.
- `event_id` es el identificador técnico de indexación actual; puede cambiar tras reprocess. `stable_event_id` es la identidad lógica estable usada para reconciliación v1.
- `ingest_plan.json` exporta el plan de ingest activo por evidencia.
- `ingest_plan_diff.json` resume candidatos missing/changed/new del último preview de reprocess.
- `ingest_reprocess_report.json` resume el modo de reprocess usado, candidatos seleccionados, preservación de estado del analista y warnings.
