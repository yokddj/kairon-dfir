# Troubleshooting

## Backend no arranca

Comprueba:

- `docker compose ps`
- `docker compose logs -f backend`
- credenciales de PostgreSQL
- conectividad a OpenSearch y Redis
- migración automática de columnas nuevas

## OpenSearch 502 / timeout

Comprueba:

- estado de `opensearch`
- heap disponible
- disco libre
- límites de bulk/refresh
- si hay restart pendiente tras cambiar `OPENSEARCH_JAVA_HEAP`

## OpenSearch: `index_create_block_exception` / create-index blocked

Síntoma típico:

- `AuthorizationException(403, 'index_create_block_exception', 'blocked by: [FORBIDDEN/10/cluster create-index blocked (api)];')`

Comportamiento esperado de la app:

- no debe empezar parsing
- no debe marcar artefactos como parser failed si la preflight falla antes de indexar
- debe mostrar un error claro:
  - `OpenSearch is not writable or cannot create indices. Ingest has not started.`

Diagnóstico:

```bash
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cluster/settings?include_defaults=true&pretty'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cluster/health?pretty'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cat/allocation?v'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cat/indices?v'
```

Qué buscar:

- `persistent.cluster.blocks.create_index`
- `transient.cluster.blocks.create_index`
- `defaults.cluster.blocks.create_index`
- `persistent.cluster.blocks.write`
- `transient.cluster.blocks.write`
- `defaults.cluster.blocks.write`
- índices con `read_only_allow_delete`
- presión de disco / flood-stage watermark

Remediación segura:

1. libera espacio si el nodo está al límite
2. corrige el motivo del bloqueo
3. limpia el bloqueo de escritura o create-index

Ejemplos:

```bash
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD -XPUT 'http://localhost:9200/_cluster/settings' -H 'Content-Type: application/json' -d '{
  "persistent": {
    "cluster.blocks.create_index": null,
    "cluster.blocks.write": null
  },
  "transient": {
    "cluster.blocks.create_index": null,
    "cluster.blocks.write": null
  }
}'

curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD -XPUT 'http://localhost:9200/_all/_settings' -H 'Content-Type: application/json' -d '{
  "index.blocks.read_only_allow_delete": null
}'
```

Después:

- vuelve a comprobar `/_cluster/health`
- valida que la app marque OpenSearch como writable
- relanza el ingest o benchmark

## Bulk / refresh issues

Síntomas:

- ingestas lentas
- eventos indexados en audit pero no visibles
- refresh timeout

Revisa:

- `OPENSEARCH_BULK_DOCS`
- `OPENSEARCH_BULK_BYTES`
- `OPENSEARCH_REFRESH_TIMEOUT`
- `Performance & Resources`

## Mounted evidence: path validation falla

Comprueba:

- `DFIR_ALLOW_HOST_PATH_IMPORT=true`
- la ruta cae dentro de `DFIR_ALLOWED_EVIDENCE_ROOTS`
- el path existe
- no hay symlink escape

Si introduces una ruta como `C:\Users\...` o `/home/user/...`, eso suele ser una ruta del equipo cliente, no del servidor.

Acción:

- usa `Upload file`
- o monta/compártela en el servidor bajo `/mnt/evidence`, `/data/evidence` o `/cases`

## El archivo `.evtx` suelto no debería necesitar ZIP

Comportamiento esperado:

- un `.evtx` suelto debe detectarse como `Windows Event Log`
- debe procesarse como `RAW evidence`
- no debe pedir un flujo especial de archive ni mostrar `unknown`

Si no ocurre:

- revisa que el archivo termine en `.evtx`
- revisa `Evidence & Ingest` para ver si lo marcó como `Detected: Windows Event Log (.evtx)`
- si usas mounted path, valida que backend y worker ven la misma ruta
- exporta `Debug Pack` y revisa `ingest_summary.json` / `ingest_plan.json`

## ZIP RAW subido pero aún no parseado

Un archive RAW puede pasar por dos fases:

- discovery de candidatos
- parseo de los candidatos seleccionados

Si ves `waiting_selection`:

- no significa que el archive haya fallado
- significa que el discovery ya detectó artefactos compatibles y espera confirmación de selección
- la UI o el parse endpoint deben lanzar el parseo de los candidatos recomendados

Si el archive no detecta artefactos:

- el mensaje correcto es que no se detectaron artefactos soportados
- no debe aparecer un error engañoso como `Velociraptor discovery failed` para el usuario final

## System / Performance no deja claro mounted evidence

La UI actual separa:

- runtime settings
- deployment settings
- evidence storage
- advanced raw settings

Si `Server-mounted evidence import` aparece como `Disabled`, el comportamiento esperado es:

- `Upload file` sigue disponible
- `Register server-mounted path` queda explicado pero no se presenta como toggle runtime
- la propia UI muestra variables de entorno y comando de restart

Ruta recomendada:

- `System / Performance -> Evidence storage`
- `Evidence & Ingest -> Register server-mounted path`

## Low disk space

Síntomas:

- ingestas paradas
- extracción parcial
- OpenSearch inestable

Acción:

- limpia storage no necesario
- usa mounted evidence
- reduce exports y copias duplicadas

## Host contamination

Si un caso mezcla hosts de forma rara:

- revisa `host_attribution_report.json`
- revisa `host_identity_report.json`
- valida evidencias mezcladas
- filtra por `host`
- revisa si el caso necesita separar evidencias

Si el problema es naming y no contaminación real:

- abre `Overview -> Host Identity -> Manage hosts`
- fusiona aliases solo cuando tengas confianza
- separa el alias si el merge fue incorrecto

## Reingest volume drop

Si tras reingest baja mucho el volumen:

- exporta debug pack
- revisa `ingest_regression_report.json`
- revisa `parser_audit.json`
- revisa filtros de selección de artefactos

## Reprocess: findings, detections o key events cambiaron

Comprueba:

- `event_identity_report.json`
- `reconciliation_report.json`
- si los eventos nuevos tienen `stable_event_id`
- si el parser afectado está cayendo en `fingerprint_best_effort`

Puntos clave:

- `event_id` puede cambiar tras reprocess

## Reprocess parsea algo distinto a la primera vez

Comprueba el `ingest_plan` de la evidencia. El modo recomendado es `Use previous parser selection`, que reutiliza el mismo conjunto de candidatos/parsers usado antes.

Si se usa `Full rediscovery`, la app puede descubrir y seleccionar un conjunto diferente de candidatos. Eso es esperado y la UI lo avisa antes de lanzar el reprocess.

Si una evidencia antigua no tiene `ingest_plan`, la UI mostrará que no existe un plan previo y pedirá usar rediscovery o selección manual.
- `stable_event_id` es la identidad lógica que usa la reconciliación v1
- findings y detections deben preservar estado usando fingerprints estables
- key events deberían pasar a `current` o `remapped`; si no encuentran equivalente, quedan `stale`

Si un artefacto cambió demasiado entre exportaciones:

- el fingerprint puede cambiar
- la reconciliación puede crear un objeto nuevo en vez de reaprovechar el anterior
- documenta el parser/fuente como limitación best-effort si no hay locator estable

## YARA unavailable

Comportamiento esperado:

- estado claro de unavailable
- warning controlado
- no `500`

Si esperabas YARA operativo, valida la dependencia del engine en la imagen backend.

## Sigma rule invalid

Comprueba:

- YAML válido
- `detection` y `condition` presentes
- campos mapeables al esquema normalizado

## Search devuelve 0

Comprueba:

- si estás filtrando por el host correcto. Search expande aliases como `HOSTA`, `hosta` y `hosta.example.local`, pero no debe mezclar hosts no relacionados.
- si la query está dentro del artifact correcto. Prueba primero sin `artifact_type` y luego acota.
- si estás excluyendo MFT u otro artifact con filtros negativos.
- si estás viendo solo backend default mientras el dato está en un backend advanced. Usa `backend_variant=advanced` o `backend_variant=all` cuando compares EZ Tool rebuilds.
- si el término existe realmente en los datos fuente. Un Defender log puede tener eventos de configuración sin threat strings como `credential-tool` o `VirTool`.
- que el caso activo, evidencia, host y rango temporal son los esperados.
- que la evidencia terminó en `completed` o `completed_with_warnings` con `investigation_ready=true`.
- que el caso no usa un índice viejo incompatible.

Queries de comandos:

- `-ep`, `-nop` y `-w` se tratan como texto, no como NOT.
- rutas como `C:\Users\Public\remote-admin.exe` y `.\f\script.ps1` deberían buscarse por path completo y basename.
- para excluir texto usa `exclude_q` o filtros `does not contain`.

Si usas sintaxis avanzada:

- comprueba comillas sin cerrar.
- usa solo campos soportados.
- recuerda que `Search` no soporta todo KQL/Lucene.
- prueba primero con:
  - `artifact.type:mft`
  - `risk_score>=70`
  - `process.name:powershell.exe`

Si una query avanzada es inválida, la app debe devolver `400` con ejemplos y no `500`.

## Evidence appears failed but has searchable data

Comportamiento esperado:

- si la evidencia tiene documentos indexados y es investigable, debe mostrar `investigation_ready=true`.
- si hubo warnings no críticos, el estado correcto es `completed_with_warnings`, no `failed`.
- optional parser errors, `tooling_missing`, unsupported artifacts and no-data families should not hide searchable data.

Acción:

- usa `Recompute evidence status` / `Repair evidence status` si la UI lo ofrece.
- revisa `status_reason`, `searchable_documents_count`, `warning_count` y `error_count`.

## SRUM detected but not parsed

Estado esperado en Linux:

- `SRUDB.dat` puede detectarse.
- `SrumECmd` requiere Windows ESE libraries.
- la app debe mostrar `tooling_missing` o `Requires Windows parser worker`.
- no debe marcar la evidencia failed.

Solución:

- configurar un Windows parser worker cuando exista.
- mientras tanto, usar otras fuentes: EVTX, Command History, MFT, Defender, Browser, Prefetch, Amcache/Shimcache.

## MFT full indexing is large

MFT full puede añadir cientos de miles de documentos.

Comportamiento esperado:

- se lanza solo con acción explícita.
- Search puede encontrar cualquier path/filename presente en la MFT.
- Timeline no incluye MFT por defecto.
- Evidence puede seguir `completed_with_warnings` si MFT full queda parcial o falla sin afectar otros datos.

Si Search parece inundado:

- filtra por `artifact_type`.
- excluye MFT con filtros negativos.
- usa Artifact Views MFT para paginación/columnas específicas.

## EZ advanced rebuild results look duplicated

LNK, Jumplist, Amcache y Shimcache pueden tener:

- backend default/internal
- backend advanced EZ Tool

Search default oculta advanced para evitar duplicados. Usa:

- `backend_variant=advanced`
- `backend_variant=all`
- `parser_backend=<backend>`

para comparar. No borres internal docs sin una decisión explícita de activación default.

## PECmd is available but Prefetch rebuild is disabled

En este Linux deployment, PECmd raw `.pf` parsing requiere Windows decompression support. La plataforma usa parser interno de Prefetch.

Esto es una limitación de backend, no fallo de evidencia.

## Shellbags detected but no rows indexed

Shellbags desde raw hives (`NTUSER.DAT`, `UsrClass.dat`) están pendientes de backend dedicado.

Estado esperado:

- candidatos detectados.
- no parseados como Shellbags.
- User Activity puede seguir indexando UserAssist, RecentDocs, RunMRU u OpenSaveMRU si existen.

## `POST /correlate` devuelve 422

Comportamiento esperado actual:

- `POST /api/cases/{case_id}/correlate` acepta body vacío
- `POST /api/cases/{case_id}/correlate` con `{}` también funciona

Si vuelve a aparecer un `422`, revisa:

- que backend/worker estén reconstruidos con la versión actual
- que no estés llamando a un contenedor viejo
- que el endpoint no esté siendo interceptado por un cliente con esquema desactualizado

## Process Graph vacío o con ambigüedad

Comprueba:

- modo `suspicious` vs `full graph`
- filtros de host/evidence
- `warnings_summary`
- `process_tree_report.json`

Si hay muchas ambigüedades, la app debe resumirlas, no inundar el canvas.

## Build frontend lento o warning de chunk

La app usa lazy loading por rutas principales para reducir el bundle inicial.

Comprueba:

- `npm run build`
- que `Search`, `Timeline`, `Process Graph`, `Reports`, `Rules`, `Detections`, `Docs` y el resto de workspaces salgan como chunks separados
- que no estés sirviendo un frontend viejo tras el rebuild

Si reaparece un warning de chunk grande:

- revisa imports pesados añadidos a `App.tsx`
- evita importar helpers de reportes, markdown o graph fuera de su ruta
- revisa `vite.config.ts` y los `manualChunks`

## Validation case bootstrap fails

Comprueba:

- backend accesible en `http://127.0.0.1:8000`
- worker activo para ingestas y rule runs
- el archivo de validación existe fuera del repositorio
- el caso de validación se creó con nombres genéricos

Si faltan detecciones YARA pero el resto del flujo de validación funciona:

- revisa `GET /api/rules/engines/status`
- confirma si `yara-python` está disponible en la imagen backend
- trátalo como limitación conocida no bloqueante si Sigma, findings, reports y debug export están sanos

## Rules o Detections no muestran el resultado esperado

Comprueba primero qué motor estás usando:

- `Sigma`
  - corre sobre eventos indexados
- `YARA`
  - corre sobre ficheros preservados

Errores de interpretación comunes:

- lanzar YARA esperando hits sobre logs ya indexados
- lanzar Sigma esperando que inspeccione binarios, scripts o documentos sin indexar
- importar un pack YARA desde la sección Sigma o al revés

Verifica:

- `Rules -> Rule Runs` para estado, volumen y errores
- `Detections` filtrando por `source=sigma` o `source=yara`
- `Search` con:
  - `detection.source:sigma`
  - `detection.source:yara`

Si un run sigue en `queued` o `running` durante demasiado tiempo:

- revisa `heartbeat`
- si no hay heartbeat reciente, trátalo como `stale`
- usa `Mark stale runs` o la acción individual `Mark failed/stale`
- si necesitas repetirlo, usa `Retry run`
- si el worker ni siquiera llegó a arrancarlo, puedes `Cancel run`

Si `Open Detections` desde un run parece incompleto:

- recuerda que la correlación exacta por `rule_run_id` depende del contexto disponible del run
- revisa también `Rule Runs` y `Search` para validar si hubo `duplicates skipped`

Si necesitas limpiar el inventario de reglas:

- usa `Rule Library`
- filtra por `engine`, `namespace`, `estado` o texto
- prueba primero con `Disable selected` si no quieres borrarlas todavía
- `Delete all imported rules` requiere escribir `DELETE RULES`
- borrar reglas o run records no elimina detecciones ya generadas

## `stable_event_id` o reconciliación no aparecen en debug export

Comprueba:

- `event_identity_report.json`
- `reconciliation_report.json`
- que el backend indexe `stable_event_id` y `event_fingerprint`
- que `debug_export` esté pidiendo esos campos en `_source`

Si el runtime usa contenedores viejos:

- los tests pueden pasar localmente pero los ingests reales seguirán sin `stable_event_id`
- reconstruye `backend` y `worker`

## Renombré o fusioné hosts y cambiaron los resultados

Comportamiento esperado:

- `Search`, `Timeline` y `Reports` deben usar el host canónico con expansión a aliases
- el detalle sigue mostrando `Observed as` cuando el evento llegó con otro nombre
- `stable_event_id` no debería depender del nombre canónico renombrado manualmente

Si algo no cuadra:

- revisa `event_identity_report.json`
- revisa `host_identity_report.json`
- confirma que backend y worker estén reconstruidos con la versión actual

## Report sin key events

El informe puede salir pobre si no seleccionas:

- findings relevantes
- key events
- process chains

## PDF unavailable

Es el comportamiento esperado hoy. El estado correcto es `not yet available` / `501`, no error silencioso.
