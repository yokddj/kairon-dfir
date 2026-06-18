# Secciones de la aplicación

## Dashboard

- **Para qué sirve**: vista rápida del estado general del caso/plataforma.
- **Qué muestra**: contadores, estado, resumen de actividad.
- **Qué mirar primero**: si hay eventos indexados, evidencias y detections.

## Cases

- **Para qué sirve**: crear, abrir y borrar casos.
- **Qué muestra**: lista de casos y acceso al detalle.
- **Qué mirar primero**: qué caso está activo y qué evidencias tiene.

## Search

- **Para qué sirve**: búsqueda global sobre eventos normalizados.
- **Qué muestra**: tabla global para resultados mixtos, con vistas específicas si el set es homogéneo.
- **Qué admite**:
  - query textual
  - IOC
  - contains
  - filtros por campo
  - paginación
- **Cuándo usarlo**: cuando todavía no sabes de qué fuente viene la pista y quieres encontrar rápido texto, usuarios, EventIDs, rutas, claves Registry, hashes o IPs.
- **Qué mirar primero**: `windows.event_id`, `event.type`, `process.command_line`, `tags`
- **Crear findings**: selecciona eventos y usa `Create Finding from selected events`

## Artifact Explorer

- **Para qué sirve**: revisar una fuente concreta con columnas específicas por tipo de evidencia.
- **Qué muestra**: eventos filtrados por `artifact.type` / `artifact.name`, con vistas adaptadas para `evtx`, `prefetch`, `lnk`, `jumplist`, `registry`, etc.
- **Cuándo usarlo**: cuando ya sabes que quieres revisar una fuente concreta y no una mezcla global.
- **Qué mirar**:
  - detalle JSON
  - `raw`
  - `windows.payload`
  - `lnk.effective_path`
  - `jumplist.effective_path`
  - `registry.key_path`
  - `registry.value_name`
  - `registry.value_data`
  - `tags`
  - `suspicious_reasons`
- **Crear findings**: selecciona eventos del artefacto actual y crea un finding ligado al caso

## Memory Analysis

- **Para qué sirve**: registrar y revisar el estado aislado de evidencia RAM/memoria autorizada.
- **Estado actual**: experimental y desactivado por defecto. Puede registrar uploads `memory_dump` autorizados y ejecutar perfiles Volatility 3 aislados cuando un administrador habilita explícitamente upload, ejecución externa y el `memory-worker`; MemProcFS sigue como readiness-only.
- **Flujo recomendado**: `Case -> Memory Analysis -> Add memory image`. El formulario genérico de Evidence Upload sigue funcionando, pero la subida dedicada muestra capacidad, privacidad, autorización y progreso de forma más clara.
- **Qué muestra**: modo del caso (`empty`, `disk_only`, `memory_only`, `hybrid`), evidencias `memory_dump`, upload readiness, backend readiness, runs metadata/process y resultados aislados.
- **Qué no hace todavía**: no añade memoria a Search, Timeline, Artifact Explorer, Detections, Findings, Reports, SIEM, Command History, Persistence ni Execution Stories.
- **Regla legal**: usa solo evidencia RAM propia, autorizada o de laboratorio creada para ese fin. No subas ni commits dumps con datos de terceros sin autorización.

## Investigation Timeline

- **Para qué sirve**: ordenar cronológicamente lo indexado.
- **Qué muestra**: eventos por timestamp.
- **Cómo usarla**: útil para reconstruir la secuencia global, entender qué pasó antes/después y pivotar a eventos concretos.
- **Cuándo usarla**: cuando la pregunta principal es temporal, no de tipo de artefacto.
- **Crear findings**: selecciona eventos de la secuencia temporal y conviértelos en un finding investigable

## Análisis semiautomático

- **Para qué sirve**: agrupar actividad ya normalizada por categorías útiles para DFIR.
- **Qué muestra**: programas, PowerShell, logons, RDP, tareas, servicios, red, Defender, suspicious findings, archivos abiertos, documentos recientes, aplicaciones usadas, scripts abiertos, rutas de red/USB y timeline.
- **Fuentes actuales fuertes**: EVTX vía `EvtxECmd_Output.csv`, Prefetch vía `PECmd_Output.csv`, LNK vía `LECmd_Output.csv` y Jump Lists vía `JLECmd_Output.csv`.
- **Qué mirar primero**: resumen, PowerShell, logons, persistencia, Defender y, si investigas interacción de usuario, `Archivos abiertos`, `Documentos recientes`, `Aplicaciones usadas` y `Scripts abiertos`.

## Activity

- **Para qué sirve**: actividad interna de la plataforma.
- **Qué muestra**: trabajos de ingesta, importación, rule runs, errores y eventos operativos.
- **Qué mirar primero**: si una evidencia no parsea o una regla no genera resultados.

## SIEM

- **Para qué sirve**: análisis avanzado y puente con OpenSearch Dashboards.
- **Qué muestra**:
  - OpenSearch Dashboards status
  - Query Builder
  - Field Explorer
  - Saved SIEM Queries
- **Qué mirar primero**: si necesitas pivotar por campo o abrir el caso en Dashboards.
- **Cuándo usarlo**: cuando `Search` ya no basta y necesitas consultas técnicas precisas por campo, DSL o exploración avanzada en OpenSearch Dashboards.

## Rules

- **Para qué sirve**: gestionar reglas y rule packs.
- **Qué muestra**:
  - reglas individuales
  - rule packs
  - rule runs
- **Qué mirar primero**: engine, enabled, últimas ejecuciones y errores.

## Detections

- **Para qué sirve**: revisar señales automáticas.
- **Qué muestra**: detections builtin, sigma, heuristic y yara.
- **Qué mirar primero**:
  - engine
  - severity
  - source
  - target_type
  - reason
- **Crear findings**:
  - `Create finding` para abrir un cuadro de edición desde una detection
  - `Create finding from selected detections` para varias detections del mismo caso
  - `Promote to finding` para promoción rápida

## Findings

- **Para qué sirve**: consolidar hallazgos investigables o confirmados.
- **Qué diferencia hay con Detections**:
  - `Detection` = señal automática
  - `Finding` = elemento ya promovido o confirmado por el analista
- **Cómo se crean hoy**:
  - manualmente desde la propia sección
  - desde eventos seleccionados en `Search`, `Artifact Explorer` y `Investigation Timeline`
  - desde `Detections`

## Docs

- **Para qué sirve**: manual de uso y mantenimiento de la herramienta.
- **Qué mirar primero**:
  - `Primeros pasos`
  - `EVTX`
  - `Análisis semiautomático`
  - `Troubleshooting`

## System

- **Para qué sirve**: estado de recursos y ajustes runtime/deploy.
- **Qué mirar primero**:
  - CPU/RAM/OpenSearch
  - workers
  - colas
  - `AUTO_CREATE_HEURISTIC_DETECTIONS`
