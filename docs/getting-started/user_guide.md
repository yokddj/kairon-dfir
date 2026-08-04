# User Guide

## Flujo end-to-end del analista

1. Crea o selecciona un `case`.
2. Sube un archivo o registra una ruta montada en `Evidence & Ingest`.
3. Introduce el host esperado/canónico, por ejemplo `HOST-A`.
4. Indexa la evidencia.
5. Comprueba Evidence Detail:
   - `investigation_ready=true`
   - `completed` o `completed_with_warnings`
   - documentos indexados > 0
   - warnings entendibles si existen.
6. Usa `Search` como workspace principal.
7. Cambia a `Timeline` desde Search cuando necesites reconstrucción temporal.
8. Usa `Artifact Views` para columnas específicas por familia.
9. Abre `Command History` para comandos consolidados.
10. Abre `Execution Story` desde Search o Command History para procesos concretos.
11. Marca eventos/comandos como `suspicious` o `important`.
12. Crea findings con eventos, comandos, detections y notas.
13. Genera reportes con findings, marked events, Command History, Execution Story y Defender.
14. Exporta Markdown.

## Generic investigation example

With a synthetic evidence package, a typical workflow is:

1. Search for a suspicious command pattern such as `powershell -ep bypass`.
2. Open the exact command event and review its Execution Story.
3. Pivot to downloaded files, user activity and filesystem artifacts referenced by the event.
4. Review Artifact Views for MFT, User Activity, Command History and Defender where available.
5. Mark reviewed events or commands as suspicious or important.
6. Create a finding and generate a Markdown report.

Not every term exists in every dataset. A zero-result search can be valid when the source evidence simply does not contain that artifact or string.

## Evidence status

Estados relevantes:

- `completed`: el pipeline terminó sin warnings relevantes.
- `completed_with_warnings`: hay datos investigables, pero también warnings, parsers opcionales fallidos o artefactos no soportados.
- `failed`: el pipeline principal no produjo datos investigables o falló críticamente.
- `investigation_ready`: indica que la evidencia tiene datos buscables aunque existan warnings.

No trates `completed_with_warnings` como fallo. Revisa `status_reason`, warnings y counts.

## Host identity

Search es alias-aware. Si el host canónico es `HOST-A`, el filtro debe recuperar documentos observados como:

- `HOST-A`
- `host-a`
- `host-a.example.local`

El detalle conserva valores observados para trazabilidad.

## Search

Search es la puerta de entrada principal. Úsalo para:

- comandos
- paths
- hashes
- dominios
- event IDs
- artifact filters
- marked events
- pivots a Command History, Execution Story, Timeline y Reports.

Ejemplos de queries humanas válidas:

- `powershell -ep bypass`
- `-nop`
- `-w hidden`
- `script.ps1`
- `C:\Users\Public\remote-admin.exe`
- `example-control.test`
- `sample.iso`

Los flags con guion se tratan como texto. Para exclusiones usa filtros explícitos o la UI de include/exclude, no `-term`.

## Timeline

Timeline es una vista de Search. Debe preservar:

- `case_id`
- `evidence_id`
- host
- query
- rango temporal
- artifact filters

MFT/filesystem no se incluye por defecto para evitar inundar la vista temporal. Activa `Include filesystem/MFT events` o filtra por `artifact_type=mft` cuando quieras ese timeline.

## Artifact Views

Artifact Views no reemplaza Search. Úsalo para revisar familias con columnas especializadas:

- MFT / Filesystem
- Defender
- User Activity
- Prefetch
- Scheduled Tasks
- Browser
- Services / Autoruns
- LNK / Jumplist
- Amcache / Shimcache

Cada vista debe indicar backend, cobertura y limitaciones. Cuando exista backend advanced, revisa si estás viendo default, advanced o compare.

## Command History

Command History consolida ejecuciones desde fuentes como Sysmon 1, Security 4688, PowerShell Operational, PSReadLine/transcripts si existen y scheduled tasks.

Campos clave:

- timestamp
- command
- source_type
- launcher
- family
- confidence
- parent process
- supporting events
- risk reasons

Prefetch puede aparecer como contexto de ejecución, pero no como command line exacta.

## Execution Story

Execution Story responde:

- Who launched this?
- What did it launch?
- What did it do?
- Why is it suspicious?
- What evidence supports this?

Cuando abras una story desde Search o Command History, el target debe resolverse por identidad exacta:

1. `source_event_id`
2. process GUID
3. PID + timestamp + host + evidence
4. texto solo como último fallback

Clickar un nodo muestra preview. Cambiar el target requiere la acción explícita `Make target`.

## Markings and findings

Usa markings para señalizar eventos o comandos:

- `suspicious`
- `important`
- `reviewed`
- `false_positive`

Después crea findings con:

- título claro
- severidad
- eventos/comandos relacionados
- detections si aplican
- notas del analista
- resumen de Execution Story si aporta contexto

## Reports

Reports puede incluir:

- findings
- detections
- marked events
- Command History
- Execution Story summaries
- Defender section
- analyst notes

Markdown es el export validado. PDF no debe considerarse estable salvo que se valide explícitamente en el despliegue.

## Rules and detections

Sigma:

- orientado a eventos normalizados.
- usa scopes pequeños o reglas concretas para smoke/control.
- revisa detections antes de promoverlas.

YARA:

- orientado a ficheros preservados.
- debe ejecutarse con límites de tamaño, roots y scope.
- no lo lances como full scan masivo sin control.

