# Ingesta de evidencias

## Qué pasa cuando subes un archivo o carpeta

1. La evidencia se guarda en disco.
2. Si es ZIP/7z, se extrae.
3. Se recorre la estructura y se detectan artefactos.
4. Cada artefacto se clasifica por tipo y parser.
5. El normalizador genera eventos comunes.
6. Los eventos se indexan en OpenSearch.
7. Se actualiza el manifest de evidencia y la actividad de la plataforma.

## Cómo se detecta el tipo de evidencia

La detección mezcla:

- nombre de archivo
- ruta
- cabeceras del CSV/JSON
- convenciones conocidas de Velociraptor y KAPE/EZ Tools

## Parsers existentes hoy

### Parsers específicos

- `eztools/evtxecmd.py` -> `EvtxECmd_Output.csv`
- `eztools/pecmd.py` -> `PECmd_Output.csv`
- `eztools/lecmd.py` -> `LECmd_Output.csv`
- `eztools/jlecmd.py` -> `JLECmd_Output.csv`
- `eztools/recmd.py` -> `RECmd_Output.csv` y CSVs compatibles de RECmd Batch

### Normalizadores genéricos o parciales

Actualmente existen rutas parciales para artefactos parseados como:

- mft
- srum
- recycle bin
- browser
- network/process genérico

### Parsers preparados para futuro

- `raw/evtx.py`
- esqueletos EZ Tools:
  - `mftecmd.py`

## Qué se indexa y qué se preserva

### Se indexa

- campos normalizados
- `event.category`
- `event.type`
- `event.message`
- `windows.event_id`
- `process.*`
- `file.*`
- `network.*`
- `service.*`
- `task.*`
- `tags`
- `suspicious_reasons`
- `search_text`

### Se preserva sin indexación dinámica

- `raw`
- `windows.event_data`
- `windows.payload`
- XML bruto si está disponible

## Fuente principal actual: EvtxECmd_Output.csv

`EvtxECmd_Output.csv` es hoy la fuente principal de eventos Windows.

### Qué hace el parser

- detecta el CSV por nombre y cabeceras
- parsea filas de forma robusta
- extrae `Payload` JSON
- preserva `PayloadData*`
- valida `Provider/Channel`
- normaliza campos relevantes
- genera mensajes y tags útiles

### Reglas importantes

- `4625` **solo** es `logon_failed` si viene de:
  - `Channel = Security`
  - `Provider = Microsoft-Windows-Security-Auditing`
- `1102` se interpreta como `audit_log_cleared` si viene de:
  - `Channel = Security`
  - `Provider = Microsoft-Windows-Eventlog` o `Eventlog`

## Fuente actual de ejecución: PECmd_Output.csv

`PECmd_Output.csv` ya tiene parser específico para Prefetch.

### Qué hace el parser

- detecta el CSV por nombre y cabeceras
- extrae `ExecutableName`, `RunCount`, `LastRun` y `PreviousRun*`
- preserva la fila completa en `raw`
- normaliza `prefetch.*` y `execution.*`
- intenta inferir binario y rutas referenciadas
- marca LOLBins y rutas sospechosas
- deja auditoría post-ingesta por artefacto

### Qué alimenta

- `Search`
- `Artifact Explorer`
- `Timeline`
- `Análisis semiautomático > Programas ejecutados`
- `Análisis semiautomático > PowerShell` cuando el ejecutable es `powershell.exe` o `pwsh.exe`

## Fuente actual de Registry: RECmd_Output.csv

`RECmd_Output.csv` y CSVs compatibles de RECmd Batch ya tienen parser específico.

### Qué hace el parser

- detecta el CSV por nombre y cabeceras
- clasifica subtipos prioritarios
- preserva `raw`
- normaliza `registry.*`, `process.*`, `service.*`, `usb.*`, `volume.*` y `shellbag.*`
- marca persistencia, LOLBins, rutas sospechosas y actividad de usuario
- deja auditoría post-ingesta por artefacto

### Subtipos soportados

- Run Keys / RunOnce
- Services
- UserAssist
- BAM / DAM
- MUICache
- USBSTOR / USB devices
- MountedDevices
- TypedPaths
- RunMRU
- RecentDocs
- RDP MRU
- Shellbags
- Registry generic

## Errores típicos de ingesta

### 1. OpenSearch total fields limit

Suele indicar un índice antiguo o mapping incorrecto.

Qué revisar:

- `dynamic` debe ser `false`
- `raw`, `windows.event_data`, `windows.payload` deben tener `enabled: false`

### 2. Índice antiguo con mapping viejo

Si cambiaste campos normalizados y el caso sigue usando un índice viejo, puede haber inconsistencias.

Qué hacer:

- recrear el caso
- reimportar la evidencia

### 3. CSV no detectado como EvtxECmd

Qué revisar:

- nombre del archivo
- cabeceras típicas
- actividad y manifest de la evidencia

### 4. Eventos no aparecen por fallo de bulk indexing

Qué revisar:

- `Activity`
- errores del worker/backend
- auditoría post-ingesta del artefacto
