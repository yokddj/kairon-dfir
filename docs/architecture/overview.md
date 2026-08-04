# Arquitectura

## Resumen

Kairon DFIR está dividida en tres planos:

1. **Frontend** para el flujo del analista.
2. **Backend** para casos, evidencias, eventos, reglas y análisis.
3. **OpenSearch + PostgreSQL + filesystem** para búsqueda, metadatos y almacenamiento.

El pipeline actual ya tiene rutas especializadas para:

- EVTX
- Prefetch
- LNK / Jump Lists
- Registry
- MFT / USN
- Browser
- Amcache / ShimCache / AppCompat
- SRUM
- Scheduled Tasks
- PowerShell artifacts fuera de EVTX
- Recycle Bin
- USB enriquecido

Todas convergen en `NormalizedEvent` y desde ahí alimentan Search, Artifact Explorer, Timeline, detections y análisis semiautomático.

## Frontend

### Stack actual

- React 18
- TypeScript
- Vite
- TailwindCSS
- React Query
- React Router

### Páginas principales

- `Dashboard`
- `Cases`
- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Análisis semiautomático`
- `Activity`
- `SIEM`
- `Rules`
- `Detections`
- `Findings`
- `Docs`
- `System`

### Routing y navegación

El frontend usa rutas React y un `Sidebar` único como punto principal de navegación. La nueva sección `Docs` vive en `/docs`.

## Backend

### Stack actual

- FastAPI
- SQLAlchemy
- PostgreSQL
- Redis + RQ
- OpenSearch

### Módulos principales

- `backend/app/api/`
  - Rutas REST de casos, evidencias, búsqueda, reglas, actividad, sistema y findings.
- `backend/app/ingest/`
  - Detección de artefactos, parsers y normalización.
- `backend/app/analysis/`
  - Generación de `ForensicActivity` y análisis semiautomático.
- `backend/app/rules_engine/`
  - Ejecución de Sigma, heurística y YARA.
- `backend/app/core/`
  - Base de datos, OpenSearch, actividad, configuración y helpers.

### Rutas API importantes

- Casos:
  - `GET /api/cases`
  - `POST /api/cases`
  - `DELETE /api/cases/{case_id}`
- Evidencias:
  - `POST /api/evidences/upload`
  - `POST /api/evidences/upload-folder`
  - `POST /api/evidences/{evidence_id}/reprocess`
- Búsqueda:
  - `POST /api/search`
  - `POST /api/search/deep`
- Reglas:
  - `GET /api/rules`
  - `POST /api/rules/import-file`
  - `POST /api/rules/import-archive`
  - `POST /api/rules/{rule_id}/run`
- Análisis semiautomático:
  - `GET /api/cases/{case_id}/analysis/semi-auto`

## Almacenamiento

### PostgreSQL

Se usa para:

- casos
- evidencias
- artefactos
- reglas
- detections
- findings
- activity
- rule runs

### OpenSearch

Se usa para:

- eventos normalizados
- búsqueda global
- timeline
- filtros por campo
- SIEM Lite
- base del análisis semiautomático

### Filesystem

Se usa para:

- conservar el archivo original subido
- staging selectivo de ficheros requeridos por el parser
- guardar manifest y árbol de evidencia

### Velociraptor ZIP inventory

Para colecciones Velociraptor ZIP, el backend ya no extrae todo el contenedor al inicio.

Ahora el flujo es:

- inventario del ZIP
- discovery por rutas/nombres del inventario
- selección de categorías
- extracción selectiva de los ficheros requeridos
- parseo
- indexación

Esto reduce drásticamente el coste cuando el analista solo quiere parsear una categoría concreta como Browser.

## Flujo de datos

```text
Colección / evidencia
  -> detector de tipo
  -> parser específico o genérico
  -> evento normalizado
  -> OpenSearch
  -> reglas / detections
  -> forensic activities
  -> UI
```

## Modelo conceptual

- **Raw evidence**: archivo original conservado.
- **Parsed artifact**: CSV/JSON/JSONL/TXT ya procesado por otra herramienta.
- **NormalizedEvent**: documento común indexado.
- **Detection**: señal automática o match de regla.
- **Finding**: hallazgo consolidado por el analista.
- **ForensicActivity**: actividad agrupada para el análisis semiautomático.

## Decisiones importantes actuales

### CSV de EZ Tools como fuente principal

La fuente principal actual para Windows es **EZ Tools parseado**, no el raw EVTX.

### EVTX vía EvtxECmd

`EvtxECmd_Output.csv` es hoy la ruta principal y más robusta para:

- logons
- PowerShell
- servicios
- tareas
- red
- Defender
- RDP

### PowerShell fuera de EVTX

`ConsoleHost_history.txt`, transcripts y scripts observados ya tienen parser específico propio y convergen también en `NormalizedEvent`.

Se usan para:

- comandos interactivos observados
- `EncodedCommand`
- `Invoke-WebRequest` / `DownloadString` / `IEX`
- Defender tampering
- persistencia vía tareas, Run Keys o servicios
- correlación con `4104`, `4688`, Prefetch, Browser, MFT, Defender y SRUM

### Recycle Bin

`RBCmd_Output.csv` y los artefactos raw `$I/$R` desde Velociraptor ya tienen parser específico y también convergen en `NormalizedEvent`.

Se usan para:

- reconstruir archivos enviados a la papelera
- recuperar ruta original, SID, tamaño y `deleted_time`
- emparejar `$I` y `$R`
- correlacionar con Browser downloads, `MFT/USN`, Defender, PowerShell, Prefetch y Scheduled Tasks

### USB enriquecido

`setupapi.dev.log` y CSVs USB/Registry compatibles ya tienen parser específico y también convergen en `NormalizedEvent`.

Se usan para:

- observar dispositivos USB y volúmenes removibles
- extraer `vendor`, `product`, `serial`, `device_instance_id` y mapeos de volumen
- correlacionar con `LNK`, `JumpLists`, `Shellbags`, `Browser`, `PowerShell`, `MFT/USN` y `Recycle Bin`

### BITS

BITS ya entra como familia específica de `NormalizedEvent`.

Fuentes soportadas en esta iteración:

- CSV/JSON/TXT parseado compatible
- discovery raw de `qmgr*.dat` y `qmgr.db`
- EVTX BITS manejado por el parser de eventos cuando exista esa ruta

Objetivo semántico:

- observar jobs y transferencias en segundo plano
- distinguir jobs benignos de candidatos de abuso
- elevar la confianza cuando el archivo descargado luego se ejecuta o es detectado

### Prefetch vía PECmd

`PECmd_Output.csv` ya tiene parser específico y se usa para:

- programas ejecutados
- PowerShell observado por Prefetch
- hallazgos sospechosos por LOLBins o rutas
- timeline
- correlación básica con EVTX 4688

### LNK vía LECmd

`LECmd_Output.csv` ya tiene parser específico y se usa para:

- archivos abiertos
- documentos accedidos
- scripts y ejecutables abiertos por el usuario
- rutas UNC y accesos a red
- indicios de USB o medios removibles
- correlación básica con Prefetch y EVTX 4688

### Jump Lists vía JLECmd y raw Velociraptor

`JLECmd_Output.csv` ya tiene parser específico y ahora se complementa con parseo raw de `automaticDestinations-ms` y soporte parcial para `customDestinations-ms`:

- documentos recientes por aplicación
- archivos y scripts abiertos
- interacción de usuario por `AppID`
- rutas UNC y posibles USB
- correlación básica con LNK, Browser, Recycle Bin, Shellbags, Prefetch y EVTX 4688
- `automaticDestinations` raw parseable desde colecciones Velociraptor
- `customDestinations` raw con soporte parcial y warnings controlados

### Registry vía RECmd

`RECmd_Output.csv` y CSVs compatibles de RECmd Batch ya tienen parser específico y se usan para:

- persistencia por Run Keys y Services
- ejecución observada vía UserAssist y BAM/DAM
- indicios de presencia/uso vía MUICache
- USBSTOR y MountedDevices
- TypedPaths, RunMRU, RecentDocs, RDP MRU y Shellbags
- `SBECmd` como fuente específica de `folder_activity`, `network_share_activity`, `usb_folder_activity`, `cloud_folder_activity` y correlaciones con LNK/JumpLists/Recycle Bin
- `WMI` como fuente específica de `wmi_filter`, `wmi_consumer`, `wmi_binding`, `wmi_persistence_candidate`, `wmi_activity_query` y correlaciones con PowerShell, Defender, Prefetch, Amcache, MFT, Browser y BITS
- correlación básica con EVTX, Prefetch, LNK y Jump Lists

### Sistema de archivos vía MFTECmd

`MFTECmd_Output.csv` y CSVs compatibles de `USN Journal` ya tienen parser específico y se usan para:

- observación de archivos y carpetas históricas
- deleted candidates vía `InUse = false`
- ADS
- creaciones, borrados, renombrados y modificaciones vía USN
- detección básica de posibles discrepancias `$SI/$FN`
- correlación básica con EVTX, Prefetch, LNK, Jump Lists y Registry

### Browser activity vía CSV/JSON parseado

Outputs compatibles de `BrowserHistoryView`, `BrowsingHistoryView`, exports CSV/JSON de `History` / `Downloads` y formatos similares ya tienen parser específico y se usan para:

- historial de navegación
- descargas
- términos de búsqueda
- correlación básica descarga -> archivo creado -> archivo abierto -> ejecución

### Execution artifacts vía CSV parseado

Outputs compatibles de `AmcacheParser`, `AppCompatCacheParser`, `ShimCacheParser`, `RecentFileCache` y algunos CSVs de `RECmd Batch` ya tienen parser específico y se usan para:

- inventario de programas observados
- presencia o posible ejecución histórica
- hashes y metadatos PE
- correlación con Browser, MFT/USN, Prefetch, EVTX, Registry y Defender

Se interpretan de forma conservadora:

- `Amcache`: observación / inventario, no ejecución confirmada por defecto
- `ShimCache` / `AppCompat`: presencia o posible ejecución, no ejecución confirmada por defecto

### Velociraptor collection discovery

La app ya tiene una ruta específica para colecciones Velociraptor:

1. subir ZIP o carpeta
2. hacer discovery de evidencias
3. seleccionar candidatos soportados
4. encolar parseo selectivo

En esta fase el parseo raw implementado directamente sobre Velociraptor es:

- Chromium `History`
- XML raw de `C:\Windows\System32\Tasks\*`
- artefactos raw de Defender como `DetectionHistory` y `MPLog*.log`

### Scheduled Tasks

XML raw de `C:\Windows\System32\Tasks\*` y CSVs compatibles de Scheduled Tasks ya tienen parser específico y se usan para:

- observar definición de tareas
- detectar persistencia por tareas habilitadas con acciones `Exec` o `ComHandler`
- extraer `RunAs`, `RunLevel`, triggers, command, arguments y working directory
- detectar PowerShell codificado, LOLBins, rutas sospechosas, rutas UNC y tareas `hidden + enabled`
- correlacionar con EVTX `4698/4702/106/140/200/201/102`, Prefetch, Browser downloads, MFT/USN, Registry, SRUM y Defender

Se interpretan de forma conservadora:

- XML raw o CSV de tarea: **definición observada**
- EVTX TaskScheduler/Security: **creación, modificación o ejecución observada**
- la confianza sube cuando hay correlación con ejecución o con archivos descargados/presentes
- Defender raw/log/CSV/JSON sigue el mismo patrón del resto: parser específico, normalización a `artifact.type = defender` y correlación posterior con Browser, MFT/USN, Prefetch, EVTX, Scheduled Tasks, Registry y SRUM
- Firefox `places.sqlite`
- correlación básica con MFT/USN, LNK, Jump Lists, Prefetch, EVTX y Defender

### Raw preservado, no indexado dinámicamente

Los eventos preservan:

- `raw`
- `windows.event_data`
- `windows.payload`

pero esos contenedores no se expanden dinámicamente en OpenSearch.

### OpenSearch con `dynamic: false`

Se usa para evitar explosión de campos al indexar EVTX con payloads variables.
# Actualización de arquitectura

- La familia `autoruns` añade un namespace `autoruns.*` y otro `persistence.*` con mapping explícito `dynamic: false`, además de correlación semiautomática con Browser, BITS, Defender, Prefetch, WMI, Scheduled Tasks y Registry.
- La familia `cloud_sync` añade un namespace `cloud.*` con mapping explícito `dynamic: false`, detección por path inference, parse genérico CSV/JSON/log, y correlación semiautomática con Browser, BITS, PowerShell, MFT, Recycle Bin, Defender, Autoruns, WMI y USB.
- La familia `network` añade namespaces `network.*`, `wlan.*` y `dns.*` con mapping explícito `dynamic: false`, parse de WLAN XML / `hosts` / DNS-network CSV-JSON-TXT, clasificación de WLAN AutoConfig EVTX y Registry `NetworkList` / `Tcpip`, además de correlación semiautomática con Browser, BITS, PowerShell, Defender, Cloud Sync, SRUM y MFT.
# Raw parser foundation now exists for direct native parsing of EVTX and LNK, alongside the existing external CSV workflows.
## Debug Export Pack

La arquitectura incluye un servicio de exportación de validación/debug que genera un ZIP reducido por caso, evidencia, búsqueda, vista de artefactos o análisis semiautomático. El pack reutiliza manifests de evidencia, muestras indexadas desde OpenSearch, resultados de reglas, análisis semiautomático y errores de ingesta, con redacción y truncado por defecto para facilitar revisión externa sin compartir la evidencia completa.
