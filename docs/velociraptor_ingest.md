# Velociraptor Ingest

## Qué es una colección Velociraptor

Una colección Velociraptor suele contener:

- `uploads/`
- `results/`
- rutas percent-encoded como `C%3A/Users/...`

La app normaliza esas rutas para poder inferir usuario, navegador, perfil y tipo de evidencia.

## Qué soporta ahora

Discovery:

- Browser raw
- EVTX raw
- Prefetch raw
- LNK raw
  - `Recent`, `Office\\Recent`, `Desktop`, `Downloads`, `Start Menu` y `Startup`
- Registry hives
- MFT/USN raw
- Jump Lists raw
- otros candidatos relevantes

Parseo directo implementado en esta iteración:

- Chromium `History`
- Firefox `places.sqlite`
- Scheduled Tasks XML desde `Windows\\System32\\Tasks\\*`
- Defender raw desde `DetectionHistory` y `MPLog*.log`
- PowerShell raw desde `ConsoleHost_history.txt`, transcripts y scripts observados
- Recycle Bin raw desde `$Recycle.Bin\\<SID>\\$I*` y pairing `$I/$R`
- Shellbags CSV de `SBECmd` y discovery raw de `NTUSER.DAT` / `UsrClass.dat`
- JumpLists CSV de `JLECmd`, parseo raw de `*.automaticDestinations-ms` y soporte parcial para `*.customDestinations-ms`
- `setupapi.dev.log` raw para actividad USB enriquecida
- Prefetch raw nativo desde `Windows\\Prefetch\\*.pf`
- discovery raw de `qmgr0.dat`, `qmgr1.dat` y `qmgr.db` para BITS, además de CSV/JSON/TXT parseado compatible

## Flujo

1. Subir ZIP o carpeta Velociraptor.
2. Leer el inventario del contenedor sin extraerlo completo.
3. Ejecutar discovery sobre los nombres/rutas del inventario.
4. Revisar evidencias detectadas.
5. Seleccionar Browser, Scheduled Tasks, Defender, PowerShell, Recycle Bin, Shellbags u otros soportados.
6. Extraer solo los ficheros necesarios para las categorías elegidas.
7. Encolar parseo.

## ZIP inventory y selective extraction

La app ya no extrae todo el ZIP de Velociraptor al inicio.

Fases principales:

- `indexing_zip`
- `discovering_candidates`
- `waiting_selection`
- `extracting_selected`
- `parsing`
- `indexing_events`

Para ZIP se usa el índice interno (`ZipFile.infolist()`) y la detección trabaja sobre ese inventario. Para carpetas ya extraídas se recorre el árbol local y solo se copian a staging los ficheros que el parser necesita.

## Qué se ignora automáticamente

- `__MACOSX/`
- `.DS_Store`
- `._*`
- `Thumbs.db`
- `desktop.ini`
- directorios
- ficheros vacíos irrelevantes

Estos elementos quedan auditados, pero no se usan en discovery ni se extraen.

## Extracción selectiva de Browser

Si el usuario selecciona solo Browser, la app extrae únicamente:

- Chromium `History`
- `History-wal`
- `History-shm`
- Firefox `places.sqlite`
- `places.sqlite-wal`
- `places.sqlite-shm`

No extrae por defecto:

- `Cache`
- `Code Cache`
- `GPUCache`
- `Service Worker`
- `IndexedDB`
- `Local Storage`
- `Cookies`
- `Login Data`
- `Web Data`

## Normalización de paths

La app convierte conceptualmente:

- `C%3A/Users/alex/...`
- `C:/Users/alex/...`
- `C:\\Users\\alex\\...`

en una forma útil para investigación:

- `C:\\Users\\alex\\...`

El path original de Velociraptor también se preserva en:

- `velociraptor.original_path`

## Evidencias detectadas pero aún no parseadas raw

Se muestran como `detected_not_implemented`:

- Registry hives raw
- MFT/USN raw
- Shellbags raw hives (`NTUSER.DAT`, `UsrClass.dat`) cuando no hay parser raw de hive
- JumpList raw `customDestinations-ms` cuando una entrada concreta no puede resolverse más allá de soporte parcial

Para esas fuentes, en algunos casos sigue siendo preferible usar salidas CSV parseadas por EZ/KAPE cuando ya existan, especialmente para `customDestinations-ms`.

## Troubleshooting

- `C%3A` en rutas:
  la colección usa percent-encoding; la app lo normaliza.
- `La fase extracting tarda mucho`:
  en el flujo nuevo, si solo seleccionas Browser no debería extraerse toda la colección. Revisa `selected_files_total` y `selected_files_extracted` en la evidencia.
- `El ZIP contiene __MACOSX`:
  esos elementos se ignoran automáticamente y no deberían aparecer como candidatos.
- `No aparecen candidatos Browser`:
  comprueba que la colección contiene `History` o `places.sqlite` en rutas compatibles.
- `Solo quiero parsear Browser`:
  selecciona solo Browser; la app extraerá únicamente los SQLite y sus WAL/SHM asociados.
- `Quiero investigar USB`:
  selecciona USB; la app extraerá `setupapi.dev.log` y CSVs USB compatibles, no la colección completa.
- `Quiero investigar BITS`:
  selecciona BITS; la app extraerá CSV/JSON/TXT compatibles y, si existen, preservará `qmgr*.dat` / `qmgr.db` sin extraer toda la colección.
- `La colección está ya extraída`:
  la app no duplica toda la carpeta; recorre los paths y solo copia a staging los ficheros requeridos por el parser.
- SQLite sin WAL/SHM:
  puede faltar actividad reciente.
- SQLite corrupto:
  se registran warnings y no debe romper toda la colección.
- CSV de NirSoft vacío:
  el parser directo desde Velociraptor puede ser mejor opción para navegador.
- Hindsight/XLSX:
  puede ser menos cómodo para la plataforma que parsear SQLite raw directamente.
## WMI repository raw

La discovery de Velociraptor detecta actualmente:

- `OBJECTS.DATA`
- `INDEX.BTR`
- `MAPPING*.MAP`
- `Microsoft-Windows-WMI-Activity%4Operational.evtx`

Estado actual:

- CSV/JSON WMI parseado: `ready`
- `WMI Activity` EVTX: `handled_by_evtx_parser`
- repositorio raw WMI: `detected_not_implemented`

Eso significa que el repositorio raw se preserva y aparece en la UI, pero no debe mostrarse como parseado falsamente hasta que exista parser binario real.
# Autoruns / ASEP en Velociraptor

- Discovery detecta salidas `Autoruns/Autorunsc` parseadas, startup folder files, hives ASEP candidatos, Task XML y repositorio WMI raw relacionado.

# Cloud Sync en Velociraptor

- Discovery detecta sync roots de OneDrive, Google Drive / DriveFS, Dropbox, MEGAsync, iCloud y Box.
- También detecta configs/logs pequeños y outputs parseados `Cloud*.csv/json` cuando existan.
- Las carpetas cloud completas quedan como `discovery_only` o `path_inference`: no se extraen masivamente por defecto.
- Si solo hay rutas cloud observadas, la app lo tratará como evidencia de uso o staging potencial, no como upload confirmado.

# Network / WLAN / DNS en Velociraptor

- Discovery detecta `WLAN` profile XML bajo `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml`.
- Detecta `hosts` en `Windows/System32/drivers/etc/hosts`.
- Detecta CSV/JSON/TXT de red como `DNSCache`, `ipconfig`, `netsh`, `netstat`, `arp`, `NetAdapter`, `NetIPConfiguration` y similares.
- `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx` se clasifica como `handled_by_evtx_parser`.
- Hives raw `SOFTWARE`, `SYSTEM` y `NTUSER.DAT` relacionados con `NetworkList` / `Tcpip` se preservan como candidatos y no deben mostrarse como parseados si no existe parser raw.
# Velociraptor raw discovery can now route EVTX and LNK files to native Kairon DFIR parsers without requiring EvtxECmd or LECmd first.
