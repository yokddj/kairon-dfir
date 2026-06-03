# BITS

## Qué es

BITS (`Background Intelligent Transfer Service`) es el servicio de Windows usado para transferencias en segundo plano.

Puede ser legítimo:

- Windows Update
- Microsoft Store
- navegadores y aplicaciones normales

Pero también puede ser abusado para:

- descargar payloads
- mantener jobs persistentes
- ejecutar notify commands
- esconder actividad de red dentro de un servicio legítimo

## Qué soporta la app

- discovery raw de `qmgr0.dat`, `qmgr1.dat` y `qmgr.db` desde Velociraptor
- CSV parseados de BITS
- JSON parseados de BITS
- salida tipo `bitsadmin`
- correlación con PowerShell, Browser, Defender, MFT/USN, Prefetch, LNK/JumpLists y Scheduled Tasks

## Qué se parsea directamente desde Velociraptor

En esta iteración:

- los `qmgr*.dat` y `qmgr.db` se detectan y preservan como raw
- no se parsean todavía como base de datos binaria
- los EVTX BITS se detectan como `handled_by_evtx_parser`

Esto significa:

- `qmgr` raw = discovery honesto, no parseo fingido
- CSV/JSON/TXT parseado = soporte real

## Qué campos se extraen

- Job ID / GUID
- display name
- owner / owner SID
- state
- type
- priority
- remote URL / remote name
- local path / local name
- bytes total / transferred
- files total / transferred
- creation / modification / completion / expiration times
- notify command
- error code / description

## Cómo interpretar estados BITS

- `queued`, `connecting`, `transferring`: job activo o pendiente
- `transferred`: transferencia completada, no implica ejecución
- `acknowledged`: job completado y reconocido
- `suspended`, `error`, `transient_error`: job fallido o estancado

## Notify command

`notify_cmd_line` es especialmente importante:

- puede ejecutar un comando al completarse el job
- puede ser persistencia o automatización legítima
- sube mucho de valor si usa `powershell`, `cmd /c`, `mshta`, `rundll32` o `regsvr32`

## Diferencia entre uso legítimo y posible abuso

Un job BITS no es sospechoso por sí solo.

Sube de interés si coincide con:

- URL externa rara o IP directa
- HTTP claro para scripts o ejecutables
- `AppData`, `Temp`, `ProgramData`, `Public`, `Startup`
- payloads `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.msi`
- notify command
- correlación posterior con PowerShell, Defender, MFT o ejecución

## Correlación

La app cruza BITS con:

- PowerShell: `Start-BitsTransfer`, `bitsadmin`, `Add-BitsFile`, `Set-BitsTransfer`
- Browser: misma URL o mismo target path
- Defender: `bits.local_path`
- MFT/USN: creación/modificación del archivo local
- Prefetch / ejecución: archivo descargado ejecutado después
- Scheduled Tasks: tarea que ejecuta el archivo descargado
- JumpLists / LNK: archivo descargado luego abierto
- SRUM: contexto de red de fondo

## Falsos positivos comunes

- Windows Update
- Microsoft Store
- instaladores corporativos
- aplicaciones de terceros que usan BITS como backend legítimo

## Limitaciones

- `qmgr` raw todavía no tiene parser específico
- Windows Update genera bastante ruido benigno
- un job no prueba ejecución por sí solo
- `source_file_mtime` es solo fallback temporal si faltan timestamps propios del job

## Cuándo considerar BITS evidencia fuerte

La confianza sube si hay varias piezas a la vez:

- `remote_url` clara
- `local_path` claro
- timestamp de completion/modification
- notify command
- correlación con PowerShell
- creación del archivo en MFT
- ejecución posterior en Prefetch/EVTX
- detección posterior por Defender
