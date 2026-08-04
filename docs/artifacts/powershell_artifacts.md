# PowerShell artifacts fuera de EVTX

## Qué artefactos soporta la app

La plataforma soporta hoy, fuera de EVTX:

- `ConsoleHost_history.txt` de `PSReadLine`
- `PowerShell_transcript*.txt` y variantes de transcript
- scripts `*.ps1`, `*.psm1`, `*.psd1` como contenido observado
- CSV/JSON parseados relacionados con PowerShell cuando tienen estructura compatible
- discovery raw desde colecciones Velociraptor

## Diferencia frente a EVTX 4104/4688

- `4104` y `4688` suelen aportar mejor contexto de ejecución y timestamps.
- `PSReadLine` aporta visibilidad de comandos interactivos escritos por el usuario.
- `Transcript` aporta más contexto operativo, metadatos de sesión y a veces tiempo por comando.
- Un script `.ps1` observado no prueba por sí solo ejecución.

## Qué es ConsoleHost_history.txt

Es el historial de comandos de `PSReadLine`. Suele contener un comando por línea.

Limitaciones importantes:

- normalmente no tiene timestamp por comando
- un comando presente no prueba ejecución exitosa
- puede contener comandos benignos junto a comandos sospechosos

## Qué son los PowerShell transcripts

Los transcripts son logs textuales de sesiones PowerShell. Pueden incluir:

- usuario
- `RunAs`
- máquina
- `Host Application`
- `Process ID`
- versión de PowerShell
- comandos emitidos desde el prompt

Son mucho más útiles que `PSReadLine` para reconstruir contexto temporal cuando existen.

## Qué campos se extraen

- `powershell.command`
- `powershell.command_preview`
- `powershell.line_number`
- `powershell.source_file`
- `powershell.transcript_start_time`
- `powershell.transcript_end_time`
- `powershell.username`
- `powershell.run_as`
- `powershell.machine`
- `powershell.host_application`
- `powershell.process_id`
- `powershell.ps_version`
- `powershell.has_encoded_command`
- `powershell.encoded_command`
- `powershell.decoded_command_preview`
- `powershell.has_download`
- `powershell.has_iex`
- `powershell.has_execution_policy_bypass`
- `powershell.has_defender_tampering`
- `powershell.has_persistence`
- `powershell.urls`
- `powershell.domains`
- `powershell.paths`
- `powershell.indicators`

Además, cuando procede:

- `process.command_line`
- `url.full`
- `url.domain`
- `file.path`

## Indicadores que detecta la app

- `EncodedCommand`
- `Invoke-Expression` / `IEX`
- download cradle
- `ExecutionPolicy Bypass`
- `NoProfile` / `WindowStyle Hidden` en contexto sospechoso
- Defender tampering:
  - `Set-MpPreference`
  - `Add-MpPreference`
  - `DisableRealtimeMonitoring`
  - exclusiones
- persistencia:
  - `Register-ScheduledTask`
  - `schtasks`
  - `reg add`
  - Run Keys
  - creación de servicios
- reconocimiento:
  - `whoami`
  - `hostname`
  - `ipconfig`
  - `systeminfo`
  - `tasklist`
- acceso a credenciales o dumping:
  - `lsass`
  - `mimikatz`
  - `sekurlsa`
  - `procdump`
  - `comsvcs.dll`

## Cómo se interpretan timestamps ausentes

- `PSReadLine` usa `source_file_mtime` como aproximación si está disponible.
- Si no hay tiempo fiable, queda `timestamp_precision = unknown`.
- En transcripts se prioriza:
  1. `Command start time`
  2. `transcript start time`
  3. `source file mtime`

Esto permite meter los eventos en timeline sin vender una precisión falsa.

## Cómo se correlaciona

La app correlaciona PowerShell con:

- EVTX `4104` y `4688`
- Browser downloads
- `MFT/USN`
- Prefetch
- Defender
- Scheduled Tasks
- Registry
- SRUM

Se crean actividades como:

- `powershell_download`
- `powershell_encoded_execution`
- `powershell_defender_tampering`
- `powershell_persistence`
- `powershell_recon`
- `powershell_credential_access`
- `downloaded_and_executed_via_powershell`

## Falsos positivos comunes

- administración legítima con PowerShell
- automatizaciones corporativas
- transcripts de soporte o troubleshooting
- scripts de login
- `ExecutionPolicy Bypass` en tooling interno

## Limitaciones

- `ConsoleHost_history.txt` no suele tener timestamps por comando
- historial observado no equivale a éxito o ejecución confirmada
- scripts observados no prueban ejecución
- la decodificación de Base64 es solo de vista previa y nunca ejecuta contenido
- no se estructuran credenciales ni secretos aunque aparezcan en raw

## Ejemplos de investigación

- `Invoke-WebRequest` seguido de archivo creado en `Downloads` y detección de Defender
- `IEX(New-Object Net.WebClient)...` correlacionado con `4104`
- `Set-MpPreference -DisableRealtimeMonitoring` antes de una detección fallida
- `schtasks /Create` o `Register-ScheduledTask` correlacionado con XML de Scheduled Tasks
