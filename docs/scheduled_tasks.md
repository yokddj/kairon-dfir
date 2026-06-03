# Scheduled Tasks / Task Scheduler

## Qué son

Las Scheduled Tasks de Windows describen **persistencia técnica y automatización**. El XML de `C:\Windows\System32\Tasks\...` representa la **definición** de la tarea, no una prueba de ejecución reciente por sí solo.

## Qué soporta ahora la plataforma

- XML raw desde:
  - `C:\Windows\System32\Tasks\*`
  - colecciones Velociraptor con rutas `uploads/auto/C%3A/Windows/System32/Tasks/...`
- CSV parseados compatibles con:
  - `*ScheduledTasks*.csv`
  - `*TaskScheduler*.csv`
  - `*Tasks*.csv`

## Qué campos se extraen

- `RegistrationInfo`: `Author`, `Description`, `Date`, `URI`, `Version`
- `Principal`: `UserId`, `GroupId`, `LogonType`, `RunLevel`
- `Settings`: `Enabled`, `Hidden`, `RunOnlyIfNetworkAvailable`, `ExecutionTimeLimit`, etc.
- `Triggers`: `BootTrigger`, `LogonTrigger`, `CalendarTrigger`, `EventTrigger`, `RegistrationTrigger`, `IdleTrigger`
- `Actions`:
  - `Exec`: `Command`, `Arguments`, `WorkingDirectory`
  - `ComHandler`: `ClassId`, `Data`

## Cómo se interpreta

- `scheduled_task_definition`: definición observada
- `scheduled_task_com_handler`: tarea con acción COM handler
- `scheduled_task_created` / `scheduled_task_updated`: eventos EVTX que prueban creación o modificación
- `task_execution`: actividad correlacionada con EVTX/Prefetch/ejecución

La app diferencia explícitamente:

- tarea observada
- tarea creada/modificada
- tarea posiblemente usada como persistencia
- tarea con ejecución correlacionada

## Qué significa Enabled / Hidden

- `Enabled=true`: la tarea está habilitada para ejecutarse
- `Hidden=true`: la tarea no se muestra normalmente en la interfaz

Una tarea `hidden + enabled` no es automáticamente maliciosa, pero sube interés si además usa PowerShell, LOLBins, rutas de usuario o comandos codificados.

## Qué es ComHandler

Una tarea con `ComHandler` no ejecuta un binario visible en `Command`, sino una clase COM. Es una técnica legítima del sistema, pero también puede ocultar persistencia menos evidente.

## Correlación

La plataforma correlaciona Scheduled Tasks con:

- EVTX:
  - Security `4698`, `4699`, `4700`, `4701`, `4702`
  - TaskScheduler Operational `106`, `140`, `141`, `200`, `201`, `102`, `129`
- Prefetch
- Browser downloads
- MFT / USN
- Registry
- Amcache / ShimCache
- SRUM
- Defender

## Hallazgos sospechosos típicos

- PowerShell con `-EncodedCommand`
- ejecución desde `AppData`, `Temp`, `Downloads`, `Users\Public`, `ProgramData`, `Desktop`
- uso de `mshta`, `regsvr32`, `wscript`, `cscript`, `certutil`, `bitsadmin`
- rutas UNC `\\server\share\...`
- tareas `hidden + enabled`
- nombres de tarea que imitan updates legítimos
- `ComHandler` poco habitual

## Limitaciones

- el XML no prueba ejecución por sí solo
- las tareas Microsoft legítimas generan mucho ruido
- el timestamp principal puede venir de `RegistrationInfo/Date` o del `mtime` del XML
- la confianza sube mucho cuando hay correlación con EVTX o Prefetch
