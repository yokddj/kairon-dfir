# Prefetch / PECmd / Native Prefetch

## Qué es Prefetch

Prefetch es un mecanismo de Windows que registra información resumida sobre ejecuciones de programas. En Kairon DFIR se puede consumir:

- `*_PECmd_Output.csv`
- `PECmd_Output.csv`
- `.pf` raw detectados directamente en `C:\Windows\Prefetch\*.pf`

Los CSV suelen venir de **PECmd** de Eric Zimmerman. Los `.pf` raw pueden parsearse de forma nativa dentro de la plataforma.

## Qué aporta en Kairon DFIR

Prefetch ayuda a responder preguntas como:

- ¿Qué binarios se ejecutaron?
- ¿Cuántas veces se ejecutaron?
- ¿Cuál fue la última ejecución observada?
- ¿Qué ficheros o directorios estaban relacionados con esa ejecución?

No sustituye a EVTX ni demuestra intención maliciosa por sí solo, pero añade una fuente muy útil de **evidencia de ejecución**.

## Campos principales usados

Kairon DFIR intenta extraer al menos:

- `ExecutableName`
- `ExecutablePath` cuando puede inferirse
- `RunCount`
- `LastRun` / `LastRunTime`
- `PreviousRun0..7`
- `SourceFilename` / `SourceFile`
- `FilesLoaded`
- `ReferencedFiles`
- `Directories`
- `VolumeSerialNumber`
- `VolumeDevicePath`
- `Version`
- `Signature`

## Qué significa RunCount

`RunCount` es el contador de ejecuciones observado en el artefacto Prefetch. Es útil para distinguir entre:

- una ejecución aislada
- una herramienta usada repetidamente
- binarios que forman parte de la operativa normal del equipo

No debe interpretarse solo. Un `RunCount` alto puede ser benigno.

## Qué significan LastRun y PreviousRuns

- `LastRun`: última ejecución observada por Prefetch.
- `PreviousRuns`: ejecuciones anteriores preservadas en el fichero Prefetch.

Kairon DFIR usa, por orden:

1. `LastRun` como `@timestamp` principal si existe
2. el último valor disponible de `last_runs` si no hay `LastRun`
3. `source_modified` / `source_file_mtime` solo como fallback

La hora real de parseo se guarda en `ingest.processed_at` y no debe usarse como tiempo forense.

## Qué son referenced files

PECmd puede exponer ficheros y directorios relacionados con la ejecución.

Kairon DFIR los guarda en:

- `prefetch.referenced_files`
- `prefetch.directories`

Esto es útil para detectar:

- scripts en `Downloads`
- binarios en `AppData`
- ejecución apoyada en ficheros sospechosos

## Qué significa ejecución confirmada

En la plataforma:

- `execution.source = prefetch`
- `execution.is_execution_confirmed = true`
- `execution.confidence = high`

porque Prefetch, cuando existe y está habilitado, es evidencia fuerte de ejecución del programa.

Esto no implica:

- command line conocido
- usuario conocido
- proceso padre conocido

## Cómo se usa en la app

Hoy Prefetch alimenta sobre todo:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Análisis semiautomático`

## Qué muestra el análisis semiautomático

### Programas ejecutados

Incluye eventos Prefetch como:

- nombre del proceso
- ruta inferida
- `run_count`
- `last_run`
- número de `previous_runs`
- confianza
- razones sospechosas

### PowerShell

Si el ejecutable es:

- `powershell.exe`
- `pwsh.exe`

Kairon DFIR también lo incluye en la sección `PowerShell` con el mensaje:

> PowerShell execution observed via Prefetch

### Hallazgos sospechosos

Prefetch puede generar señales si detecta:

- LOLBins (`powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`, etc.)
- rutas sospechosas
- referenced files en `AppData`, `Temp`, `Downloads`, `Users\\Public`, `ProgramData`, UNC paths, etc.

## Correlación con EVTX 4688

Kairon DFIR intenta una correlación básica entre:

- EVTX `4688` (`process_creation`)
- Prefetch `program_execution`

cuando se cumplen estas condiciones:

- mismo host
- mismo `process.name`
- timestamps cercanos, por defecto 10 minutos

Si encuentra coincidencia, el análisis semiautomático agrupa ambas evidencias en la misma actividad con mayor confianza.

## Parser nativo vs PECmd

- `PECmd` suele ser más cómodo cuando ya tienes la salida parseada.
- `native_prefetch` permite trabajar directamente con `.pf` desde Velociraptor, ZIP raw o árbol copiado.
- Ambos deben converger al mismo modelo de ejecución para que Search, Timeline, SIEM y SemiAuto no se dupliquen.

## Limitaciones actuales

- Prefetch puede estar deshabilitado en el sistema.
- No siempre aporta `command line`.
- No siempre permite inferir el usuario.
- No prueba por sí solo que una acción sea maliciosa.
- No indica proceso padre.
- No siempre hay ruta completa resoluble para el ejecutable.
- La correlación con EVTX 4688 es básica; no sustituye a revisión manual.

## Cómo comprobar que funciona

1. Importa un `PECmd_Output.csv`.
2. Verifica que el artefacto se detecta como:
   - `artifact.type = prefetch`
   - `artifact.parser = zimmerman`
3. Busca `powershell.exe` o `cmd.exe` en `Search`.
4. Revisa `Análisis semiautomático > Programas ejecutados`.
5. Comprueba que aparecen:
   - `run_count`
   - `last_run`
   - `Fuente = prefetch`
6. Si el binario es PowerShell, comprueba también la sección `PowerShell`.

## Falsos positivos y cautelas

- Un LOLBin no implica compromiso por sí solo.
- Un binario en `Downloads` o `AppData` merece revisión, pero no equivale automáticamente a malware.
- Un `RunCount` alto puede corresponder a uso legítimo repetido.
