# Autoruns / ASEP

## Qué es

Autoruns / ASEP resume mecanismos de autoarranque y persistencia de Windows:

- Run / RunOnce
- Startup folder
- Services / Drivers
- Scheduled Tasks
- WMI persistence
- Winlogon
- IFEO Debugger
- AppInit / AppCert DLLs
- LSA Providers
- Print Monitors
- Shell Extensions
- Office add-ins

La plataforma trata estas entradas como persistencia observada o candidata, no como ejecución confirmada por sí sola.

## Qué soporta la app

- Autoruns CSV
- Autoruns TSV
- Autoruns XML
- Autorunsc output
- startup folder files detectados desde colecciones raw
- correlación con Registry, Scheduled Tasks, WMI, PowerShell, Defender, Prefetch, Amcache, MFT, Browser y BITS

## Qué se parsea directamente desde Velociraptor

Si una colección raw incluye salidas parseadas de Autoruns, la app las ingiere directamente.

Además detecta:

- Startup folder files
- `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, `UsrClass.dat` como candidatos ASEP
- Task XML
- repositorio WMI raw como candidato relacionado

## Qué queda solo como discovery

Si solo hay hives raw o repositorio WMI raw:

- se preservan como candidatos
- no se marcan como parseados falsamente
- el parser recomendado sigue siendo RECmd / Scheduled Tasks / WMI según el caso

## Campos extraídos

- categoría, entry location, entry, enabled
- profile / user / SID
- image path, launch string, command line, arguments
- publisher, signer, signed, verified
- hashes MD5 / SHA1 / SHA256 / PE hashes
- VT detection / link si existe
- mecanismo de persistencia normalizado

## Cómo interpretar signed / verified / publisher

- `signed` o `verified` ayuda a priorizar, pero no garantiza benignidad
- ausencia de firma tampoco prueba malicia
- Microsoft-signed en rutas estándar suele bajar prioridad
- unsigned o unknown en AppData / Temp / ProgramData suele subirla

## Cómo interpretar VT detection

- `vt_detection > 0` es una señal adicional
- no debe usarse aislada
- tiene más valor cuando coincide con path sospechoso, LOLBins, descarga previa o ejecución posterior

## Correlaciones

La capa semiautomática enlaza Autoruns con:

- PowerShell que crea Run keys, tareas, servicios o WMI
- Browser / BITS que descargan el target antes de persistirse
- MFT / USN que crean o modifican el target cerca del timestamp
- Prefetch que ejecuta el target después
- Defender que detecta el target
- WMI / Scheduled Tasks / Registry cuando reflejan el mismo mecanismo

## Falsos positivos comunes

- actualizadores legítimos en `Run`
- software corporativo con services o tasks propias
- shell extensions, Office add-ins y BHOs de software conocido
- binarios no firmados internos o legacy

## Limitaciones

- Autoruns refleja estado observado, no siempre fecha real de creación
- una entrada deshabilitada puede seguir siendo relevante
- firma válida no garantiza benignidad
- ausencia de firma no garantiza malicia
- hives raw y parte del ASEP agregado siguen dependiendo de parsers especializados ya existentes

## Ejemplos de investigación

1. `Run key -> AppData -> unsigned -> Browser/BITS download -> Prefetch`
2. `IFEO Debugger -> cmd /c payload`
3. `Winlogon Shell -> binario fuera de rutas estándar`
4. `Startup folder -> script o LOLBin`
