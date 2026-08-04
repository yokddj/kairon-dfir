# WMI

## Qué soporta la app

La app soporta actualmente:

- CSV parseado de `__EventFilter`
- CSV parseado de `CommandLineEventConsumer`
- CSV parseado de `ActiveScriptEventConsumer`
- CSV parseado de `__FilterToConsumerBinding`
- JSON parseado equivalente
- CSV de Autoruns/Sysinternals cuando contiene entradas WMI
- clasificación de eventos `Microsoft-Windows-WMI-Activity/Operational` ya parseados por EVTX
- discovery raw del repositorio WMI:
  - `OBJECTS.DATA`
  - `INDEX.BTR`
  - `MAPPING*.MAP`

## Qué se parsea directamente desde Velociraptor

Se parsea directamente desde una colección Velociraptor cuando la colección ya contiene:

- CSV/JSON WMI parseado
- EVTX WMI Activity que luego entra por el parser EVTX

El repositorio raw WMI bajo `C:\Windows\System32\wbem\Repository\` se detecta y preserva, pero en esta iteración queda como `detected_not_implemented`.

## Qué son Filter, Consumer y Binding

- `__EventFilter`: define la condición WQL que dispara algo.
- `EventConsumer`: define qué hacer cuando el filtro se cumple.
- `__FilterToConsumerBinding`: une filtro y consumer.

La persistencia WMI útil suele requerir la cadena completa:

1. filter
2. consumer
3. binding

## Consumers importantes

### CommandLineEventConsumer

Es especialmente relevante porque puede ejecutar:

- `powershell`
- `cmd.exe`
- `wscript`
- `cscript`
- `mshta`
- `rundll32`
- `regsvr32`

### ActiveScriptEventConsumer

Es relevante porque puede contener `VBScript` o `JScript` embebido en `ScriptText`.

## Cómo interpretar WMI Activity vs WMI Persistence

- `WMI Activity EVTX` puede indicar consultas, errores o actividad del subsistema WMI.
- `WMI Activity EVTX` por sí solo no prueba persistencia.
- `WMI persistence candidate` requiere al menos una correlación razonable entre filter, consumer y binding.

## Campos principales

La app extrae y normaliza, cuando están disponibles:

- `wmi.namespace`
- `wmi.class_name`
- `wmi.name`
- `wmi.filter_name`
- `wmi.consumer_name`
- `wmi.query`
- `wmi.query_language`
- `wmi.command_line_template`
- `wmi.executable_path`
- `wmi.script_text`
- `wmi.script_preview`
- `wmi.binding_filter`
- `wmi.binding_consumer`
- `wmi.creator_sid`
- `wmi.creator_user`
- timestamps WMI

## Qué aumenta el riesgo

- `CommandLineEventConsumer` con `powershell -enc`
- `ActiveScriptEventConsumer` con script no vacío
- query WQL con:
  - `Win32_ProcessStartTrace`
  - `RegistryValueChangeEvent`
  - `__InstanceCreationEvent`
  - `__InstanceModificationEvent`
  - `__TimerEvent`
- `binding` completo entre filter y consumer
- URLs, downloads o rutas en `AppData`, `Temp`, `ProgramData`, `Public`
- correlación posterior con Defender, Prefetch, Amcache o MFT

## Correlaciones que hace la app

- WMI -> PowerShell
- WMI -> Defender
- WMI -> Prefetch / ejecución
- WMI -> Amcache / ShimCache
- WMI -> MFT / USN
- WMI -> Browser / BITS
- WMI -> Scheduled Tasks

## Falsos positivos comunes

- agentes de gestión
- monitorización legítima basada en WMI
- software corporativo que usa consumers benignos
- WMI Activity EVTX con errores o queries administrativas sin persistencia real

## Limitaciones actuales

- `OBJECTS.DATA` raw aún no tiene parser binario real
- `WMI Activity EVTX` no siempre prueba persistencia
- un `consumer` o `binding` por sí solo no prueba ejecución real

## Ejemplos de investigación

- buscar `artifact.type = wmi` y filtrar `wmi.consumer_name`, `wmi.query` o `wmi.command_line_template`
- revisar si existe:
  - filter
  - consumer
  - binding
- pivotar el `executable_path` o la URL hacia:
  - Defender
  - Prefetch
  - PowerShell
  - MFT
  - BITS
