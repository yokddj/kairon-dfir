# Registry / RECmd

## Qué es el Registro de Windows

El Registro de Windows es una base de datos jerárquica donde el sistema y las aplicaciones guardan:

- configuración
- persistencia
- historial de uso
- dispositivos conectados
- artefactos de actividad del usuario

En DFIR no se usa solo para "configuración". También sirve para responder:

- qué programas se usaron
- qué persistencias había
- qué rutas escribió el usuario
- qué USB se vieron
- qué servidores RDP se usaron

## Por qué RECmd es importante

RECmd permite parsear hives y plugins de Registry a CSV. En esta app es la vía principal actual para Registry parseado:

- `*_RECmd_Output.csv`
- `RECmd_Output.csv`
- salidas CSV de RECmd Batch

## Hives que puede alimentar esta ruta

- `NTUSER.DAT`
- `UsrClass.dat`
- `SYSTEM`
- `SOFTWARE`
- `SAM`
- `SECURITY`
- `Amcache.hve` si aparece exportado en CSV compatible

## Subtipos soportados hoy

| Subtipo | Qué aporta |
| --- | --- |
| Run Keys / RunOnce | Persistencia por logon |
| Services | Persistencia y configuración de servicios |
| UserAssist | Evidencia fuerte de uso/ejecución por usuario |
| BAM / DAM | Ejecución observada por el sistema |
| MUICache | Presencia o indicio de uso, no ejecución confirmada |
| USBSTOR / USB | Dispositivos externos observados |
| MountedDevices | Letras/unidades y mappings de volumen |
| TypedPaths | Rutas tecleadas en Explorer |
| RunMRU | Comandos usados en el cuadro Ejecutar |
| RecentDocs | Documentos recientes |
| RDP MRU | Historial de destinos RDP |
| Shellbags | Carpetas navegadas por el usuario |
| Registry generic | Filas no clasificadas aún en un subtipo |

## Campos principales que extrae la app

- `registry.hive`
- `registry.hive_path`
- `registry.key_path`
- `registry.key_name`
- `registry.value_name`
- `registry.value_type`
- `registry.value_data`
- `registry.last_write_time`
- `registry.artifact_type`
- `registry.plugin`
- `registry.batch`

Según el subtipo también puede rellenar:

- `process.path`
- `process.command_line`
- `service.image_path`
- `service.service_dll`
- `usb.vendor`
- `usb.product`
- `usb.serial`
- `volume.drive_letter`
- `destination.hostname`
- `shellbag.path`

## Campos clave que debe revisar el analista

Cuando revises eventos Registry en `Artifact Explorer` o `Search`, los campos más útiles suelen ser:

- `registry.artifact_type`
- `registry.hive`
- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `registry.last_write_time`
- `process.path`
- `process.command_line`
- `service.name`
- `service.image_path`
- `service.service_dll`
- `user.sid`
- `usb.vendor`
- `usb.product`
- `usb.serial`
- `destination.hostname`

En la práctica:

- para `Run Keys`, mira sobre todo `key_path`, `value_name`, `value_data` y `process.command_line`
- para `Services`, mira `service.name`, `service.image_path`, `service.service_dll` y `start_type`
- para `BAM/DAM` y `UserAssist`, mira `process.path`, `process.name`, `user.sid` y `execution.last_run`
- para `USBSTOR`, mira `usb.vendor`, `usb.product`, `usb.serial`
- para `RDP MRU`, mira `destination.hostname`

## Cómo interpreta la app los subtipos principales

### Run Keys

- `event.type = registry_run_key`
- categoría: `persistence`
- mapea `ValueData` a `process.command_line`
- intenta extraer ejecutable a `process.path`

Ejemplo de mensaje:

```text
Run key persistence: Updater -> powershell.exe -enc aQ==
```

### Services

- `event.type = registry_service`
- categoría: `persistence`
- extrae `service.name` desde la ruta de clave
- interpreta `ImagePath`, `DisplayName`, `Start`, `Type`, `ObjectName`, `ServiceDll`

### UserAssist

- `event.type = userassist_execution`
- categoría: `execution`
- decodifica ROT13 si el valor viene codificado
- rellena `execution.run_count`, `execution.focus_time` y `execution.last_run` si están disponibles

### BAM / DAM

- `event.type = bam_execution` o `dam_execution`
- categoría: `execution`
- usa la ruta del ejecutable como `process.path`
- si hay datos suficientes, el resumen debe mostrar el ejecutable concreto y no `unknown`

### MUICache

- `event.type = muicache_entry`
- categoría: `execution`
- **no** debe interpretarse como ejecución confirmada por sí sola
- se trata como indicio o pista de presencia/uso

### USBSTOR / USB

- `event.type = usb_device_seen`
- categoría: `device`
- intenta extraer vendor, product y serial desde `KeyPath`

### MountedDevices

- `event.type = mounted_device`
- categoría: `device`
- intenta extraer `volume.drive_letter` y `volume.guid`

### TypedPaths

- `event.type = typed_path`
- categoría: `file_access`
- usa `ValueData` como `file.path`

### RunMRU

- `event.type = run_mru_command`
- categoría: `execution`
- usa `ValueData` como `process.command_line`

### RecentDocs

- `event.type = recent_document`
- categoría: `file_access`
- intenta rellenar `file.path` o `file.name`

### RDP MRU

- `event.type = rdp_mru`
- categoría: `remote_access`
- rellena `destination.hostname`

### Shellbags

- `event.type = shellbag_folder_access`
- categoría: `file_access`
- rellena `shellbag.path`

## Cómo interpretar LastWriteTime

`LastWriteTime` es el timestamp de la **clave** de registro, no siempre del valor concreto.

Eso significa que:

- es muy útil para ordenar actividad
- pero no siempre equivale al momento exacto en que el usuario ejecutó algo

## Qué significa cada artefacto en términos de confianza

- **Alta utilidad para ejecución**: `UserAssist`, `BAM`, `DAM`
- **Muy útil para persistencia**: `Run Keys`, `Services`
- **Muy útil para historial de usuario**: `RunMRU`, `TypedPaths`, `RecentDocs`, `Shellbags`
- **Útil como indicio, no ejecución confirmada**: `MUICache`
- **Útil para contexto de dispositivos**: `USBSTOR`, `MountedDevices`

## Correlación con otras evidencias

La app intenta correlacionar Registry con:

- EVTX `4688`, `7045`, `4697`, RDP
- Prefetch / `PECmd_Output.csv`
- LNK / `LECmd_Output.csv`
- Jump Lists / `JLECmd_Output.csv`

Ejemplos:

- Run key + `4688` o Prefetch del mismo binario
- Service registry + `7045` / `4697`
- UserAssist + Prefetch
- RecentDocs / TypedPaths / Shellbags + LNK / Jump Lists
- RDP MRU + eventos RDP del EVTX

## Uso en Análisis semiautomático

Registry ya alimenta:

- `Persistencia`
- `Programas ejecutados`
- `Actividad de usuario`
- `Dispositivos USB`
- `RDP`
- `Archivos abiertos`
- `Hallazgos sospechosos`
- `Timeline`

## Limitaciones actuales

- `LastWriteTime` es de clave, no siempre del valor.
- `MUICache` no demuestra ejecución confirmada.
- `USBSTOR` no implica copia de archivos por sí solo.
- Los servicios desde registro se indexan por fila; aún no se hace agrupación "perfecta" de todas las values en una sola entidad.
- Algunos outputs de RECmd Batch cambian columnas según plugin y pueden requerir ampliar el parser en futuros sprints.

## Persistencia sospechosa: ejemplos prácticos

### Run key con PowerShell encoded

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Updater = powershell.exe -enc ...
```

Qué mirar:

- ruta real del script o binario
- usuario afectado
- correlación con `4688`, `4104` y Prefetch

### Servicio en ruta de usuario

```text
HKLM\SYSTEM\CurrentControlSet\Services\BadSvc\ImagePath
C:\Users\Public\svc.exe
```

Qué mirar:

- `ImagePath`
- `ServiceDll`
- `Start`
- `ObjectName`
- correlación con `7045`, `4697`, Prefetch y detections

## Falsos positivos comunes

- scripts internos de logon en Run keys
- software legítimo con servicios en rutas raras
- comandos RunMRU ejecutados por administradores
- MUICache con binarios ya borrados
- dispositivos USB corporativos o discos externos autorizados
