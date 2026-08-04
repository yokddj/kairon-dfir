# USB Enriquecido

## Qué evidencias USB soporta la app

La app soporta ahora:

- `setupapi.dev.log` raw
- CSVs de `USBSTOR`, `USB`, `MountedDevices`, `PortableDevices` y similares
- correlación con `LNK`, `JumpLists`, `Shellbags`, `MFT/USN`, `Recycle Bin`, `Browser` y `PowerShell`

## Qué aporta `SetupAPI.dev.log`

`SetupAPI.dev.log` permite extraer bloques de instalación/configuración de dispositivos y, cuando el contenido lo permite:

- `Device Instance ID`
- `Vendor`
- `Product`
- `Revision`
- `Serial`
- `Service`
- `INF`
- versión/proveedor de driver
- timestamps de sección

Importante:

- no todo bloque con la palabra `USB` representa un dispositivo externo concreto
- `Install Driver Updates` suele reflejar actividad genérica de actualización/publicación de drivers
- `USB\\Class_07`, `USB\\Class_08`, `USB\\ROOT_HUB` y similares son clases o controladores genéricos

## Qué aporta Registry USBSTOR / MountedDevices

Los artefactos de registro parseados pueden enriquecer:

- seriales
- `FriendlyName`
- `ContainerId`
- `ParentIdPrefix`
- `Volume GUID`
- `Drive letter`
- `MountedDevice` / `DosDevices`

## Qué se parsea directamente desde Velociraptor

Soportado directamente:

- `C:\\Windows\\INF\\setupapi.dev.log`

Discovery-only en esta iteración si llegan raw:

- `SYSTEM`
- `SOFTWARE`
- `NTUSER.DAT`

## Qué considera la app un USB “útil”

La app prioriza identificadores útiles como:

- `USBSTOR\\Disk&Ven_...&Prod_...&Rev_...\\SERIAL`
- `USB\\VID_XXXX&PID_YYYY\\SERIAL`
- `SWD\\WPDBUSENUM\\...`
- `WPD\\...`
- `STORAGE\\Volume\\...`

Los bloques genéricos de driver update o clases USB sin serial útil se omiten del flujo principal o se tratan como diagnóstico de bajo valor.

## Cómo interpretar `Device Instance ID`

Ejemplos habituales:

- `USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0`
- `USB\\VID_0781&PID_5581\\1234567890ABCDEF`

La app intenta extraer:

- `vendor`
- `product`
- `revision`
- `serial`
- `vid`
- `pid`
- `device_type`

Siempre conserva también `usb.raw_instance_id`.

## Volume y drive letter

La letra de unidad no es identidad fuerte por sí sola.

La correlación prioriza:

- `serial`
- `device_instance_id`
- `volume.serial`
- `volume.guid`
- `container_id`
- `parent_id_prefix`

## USB observado, acceso y posible exfiltración

La app usa wording prudente:

- `usb_device_install` / `usb_device_observed`: dispositivo observado
- `usb_volume_mapping`: mapeo de volumen o letra observado
- `usb_file_access` / `usb_folder_access`: actividad en ruta removible
- `possible_usb_exfiltration_candidate`: hipótesis de copia o salida de datos

USB conectado no implica exfiltración.

## Correlación con otros artefactos

- `LNK`: rutas removibles, `volume.serial`, `drive_type`
- `JumpLists`: archivos recientes en rutas removibles
- `Shellbags`: carpetas vistas en unidad externa
- `MFT/USN`: creaciones/modificaciones/borrados en rutas removibles
- `Recycle Bin`: ficheros borrados/reciclados desde unidad externa
- `Browser`: descargas directas a `E:\\`, `F:\\`, etc.
- `PowerShell`: `Copy-Item`, `robocopy`, `xcopy`, `move`, compresión hacia unidad removible

## Falsos positivos comunes

- pendrives corporativos legítimos
- discos externos de backup
- descargas manuales guardadas en USB
- tooling portable de administración

## Limitaciones

- `SetupAPI.dev.log` suele indicar instalación/configuración, no cada conexión exacta
- la letra de unidad puede cambiar
- el serial puede faltar o ser poco distintivo
- acceso a un archivo en USB no equivale a copia
- `possible_usb_exfiltration_candidate` es una hipótesis, no una conclusión automática
- algunos bloques de `SetupAPI` se omiten deliberadamente por bajo valor para evitar falsos positivos operativos
