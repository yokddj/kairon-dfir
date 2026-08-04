# Cloud Sync

## Qué es

`Cloud Sync` agrupa evidencias de clientes de sincronización cloud y carpetas sincronizadas locales. En Kairon DFIR no se interpreta por defecto como exfiltración confirmada.

Proveedores cubiertos:

- OneDrive
- Google Drive / Drive for Desktop / DriveFS
- Dropbox
- MEGAsync
- iCloud Drive
- Box Drive / Box Sync
- carpetas cloud genéricas detectadas por ruta

## Qué soporta la app

La app soporta:

- discovery de sync roots y rutas de configuración/log
- parse CSV/JSON cloud genérico
- parse básico de logs de texto simples
- inferencia por ruta sobre eventos ya normalizados
- correlación con Browser, BITS, PowerShell, MFT/USN, LNK, JumpLists, Recycle Bin, Defender, Autoruns, Scheduled Tasks, WMI y USB

## Qué se parsea directamente desde Velociraptor

Si la colección ya contiene salidas parseadas pequeñas o logs/configs legibles, la app puede procesar:

- `*OneDrive*.csv`
- `*GoogleDrive*.csv`
- `*DriveFS*.csv`
- `*Dropbox*.csv`
- `*MEGAsync*.csv`
- `*iCloud*.csv`
- `*BoxDrive*.csv`
- `*CloudSync*.json`
- logs/configs pequeños reconocibles del cliente

También detecta sync roots observados por ruta sin extraer por defecto todo su contenido.

## Qué queda como discovery

Se detectan como discovery o `path_inference`:

- carpetas completas OneDrive/Dropbox/Google Drive/MEGA/iCloud/Box
- rutas grandes de `DriveFS`
- configs o bases propietarias no parseadas

La app no extrae masivamente carpetas cloud completas por defecto.

## Campos extraídos

- proveedor
- cuenta / email si aparece
- sync root
- ruta local
- ruta remota / cloud path
- estado / sync status
- timestamps de sync, upload, download y file activity
- URL/domain si existe
- direction / detection_method / confidence

## Tipos de artefacto cloud

La app diferencia entre:

- `cloud_client_config`: configuración del cliente cloud, por ejemplo `OneDrive\\settings\\ECSConfig.json`
- `cloud_client_log`: logs del cliente cloud, por ejemplo `OneDrive\\logs\\...`
- `cloud_sync_root`: raíz sincronizada real, por ejemplo `C:\\Users\\user\\OneDrive` o `C:\\Users\\user\\Dropbox`
- `cloud_file_activity`: archivo observado dentro de una carpeta cloud
- `cloud_staging_candidate`: evidencia prudente de staging hacia cloud
- `possible_cloud_exfiltration`: candidato de exfiltración cloud, no subida confirmada

Un `cloud_client_config` o `cloud_client_log` no se interpreta como sync root ni como subida.

## Sync roots y actividad cloud

La app diferencia entre:

- `cloud folder observed`
- `cloud client config`
- `cloud client log`
- `cloud file activity`
- `cloud staging candidate`
- `possible cloud exfiltration candidate`

Un archivo dentro de OneDrive o Dropbox no prueba subida. Para subir confianza se buscan:

- archivos sensibles dentro del sync root
- comprimidos creados dentro del sync root
- actividad de copia o compresión hacia cloud
- descargas Browser/BITS directas a cloud
- muchos ficheros creados o modificados en ventana corta
- detecciones Defender o borrado posterior en Recycle Bin

## Correlaciones

Se correlaciona con:

- Browser history y downloads
- BITS `local_path`
- PowerShell `Copy-Item`, `Move-Item`, `Compress-Archive`, `robocopy`, etc.
- MFT/USN en rutas cloud
- LNK y JumpLists con targets en carpetas cloud
- Recycle Bin con `original_path` en cloud
- Defender detections en rutas cloud
- Prefetch / Amcache / ShimCache si se ejecuta contenido desde cloud
- Autoruns / Scheduled Tasks / WMI si la persistencia apunta a cloud
- USB cuando hay nombres/rutas coincidentes y cercanía temporal

## Falsos positivos comunes

- trabajo colaborativo normal en OneDrive o Google Drive
- backups o zips legítimos en carpetas sincronizadas
- scripts o herramientas internas compartidas entre usuarios
- sincronización masiva legítima tras migraciones

## Limitaciones

- un archivo dentro de una carpeta cloud no prueba subida real
- muchos clientes no dejan logs locales útiles
- `DriveFS` puede usar rutas virtuales
- `sync status` o `last_upload_time` puede faltar
- no se parsean bases propietarias complejas en este sprint

## Ejemplos de investigación

Investiga primero como `possible cloud staging` cuando veas:

- `credentials.kdbx`, `backup.zip` o `export.db` dentro de OneDrive/Dropbox
- `Copy-Item` o `robocopy` hacia el sync root
- Browser/BITS descargando directamente a cloud
- Defender detectando un payload dentro del sync root

Solo sube a hipótesis de exfiltración cuando además exista una cadena razonable de staging, compresión o sync explícito.
