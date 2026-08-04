# Jump Lists / JLECmd

## Qué son Jump Lists

Las Jump Lists son listas recientes o frecuentes asociadas a una aplicación en Windows. Suelen reflejar:

- documentos abiertos recientemente
- carpetas o rutas usadas desde una app
- scripts o binarios abiertos
- interacción del usuario con una aplicación concreta

## AutomaticDestinations vs CustomDestinations

- `AutomaticDestinations`: listas generadas automáticamente por la aplicación o por Windows.
- `CustomDestinations`: listas mantenidas por la propia aplicación.

En esta iteración Kairon DFIR:

- sigue soportando el CSV de `JLECmd`
- ya puede parsear raw `.automaticDestinations-ms` desde Velociraptor
- tiene soporte parcial para `.customDestinations-ms`

## Por qué son importantes en DFIR

Aportan contexto de **uso real por aplicación**. No prueban siempre ejecución, pero sí ayudan a responder:

- qué archivo abrió el usuario
- desde qué aplicación
- si era un documento, script o ejecutable
- si había rutas de red `UNC`
- si había indicios de USB o medios removibles

## Qué aporta JLECmd

`JLECmd_Output.csv` permite extraer:

- `AppID` y descripción de la aplicación
- `AppName` con fallback desde un mapeo básico de AppIDs conocidos
- rutas objetivo y rutas locales
- `InteractionCount`
- timestamps relevantes
- argumentos y directorio de trabajo
- volumen, serial y red
- `MachineID`
- `TargetMFTEntryNumber` / `TargetMFTSequenceNumber` cuando existen

## Qué aporta el parser raw

Para `automaticDestinations-ms` la app intenta:

- abrir el contenedor OLE/Compound File
- detectar el stream `DestList`
- enumerar streams tipo `LNK`
- extraer rutas, argumentos, directorio de trabajo, timestamps y metadatos de volumen/red

Para `customDestinations-ms` la app hace un escaneo parcial de estructuras `ShellLink/LNK`. Si no obtiene entradas útiles, conserva warnings y no rompe la ingesta.

## Qué significa AppID

`AppID` identifica la aplicación a la que pertenece la Jump List. Si `JLECmd` aporta una descripción (`AppIdDescription` o similar), la app la usa como nombre visible.

## Qué significa InteractionCount

Es una señal de interacción o recurrencia. No equivale a ejecución confirmada, pero ayuda a priorizar elementos recientes o repetidos.

## Qué timestamps son importantes

La app usa esta prioridad para `@timestamp`:

1. `TargetAccessed`
2. `LastAccessed`
3. `AccessedTime`
4. `TargetModified`
5. `LastModified`
6. `ModifiedTime`
7. `CreationTime`
8. `TrackerCreatedOn`
9. `source file mtime`

## Qué relación tienen con LNK

Tanto `LNK` como `Jump Lists` describen interacción del usuario con recursos de Windows, pero:

- `LNK` suele representar un shortcut concreto
- `Jump Lists` añaden el **contexto de aplicación** y uso reciente

## Cómo se calcula la ruta efectiva

Cuando un registro tiene varias rutas, Kairon DFIR calcula:

- `jumplist.effective_path`
- `jumplist.effective_path_source`
- `jumplist.display_name`

Prioridad actual:

1. `LocalPath`
2. `TargetPath`
3. `TargetIDAbsolutePath`
4. `CommonPath`
5. `NetworkPath`
6. `RelativePath`
7. `Path` / `FilePath` / `FullPath`

Esto evita mostrar valores parciales como `Desktop\\` cuando existe una ruta real mejor.

Si solo existe un target genérico como `Desktop\\`, `Computer` o `This PC`, la app intenta no tratarlo como ruta efectiva útil. Ese caso puede quedar marcado como `generic_target_path` o descartarse como `low_value_record`.

## Qué detecta como relevante

La app marca como interesantes:

- `\\host\share\...`
- `NetworkPath`, `NetName` o `ShareName`
- `DriveType` que parezca removible
- carpetas cloud sync (`OneDrive`, `Dropbox`, `Google Drive`, `Box`, `Mega`)
- rutas de usuario sensibles (`Downloads`, `Desktop`, `AppData`, `Temp`, `Users\\Public`, `ProgramData`)
- doble extensión
- argumentos tipo `powershell -enc`, `bypass`, `mshta`, `rundll32`, `regsvr32`

## Contexto vs sospecha

- una ruta `user_writable_path` como `Desktop`, `Documents` o `Downloads` es **contexto**, no sospecha por sí sola
- un documento normal como `.txt`, `.docx`, `.xlsx`, `.pdf`, `.csv` o `.log` en esas rutas queda como `info` con riesgo bajo
- la app solo promueve JumpLists a `suspicious` cuando además hay ejecutables/scripts, doble extensión, keywords sospechosas, argumentos sospechosos o combinaciones de alto riesgo como `AppData\\Local\\Temp` + script/ejecutable

## Cómo interpretar timestamps raw

Cuando el parser raw no puede extraer un timestamp del item y cae a `source_file_mtime`:

- la hora representa la modificación del fichero JumpList
- puede indicar que la JumpList se actualizó
- no equivale necesariamente a la hora exacta en que el usuario abrió ese item

Ese caso queda reflejado en:

- `timestamp_precision = source_file_mtime`
- `jumplist.timestamp_interpretation`

## Cómo se usa en la app

Hoy Jump Lists alimenta:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Análisis semiautomático`

## Qué muestra el análisis semiautomático

### Archivos abiertos

- timestamp
- usuario
- aplicación
- target efectivo
- interaction count

### Documentos recientes

- documentos abiertos desde una aplicación
- contexto de usuario y aplicación

### Aplicaciones usadas

- app name
- app id
- usuario
- count
- last seen

### Recent files / downloaded files opened / deleted files opened

- items recientes por aplicación
- descargas luego abiertas
- ficheros luego borrados o reciclados
- correlación con `Shellbags`, `Recycle Bin`, `Browser`, `LNK` y `MFT/USN`

## Parser status en Velociraptor

- `ready`: el archivo raw puede parsearse directamente
- `partial`: hay soporte útil pero incompleto
- `detected_not_implemented`: detectado pero sin parser raw disponible

En JumpLists:

- `automaticDestinations-ms` aparece como `ready`
- `customDestinations-ms` puede aparecer como `partial`

## Cuándo es evidencia fuerte

Una entrada JumpList gana valor cuando combina:

- `effective_path` claro
- aplicación claramente identificada (`app_name` / `app_id`)
- timestamp específico del item, mejor que `source_file_mtime`
- correlación con `LNK`, `MFT/USN`, `Recycle Bin`, `Browser` o `Shellbags`

### Scripts abiertos

Si el target es `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` o los argumentos contienen PowerShell/cmd, se resalta como `script_opened`.

### Rutas de red / USB

Si el target es UNC o `DriveType` apunta a removible, se añade contexto de red o medio extraíble.

## Cómo se correlaciona con otros artefactos

Kairon DFIR intenta una correlación básica cuando:

- el `effective_path` coincide con un `LNK`
- la carpeta padre coincide con `Shellbags`
- el mismo path aparece en `Recycle Bin`
- coincide con un `Browser download`
- el target coincide con un `4688`
- el target o su nombre coinciden con Prefetch
- el target aparece en `process.command_line`

## Limitaciones actuales

- Jump List indica uso o interacción reciente, no siempre ejecución confirmada.
- Puede contener entradas antiguas.
- No siempre hay usuario explícito; a veces se infiere desde la ruta.
- No siempre existe ruta completa.
- `automaticDestinations-ms` ya puede parsearse raw, pero `customDestinations-ms` sigue siendo parcial.
- El mapeo de `AppID -> aplicación` es útil pero incompleto por diseño.
- Si un `AppID` no se resuelve, la app conserva el `app_id` y lo marca como `unresolved_jumplist_app_id` en calidad de datos.
- Algunas entradas pueden omitirse como `low_value_record` si no aportan ruta efectiva, timestamp o metadata útil.

## Falsos positivos comunes

- documentos abiertos legítimamente
- rutas de red corporativas
- scripts o binarios usados por administradores
- entradas antiguas que ya no representan actividad actual
