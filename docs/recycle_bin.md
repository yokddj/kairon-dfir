# Recycle Bin

## Qué soporta la app

- `RBCmd_Output.csv` y variantes compatibles
- artefactos raw de Velociraptor:
  - `$Recycle.Bin\<SID>\$I*`
  - `$Recycle.Bin\<SID>\$R*`

## Qué son `$I` y `$R`

- `$I*` guarda metadata del elemento reciclado:
  - tamaño original
  - fecha/hora de borrado
  - ruta original
- en versiones modernas de Windows suele incluir:
  - `version`
  - `original file size`
  - `deletion FILETIME`
  - longitud de ruta o metadata relacionada
  - ruta original en `UTF-16LE`
- `$R*` es el contenido reciclado.
- Si `$I` y `$R` comparten sufijo, la app los empareja como un mismo candidato lógico.

## Qué aporta RBCmd

RBCmd ya entrega en CSV gran parte de la metadata útil de la papelera y es la ruta más cómoda cuando ya existe salida parseada.

## Qué se parsea directamente desde Velociraptor

La app ya parsea directamente:

- `$I` raw
- pairing `$I/$R`
- `$R` huérfano como evidencia parcial

Si la ruta original no puede resolverse por el offset principal, la app intenta un fallback buscando una cadena `UTF-16LE` que parezca una ruta Windows real dentro del blob.

## Qué campos se extraen

- `recycle.original_path`
- `recycle.original_file_name`
- `recycle.original_size`
- `recycle.deleted_time`
- `recycle.sid`
- `recycle.i_file_path`
- `recycle.r_file_path`
- `recycle.has_i_file`
- `recycle.has_r_file`
- `recycle.pair_id`
- `recycle.version`
- `recycle.drive_letter`
- `recycle.content_status`

También se rellenan:

- `file.path`
- `file.name`
- `file.extension`
- `file.size`
- `file.deleted_time`
- `user.sid`
- `user.name` cuando puede inferirse

## Cómo interpretar `deleted_time`

La hora principal del evento es la fecha/hora de reciclado observada en `$I` o en la salida de RBCmd.

Esto significa:

- evidencia de envío a la papelera
- no prueba borrado permanente
- no garantiza por sí solo cuándo se ejecutó el archivo

## Qué significa `content_missing`

- `content_missing_confirmed`: se encontró `$I`, pero en la colección no existe el `$R` correspondiente
- `present`: existe el `$R` correspondiente

La ausencia de `$R` no implica por sí sola actividad maliciosa. Puede deberse a limpieza previa o a una colección incompleta.

## Qué significa `original_path_extracted_by_utf16_fallback`

Es un warning de parseo que indica:

- el offset principal del `$I` no produjo una ruta válida
- la app encontró una ruta Windows plausible escaneando el blob `UTF-16LE`
- la ruta resultante es útil para investigación, pero conviene validarla con otros artefactos

## Qué significa `invalid_recycle_original_path`

Se marca cuando:

- el parser obtiene un valor que no parece una ruta Windows válida
- o no consigue extraer una ruta útil ni siquiera con el fallback

En ese caso la app:

- no indexa valores basura como `5`, `^` o una letra aislada como `file.path`
- conserva el resto de metadata útil (`SID`, tamaño, deleted_time, source file)
- muestra el evento como metadata observada, no como un reciclado completo con path fiable

## Cómo interpretar SID y usuario

- el SID suele venir del path `$Recycle.Bin\<SID>\...`
- si existe resolución con otros artefactos, la app puede enriquecer `user.name`
- si no, conserva `user.sid` y marca calidad de dato no resuelta

## Correlaciones que hace la app

- `Recycle Bin -> MFT/USN`
- `Recycle Bin -> Browser downloads`
- `Recycle Bin -> LNK / Jump Lists`
- `Recycle Bin -> Defender`
- `Recycle Bin -> PowerShell`
- `Recycle Bin -> Prefetch / Amcache`
- `Recycle Bin -> Scheduled Tasks`

Actividades derivadas:

- `file_recycled`
- `deleted_download`
- `deleted_detected_file`
- `deleted_executable`
- `deleted_script`
- `cleanup_candidate`

## Falsos positivos comunes

- descargas legítimas que el usuario descartó
- scripts temporales de administración o desarrollo
- software legítimo borrado manualmente
- colecciones parciales donde falta `$R`

## Limitaciones

- papelera no equivale a borrado permanente
- `$R` puede faltar por colección parcial o limpieza previa
- SID puede no resolverse a nombre
- algunos borrados nunca pasan por la papelera
- la app no calcula hashes grandes del contenido `$R` por defecto
- algunos `$I` pueden requerir fallback `UTF-16LE` si la variante concreta no coincide con el layout esperado

## Ejemplos de investigación

- descarga enviada a la papelera tras ejecución
- payload detectado por Defender y luego reciclado
- script usado desde PowerShell y luego borrado
- metadata `$I` presente sin `$R`, posible limpieza parcial de evidencias
