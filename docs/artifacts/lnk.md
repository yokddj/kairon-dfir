# LNK / LECmd / native_lnk

## Qué son los archivos LNK

Los archivos `.lnk` son shortcuts de Windows. Suelen representar que un usuario abrió o tuvo interacción con:

- un documento
- un script
- un ejecutable
- una carpeta
- una ruta de red
- una unidad extraíble

## Por qué son importantes en DFIR

Un `.lnk` no siempre significa ejecución, pero sí puede dar pistas muy útiles sobre:

- archivos abiertos por el usuario
- scripts lanzados desde `Downloads`, `Desktop` o `AppData`
- accesos a recursos de red `UNC`
- posibles accesos a USB o volúmenes removibles
- correlación con EVTX `4688` y Prefetch

## Qué aporta LECmd y qué aporta el parser nativo

`LECmd_Output.csv` permite extraer:

- el fichero `.lnk` de origen
- la ruta objetivo
- argumentos
- directorio de trabajo
- timestamps del target
- información de volumen
- datos de red
- `MachineID`

El parser nativo `lnk_raw` ahora puede ingerir directamente shortcuts raw desde colecciones Velociraptor o ZIPs de triage en rutas como:

- `Recent`
- `Office\\Recent`
- `Desktop`
- `Downloads`
- `Start Menu`
- `Startup`

## Diferencia entre source file y target path

- `source file`: el `.lnk` en sí, por ejemplo `C:\Users\analyst\Desktop\runme.lnk`
- `target path`: el recurso al que apunta, por ejemplo `C:\Users\analyst\Downloads\runme.ps1`

Esto es importante porque el `.lnk` puede seguir existiendo aunque el target ya haya desaparecido.

## Ruta efectiva del target LNK

`LECmd` puede devolver varias rutas o pseudo-rutas para el mismo acceso:

- `TargetPath`
- `TargetIDAbsolutePath`
- `LocalPath`
- `CommonPath`
- `NetworkPath`
- `RelativePath`
- `WorkingDirectory`

No todas son igual de útiles para el analista. Valores como `Desktop\\` o `Internet Explorer (Homepage)` son **shell targets** o rutas parciales.

Por eso la app calcula:

- `lnk.effective_path`
- `lnk.effective_path_source`
- `lnk.display_name`

### Prioridad usada por la app
1. `LocalPath + CommonPath`
2. `LocalPath`
3. `TargetPath`
4. `TargetIDAbsolutePath`
5. `NetworkPath`
6. `RelativePath`
7. `Description / NameString` si parece ruta
8. `SourceFile` como último fallback

### Ejemplo real

Si `LECmd` devuelve:

- `TargetIDAbsolutePath = Desktop\\`
- `LocalPath = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`

el evento normalizado mostrará:

- `lnk.effective_path = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`
- `lnk.effective_path_source = local_path`
- `file.path = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`

Así `Search`, `Artifact Explorer` y `Análisis semiautomático` dejan de enseñar resúmenes inútiles como `Desktop\\`.

## Qué significan TargetCreated / Modified / Accessed

Son timestamps del **target registrados dentro del LNK**, no necesariamente el momento exacto en que el usuario hizo clic.

Kairon DFIR usa como prioridad:

1. `TargetAccessed`
2. `SourceModified`
3. `SourceCreated`
4. `TargetModified`
5. `candidate/source file mtime`

## Qué significa MachineID

`MachineID` suele apuntar al equipo donde el shortcut fue creado o resuelto. Puede ayudar a:

- identificar el host
- correlacionar actividad entre accesos
- detectar si el acceso parece venir del propio equipo o de otro contexto

## Qué indican DriveType y VolumeSerial

Pueden sugerir:

- volumen fijo
- unidad removible
- posible USB

No prueban por sí solos que el acceso fuera malicioso, pero son muy útiles para contexto.

## Cómo detectar rutas USB o UNC

Kairon DFIR marca como interesantes:

- `\\host\share\...`
- rutas con `NetworkPath`, `NetName` o `ShareName`
- `DriveType` que parezca removible

## Cómo se usa en la app

Hoy LNK alimenta:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Análisis semiautomático`
- `Debug Export Pack`

## Qué muestra el análisis semiautomático

### Archivos abiertos

- timestamp
- usuario
- target efectivo
- extensión
- source LNK
- drive type
- network path
- confidence
- suspicious reasons

### Scripts abiertos

Si el target es `.ps1`, `.bat`, `.cmd`, `.js`, etc., el acceso se resalta como `script_opened`.

### Startup persistence

Si el `.lnk` está en una carpeta `Startup`, el evento se normaliza como `startup_lnk` y rellena el namespace `persistence.*`.
Esto sigue sin probar ejecución por sí solo; se trata como `possible startup persistence via LNK`.

### Rutas de red

Si el target es UNC o usa `NetworkPath`, aparece también como `network_path_opened`.

### USB / removable media

Si `DriveType` indica removable o USB candidate, aparece en `removable_media`.

## Cómo se correlaciona con EVTX y Prefetch

Kairon DFIR intenta una correlación básica cuando:

- el target del LNK coincide con el ejecutable visto en Prefetch
- el target aparece en `4688` o en `process.command_line`
- el target aparece en `PowerShell` script blocks o comandos
- los timestamps están cerca, por defecto 30 minutos

Esto no sustituye a revisión manual, pero sube mucho el valor forense del shortcut.

## Limitaciones actuales

- Un LNK indica acceso o interacción, no siempre ejecución confirmada.
- Los timestamps del target vienen del LNK, no siempre del momento exacto de apertura.
- Puede existir el `.lnk` aunque el target ya no exista.
- No todos los campos aparecen siempre en todas las versiones de `LECmd`.
- Los targets parciales o shell namespace (`Desktop\\`, `Control Panel`, etc.) se preservan con `partial_lnk_target` o `unresolved_lnk_target`.
- Si cambió el mapping y se añadieron campos `lnk.effective_*`, los índices antiguos no mostrarán esos campos hasta reimportar el caso o recrear el índice.

## Falsos positivos comunes

- documentos abiertos legítimamente
- accesos normales a shares corporativos
- scripts o binarios usados por administradores
- LNKs antiguos que ya no representan actividad actual
