# Shellbags

## Qué soporta la app

- `SBECmd_Output.csv`
- `*_SBECmd_Output.csv`
- variantes `*Shellbags*.csv`
- discovery raw desde Velociraptor de `NTUSER.DAT` y `UsrClass.dat`

## Qué aportan

Shellbags ayudan a responder qué carpetas fueron vistas o navegadas por el usuario desde Explorer o componentes del shell. No prueban ejecución.

## Qué se parsea directamente

- CSV parseados por `SBECmd`

## Qué queda como discovery raw

- `NTUSER.DAT`
- `UsrClass.dat`
- logs asociados

Cuando solo aparecen hives raw, la UI los muestra como `detected_not_implemented` y recomienda usar `SBECmd` parseado.

## Campos extraídos

- ruta de carpeta
- bag path
- hive/source file
- shell type
- MRU / slot / node slot
- timestamps disponibles
- user / SID si existe
- flags de red, USB, cloud, control panel y deleted/missing candidate

## Interpretación forense

- Shellbags indican navegación o interacción con carpetas.
- No implican ejecución.
- Son muy útiles para rutas USB, UNC, carpetas borradas o ya no existentes y carpetas vistas por el usuario.

## Correlaciones principales

- LNK
- JumpLists
- MFT/USN
- Recycle Bin
- Browser downloads
- PowerShell
- Defender
- USBSTOR / MountedDevices

## Limitaciones

- Shellbags no prueban ejecución.
- El parser raw de hives no está implementado en esta iteración.
- Rutas virtuales o de Control Panel pueden generar ruido.
- Los timestamps pueden variar según la fuente y la versión de Windows.
