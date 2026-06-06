# Large Evidence

## Modos de entrada

- `RAW evidence`
- `Parsed evidence`
- `Server-mounted path`

Empaquetado recomendado:

- `Single file`
- `Compressed archive ZIP/TAR/7z`
- `File or directory path` cuando la evidencia ya está montada en servidor

Para carpetas grandes o extracciones completas:

- evita la subida directa de carpetas desde navegador
- comprime la carpeta a `ZIP/TAR/7z`
- o usa `Server-mounted path`

La detección de tecnologías concretas es automática. No hace falta que el usuario elija si el archive viene de una herramienta concreta.

Casos habituales:

- `.evtx` suelto -> `RAW evidence` como `Windows Event Log`
- ZIP con varios `.evtx` -> `RAW evidence` como colección raw
- `CSV/JSON/JSONL` ya estructurado -> `Parsed evidence`
- carpeta grande o share NAS -> `Server-mounted path`

## Browser path vs server-mounted path

La app no puede leer rutas del equipo desde el que abres el navegador solo porque existan allí.

Ejemplos que `no` funcionan por sí solos:

- `C:\Users\analyst\Desktop\Evidence`
- `/home/user/Evidence`
- `/opt/evidence`

Esas rutas solo sirven si:

- haces `Upload file` desde el navegador
- o montas/compartes esa carpeta en el servidor bajo un root permitido

## `copy_to_storage`

- `true`: copia la evidencia al storage interno del caso.
- `false`: conserva referencia a la ruta montada en servidor y evita duplicar datos.

Para evidencia grande, `copy_to_storage=false` suele ser preferible si la ruta montada es estable y segura.

## Roots permitidos

La importación por host path solo debe usar rutas dentro de:

- `/mnt/evidence`
- `/data/evidence`
- `/cases`

o las rutas configuradas en `DFIR_ALLOWED_EVIDENCE_ROOTS`.

## Validación de server-mounted path

La app valida:

- que el root esté permitido
- que la ruta exista
- que no escape por symlink o path traversal
- que el muestreo inicial no exceda límites razonables
- si parece una ruta del cliente (`C:\...`, `/home/user/...`, `\\server\share`, etc.)

## Why my local path does not work?

Porque el backend y el worker corren en Docker o en un servidor remoto.

Soluciones:

- usa `Upload file` para subir desde el navegador
- monta la carpeta en el servidor, por ejemplo:
  - Docker/Linux: `/host/evidence:/mnt/evidence:ro`
  - Windows Docker Desktop: comparte `C:\Evidence` y móntalo como `/mnt/evidence`
  - NAS: monta el share en el servidor en `/mnt/evidence`
- registra después la ruta del servidor, no la de tu portátil/desktop

## Browser folder upload

La subida de carpetas desde navegador no es el flujo principal para forense:

- puede omitir metadatos o comportarse de forma inconsistente según navegador
- empeora con muchos miles de ficheros
- no es buena opción para colecciones grandes o evidencias adquiridas

Recomendación:

- comprime primero a `ZIP/TAR/7z`
- o usa `Server-mounted path`
- usa folder upload solo si el despliegue lo habilitó como opción experimental

## Qué se borra y qué no al borrar evidence

- Si la evidencia fue copiada a storage interno, se puede limpiar el árbol del caso.
- Si era mounted path con `copy_to_storage=false`, la app no debe borrar la ruta original externa.

## Problemas de espacio

Si el host va justo de disco:

- usa mounted evidence
- evita copias duplicadas
- reduce extracción innecesaria
- revisa `Performance & Resources`
- exporta debug pack en scope reducido, no por caso completo si no hace falta

## Recomendaciones prácticas

- usa `RAW evidence` para datos que todavía necesitan parsing
- usa `Parsed evidence` para CSV, JSONL, timeline exports u otros outputs ya estructurados
- Para colecciones grandes, prioriza `server-mounted path`.
- Mantén la evidencia en SSD/NVMe si vas a iterar mucho en Search o YARA acotado.
- No lances YARA full scan sobre shares enormes sin paths seleccionados.
- Si solo necesitas una familia, usa scopes reducidos y filtros de evidencia/host.
## Reprocessing Large Raw Evidence

For raw archives and mounted raw collections, the recommended reprocess mode is `Use previous parser selection`. This keeps the ingest reproducible and avoids parsing newly discovered files unless the analyst explicitly chooses to do so.

Use `Refresh discovery and keep previous selection` when the archive or mounted directory changed and you want to review new, missing or changed candidates before reprocessing.

Use `Full rediscovery` only when parser coverage changed or when you intentionally want a new parsing plan.
