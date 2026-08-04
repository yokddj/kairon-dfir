# Browser

## Qué soporta la app

La plataforma soporta dos rutas para evidencias de navegador:

1. CSV/JSON ya parseado por BrowserHistoryView, KAPE, NirSoft u otras herramientas compatibles.
2. Parseo directo desde colecciones Velociraptor para:
   - Chromium `History`
   - Firefox `places.sqlite`

## Artefactos priorizados

- Historial
- Descargas
- Términos de búsqueda

No se procesan en esta fase:

- Cookies
- Passwords
- Autofill
- Otros datos sensibles del navegador

## Navegadores soportados o inferidos

- Chrome
- Edge
- Brave
- Chromium
- Opera
- Firefox
- IE/Edge Legacy solo si ya viene parseado en CSV/JSON

## Campos extraídos

- `browser.name`
- `browser.profile`
- `browser.url`
- `browser.domain`
- `browser.title`
- `browser.search_terms`
- `download.target_path`
- `download.file_name`
- `download.total_bytes`
- `url.full`
- `file.path`

## Parseo directo desde Velociraptor

Para Chromium se usa extracción selectiva y copia segura de `History` y, si existen, también `History-wal` y `History-shm`. La app no necesita extraer toda la colección Velociraptor para llegar a esos SQLite.

Tablas principales:

- `urls`
- `visits`
- `downloads`
- `downloads_url_chains`
- `keyword_search_terms`

Para Firefox se usa extracción selectiva y copia segura de `places.sqlite` y, si existen, `places.sqlite-wal` y `places.sqlite-shm`.

Tablas principales:

- `moz_places`
- `moz_historyvisits`

Las descargas de Firefox pueden variar según versión y no siempre se extraen con la misma claridad que en Chromium.

Artefactos de navegador que no se extraen por defecto en este flujo:

- `Cache`
- `Code Cache`
- `GPUCache`
- `Service Worker`
- `IndexedDB`
- `Local Storage`
- `Cookies`
- `Login Data`
- `Web Data`

## Correlación

La app correlaciona descargas de navegador con:

- MFT/USN para creación de archivos
- LNK y Jump Lists para apertura
- Prefetch y EVTX para ejecución
- Defender para detecciones posteriores

## Limitaciones

- En esta fase se priorizan outputs parseados y SQLite raw de historial/places.
- Hindsight, XLSX o JSON de terceros pueden seguir siendo útiles, pero no siempre son la mejor fuente para automatizar la plataforma.
- Historial no implica descarga.
- Descarga no implica ejecución.
- Firefox downloads pueden no aparecer según versión/perfil/base.

## Falsos positivos comunes

- Descargas legítimas de herramientas administrativas
- Visitas a servicios cloud sin actividad maliciosa
- Búsquedas técnicas o de troubleshooting
