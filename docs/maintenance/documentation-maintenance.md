# Mantenimiento de documentación

## Objetivo

La documentación debe cambiar junto al código. Si la herramienta evoluciona y la documentación no, acaba siendo peor que no tener docs.

## Cuándo hay que actualizar docs

Cada vez que se añada o cambie:

- un parser nuevo
- una evidencia nueva
- un endpoint nuevo
- una sección frontend nueva
- una regla builtin nueva
- un `event.type` nuevo
- un campo normalizado nuevo
- una sección del análisis semiautomático

## Qué documentos revisar

- `docs/artifacts.md`
- `docs/prefetch.md` si cambia Prefetch / PECmd / native_prefetch
- `docs/lnk.md` si cambia LNK / LECmd / native_lnk
- `docs/jumplists.md` si cambia Jump Lists / JLECmd / raw automaticDestinations/customDestinations
- `docs/registry.md` si cambia Registry / RECmd
- `docs/filesystem_mft_usn.md` si cambia MFT / USN / MFTECmd
- `docs/browser.md` si cambia history / downloads / search terms
- `docs/execution_artifacts.md` si cambia Amcache / ShimCache / AppCompat
- `docs/srum.md` si cambia SrumECmd / network usage / semiauto de red
- `docs/scheduled_tasks.md` si cambia Task Scheduler XML / CSV, correlaciones o semiauto de persistencia
- `docs/defender.md` si cambia DetectionHistory, MPLog, correlaciones o el wording de remediación
- `docs/powershell_artifacts.md` si cambia PSReadLine, transcripts, scripts observados o correlaciones PowerShell
- `docs/recycle_bin.md` si cambia RBCmd, `$I/$R`, correlaciones o secciones del semi-auto relacionadas con borrado/cleanup
- `docs/shellbags.md` si cambia SBECmd, Shellbags raw detectados desde Velociraptor, correlaciones o secciones del semi-auto relacionadas con carpetas observadas
- `docs/usb.md` si cambia `setupapi.dev.log`, CSVs USB/Registry, correlaciones con volúmenes removibles o hipótesis de copia a USB
- `docs/bits.md` si cambia BITS, `qmgr` discovery, CSV/JSON/TXT parseado, notify commands o correlaciones con PowerShell/Browser/Defender
- `docs/cloud_sync.md` si cambia detección de proveedores cloud, path inference, staging/exfiltración prudente o correlaciones con Browser/BITS/PowerShell
- `docs/velociraptor_ingest.md` si cambia ZIP inventory, discovery, selective extraction o staging de colecciones
- `docs/semi_automatic_analysis.md`
- `docs/builtin_rules.md`
- `docs/wmi.md`
- `docs/rule_authoring.md`
- `docs/app_sections.md`
- `docs/architecture.md`
- `docs/opensearch.md`
- `docs/troubleshooting.md`
- `docs/roadmap.md`

## Checklist para cambios / PR

- [ ] ¿Añadí o modifiqué parser?
- [ ] ¿Actualicé `artifacts.md`?
- [ ] ¿Añadí `event.type` nuevo?
- [ ] ¿Actualicé `semi_automatic_analysis.md`?
- [ ] ¿Añadí regla builtin?
- [ ] ¿Actualicé `builtin_rules.md`?
- [ ] ¿Cambió UI?
- [ ] ¿Actualicé `app_sections.md`?
- [ ] ¿Cambió mapping OpenSearch?
- [ ] ¿Actualicé `opensearch.md` y `troubleshooting.md`?
- [ ] ¿Añadí tests?
- [ ] ¿Documenté limitaciones?

## Recomendación práctica

Cuando cambies una capacidad de análisis, haz estas tres preguntas:

1. ¿Dónde se usa en la UI?
2. ¿De qué evidencias se alimenta?
3. ¿Qué debe comprobar un analista para validar que funciona?

Si no puedes responderlas leyendo la documentación, la documentación no está completa.
# Recordatorio

- Cualquier ampliación de `Autoruns / ASEP` debe actualizar `docs/autoruns.md`, `docs/artifacts.md`, `docs/semi_automatic_analysis.md` y `docs/builtin_rules.md`.
- Cualquier ampliación de `Cloud Sync` debe actualizar `docs/cloud_sync.md`, `docs/artifacts.md`, `docs/semi_automatic_analysis.md`, `docs/troubleshooting.md` y `docs/builtin_rules.md`.
- Cualquier ampliación de `Network / WLAN / DNS` debe actualizar `docs/network.md`, `docs/artifacts.md`, `docs/semi_automatic_analysis.md`, `docs/troubleshooting.md`, `docs/velociraptor_ingest.md` y `docs/builtin_rules.md`.
# Keep `docs/raw_parsers.md` aligned with parser statuses, supported native raw types and deduplication behavior.
## Debug Export Pack

Cuando cambie el contenido del ZIP de validación, actualiza `docs/debug_export_pack.md` y cualquier referencia cruzada en troubleshooting, architecture y roadmap. Mantén alineados los nombres de fichero, opciones por defecto, redacción de secretos y limitaciones declaradas.
