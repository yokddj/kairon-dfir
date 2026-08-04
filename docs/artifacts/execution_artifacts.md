# Execution Artifacts: Amcache, ShimCache y AppCompat

## Qué es cada fuente

- `Amcache`: inventario de programas, binarios, drivers y metadatos PE observados por Windows.
- `ShimCache` / `AppCompatCache`: caché de compatibilidad que ayuda a reconstruir presencia y posible ejecución de binarios.
- `RecentFileCache`: artefacto histórico relacionado con presencia o actividad de programas/archivos recientes.

## Qué aportan en DFIR

- Visibilidad de binarios presentes aunque ya no tengamos el archivo original.
- Metadatos útiles:
  - `publisher`
  - `product_name`
  - `version`
  - `compile_time`
  - `hashes`
- Contexto para cruzar:
  - Browser downloads
  - MFT / USN
  - Prefetch
  - EVTX 4688
  - Registry
  - Defender

## Diferencia clave: presencia vs posible ejecución vs ejecución confirmada

- `Prefetch`: ejecución fuerte.
- `EVTX 4688`: ejecución fuerte.
- `UserAssist` / `BAM`: ejecución o uso con peso fuerte/medio.
- `Amcache`: programa observado o inventario; puede sugerir instalación o uso, pero no confirma ejecución por sí solo.
- `ShimCache` / `AppCompatCache`: indicio de presencia o posible ejecución; muy útil para orden temporal y pivotes, no para afirmar ejecución por sí solo.
- `RecentFileCache`: indicio de presencia/uso histórico; no debe venderse como ejecución confirmada.

La plataforma representa esto con:

- `execution.source`
- `execution.confidence`
- `execution.is_execution_confirmed`
- `execution.interpretation`

## Campos extraídos

### Execution

- `execution.source`
- `execution.confidence`
- `execution.is_execution_confirmed`
- `execution.interpretation`
- `execution.first_seen`
- `execution.last_seen`
- `execution.last_modified`
- `execution.install_date`
- `execution.compile_time`

### File / Process

- `file.path`
- `file.name`
- `file.extension`
- `file.size`
- `file.hash_sha1`
- `file.hash_sha256`
- `file.md5`
- `process.path`
- `process.name`
- `process.publisher`
- `process.product_name`
- `process.product_version`

### Amcache

- `amcache.program_id`
- `amcache.program_name`
- `amcache.program_version`
- `amcache.publisher`
- `amcache.product_name`
- `amcache.product_version`
- `amcache.file_id`
- `amcache.file_name`
- `amcache.file_path`
- `amcache.install_date`
- `amcache.compile_time`
- `amcache.key_path`

### ShimCache / AppCompat

- `shimcache.entry_number`
- `shimcache.position`
- `shimcache.path`
- `shimcache.last_modified_time`
- `shimcache.last_update`
- `shimcache.executed`
- `shimcache.control_set`
- `appcompat.artifact_type`
- `appcompat.path`
- `appcompat.name`
- `appcompat.last_modified`

## Cómo interpretar timestamps

- En `Amcache` el timestamp principal suele venir de:
  - `LastModified`
  - `KeyLastWrite`
  - `InstallDate`
  - `CompileTime`
- En `ShimCache` suele venir de:
  - `LastModifiedTime`
  - `LastUpdate`
  - `LastWriteTime`

No todos los tiempos significan “momento de ejecución”.

## Cómo interpretar hashes

- Se normalizan y validan si tienen longitud consistente.
- Son especialmente útiles para cruzar con:
  - Defender
  - IOC
  - evidencias de descarga o ficheros observados

## Correlación

La app cruza Amcache/ShimCache/AppCompat con:

- Browser downloads
- MFT / USN
- Prefetch
- EVTX 4688
- Registry Run Keys / Services / BAM / UserAssist
- Defender

Esto permite elevar confianza sin exagerar el artefacto original.

## Limitaciones

- `Amcache` no siempre prueba ejecución.
- `ShimCache` no siempre prueba ejecución.
- `RecentFileCache` es un indicio, no una confirmación.
- El orden, formato y significado de ciertos campos varían entre versiones de Windows y parsers.
- Si faltan `path` o `timestamp`, la confianza baja de forma explícita.

## Falsos positivos comunes

- Instaladores legítimos en `Downloads`.
- Software portable en `AppData`.
- LOLBins usados por administradores.
- Herramientas de soporte remoto autorizadas.
- Binarios internos sin metadatos PE completos o sin publisher.

## Ejemplos de investigación

1. Descarga en navegador de `invoice.pdf.exe` -> aparece en `Amcache` -> luego aparece en `Prefetch`.
2. `runme.ps1` observado en `AppData\\Local\\Temp` en `Amcache` y `ShimCache`, pero sin `4688`: indicio fuerte de presencia, no ejecución confirmada.
3. `AnyDesk.exe` observado en `ShimCache` y `Browser history`: revisar si la herramienta estaba autorizada y si hubo actividad remota.
