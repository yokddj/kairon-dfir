# OpenSearch en Kairon DFIR

## Para qué se usa

OpenSearch es el motor de:

- indexación de eventos normalizados
- búsqueda global
- timeline
- SIEM Lite
- base del análisis semiautomático

## Índices por caso

La plataforma crea índices de eventos por caso. Eso permite:

- separar investigaciones
- borrar un caso limpiando su índice
- aplicar mappings controlados

## Por qué `dynamic: false`

Los eventos EVTX pueden traer payloads muy variables. Si OpenSearch expandiera automáticamente todos esos campos, se dispararía el número total de fields.

Por eso los índices nuevos usan:

```json
{
  "dynamic": false
}
```

## Por qué `raw`, `windows.event_data` y `windows.payload` tienen `enabled: false`

Esos contenedores se conservan para:

- trazabilidad
- detalle del evento
- validación manual

pero **no** deben abrir miles de campos en el mapping.

## Qué campos sí son buscables

Ejemplos típicos:

- `event.type`
- `event.category`
- `event.message`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `user.name`
- `source.ip`
- `process.path`
- `process.command_line`
- `execution.source`
- `execution.run_count`
- `execution.last_run`
- `prefetch.executable_name`
- `prefetch.referenced_files`
- `registry.artifact_type`
- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `usb.serial`
- `volume.drive_letter`
- `shellbag.path`
- `service.image_path`
- `task.command`
- `tags`
- `suspicious_reasons`
- `search_text`

## Qué campos solo se ven en detalle

- `raw`
- `windows.event_data`
- `windows.payload`
- partes no mapeadas del XML/payload

## Cómo comprobar el mapping

Ejemplo orientativo:

```bash
curl http://localhost:9200/<indice-del-caso>/_mapping?pretty
```

## Si cambia el mapping

Si modificas los campos normalizados o el mapping base:

1. recrea el caso o su índice
2. reimporta la evidencia

Si no lo haces, puedes mezclar un parser nuevo con un índice viejo.

## Error: total fields limit

Suele significar:

- índice antiguo
- `dynamic` mal configurado
- `raw` / `event_data` / `payload` expandiéndose

## Bulk indexing errors

La ingesta ya intenta detectar errores de bulk y no fallar silenciosamente.

Qué revisar:

- `Activity`
- logs del backend/worker
- manifest o auditoría de ingesta

## Preflight de ingest

Antes de arrancar una ingesta, reprocess o benchmark, la plataforma debe validar que OpenSearch:

- es alcanzable
- no está en `red`
- no tiene `cluster.blocks.create_index=true`
- no tiene `cluster.blocks.write=true`
- no tiene índices relevantes en `read_only_allow_delete`
- puede crear el índice del caso si aún no existe

Si falla esa preflight:

- no empieza el parsing
- el run se clasifica como `infrastructure_blocked_opensearch`
- la UI debe mostrar que OpenSearch no está writable

Esto evita confundir un problema de infraestructura con un problema de parser o throughput.

## Comandos útiles

```bash
curl http://localhost:9200/_cat/indices?v
curl http://localhost:9200/<indice-del-caso>/_count?pretty
curl http://localhost:9200/<indice-del-caso>/_mapping?pretty
```

Advertencia:

> Host, puerto y credenciales pueden variar según tu despliegue.
