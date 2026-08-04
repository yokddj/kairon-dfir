# Performance

## Perfiles

La UI expone perfiles:

- `safe`
- `balanced`
- `max`
- `custom`

## Qué ajusta cada perfil

### `safe`

- batches y bulks más pequeños
- menos paralelismo
- process graph y correlation con límites conservadores
- adecuado para hosts con poca RAM o disco justo

### `balanced`

- defaults del despliegue
- perfil recomendado para la mayoría de instalaciones locales

### `max`

- batches y bulk mayores
- más paralelismo
- `PROCESS_GRAPH_MAX_NODES` y `CORRELATION_MAX_EVENTS` más altos
- `OPENSEARCH_JAVA_HEAP` recomendado de `4g`

### `custom`

- overrides manuales desde UI/API
- útil cuando quieres tocar solo uno o dos límites sin moverte a `max`

## Parámetros relevantes

- `INGEST_BATCH_SIZE`
- `OPENSEARCH_BULK_DOCS`
- `OPENSEARCH_BULK_BYTES`
- `MAX_PARALLEL_ARTIFACTS`
- `MAX_PARALLEL_RULE_RUNS`
- `MOUNTED_PATH_SCAN_LIMIT`
- `PROCESS_GRAPH_MAX_NODES`
- `CORRELATION_MAX_EVENTS`
- `DEBUG_EXPORT_MAX_EVENTS`
- `OPENSEARCH_JAVA_HEAP`
- `BACKEND_UVICORN_WORKERS`
- `WORKER_SCALE`

## Qué requiere restart

### Inmediato

- la mayoría de runtime settings como batches, search page size, graph limits y rule parallelism

### Requiere restart

- `OPENSEARCH_JAVA_HEAP` -> recrear `opensearch`
- `BACKEND_UVICORN_WORKERS` -> recrear `backend`
- `WORKER_SCALE` -> escalar `worker`
- límites Docker globales -> recrear servicios afectados

## Warnings del panel

El panel puede avisar de:

- `low_disk_space`
- `low_available_memory`
- `max_profile_low_memory_risk`
- `opensearch_unavailable`

## Cómo interpretar Performance & Resources

- revisa CPU, memoria disponible, disco libre y tamaño de storage usado
- revisa colas de `dfir-ingest` y `dfir-rules`
- revisa si hay pending settings que aún no se han aplicado por restart pendiente

## Recomendaciones

- más RAM y heap de OpenSearch ayudan mucho más que GPU
- SSD/NVMe mejora ingestas, mounted evidence y YARA controlado
- mounted evidence evita duplicación de disco
- no uses GPU salvo casos futuros específicos; hoy no aporta beneficio real
