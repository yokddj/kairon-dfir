# Performance

## Profiles

The UI exposes profiles:

- `safe`
- `balanced`
- `max`
- `custom`

## What each profile adjusts

### `safe`

- smaller batches and bulks
- less parallelism
- process graph and correlation with conservative limits
- suitable for hosts with low RAM or tight disk space

### `balanced`

- deployment defaults
- recommended profile for most local installations

### `max`

- larger batches and bulk
- more parallelism
- higher `PROCESS_GRAPH_MAX_NODES` and `CORRELATION_MAX_EVENTS`
- `OPENSEARCH_JAVA_HEAP` recommended at `4g`

### `custom`

- manual overrides from UI/API
- useful when you want to touch only one or two limits without switching to `max`

## Relevant parameters

- `INGEST_BATCH_SIZE`
- `OPENSEARCH_BULK_DOCS`
- `OPENSEARCH_BULK_BYTES`
- `MAX_PARALLEL_ARTIFACTS`
- `MAX_PARALLEL_RULE_RUNS`
- `MOUNTED_PATH_SCAN_LIMIT`
- `PROCESS_GRAPH_MAX_NODES`
- `CORRELATION_MAX_EVENTS`
- `OPENSEARCH_JAVA_HEAP`
- `BACKEND_UVICORN_WORKERS`
- `WORKER_SCALE`

## What requires a restart

### Immediate

- most runtime settings such as batches, search page size, graph limits and rule parallelism

### Requires restart

- `OPENSEARCH_JAVA_HEAP` -> recreate `opensearch`
- `BACKEND_UVICORN_WORKERS` -> recreate `backend`
- `WORKER_SCALE` -> scale `worker`
- global Docker limits -> recreate affected services

## Panel warnings

The panel can warn about:

- `low_disk_space`
- `low_available_memory`
- `max_profile_low_memory_risk`
- `opensearch_unavailable`

## How to interpret Performance & Resources

- check CPU, available memory, free disk and storage size used
- check `dfir-ingest` and `dfir-rules` queues
- check whether there are pending settings that have not yet been applied due to a pending restart

## Recommendations

- more RAM and OpenSearch heap help much more than a GPU
- SSD/NVMe improves ingests, mounted evidence and controlled YARA
- mounted evidence avoids disk duplication
- do not use a GPU except for specific future cases; today it provides no real benefit
