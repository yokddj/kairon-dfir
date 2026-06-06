# Deployment

## Stack Docker Compose

Servicios principales:

- `postgres`
- `redis`
- `opensearch`
- `opensearch-dashboards`
- `backend`
- `worker`
- `frontend`

Arranque:

```bash
docker compose up --build
```

## Endpoints por defecto

- frontend: `http://localhost:5173`
- backend docs: `http://localhost:8000/docs`
- dashboards: `http://localhost:5601`

## Variables `.env` importantes

### Base de datos / cola

- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `REDIS_URL`

### OpenSearch

- `OPENSEARCH_HOST`
- `OPENSEARCH_PORT`
- `OPENSEARCH_USER`
- `OPENSEARCH_PASSWORD`
- `OPENSEARCH_INITIAL_ADMIN_PASSWORD`
- `OPENSEARCH_INDEX_PREFIX`
- `OPENSEARCH_JAVA_HEAP`
- `OPENSEARCH_DASHBOARDS_INTERNAL_URL`
- `OPENSEARCH_DASHBOARDS_PUBLIC_URL`

### Backend / evidencia

- `BACKEND_DATA_DIR`
- `BACKEND_TEMP_DIR`
- `BACKEND_MAX_UPLOAD_SIZE`
- `BACKEND_MAX_EXTRACTED_FILES`
- `BACKEND_MAX_EXTRACTED_BYTES`
- `DFIR_ALLOW_HOST_PATH_IMPORT`
- `DFIR_ALLOWED_EVIDENCE_ROOTS`

### Performance / ingest

- `INGEST_BATCH_SIZE`
- `OPENSEARCH_BULK_DOCS`
- `OPENSEARCH_BULK_BYTES`
- `BACKEND_UVICORN_WORKERS`
- `MAX_PARALLEL_ARTIFACTS`
- `MAX_PARALLEL_RULE_RUNS`
- `SEARCH_DEFAULT_PAGE_SIZE`
- `SEARCH_MAX_PAGE_SIZE`

### YARA

- `YARA_SCAN_RAW_EVIDENCE`
- `YARA_SCAN_PARSED_OUTPUTS`
- `YARA_SCAN_ARCHIVES`
- `YARA_SCAN_TEXT_OUTPUTS`
- `YARA_MAX_FILE_SIZE_MB`

### Frontend

- `FRONTEND_API_BASE_URL`

## Volúmenes y rutas montadas

El stack actual monta:

- `./data:/app/data`
- `/mnt/evidence:/mnt/evidence:ro`
- `/data/evidence:/data/evidence:ro`
- `/cases:/cases:ro`

Esas rutas son las bases esperadas para `server-mounted path` si `DFIR_ALLOW_HOST_PATH_IMPORT=true`.

## Why my local path does not work?

Si escribes en la UI una ruta como:

- `C:\Users\analyst\Desktop\Evidence`
- `/home/user/Evidence`
- `/opt/evidence`

el backend no podrá leerla solo porque exista en tu equipo.

Debes:

1. usar `Upload file` desde el navegador
2. o montar/compartir esa carpeta en el servidor bajo un root permitido, por ejemplo `/mnt/evidence`

## Reinicios selectivos

```bash
docker compose up -d --force-recreate backend
docker compose up -d --force-recreate frontend
docker compose up -d --force-recreate opensearch
docker compose up -d --scale worker=1
```

## Cómo comprobar estado

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f opensearch
curl -I http://localhost:5173
curl -I http://localhost:8000/docs
```

## Seguridad operativa

- No montes `docker.sock` salvo decisión explícita y consciente.
- Mantén `DFIR_ALLOWED_EVIDENCE_ROOTS` restringido a roots de evidencia reales.
- No habilites host path import sin necesidad.
- YARA debe ejecutarse con límites de tamaño y scope.
- Evita publicar `postgres`, `redis` y `opensearch` al host si no hace falta.

## Notas de despliegue remoto

- Si cambias `OPENSEARCH_JAVA_HEAP`, recrea `opensearch`.
- Si cambias `BACKEND_UVICORN_WORKERS`, recrea `backend`.
- Si escalas workers, usa `docker compose up -d --scale worker=<N>`.
