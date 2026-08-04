# Deployment Guide

This guide describes a controlled, self-hosted deployment of Kairon DFIR. It is not a guide for exposing the stack directly to the public Internet — see [`/SECURITY.md`](../../SECURITY.md) for the deployment security boundary.

## Scope

The stack runs:

- `frontend` on port `5173`
- `backend` on port `8000`
- `worker`
- `postgres`
- `redis`
- `opensearch`
- `opensearch-dashboards` on port `5601`

Rules, reports, parser rebuilds and SRUM Windows-worker parsing are not part of initial evidence indexing. They remain explicit analyst actions.

## Requirements

- Docker and Docker Compose plugin.
- 4 CPU cores minimum for small deployments; 8+ preferred for multi-host evidence.
- 16 GB RAM minimum; 32 GB preferred when using full MFT and OpenSearch.
- Persistent disk sized for evidence plus indexed data. For validation or training evidence, size storage according to the dataset owner's guidance.
- Private network access only. Do not expose the stack directly to the Internet.

## First-Time Setup

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Replace all `CHANGE_ME` values in `.env`.

3. Keep these defaults unless you have a reason to change them:

```bash
DFIR_ALLOW_HOST_PATH_IMPORT=false
MAX_PARALLEL_ARTIFACTS=1
MAX_PARALLEL_RULE_RUNS=1
OPENSEARCH_JAVA_HEAP=2g
```

4. Start the stack:

```bash
docker compose up -d --build
```

5. Verify health:

```bash
./scripts/dfir-healthcheck.sh
```

Default endpoints once the stack is up:

- frontend: `http://localhost:5173`
- backend docs: `http://localhost:8000/docs`
- dashboards: `http://localhost:5601`

## Environment Variables Reference

### Database / queue

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

### Backend / evidence

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

See `.env.example` for the full, authoritative list with defaults.

## Volumes and Data

Persistent Docker volumes:

- `postgres_data`: cases, evidence metadata, findings, reports, rules, validation matrix, timeline metadata.
- `opensearch_data`: indexed events and search data.

Repository data directory:

- `./data`: uploaded evidence staging, extracted evidence data, generated artifacts, temporary files.

Read-only external evidence mounts:

- `./data/local-mounts/mnt-evidence:/mnt/evidence:ro`
- `./data/local-mounts/data-evidence:/data/evidence:ro`
- `./data/local-mounts/cases:/cases:ro`

These paths are the expected bases for `server-mounted path` selection when `DFIR_ALLOW_HOST_PATH_IMPORT=true`.

Do not store secrets in repository files. `.env` is local deployment state.

### Why doesn't my local path work?

If you type a path into the UI such as:

- `C:\Users\analyst\Desktop\Evidence`
- `/home/user/Evidence`
- `/opt/evidence`

the backend cannot read it just because it exists on your own machine — the backend runs in its own container. You must either:

1. use **Upload file** from the browser, or
2. mount/share that folder on the server under one of the allowed roots above (e.g. `./data/local-mounts/mnt-evidence`).

## Health Checks

Use:

```bash
./scripts/dfir-healthcheck.sh
```

It checks:

- frontend HTTP
- backend docs and `/health`
- OpenSearch cluster status
- Redis/RQ queues
- worker presence
- data directory disk usage
- parser tool availability
- task health warnings

The in-app System page and `/api/system/status` expose the same operational components.

## Operations

Selective restarts:

```bash
docker compose up -d --force-recreate backend
docker compose up -d --force-recreate frontend
docker compose up -d --force-recreate opensearch
docker compose up -d --scale worker=1
```

Checking status:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f opensearch
curl -I http://localhost:5173
curl -I http://localhost:8000/docs
```

If you change `OPENSEARCH_JAVA_HEAP`, recreate `opensearch`. If you change `BACKEND_UVICORN_WORKERS`, recreate `backend`. To scale workers, use `docker compose up -d --scale worker=<N>`.

## Security Notes

The stack is intended for a trusted private network, VPN, or authenticated reverse proxy.

Do not expose these ports directly to the public Internet:

- `5173`
- `8000`
- `5601`
- `9200`
- `5432`
- `6379`

If authentication is not configured at the reverse proxy, the deployment is not suitable for exposure beyond a trusted network.

Recommended reverse proxy controls:

- VPN or IP allowlist.
- TLS termination.
- HTTP basic auth or SSO in front of frontend/backend.
- No public access to Postgres, Redis or OpenSearch.

Additional operational hygiene:

- Do not mount `docker.sock` without an explicit, deliberate reason.
- Keep `DFIR_ALLOWED_EVIDENCE_ROOTS` restricted to real evidence roots.
- Do not enable host-path import unless you need it.
- Run YARA scans with size and scope limits.
- Avoid publishing `postgres`, `redis`, and `opensearch` to the host unless necessary.

## Validation Datasets

The main branch does not bundle evidence archives, public challenge datasets or answer keys. Validation datasets should be maintained as separate packages and imported only into environments where users expect QA or training material.

Relevant docs:

- [Validation workflow](../validation/README.md)
- [Validation matrix format](../validation/validation-matrix-format.md)

If you import a validation dataset, treat it as evidence data and back it up like any other case.

## Operational Smoke After Deploy

Run:

```bash
./scripts/dfir-healthcheck.sh
```

Then validate in the UI:

- open Case Home
- run Search for a known term from a controlled validation case, if one is loaded
- open Artifact Views
- preview or export a report
