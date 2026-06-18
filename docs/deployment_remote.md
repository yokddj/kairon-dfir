# Remote Deployment

This project deploys to the Kairon host through a Git-tracked source tree and Docker Compose.

## Target

- Host: `192.168.1.19`
- SSH: use the existing local SSH configuration, for example the `dfir-server` host alias.
- Project directory: `/root/DFIR_APP`
- Compose project: `dfir_app`

Do not store passwords, private keys, tokens, or server-local `.env` values in this repository.

## Preflight

Before deployment, record:

```sh
hostname
date -Is
cd /root/DFIR_APP
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short
git diff --stat
docker compose ps
```

Keep evidence, databases, OpenSearch indexes, Redis, and Docker volumes intact. Do not run destructive cleanup commands such as `git reset --hard`, `git clean -fd`, `docker compose down -v`, `docker volume prune`, `docker system prune`, database resets, or OpenSearch index deletion.

## Source Of Truth

Preferred deployment source is a clean Git commit. Build images from the intended commit and record:

- commit hash
- backend image ID
- frontend image ID
- container IDs
- build time

If selective file sync is required, use repository-relative paths and preserve directory structure:

```sh
rsync -avzcR ./backend/app/api/routes_memory.py dfir-server:/root/DFIR_APP/
```

Rules for selective sync:

- run a dry-run first for broad changes
- never use `--delete`
- never flatten directories
- never copy `.env`, evidence, volumes, caches, `node_modules`, build output, credentials, or backup files
- verify destination paths after copy

## Build And Recreate

Build only affected services:

```sh
cd /root/DFIR_APP
docker compose build backend frontend
docker compose up -d backend frontend
```

Only run database migration steps when the diff actually changes persistent schema. Recreate storage services only when specifically required; do not recreate Postgres, OpenSearch, Redis, or evidence volumes for ordinary backend/frontend changes.

## Health Validation

Validate after deployment:

```sh
curl -fsS http://127.0.0.1:8000/docs >/dev/null
curl -I -fsS http://127.0.0.1:5173/ | head -n 1
docker compose ps
docker compose logs --tail=120 backend
```

For Memory Analysis readiness:

```sh
curl -fsS http://127.0.0.1:8000/api/memory/backends
```

Confirm no `MemoryScanRun`, `MemoryArtifactSummary`, or `dfir-memory*` OpenSearch index is created by readiness checks.

## Rollback

Rollback should use the prior known commit or image IDs and recreate only affected services:

```sh
cd /root/DFIR_APP
docker compose up -d backend frontend
```

Do not delete volumes, evidence, databases, Redis, or OpenSearch indexes during rollback. Database rollback is only relevant when a schema migration was applied.
