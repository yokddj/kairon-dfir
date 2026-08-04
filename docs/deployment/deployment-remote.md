# Remote Deployment

This project deploys to the Kairon host through a Git-tracked source tree and Docker Compose.

## Target

- Host: your deployment target, never hardcoded here -- set `REMOTE_HOST` (see `scripts/deploy_remote.sh`) or use a local SSH config alias, e.g. `your-host-alias`.
- Project directory: `$REMOTE_DIR` (defaults to `/root/kairon-dfir` in `scripts/deploy_remote.sh` if unset).
- Compose project: named after the project directory (`kairon-dfir` by default).

> **Lesson from a real incident:** this document once continued to name an
> old deployment directory as the target well after the actual running
> application had moved to a new one. That old directory wasn't fully
> dead either -- it still hosted a separate, not-yet-migrated container.
> Before trusting this document (or any deployment doc) as current, verify
> the *actual* running state on the host (`docker compose ps`, check which
> directory has a live `.git`/`.env`) rather than assuming the documented
> path is still accurate. If you have more than one checkout on a host,
> record which one is authoritative in your own local notes, not here.

Do not store passwords, private keys, tokens, real hostnames/IPs, or server-local `.env` values in this repository.

## Preflight

Before deployment, record:

```sh
hostname
date -Is
cd "$REMOTE_DIR"
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
rsync -avzcR ./backend/app/api/routes_memory.py "$REMOTE_HOST:$REMOTE_DIR/"
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
cd "$REMOTE_DIR"
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

## Optional Memory Worker

The optional Volatility memory worker is not built or started by default. To build it on the target server after reviewing `docker/memory-worker/THIRD_PARTY_NOTICES.md`:

```sh
docker compose --profile memory build memory-worker
docker compose --profile memory up -d memory-worker
```

Keep `MEMORY_SYMBOL_MODE=offline_only`. Do not enable managed symbol acquisition
unless restricted official-source egress and authenticated administrator
authorization have both been implemented and independently verified. A normal
Docker bridge is not sufficient. See [Managed Windows symbols](../memory/memory_symbols.md).

The isolated fetcher can be built for security validation without enabling a
download:

```bash
docker compose --profile memory-symbols build symbol-fetcher
docker compose --profile memory-symbols up -d symbol-fetcher
```

It must have no evidence mount and `MEMORY_SYMBOL_NETWORK_ISOLATION_READY` must
remain false until host firewall or egress-proxy enforcement is proven.

Do not publish the resulting image to a registry. Do not install Volatility on the host, backend, or normal worker. Keep `MEMORY_ANALYSIS_ENABLED`, `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION`, and `MEMORY_PROCESS_PROFILE_ENABLED` disabled unless an administrator intentionally enables authorized memory analysis.

## Rollback

Rollback should use the prior known commit or image IDs and recreate only affected services:

```sh
cd "$REMOTE_DIR"
docker compose up -d backend frontend
```

Do not delete volumes, evidence, databases, Redis, or OpenSearch indexes during rollback. Database rollback is only relevant when a schema migration was applied.
