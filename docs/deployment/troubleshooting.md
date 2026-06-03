# Beta Troubleshooting

## Health Command

Run:

```bash
./scripts/dfir-healthcheck.sh
```

If it returns `degraded`, inspect the named component.

## Frontend Unavailable

Check:

```bash
docker compose ps frontend
docker compose logs --tail=100 frontend
curl -I http://127.0.0.1:5173
```

Common causes:

- frontend container not running
- wrong `FRONTEND_API_BASE_URL`
- reverse proxy forwarding to the wrong port

## Backend Unavailable

Check:

```bash
docker compose ps backend
docker compose logs --tail=100 backend
curl -I http://127.0.0.1:8000/docs
```

Common causes:

- invalid `.env`
- Postgres or OpenSearch not healthy
- migration/import error at startup

## Worker Not Processing Jobs

Check:

```bash
docker compose ps worker
docker compose logs --tail=100 worker
curl -fsS http://127.0.0.1:8000/api/system/task-health
```

If jobs remain queued, restart the worker:

```bash
docker compose restart worker
```

## OpenSearch Degraded

Check:

```bash
docker compose logs --tail=100 opensearch
curl -fsS http://127.0.0.1:9200/_cluster/health?pretty
```

OpenSearch may become read-only or unhealthy when disk is low. Free disk, then clear read-only blocks only after confirming enough free space.

## Disk Space

The System page and `/api/system/status` report data directory disk usage. Treat these thresholds as beta defaults:

- below 75%: healthy
- 75-85%: monitor
- above 85%: degraded
- above 90%: stop ingest and free space

Clean only safe targets:

- Docker build cache after confirming images are not needed.
- old backups after validating newer backups.
- temporary files under `./data/tmp`.

Do not delete `postgres_data`, `opensearch_data`, or uploaded evidence unless restoring intentionally.

## Parser Tooling Missing

Some parsers require optional tooling:

- SRUM currently requires a Windows-capable worker for SrumECmd/ESE support.
- PECmd raw Prefetch parsing on Linux is disabled because Windows decompression support is required.
- Shellbags backend is pending.

These are `tooling_missing` or planned states, not evidence failures.

## Security Reminder

If the stack is reachable without VPN/reverse proxy authentication, assume evidence is exposed. Do not publish beta deployments directly to the Internet.

