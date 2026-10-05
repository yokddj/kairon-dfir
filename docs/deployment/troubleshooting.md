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

The System page and `/api/system/status` report data directory disk usage and OpenSearch write-block risk. Treat these thresholds as beta defaults:

- below 80%: healthy
- 80-90%: degraded; plan cleanup before validation runs or large ingest jobs
- above 90%: stop ingest and free space
- OpenSearch write blocked: critical; do not start ingest until disk pressure is resolved and write blocks are cleared

Safe immediate cleanup targets:

- Docker build cache with `docker builder prune` after confirming no image build is active.
- stopped containers with `docker container prune`.
- dangling images with `docker image prune`.
- Python `__pycache__`, `.pytest_cache`, npm cache and old local build caches.
- rotated logs that are not needed for incident review.
- temporary parser directories under `./data/tmp` only when no ingest/reprocess job is active.

Require explicit operator confirmation before deleting:

- old backups, exports, report previews or debug packs
- duplicated uploaded evidence archives
- parsed CSV/output caches that can be regenerated
- old validation or training evidence duplicates

Do not delete:

- `postgres_data`
- `opensearch_data` or active `dfir-events-*` indices
- current uploaded evidence archives
- `.env`, `docker-compose.yml` or the deployed repo
- the latest known-good backup

If OpenSearch entered `read_only_allow_delete` or create-index protection, first confirm disk is below the safe threshold, then clear blocks:

```bash
curl -fsS http://127.0.0.1:9200/_all/_settings/index.blocks.read_only_allow_delete
curl -X PUT http://127.0.0.1:9200/_all/_settings \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
```

Do not lower OpenSearch watermarks as a routine fix. Free disk instead.

## Disk Images: Temporary Storage

VMDK, VHD/VHDX, QCOW2 and VDI images are converted to a temporary RAW copy before they are read. The copy is written sparse, so it takes about the image's real data, not its full virtual size: a 500 GB virtual disk with 40 GB in use needs about 40 GB (plus 15% margin) in the temp directory. The preflight check before processing measures this:

- **Temporary storage is tight** (recommendation): the real data fits, but the full virtual size would not. Processing works on normal Linux/macOS filesystems, which support sparse files.
- **Temporary storage too low** (blocking): not even the real data fits. Free space or move the temp directory.

The temp directory is `/app/data/tmp` inside the backend and worker containers, which is `./data/tmp` on the host: the same disk as the rest of Kairon's data. Changing `BACKEND_TEMP_DIR` in `.env` does not move it to another disk. To use a larger disk, mount a host folder there with a `docker-compose.override.yml` next to `docker-compose.yml`:

```yaml
services:
  backend:
    volumes:
      - /path/on/the/large/disk/kairon-tmp:/app/data/tmp
  worker:
    volumes:
      - /path/on/the/large/disk/kairon-tmp:/app/data/tmp
```

then `docker compose up -d`. Without Docker, set `BACKEND_TEMP_DIR` to a folder on the larger disk and restart the backend and worker.

## Parser Tooling Missing

Some parsers require optional tooling:

- SRUM currently requires a Windows-capable worker for SrumECmd/ESE support.
- PECmd raw Prefetch parsing on Linux is disabled because Windows decompression support is required.
- Shellbags backend is pending.

These are `tooling_missing` or planned states, not evidence failures.

## Security Reminder

If the stack is reachable without VPN/reverse proxy authentication, assume evidence is exposed. Do not publish beta deployments directly to the Internet.
