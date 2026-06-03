# Backup and Restore

Backups must be taken before beta updates, before migrations, and before deleting large evidence.

## What To Back Up

Required:

- PostgreSQL logical dump.
- `./data` directory, excluding temporary files and external read-only mounts.
- OpenSearch index inventory and either OpenSearch snapshots or a documented reindex path.

Included in PostgreSQL:

- cases
- evidence metadata
- findings and markings
- reports metadata
- rule library metadata
- validation matrices
- incident timeline metadata

Included in `./data`:

- uploaded evidence storage
- extracted evidence files
- generated report files where stored on disk
- parser outputs and derived data

Not included by the lightweight backup script:

- Docker images
- external evidence mounted read-only under `/mnt/evidence`, `/data/evidence`, or `/cases`
- physical OpenSearch shard snapshots

## Dry Run

The default script mode is safe and writes no data:

```bash
./scripts/dfir-backup.sh --dry-run
```

## Create A Backup

```bash
./scripts/dfir-backup.sh --run
```

Output defaults to:

```text
./backups/<UTC timestamp>/
```

Files:

- `postgres.sql`
- `app-data.tgz`
- `opensearch-indices.json`
- `manifest.json`

## OpenSearch Snapshot Strategy

For private beta, the minimum supported strategy is:

1. Back up PostgreSQL.
2. Back up `./data`.
3. Record OpenSearch index inventory.
4. Keep original evidence so indexed events can be regenerated if OpenSearch data is lost.

For larger beta deployments, configure an OpenSearch snapshot repository and snapshot all `dfir-events-*` indices before updates.

## Restore Order

1. Stop services:

```bash
docker compose down
```

2. Restore `./data` from `app-data.tgz`.

3. Start Postgres only:

```bash
docker compose up -d postgres
```

4. Restore database:

```bash
cat backups/<timestamp>/postgres.sql | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

5. Restore OpenSearch from snapshot, or reindex from evidence if snapshot was not taken.

6. Start the full stack:

```bash
docker compose up -d
```

7. Run:

```bash
./scripts/dfir-healthcheck.sh
```

## Expected Downtime

PostgreSQL logical restore and OpenSearch snapshot restore require downtime. Do not run ingest jobs during backup or restore.

