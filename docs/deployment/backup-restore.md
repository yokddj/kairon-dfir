# Backup and Restore

The code is on GitHub; what a backup protects is your data: the database (cases, evidence records, findings, users, settings) and the `.env` configuration, whose secrets sign sessions and encrypt stored provider keys. An upgrade changes the database, never the evidence, so the backup before an upgrade only needs the database.

## Which Backup When

| Mode | Contents | Time / size | Use it |
| --- | --- | --- | --- |
| `--db-only` | database dump, `.env`, index inventory | seconds, tens of MB | before every upgrade |
| `--run` | the same plus `./data` (uploaded evidence, extracted files, reports) | minutes, as big as the evidence | now and then, and before deleting evidence or moving the installation |
| `--dry-run` (default) | nothing is written; prints what would be done | — | to check the paths |

```bash
./scripts/dfir-backup.sh --db-only
./scripts/dfir-backup.sh --run
```

Each backup goes to `./backups/<UTC timestamp>/` (set `DFIR_BACKUP_ROOT` to change it):

- `postgres.sql`: logical dump of the database
- `env.backup`: copy of `.env`, readable only by its owner (it holds secrets; keep backups on the Kairon host or encrypted media)
- `app-data.tgz`: `./data` without `data/tmp` and local mounts (`--run` only)
- `opensearch-indices.json`: list of the search indexes
- `manifest.json`: mode, what is and is not included

A full backup can take several GB. Keep one recent full backup and a few database-only ones, and delete older ones: a full disk stops ingestion.

If a file changes while `./data` is archived (a log being written), the backup still completes and the manifest says so; only a real archive error stops it.

## What Is Not Backed Up

- Docker images (rebuilt from the code).
- Evidence mounted read-only from outside (`/mnt/evidence`, `/data/evidence`, `/cases`): it never leaves its source.
- The OpenSearch indexes. The search data is derived from the evidence: if it is lost, reprocess the evidence. For large installations, configure an OpenSearch snapshot repository and snapshot the `dfir-events-*` indexes before upgrades.

## Restore

```bash
./scripts/restore.sh backups/<timestamp>
docker compose up -d
./scripts/dfir-healthcheck.sh
```

`restore.sh` waits 10 seconds so it can be cancelled, then:

1. stops the frontend, backend and workers;
2. restores `.env` if the backup has it (the current one is kept as `.env.before-restore-<time>`);
3. restores `./data` if the backup is a full one; a database-only backup leaves `./data` as it is;
4. empties the database schema and loads the dump, stopping at the first error.

It replaces the database completely: anything created after the backup is lost. Run it from the installation directory, or set `APP_DIR`. Backups made by the older `scripts/backup.sh` (`data.tar.gz`, `.env.backup`) are also accepted.

Try a restore on a test machine before you need one.

## Downtime

Kairon is stopped during a restore. Do not run ingest jobs while a full backup is being taken.
