# Update and Rollback

Use this process for Kairon DFIR updates.

## Pre-Update Checklist

1. Confirm current health:

```bash
./scripts/dfir-healthcheck.sh
```

2. Back up the database and configuration (seconds; an upgrade does not touch the evidence):

```bash
./scripts/dfir-backup.sh --db-only
```

Take a full backup (`--run`) instead if you have none recent. See [Backup and Restore](backup-restore.md).

3. Confirm no ingest/rules/report jobs are running in the System page or queue status.

4. Confirm enough free disk space exists for uploaded evidence, extracted artifacts, PostgreSQL, and OpenSearch data.

## Update

```bash
./scripts/upgrade.sh
```

It pulls the code (`git pull`), keeps the secrets in `.env` (a copy is left as `.env.backup-<time>` next to it; old copies can be deleted), rebuilds the images and recreates the containers. Data volumes and `./data` are kept. Run it in a terminal that stays open until it finishes: if the session that started it ends halfway, the stack may be left partly rebuilt; run it again.

Database migrations and compatibility schema checks run during backend startup. Do not open the UI to analysts until the backend health endpoint reports healthy after the update.

## Post-Update Smoke

```bash
./scripts/dfir-healthcheck.sh
```

Then validate:

- frontend loads
- backend docs load
- System page shows OpenSearch and worker healthy
- existing case Search works
- report preview/export works
- users, cases, hosts, evidence, and custody events are still visible
- a new non-memory evidence upload resolves or creates the expected host according to its Host Resolution policy
- memory evidence upload still requires an explicit source host

For the validation sample case, use:

- `powershell -ep bypass`
- `sample.iso`

## Rollback

If the update fails before migrations:

```bash
git checkout <previous-known-good-ref>
docker compose build
docker compose up -d
./scripts/dfir-healthcheck.sh
```

If migrations or data changes occurred, go back to the previous version and restore the backup taken before the update:

```bash
git checkout <previous-known-good-ref>
./scripts/restore.sh backups/<timestamp>
docker compose build
docker compose up -d
./scripts/dfir-healthcheck.sh
```

Restore OpenSearch from a snapshot if you took one; otherwise reprocess evidence whose search data changed.

## 0.9.0-beta Notes

- Host Resolution Service uses existing schema for case hosts, aliases, evidence assignment fields, platform fields, and custody events.
- No automatic host merge is performed during upgrade.
- Existing evidence remains readable; new deterministic host behavior applies to new intake and reassignment operations.
- Reindex is not required solely for this release unless operators want historical search documents to reflect newly assigned host metadata.

## Evidence Volumes

Never delete Docker volumes during rollback unless you are intentionally restoring from backup:

- `postgres_data`
- `opensearch_data`

Do not clean `./data` unless you understand which uploaded evidence and derived parser outputs it contains.
