# Update and Rollback

Use this process for private beta updates.

## Pre-Update Checklist

1. Confirm current health:

```bash
./scripts/dfir-healthcheck.sh
```

2. Take a backup:

```bash
./scripts/dfir-backup.sh --run
```

3. Confirm no ingest/rules/report jobs are running in the System page or queue status.

## Update

```bash
git pull
docker compose build
docker compose up -d
```

If database migrations are part of a release, run them before opening the UI to analysts.

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

If migrations or data changes occurred:

1. Stop the stack.
2. Restore PostgreSQL backup.
3. Restore OpenSearch snapshot or reindex if snapshot was not taken.
4. Restore `./data` if files were changed or removed.
5. Start the previous known-good version.

## Evidence Volumes

Never delete Docker volumes during rollback unless you are intentionally restoring from backup:

- `postgres_data`
- `opensearch_data`

Do not clean `./data` unless you understand which uploaded evidence and derived parser outputs it contains.

