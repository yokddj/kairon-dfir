# Beta Deployment Guide

This guide describes a controlled private-beta deployment of Kairon DFIR. It is not a public Internet deployment guide.

## Scope

The beta stack runs:

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
- 4 CPU cores minimum for small beta use; 8+ preferred for multi-host evidence.
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

Do not store secrets in repository files. `.env` is local deployment state.

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

## Security Notes

The beta stack is intended for a trusted private network, VPN, or authenticated reverse proxy.

Do not expose these ports directly to the public Internet:

- `5173`
- `8000`
- `5601`
- `9200`
- `5432`
- `6379`

If authentication is not configured at the reverse proxy, the deployment is not suitable for public access.

Recommended reverse proxy controls:

- VPN or IP allowlist.
- TLS termination.
- HTTP basic auth or SSO in front of frontend/backend.
- No public access to Postgres, Redis or OpenSearch.

## Validation Datasets

The main branch does not bundle evidence archives, public challenge datasets or answer keys. Validation datasets should be maintained as separate packages and imported only into environments where users expect QA or training material.

Relevant docs:

- `docs/validation/README.md`
- `docs/validation/validation-matrix-format.md`

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
