# GitHub Beta Release Repository Cleanup

Status: private beta repository hygiene baseline.

## Inventory Classification

| Path | Category | Reason |
|---|---|---|
| `backend/` | keep | FastAPI backend, parser integrations, services, tests and fixtures. |
| `frontend/` | keep | React/Vite UI and tests. |
| `docs/` | keep | Current user, deployment, validation, feature map and troubleshooting documentation. |
| `scripts/dfir-healthcheck.sh` | keep | Beta operational healthcheck helper. |
| `scripts/dfir-backup.sh` | keep | Safe dry-run backup helper and optional backup runner. |
| `docker-compose.yml` | keep | Primary beta deployment stack. |
| `backend/Dockerfile` | keep | Backend/worker image build; downloads parser tools at build time. |
| `.env.example` | keep | Redacted configuration template. |
| `.env` | gitignore | Local deployment secrets. Never commit. |
| `data/` | gitignore | Uploaded evidence, extracted evidence and runtime parser output. Only `.gitkeep` files are retained. |
| `backups/` | gitignore | Database/application backups may contain sensitive evidence and reports. |
| `logs/` | gitignore | Runtime logs can include paths, IOCs or environment details. |
| `reports/generated/` | gitignore | Generated reports can contain sensitive findings and evidence references. |
| `frontend/node_modules/`, `frontend/dist/` | gitignore/dockerignore | Generated dependency/build output. |
| `backend/.pytest_cache/`, `__pycache__/`, `*.egg-info` | gitignore/dockerignore | Generated Python test/build output. |
| `*.7z`, `*.zip`, `*.E01`, `*.raw`, `*.dd`, `*.ost`, `*.pst`, `*.vhd*` | gitignore/dockerignore | Evidence archives, mail stores and disk images must not be committed accidentally. |
| `tmp_*`, `.tmp-backend-data/` | gitignore | Local scratch and generated output. |

## Secret Scan Summary

Manual ripgrep scan was run for common secret patterns:

- password/passwd
- token/API key/access key/private key
- database URLs and credentialed URLs
- certificate/private-key filenames
- `.env`

Findings:

- No production secrets were identified in versioned release files.
- `.env` exists locally and is ignored.
- Test strings such as `demosecret`, `SuperSecret`, `access_token=...` exist only in fixtures used to validate redaction behavior.
- Development defaults such as `dfir`/`admin` exist in code/config for local Docker defaults; `.env.example` uses `CHANGE_ME` placeholders for beta deployments.

## Data Cleanup Policy

Do not commit:

- uploaded evidence;
- OpenSearch/Postgres volumes;
- backups;
- generated reports;
- debug exports;
- parser temp output;
- real mail stores, disk images or evidence archives.

The repository keeps only minimal `.gitkeep` files for data directory structure.

## Documentation Kept

Current beta-facing docs include:

- `README.md`
- `docs/deployment/beta-deployment.md`
- `docs/deployment/backup-restore.md`
- `docs/deployment/update-rollback.md`
- `docs/deployment/troubleshooting.md`
- `docs/SECURITY.md`
- `docs/KNOWN_LIMITATIONS.md`
- `docs/BETA_NOTES.md`
- `CHANGELOG.md`
- Demo/training validation docs.

## Legal / Third-Party Review

`LICENSE` is a private beta evaluation license. Before any public release, review:

- whether the project should move to an open-source license;
- Eric Zimmerman Tools download/build-time usage and redistribution terms;
- any bundled Sigma/YARA/rule content license requirements;
- dependency attribution expectations.
