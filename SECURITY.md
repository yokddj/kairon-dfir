# Security

Kairon DFIR handles forensic evidence, extracted artifacts, indexed events, reports and analyst notes. Treat every deployment as sensitive.

## Self-Hosted Deployment Boundary

Kairon DFIR is self-hosted software, not a managed service. It does not provide a complete public-facing security boundary by itself — do not expose a deployment directly to the public Internet.

Recommended access controls:

- VPN or private network.
- Reverse proxy with TLS.
- HTTP basic auth, SSO, or another access-control layer in front of frontend/backend.
- Firewall rules blocking direct access to Postgres, Redis, OpenSearch and OpenSearch Dashboards.

Do not publish these ports publicly:

- `5173` frontend
- `8000` backend/API
- `5601` OpenSearch Dashboards
- `9200` OpenSearch
- `5432` Postgres
- `6379` Redis

## Secrets

- Use `.env.example` as a template.
- Store real values only in local `.env`.
- Never commit `.env`, certificates, private keys, tokens or service passwords.
- Rotate secrets before sharing logs or screenshots if exposure is suspected.

## Deployment Metadata

Never commit real deployment infrastructure: hostnames, IP addresses, SSH usernames, or server-specific filesystem paths. This is a public repository — anything committed here is permanently, publicly disclosed, regardless of later edits or history rewrites.

- Deployment scripts (`deploy.sh`, `scripts/deploy_remote.sh`, `scripts/backup.sh`, `scripts/restore.sh`) take the real target via environment variables (`REMOTE_HOST`, `REMOTE_DIR`, `APP_DIR`, `POSTGRES_CONTAINER`) and fail with a clear error if a required one is missing. Never add a hardcoded fallback to a real value — an empty/required default that fails loudly is correct; a real value that "just works" is not.
- Documentation and examples that need to show an IP address must use an RFC 5737 documentation range, never a real or guessed private address:
  - `192.0.2.0/24`
  - `198.51.100.0/24`
  - `203.0.113.0/24`
- `127.0.0.1`, `0.0.0.0`, and `localhost` are always fine to use literally — they're standard binds/loopback, not infrastructure disclosure.
- DFIR test fixtures are the one deliberate exception: this project's test suite legitimately uses realistic-looking private (RFC 1918) IPs and Linux/Windows paths as simulated victim-machine data. That's expected test content, not a leak — `scripts/check-infra-metadata.sh` already excludes `backend/tests/**` and `*.test.ts(x)` files for exactly this reason.
- Run `bash scripts/check-infra-metadata.sh` (also wired into CI) before committing anything that touches deployment scripts or docs, if you're ever unsure.

## Evidence Data

Do not commit or upload private evidence to GitHub:

- evidence archives (`.7z`, `.zip`, `.E01`, `.raw`, `.dd`, `.vhd`, `.vhdx`);
- mail stores (`.ost`, `.pst`, `.eml`, `.msg`);
- uploaded/extracted evidence under `data/`;
- OpenSearch/Postgres volumes;
- backups;
- generated reports/debug exports.

## Reporting a Vulnerability

This project does not yet have a dedicated security-disclosure contact configured. Until one is published here, please use GitHub's private reporting channel — repository **Security** tab → **Report a vulnerability** — instead of opening a public issue, so the report is not visible before a fix is available.

Do not attach raw evidence, full reports, backups, debug export packs or screenshots with sensitive content to a vulnerability report unless there is an approved secure transfer path.

## Bug Reports

When reporting bugs (not security vulnerabilities), include sanitized reproduction details only:

- case type and artifact type;
- redacted log snippets;
- UI route or API endpoint;
- query text if safe;
- screenshots with victim names, hostnames, paths and indicators redacted where needed.

## Third-Party Tools

The backend Docker build downloads Eric Zimmerman Tools at build time. The repository does not vendor those binaries. Review tool licenses and redistribution terms before building a distribution that bundles binaries.

OpenSearch, Postgres, Redis, FastAPI, React and other dependencies retain their own licenses. See `NOTICE` for a summary.
