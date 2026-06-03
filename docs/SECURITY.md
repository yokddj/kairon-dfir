# Security

Kairon DFIR handles forensic evidence, extracted artifacts, indexed events, reports and analyst notes. Treat every deployment as sensitive.

## Private Beta Boundary

Do not expose the beta stack directly to the public Internet.

Recommended access controls:

- VPN or private lab network.
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

## Evidence Data

Do not commit or upload private evidence to GitHub:

- evidence archives (`.7z`, `.zip`, `.E01`, `.raw`, `.dd`, `.vhd`, `.vhdx`);
- mail stores (`.ost`, `.pst`, `.eml`, `.msg`);
- uploaded/extracted evidence under `data/`;
- OpenSearch/Postgres volumes;
- backups;
- generated reports/debug exports.

## Bug Reports

When reporting bugs, include sanitized reproduction details only:

- case type and artifact type;
- redacted log snippets;
- UI route or API endpoint;
- query text if safe;
- screenshots with victim names, hostnames, paths and indicators redacted where needed.

Do not attach raw evidence, full reports, backups, debug export packs or screenshots with sensitive content unless there is an approved secure transfer path.

## Third-Party Tools

The backend Docker build downloads Eric Zimmerman Tools at build time. The repository does not vendor those binaries. Review tool licenses and redistribution terms before building a public distribution that bundles binaries.

OpenSearch, Postgres, Redis, FastAPI, React and other dependencies retain their own licenses.

