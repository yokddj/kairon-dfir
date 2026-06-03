<p align="center">
  <img src="frontend/public/brand/kairon-dfir-logo-horizontal.svg" alt="Kairon DFIR" width="520" />
</p>

<h1 align="center">Kairon DFIR</h1>

<p align="center">
  <strong>A local-first DFIR investigation platform built to help analysts centralize artifacts, reduce noise, and reconstruct what happened.</strong>
</p>

Kairon DFIR supports the analyst; it does not replace them. It provides a clear lens over forensic evidence so critical moments can be interpreted faster and with more context.

The project is intended for trusted labs and controlled private beta deployments. Evidence can contain highly sensitive data. Do not expose Kairon DFIR directly to the internet without authentication, VPN, or a protected reverse proxy.

## What It Does

- Ingests Windows forensic evidence into case-centered investigations.
- Normalizes artifacts for search, triage, timelines, detections, findings, and reports.
- Provides analyst workflows for Search, Artifact Views, Command History, Execution Stories, Incident Timeline, Findings, and Reports.
- Keeps demo and validation features optional and disabled by default for normal investigations.

## Requirements

- Docker and Docker Compose plugin.
- 4 CPU cores minimum; 8+ preferred for multi-host evidence.
- 16 GB RAM minimum; 32 GB preferred for full MFT and large OpenSearch indices.
- Persistent disk sized for uploaded evidence plus extracted/indexed data.

## Quick Start

```bash
git clone https://github.com/yokddj/kairon-dfir.git
cd kairon-dfir
cp .env.example .env
docker compose up -d --build
```

Open:

- Frontend: http://127.0.0.1:5173
- Backend health: http://127.0.0.1:8000/health
- API docs: http://127.0.0.1:8000/docs

## Local Deployment Notes

Default beta/investigation mode is clean:

```bash
DFIR_ENABLE_DEMO_CASES=false
DFIR_ENABLE_VALIDATION_FEATURES=false
DFIR_DEFAULT_CASE_MODE=investigation
```

Use demo/validation flags only in training, QA, or controlled product demonstrations. This repository does not include evidence archives, processed data, OpenSearch indexes, Postgres dumps, public challenge datasets, or answer keys.

## Security Warning

Do not expose ports `5173`, `8000`, `5601`, `9200`, `5432`, or `6379` directly to the internet. Place the deployment behind VPN, SSO/authentication, firewall rules, or a properly configured reverse proxy.

Treat these as sensitive:

- uploaded evidence;
- extracted parser outputs;
- OpenSearch indexes;
- Postgres data;
- generated reports;
- debug exports;
- backups;
- `.env` files.

Never commit real evidence, secrets, logs, backups, database dumps, or generated reports.

## Documentation

- `docs/index.md` — documentation index.
- `docs/feature_map.md` — current capability map.
- `docs/artifacts_matrix.md` — artifact support matrix.
- `docs/deployment/beta-deployment.md` — private beta deployment guidance.
- `docs/deployment/beta-vs-demo-mode.md` — investigation vs demo/validation modes.
- `docs/validation/README.md` — optional validation matrix workflow.
- `docs/demo/README.md` — generic demo mode guidance.

## Known Limitations

- This beta is not a hosted SaaS security boundary.
- OST/PST content parsing is not part of the current core parser set.
- SRUM parsing requires a Windows-capable worker or backend alternative.
- Some advanced Windows artifacts may require additional parser workers or tooling.
- Validation Matrix is optional QA/demo metadata; it is not part of normal investigations.
- Kairon DFIR assists analysis, but final interpretation remains the analyst’s responsibility.

## Demo / Validation Data

No bundled datasets or evidence are included in `main`. Optional demo or validation datasets can be imported separately by the operator. Validation metadata should reference expected findings only; evidence must be uploaded/indexed as a separate analyst action.

## License

See `LICENSE`.
