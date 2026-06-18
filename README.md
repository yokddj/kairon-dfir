<p align="center">
  <img src="frontend/public/brand/kairon-dfir-logo-horizontal.svg" alt="Kairon DFIR" width="520" />
</p>

<h1 align="center">Kairon DFIR</h1>

<p align="center">
  <strong>Local-first DFIR investigation platform for centralizing artifacts, reducing noise, and reconstructing incidents.</strong>
</p>

<p align="center">
  <img src="docs/assets/kairon-dfir-execution-story.png" alt="Synthetic screenshot of the Kairon DFIR investigation workspace with case, indexing, search, artifacts, findings, and timeline panels." width="900" />
</p>

<p align="center">
  <img alt="Beta" src="https://img.shields.io/badge/status-beta-7dd3fc" />
  <img alt="Local-first" src="https://img.shields.io/badge/deployment-local--first-8fd694" />
  <img alt="Docker" src="https://img.shields.io/badge/runtime-docker-2496ed" />
  <img alt="Python and TypeScript" src="https://img.shields.io/badge/stack-python%20%2B%20typescript-111827" />
</p>


Kairon DFIR supports the analyst; it does not replace them. It provides a clear lens over forensic evidence so critical moments can be interpreted faster and with more context.

The project is intended for trusted labs and controlled private beta deployments. Evidence can contain highly sensitive data. Do not expose Kairon DFIR directly to the internet without authentication, VPN, or a protected reverse proxy.

## What It Does

- Ingests Windows forensic evidence into case-centered investigations.
- Normalizes artifacts for search, triage, timelines, detections, findings, and reports.
- Provides analyst workflows for Search, Artifact Views, Command History, Execution Stories, Incident Timeline, Findings, and Reports.
- Includes an experimental Memory Analysis foundation for authorized RAM evidence, disabled by default and isolated from current global Search, Timeline, Detections, Findings, Reports, and SIEM.
- Keeps validation features optional and disabled by default for normal investigations.

## Quick Start

Requirements:

- Docker and Docker Compose plugin.
- 4 CPU cores minimum; 8+ preferred for multi-host evidence.
- 16 GB RAM minimum; 32 GB preferred for full MFT and large OpenSearch indices.
- Persistent disk sized for uploaded evidence plus extracted/indexed data.

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

Default beta/investigation mode is clean:

```bash
DFIR_ENABLE_DEMO_CASES=false
DFIR_ENABLE_VALIDATION_FEATURES=false
DFIR_DEFAULT_CASE_MODE=investigation
```

Use validation flags only in QA, training, or controlled product presentations. This repository does not include evidence archives, processed data, OpenSearch indexes, Postgres dumps, public challenge datasets, or answer keys.

## First Investigation Workflow

1. Create a case
   - Open Kairon DFIR.
   - Go to Cases.
   - Click Create case.
   - Give it a name and timezone.

2. Add evidence
   - Open the case.
   - Go to Evidence & Ingest.
   - Upload a supported evidence archive or collection.
   - Wait for raw discovery.

3. Index evidence for investigation
   - Click Index evidence for investigation.
   - Use recommended indexing for the normal path.
   - Use Index selected artifact types only when you want a focused parse.

4. Start triage
   - Use Investigation Home.
   - Review Search.
   - Review Command History.
   - Review Artifact Views.
   - Check Startup & Persistence, MOTW/Downloaded Files, and Email Artifacts if present.

5. Build findings
   - Promote relevant evidence into Findings.
   - Use correlation carefully with visible scope.
   - Add important events to Incident Timeline.

6. Generate a report
   - Use Reports after evidence and findings exist.
   - Export Markdown for review.

Kairon DFIR assists the analyst; final interpretation remains the analyst's responsibility.

## Supported Evidence And Artifact Overview

Coverage depends on the artifacts present in the uploaded evidence and on parser availability in the deployment.

| Area | Examples |
| --- | --- |
| Event logs | EVTX, Sysmon, Security, PowerShell |
| Filesystem | MFT, MOTW/Zone.Identifier |
| Execution | Prefetch, Shimcache, Amcache, LNK, Jump Lists |
| User activity | RecentDocs, UserAssist, OpenSaveMRU |
| Persistence | Scheduled Tasks, Services, registry autoruns, startup folders |
| Browser/email triage | Browser history/downloads, mail stores, webmail traces |
| Memory analysis | Planned/experimental authorized RAM evidence registration, disabled by default |
| Investigation outputs | Findings, Incident Timeline, Reports |

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

Do not commit private evidence archives, processed case data, customer datasets, generated reports, indexes, database dumps or local environment files. Keep all evidence and generated case data outside version control.

Memory dumps can contain credentials, personal data, and third-party private data. Use only RAM evidence you own, are authorized to analyze, or lab/demo evidence created for that purpose. Do not commit memory dumps, extracted secrets, malware, symbol packs, or third-party memory-forensics outputs. External memory tools such as Volatility 3 and MemProcFS are not bundled. Optional Volatility 3 execution is disabled by default and requires administrator-controlled configuration plus an authorization acknowledgement per scan.

Memory backend readiness checks use only trusted server-side command settings such as `VOLATILITY3_COMMAND` and `MEMPROCFS_COMMAND`. They reject shell fragments and arguments, run harmless help/version checks only, and never receive memory-image paths.

## Documentation

- [Documentation index](docs/index.md)
- [User guide](docs/user_guide.md)
- [Feature map](docs/feature_map.md)
- [Artifact support matrix](docs/artifacts_matrix.md)
- [Memory Analysis](docs/memory_analysis.md)
- [Private beta deployment](docs/deployment/beta-deployment.md)
- [Security notes](docs/SECURITY.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
- [Validation workflow](docs/validation/README.md)

## Known Limitations

- This beta is not a hosted SaaS security boundary.
- OST/PST content parsing is not part of the current core parser set.
- SRUM parsing requires a Windows-capable worker or backend alternative.
- Some advanced Windows artifacts may require additional parser workers or tooling.
- Memory Analysis is isolated and disabled by default. Standard upload can register authorized `memory_dump` evidence when enabled, and the optional memory worker can run only the supported Volatility metadata/process profiles.
- Validation Matrix is optional QA metadata; it is not part of normal investigations.
- Kairon DFIR assists analysis, but final interpretation remains the analyst's responsibility.

## License

See [LICENSE](LICENSE).
