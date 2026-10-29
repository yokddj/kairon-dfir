# Codebase Map

A guide for contributors: where each part of Kairon DFIR lives, how a piece of
evidence travels through the code, and where to start for the most common
changes. For the product-level architecture see [overview.md](overview.md) and
[platform-architecture.md](platform-architecture.md).

## Repository layout

| Path | What it holds |
| --- | --- |
| `backend/app/` | FastAPI application, RQ workers, parsers, services. |
| `backend/tests/` | Pytest suite (unit, contract and `integration/` tests) and fixtures. |
| `frontend/src/` | React 18 + TypeScript + Vite single-page app. |
| `docker/` | Images for the memory side-cars (`memory-worker`, `symbol-fetcher`, `symbol-egress-gateway`). |
| `docker-compose.yml` | The whole stack; optional services sit behind Compose profiles. |
| `config/defaults.env` | Defaults the setup wizard starts from. |
| `scripts/` | Setup, upgrade, backup/restore, health checks, quality gate, release helpers. |
| `tooling/tooling.lock.yaml` | Pinned versions and hashes of external forensic tools. |
| `docs/` | This documentation. `docs/data/investigation-guide.json` feeds the in-app Investigation Guide. |

## Runtime services

| Service | Entry point | Role |
| --- | --- | --- |
| `backend` | `uvicorn app.main:app` | HTTP API on port 8000. |
| `worker` | `python -m app.workers.worker` | RQ worker for the `dfir-ingest`, `dfir-rules` and `dfir-analysis` queues. |
| `memory-worker` | `python -m app.workers.memory_worker` | Volatility 3 / MemProcFS runs, on its own queue, read-only root filesystem. |
| `symbol-fetcher`, `symbol-egress-gateway` | profile `memory-symbols` | Optional, operator-approved Windows symbol downloads. |
| `experimental-worker`, `memory-native-probe-worker` | profiles `experimental`, `native-probe` | Optional memory side paths. |
| `frontend` | nginx | Serves the built SPA and proxies `/api` to `backend`. |
| `postgres`, `redis`, `opensearch` | — | Metadata, job queue, search indices. |

The worker processes are long-lived: they import code once at start-up, so a
code change only reaches queued jobs after the worker container restarts.

## Backend (`backend/app/`)

| Package | Responsibility |
| --- | --- |
| `main.py` | App composition: routers, start-up hooks, middleware. Memory routers are mounted only when `memory_enabled` is true. |
| `api/routes_*.py` | HTTP routes, one module per area (evidence, search, timeline, rules, memory, ai…). See [api_summary.md](../operations/api_summary.md). |
| `core/` | Settings (`config.py`), database session and hand-written schema migrations (`database.py`, `migrations.py`), OpenSearch mappings and helpers (`opensearch.py`), storage paths, the artifact and platform registries (`artifact_registry.py`, `evidence_platforms.py`), CSRF/origin checks. |
| `models/` | SQLAlchemy models (cases, evidence, hosts, findings, rules, memory runs, AI conversations…). |
| `schemas/` | Pydantic request/response models. A field missing here is dropped from the HTTP response. |
| `ingest/` | Evidence discovery and parsing: `detector.py` (what each file is), `normalizer.py` and `artifact_normalizers.py` (rows → normalized events), and one sub-package per artifact family (`windows/`, `linux/`, `eztools/`, `velociraptor/`, `browser/`, `powershell/`…). |
| `disk_images/` | Read-only access to RAW, EWF, VMDK, VHD/VHDX, QCOW, VDI images: partitions, volumes, file extraction. |
| `services/` | Business logic used by routes and workers: search, timeline, command history, process tree, host identity, findings and correlation, reports, source tables, `memory/` and `ai/`. |
| `rules_engine/` | Sigma engine and the built-in detection catalogue. |
| `search/` | Search query syntax (field shortcuts such as `eventid:`, `ip:`, `process:`). |
| `analysis/` | Semi-automatic analysis and activity derivation. |
| `workers/` | RQ entry points; `tasks.py` holds the job functions (`ingest_evidence`, rule runs, memory jobs, preflight). |
| `cli/` | Maintenance commands (`python -m app.cli …`), mostly for memory symbols and results. |
| `parsers/` | Thin legacy wrappers; real parsing lives in `ingest/`. |

## How evidence flows

1. **Intake.** The upload wizard (`frontend/src/components/EvidenceIngestionWizard.tsx`)
   creates an upload session; files arrive by resumable upload, folder, disk
   image or a server path (`services/evidence_upload_session.py`,
   `services/evidence_unified_upload.py`). A SHA-256 is computed and duplicates
   inside the case are refused.
2. **Preflight.** `services/evidence_preflight.py` inspects the files read-only
   and shows which parsers would run before anything is indexed.
3. **Ingest job.** `workers/tasks.py:ingest_evidence` runs on the `dfir-ingest`
   queue: extracts archives (`ingest/archive.py`) or opens disk images
   (`disk_images/`), discovers artifacts (`ingest/detector.py`), dispatches each
   to its parser, normalizes rows into one event model and bulk-indexes them into
   the case events index in OpenSearch. Host identity is resolved along the way
   (`services/host_identity.py`, `services/host_resolution.py`).
4. **Status.** Evidence ends `completed`, `completed_with_warnings` or `failed`;
   `investigation_ready` says whether there is enough indexed data to work with.
5. **Investigation.** Search, Timeline, Artifact Views, Command History,
   Execution Story and Host Information all read the same events index through
   services such as `search_service.py` and `timeline_service.py`. Diagnose
   search behaviour through these services, not with a raw OpenSearch query:
   the query builder adds fallbacks (for example the `wildcard` sub-field).
6. **Analyst output.** Detections (run on demand), event markings, findings,
   the Incident Timeline and the report (`services/report_service.py`, Markdown
   and PDF) are stored in PostgreSQL and point back to source events.

Memory images take their own path: `services/evidence_memory_workflow.py`
registers them, the memory worker runs Volatility 3 and MemProcFS
(`services/memory/execution.py`), and results go to memory tables and a memory
index, from where the case Timeline, Search, Command History and Persistence
read them. See [memory_analysis.md](../memory/memory_analysis.md).

CSV/TSV files can additionally be indexed whole as Source Tables, in indices
that Search and detections never read. See
[source-tables.md](../search-and-investigation/source-tables.md).

## Frontend (`frontend/src/`)

| Path | Responsibility |
| --- | --- |
| `App.tsx` | Routes. Canonical routes and legacy redirects: [routing.md](routing.md). |
| `api/client.ts` | Every API call and its TypeScript types. |
| `pages/` | One component per screen (Search, Timeline, EvidenceDetail, MemoryEvidencePage, CaseReportsPage…). |
| `components/` | Shared pieces (event table, ingestion wizard, process tree, sidebar, finding dialogs) and area folders `ai/`, `memory/`, `rules/`, `table/`, `workbench/`. |
| `features/memory/` | Resumable upload of large memory images. |
| `lib/` | Registries mirrored from the backend (`artifactRegistry.ts`, `platformRegistry.ts`), event presentation profiles, route helpers. |
| `context/` | Auth, active case, timezone, notifications. |

## Where to start for common changes

| Change | Start here |
| --- | --- |
| New artifact family | Register it in `core/artifact_registry.py` and `frontend/src/lib/artifactRegistry.ts`; add detection in `ingest/detector.py`, a parser under `ingest/<family>/`, normalization, a fixture and tests; update [parser-coverage.md](../artifacts/parser-coverage.md). |
| New search field or shortcut | `search/query_syntax.py`, the mapping in `core/opensearch.py` if the field is new. |
| New Artifact View layout | `frontend/src/lib/eventPresentationProfiles.ts`, `pages/ArtifactExplorer.tsx`. |
| New built-in detection | `rules_engine/builtin_catalog.py`; see [rule_authoring.md](../rules/rule_authoring.md). |
| New report section | `services/report_service.py` (Markdown and PDF renderers). |
| New memory plugin or profile | `services/memory/catalogue.py` and `analysis_plan.py`; keep the catalogue modal and Run all in sync (contract tests check it). |
| New database column | Model in `models/`, an idempotent step in `core/migrations.py`; `backend/tests/schema_snapshot.json` must be updated. |
| New API field | Add it to the response schema in `schemas/` as well as the service. |

## Tests

- Backend: `pytest` from `backend/`; see [testing.md](../operations/testing.md)
  for the environment variables a run outside Docker needs and for the
  `integration` job that ingests real evidence against PostgreSQL, OpenSearch
  and Redis.
- Frontend: `npm test` (Vitest) and `npm run build` (`tsc -b` + Vite). On
  Node versions with Web Storage on by default, run Vitest with `NODE_OPTIONS=--no-experimental-webstorage` if
  `localStorage` tests fail.
- `scripts/quality-gate.sh --fast|--full` runs the same checks as CI.
