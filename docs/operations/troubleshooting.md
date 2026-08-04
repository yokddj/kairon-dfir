# Troubleshooting

## Backend does not start

Check:

- `docker compose ps`
- `docker compose logs -f backend`
- PostgreSQL credentials
- connectivity to OpenSearch and Redis
- automatic migration of new columns

## OpenSearch 502 / timeout

Check:

- `opensearch` status
- available heap
- free disk
- bulk/refresh limits
- whether a restart is pending after changing `OPENSEARCH_JAVA_HEAP`

## OpenSearch: `index_create_block_exception` / create-index blocked

Typical symptom:

- `AuthorizationException(403, 'index_create_block_exception', 'blocked by: [FORBIDDEN/10/cluster create-index blocked (api)];')`

Expected app behavior:

- must not start parsing
- must not mark artifacts as parser failed if the preflight fails before indexing
- must show a clear error:
  - `OpenSearch is not writable or cannot create indices. Ingest has not started.`

Diagnosis:

```bash
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cluster/settings?include_defaults=true&pretty'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cluster/health?pretty'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cat/allocation?v'
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD 'http://localhost:9200/_cat/indices?v'
```

What to look for:

- `persistent.cluster.blocks.create_index`
- `transient.cluster.blocks.create_index`
- `defaults.cluster.blocks.create_index`
- `persistent.cluster.blocks.write`
- `transient.cluster.blocks.write`
- `defaults.cluster.blocks.write`
- indices with `read_only_allow_delete`
- disk pressure / flood-stage watermark

Safe remediation:

1. free up space if the node is at its limit
2. fix the cause of the block
3. clear the write or create-index block

Examples:

```bash
curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD -XPUT 'http://localhost:9200/_cluster/settings' -H 'Content-Type: application/json' -d '{
  "persistent": {
    "cluster.blocks.create_index": null,
    "cluster.blocks.write": null
  },
  "transient": {
    "cluster.blocks.create_index": null,
    "cluster.blocks.write": null
  }
}'

curl -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD -XPUT 'http://localhost:9200/_all/_settings' -H 'Content-Type: application/json' -d '{
  "index.blocks.read_only_allow_delete": null
}'
```

Afterwards:

- check `/_cluster/health` again
- confirm the app marks OpenSearch as writable
- relaunch the ingest or benchmark

## Bulk / refresh issues

Symptoms:

- slow ingests
- events indexed in audit but not visible
- refresh timeout

Check:

- `OPENSEARCH_BULK_DOCS`
- `OPENSEARCH_BULK_BYTES`
- `OPENSEARCH_REFRESH_TIMEOUT`
- `Performance & Resources`

## Mounted evidence: path validation fails

Check:

- `DFIR_ALLOW_HOST_PATH_IMPORT=true`
- the path falls within `DFIR_ALLOWED_EVIDENCE_ROOTS`
- the path exists
- there is no symlink escape

If you enter a path like `C:\Users\...` or `/home/user/...`, that is usually a path on the client machine, not the server.

Action:

- use `Upload file`
- or mount/share it on the server under `/mnt/evidence`, `/data/evidence` or `/cases`

## A loose `.evtx` file should not need a ZIP

Expected behavior:

- a loose `.evtx` file must be detected as `Windows Event Log`
- it must be processed as `RAW evidence`
- it must not require a special archive flow or show `unknown`

If this does not happen:

- check that the file ends in `.evtx`
- check `Evidence & Ingest` to see if it was marked as `Detected: Windows Event Log (.evtx)`
- if you're using a mounted path, verify that backend and worker see the same path
- export the `Debug Pack` and check `ingest_summary.json` / `ingest_plan.json`

## Uploaded RAW ZIP still not parsed

A RAW archive can go through two phases:

- discovery of candidates
- parsing of the selected candidates

If you see `waiting_selection`:

- it does not mean the archive failed
- it means discovery already detected compatible artifacts and is waiting for selection confirmation
- the UI or the parse endpoint must trigger parsing of the recommended candidates

If the archive does not detect any artifacts:

- the correct message is that no supported artifacts were detected
- a misleading error such as `Velociraptor discovery failed` must not appear to the end user

## System / Performance does not make mounted evidence clear

The current UI separates:

- runtime settings
- deployment settings
- evidence storage
- advanced raw settings

If `Server-mounted evidence import` shows as `Disabled`, the expected behavior is:

- `Upload file` remains available
- `Register server-mounted path` is explained but not presented as a runtime toggle
- the UI itself shows the environment variables and restart command

Recommended path:

- `System / Performance -> Evidence storage`
- `Evidence & Ingest -> Register server-mounted path`

## Low disk space

Symptoms:

- stalled ingests
- partial extraction
- unstable OpenSearch

Action:

- clean up unneeded storage
- use mounted evidence
- reduce exports and duplicate copies

## Host contamination

If a case mixes hosts in an odd way:

- check `host_attribution_report.json`
- check `host_identity_report.json`
- validate mixed evidence
- filter by `host`
- check whether the case needs to separate evidence

If the problem is naming rather than actual contamination:

- open `Overview -> Host Identity -> Manage hosts`
- merge aliases only when you're confident
- split the alias if the merge was incorrect

## Reingest volume drop

If volume drops significantly after a reingest:

- export the debug pack
- check `ingest_regression_report.json`
- check `parser_audit.json`
- check artifact selection filters

## Reprocess: findings, detections or key events changed

Check:

- `event_identity_report.json`
- `reconciliation_report.json`
- whether new events have a `stable_event_id`
- whether the affected parser is falling into `fingerprint_best_effort`

Key points:

- `event_id` can change after a reprocess

## Reprocess parses something different from the first time

Check the evidence's `ingest_plan`. The recommended mode is `Use previous parser selection`, which reuses the same set of candidates/parsers used before.

If `Full rediscovery` is used, the app may discover and select a different set of candidates. This is expected, and the UI warns about it before launching the reprocess.

If old evidence has no `ingest_plan`, the UI will show that no previous plan exists and will ask to use rediscovery or manual selection.
- `stable_event_id` is the logical identity used by v1 reconciliation
- findings and detections must preserve state using stable fingerprints
- key events should move to `current` or `remapped`; if no equivalent is found, they remain `stale`

If an artifact changed too much between exports:

- the fingerprint may change
- reconciliation may create a new object instead of reusing the previous one
- document the parser/source as a best-effort limitation if there is no stable locator

## YARA unavailable

Expected behavior:

- clear unavailable status
- controlled warning
- no `500`

If you expected YARA to be operational, check the engine dependency in the backend image.

## Sigma rule invalid

Check:

- valid YAML
- `detection` and `condition` present
- fields mappable to the normalized schema

## Search returns 0

Check:

- whether you're filtering by the correct host. Search expands aliases like `HOSTA`, `hosta` and `hosta.example.local`, but must not mix unrelated hosts.
- whether the query is within the correct artifact. Try first without `artifact_type` and then narrow it down.
- whether you're excluding MFT or another artifact with negative filters.
- whether you're only viewing the default backend while the data is in an advanced backend. Use `backend_variant=advanced` or `backend_variant=all` when comparing EZ Tool rebuilds.
- whether the term actually exists in the source data. A Defender log may have configuration events without threat strings such as `credential-tool` or `VirTool`.
- that the active case, evidence, host and time range are the expected ones.
- that the evidence finished as `completed` or `completed_with_warnings` with `investigation_ready=true`.
- that the case is not using an old incompatible index.

Command queries:

- `-ep`, `-nop` and `-w` are treated as text, not as NOT.
- paths like `C:\Users\Public\remote-admin.exe` and `.\f\script.ps1` should be searched by full path and basename.
- to exclude text, use `exclude_q` or `does not contain` filters.

If using advanced syntax:

- check for unclosed quotes.
- use only supported fields.
- remember that `Search` does not support the full KQL/Lucene syntax.
- try first with:
  - `artifact.type:mft`
  - `risk_score>=70`
  - `process.name:powershell.exe`

If an advanced query is invalid, the app must return `400` with examples, not `500`.

## Evidence appears failed but has searchable data

Expected behavior:

- if the evidence has indexed documents and is investigable, it must show `investigation_ready=true`.
- if there were non-critical warnings, the correct status is `completed_with_warnings`, not `failed`.
- optional parser errors, `tooling_missing`, unsupported artifacts and no-data families should not hide searchable data.

Action:

- use `Recompute evidence status` / `Repair evidence status` if the UI offers it.
- check `status_reason`, `searchable_documents_count`, `warning_count` and `error_count`.

## SRUM detected but not parsed

Expected status on Linux:

- `SRUDB.dat` may be detected.
- `SrumECmd` requires Windows ESE libraries.
- the app must show `tooling_missing` or `Requires Windows parser worker`.
- it must not mark the evidence as failed.

Solution:

- configure a Windows parser worker when available.
- in the meantime, use other sources: EVTX, Command History, MFT, Defender, Browser, Prefetch, Amcache/Shimcache.

## MFT full indexing is large

MFT full can add hundreds of thousands of documents.

Expected behavior:

- it is only launched with an explicit action.
- Search can find any path/filename present in the MFT.
- Timeline does not include MFT by default.
- Evidence can still be `completed_with_warnings` if MFT full ends up partial or fails without affecting other data.

If Search seems flooded:

- filter by `artifact_type`.
- exclude MFT with negative filters.
- use Artifact Views MFT for pagination/specific columns.

## EZ advanced rebuild results look duplicated

LNK, Jumplist, Amcache and Shimcache can have:

- default/internal backend
- advanced EZ Tool backend

Default Search hides advanced to avoid duplicates. Use:

- `backend_variant=advanced`
- `backend_variant=all`
- `parser_backend=<backend>`

to compare. Do not delete internal docs without an explicit decision to activate them by default.

## PECmd is available but Prefetch rebuild is disabled

In this Linux deployment, raw PECmd `.pf` parsing requires Windows decompression support. The platform uses its internal Prefetch parser.

This is a backend limitation, not an evidence failure.

## Shellbags detected but no rows indexed

Shellbags from raw hives (`NTUSER.DAT`, `UsrClass.dat`) are pending a dedicated backend.

Expected status:

- candidates detected.
- not parsed as Shellbags.
- User Activity can still index UserAssist, RecentDocs, RunMRU or OpenSaveMRU if present.

## `POST /correlate` returns 422

Current expected behavior:

- `POST /api/cases/{case_id}/correlate` accepts an empty body
- `POST /api/cases/{case_id}/correlate` with `{}` also works

If a `422` reappears, check:

- that backend/worker have been rebuilt with the current version
- that you're not calling an old container
- that the endpoint is not being intercepted by a client with an outdated schema

## Empty or ambiguous Process Graph

Check:

- `suspicious` vs `full graph` mode
- host/evidence filters
- `warnings_summary`
- `process_tree_report.json`

If there are many ambiguities, the app must summarize them, not flood the canvas.

## Slow frontend build or chunk warning

The app uses lazy loading by main routes to reduce the initial bundle.

Check:

- `npm run build`
- that `Search`, `Timeline`, `Process Graph`, `Reports`, `Rules`, `Detections`, `Docs` and the rest of the workspaces come out as separate chunks
- that you're not serving an old frontend after the rebuild

If a large chunk warning reappears:

- check for heavy imports added to `App.tsx`
- avoid importing report, markdown or graph helpers outside their route
- check `vite.config.ts` and the `manualChunks`

## Validation case bootstrap fails

Check:

- backend reachable at `http://127.0.0.1:8000`
- worker active for ingests and rule runs
- the validation file exists outside the repository
- the validation case was created with generic names

If YARA detections are missing but the rest of the validation flow works:

- check `GET /api/rules/engines/status`
- confirm whether `yara-python` is available in the backend image
- treat it as a known non-blocking limitation if Sigma, findings, reports and debug export are healthy

## Rules or Detections do not show the expected result

First check which engine you're using:

- `Sigma`
  - runs over indexed events
- `YARA`
  - runs over preserved files

Common interpretation errors:

- running YARA expecting hits over already-indexed logs
- running Sigma expecting it to inspect binaries, scripts or unindexed documents
- importing a YARA pack from the Sigma section or vice versa

Verify:

- `Rules -> Rule Runs` for status, volume and errors
- `Detections` filtering by `source=sigma` or `source=yara`
- `Search` with:
  - `detection.source:sigma`
  - `detection.source:yara`

If a run stays in `queued` or `running` for too long:

- check the `heartbeat`
- if there is no recent heartbeat, treat it as `stale`
- use `Mark stale runs` or the individual `Mark failed/stale` action
- if you need to repeat it, use `Retry run`
- if the worker never even started it, you can `Cancel run`

If `Open Detections` from a run looks incomplete:

- remember that exact correlation by `rule_run_id` depends on the run's available context
- also check `Rule Runs` and `Search` to validate whether there were `duplicates skipped`

If you need to clean up the rule inventory:

- use `Rule Library`
- filter by `engine`, `namespace`, `status` or text
- try `Disable selected` first if you don't want to delete them yet
- `Delete all imported rules` requires typing `DELETE RULES`
- deleting rules or run records does not remove detections already generated

## `stable_event_id` or reconciliation do not appear in debug export

Check:

- `event_identity_report.json`
- `reconciliation_report.json`
- that the backend indexes `stable_event_id` and `event_fingerprint`
- that `debug_export` is requesting those fields in `_source`

If the runtime is using old containers:

- tests may pass locally but real ingests will still lack `stable_event_id`
- rebuild `backend` and `worker`

## I renamed or merged hosts and the results changed

Expected behavior:

- `Search`, `Timeline` and `Reports` must use the canonical host with alias expansion
- the detail view still shows `Observed as` when the event arrived under a different name
- `stable_event_id` should not depend on a manually renamed canonical name

If something doesn't add up:

- check `event_identity_report.json`
- check `host_identity_report.json`
- confirm that backend and worker have been rebuilt with the current version

## Report with no key events

The report can come out sparse if you don't select:

- relevant findings
- key events
- process chains

## PDF unavailable

This is the expected behavior today. The correct status is `not yet available` / `501`, not a silent error.
