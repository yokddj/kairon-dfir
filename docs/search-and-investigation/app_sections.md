# Application sections

## Dashboard

- **What it's for**: quick view of the overall case/platform status.
- **What it shows**: counters, status, activity summary.
- **What to look at first**: whether there are indexed events, evidence and detections.

## Cases

- **What it's for**: creating, opening and deleting cases.
- **What it shows**: case list and access to case detail.
- **What to look at first**: which case is active and what evidence it has.

## Search

- **What it's for**: global search across normalized events.
- **What it shows**: global table for mixed results, with specific views when the set is homogeneous.
- **What it supports**:
  - textual query
  - IOC
  - contains
  - field filters
  - pagination
- **When to use it**: when you don't yet know which source the lead comes from and want to quickly find text, users, EventIDs, paths, Registry keys, hashes or IPs.
- **What to look at first**: `windows.event_id`, `event.type`, `process.command_line`, `tags`
- **Create findings**: select events and use `Create Finding from selected events`

## Artifact Explorer

- **What it's for**: reviewing a specific source with columns tailored to each evidence type.
- **What it shows**: events filtered by `artifact.type` / `artifact.name`, with views adapted for `evtx`, `prefetch`, `lnk`, `jumplist`, `registry`, etc.
- **When to use it**: when you already know you want to review a specific source rather than a global mix.
- **What to look at**:
  - JSON detail
  - `raw`
  - `windows.payload`
  - `lnk.effective_path`
  - `jumplist.effective_path`
  - `registry.key_path`
  - `registry.value_name`
  - `registry.value_data`
  - `tags`
  - `suspicious_reasons`
- **Create findings**: select events from the current artifact and create a finding linked to the case

## Memory Analysis

- **What it's for**: registering and reviewing the isolated state of authorized RAM/memory evidence.
- **Current status**: Preview (Core DFIR Capability — Preview). The capability itself is enabled by default (`memory_enabled=true`); execution of Volatility 3 profiles remains disabled by default (`MEMORY_ANALYSIS_ENABLED=false`) until an administrator explicitly enables it together with upload, external execution and the `memory-worker`; MemProcFS remains readiness-only.
- **Recommended flow**: `Case -> Memory Analysis -> Add memory image`. The generic Evidence Upload form still works, but the dedicated upload shows capability, privacy, authorization and progress more clearly.
- **What it shows**: case mode (`empty`, `disk_only`, `memory_only`, `hybrid`), `memory_dump` evidence, upload readiness, backend readiness, run metadata/process and isolated results.
- **What it doesn't do yet**: it doesn't add memory to Search, Timeline, Artifact Explorer, Detections, Reports, SIEM, Command History, Persistence or Execution Stories. It does allow creating Findings directly from memory process rows and memory-derived views when row context is available — see `docs/findings-notes.md`.
- **Legal rule**: use only your own RAM evidence, authorized evidence, or lab evidence created for that purpose. Do not upload or commit dumps containing third-party data without authorization.

## Investigation Timeline

- **What it's for**: chronologically ordering what has been indexed.
- **What it shows**: events by timestamp.
- **How to use it**: useful for reconstructing the overall sequence, understanding what happened before/after, and pivoting to specific events.
- **When to use it**: when the main question is temporal rather than about artifact type.
- **Create findings**: select events from the timeline sequence and turn them into an investigable finding

## Semi-automatic analysis

- **What it's for**: grouping already-normalized activity into categories useful for DFIR.
- **What it shows**: programs, PowerShell, logons, RDP, tasks, services, network, Defender, suspicious findings, opened files, recent documents, applications used, opened scripts, network/USB paths and timeline.
- **Currently strong sources**: EVTX via `EvtxECmd_Output.csv`, Prefetch via `PECmd_Output.csv`, LNK via `LECmd_Output.csv` and Jump Lists via `JLECmd_Output.csv`.
- **What to look at first**: summary, PowerShell, logons, persistence, Defender and, if investigating user interaction, `Opened Files`, `Recent Documents`, `Applications Used` and `Opened Scripts`.

## Activity

- **What it's for**: internal platform activity.
- **What it shows**: ingestion jobs, imports, rule runs, errors and operational events.
- **What to look at first**: whether a piece of evidence fails to parse or a rule produces no results.

## SIEM

- **What it's for**: advanced analysis and bridge to OpenSearch Dashboards.
- **What it shows**:
  - OpenSearch Dashboards status
  - Query Builder
  - Field Explorer
  - Saved SIEM Queries
- **What to look at first**: whether you need to pivot by field or open the case in Dashboards.
- **When to use it**: when `Search` is no longer enough and you need precise technical queries by field, DSL or advanced exploration in OpenSearch Dashboards.

## Rules

- **What it's for**: managing rules and rule packs.
- **What it shows**:
  - individual rules
  - rule packs
  - rule runs
- **What to look at first**: engine, enabled, latest runs and errors.

## Detections

- **What it's for**: reviewing automatic signals.
- **What it shows**: builtin, sigma, heuristic and yara detections.
- **What to look at first**:
  - engine
  - severity
  - source
  - target_type
  - reason
- **Create findings**:
  - `Create finding` to open an edit box from a detection
  - `Create finding from selected detections` for several detections from the same case
  - `Promote to finding` for quick promotion

## Findings

- **What it's for**: consolidating investigable or confirmed findings.
- **How it differs from Detections**:
  - `Detection` = automatic signal
  - `Finding` = item already promoted or confirmed by the analyst
- **How they're created today**:
  - manually from the section itself
  - from events selected in `Search`, `Artifact Explorer` and `Investigation Timeline`
  - from `Detections`

## Docs

- **What it's for**: usage and maintenance manual for the tool.
- **What to look at first**:
  - `Getting Started`
  - `EVTX`
  - `Semi-automatic analysis`
  - `Troubleshooting`

## System

- **What it's for**: resource status and runtime/deploy settings.
- **What to look at first**:
  - CPU/RAM/OpenSearch
  - workers
  - queues
  - `AUTO_CREATE_HEURISTIC_DETECTIONS`
