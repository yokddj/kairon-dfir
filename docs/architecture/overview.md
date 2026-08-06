# Architecture

## Summary

Kairon DFIR is split into three planes:

1. **Frontend** for the analyst workflow.
2. **Backend** for cases, evidence, events, rules, and analysis.
3. **OpenSearch + PostgreSQL + filesystem** for search, metadata, and storage.

The current pipeline already has specialized routes for:

- EVTX
- Prefetch
- LNK / Jump Lists
- Registry
- MFT / USN
- Browser
- Amcache / ShimCache / AppCompat
- SRUM
- Scheduled Tasks
- PowerShell artifacts outside EVTX
- Recycle Bin
- Enriched USB

All of these converge on `NormalizedEvent`, which then feeds Search, Artifact Explorer, Timeline, detections, and semi-automatic analysis.

## Frontend

### Current Stack

- React 18
- TypeScript
- Vite
- TailwindCSS
- React Query
- React Router

### Main Pages

- `Dashboard`
- `Cases`
- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Semi-automatic Analysis`
- `Activity`
- `SIEM`
- `Rules`
- `Detections`
- `Findings`
- `Docs`
- `System`

### Routing and Navigation

The frontend uses React routes and a single `Sidebar` as the main navigation point. The `Docs` section lives at `/docs`.

## Backend

### Current Stack

- FastAPI
- SQLAlchemy
- PostgreSQL
- Redis + RQ
- OpenSearch

### Main Modules

- `backend/app/api/`
  - REST routes for cases, evidence, search, rules, activity, system, and findings.
- `backend/app/ingest/`
  - Artifact detection, parsers, and normalization.
- `backend/app/analysis/`
  - `ForensicActivity` generation and semi-automatic analysis.
- `backend/app/rules_engine/`
  - Sigma, heuristic, and YARA execution.
- `backend/app/core/`
  - Database, OpenSearch, activity, configuration, and helpers.

### Important API Routes

- Cases:
  - `GET /api/cases`
  - `POST /api/cases`
  - `DELETE /api/cases/{case_id}`
- Evidence:
  - `POST /api/evidences/upload`
  - `POST /api/evidences/upload-folder`
  - `POST /api/evidences/{evidence_id}/reprocess`
- Search:
  - `POST /api/search`
  - `POST /api/search/deep`
- Rules:
  - `GET /api/rules`
  - `POST /api/rules/import-file`
  - `POST /api/rules/import-archive`
  - `POST /api/rules/{rule_id}/run`
- Semi-automatic analysis:
  - `GET /api/cases/{case_id}/analysis/semi-auto`

## Storage

### PostgreSQL

Used for:

- cases
- evidence
- artifacts
- rules
- detections
- findings
- activity
- rule runs

### OpenSearch

Used for:

- normalized events
- global search
- timeline
- field filters
- SIEM Lite
- the basis of semi-automatic analysis

### Filesystem

Used for:

- keeping the original uploaded file
- selective staging of files required by the parser
- storing the evidence manifest and tree

### Velociraptor ZIP Inventory

For Velociraptor ZIP collections, the backend no longer extracts the entire container up front.

The flow is now:

- ZIP inventory
- discovery by inventory paths/names
- category selection
- selective extraction of the required files
- parsing
- indexing

This drastically reduces cost when the analyst only wants to parse a specific category such as Browser.

## Data Flow

```text
Collection / evidence
  -> type detector
  -> specific or generic parser
  -> normalized event
  -> OpenSearch
  -> rules / detections
  -> forensic activities
  -> UI
```

## Conceptual Model

- **Raw evidence**: the original file, preserved.
- **Parsed artifact**: CSV/JSON/JSONL/TXT already processed by another tool.
- **NormalizedEvent**: common indexed document.
- **Detection**: automatic signal or rule match.
- **Finding**: hallmark consolidated by the analyst.
- **ForensicActivity**: grouped activity for semi-automatic analysis.

## Current Key Decisions

### EZ Tools CSV as the Primary Source

The current primary source for Windows is **parsed EZ Tools**, not raw EVTX.

### EVTX via EvtxECmd

`EvtxECmd_Output.csv` is today the main and most robust route for:

- logons
- PowerShell
- services
- tasks
- network
- Defender
- RDP

### PowerShell Outside EVTX

`ConsoleHost_history.txt`, transcripts, and observed scripts already have their own specific parser and also converge on `NormalizedEvent`.

Used for:

- observed interactive commands
- `EncodedCommand`
- `Invoke-WebRequest` / `DownloadString` / `IEX`
- Defender tampering
- persistence via tasks, Run Keys, or services
- correlation with `4104`, `4688`, Prefetch, Browser, MFT, Defender, and SRUM

### Recycle Bin

`RBCmd_Output.csv` and raw `$I/$R` artifacts from Velociraptor already have a specific parser and also converge on `NormalizedEvent`.

Used for:

- reconstructing files sent to the recycle bin
- recovering original path, SID, size, and `deleted_time`
- pairing `$I` and `$R`
- correlating with Browser downloads, `MFT/USN`, Defender, PowerShell, Prefetch, and Scheduled Tasks

### Enriched USB

`setupapi.dev.log` and compatible USB/Registry CSVs already have a specific parser and also converge on `NormalizedEvent`.

Used for:

- observing USB devices and removable volumes
- extracting `vendor`, `product`, `serial`, `device_instance_id`, and volume mappings
- correlating with `LNK`, `JumpLists`, `Shellbags`, `Browser`, `PowerShell`, `MFT/USN`, and `Recycle Bin`

### BITS

BITS is already a specific `NormalizedEvent` family.

Sources supported in this iteration:

- compatible parsed CSV/JSON/TXT
- raw discovery of `qmgr*.dat` and `qmgr.db`
- EVTX BITS handled by the event parser when that route exists

Semantic goal:

- observe background jobs and transfers
- distinguish benign jobs from abuse candidates
- raise confidence when the downloaded file is later executed or detected

### Prefetch via PECmd

`PECmd_Output.csv` already has a specific parser and is used for:

- executed programs
- PowerShell observed via Prefetch
- suspicious findings via LOLBins or paths
- timeline
- basic correlation with EVTX 4688

### LNK via LECmd

`LECmd_Output.csv` already has a specific parser and is used for:

- opened files
- accessed documents
- scripts and executables opened by the user
- UNC paths and network access
- indicators of USB or removable media
- basic correlation with Prefetch and EVTX 4688

### Jump Lists via JLECmd and Raw Velociraptor

`JLECmd_Output.csv` already has a specific parser and is now complemented by raw parsing of `automaticDestinations-ms` and partial support for `customDestinations-ms`:

- recent documents per application
- opened files and scripts
- user interaction via `AppID`
- UNC paths and possible USB
- basic correlation with LNK, Browser, Recycle Bin, Shellbags, Prefetch, and EVTX 4688
- raw `automaticDestinations` parseable from Velociraptor collections
- raw `customDestinations` with partial support and controlled warnings

### Registry via RECmd

`RECmd_Output.csv` and compatible RECmd Batch CSVs already have a specific parser and are used for:

- persistence via Run Keys and Services
- observed execution via UserAssist and BAM/DAM
- presence/usage indicators via MUICache
- USBSTOR and MountedDevices
- TypedPaths, RunMRU, RecentDocs, RDP MRU, and Shellbags
- `SBECmd` as a specific source for `folder_activity`, `network_share_activity`, `usb_folder_activity`, `cloud_folder_activity`, and correlations with LNK/JumpLists/Recycle Bin
- `WMI` as a specific source for `wmi_filter`, `wmi_consumer`, `wmi_binding`, `wmi_persistence_candidate`, `wmi_activity_query`, and correlations with PowerShell, Defender, Prefetch, Amcache, MFT, Browser, and BITS
- basic correlation with EVTX, Prefetch, LNK, and Jump Lists

### Filesystem via MFTECmd

`MFTECmd_Output.csv` and compatible `USN Journal` CSVs already have a specific parser and are used for:

- observing historical files and folders
- deleted candidates via `InUse = false`
- ADS
- creations, deletions, renames, and modifications via USN
- basic detection of possible `$SI/$FN` discrepancies
- basic correlation with EVTX, Prefetch, LNK, Jump Lists, and Registry

### Browser Activity via Parsed CSV/JSON

Compatible outputs from `BrowserHistoryView`, `BrowsingHistoryView`, CSV/JSON exports of `History` / `Downloads`, and similar formats already have a specific parser and are used for:

- browsing history
- downloads
- search terms
- basic correlation: download -> file created -> file opened -> execution

### Execution Artifacts via Parsed CSV

Compatible outputs from `AmcacheParser`, `AppCompatCacheParser`, `ShimCacheParser`, `RecentFileCache`, and some `RECmd Batch` CSVs already have a specific parser and are used for:

- inventory of observed programs
- presence or possible historical execution
- hashes and PE metadata
- correlation with Browser, MFT/USN, Prefetch, EVTX, Registry, and Defender

Interpreted conservatively:

- `Amcache`: observation / inventory, not confirmed execution by default
- `ShimCache` / `AppCompat`: presence or possible execution, not confirmed execution by default

### Velociraptor Collection Discovery

The app already has a specific route for Velociraptor collections:

1. upload ZIP or folder
2. run evidence discovery
3. select supported candidates
4. queue selective parsing

At this stage, the raw parsing implemented directly over Velociraptor is:

- Chromium `History`
- raw XML from `C:\Windows\System32\Tasks\*`
- raw Defender artifacts such as `DetectionHistory` and `MPLog*.log`

### Scheduled Tasks

Raw XML from `C:\Windows\System32\Tasks\*` and compatible Scheduled Tasks CSVs already have a specific parser and are used for:

- observing task definitions
- detecting persistence via enabled tasks with `Exec` or `ComHandler` actions
- extracting `RunAs`, `RunLevel`, triggers, command, arguments, and working directory
- detecting encoded PowerShell, LOLBins, suspicious paths, UNC paths, and `hidden + enabled` tasks
- correlating with EVTX `4698/4702/106/140/200/201/102`, Prefetch, Browser downloads, MFT/USN, Registry, SRUM, and Defender

Interpreted conservatively:

- raw XML or task CSV: **observed definition**
- EVTX TaskScheduler/Security: **observed creation, modification, or execution**
- confidence rises when there is correlation with execution or with downloaded/present files
- raw/log/CSV/JSON Defender follows the same pattern as the rest: specific parser, normalization to `artifact.type = defender`, and later correlation with Browser, MFT/USN, Prefetch, EVTX, Scheduled Tasks, Registry, and SRUM
- Firefox `places.sqlite`
- basic correlation with MFT/USN, LNK, Jump Lists, Prefetch, EVTX, and Defender

### Raw Preserved, Not Dynamically Indexed

Events preserve:

- `raw`
- `windows.event_data`
- `windows.payload`

but these containers are not dynamically expanded in OpenSearch.

### OpenSearch with `dynamic: false`

Used to avoid field explosion when indexing EVTX with variable payloads. The more recent families follow the same pattern:

- `autoruns` adds an `autoruns.*` namespace and a `persistence.*` namespace with explicit `dynamic: false` mapping, plus semi-automatic correlation with Browser, BITS, Defender, Prefetch, WMI, Scheduled Tasks, and Registry.
- `cloud_sync` adds a `cloud.*` namespace with explicit `dynamic: false` mapping, detection via path inference, generic CSV/JSON/log parsing, and semi-automatic correlation with Browser, BITS, PowerShell, MFT, Recycle Bin, Defender, Autoruns, WMI, and USB.
- `network` adds `network.*`, `wlan.*`, and `dns.*` namespaces with explicit `dynamic: false` mapping, parsing of WLAN XML / `hosts` / DNS-network CSV-JSON-TXT, classification of WLAN AutoConfig EVTX and Registry `NetworkList` / `Tcpip`, plus semi-automatic correlation with Browser, BITS, PowerShell, Defender, Cloud Sync, SRUM, and MFT.

In addition to the external pipeline (EvtxECmd/LECmd), there is also a foundation of native raw parsers for direct parsing of EVTX and LNK.
