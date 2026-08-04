# Evidence Ingestion

## What Happens When You Upload a File or Folder

1. The evidence is saved to disk.
2. If it's ZIP/7z, it's extracted.
3. The structure is walked and artifacts are detected.
4. Each artifact is classified by type and parser.
5. The normalizer generates common events.
6. The events are indexed in OpenSearch.
7. The evidence manifest and platform activity are updated.

## How the Evidence Type Is Detected

Detection combines:

- file name
- path
- CSV/JSON headers
- known Velociraptor and KAPE/EZ Tools conventions

## Parsers That Exist Today

### Specific Parsers

- `eztools/evtxecmd.py` -> `EvtxECmd_Output.csv`
- `eztools/pecmd.py` -> `PECmd_Output.csv`
- `eztools/lecmd.py` -> `LECmd_Output.csv`
- `eztools/jlecmd.py` -> `JLECmd_Output.csv`
- `eztools/recmd.py` -> `RECmd_Output.csv` and compatible RECmd Batch CSVs

### Generic or Partial Normalizers

Partial routes currently exist for parsed artifacts such as:

- mft
- srum
- recycle bin
- browser
- generic network/process

### Parsers Prepared for the Future

- `raw/evtx.py`
- EZ Tools skeletons:
  - `mftecmd.py`

## What Gets Indexed and What Gets Preserved

### Indexed

- normalized fields
- `event.category`
- `event.type`
- `event.message`
- `windows.event_id`
- `process.*`
- `file.*`
- `network.*`
- `service.*`
- `task.*`
- `tags`
- `suspicious_reasons`
- `search_text`

### Preserved Without Dynamic Indexing

- `raw`
- `windows.event_data`
- `windows.payload`
- raw XML if available

## Current Primary Source: EvtxECmd_Output.csv

`EvtxECmd_Output.csv` is today the primary source of Windows events.

### What the Parser Does

- detects the CSV by name and headers
- parses rows robustly
- extracts the `Payload` JSON
- preserves `PayloadData*`
- validates `Provider/Channel`
- normalizes relevant fields
- generates useful messages and tags

### Important Rules

- `4625` is **only** `logon_failed` if it comes from:
  - `Channel = Security`
  - `Provider = Microsoft-Windows-Security-Auditing`
- `1102` is interpreted as `audit_log_cleared` if it comes from:
  - `Channel = Security`
  - `Provider = Microsoft-Windows-Eventlog` or `Eventlog`

## Current Execution Source: PECmd_Output.csv

`PECmd_Output.csv` already has a specific parser for Prefetch.

### What the Parser Does

- detects the CSV by name and headers
- extracts `ExecutableName`, `RunCount`, `LastRun`, and `PreviousRun*`
- preserves the full row in `raw`
- normalizes `prefetch.*` and `execution.*`
- attempts to infer the referenced binary and paths
- flags LOLBins and suspicious paths
- leaves a post-ingest audit trail per artifact

### What It Feeds

- `Search`
- `Artifact Explorer`
- `Timeline`
- `Semi-automatic Analysis > Executed Programs`
- `Semi-automatic Analysis > PowerShell` when the executable is `powershell.exe` or `pwsh.exe`

## Current Registry Source: RECmd_Output.csv

`RECmd_Output.csv` and compatible RECmd Batch CSVs already have a specific parser.

### What the Parser Does

- detects the CSV by name and headers
- classifies priority subtypes
- preserves `raw`
- normalizes `registry.*`, `process.*`, `service.*`, `usb.*`, `volume.*`, and `shellbag.*`
- flags persistence, LOLBins, suspicious paths, and user activity
- leaves a post-ingest audit trail per artifact

### Supported Subtypes

- Run Keys / RunOnce
- Services
- UserAssist
- BAM / DAM
- MUICache
- USBSTOR / USB devices
- MountedDevices
- TypedPaths
- RunMRU
- RecentDocs
- RDP MRU
- Shellbags
- Registry generic

## Typical Ingestion Errors

### 1. OpenSearch Total Fields Limit

Usually indicates an old index or an incorrect mapping.

What to check:

- `dynamic` must be `false`
- `raw`, `windows.event_data`, `windows.payload` must have `enabled: false`

### 2. Old Index with Stale Mapping

If you changed normalized fields and the case still uses an old index, inconsistencies can occur.

What to do:

- recreate the case
- reimport the evidence

### 3. CSV Not Detected as EvtxECmd

What to check:

- the file name
- typical headers
- the evidence's activity and manifest

### 4. Events Don't Appear Due to a Bulk Indexing Failure

What to check:

- `Activity`
- worker/backend errors
- the artifact's post-ingest audit trail
