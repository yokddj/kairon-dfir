# Parser Backends

This page records which parser backends are active in the current platform state.

| Backend | Status | Runs on current Linux deployment | Default use | Notes |
| --- | --- | --- | --- | --- |
| EvtxECmd | stable | yes | EVTX default | Used for broad Windows Event Log coverage, including Sysmon, Security, PowerShell and Defender channel rows. |
| MFTECmd | stable | yes | MFT summary/full actions | Raw `$MFT` can be detected and parsed through MFTECmd CSV output. Full indexing is explicit because volume can be large. |
| RECmd | stable partial | yes | scoped user activity extraction | Used for selected NTUSER.DAT/UsrClass.dat activity families: UserAssist, RecentDocs, RunMRU and OpenSaveMRU where data exists. Shellbags remain a separate follow-up. |
| Defender EVTX parser | stable | yes | Defender artifact normalization | Reuses Defender EVTX rows and normalizes threat/action/configuration fields where present. No-data is not parser failure. |
| PECmd | unavailable for raw Prefetch on Linux | partially | disabled for raw `.pf` rebuild | Tool exists, but raw Prefetch parsing requires Windows decompression support in this environment. Internal Prefetch parser remains active. |
| LECmd | advanced | yes | advanced rebuild only | Available for scoped LNK rebuild/compare. Not default because HOSTA coverage was lower than internal. |
| JLECmd | advanced | yes | advanced rebuild only | Available for scoped Jumplist rebuild/compare. Not default because HOSTA coverage was lower than internal. |
| AmcacheParser | advanced | yes | advanced rebuild only | Produces richer fields; advanced docs are separate from default Search unless selected. |
| AppCompatCacheParser | advanced | yes | advanced rebuild only | Produces richer Shimcache/AppCompatCache fields; interpretation remains cautious. |
| SrumECmd | tooling_missing | no | not available | Installed tool requires Windows ESE libraries. SRUM is detected but needs a Windows parser worker. |
| SBECmd / ShellBagsExplorer | planned | not active | none | Shellbags are pending a dedicated backend decision. |
| UsnJrnl2Csv | tooling_missing | no active backend | none | USN Journal support should not be claimed as stable unless a parsed compatible source exists. |

## Backend status meanings

- `stable`: used in the normal ingest or explicit supported action.
- `advanced`: available only behind an explicit rebuild/compare action or advanced filter.
- `tooling_missing`: source can be detected but parser cannot run in this deployment.
- `planned`: not implemented yet.

Memory backends remain external and optional. Do not add memory dumps, third-party memory-forensics outputs, symbol packs, malware samples, credentials, Volatility plugins, or MemProcFS binaries to the repository.

## Memory Analysis Backends

These backends are external, optional, not bundled, and not installed by Kairon.

| Backend | Distribution | Readiness detection | Evidence execution |
| --- | --- | --- | --- |
| Volatility 3 | external optional tool, not bundled | supported through configured executable detection and harmless help/version check | metadata and process profiles supported conditionally for `windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan`, and `windows.cmdline` only |
| MemProcFS | external optional tool, not bundled | supported through configured executable detection and harmless help/version check | not implemented in this sprint |

Readiness detection does not supply a memory-image path, run plugins, mount devices, create artifacts, create MemoryScanRun rows, or write OpenSearch documents.

Volatility 3 execution is disabled by default and controlled by administrator configuration. Kairon builds a fixed `shell=False` argv from named profiles and never accepts plugin names or command arguments from API/UI requests. It writes normalized metadata, memory process, and memory process edge documents only to the isolated `dfir-memory-{case_id}` index.

## Advanced backend search behavior

Advanced EZ Tool rebuilds do not replace default artifact results automatically. Search keeps default/internal results unless the analyst selects an advanced backend filter such as:

- `backend_variant=advanced`
- `backend_variant=all`
- `parser_backend=amcacheparser_csv`

This avoids duplicate-looking results in normal Search while preserving the richer advanced output for comparison.
