# Parser Coverage Matrix

Kairon supports a growing set of Windows, Linux, and memory artifacts. This page describes exact parser coverage. It is not a promise of complete forensic coverage. This is the canonical reference for parser/artifact status — other documents should link here rather than maintaining their own copy.

The structured source of truth is [`docs/data/parser-coverage.json`](../data/parser-coverage.json). Evidence upload also records platform selection; see [Evidence Platform Selection](../evidence/evidence-platforms.md).

## Status Meanings

| Status | Meaning |
| --- | --- |
| `stable` | Recognized and ingested in normal workflows or explicit supported actions. |
| `partial` | A parser or normalization path exists, but coverage is scoped, source-dependent, or not complete. |
| `experimental` | Works for specific cases and may change. Treat output as analyst-assistive. |
| `planned` | Documented intent, not implemented. |
| `unsupported` | Do not expect parsed results. Detection, if any, is only a placeholder or inventory signal. |
| `deprecated` | Avoid using; kept only for historical reference. |

## General Matrix

| Family | Status | Input formats | Source tools | Main views | Key limitations |
| --- | --- | --- | --- | --- | --- |
| Windows Event Logs / EVTX | stable | EVTX, CSV, JSON, JSONL | EvtxECmd, Velociraptor, KAPE | Artifact Explorer, Search, Timeline, Detections, Command History, Process Graph | Field richness depends on event payload and audit policy. |
| $MFT / MFTECmd | stable | CSV, JSON, JSONL, raw $MFT inventory | MFTECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Full indexing is explicit because volume can be high. |
| USN Journal | partial | CSV, JSON, JSONL | MFTECmd parsed output | Artifact Explorer, Search, Timeline | No active raw UsnJrnl2Csv backend. |
| Prefetch | stable | PF, CSV | native raw parser, PECmd CSV | Artifact Explorer, Search, Timeline | Prefetch has no parent process or command line; raw PECmd rebuild is disabled on Linux (Windows decompression dependency). |
| Registry / RECmd | partial | CSV, raw hives | RECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Not every registry key has a semantic parser. |
| LNK | stable | LNK, CSV | native raw parser, LECmd | Artifact Explorer, Search, Timeline | LNK interaction is not guaranteed execution. |
| Jump Lists | stable | automaticDestinations, customDestinations, CSV | native raw parser, JLECmd | Artifact Explorer, Search, Timeline | Recent-item activity is not direct execution proof. |
| Amcache | stable | Amcache.hve, CSV | native raw parser, AmcacheParser | Artifact Explorer, Search, Timeline | Inventory/presence context, not proof of execution. |
| Shimcache / AppCompat | stable | CSV, registry-derived rows | AppCompatCacheParser, ShimCacheParser | Artifact Explorer, Search, Timeline | Execution semantics are cautious and OS-dependent. |
| Scheduled Tasks | stable | XML, CSV, JSON, JSONL | Task Scheduler XML, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Detections | Presence requires context. |
| Services | stable | CSV, registry-derived rows | Velociraptor, RECmd, KAPE | Artifact Explorer, Search, Timeline, Detections | Not every service is malicious. |
| Autoruns / ASEP | partial | CSV, TSV, XML, JSON, JSONL | Sysinternals Autoruns, KAPE | Artifact Explorer, Search, Timeline, Detections | Some ASEP sources are inventory-only. |
| Defender | stable | EVTX, CSV, JSON, JSONL, LOG, DetectionHistory | Defender logs, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Detections | No-data is common and is not parser failure. |
| PowerShell | stable | EVTX, CSV, JSON, JSONL, TXT, PS1 | EvtxECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Command History, Process Graph | PSReadLine often lacks reliable forensic timestamp. |
| Browser | stable | SQLite, CSV, JSON, JSONL | native SQLite parser, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Credential and cookie stores are intentionally not parsed. |
| Recycle Bin | stable | $I raw, CSV, JSON, JSONL | native $I parser, RBCmd | Artifact Explorer, Search, Timeline | $I/$R pairing depends on available files. |
| USB | partial | SetupAPI log, CSV, JSON, JSONL, TXT, registry rows | KAPE, Velociraptor | Artifact Explorer, Search, Timeline | USB presence does not prove exfiltration. |
| BITS | partial | CSV, JSON, JSONL, TXT, qmgr inventory | bitsadmin output, KAPE | Artifact Explorer, Search, Timeline, Detections | Raw qmgr support may be inventory-only. |
| Network / DNS / WLAN | partial | CSV, JSON, JSONL, TXT, XML, hosts file | Velociraptor, netsh, ipconfig | Artifact Explorer, Search, Timeline | Many outputs are configuration/context, not events. |
| Cloud Sync | partial | CSV, JSON, JSONL, LOG, TXT, INI | KAPE, Velociraptor, manual collections | Artifact Explorer, Search, Timeline | Does not prove exfiltration by itself. |
| WMI | partial | CSV, JSON, JSONL, EVTX, registry rows | Autoruns, Velociraptor, KAPE | Artifact Explorer, Search, Timeline, Detections | Raw WMI repository parsing is incomplete. |
| Shellbags | partial | CSV | SBECmd output | Artifact Explorer, Search, Timeline | SBECmd CSV is parsed and indexed; direct raw `NTUSER.DAT`/`UsrClass.dat` hive decoding is not implemented. |
| SRUM | partial | CSV, JSON, JSONL, SRUDB inventory | SrumECmd parsed output | Artifact Explorer, Search, Timeline | SrumECmd cannot run in current Linux deployment (requires Windows ESE libraries). |
| Email | experimental | EML, MBOX, PST/OST inventory | manual collections, KAPE, Velociraptor | Artifact Explorer, Search | PST/OST support is inventory-oriented. |
| Windows UI local DBs | partial | CSV, raw DB inventory | manual collections, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Many raw DB files are preserved but not fully parsed. |
| Memory | experimental | RAW, DMP, VMEM, LIME, AFF4 | Volatility 3 optional external backend | Memory views, Process Graph | Isolated from global Search/Timeline/Detections. See Memory Analysis Backends below. |
| PCAP / network captures | experimental | PCAP, PCAPNG, Zeek-style outputs | manual collections, Zeek outputs | Artifact Explorer, Search | Not complete PCAP forensic coverage. |
| Sigma/YARA rule files | stable | YAML, YML, YAR, YARA | manual rule upload | Detections, Rules | Rule files are detection content, not evidence artifacts. |

## Backend Modules and Common Source Filenames

Quick reference for locating the parser code and recognizing typical input filenames for each family. Forensic interpretation (what each family contributes to an investigation, and how it correlates with others) lives in each family's own document under [`docs/artifacts/`](.).

| Family | Common source filenames | Backend module |
| --- | --- | --- |
| EVTX | `*_EvtxECmd_Output.csv` | `backend/app/ingest/eztools/evtxecmd.py` |
| Prefetch | `*_PECmd_Output.csv`, raw `*.pf` | `backend/app/ingest/eztools/pecmd.py`, `backend/app/ingest/raw_parsers/prefetch_parser.py` |
| LNK | `*_LECmd_Output.csv`, raw `*.lnk` | `backend/app/ingest/eztools/lecmd.py`, `backend/app/ingest/raw_parsers/lnk_parser.py` |
| Jump Lists | `*_JLECmd_Output.csv`, raw `automaticDestinations`/`customDestinations` | `backend/app/ingest/jumplists/*` |
| Registry | `*_RECmd_Output.csv`, RECmd Batch outputs | `backend/app/ingest/eztools/recmd.py` |
| MFT | `*_MFTECmd_Output.csv` | `backend/app/ingest/eztools/mftecmd.py` |
| USN Journal | CSVs of `$J`/`UsnJrnl` parsed by MFTECmd | `backend/app/ingest/eztools/mftecmd.py` |
| SRUM | `*_SrumECmd_Output.csv`, `*NetworkUsage*.csv`, `*ApplicationResourceUsage*.csv` | `backend/app/ingest/eztools/srumecmd.py` |
| Scheduled Tasks | raw Task Scheduler XML, `*ScheduledTasks*.csv`, `*TaskScheduler*.csv` | `backend/app/ingest/scheduled_tasks/*` |
| Defender | `DetectionHistory`, `MPLog*.log`, `*Defender*.csv/json` | `backend/app/ingest/defender/*` |
| PowerShell (non-EVTX) | `ConsoleHost_history.txt`, `PowerShell_transcript*.txt`, `*.ps1` | `backend/app/ingest/powershell/*` |
| Recycle Bin | `*_RBCmd_Output.csv`, raw `$I`/`$R` | `backend/app/ingest/recycle_bin/*` |
| Browser | parsed CSV/JSON, raw `History`/`places.sqlite` | `backend/app/ingest/browser/*` |
| Amcache | `*Amcache*.csv`, `AmcacheParser_Output.csv` | normalizer: `normalize_amcache_row` |
| Shimcache / AppCompat | `*ShimCache*.csv`, `*AppCompatCache*.csv`, `*RecentFileCache*.csv` | normalizer: `normalize_shimcache_row` |
| Shellbags | `*_SBECmd_Output.csv`, raw hives from Velociraptor | `backend/app/ingest/shellbags/*` |
| USB | `setupapi.dev.log`, `*USB*.csv`, `*USBSTOR*.csv`, `*MountedDevices*.csv` | `backend/app/ingest/usb/*` |
| BITS | `*BITS*.csv/json`, `*bitsadmin*.txt`, `qmgr*.dat`, `qmgr.db` | `backend/app/ingest/bits/*` |
| WMI | `*WMI*.csv/json`, `OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`, WMI-Activity EVTX/CSV | `backend/app/ingest/wmi/*` |
| Autoruns / ASEP | `Autoruns.csv/tsv/xml`, startup folder files, hive/Task XML/WMI raw candidates | `backend/app/ingest/autoruns/*` |
| Cloud Sync | OneDrive/Dropbox/Google Drive/DriveFS/MEGAsync/iCloud/Box paths, `*Cloud*.csv/json` | `backend/app/ingest/cloud_sync/*` |
| Network / WLAN / DNS | WLAN profile XML, `hosts`, `*DNS*.csv/json`, `*netstat*.txt`, `*arp*.txt` | `backend/app/ingest/network/*` |

## Format Matrix

| Format | Typical supported families |
| --- | --- |
| EVTX | Windows Event Logs, Defender, PowerShell, WMI Activity, USB/PNP when exported as event rows. |
| CSV / JSON / JSONL | Most parsed Windows artifacts when columns match known collectors or Kairon detectors. |
| SQLite | Browser history/downloads for Chromium and Firefox style stores. |
| XML | Scheduled Tasks and WLAN profiles. |
| Raw registry hives | Scoped user activity and selected registry-derived families only. |
| RAW / DMP / VMEM / LIME / AFF4 | Memory workflow only. |
| PCAP / PCAPNG | Experimental network-capture handling only. |

## Linux Artifact Support

Linux artifacts are supported with partial parser coverage. Evidence from Linux triage collections is ingested and searchable across 12 artifact families. See [Linux Support](../linux/linux-support.md) for detailed per-family documentation and collection layout.

## Collector Compatibility

Kairon documents compatible outputs, but does not redistribute third-party collector binaries. Users are responsible for obtaining and using third-party tools according to their licenses.

| Collector / Tool | Compatibility notes |
| --- | --- |
| KAPE | Good source for EZ Tools CSV output and common Windows artifacts. Coverage depends on selected targets/modules. |
| Velociraptor | Supported for ZIP discovery, selected artifact outputs, browser SQLite and several Windows triage outputs. |
| Eric Zimmerman tools | EvtxECmd, MFTECmd and RECmd are primary supported parsed-output paths. LECmd, JLECmd, AmcacheParser and AppCompatCacheParser are advanced or compatible-output paths. SrumECmd and SBECmd have limitations in the current deployment. |
| Hayabusa | Detection-style output may be recognized as EVTX/detection context when exported to compatible structured rows. It is not a replacement for raw EVTX parsing. |
| Chainsaw | Not documented as a stable parser family. Compatible outputs may be searchable if exported as generic CSV/JSON with recognizable fields, but no first-class support is claimed. |
| SIFT | Kairon does not integrate SIFT as a collector. Files exported from SIFT workflows may be ingested if they match supported formats. |
| Manual ZIP collections | Supported when files match recognized filenames, extensions or headers. Unsupported files are preserved/detected but may not generate artifacts. |

## Memory Analysis Backends

These backends are external, optional, not bundled, and not installed by Kairon. Do not add memory dumps, third-party memory-forensics outputs, symbol packs, malware samples, credentials, Volatility plugins, or MemProcFS binaries to the repository.

| Backend | Distribution | Readiness detection | Evidence execution |
| --- | --- | --- | --- |
| Volatility 3 | external optional tool, not bundled | supported through configured executable detection and harmless help/version check | metadata and process profiles supported conditionally for a fixed set of read-only plugins (see [Memory Analysis](../memory/memory_analysis.md) for the current list) |
| MemProcFS | external optional tool, not bundled | supported through configured executable detection and harmless help/version check | not implemented |

Readiness detection does not supply a memory-image path, run plugins, mount devices, create artifacts, create MemoryScanRun rows, or write OpenSearch documents.

Volatility 3 execution is disabled by default and controlled by administrator configuration. Kairon builds a fixed `shell=False` argv from named profiles and never accepts plugin names or command arguments from API/UI requests. It writes normalized metadata, memory process, and memory process edge documents only to the isolated `dfir-memory-{case_id}` index.

An optional `memory-worker` Compose profile can be built by the operator to install pinned Volatility 3 from official PyPI inside an isolated worker image. Kairon does not commit or publish Volatility source, wheels, binaries, symbol packs, plugins, or prebuilt memory-worker images.

## Advanced Backend Search Behavior

Advanced EZ Tool rebuilds (LECmd, JLECmd, AmcacheParser, AppCompatCacheParser) do not replace default artifact results automatically. Search keeps default/internal results unless the analyst selects an advanced backend filter such as:

- `backend_variant=advanced`
- `backend_variant=all`
- `parser_backend=amcacheparser_csv`

This avoids duplicate-looking results in normal Search while preserving the richer advanced output for comparison. Advanced docs are hidden from default Search unless one of these filters is selected.

## Evidence and Processing Status

Optional parser failure, `tooling_missing` conditions, unsupported artifacts, or no-data results should not mark an evidence item failed when other searchable data exists. Kairon uses, instead of a blanket `failed`:

- `completed_with_warnings`
- `investigation_ready=true`
- parser-specific status metadata

When interpreting Processing Queue results:

- `parser failed`: a parser was applicable but recorded an error. Review Processing details and parser error text.
- `parser not applicable`: the evidence did not contain a recognized artifact for that parser family.
- `unsupported format`: Kairon may preserve or inventory the file, but no parsed results should be expected.
- `no artifacts found`: the parser or source can be valid but legitimately empty — this is not failure.
- `partial support`: some fields/views are available, but full forensic semantics are not guaranteed.

## Not Supported Yet

- macOS artifact support is not implemented.
- Virtual Disk Upload is not implemented.
- Raw Shellbags hive parsing is not stable.
- Raw SRUDB.dat parsing is not stable in the current Linux deployment.
- Full PCAP forensics is not claimed.
- Browser credential/cookie stores are intentionally not parsed.
