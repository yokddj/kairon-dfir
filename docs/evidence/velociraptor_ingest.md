# Velociraptor Ingest

## What a Velociraptor Collection Is

A Velociraptor collection typically contains:

- `uploads/`
- `results/`
- percent-encoded paths such as `C%3A/<Windows-profile>/...`

The app normalizes those paths so it can infer user, browser, profile, and evidence type.

## What Is Currently Supported

Discovery:

- Raw Browser
- Raw EVTX
- Raw Prefetch
- Raw LNK
  - `Recent`, `Office\\Recent`, `Desktop`, `Downloads`, `Start Menu`, and `Startup`
- Registry hives
- Raw MFT/USN
- Raw Jump Lists
- other relevant candidates

Direct parsing implemented in this iteration:

- Chromium `History`
- Firefox `places.sqlite`
- Scheduled Tasks XML from `Windows\\System32\\Tasks\\*`
- Raw Defender from `DetectionHistory` and `MPLog*.log`
- Raw PowerShell from `ConsoleHost_history.txt`, transcripts, and observed scripts
- Raw Recycle Bin from `$Recycle.Bin\\<SID>\\$I*` with `$I/$R` pairing
- Shellbags CSV from `SBECmd` and raw discovery of `NTUSER.DAT` / `UsrClass.dat`
- JumpLists CSV from `JLECmd`, raw parsing of `*.automaticDestinations-ms`, and partial support for `*.customDestinations-ms`
- raw `setupapi.dev.log` for enriched USB activity
- native raw Prefetch from `Windows\\Prefetch\\*.pf`
- raw discovery of `qmgr0.dat`, `qmgr1.dat`, and `qmgr.db` for BITS, plus compatible parsed CSV/JSON/TXT

## Flow

1. Upload a Velociraptor ZIP or folder.
2. Read the container's inventory without fully extracting it.
3. Run discovery over the inventory's names/paths.
4. Review detected evidence.
5. Select Browser, Scheduled Tasks, Defender, PowerShell, Recycle Bin, Shellbags, or other supported categories.
6. Extract only the files needed for the chosen categories.
7. Queue parsing.

## ZIP Inventory and Selective Extraction

The app no longer extracts the entire Velociraptor ZIP up front.

Main phases:

- `indexing_zip`
- `discovering_candidates`
- `waiting_selection`
- `extracting_selected`
- `parsing`
- `indexing_events`

For ZIP files, the internal index (`ZipFile.infolist()`) is used and detection works over that inventory. For already-extracted folders, the local tree is walked and only the files the parser needs are copied to staging.

## What Gets Automatically Ignored

- `__MACOSX/`
- `.DS_Store`
- `._*`
- `Thumbs.db`
- `desktop.ini`
- directories
- irrelevant empty files

These items are logged but are not used in discovery or extracted.

## Selective Browser Extraction

If the user selects only Browser, the app extracts only:

- Chromium `History`
- `History-wal`
- `History-shm`
- Firefox `places.sqlite`
- `places.sqlite-wal`
- `places.sqlite-shm`

Not extracted by default:

- `Cache`
- `Code Cache`
- `GPUCache`
- `Service Worker`
- `IndexedDB`
- `Local Storage`
- `Cookies`
- `Login Data`
- `Web Data`

## Path Normalization

The app conceptually converts:

- `C%3A/<Windows-profile>/...`
- `C:/<Windows-profile>/...`
- `C:\\<Windows-profile>\\...`

into a form useful for investigation:

- `C:\\Users\\alex\\...`

The original Velociraptor path is also preserved in:

- `velociraptor.original_path`

## Evidence Detected but Not Yet Raw-Parsed

Shown as `detected_not_implemented`:

- raw Registry hives
- raw MFT/USN
- raw Shellbags hives (`NTUSER.DAT`, `UsrClass.dat`) when there is no raw hive parser
- raw JumpList `customDestinations-ms` when a specific entry cannot be resolved beyond partial support

For those sources, in some cases it can still be preferable to use CSV outputs already parsed by EZ/KAPE when they exist, especially for `customDestinations-ms`.

## Troubleshooting

- `C%3A` in paths:
  the collection uses percent-encoding; the app normalizes it.
- `The extracting phase takes a long time`:
  in the new flow, if you only selected Browser the whole collection should not be extracted. Check `selected_files_total` and `selected_files_extracted` on the evidence.
- `The ZIP contains __MACOSX`:
  those items are ignored automatically and should not appear as candidates.
- `No Browser candidates appear`:
  check that the collection contains `History` or `places.sqlite` at compatible paths.
- `I only want to parse Browser`:
  select only Browser; the app will extract only the SQLite files and their associated WAL/SHM files.
- `I want to investigate USB`:
  select USB; the app will extract `setupapi.dev.log` and compatible USB CSVs, not the whole collection.
- `I want to investigate BITS`:
  select BITS; the app will extract compatible CSV/JSON/TXT and, if present, preserve `qmgr*.dat` / `qmgr.db` without extracting the whole collection.
- `The collection is already extracted`:
  the app does not duplicate the whole folder; it walks the paths and only copies to staging the files the parser requires.
- SQLite without WAL/SHM:
  recent activity may be missing.
- Corrupt SQLite:
  warnings are logged and it should not break the whole collection.
- Empty NirSoft CSV:
  parsing directly from Velociraptor may be a better option for the browser.
- Hindsight/XLSX:
  may be less convenient for the platform than parsing raw SQLite directly.

## WMI Repository Raw

Velociraptor discovery currently detects:

- `OBJECTS.DATA`
- `INDEX.BTR`
- `MAPPING*.MAP`
- `Microsoft-Windows-WMI-Activity%4Operational.evtx`

Current status:

- parsed WMI CSV/JSON: `ready`
- `WMI Activity` EVTX: `handled_by_evtx_parser`
- raw WMI repository: `detected_not_implemented`

This means the raw repository is preserved and appears in the UI, but must not be shown as falsely parsed until a real binary parser exists.

## Autoruns / ASEP in Velociraptor

- Discovery detects parsed `Autoruns/Autorunsc` outputs, startup folder files, candidate ASEP hives, Task XML, and the related raw WMI repository.

## Cloud Sync in Velociraptor

- Discovery detects sync roots for OneDrive, Google Drive / DriveFS, Dropbox, MEGAsync, iCloud, and Box.
- It also detects small configs/logs and parsed `Cloud*.csv/json` outputs when they exist.
- Full cloud folders remain `discovery_only` or `path_inference`: they are not extracted in bulk by default.
- If only cloud paths are observed, the app treats it as evidence of usage or potential staging, not as confirmed upload.

## Network / WLAN / DNS in Velociraptor

- Discovery detects `WLAN` profile XML under `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml`.
- Detects `hosts` under `Windows/System32/drivers/etc/hosts`.
- Detects network CSV/JSON/TXT such as `DNSCache`, `ipconfig`, `netsh`, `netstat`, `arp`, `NetAdapter`, `NetIPConfiguration`, and similar.
- `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx` is classified as `handled_by_evtx_parser`.
- Raw `SOFTWARE`, `SYSTEM`, and `NTUSER.DAT` hives related to `NetworkList` / `Tcpip` are preserved as candidates and must not be shown as parsed when no raw parser exists.

Raw Velociraptor discovery can route EVTX and LNK files to Kairon DFIR's native parsers without needing EvtxECmd or LECmd first.
