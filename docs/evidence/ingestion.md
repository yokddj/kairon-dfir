# Evidence Ingestion

## What Happens When You Upload a File or Folder

1. The evidence is saved to disk.
2. If it's ZIP/7z, it's extracted. An AD1 logical image is repacked into a ZIP first
   (see [AD1 logical images](#ad1-logical-images)).
3. The structure is walked and artifacts are detected.
4. Each artifact is classified by type and parser.
5. The normalizer generates common events.
6. The events are indexed in OpenSearch.
7. The evidence manifest and platform activity are updated.

## AD1 Logical Images

An `.ad1` from FTK Imager (a folder or custom-content image) holds files, not a
filesystem, so it is handled as a collection, not as a disk image:

- Preflight lists its files in place with `dissect.evidence`.
- At registration the live files are repacked into a ZIP in `original/`;
  discovery, selected extraction and the raw hive, SRUM and `$MFT` steps read that
  ZIP like any uploaded collection. The `.ad1` is moved to `source/`: it keeps the
  evidence hash and is what the integrity check verifies.
- A ZIP whose only file is an `.ad1` (how training and CTF images are usually
  shipped) is unwrapped and handled the same way.
- Paths are rebased on the source volume: FTK names the image after where it was
  taken (`C:\NONAME [NTFS]\[root]\Users\alice`); the partition label and `[root]`
  are dropped, so files read `C/Users/alice/NTUSER.DAT`.
- Deleted entries (no reliable content) and reparse points are skipped. FTK stores
  an empty `$I30` index twin next to some files; the copy with content is kept.
  Files whose content cannot be decompressed are listed in
  `metadata_json.ad1_image.failed`.
- **Browse files** on the evidence shows the image's tree with the times, hashes,
  owner and attributes FTK recorded (see
  [disk-image-ingestion.md](disk-image-ingestion.md#collections)).
- **Multi-segment images** (`.ad1` + `.ad2` + `.ad3`...) are supported: selecting
  every segment stages them together (the same mechanism multi-segment EWF/RAW
  disk images use), and all of them are passed to the AD1 reader in order. An
  incomplete segment set is rejected with how many segments the image actually
  has and how many were uploaded.
- **ADCRYPT-encrypted images** (the password FTK Imager asks for when creating an
  encrypted custom-content image) are supported with a passphrase; a private
  key/certificate is not. Preflight detects an encrypted image from its header
  (no password needed) and the wizard asks for the password before processing
  starts, the same way it does for a password-protected archive.

## Password-Protected Archives and AD1 Images

Preflight detects a password-protected ZIP, 7z or RAR (reading the central
directory/listing, no password needed) or an ADCRYPT-encrypted AD1 (from its
header), and the wizard asks for the password before processing starts. With it:

- ZIP and 7z are decrypted with 7-Zip (ZipCrypto and AES for ZIP); RAR is
  decrypted with `unar` instead (7-Zip's own RAR reader cannot decompress RAR's
  encrypted data streams). Decrypted once into a plain ZIP in `original/`.
- An ADCRYPT AD1 is unlocked with the password, then repacked into a ZIP the
  same way any AD1 is (see above).

Either way, the encrypted original is moved to `source/` and keeps the evidence
hash. The password is checked before the upload is registered, so a wrong one can
be corrected without uploading again. It is used for that one decryption and is
not stored. An encrypted upload without its password through the API is rejected
(`archive_password_required` / `ad1_password_required`).

`metadata_json.repacked_from` records the uploaded file(s) and each step taken
(`encrypted_zip`, `encrypted_7z`, `encrypted_rar`, `zip_member`, `ad1`).

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
