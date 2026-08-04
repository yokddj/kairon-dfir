# Execution Artifacts: Amcache, ShimCache, and AppCompat

## What each source is

- `Amcache`: inventory of programs, binaries, drivers, and PE metadata observed by Windows.
- `ShimCache` / `AppCompatCache`: compatibility cache that helps reconstruct the presence and possible execution of binaries.
- `RecentFileCache`: historical artifact related to the presence or activity of recent programs/files.

## What they contribute in DFIR

- Visibility into binaries present even if we no longer have the original file.
- Useful metadata:
  - `publisher`
  - `product_name`
  - `version`
  - `compile_time`
  - `hashes`
- Context for cross-referencing:
  - Browser downloads
  - MFT / USN
  - Prefetch
  - EVTX 4688
  - Registry
  - Defender

## Key difference: presence vs possible execution vs confirmed execution

- `Prefetch`: strong execution.
- `EVTX 4688`: strong execution.
- `UserAssist` / `BAM`: execution or use with strong/medium weight.
- `Amcache`: observed program or inventory; may suggest installation or use, but does not confirm execution on its own.
- `ShimCache` / `AppCompatCache`: indicator of presence or possible execution; very useful for chronological order and pivoting, not for asserting execution on its own.
- `RecentFileCache`: indicator of historical presence/use; should not be sold as confirmed execution.

The platform represents this with:

- `execution.source`
- `execution.confidence`
- `execution.is_execution_confirmed`
- `execution.interpretation`

## Extracted fields

### Execution

- `execution.source`
- `execution.confidence`
- `execution.is_execution_confirmed`
- `execution.interpretation`
- `execution.first_seen`
- `execution.last_seen`
- `execution.last_modified`
- `execution.install_date`
- `execution.compile_time`

### File / Process

- `file.path`
- `file.name`
- `file.extension`
- `file.size`
- `file.hash_sha1`
- `file.hash_sha256`
- `file.md5`
- `process.path`
- `process.name`
- `process.publisher`
- `process.product_name`
- `process.product_version`

### Amcache

- `amcache.program_id`
- `amcache.program_name`
- `amcache.program_version`
- `amcache.publisher`
- `amcache.product_name`
- `amcache.product_version`
- `amcache.file_id`
- `amcache.file_name`
- `amcache.file_path`
- `amcache.install_date`
- `amcache.compile_time`
- `amcache.key_path`

### ShimCache / AppCompat

- `shimcache.entry_number`
- `shimcache.position`
- `shimcache.path`
- `shimcache.last_modified_time`
- `shimcache.last_update`
- `shimcache.executed`
- `shimcache.control_set`
- `appcompat.artifact_type`
- `appcompat.path`
- `appcompat.name`
- `appcompat.last_modified`

## How to interpret timestamps

- In `Amcache` the main timestamp usually comes from:
  - `LastModified`
  - `KeyLastWrite`
  - `InstallDate`
  - `CompileTime`
- In `ShimCache` it usually comes from:
  - `LastModifiedTime`
  - `LastUpdate`
  - `LastWriteTime`

Not all times mean "moment of execution."

## How to interpret hashes

- They are normalized and validated if they have a consistent length.
- They are especially useful for cross-referencing with:
  - Defender
  - IOC
  - download evidence or observed files

## Correlation

The app cross-references Amcache/ShimCache/AppCompat with:

- Browser downloads
- MFT / USN
- Prefetch
- EVTX 4688
- Registry Run Keys / Services / BAM / UserAssist
- Defender

This allows raising confidence without overstating the original artifact.

## Limitations

- `Amcache` does not always prove execution.
- `ShimCache` does not always prove execution.
- `RecentFileCache` is an indicator, not a confirmation.
- The order, format, and meaning of certain fields vary between Windows versions and parsers.
- If `path` or `timestamp` is missing, confidence is explicitly lowered.

## Common false positives

- Legitimate installers in `Downloads`.
- Portable software in `AppData`.
- LOLBins used by administrators.
- Authorized remote support tools.
- Internal binaries without complete PE metadata or without a publisher.

## Investigation examples

1. Browser download of `invoice.pdf.exe` -> appears in `Amcache` -> later appears in `Prefetch`.
2. `runme.ps1` observed in `AppData\\Local\\Temp` in `Amcache` and `ShimCache`, but without `4688`: strong indicator of presence, not confirmed execution.
3. `AnyDesk.exe` observed in `ShimCache` and `Browser history`: check whether the tool was authorized and whether there was remote activity.
