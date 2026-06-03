# Project Status

## Current status

Kairon DFIR is a Windows-focused, case-centric forensic investigation tool. It supports evidence upload/indexing, host identity, Search, Timeline, Artifact Views, Command History, Execution Story, markings/findings, Sigma detections and Markdown reporting.

For the detailed state map, see [feature_map.md](feature_map.md).

## Stable

- Upload Wizard and evidence indexing.
- Evidence status reconciliation with `investigation_ready` and `completed_with_warnings`.
- Host canonicalization and alias-aware Search.
- Search workspace and Timeline as a Search view.
- Artifact Views.
- EVTX with EvtxECmd.
- Sysmon rich fields.
- Security 4688/4663 normalization.
- MFT summary/full indexing with MFTECmd.
- Defender artifact parser from Defender EVTX.
- RECmd selected User Activity: UserAssist, RecentDocs, RunMRU and OpenSaveMRU where data exists.
- Command History.
- Execution Story with exact source-event pivots.
- Event markings and findings.
- Reports with Command History, Execution Story and Defender sections.
- Sigma rules, coverage and detections triage.

## Advanced

- MFT full indexing.
- YARA scoped scans.
- EZ Tool advanced rebuilds for LNK, Jumplist, Amcache and Shimcache.
- Advanced backend filters in Search.

## Tooling missing / planned

- SRUM: `SRUDB.dat` can be detected, but `SrumECmd` requires Windows ESE libraries. Needs Windows parser worker.
- Shellbags: raw hive candidates can be detected, but Shellbags parsing is pending.
- PECmd raw Prefetch: disabled on Linux due Windows decompression dependency; internal Prefetch remains active.
- Windows worker: planned for Windows-only parser backends.

## Known limitations

- Markdown is the validated report export. PDF should not be documented as stable unless separately validated.
- MFT full is high-volume; Timeline excludes MFT by default.
- Advanced EZ backend docs are hidden from default Search to avoid duplicates.
- Detections and findings require analyst validation.
- Some parser families remain partial or discovery-only.

