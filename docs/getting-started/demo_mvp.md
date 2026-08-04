# DFIR APP MVP Demo Guide

## Purpose

This demo shows the end-to-end analyst workflow in DFIR APP using a fully synthetic dataset:

- case creation
- evidence ingest
- overview and host attribution
- advanced search
- artifact search
- findings and correlation
- timeline and key events
- process graph
- Sigma and YARA detections
- report draft and export
- debug export
- OpenSearch Discover
- evidence intake UX for upload vs mounted paths

All demo data is generic. No real customer or host names are used.

## Quick Start

1. Ensure backend, worker, frontend and OpenSearch are running.
2. Generate the synthetic pack:

```bash
python3 tools/demo/generate_demo_evidence.py
```

3. Optionally bootstrap the full case automatically:

```bash
python3 tools/demo/bootstrap_demo_case.py
```

4. Open the case:

- `Demo - ACME Incident 001`

## Demo Data

- Case: `Demo - ACME Incident 001`
- Host: `TEST-WIN10-01`
- User: `user01`
- Domain: `example.local`
- Demo ZIP: `demo/evidence/acme_incident_001.zip`

The pack contains synthetic evidence families already supported by the platform:

- Security 4688 / PowerShell EVTX-style CSV
- Defender CSV
- Chromium History SQLite with download activity
- synthetic email (`EML`, `MBOX`)
- user activity registry artifacts
- NTFS deep artifacts
- Windows UI / local DB artifacts
- cloud sync CSV
- USB CSV
- recycle bin CSV
- a YARA marker file

## Recommended Route

### A. Overview

Show:

- case health
- completed evidence
- host `TEST-WIN10-01`
- findings and detections summary

### B. Search

Run:

- `artifact.type:email invoice.docm`
- `artifact.type:user_activity EncodedCommand`
- `artifact.type:ntfs risk_score>=70`
- `artifact.type:windows_ui Trojan`
- `process.name:powershell.exe`
- `file.name:"payload.exe"`
- `stable_event_id:<paste one from a detail raw/technical section>`

Explain:

- free text still works
- field syntax is allowlisted and case-scoped

### C. Findings

Open useful findings such as:

- `office_powershell`
- `downloaded_executable_origin`
- `trusted_office_macro_document`
- `suspicious_ui_observed_file`
- `security_notification_observed`
- `cloud_exfil_candidate`

### C2. Artifact Search

Show:

- `Artifact Search` as a case workspace view, not an evidence upload area
- pivot by `artifact.type` such as `browser`, `registry`, `prefetch` or `defender`
- focused columns and filters that differ from global `Search`

### D. Timeline

Show:

- investigation mode
- key events
- around finding / around event
- key event export if desired

### E. Process Graph

Show:

- focused suspicious chain
- Office -> PowerShell -> certutil style flow
- opening graph from a finding

### F. Detections / Rules

Show:

- `Rules -> Sigma`
  - imported Sigma demo rule for encoded PowerShell
  - explain clearly that Sigma scans indexed events
- `Rules -> YARA`
  - imported YARA demo rule for `malicious_test_marker`
  - explain clearly that YARA scans preserved files
- `Rules -> Rule Runs`
  - show queued/completed runs
- `Detections`
  - review filtered detections opened directly from a run
- review / dismiss workflow

### G. Reports

Show:

- report draft
- preview sections
- Markdown export
- PDF export

### H. Debug Export

Show that the debug pack includes:

- `correlation_findings_report.json`
- `event_identity_report.json`
- `reconciliation_report.json`
- `email_parse_report.json`
- `user_activity_parse_report.json`
- `ntfs_parse_report.json`
- `windows_ui_parse_report.json`

### I. OpenSearch Console

Show:

- data view ready
- Discover query examples:
  - `case_id:"<demo_case_id>"`
  - `artifact.type:"ntfs"`
  - `host.name:"TEST-WIN10-01"`

### J. Evidence Intake

Show:

- `Upload file`
- `Register server-mounted path`
- local path warning for browser/client machine paths

## Talking Points

- privacy-first demo data
- stable IDs survive re-ingest
- mounted path support for large evidence
- Sigma and YARA operationalized in one platform
- detections are the landing zone for all rule hits
- analyst workflow remains consistent across Search, Findings, Timeline and Process Graph
- debug export supports supportability and validation

## Known Limitations

- raw binary PST/OST, `Windows.edb`, `$UsnJrnl` and similar deep artifacts may still be inventory/export-based unless parsed output exists
- thumbnails indicate cache/UI presence, not guaranteed direct opening
- YARA results depend on `yara-python` availability in the runtime
- AI workflows are not implemented in this MVP
- full graph can still be noisy; focused views are preferred

## Output from Bootstrap

`tools/demo/bootstrap_demo_case.py` writes:

- report markdown
- report PDF
- debug export ZIP
- a bootstrap summary JSON

under:

- `demo/output/`
