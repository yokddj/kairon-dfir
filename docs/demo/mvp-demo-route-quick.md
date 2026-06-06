# Demo Route Quick Guide

Use this walkthrough with your generated demo case.

## Route 5-10 min

1. `Overview`
   - Open `Demo - ACME Incident 001`
   - Show host `TEST-WIN10-01`
   - Highlight `20 findings` and `19 detections`

2. `Search`
   - Run:
     - `process.name:powershell.exe`
     - `artifact.type:user_activity EncodedCommand`
     - `artifact.type:ntfs risk_score>=70`
     - `artifact.type:windows_ui Trojan`
     - `file.name:"payload.exe"`
   - Open one result and show the wide detail modal

3. `Findings`
   - Show 3-4 clear findings:
     - `office_powershell`
     - `downloaded_executable_origin`
     - `trusted_office_macro_document`
     - `security_notification_observed`
   - Pivot from one of them into `Timeline` or `Process Graph`

4. `Timeline`
   - Open `Investigation timeline`
   - Show that there are `7 key events`
   - Walk through:
     - phishing or delivery
     - trust of `invoice.docm`
     - `powershell.exe -EncodedCommand`
     - download of `payload.exe`
     - Defender alert
     - cloud or USB context

5. `Process Graph`
   - Open from a finding
   - Explain that it opens in focused mode, not full graph
   - Show the suspicious chain Office -> PowerShell -> payload

6. `Detections / Rules`
   - Show one Sigma detection for encoded PowerShell
   - Show one YARA detection for the marker
   - Optionally mark one as `reviewed` or `dismissed`

7. `Reports`
   - Open the draft report
   - Show preview
   - Mention that Markdown and PDF export already validated OK

8. `Debug Export`
   - Show that the debug pack exists
   - Mention:
     - `event_identity_report.json`
     - `reconciliation_report.json`
     - `ntfs`, `user_activity`, `windows_ui`, `email` reports

9. `OpenSearch`
   - In Discover, run:
     - `case_id:"<demo_case_id>"`
     - `host.name:"TEST-WIN10-01"`
     - `artifact.type:"ntfs"`

10. `Evidence Intake`
   - Close by showing:
     - `Upload file`
     - `Register server-mounted path`
     - the warning for browser-local paths

## Key Messages

- All data is synthetic and anonymized.
- The platform covers ingest, hunting, correlation, detections, graph, and reporting.
- `stable_event_id` supports re-ingest without losing analyst context.
- For large evidence, mounted path can be used instead of browser upload.

## Useful Queries

- `artifact.type:email invoice.docm`
- `artifact.type:user_activity EncodedCommand`
- `artifact.type:ntfs risk_score>=70`
- `artifact.type:windows_ui Trojan`
- `process.name:powershell.exe`
- `file.name:"payload.exe"`
