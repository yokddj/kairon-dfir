# MVP Demo Checklist

## Pre-flight

- backend up
- worker up
- frontend up
- OpenSearch healthy
- OpenSearch Dashboards data view available

## Pack

- `python3 tools/demo/generate_demo_evidence.py` completed
- `demo/evidence/acme_incident_001.zip` exists
- no real customer or host names inside demo assets

## Case

- case name is `Demo - ACME Incident 001`
- host visible as `TEST-WIN10-01`
- evidence ingest completed
- events indexed > 0

## Investigation

- findings count > 0
- at least one Sigma detection
- YARA detection present if runtime supports YARA
- Rules page shows separate `Sigma`, `YARA`, `Heuristics`, `Rule Runs`
- key events visible in Timeline
- Process Graph opens with suspicious chain context

## Search

- `artifact.type:email invoice.docm`
- `artifact.type:user_activity EncodedCommand`
- `artifact.type:ntfs risk_score>=70`
- `artifact.type:windows_ui Trojan`
- `process.name:powershell.exe`
- `file.name:"payload.exe"`

## Artifact Search

- sidebar shows `Artifact Search` under `Case Workspace`
- `Artifact Search` opens from the case workspace, not from Evidence
- page title says `Artifact Search`

## Reports and Debug

- report draft created
- Markdown export works
- PDF export works
- debug export works
- debug export contains identity and reconciliation reports

## UI / Ops

- Findings open correctly
- Timeline detail opens correctly
- Process Graph detail opens correctly
- mounted path warning still explains client vs server path
- Sigma tab explains `indexed events`
- YARA tab explains `preserved files`
- opening detections from a rule run applies source/run filters

## Privacy

- no real customer names in demo docs
- no real case IDs in demo docs
- no real hostnames or real usernames in generated pack
