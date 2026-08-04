# Findings and Correlation

## What a finding is

A `finding` is an investigative conclusion supported by one or more related events, detections, process chains or IOCs.

It is not equivalent to a triggered rule.

## Main v1 types

- `download_execute_detect`
- `office_powershell`
- `powershell_network`
- `persistence_execution`
- `cloud_exfil_candidate`
- `usb_exfil_candidate`
- `execution_cleanup`
- `suspicious_process_chain`
- `user_executed_suspicious_command`
- `trusted_office_macro_document`
- `user_activity_suspicious_program`
- `downloaded_executable_origin`
- `suspicious_file_deleted_or_renamed`
- `office_security_alert_document`
- `suspicious_ui_observed_file`
- `security_notification_observed`

## Severity, confidence and status

- severity: `low` to `critical`
- confidence: `low`, `medium`, `high`
- status: `new`, `reviewed`, `confirmed`, `dismissed`

Status must be preserved if the finding or its signals reappear on reruns.

## Deduplication

Correlation attempts to avoid duplicate findings using fingerprints and case/evidence/host/event context.

## Relationship with detections and rules

- a `detection` can support a finding
- a confirmed detection can be promoted to a finding
- not every high-severity detection should automatically become a high-severity finding

## Limitations

- correlation is still heuristic
- `usb_exfil_candidate` and `cloud_exfil_candidate` express hypotheses, not conclusive proof
- findings should be read alongside the Timeline, Search and Process Graph
- `user_executed_suspicious_command` is reserved for high-confidence signals such as `RunMRU` with encoded PowerShell / a clear LOLBIN
- `trusted_office_macro_document` uses `TrustRecords` as evidence of a trusted document or enabled content, but its interpretation depends on the Office version and the observed value
- `user_activity_suspicious_program` avoids triggering on isolated `RecentDocs`, `TypedPaths` or `Shellbags`
- `downloaded_executable_origin` uses `Zone.Identifier` and URL/web-origin context to link a file to its provenance; it does not confirm execution by itself
- `suspicious_file_deleted_or_renamed` uses USN / `$LogFile` / `$I30` to flag staging, deletion or suspicious renaming, but high severity depends on additional correlation
- `office_security_alert_document` relies on OAlerts/Office cache/UI artifacts to highlight Protected View, macros or content enablement; it should be read together with Email, NTFS and User Activity
- `suspicious_ui_observed_file` uses thumbnails, ActivitiesCache or Windows Search to flag UI references to suspicious files, not as proof of execution
- `security_notification_observed` summarizes high-value security notifications such as Defender/quarantine/phishing, with a truncated and sanitized body
