# Debug Export Pack

## What it is

A reduced ZIP to validate ingest, normalization, correlation, process graph, detections and UI context without exposing all the original evidence.

## When to use it

- empty or incomplete timeline
- inconsistent process graph
- questionable detections or rules
- event volume regressions
- host attribution issues
- partial parsing or unexpected data quality

## Common scopes

- `case`
- `evidence`
- `artifact_type`
- specific investigation views

## Main reports

- `manifest.json`
- `ingest_summary.json`
- `discovery_candidates.json`
- `parser_audit.json`
- `normalized_events_sample.jsonl`
- `field_coverage_report.json`
- `dedup_report.json`
- `data_quality_report.json`
- `ui_context.json`

## Investigation / correlation reports

- `correlation_findings_report.json`
- `event_identity_report.json`
- `reconciliation_report.json`
- `process_graph.json`
- `process_tree_report.json`
- `process_tree_sample_chains.jsonl`
- `noise_reduction_report.json`
- `host_attribution_report.json`
- `host_identity_report.json`
- `ingest_regression_report.json`

## Rules / detections reports

- `rules_run_report.json`
- `detections_report.json`
- `sigma_matches.jsonl`
- `yara_matches.jsonl`

## Artifact family reports

- `browser_parse_report.json`
- `defender_parse_report.json`
- `bits_parse_report.json`
- `usb_parse_report.json`
- `recycle_parse_report.json`
- `srum_parse_report.json`
- `wlan_parse_report.json`
- `dns_parse_report.json`
- `cloud_parse_report.json`
- `email_parse_report.json`
- `user_activity_parse_report.json`
- `ntfs_parse_report.json`
- `windows_ui_parse_report.json`
- `autoruns_parse_report.json`
- `lnk_parse_report.json`
- `prefetch_parse_report.json`
- `email_sample_events.jsonl`
- `user_activity_sample_events.jsonl`
- `ntfs_sample_events.jsonl`
- `windows_ui_sample_events.jsonl`

## How to read it

Recommended order:

1. `manifest.json`
2. `ingest_summary.json`
3. `parser_audit.json`
4. `data_quality_report.json`
5. `ingest_regression_report.json`
6. `host_attribution_report.json`
7. `host_identity_report.json`
8. `event_identity_report.json`
9. `reconciliation_report.json`
10. specific reports for the problematic view

## What it does not include by default

- full heavy raw evidence
- complete user dumps
- untruncated mass export of sensitive strings

## Notes

- It is a validation pack, not a substitute for the original evidence.
- Reports depend on the scope and on whether data for that family exists.
- `yara_matches.jsonl` may be empty or include a warning if YARA did not apply to that scope.
- `email_parse_report.json` summarizes messages, attachments, mailbox inventory and SPF/DKIM/DMARC failures already present in headers; it does not perform external DNS validation.
- `user_activity_parse_report.json` summarizes UserAssist/BAM/RunMRU/TypedPaths/RecentDocs/Shellbags/Office MRU/TrustRecords activity and marks raw hives as inventory-only when no parsed export was available.
- `ntfs_parse_report.json` summarizes Zone.Identifier, USN, `$LogFile`, `$I30`, shadow copies and raw NTFS inventory-only. `ntfs_sample_events.jsonl` helps validate web origin, create/delete/rename and deleted entries without exporting all the evidence.
- `windows_ui_parse_report.json` summarizes thumbnails, notifications, ActivitiesCache, Windows.edb, EventTranscript, Office alerts and Office cache. `windows_ui_sample_events.jsonl` is used to validate high-value UI/local DB signals without including binary blobs or full sensitive text.
- `event_identity_report.json` summarizes how many events have a `stable_event_id`, how many are best-effort, whether there were collisions and how they were distributed by artifact family.
- `host_identity_report.json` summarizes canonical hosts, aliases, manual merges, splits, pending candidates and `observed_host.name` coverage.
- `reconciliation_report.json` summarizes what happened after a reprocess: reconciled findings/detections, remapped key events and references that remained stale.
- `event_id` is the current technical indexing identifier; it can change after a reprocess. `stable_event_id` is the stable logical identity used for v1 reconciliation.
- `ingest_plan.json` exports the active ingest plan per evidence.
- `ingest_plan_diff.json` summarizes missing/changed/new candidates from the last reprocess preview.
- `ingest_reprocess_report.json` summarizes the reprocess mode used, selected candidates, analyst state preservation and warnings.
