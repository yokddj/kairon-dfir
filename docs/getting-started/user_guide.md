# User Guide

## End-to-End Analyst Flow

1. Create or select a `case`.
2. Upload a file or register a mounted path in `Evidence & Ingest`.
3. Enter the expected/canonical host, e.g. `HOST-A`.
4. Index the evidence.
5. Check Evidence Detail:
   - `investigation_ready=true`
   - `completed` or `completed_with_warnings`
   - indexed documents > 0
   - understandable warnings, if any.
6. Use `Search` as the main workspace.
7. Switch to `Timeline` from Search when you need temporal reconstruction.
8. Use `Artifact Views` for family-specific columns.
9. Open `Command History` for consolidated commands.
10. Open `Execution Story` from Search or Command History for specific processes.
11. Mark events/commands as `suspicious` or `important`.
12. Create findings from events, commands, detections and notes.
13. Generate reports with findings, marked events, Command History, Execution Story and Defender.
14. Export Markdown.

## Generic Investigation Example

With a synthetic evidence package, a typical workflow is:

1. Search for a suspicious command pattern such as `powershell -ep bypass`.
2. Open the exact command event and review its Execution Story.
3. Pivot to downloaded files, user activity and filesystem artifacts referenced by the event.
4. Review Artifact Views for MFT, User Activity, Command History and Defender where available.
5. Mark reviewed events or commands as suspicious or important.
6. Create a finding and generate a Markdown report.

Not every term exists in every dataset. A zero-result search can be valid when the source evidence simply does not contain that artifact or string.

## Evidence Status

Relevant statuses:

- `completed`: the pipeline finished with no relevant warnings.
- `completed_with_warnings`: investigable data exists, but there are also warnings, failed optional parsers, or unsupported artifacts.
- `failed`: the main pipeline produced no investigable data, or failed critically.
- `investigation_ready`: indicates the evidence has searchable data even if warnings exist.

Do not treat `completed_with_warnings` as failure. Review `status_reason`, warnings, and counts.

## Host Identity

Search is alias-aware. If the canonical host is `HOST-A`, the filter should retrieve documents observed as:

- `HOST-A`
- `host-a`
- `host-a.example.local`

The detail view preserves observed values for traceability.

## Search

Search is the main entry point. Use it for:

- commands
- paths
- hashes
- domains
- event IDs
- artifact filters
- marked events
- pivots to Command History, Execution Story, Timeline and Reports.

Examples of valid human queries:

- `powershell -ep bypass`
- `-nop`
- `-w hidden`
- `script.ps1`
- `C:\Users\Public\remote-admin.exe`
- `example-control.test`
- `sample.iso`

Flags with a leading dash are treated as text. For exclusions, use explicit filters or the include/exclude UI, not `-term`.

## Timeline

Timeline is a Search view. It should preserve:

- `case_id`
- `evidence_id`
- host
- query
- time range
- artifact filters

MFT/filesystem records are not included by default to avoid flooding the timeline view. Enable `Include filesystem/MFT events` or filter by `artifact_type=mft` when you want that timeline.

## Artifact Views

Artifact Views does not replace Search. Use it to review families with specialized columns:

- MFT / Filesystem
- Defender
- User Activity
- Prefetch
- Scheduled Tasks
- Browser
- Services / Autoruns
- LNK / Jumplist
- Amcache / Shimcache

Each view should indicate backend, coverage, and limitations. Where an advanced backend exists, check whether you are viewing default, advanced, or compare.

## Command History

Command History consolidates executions from sources such as Sysmon 1, Security 4688, PowerShell Operational, PSReadLine/transcripts where they exist, and scheduled tasks.

Key fields:

- timestamp
- command
- source_type
- launcher
- family
- confidence
- parent process
- supporting events
- risk reasons

Prefetch can appear as execution context, but not as an exact command line.

## Execution Story

Execution Story answers:

- Who launched this?
- What did it launch?
- What did it do?
- Why is it suspicious?
- What evidence supports this?

When you open a story from Search or Command History, the target must resolve by exact identity:

1. `source_event_id`
2. process GUID
3. PID + timestamp + host + evidence
4. text only as a last-resort fallback

Clicking a node shows a preview. Changing the target requires the explicit `Make target` action.

## Markings and Findings

Use markings to flag events or commands:

- `suspicious`
- `important`
- `reviewed`
- `false_positive`

Then create findings with:

- a clear title
- severity
- related events/commands
- detections, if applicable
- analyst notes
- an Execution Story summary if it adds context

## Reports

Reports can include:

- findings
- detections
- marked events
- Command History
- Execution Story summaries
- Defender section
- analyst notes

Markdown is the validated export. PDF should not be considered stable unless explicitly validated for the deployment.

## Rules and Detections

Sigma:

- oriented toward normalized events.
- use small scopes or specific rules for smoke/control runs.
- review detections before promoting them.

YARA:

- oriented toward preserved files.
- must run with size, root, and scope limits.
- do not launch it as an uncontrolled full mass scan.
