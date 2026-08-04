# Rules, Sigma and YARA

## Rules Engine v2

The `Rules` UI is now designed as a `Sigma-first` flow.

Common engine for:

- `Sigma` over normalized events
- `YARA` over accessible evidence files
- builtin detections

The important product-level separation is:

- `Sigma`
  - runs over `indexed events`
- `YARA`
  - runs over `preserved files`
- `Heuristics`
  - automatic internal detections

These must not be mixed visually in the UI.

## Sigma

### What it supports

- YAML rule validation
- execution per case, evidence, host or time window
- mapping of common fields to the normalized schema
- creation of detections linked to events

### Correct import

- `Import Sigma rule`
  - a single `.yml` or `.yaml` file
- `Import Sigma rule pack`
  - a `ZIP/TAR/7z` with several Sigma rules

If a compressed collection doesn't match a specialized format, it must fall back to generic ingest without forcing the user to understand the internal technology.

### Useful output

Each Sigma detection must expose:

- rule
- linked event
- matching fields
- condition summary
- severity
- confidence
- tags / MITRE if present

## YARA

### What it supports

- rule validation and compilation
- execution over preserved files or selected paths
- truncated and safe `matched_strings`
- deduplication and persistent state on rerun

### Correct import

- `Import YARA rule`
  - a single `.yar` or `.yara` file
- `Import YARA rule pack`
  - a `ZIP/TAR/7z` with several YARA files

The UI must make it clear that YARA does not run over indexed logs.

### Security limits

- do not follow symlink escapes
- do not leave allowed roots
- skip files that are too large according to configuration
- do not launch a massive full scan by default

### Operational recommendation

- start with a small scope
- use `selected paths` or specific evidence
- avoid the whole collection unless clearly necessary

## Detections

All rule executions land here first.

States:

- `new`
- `reviewed`
- `confirmed`
- `dismissed`

Actions:

- open detail
- open related event or file
- pivot to Search
- open Timeline
- open Process Graph if process context exists
- promote to Finding

## Debug reports

The debug pack can include:

- `rules_run_report.json`
- `detections_report.json`
- `sigma_matches.jsonl`
- `yara_matches.jsonl`

## Usage recommendation

- start with controlled/builtin Sigma
- add YARA once you already have a clear scope
- use `Rule Runs` to check status, volume and errors
- open `Detections` filtered by `source=sigma|yara` after each run
- use `Search` with queries like `detection.source:sigma` or `detection.source:yara`
- don't promote weak detections to high-severity findings without additional context

## Operations v2

The `Rule Library` tab now allows bulk operations over imported rules:

- multi-selection by rule or pack
- `Enable selected`
- `Disable selected`
- `Delete selected`
- `Delete all matching`
- `Delete all imported rules`

Protections:

- builtin heuristics must not be deleted by `delete imported rules`
- destructive bulk deletions require typing `DELETE RULES`
- deleting rules or packs does not remove detections already created

`Rule Runs` adds operational control:

- `Cancel run`
- `Mark failed/stale`
- `Retry run`
- `Delete run record`
- bulk actions for selected runs

What `stale` means:

- the run is still marked as `queued` or `running` in persistence
- but there is no recent worker `heartbeat`
- the UI surfaces it as an operational warning so the analyst can cancel it, mark it as failed, or retry it
