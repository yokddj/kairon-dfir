# How to add new rules

## Where rules live today

### Rules stored in the database

Created or imported via API/UI and live as `Rule` or `RuleSet` objects.

### Repository YAML files

Currently the repo includes auxiliary rules in:

```text
backend/app/rules/
```

This directory already includes, for example:

- `suspicious_keywords.yaml`
- `artifact_profiles.yaml`
- `known_windows_artifacts.yaml`
- `builtin_detection_overrides.yaml`

Important:

- `suspicious_keywords.yaml` helps tag events, it is not a database `Rule` by itself.
- Builtin detections live in code and are documented separately.

## Engines supported today

- `heuristic`
- `sigma`
- `yara`

## Actual format of a heuristic rule

The heuristic engine supports a simple format with:

- `query.any`
- `filters`

Example:

```yaml
name: PowerShell encoded command
description: Looks for PowerShell commands with -enc
severity: high
query:
  any:
    - field: process.command_line
      contains: -enc
filters:
  event.type:
    - process_creation
```

## Actual Sigma format

The project's Sigma path supports an MVP focused on:

- `detection.selection`
- `condition: selection`

Known Sigma fields are remapped to normalized fields, for example:

- `EventID` -> `windows.event_id`
- `Image` -> `process.path`
- `CommandLine` -> `process.command_line`
- `TargetUserName` -> `user.name`

## YARA

YARA is imported as:

- an individual rule
- a rule pack

YARA execution is done over preserved files, not over CSV/JSON parsed by default.

## Useful fields for rules

- `event.type`
- `event.category`
- `event.action`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `process.command_line`
- `process.path`
- `powershell.script_block_text`
- `file.path`
- `service.image_path`
- `task.command`
- `detection.threat_name`
- `tags`
- `suspicious_reasons`

## How to define severity

Use a severity that helps the analyst prioritize:

- `info`
- `low`
- `medium`
- `high`
- `critical`

## How to add description and recommendation

Whenever possible, a rule should answer:

1. What it looks for
2. Why it is relevant
3. What to check after a match

## Practical examples

### Heuristic rule for PowerShell encoded command

```yaml
name: PowerShell encoded command
description: Looks for PowerShell processes with -enc
severity: high
query:
  any:
    - field: process.command_line
      contains: -enc
filters:
  process.name:
    - powershell.exe
    - pwsh.exe
```

### Heuristic rule for service from AppData

```yaml
name: Suspicious service path
description: Service created with binary under AppData
severity: high
query:
  any:
    - field: service.image_path
      contains: \\AppData\\
filters:
  event.type:
    - service_created
```

### Heuristic rule for scheduled task that runs PowerShell

```yaml
name: Scheduled task runs PowerShell
description: Scheduled task that calls PowerShell
severity: medium
query:
  any:
    - field: task.command
      contains: powershell
filters:
  event.type:
    - scheduled_task_created
    - scheduled_task_updated
```

### Rule for log cleared 1102

```yaml
name: Audit log cleared
description: Looks for deletion of the audit log
severity: high
query:
  any:
    - field: windows.event_id
      equals: 1102
filters:
  event.type:
    - audit_log_cleared
```

## How to disable a rule

### Stored rules

The UI and API already support `enabled = true/false`.

### Builtin detections

See [builtin_rules.md](builtin_rules.md). They are disabled:

- globally with `AUTO_CREATE_HEURISTIC_DETECTIONS`
- individually with `builtin_detection_overrides.yaml`

## How to avoid false positives

1. Filter by `event.type` or `artifact.type` whenever possible.
2. Don't search only by text if a better normalized field exists.
3. Use the correct Provider/Channel in Windows events.
4. Add a clear description of the expected context.
