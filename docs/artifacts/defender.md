# Microsoft Defender Artifacts

## Current support

Defender is handled as a dedicated artifact when Defender EVTX/channel data exists.

Supported source path:

- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-Windows Defender%4Operational.evtx`
- EvtxECmd CSV rows from that channel

The parser normalizes Defender events into `artifact.type = defender`.

## Common event coverage

Initial coverage includes common Defender event IDs such as:

- malware/threat detection and remediation events where present
- remediation success/failure/action events where present
- configuration changes such as Event ID 5007
- platform/health events where useful

If a log contains only health/configuration events, threat queries such as a malware family name can correctly return zero.

## Normalized fields

Where available:

- `event.provider`
- `event.channel`
- `windows.event_id`
- `@timestamp`
- `host.name`
- `user.name`
- `threat.name`
- `threat.id`
- `threat.severity`
- `threat.category`
- `threat.status`
- `defender.action`
- `defender.action_result`
- `defender.detection_source`
- `defender.path`
- `file.path`
- `process.name`
- `process.executable`
- `process.command_line`
- `registry.path`
- `url.full`
- `url.domain`
- `event.message`
- raw `winlog.event_data`

## Search

Use:

- `artifact_type=defender`
- threat name
- file/path
- Defender action/result
- Windows Event ID

Examples:

- `artifact.type:defender`
- `VirTool`
- `Rubeus`
- `PUAProtection`
- `Windows Defender`

If `Rubeus` or `VirTool` returns zero, verify whether those strings exist in the indexed/source data. Zero can be a valid no-data result.

## Artifact View

The Defender view should show:

- total Defender docs
- high/critical detections when present
- remediated/action failed counts
- configuration changes
- timestamp
- threat/action/path/user/event ID columns

Actions:

- Open in Search
- Open timeline around
- Mark suspicious/important
- Add to finding
- Copy IOC/path/threat

## Reports

Reports can include Defender sections for:

- detections
- threats
- actions/results
- failed remediation
- paths
- marked Defender events

## Interpretation

Do not claim infection solely from a Defender configuration or health event. Use wording such as:

- detected
- remediated
- remediation failed
- configuration changed
- no relevant detection events found

