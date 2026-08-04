# EVTX / EvtxECmd

## What EVTX is

EVTX is the Windows event log format. The platform supports two paths:

- output already parsed with **EvtxECmd**
- **native raw** parsing of the `.evtx` when the parser dependency is available

## Why EvtxECmd_Output.csv is still used

Because it allows:

- fast and reproducible ingestion
- preserving raw and payload without yet designing a full raw parser
- normalizing relevant events with control over `Provider/Channel`

The native raw parser and the `EvtxECmd_Output.csv` flow share the same classification philosophy:

- do not classify by `EventID` alone
- always validate `Provider + Channel + EventID`
- degrade to generic `windows_event` when the `EventID` collides with another family

## Fields extracted

- `EventID`
- `Provider`
- `Channel`
- `TimeCreated`
- `RecordNumber`
- `Computer`
- `UserName`
- `PayloadData*`
- `Payload`
- `EventData`
- `Xml` / `RawXml` if present

## How Payload JSON is parsed

If `Payload` contains valid JSON, it is extracted and merged into `windows.event_data`.

Example:

```json
{
  "EventData": {
    "Data": [
      {"@Name": "TargetUserName", "#text": "SYSTEM"},
      {"@Name": "LogonType", "#text": "5"}
    ]
  }
}
```

This becomes something like:

- `windows.event_data.TargetUserName = SYSTEM`
- `windows.event_data.LogonType = 5`

Additionally:

- `windows.payload.Payload` preserves the original payload
- `windows.event_data.payload_columns` preserves `PayloadData*`
- `raw` preserves the original row

## What `source_mismatch` means

A `source_mismatch` means:

- the `EventID` matches a known one
- but `Provider/Channel` are **not** the expected ones
- therefore the event is **not** labeled as `logon_failed`, `service_created`, etc.

In that case it falls back to a generic classification:

- `event.category = windows_event`
- `event.type = event_id_<ID>`
- `event.action = windows_event_observed`
- tags include `source_mismatch`

Important example:

- `EventID 400` is only interpreted as PowerShell if the source is actually PowerShell
- `Microsoft-Windows-AppXDeploymentServer/Operational` with `EventID 400` should **not** be seen as PowerShell
- `Microsoft-Windows-StateRepository/Operational` with `EventID 400` should **not** be seen as PowerShell

## Table of supported EventIDs

| EventID | Expected Provider / Channel | Classification | What it looks for | Important fields | Semi-automatic section |
| --- | --- | --- | --- | --- | --- |
| 4624 | Security-Auditing / Security | `logon_success` | Successful logon | user, LogonType, IP, ProcessName | Logons / RDP |
| 4625 | Security-Auditing / Security | `logon_failed` | Failed logon | user, LogonType, Status, IP | Logons |
| 4634 | Security-Auditing / Security | `logoff` | Logoff | user, LogonType | Logons |
| 4647 | Security-Auditing / Security | `user_logoff` | User-initiated logoff | user, LogonId | Logons |
| 4648 | Security-Auditing / Security | `explicit_credentials_logon` | Explicit use of credentials | SubjectUserName, TargetUserName, ProcessName | Logons |
| 4672 | Security-Auditing / Security | `special_privileges_assigned` | Special privileges | SubjectUserName, PrivilegeList | Logons |
| 4688 | Security-Auditing / Security | `process_creation` | Process creation | NewProcessName, CommandLine, ParentProcessName | Executed programs |
| 4689 | Security-Auditing / Security | `process_termination` | Process end | ProcessName, ProcessId | Timeline |
| 4697 | Security-Auditing / Security | `service_created` | Service installation | ServiceName, ServiceFileName | Services / Persistence |
| 4698 | Security-Auditing / Security | `scheduled_task_created` | Task created | TaskName, TaskContent | Tasks / Persistence |
| 4702 | Security-Auditing / Security | `scheduled_task_updated` | Task modified | TaskName, TaskContent | Tasks / Persistence |
| 4720 | Security-Auditing / Security | `user_created` | User created | TargetUserName | Account changes |
| 4722 | Security-Auditing / Security | `user_enabled` | User enabled | TargetUserName | Account changes |
| 4723 | Security-Auditing / Security | `password_change_attempt` | Password change | TargetUserName | Account changes |
| 4724 | Security-Auditing / Security | `password_reset_attempt` | Password reset | TargetUserName | Account changes |
| 4725 | Security-Auditing / Security | `user_disabled` | User disabled | TargetUserName | Account changes |
| 4726 | Security-Auditing / Security | `user_deleted` | User deleted | TargetUserName | Account changes |
| 4728 / 4732 | Security-Auditing / Security | `user_added_to_group` | User added to group | MemberName, SubjectUserName | Account changes |
| 4735 / 4737 | Security-Auditing / Security | `group_changed` | Group modified | TargetUserName | Account changes |
| 4738 | Security-Auditing / Security | `user_modified` | User modified | TargetUserName | Account changes |
| 4740 | Security-Auditing / Security | `account_locked_out` | Account locked out | TargetUserName | Account changes |
| 4768 / 4769 / 4771 / 4776 | Security-Auditing / Security | Kerberos / NTLM | Domain authentication | user, status, IP | Logons |
| 4778 / 4779 | Security-Auditing / Security | RDP reconnection/disconnection | RDP sessions | AccountName, ClientAddress | RDP |
| 5140 / 5145 | Security-Auditing / Security | Share access | SMB share access | ShareName, RelativeTargetName, IpAddress | Network / Timeline |
| 5156 | Security-Auditing / Security | `network_connection_allowed` | Connection allowed | Application, SourceAddress, DestinationAddress | Network |
| 1102 | Eventlog / Security | `audit_log_cleared` | Audit log cleared | SubjectUserName | Anti-forensics |
| 7036 / 7040 / 7045 | Service Control Manager / System | service changes | State, start type, creation | ServiceName, ImagePath | Services / Persistence |
| 106 / 129 / 140 / 141 / 200 / 201 | TaskScheduler Operational | task activity | Registration, deletion, action started/finished | TaskName, ActionName | Tasks |
| 400 / 403 / 600 / 800 | PowerShell | engine/pipeline lifecycle | HostApplication, CommandLine | PowerShell |
| 4103 / 4104 / 4105 / 4106 | PowerShell Operational | module logging / script block | ScriptBlockText, ScriptBlockId | PowerShell |
| 21 / 22 / 23 / 24 / 25 / 39 / 40 | TerminalServices LocalSessionManager | RDP activity | User, Address, Reason | RDP |
| 1149 | TerminalServices RemoteConnectionManager | `rdp_authentication_success` | RDP authentication | User, Domain, SourceNetworkAddress | RDP |
| 1116 / 1117 / 1118 / 1119 / 5007 / 5013 | Windows Defender Operational | Defender activity | ThreatName, Path, Action | Defender |
| 5857 / 5858 / 5859 / 5860 / 5861 | WMI Activity Operational | WMI activity | ClientMachine, Query, Consumer | Persistence / Timeline |
| Sysmon 1,3,7,10,11,12,13,14,15,22,23,26 | Sysmon Operational | ready | Sysmon telemetry | depends on event | Future |

## Important points

### Not every EventID means the same thing

Example:

> `4625` should only be interpreted as a failed logon when it comes from `Security / Microsoft-Windows-Security-Auditing`.

Another example:

> `400` should only be interpreted as PowerShell activity when `Provider/Channel` correspond to PowerShell.

### 1102 is not treated as Security-Auditing

`1102` is expected in:

- `Channel = Security`
- `Provider = Microsoft-Windows-Eventlog` or `Eventlog`

### How to check it works

1. Import an `EvtxECmd_Output.csv`.
2. Search for `4624`.
3. Open an event.
4. Verify:
   - `windows.event_id = 4624`
   - `user.name`
   - `windows.logon_type`
   - `process.path`
   - `windows.event_data`
   - `windows.payload`
