# Scheduled Tasks / Task Scheduler

## What they are

Windows Scheduled Tasks describe **technical persistence and automation**. The XML from `C:\Windows\System32\Tasks\...` represents the task's **definition**, not by itself proof of recent execution.

## What the platform currently supports

- raw XML from:
  - `C:\Windows\System32\Tasks\*`
  - Velociraptor collections with paths like `uploads/auto/C%3A/Windows/System32/Tasks/...`
- compatible parsed CSV:
  - `*ScheduledTasks*.csv`
  - `*TaskScheduler*.csv`
  - `*Tasks*.csv`

## What fields are extracted

- `RegistrationInfo`: `Author`, `Description`, `Date`, `URI`, `Version`
- `Principal`: `UserId`, `GroupId`, `LogonType`, `RunLevel`
- `Settings`: `Enabled`, `Hidden`, `RunOnlyIfNetworkAvailable`, `ExecutionTimeLimit`, etc.
- `Triggers`: `BootTrigger`, `LogonTrigger`, `CalendarTrigger`, `EventTrigger`, `RegistrationTrigger`, `IdleTrigger`
- `Actions`:
  - `Exec`: `Command`, `Arguments`, `WorkingDirectory`
  - `ComHandler`: `ClassId`, `Data`

## How it's interpreted

- `scheduled_task_definition`: observed definition
- `scheduled_task_com_handler`: task with a COM handler action
- `scheduled_task_created` / `scheduled_task_updated`: EVTX events that prove creation or modification
- `task_execution`: activity correlated with EVTX/Prefetch/execution

The app explicitly distinguishes:

- observed task
- created/modified task
- task possibly used as persistence
- task with correlated execution

## Who the task runs as (`persistence.scope`)

Decided by the task's principal, in this order:

- `system`: runs as SYSTEM, LOCAL SERVICE or NETWORK SERVICE (by name or SID).
- `interactive_user`: runs as whoever is logged on (`GroupId` `S-1-5-4`, INTERACTIVE).
- `user`: runs as a specific account (`UserId`, or a user profile path in the command).
- `system` again only when the task names no principal at all and lives in the system task store.

Every task file is stored under `C:\Windows\System32\Tasks`, so the location says nothing about who runs it. Before 2026-10-05 the location was checked first and every task came out as `system`; reprocess the evidence to correct `persistence.scope` on tasks indexed earlier.

A disabled task that has a command still appears in the timeline: its registration date is real, and a task can be disabled after it has been used. It is tagged `disabled`.

## What Enabled / Hidden mean

- `Enabled=true`: the task is enabled to run
- `Hidden=true`: the task is not normally shown in the interface

A `hidden + enabled` task is not automatically malicious, but interest increases if it also uses PowerShell, LOLBins, user paths, or encoded commands.

## What ComHandler is

A task with `ComHandler` does not execute a visible binary in `Command`, but rather a COM class. This is a legitimate system technique, but it can also hide less obvious persistence.

## Correlation

The platform correlates Scheduled Tasks with:

- EVTX:
  - Security `4698`, `4699`, `4700`, `4701`, `4702`
  - TaskScheduler Operational `106`, `140`, `141`, `200`, `201`, `102`, `129`
- Prefetch
- Browser downloads
- MFT / USN
- Registry
- Amcache / ShimCache
- SRUM
- Defender

## Typical suspicious findings

- PowerShell with `-EncodedCommand`
- execution from `AppData`, `Temp`, `Downloads`, `Users\Public`, `ProgramData`, `Desktop`
- use of `mshta`, `regsvr32`, `wscript`, `cscript`, `certutil`, `bitsadmin`
- UNC paths `\\server\share\...`
- `hidden + enabled` tasks
- task names that imitate legitimate updates
- unusual `ComHandler`

## Limitations

- the XML does not by itself prove execution
- legitimate Microsoft tasks generate a lot of noise
- the main timestamp can come from `RegistrationInfo/Date` or from the XML's `mtime`
- confidence increases greatly when there is correlation with EVTX or Prefetch
