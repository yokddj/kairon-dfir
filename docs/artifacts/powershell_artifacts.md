# PowerShell artifacts outside EVTX

## What artifacts the app supports

The platform currently supports, outside of EVTX:

- `ConsoleHost_history.txt` from `PSReadLine`
- `PowerShell_transcript*.txt` and transcript variants
- `*.ps1`, `*.psm1`, `*.psd1` scripts as observed content
- parsed CSV/JSON related to PowerShell when they have a compatible structure
- raw discovery from Velociraptor collections

## Difference from EVTX 4104/4688

- `4104` and `4688` usually provide better execution context and timestamps.
- `PSReadLine` provides visibility into interactive commands typed by the user.
- `Transcript` provides more operational context, session metadata, and sometimes per-command timing.
- An observed `.ps1` script does not by itself prove execution.

## What ConsoleHost_history.txt is

This is the `PSReadLine` command history. It usually contains one command per line.

Important limitations:

- normally has no per-command timestamp
- a present command does not prove successful execution
- may contain benign commands alongside suspicious commands

## What PowerShell transcripts are

Transcripts are text logs of PowerShell sessions. They can include:

- user
- `RunAs`
- machine
- `Host Application`
- `Process ID`
- PowerShell version
- commands issued from the prompt

They are much more useful than `PSReadLine` for reconstructing temporal context when they exist.

## What fields are extracted

- `powershell.command`
- `powershell.command_preview`
- `powershell.line_number`
- `powershell.source_file`
- `powershell.transcript_start_time`
- `powershell.transcript_end_time`
- `powershell.username`
- `powershell.run_as`
- `powershell.machine`
- `powershell.host_application`
- `powershell.process_id`
- `powershell.ps_version`
- `powershell.has_encoded_command`
- `powershell.encoded_command`
- `powershell.decoded_command_preview`
- `powershell.has_download`
- `powershell.has_iex`
- `powershell.has_execution_policy_bypass`
- `powershell.has_defender_tampering`
- `powershell.has_persistence`
- `powershell.urls`
- `powershell.domains`
- `powershell.paths`
- `powershell.indicators`

Additionally, when applicable:

- `process.command_line`
- `url.full`
- `url.domain`
- `file.path`

## Indicators the app detects

- `EncodedCommand`
- `Invoke-Expression` / `IEX`
- download cradle
- `ExecutionPolicy Bypass`
- `NoProfile` / `WindowStyle Hidden` in a suspicious context
- Defender tampering:
  - `Set-MpPreference`
  - `Add-MpPreference`
  - `DisableRealtimeMonitoring`
  - exclusions
- persistence:
  - `Register-ScheduledTask`
  - `schtasks`
  - `reg add`
  - Run Keys
  - service creation
- reconnaissance:
  - `whoami`
  - `hostname`
  - `ipconfig`
  - `systeminfo`
  - `tasklist`
- credential access or dumping:
  - `lsass`
  - `mimikatz`
  - `sekurlsa`
  - `procdump`
  - `comsvcs.dll`

## How missing timestamps are interpreted

- `PSReadLine` uses `source_file_mtime` as an approximation when available.
- If there is no reliable time, `timestamp_precision = unknown` remains.
- In transcripts, priority is given to:
  1. `Command start time`
  2. `transcript start time`
  3. `source file mtime`

This allows events to be placed on the timeline without claiming false precision.

## How it correlates

The app correlates PowerShell with:

- EVTX `4104` and `4688`
- Browser downloads
- `MFT/USN`
- Prefetch
- Defender
- Scheduled Tasks
- Registry
- SRUM

The following activities are created:

- `powershell_download`
- `powershell_encoded_execution`
- `powershell_defender_tampering`
- `powershell_persistence`
- `powershell_recon`
- `powershell_credential_access`
- `downloaded_and_executed_via_powershell`

## Common false positives

- legitimate administration with PowerShell
- corporate automation
- support or troubleshooting transcripts
- login scripts
- `ExecutionPolicy Bypass` in internal tooling

## Limitations

- `ConsoleHost_history.txt` usually has no per-command timestamps
- observed history does not equal confirmed success or execution
- observed scripts do not prove execution
- Base64 decoding is preview-only and never executes content
- credentials or secrets are not structured even if they appear in raw form

## Investigation examples

- `Invoke-WebRequest` followed by a file created in `Downloads` and a Defender detection
- `IEX(New-Object Net.WebClient)...` correlated with `4104`
- `Set-MpPreference -DisableRealtimeMonitoring` before a failed detection
- `schtasks /Create` or `Register-ScheduledTask` correlated with Scheduled Tasks XML
