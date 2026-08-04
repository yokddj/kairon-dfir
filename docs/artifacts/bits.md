# BITS

## What it is

BITS (`Background Intelligent Transfer Service`) is the Windows service used for background transfers.

It can be legitimate:

- Windows Update
- Microsoft Store
- normal browsers and applications

But it can also be abused to:

- download payloads
- maintain persistent jobs
- run notify commands
- hide network activity inside a legitimate service

## What the app supports

- raw discovery of `qmgr0.dat`, `qmgr1.dat`, and `qmgr.db` from Velociraptor
- parsed BITS CSV
- parsed BITS JSON
- `bitsadmin`-type output
- correlation with PowerShell, Browser, Defender, MFT/USN, Prefetch, LNK/JumpLists, and Scheduled Tasks

## What is parsed directly from Velociraptor

In this iteration:

- `qmgr*.dat` and `qmgr.db` are detected and preserved as raw
- they are not yet parsed as a binary database
- BITS EVTX are detected as `handled_by_evtx_parser`

This means:

- raw `qmgr` = honest discovery, not fake parsing
- parsed CSV/JSON/TXT = real support

## What fields are extracted

- Job ID / GUID
- display name
- owner / owner SID
- state
- type
- priority
- remote URL / remote name
- local path / local name
- bytes total / transferred
- files total / transferred
- creation / modification / completion / expiration times
- notify command
- error code / description

## How to interpret BITS states

- `queued`, `connecting`, `transferring`: active or pending job
- `transferred`: transfer completed, does not imply execution
- `acknowledged`: job completed and acknowledged
- `suspended`, `error`, `transient_error`: failed or stalled job

## Notify command

`notify_cmd_line` is especially important:

- it can run a command when the job completes
- it can be persistence or legitimate automation
- it rises significantly in value if it uses `powershell`, `cmd /c`, `mshta`, `rundll32`, or `regsvr32`

## Difference between legitimate use and possible abuse

A BITS job is not suspicious on its own.

It rises in interest if it coincides with:

- an unusual external URL or direct IP
- plain HTTP for scripts or executables
- `AppData`, `Temp`, `ProgramData`, `Public`, `Startup`
- `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.msi` payloads
- notify command
- subsequent correlation with PowerShell, Defender, MFT, or execution

## Correlation

The app cross-references BITS with:

- PowerShell: `Start-BitsTransfer`, `bitsadmin`, `Add-BitsFile`, `Set-BitsTransfer`
- Browser: same URL or same target path
- Defender: `bits.local_path`
- MFT/USN: creation/modification of the local file
- Prefetch / execution: downloaded file executed afterward
- Scheduled Tasks: task that runs the downloaded file
- JumpLists / LNK: downloaded file later opened
- SRUM: background network context

## Common false positives

- Windows Update
- Microsoft Store
- corporate installers
- third-party applications that use BITS as a legitimate backend

## Limitations

- raw `qmgr` still has no dedicated parser
- Windows Update generates a fair amount of benign noise
- a job does not prove execution on its own
- `source_file_mtime` is only a temporary fallback if the job's own timestamps are missing

## When to consider BITS strong evidence

Confidence rises if several pieces are present at once:

- clear `remote_url`
- clear `local_path`
- completion/modification timestamp
- notify command
- correlation with PowerShell
- file creation in MFT
- subsequent execution in Prefetch/EVTX
- subsequent detection by Defender
