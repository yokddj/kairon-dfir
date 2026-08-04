# Prefetch / PECmd / Native Prefetch

## What Prefetch is

Prefetch is a Windows mechanism that records summarized information about program executions. In Kairon DFIR the following can be consumed:

- `*_PECmd_Output.csv`
- `PECmd_Output.csv`
- raw `.pf` files detected directly in `C:\Windows\Prefetch\*.pf`

The CSVs usually come from Eric Zimmerman's **PECmd**. Raw `.pf` files can be parsed natively within the platform.

## What it provides in Kairon DFIR

Prefetch helps answer questions such as:

- Which binaries were executed?
- How many times were they executed?
- What was the last observed execution?
- What files or directories were related to that execution?

It does not replace EVTX and does not by itself prove malicious intent, but it adds a very useful source of **execution evidence**.

## Main fields used

Kairon DFIR tries to extract at least:

- `ExecutableName`
- `ExecutablePath` when it can be inferred
- `RunCount`
- `LastRun` / `LastRunTime`
- `PreviousRun0..7`
- `SourceFilename` / `SourceFile`
- `FilesLoaded`
- `ReferencedFiles`
- `Directories`
- `VolumeSerialNumber`
- `VolumeDevicePath`
- `Version`
- `Signature`

## What RunCount means

`RunCount` is the execution counter observed in the Prefetch artifact. It is useful for distinguishing between:

- an isolated execution
- a repeatedly used tool
- binaries that are part of normal operation of the machine

It should not be interpreted alone. A high `RunCount` can be benign.

## What LastRun and PreviousRuns mean

- `LastRun`: last execution observed by Prefetch.
- `PreviousRuns`: earlier executions preserved in the Prefetch file.

Kairon DFIR uses, in order:

1. `LastRun` as the main `@timestamp` if it exists
2. the last available value of `last_runs` if there is no `LastRun`
3. `source_modified` / `source_file_mtime` only as a fallback

The actual parsing time is stored in `ingest.processed_at` and must not be used as forensic time.

## What referenced files are

PECmd can expose files and directories related to the execution.

Kairon DFIR stores them in:

- `prefetch.referenced_files`
- `prefetch.directories`

This is useful for detecting:

- scripts in `Downloads`
- binaries in `AppData`
- execution supported by suspicious files

## What confirmed execution means

In the platform:

- `execution.source = prefetch`
- `execution.is_execution_confirmed = true`
- `execution.confidence = high`

because Prefetch, when it exists and is enabled, is strong evidence of program execution.

This does not imply:

- a known command line
- a known user
- a known parent process

## How it's used in the app

Today Prefetch mainly feeds:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Semi-automated Analysis`

## What the semi-automated analysis shows

### Executed programs

Includes Prefetch events such as:

- process name
- inferred path
- `run_count`
- `last_run`
- number of `previous_runs`
- confidence
- suspicious reasons

### PowerShell

If the executable is:

- `powershell.exe`
- `pwsh.exe`

Kairon DFIR also includes it in the `PowerShell` section with the message:

> PowerShell execution observed via Prefetch

### Suspicious findings

Prefetch can generate signals if it detects:

- LOLBins (`powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`, etc.)
- suspicious paths
- referenced files in `AppData`, `Temp`, `Downloads`, `Users\\Public`, `ProgramData`, UNC paths, etc.

## Correlation with EVTX 4688

Kairon DFIR attempts a basic correlation between:

- EVTX `4688` (`process_creation`)
- Prefetch `program_execution`

when the following conditions are met:

- same host
- same `process.name`
- close timestamps, 10 minutes by default

If a match is found, the semi-automated analysis groups both pieces of evidence into the same activity with higher confidence.

## Native parser vs PECmd

- `PECmd` is usually more convenient when you already have the parsed output.
- `native_prefetch` allows working directly with `.pf` files from Velociraptor, a raw ZIP, or a copied tree.
- Both must converge on the same execution model so that Search, Timeline, SIEM, and SemiAuto are not duplicated.

## Current limitations

- Prefetch can be disabled on the system.
- It does not always provide a `command line`.
- It does not always allow inferring the user.
- It does not by itself prove that an action is malicious.
- It does not indicate parent process.
- A fully resolvable path for the executable is not always available.
- Correlation with EVTX 4688 is basic; it does not replace manual review.

## How to verify it works

1. Import a `PECmd_Output.csv`.
2. Verify that the artifact is detected as:
   - `artifact.type = prefetch`
   - `artifact.parser = zimmerman`
3. Search for `powershell.exe` or `cmd.exe` in `Search`.
4. Check `Semi-automated Analysis > Executed programs`.
5. Verify that the following appear:
   - `run_count`
   - `last_run`
   - `Source = prefetch`
6. If the binary is PowerShell, also check the `PowerShell` section.

## False positives and caveats

- A LOLBin does not by itself imply compromise.
- A binary in `Downloads` or `AppData` deserves review, but does not automatically equate to malware.
- A high `RunCount` may correspond to legitimate repeated use.
