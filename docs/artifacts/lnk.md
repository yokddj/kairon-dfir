# LNK / LECmd / native_lnk

## What LNK files are

`.lnk` files are Windows shortcuts. They usually represent that a user opened or interacted with:

- a document
- a script
- an executable
- a folder
- a network path
- a removable drive

## Why they matter in DFIR

A `.lnk` doesn't always mean execution, but it can provide very useful clues about:

- files opened by the user
- scripts launched from `Downloads`, `Desktop`, or `AppData`
- access to `UNC` network resources
- possible access to USB or removable volumes
- correlation with EVTX `4688` and Prefetch

## What LECmd provides vs. what the native parser provides

`LECmd_Output.csv` allows extraction of:

- the source `.lnk` file
- the target path
- arguments
- working directory
- target timestamps
- volume information
- network data
- `MachineID`

The native `lnk_raw` parser can now ingest raw shortcuts directly from Velociraptor collections or triage ZIPs at paths such as:

- `Recent`
- `Office\\Recent`
- `Desktop`
- `Downloads`
- `Start Menu`
- `Startup`

## Difference between source file and target path

- `source file`: the `.lnk` itself, for example `C:\Users\analyst\Desktop\runme.lnk`
- `target path`: the resource it points to, for example `C:\Users\analyst\Downloads\runme.ps1`

This matters because the `.lnk` may continue to exist even after the target has disappeared.

## Effective LNK target path

`LECmd` can return several paths or pseudo-paths for the same access:

- `TargetPath`
- `TargetIDAbsolutePath`
- `LocalPath`
- `CommonPath`
- `NetworkPath`
- `RelativePath`
- `WorkingDirectory`

Not all of them are equally useful to the analyst. Values like `Desktop\\` or `Internet Explorer (Homepage)` are **shell targets** or partial paths.

That's why the app calculates:

- `lnk.effective_path`
- `lnk.effective_path_source`
- `lnk.display_name`

### Priority used by the app
1. `LocalPath + CommonPath`
2. `LocalPath`
3. `TargetPath`
4. `TargetIDAbsolutePath`
5. `NetworkPath`
6. `RelativePath`
7. `Description / NameString` if it looks like a path
8. `SourceFile` as a last fallback

### Real example

If `LECmd` returns:

- `TargetIDAbsolutePath = Desktop\\`
- `LocalPath = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`

the normalized event will show:

- `lnk.effective_path = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`
- `lnk.effective_path_source = local_path`
- `file.path = C:\Users\analyst\Desktop\DFIRLabEvidence\DFIRLab-training-dataset`

This way `Search`, `Artifact Explorer`, and `Semi-automated Analysis` stop showing useless summaries like `Desktop\\`.

## What TargetCreated / Modified / Accessed mean

These are timestamps of the **target recorded inside the LNK**, not necessarily the exact moment the user clicked it.

Kairon DFIR uses the following priority:

1. `TargetAccessed`
2. `SourceModified`
3. `SourceCreated`
4. `TargetModified`
5. `candidate/source file mtime`

## What MachineID means

`MachineID` usually points to the machine where the shortcut was created or resolved. It can help to:

- identify the host
- correlate activity between accesses
- detect whether the access appears to come from the machine itself or from another context

## What DriveType and VolumeSerial indicate

They can suggest:

- fixed volume
- removable drive
- possible USB

They don't prove by themselves that the access was malicious, but they are very useful for context.

## How to detect USB or UNC paths

Kairon DFIR flags as interesting:

- `\\host\share\...`
- paths with `NetworkPath`, `NetName`, or `ShareName`
- `DriveType` that appears removable

## How it's used in the app

Today LNK feeds:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Semi-automated Analysis`
- `Debug Export Pack`

## What the semi-automated analysis shows

### Opened files

- timestamp
- user
- effective target
- extension
- source LNK
- drive type
- network path
- confidence
- suspicious reasons

### Opened scripts

If the target is `.ps1`, `.bat`, `.cmd`, `.js`, etc., the access is highlighted as `script_opened`.

### Startup persistence

If the `.lnk` is in a `Startup` folder, the event is normalized as `startup_lnk` and fills the `persistence.*` namespace.
This still does not prove execution by itself; it is treated as `possible startup persistence via LNK`.

### Network paths

If the target is UNC or uses `NetworkPath`, it also appears as `network_path_opened`.

### USB / removable media

If `DriveType` indicates removable or USB candidate, it appears in `removable_media`.

## How it correlates with EVTX and Prefetch

Kairon DFIR attempts a basic correlation when:

- the LNK target matches the executable seen in Prefetch
- the target appears in `4688` or in `process.command_line`
- the target appears in `PowerShell` script blocks or commands
- the timestamps are close, 30 minutes by default

This does not replace manual review, but it significantly increases the forensic value of the shortcut.

## Current limitations

- An LNK indicates access or interaction, not always confirmed execution.
- Target timestamps come from the LNK, not always from the exact moment of opening.
- The `.lnk` may exist even if the target no longer exists.
- Not all fields always appear in every version of `LECmd`.
- Partial or shell-namespace targets (`Desktop\\`, `Control Panel`, etc.) are preserved with `partial_lnk_target` or `unresolved_lnk_target`.
- If the mapping changed and `lnk.effective_*` fields were added, older indexes will not show those fields until the case is reimported or the index is rebuilt.

## Common false positives

- documents legitimately opened
- normal access to corporate shares
- scripts or binaries used by administrators
- old LNKs that no longer represent current activity
