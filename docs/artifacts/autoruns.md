# Autoruns / ASEP

## What it is

Autoruns / ASEP summarizes Windows auto-start and persistence mechanisms:

- Run / RunOnce
- Startup folder
- Services / Drivers
- Scheduled Tasks
- WMI persistence
- Winlogon
- IFEO Debugger
- AppInit / AppCert DLLs
- LSA Providers
- Print Monitors
- Shell Extensions
- Office add-ins

The platform treats these entries as observed or candidate persistence, not as execution confirmed on their own.

## What the app supports

- Autoruns CSV
- Autoruns TSV
- Autoruns XML
- Autorunsc output
- startup folder files detected from raw collections
- correlation with Registry, Scheduled Tasks, WMI, PowerShell, Defender, Prefetch, Amcache, MFT, Browser, and BITS

## What is parsed directly from Velociraptor

If a raw collection includes already-parsed Autoruns output, the app ingests it directly.

It also detects:

- Startup folder files
- `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, `UsrClass.dat` as ASEP candidates
- Task XML
- raw WMI repository as a related candidate

## What remains discovery-only

If only raw hives or a raw WMI repository are present:

- they are preserved as candidates
- they are not falsely marked as parsed
- the recommended parser is still RECmd / Scheduled Tasks / WMI depending on the case

## Extracted fields

- category, entry location, entry, enabled
- profile / user / SID
- image path, launch string, command line, arguments
- publisher, signer, signed, verified
- MD5 / SHA1 / SHA256 hashes / PE hashes
- VT detection / link if present
- normalized persistence mechanism

## How to interpret signed / verified / publisher

- `signed` or `verified` helps prioritize, but does not guarantee benignity
- absence of a signature does not prove malice either
- Microsoft-signed in standard paths usually lowers priority
- unsigned or unknown in AppData / Temp / ProgramData usually raises it

## How to interpret VT detection

- `vt_detection > 0` is an additional signal
- it should not be used in isolation
- it has more value when it coincides with a suspicious path, LOLBins, a prior download, or subsequent execution

## Correlations

The semi-automatic layer links Autoruns with:

- PowerShell that creates Run keys, tasks, services, or WMI
- Browser / BITS that download the target before it persists
- MFT / USN that create or modify the target near the timestamp
- Prefetch that executes the target afterward
- Defender that detects the target
- WMI / Scheduled Tasks / Registry when they reflect the same mechanism

## Common false positives

- legitimate updaters in `Run`
- corporate software with its own services or tasks
- shell extensions, Office add-ins, and BHOs from known software
- unsigned internal or legacy binaries

## Limitations

- Autoruns reflects observed state, not always the actual creation date
- a disabled entry can still be relevant
- a valid signature does not guarantee benignity
- absence of a signature does not guarantee malice
- raw hives and part of the aggregated ASEP still depend on already-existing specialized parsers

## Investigation examples

1. `Run key -> AppData -> unsigned -> Browser/BITS download -> Prefetch`
2. `IFEO Debugger -> cmd /c payload`
3. `Winlogon Shell -> binary outside standard paths`
4. `Startup folder -> script or LOLBin`
