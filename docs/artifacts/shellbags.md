# Shellbags

## What the app supports

- `SBECmd_Output.csv`
- `*_SBECmd_Output.csv`
- `*Shellbags*.csv` variants
- raw discovery from Velociraptor of `NTUSER.DAT` and `UsrClass.dat`

## What they provide

Shellbags help answer which folders were viewed or browsed by the user via Explorer or shell components. They do not prove execution.

## What is parsed directly

- CSV parsed by `SBECmd`

## What remains as raw discovery

- `NTUSER.DAT`
- `UsrClass.dat`
- associated logs

When only raw hives appear, the UI shows them as `detected_not_implemented` and recommends using parsed `SBECmd` instead.

## Extracted fields

- folder path
- bag path
- hive/source file
- shell type
- MRU / slot / node slot
- available timestamps
- user / SID if present
- network, USB, cloud, control panel, and deleted/missing candidate flags

## Forensic interpretation

- Shellbags indicate navigation or interaction with folders.
- They do not imply execution.
- They are very useful for USB paths, UNC paths, deleted or no-longer-existing folders, and folders viewed by the user.

## Main correlations

- LNK
- JumpLists
- MFT/USN
- Recycle Bin
- Browser downloads
- PowerShell
- Defender
- USBSTOR / MountedDevices

## Limitations

- Shellbags do not prove execution.
- The raw hive parser is not implemented in this iteration.
- Virtual or Control Panel paths can generate noise.
- Timestamps can vary depending on the source and Windows version.
