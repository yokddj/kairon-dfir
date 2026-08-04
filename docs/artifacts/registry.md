# Registry / RECmd

## What the Windows Registry is

The Windows Registry is a hierarchical database where the system and applications store:

- configuration
- persistence
- usage history
- connected devices
- user activity artifacts

In DFIR it is not used only for "configuration." It also helps answer:

- what programs were used
- what persistence existed
- what paths the user typed
- what USB devices were seen
- what RDP servers were used

## Why RECmd matters

RECmd allows parsing Registry hives and plugins to CSV. In this app it is currently the main path for parsed Registry:

- `*_RECmd_Output.csv`
- `RECmd_Output.csv`
- CSV outputs from RECmd Batch

## Hives that can feed this path

- `NTUSER.DAT`
- `UsrClass.dat`
- `SYSTEM`
- `SOFTWARE`
- `SAM`
- `SECURITY`
- `Amcache.hve` if exported in compatible CSV form

## Subtypes supported today

| Subtype | What it provides |
| --- | --- |
| Run Keys / RunOnce | Logon persistence |
| Services | Service persistence and configuration |
| UserAssist | Strong evidence of user-level use/execution |
| BAM / DAM | Execution observed by the system |
| MUICache | Presence or hint of use, not confirmed execution |
| USBSTOR / USB | Observed external devices |
| MountedDevices | Drive letters and volume mappings |
| TypedPaths | Paths typed in Explorer |
| RunMRU | Commands used in the Run box |
| RecentDocs | Recent documents |
| RDP MRU | RDP destination history |
| Shellbags | Folders browsed by the user |
| Registry generic | Rows not yet classified into a subtype |

## Main fields the app extracts

- `registry.hive`
- `registry.hive_path`
- `registry.key_path`
- `registry.key_name`
- `registry.value_name`
- `registry.value_type`
- `registry.value_data`
- `registry.last_write_time`
- `registry.artifact_type`
- `registry.plugin`
- `registry.batch`

Depending on the subtype, it may also fill:

- `process.path`
- `process.command_line`
- `service.image_path`
- `service.service_dll`
- `usb.vendor`
- `usb.product`
- `usb.serial`
- `volume.drive_letter`
- `destination.hostname`
- `shellbag.path`

## Key fields the analyst should review

When reviewing Registry events in `Artifact Explorer` or `Search`, the most useful fields are usually:

- `registry.artifact_type`
- `registry.hive`
- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `registry.last_write_time`
- `process.path`
- `process.command_line`
- `service.name`
- `service.image_path`
- `service.service_dll`
- `user.sid`
- `usb.vendor`
- `usb.product`
- `usb.serial`
- `destination.hostname`

In practice:

- for `Run Keys`, look mainly at `key_path`, `value_name`, `value_data`, and `process.command_line`
- for `Services`, look at `service.name`, `service.image_path`, `service.service_dll`, and `start_type`
- for `BAM/DAM` and `UserAssist`, look at `process.path`, `process.name`, `user.sid`, and `execution.last_run`
- for `USBSTOR`, look at `usb.vendor`, `usb.product`, `usb.serial`
- for `RDP MRU`, look at `destination.hostname`

## How the app interprets the main subtypes

### Run Keys

- `event.type = registry_run_key`
- category: `persistence`
- maps `ValueData` to `process.command_line`
- attempts to extract the executable into `process.path`

Example message:

```text
Run key persistence: Updater -> powershell.exe -enc aQ==
```

### Services

- `event.type = registry_service`
- category: `persistence`
- extracts `service.name` from the key path
- interprets `ImagePath`, `DisplayName`, `Start`, `Type`, `ObjectName`, `ServiceDll`

### UserAssist

- `event.type = userassist_execution`
- category: `execution`
- decodes ROT13 if the value is encoded
- fills `execution.run_count`, `execution.focus_time`, and `execution.last_run` when available

### BAM / DAM

- `event.type = bam_execution` or `dam_execution`
- category: `execution`
- uses the executable path as `process.path`
- if there is enough data, the summary should show the specific executable and not `unknown`

### MUICache

- `event.type = muicache_entry`
- category: `execution`
- must **not** be interpreted as confirmed execution by itself
- treated as a hint or clue of presence/use

### USBSTOR / USB

- `event.type = usb_device_seen`
- category: `device`
- attempts to extract vendor, product, and serial from `KeyPath`

### MountedDevices

- `event.type = mounted_device`
- category: `device`
- attempts to extract `volume.drive_letter` and `volume.guid`

### TypedPaths

- `event.type = typed_path`
- category: `file_access`
- uses `ValueData` as `file.path`

### RunMRU

- `event.type = run_mru_command`
- category: `execution`
- uses `ValueData` as `process.command_line`

### RecentDocs

- `event.type = recent_document`
- category: `file_access`
- attempts to fill `file.path` or `file.name`

### RDP MRU

- `event.type = rdp_mru`
- category: `remote_access`
- fills `destination.hostname`

### Shellbags

- `event.type = shellbag_folder_access`
- category: `file_access`
- fills `shellbag.path`

## How to interpret LastWriteTime

`LastWriteTime` is the timestamp of the registry **key**, not always of the specific value.

This means:

- it is very useful for ordering activity
- but it does not always equal the exact moment the user executed something

## What each artifact means in terms of confidence

- **High utility for execution**: `UserAssist`, `BAM`, `DAM`
- **Very useful for persistence**: `Run Keys`, `Services`
- **Very useful for user history**: `RunMRU`, `TypedPaths`, `RecentDocs`, `Shellbags`
- **Useful as a clue, not confirmed execution**: `MUICache`
- **Useful for device context**: `USBSTOR`, `MountedDevices`

## Correlation with other evidence

The app attempts to correlate Registry with:

- EVTX `4688`, `7045`, `4697`, RDP
- Prefetch / `PECmd_Output.csv`
- LNK / `LECmd_Output.csv`
- Jump Lists / `JLECmd_Output.csv`

Examples:

- Run key + `4688` or Prefetch for the same binary
- Service registry + `7045` / `4697`
- UserAssist + Prefetch
- RecentDocs / TypedPaths / Shellbags + LNK / Jump Lists
- RDP MRU + RDP events from EVTX

## Use in Semi-automated Analysis

Registry already feeds:

- `Persistence`
- `Executed programs`
- `User activity`
- `USB devices`
- `RDP`
- `Opened files`
- `Suspicious findings`
- `Timeline`

## Current limitations

- `LastWriteTime` belongs to the key, not always to the value.
- `MUICache` does not demonstrate confirmed execution.
- `USBSTOR` does not by itself imply file copying.
- Services from the registry are indexed per row; there is not yet "perfect" grouping of all values into a single entity.
- Some RECmd Batch outputs change columns depending on the plugin and may require extending the parser in future sprints.

## Suspicious persistence: practical examples

### Run key with encoded PowerShell

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Updater = powershell.exe -enc ...
```

What to check:

- actual path of the script or binary
- affected user
- correlation with `4688`, `4104`, and Prefetch

### Service in a user path

```text
HKLM\SYSTEM\CurrentControlSet\Services\BadSvc\ImagePath
C:\Users\Public\svc.exe
```

What to check:

- `ImagePath`
- `ServiceDll`
- `Start`
- `ObjectName`
- correlation with `7045`, `4697`, Prefetch, and detections

## Common false positives

- internal logon scripts in Run keys
- legitimate software with services in unusual paths
- RunMRU commands executed by administrators
- MUICache with binaries already deleted
- authorized corporate USB devices or external drives
