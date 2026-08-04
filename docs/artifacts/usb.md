# Enriched USB

## What USB evidence the app supports

The app now supports:

- raw `setupapi.dev.log`
- CSVs from `USBSTOR`, `USB`, `MountedDevices`, `PortableDevices`, and similar
- correlation with `LNK`, `JumpLists`, `Shellbags`, `MFT/USN`, `Recycle Bin`, `Browser`, and `PowerShell`

## What `SetupAPI.dev.log` provides

`SetupAPI.dev.log` allows extraction of device installation/configuration blocks and, when the content allows:

- `Device Instance ID`
- `Vendor`
- `Product`
- `Revision`
- `Serial`
- `Service`
- `INF`
- driver version/provider
- section timestamps

Important:

- not every block containing the word `USB` represents a specific external device
- `Install Driver Updates` usually reflects generic driver update/publishing activity
- `USB\\Class_07`, `USB\\Class_08`, `USB\\ROOT_HUB`, and similar are generic classes or controllers

## What Registry USBSTOR / MountedDevices provides

Parsed registry artifacts can enrich:

- serials
- `FriendlyName`
- `ContainerId`
- `ParentIdPrefix`
- `Volume GUID`
- `Drive letter`
- `MountedDevice` / `DosDevices`

## What is parsed directly from Velociraptor

Directly supported:

- `C:\\Windows\\INF\\setupapi.dev.log`

Discovery-only in this iteration if received raw:

- `SYSTEM`
- `SOFTWARE`
- `NTUSER.DAT`

## What the app considers a "useful" USB

The app prioritizes useful identifiers such as:

- `USBSTOR\\Disk&Ven_...&Prod_...&Rev_...\\SERIAL`
- `USB\\VID_XXXX&PID_YYYY\\SERIAL`
- `SWD\\WPDBUSENUM\\...`
- `WPD\\...`
- `STORAGE\\Volume\\...`

Generic driver update blocks or USB classes without a useful serial are omitted from the main flow or treated as low-value diagnostics.

## How to interpret `Device Instance ID`

Common examples:

- `USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0`
- `USB\\VID_0781&PID_5581\\1234567890ABCDEF`

The app attempts to extract:

- `vendor`
- `product`
- `revision`
- `serial`
- `vid`
- `pid`
- `device_type`

It always also keeps `usb.raw_instance_id`.

## Volume and drive letter

The drive letter is not a strong identity by itself.

Correlation prioritizes:

- `serial`
- `device_instance_id`
- `volume.serial`
- `volume.guid`
- `container_id`
- `parent_id_prefix`

## Observed USB, access, and possible exfiltration

The app uses cautious wording:

- `usb_device_install` / `usb_device_observed`: device observed
- `usb_volume_mapping`: observed volume or drive letter mapping
- `usb_file_access` / `usb_folder_access`: activity on a removable path
- `possible_usb_exfiltration_candidate`: hypothesis of data copy or exfiltration

A connected USB does not imply exfiltration.

## Correlation with other artifacts

- `LNK`: removable paths, `volume.serial`, `drive_type`
- `JumpLists`: recent files on removable paths
- `Shellbags`: folders viewed on an external drive
- `MFT/USN`: creations/modifications/deletions on removable paths
- `Recycle Bin`: files deleted/recycled from an external drive
- `Browser`: downloads directly to `E:\\`, `F:\\`, etc.
- `PowerShell`: `Copy-Item`, `robocopy`, `xcopy`, `move`, compression to a removable drive

## Common false positives

- legitimate corporate USB drives
- external backup drives
- manual downloads saved to USB
- portable administration tooling

## Limitations

- `SetupAPI.dev.log` usually indicates installation/configuration, not every exact connection
- the drive letter can change
- the serial may be missing or not very distinctive
- accessing a file on USB does not equal copying it
- `possible_usb_exfiltration_candidate` is a hypothesis, not an automatic conclusion
- some `SetupAPI` blocks are deliberately omitted for low value, to avoid operational false positives
