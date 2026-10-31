# Shellbags

## What the app supports

- Raw `UsrClass.dat` and `NTUSER.DAT` of each user profile (Velociraptor or KAPE
  collections, uploaded folders): the **Shellbags** step of recommended indexing (or
  `POST /api/evidences/{id}/shellbags-index`) runs Eric Zimmerman's **SBECmd** on the
  Linux worker (`backend/app/ingest/raw_parsers/sbecmd_backend.py`). Each hive is
  staged in its own folder with its `.LOG1`/`.LOG2` transaction logs when the
  collection kept them. Service-profile hives are skipped.
- `SBECmd_Output.csv`, `*_SBECmd_Output.csv` and `*Shellbags*.csv` uploaded by the
  analyst.

Both go through the same normalizer; documents are `artifact.type = shellbags`, and
raw-hive ones have `artifact.parser = sbecmd_csv`, the hive path in
`shellbag.hive_path` and the profile owner as `user.name`.

## What they provide

Shellbags help answer which folders a user viewed or browsed through Explorer or
shell dialogs, including network shares, removable drives and folders that no longer
exist. They do not prove execution.

## Paths

SBECmd's `AbsolutePath` walks the shell namespace (`Desktop\This PC\C:\Users\alice`,
`Desktop\Computers and Devices\srv01\srv01\share\dir`). The normalizer derives the
filesystem path from it:

- from the drive letter: `C:\Users\alice`;
- from a network location: `\\srv01\share\dir`;
- namespace-only items (known folders such as `Desktop\Downloads`, GUID folders,
  devices) keep the shell path.

`file.path` holds that filesystem path and `shellbag.absolute_path` the original
shell path. Path rules (network share, user-writable folder, suspicious tool folder)
read the filesystem path, so a folder on `C:` is no longer taken for a Control Panel
item because its shell path contains "This PC".

## Flags

- network share (`shellbag_network_folder`, `network.destination_hostname`,
  `network.share_name`);
- `rdp_client_drive`: a `\\tsclient\...` folder, the RDP client's own disk browsed
  from inside the session;
- removable/USB, cloud sync folder, Control Panel item (by shell type), suspicious tool
  or payload folder, deleted or missing candidate.

Browsing a share is routine in a domain and raises no risk on its own.

## Timestamps

The event time is, in order: `LastInteracted` (the parent key's last write when the
item is first in MRU order), `FirstInteracted` (the item's own key when it has no
children), the key's last write, then the shell item's own times.
`timestamp_precision` says which one was used.

## Limitations

- Shellbags do not prove execution.
- Timestamps vary with the Windows version and with how the shell updated the key.

## Main correlations

LNK, Jump Lists, MFT/USN, Recycle Bin, browser downloads, PowerShell, Defender,
USBSTOR / MountedDevices, lateral movement (logons to the hosts whose shares were
browsed).
