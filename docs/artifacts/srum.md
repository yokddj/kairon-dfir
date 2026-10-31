# SRUM

SRUM (`System Resource Usage Monitor`) keeps roughly 30-60 days of per-application
resource and network usage in `C:\Windows\System32\sru\SRUDB.dat`, an ESE (Jet Blue)
database.

## How it is parsed

- **Raw `SRUDB.dat`**: the **SRUM** step of recommended indexing (or
  `POST /api/evidences/{id}/srum-index`) reads the database natively with
  `dissect.esedb` (`backend/app/ingest/raw_parsers/srum_esedb.py`). SrumECmd cannot
  be used on the Linux worker: it refuses to run outside Windows because it loads
  `esent.dll`. Where SrumECmd can run (a Windows host), it is used instead.
- The native reader writes one CSV per provider table with **SrumECmd's column
  names** (`SRUM_NetworkUsages.csv`, `SRUM_NetworkConnections.csv`,
  `SRUM_AppResourceUseInfo.csv`, `SRUM_AppTimelineProvider.csv`,
  `SRUM_EnergyUsage.csv`, `SRUM_PushNotifications.csv`, `SRUM_vfuprov.csv`), so the
  same normalizer handles it and a SrumECmd CSV uploaded by the analyst.
- `artifact.parser` records which one ran: `srum_esedb` or `srumecmd_csv`.
- The step is offered only when discovery saw a `SRUDB.dat`.

Validated against SrumECmd's own output for the same machine: every column of the
rows both contain matched (network usage, connections, application resource use,
energy, vfuprov), except where Kairon is deliberately different (below).

### Differences from SrumECmd

- `UserName`: well-known SIDs get the account name (`SYSTEM`, `LOCAL SERVICE`,
  `NETWORK SERVICE`); other SIDs are named from the `ProfileList` of the `SOFTWARE`
  hive collected next to `SRUDB.dat` (`System32\config\SOFTWARE`) when it is there.
  SrumECmd prints the profile folder (`systemprofile`) and left user SIDs blank.
- Energy rows without the long-term columns leave them empty instead of `-1`.
- Packaged-app executables (`<package>!<app>!RuntimeBroker.exe!<stamp>!<hash>!`) are
  split into the executable (`ExeInfo`) and the package (`ExeInfoDescription`), like
  SrumECmd already does for `!!svchost.exe!...![group]`.
- `ProfileName` (the Wi-Fi SSID) is not resolved; `L2ProfileId` is kept.
- Pending changes in the ESE transaction logs (`SRU*.log`) are not replayed; what is
  read is what the database file holds. SrumECmd does not replay them either.

## What each table gives

| Table | `srum.artifact_type` | Meaning |
| --- | --- | --- |
| Network Usage | `srum_network_usage` | Bytes sent/received per application, user and interface, per hour. |
| Network Connectivity | `srum_network_connectivity` | When an interface connected (`ConnectStartTime`) and for how long (`srum.duration`, seconds). |
| Application Resource Usage | `srum_app_resource` | CPU cycles and disk I/O per application (foreground/background). |
| App Timeline | `srum_app_timeline` | Application activity windows (`EndTime`, duration). |
| Energy Usage | `srum_energy` | Battery and power state. |
| Push Notifications | `srum_push_notification` | Notifications delivered to an application. |
| vfuprov | `srum_vfu` | Indexed as SrumECmd outputs it; its semantics are not documented. |

SrumECmd's `AppId` column is an index into `SruDbIdMapTable`, not a name; the
application is `ExeInfo` (an NT device path, a service name, a package name or a
`svchost.exe` service group in `srum.exe_description`).

## Leads

Risk is only raised on **network usage** rows (the other tables show that an
application ran, not that it used the network):

- remote-access and transfer tool names (AnyDesk, TeamViewer, rclone, WinSCP, ngrok,
  Tor...), matched on the application name, not on folder names;
- LOLBins and script hosts with network use (PowerShell, certutil, rundll32...);
- executables in Downloads, Temp, `Users\Public` or on the Desktop; AppData alone is a
  low-risk lead, since most per-user installs (OneDrive, Teams...) live there; the
  Defender platform folder under ProgramData is not user-writable;
- high or upload-heavy outbound volume.

Rows SRUM could not attribute to an application (an empty `SruDbIdMapTable` entry)
and Delivery Optimization (`DoSvc`, which uploads updates to other machines by design)
raise no volume lead. Sync clients (OneDrive, Dropbox, Google Drive) are tagged
`cloud_sync` only.

## Interpretation

SRUM does not record destination IPs or domains. Treat it as per-application usage
context, aggregated per hour, and correlate with process, network and browser
evidence. It does not by itself prove execution.
