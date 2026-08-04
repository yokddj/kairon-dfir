# Cloud Sync

## What it is

`Cloud Sync` groups evidence of cloud sync clients and locally synced folders. In Kairon DFIR it is not interpreted by default as confirmed exfiltration.

Providers covered:

- OneDrive
- Google Drive / Drive for Desktop / DriveFS
- Dropbox
- MEGAsync
- iCloud Drive
- Box Drive / Box Sync
- generic cloud folders detected by path

## What the app supports

The app supports:

- discovery of sync roots and configuration/log paths
- generic cloud CSV/JSON parsing
- basic parsing of simple text logs
- path-based inference on already normalized events
- correlation with Browser, BITS, PowerShell, MFT/USN, LNK, JumpLists, Recycle Bin, Defender, Autoruns, Scheduled Tasks, WMI, and USB

## What is parsed directly from Velociraptor

If the collection already contains small parsed outputs or readable logs/configs, the app can process:

- `*OneDrive*.csv`
- `*GoogleDrive*.csv`
- `*DriveFS*.csv`
- `*Dropbox*.csv`
- `*MEGAsync*.csv`
- `*iCloud*.csv`
- `*BoxDrive*.csv`
- `*CloudSync*.json`
- small recognizable client logs/configs

It also detects sync roots observed by path without extracting all of their content by default.

## What remains as discovery

Detected as discovery or `path_inference`:

- complete OneDrive/Dropbox/Google Drive/MEGA/iCloud/Box folders
- large `DriveFS` paths
- unparsed configs or proprietary databases

The app does not massively extract complete cloud folders by default.

## Extracted fields

- provider
- account / email if present
- sync root
- local path
- remote path / cloud path
- status / sync status
- sync, upload, download, and file activity timestamps
- URL/domain if present
- direction / detection_method / confidence

## Cloud artifact types

The app distinguishes between:

- `cloud_client_config`: cloud client configuration, e.g. `OneDrive\\settings\\ECSConfig.json`
- `cloud_client_log`: cloud client logs, e.g. `OneDrive\\logs\\...`
- `cloud_sync_root`: actual synced root, e.g. `C:\\Users\\user\\OneDrive` or `C:\\Users\\user\\Dropbox`
- `cloud_file_activity`: file observed inside a cloud folder
- `cloud_staging_candidate`: cautious evidence of staging toward cloud
- `possible_cloud_exfiltration`: cloud exfiltration candidate, not confirmed upload

A `cloud_client_config` or `cloud_client_log` is not interpreted as a sync root or as an upload.

## Sync roots and cloud activity

The app distinguishes between:

- `cloud folder observed`
- `cloud client config`
- `cloud client log`
- `cloud file activity`
- `cloud staging candidate`
- `possible cloud exfiltration candidate`

A file inside OneDrive or Dropbox does not prove an upload. To raise confidence, the app looks for:

- sensitive files inside the sync root
- archives created inside the sync root
- copy or compression activity toward cloud
- Browser/BITS downloads directly to cloud
- many files created or modified in a short window
- Defender detections or subsequent deletion in Recycle Bin

## Correlations

It is correlated with:

- Browser history and downloads
- BITS `local_path`
- PowerShell `Copy-Item`, `Move-Item`, `Compress-Archive`, `robocopy`, etc.
- MFT/USN in cloud paths
- LNK and JumpLists with targets in cloud folders
- Recycle Bin with `original_path` in cloud
- Defender detections in cloud paths
- Prefetch / Amcache / ShimCache if content is executed from cloud
- Autoruns / Scheduled Tasks / WMI if persistence points to cloud
- USB when there are matching names/paths and temporal proximity

## Common false positives

- normal collaborative work in OneDrive or Google Drive
- legitimate backups or zips in synced folders
- internal scripts or tools shared between users
- legitimate mass sync after migrations

## Limitations

- a file inside a cloud folder does not prove an actual upload
- many clients do not leave useful local logs
- `DriveFS` may use virtual paths
- `sync status` or `last_upload_time` may be missing
- complex proprietary databases are not parsed yet

## Investigation examples

Investigate first as `possible cloud staging` when you see:

- `credentials.kdbx`, `backup.zip`, or `export.db` inside OneDrive/Dropbox
- `Copy-Item` or `robocopy` toward the sync root
- Browser/BITS downloading directly to cloud
- Defender detecting a payload inside the sync root

Only escalate to an exfiltration hypothesis when there is also a reasonable chain of staging, compression, or explicit sync.
