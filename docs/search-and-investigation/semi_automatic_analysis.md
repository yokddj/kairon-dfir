# Semi-automatic analysis

## What it is

It's a normalized-event grouping layer designed to answer more quickly the question:

> What happened on this host or this case?

It does not replace manual review. It summarizes relevant activity.

## Endpoint and view

- Backend: `GET /api/cases/{case_id}/analysis/semi-auto`
- Frontend: `Semi-automatic analysis`

## Current sections

### 1. Programs executed

| Field | Detail |
| --- | --- |
| What it looks for | Process creation and observed execution |
| Current evidence | EVTX 4688, Prefetch / PECmd, part of PowerShell, Registry / RECmd |
| EventIDs/artifacts | 4688, `PECmd_Output.csv`, `RECmd_Output.csv` (`userassist_execution`, `bam_execution`, `dam_execution`, `run_mru_command`, `muicache_entry`) |
| What it shows | timestamp, user, process, path, source, run count, last run, previous runs, confidence |
| How to interpret it | Look for anomalous executions, strange parents or suspicious paths |
| Current limitations | EVTX 4688 + Prefetch correlation is basic and relies on name, host and temporal proximity |
| Future | UserAssist, BAM/DAM, Amcache, stronger correlation with raw Prefetch |

### 2. PowerShell

| Field | Detail |
| --- | --- |
| What it looks for | Script blocks, module logging, pipeline execution, encoded command, download cradle |
| Current evidence | 4104, 4103, 800, 400, 403, Prefetch of `powershell.exe` / `pwsh.exe`, Jump Lists/LNK pointing to PowerShell scripts, `ConsoleHost_history.txt`, transcripts and observed PowerShell scripts |
| What it shows | script block, user, ScriptBlockId, suspicious reasons |
| How to interpret it | Prioritize encoded commands, downloads and Defender changes |
| Current limitations | `PSReadLine` usually has no per-command timestamp and an observed script does not equal confirmed execution |
| Future | more correlation with `4104`, enriched transcripts and better session grouping |

### 3. Logons

| Field | Detail |
| --- | --- |
| What it looks for | Successful, failed, explicit logons and special privileges |
| Current evidence | 4624, 4625, 4648, 4672 |
| What it shows | user, LogonType, source IP, workstation, status |
| How to interpret it | Review remote logons, service accounts and repeated failures |
| Current limitations | Coverage depends on the parsed EVTX being complete |
| Future | More correlation with WinRM, NTLM and Kerberos |

### 4. RDP

| Field | Detail |
| --- | --- |
| What it looks for | RDP authentications, reconnections and disconnections |
| Current evidence | 4624 LogonType 10, 1149, 21/22/23/24/25/39/40, 4778, 4779 |
| What it shows | user, source IP, summary, session |
| How to interpret it | Useful for remote access, pivots and late sessions |
| Current limitations | Not all RDP telemetry has the same level of detail |
| Future | Correlation with LNK, Prefetch and remote services |

### 5. Scheduled tasks

| Field | Detail |
| --- | --- |
| What it looks for | Task definitions, suspicious tasks, persistence and correlated execution |
| Current evidence | raw XML from `C:\\Windows\\System32\\Tasks\\*`, compatible Scheduled Tasks CSVs, 4698, 4699, 4700, 4701, 4702, 106, 140, 141, 200, 201, 102, 129 |
| What it shows | name, task path, command, arguments, RunAs, trigger summary, hidden/enabled, suspicious reasons |
| How to interpret it | Differentiate between observed definition, candidate persistence and execution observed through correlation |
| Current limitations | The XML describes configuration; confidence rises significantly when related EVTX, Prefetch, Browser, MFT or Defender data exists |
| Future | Registry `TaskCache` and stronger enrichment of TaskScheduler events |

### 6. Services

| Field | Detail |
| --- | --- |
| What it looks for | Services created or modified |
| Current evidence | 7045, 7040, 7036, 4697 |
| What it shows | name, image path, account, start type |
| How to interpret it | Focus on persistence and execution via service |
| Current limitations | Does not yet cross-reference strongly with Registry SYSTEM\\Services |
| Future | Registry and more correlation with the binary's Prefetch |

### 7. Network connections

| Field | Detail |
| --- | --- |
| What it looks for | Allowed connections and responsible application |
| Current evidence | 5156 |
| What it shows | app, source IP, destination IP, protocol |
| How to interpret it | Useful for seeing processes with network activity |
| Current limitations | SRUM is already included, but still doesn't provide exact IP/destination on its own and Sysmon 3 is still pending |
| Future | Sysmon and stronger network correlation |

## Browser activity

Semi-automatic analysis already incorporates:

- `browser_history`
- `downloaded_files`
- `web_searches`
- `cloud_activity`
- `suspicious_downloads`
- `downloaded_and_executed`

Basic correlation links downloads with:

- `MFT/USN`
- `LNK`
- `Jump Lists`
- `Prefetch`
- `EVTX 4688`
- `Defender`

These sections are fed both by parsed browser CSV/JSON and by the raw browser parser from Velociraptor collections.

## SRUM sections

- `network_activity`
- `application_network_usage`
- `high_upload_activity`
- `remote_access_activity`
- `possible_exfiltration`
- `downloaded_and_network_active_programs`

These sections use cautious wording: SRUM reinforces **per-application network activity**, not "confirmed exfiltration" nor an exact destination on its own.

## Scheduled Tasks sections

- `scheduled_tasks`
- `suspicious_tasks`
- `task_executions`
- `downloaded_and_persisted`

Operational interpretation:

- `scheduled_task_definition` and `scheduled_task_com_handler` mean **observed task**, not proven execution.
- The `scheduled_tasks` section summarizes configuration, principal, triggers and actions.
- `suspicious_tasks` prioritizes encoded PowerShell, LOLBins, UNC paths, scripts in user paths, `hidden + enabled` tasks and `ComHandler`.
- `task_executions` raises confidence when TaskScheduler/Security EVTX or related Prefetch/EVTX execution appears.
- `downloaded_and_persisted` links Browser downloads with task commands or arguments.

## PowerShell sections outside EVTX

- `powershell_activity`
- `powershell_downloads`
- `powershell_encoded_commands`
- `powershell_defender_tampering`
- `powershell_persistence`
- `powershell_recon`
- `powershell_credential_access`

Operational interpretation:

- `powershell_console_history` means a command observed in interactive history, not confirmed success.
- `powershell_transcript_command` provides better temporal and session context.
- `powershell_script_file_observed` means a script observed on disk, not proven execution.
- Confidence rises when correlations appear with `4104`, `4688`, Prefetch, Browser, MFT, Defender, Scheduled Tasks or SRUM.

## Recycle Bin sections

- `recycled_files`
- `deleted_files`
- `deleted_downloads`
- `deleted_executables`
- `deleted_scripts`
- `deleted_detected_files`
- `cleanup_candidates`

Operational interpretation:

- `file_recycled` means the file was sent to the recycle bin.
- It does not equal permanent deletion.
- Confidence rises when correlation appears with `MFT/USN`, Browser downloads or Defender.
- `cleanup_candidates` prioritizes `$I` metadata without `$R`, scripts, executables and suspicious items deleted after use or detection.

## USB sections

- `usb_devices`
- `usb_storage_devices`
- `usb_volume_mappings`
- `usb_file_activity`
- `usb_folder_activity`
- `download_to_usb`
- `possible_usb_exfiltration`
- `suspicious_usb_activity`

Operational interpretation:

- `usb_device_install` and `usb_volume_mapping` mean an observed device or volume, not a confirmed copy.
- `usb_file_activity` and `usb_folder_activity` summarize activity on removable paths.
- `download_to_usb` highlights downloads made directly to an external drive.
- `possible_usb_exfiltration` is deliberately cautious and should be read as a working hypothesis.
- `setupapi_driver_activity` is a secondary section for low-value or diagnostic SetupAPI blocks, and should not be confused with a specific connected external USB.

## BITS sections

- `background_downloads`
- `bits_jobs`
- `bits_transfers`
- `suspicious_bits_jobs`
- `bits_notify_commands`
- `downloaded_then_executed`
- `downloaded_then_detected`
- `possible_persistence`

Operational interpretation:

- a BITS job is not suspicious by default
- `Windows Update` and Microsoft jobs can be benign
- `bits_notify_commands` deserves review because it can act as persistence or a callback
- `downloaded_then_executed` and `downloaded_then_detected` are higher-value sections because they already combine several sources
- raw `qmgr` without a parser does not falsely appear as a parsed job; it remains discovery-only

## WMI sections

- `wmi_persistence`
- `wmi_filters`
- `wmi_consumers`
- `wmi_bindings`
- `suspicious_wmi_consumers`
- `wmi_encoded_powershell`
- `wmi_download_commands`
- `possible_wmi_execution`
- `wmi_activity`

Operational interpretation:

- `wmi_persistence` should be read as a persistence candidate, not confirmed execution
- the strongest signal appears when `filter + consumer + binding` all exist
- `suspicious_wmi_consumers` summarizes consumers with commands, scripts or higher-value correlations
- `wmi_activity` collects WMI activity observed in EVTX, but does not automatically equal persistence

## Autoruns / ASEP sections

- `autoruns_persistence`
- `suspicious_autoruns`
- `run_key_persistence`
- `startup_folder_persistence`
- `service_driver_persistence`
- `ifeo_debugger_persistence`
- `winlogon_persistence`
- `appinit_appcert_persistence`
- `downloaded_then_persisted`
- `persisted_then_executed`
- `persistence_detected_by_defender`

Operational interpretation:

- an Autoruns entry is observed or candidate persistence, not confirmed execution
- `suspicious_autoruns` prioritizes user-writable paths, unsigned/unverified binaries, LOLBins, download commands and critical mechanisms
- `downloaded_then_persisted` and `persisted_then_executed` are the higher-value sections because they already combine several sources

## Cloud Sync sections

Added sections:

- `cloud_sync_roots`
- `cloud_accounts`
- `cloud_file_activity`
- `cloud_sensitive_files`
- `cloud_archives`
- `downloaded_to_cloud`
- `copied_to_cloud`
- `executable_from_cloud`
- `defender_detection_in_cloud`
- `possible_cloud_staging`
- `possible_cloud_exfiltration`

The wording remains cautious:

- `cloud sync root observed`
- `cloud staging candidate`
- `possible cloud exfiltration candidate`

The existence of a file inside OneDrive, Dropbox or Google Drive does not by itself equal confirmed upload.

## Network / WLAN / DNS sections

Added sections:

- `network_overview`
- `wlan_profiles`
- `wlan_connections`
- `network_profiles`
- `dns_config`
- `dns_cache`
- `hosts_entries`
- `suspicious_hosts_entries`
- `suspicious_dns_config`
- `network_indicators`
- `network_correlations`

Operational interpretation:

- `wlan_profile` means the Wi-Fi profile was observed, not that a confirmed recent connection exists
- `wlan_connection` provides more temporal context when it comes from EVTX
- `hosts_entries` summarizes local overrides and should be reviewed together with Browser, Defender and MFT
- `network_indicators` groups observed domains, IPs, DNS and configuration
- `network_correlations` is the higher-value layer because it connects those indicators with Browser, BITS, PowerShell, Cloud Sync, SRUM or Defender

Cautious wording:

- `network indicator observed`
- `possible suspicious network configuration`
- `possible correlation`

The `network` family contextualizes connectivity and local configuration, but should not be read as automatic proof of C2 or intrusion without sufficient correlation.

### 8. Defender / malware

| Field | Detail |
| --- | --- |
| What it looks for | Detections, quarantines, remediation, remediation failures and correlations |
| Current evidence | 1116, 1117, 1118, 1119, 5007, 5013, `DetectionHistory`, `MPLog`, Defender CSV/JSON |
| What it shows | threat name, path/resource, action, severity, status, user, related events |
| How to interpret it | Confirms detection or action taken, but does not always imply execution or active infection |
| Current limitations | Raw quarantine is discovery-only; fine-grained deduplication with EVTX still improvable |
| Future | deeper quarantine metadata and additional log support |

New related sections:

- `defender_detections`
- `detected_files`
- `detected_downloads`
- `detected_executions`
- `quarantined_items`
- `remediation_failures`

### 9. Account changes

| Field | Detail |
| --- | --- |
| What it looks for | Additions, removals, password changes, users in groups |
| Current evidence | 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740 |
| What it shows | title, user, summary |
| How to interpret it | Useful for account abuse and escalation |
| Current limitations | No correlation yet with raw SAM/Registry artifacts |
| Future | RECmd and hive parsing |

### 10. Persistence

What it looks for:

- services
- tasks
- WMI persistence
- already-tagged persistent patterns
- Registry Run Keys and Services

Current evidence:

- EVTX 7045 / 4697 / 7040 / 7036
- `RECmd_Output.csv` for `registry_run_key` and `registry_service`

### 11. Anti-forensics

What it looks for:

- deletion of audit logs

Current evidence:

- `1102`

### 12. Suspicious findings

What it looks for:

- encoded PowerShell
- download cradle
- Defender tampering
- suspicious paths
- LOLBins
- executions via Prefetch from suspicious paths
- PowerShell / cmd / mshta / rundll32 / regsvr32 / certutil / bitsadmin observed in Prefetch
- ADS observed in MFT
- double extension and suspicious names in MFT/USN
- large differences between `$SI` and `$FN`

Important:

> A suspicious finding does not equal confirmed malware. It means it deserves manual review.

### 13. Files created / modified / deleted / renamed

What it looks for:

- file creations, deletions, renames and modifications

Current evidence:

- `MFTECmd_Output.csv`

## Execution artifacts: Amcache / ShimCache / AppCompat

This layer adds or reinforces these sections:

- `program_inventory`
- `execution_candidates`
- `downloaded_and_observed_programs`
- `suspicious_programs`

Operational interpretation:

- `Amcache` is used as observation of programs, inventory and metadata.
- `ShimCache` / `AppCompat` / `RecentFileCache` are used as presence or possible execution.
- Confidence rises to `high` only if correlation finds `Prefetch`, `EVTX 4688`, Browser download, `MFT/USN` or `Defender`.
- Without correlation, they should not be read as "confirmed execution".
- USN CSVs compatible with MFTECmd

What it shows:

- timestamp
- path
- extension
- size
- source (`mft` or `usn`)
- reason when it comes from USN

How to interpret it:

- `USN` is usually more useful for specific temporal activity
- `MFT` usually provides better historical context and deleted candidates

### 14. Execution candidates and suspicious files

What it looks for:

- `.exe`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.dll`, `.scr` in suspicious paths
- ADS
- double extension
- possible `$SI/$FN` anomalies

Current evidence:

- `MFTECmd_Output.csv`
- USN CSVs compatible with MFTECmd

### 15. Timeline

What it looks for:

- an ordered view of generated activities

What it shows:

- timestamp
- activity_type
- host
- user
- summary

### 16. Opened files

What it looks for:

- accesses to targets from `.lnk` shortcuts
- opened documents
- user targets with contextual value

Current evidence:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`
- raw `automaticDestinations-ms` from Velociraptor and `customDestinations-ms` with partial support
- reinforced sections for JumpLists: `recent_files`, `downloaded_files_opened`, `deleted_files_opened`, `network_file_activity`, `usb_file_activity`, `cloud_file_activity`, `suspicious_recent_items`
- if a JumpList uses `timestamp_precision = source_file_mtime`, temporal confidence is lower than for entries with `TargetAccessed` or `DestListLastAccessed`
- `user_writable_path` in JumpLists is treated as context; it does not by itself elevate an item to a suspicious finding
- `RECmd_Output.csv` for `TypedPaths`, `RecentDocs` and `Shellbags`

What it shows:

- timestamp
- user
- effective target
- extension
- source LNK
- drive type
- network path

Note:

- when `TargetPath` or `TargetIDAbsolutePath` are partial such as `Desktop\\`, the app uses `lnk.effective_path` to show the best available path
- semi-automatic analysis also consumes EVTX and LNK events parsed natively (raw), with the same normalized schema as the external parsers; for `native_lnk` this includes `startup_lnk`, cloud targets, UNC/network paths, removable media indicators and partial/unresolved target quality flags

### 17. Opened scripts

What it looks for:

- `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` and similar files opened via LNK

Current evidence:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`

How to interpret it:

- does not always imply confirmed execution
- does indicate strong interaction and deserves correlation with `4688`, PowerShell and Prefetch
- if the displayed target looks generic, check `lnk.effective_path`, `lnk.local_path` and `lnk.relative_path` in detail

### 18. Network / USB paths

What it looks for:

- `UNC` targets
- shares
- removable volumes or USB candidates

Current evidence:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`

### 19. Recent documents

What it looks for:

- documents recently opened by an application
- app and user context

Current evidence:

- `JLECmd_Output.csv`

### 20. Applications used

What it looks for:

- applications with recent Jump Lists
- interaction frequency
- last observed use

Current evidence:

- `JLECmd_Output.csv`

### 21. User activity

What it looks for:

- paths typed in Explorer
- commands launched from Run
- recent documents
- Registry artifacts that help explain user interaction without requiring a `raw` review

What to look at first:

- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `process.path`
- `destination.hostname`
- folders observed via Shellbags

Current evidence:

- `RECmd_Output.csv`

### 22. Folder activity / Shellbags

What it looks for:

- folders viewed or browsed by the user
- UNC paths or shares
- USB/removable folders
- cloud sync folders
- suspicious or no-longer-present folders

Current evidence:

- `SBECmd_Output.csv`
- `*Shellbags*.csv`
- `RECmd_Output.csv` when it includes normalized shellbags

What it shows:

- timestamp
- user
- path
- path type
- source hive/file
- MRU position
- related events

How to interpret it:

- Shellbags do not prove execution
- they do help a lot to demonstrate interaction with folders, shares, USB or paths later deleted
- confidence rises when they correlate with LNK, JumpLists, Browser, MFT/USN or Recycle Bin

### 23. USB devices

What it looks for:

- USB devices seen in the registry
- drive/volume mappings
- context for correlation with LNK and Jump Lists

Current evidence:

- `RECmd_Output.csv`
