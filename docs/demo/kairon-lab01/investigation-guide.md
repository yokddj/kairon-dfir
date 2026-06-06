# Investigation Guide

This guide walks through a practical investigation of Kairon Lab 01 in Kairon DFIR. Some artifact sources depend on the Velociraptor collection profile and parser support. If an artifact is not visible, check parser support, collection scope and ingestion logs.

## A. Ingest

1. Create a new case.
2. Upload the Velociraptor ZIP collection.
3. Wait for processing and indexing to finish.
4. Review the evidence summary.
5. Check whether any parsers reported errors or unsupported files.
6. Note which artifact types Kairon DFIR detected, such as EVTX, PowerShell, registry, scheduled tasks, Prefetch, Amcache/Shimcache, LNK, JumpLists or filesystem artifacts.

## B. First Triage

Use Search to confirm the basic scope:

- `KAIRON-LAB01`
- `analyst`
- `KAIRON-LAB01-MARKER`
- `KAIRON-LAB01-RUNKEY-MARKER`
- `KaironLab01`

Record which artifact families return results. This helps separate collection coverage from investigative absence.

## C. Timeline

1. Open Investigation Timeline or Search Timeline, depending on the workflow being used.
2. Filter for `powershell.exe`.
3. Filter for `cmd.exe`.
4. Filter for scheduled task activity.
5. Filter for Run Key or registry activity if registry artifacts are available.
6. Sort events chronologically.
7. Reconstruct the main sequence of activity.

Use the timeline to move from isolated hits to an investigable narrative. Avoid assuming a behavior occurred only because a detection fired; validate it against artifacts and command context.

## D. PowerShell

Search for evidence of:

- `powershell.exe`
- `-EncodedCommand`
- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden`
- `run_key_payload.ps1`
- `scheduled_task_payload.ps1`

Useful sources can include PowerShell Operational logs, Sysmon, Security `4688`, command history, script files, Prefetch and raw artifacts if collected.

## E. Reconnaissance

Search for commands or output files related to:

- `whoami`
- `hostname`
- `ipconfig /all`
- `systeminfo`
- `tasklist`
- `net user`
- `net localgroup administrators`
- `net localgroup administradores`

Corroborate command execution with output files under `C:\Users\analyst\Documents\KaironLab01` where available.

## F. Scheduled Task Persistence

Search for:

- `KaironLab01Updater`
- `scheduled_task_payload.ps1`
- `scheduled_task_ran.txt`
- `Microsoft-Windows-TaskScheduler/Operational`

Look for task creation, task execution and the payload path. Depending on collection scope, this may appear in TaskScheduler Operational logs, task XML artifacts, Security events, Sysmon events or filesystem artifacts.

## G. Registry Run Key Persistence

Search for:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `KaironLab01Run`
- `run_key_payload.ps1`
- `run_key_persistence_ran.txt`
- `KAIRON-LAB01-RUNKEY-MARKER`

If the Run Key is visible but execution is not, check whether logon-related artifacts were collected and whether the parser supports the relevant registry source.

## H. Execution Artifacts

Look for supporting execution evidence in:

- Sysmon, if collected;
- Security `4688`, if process creation auditing was enabled;
- PowerShell Operational logs, if collected;
- Prefetch, if available;
- Amcache or Shimcache, if available;
- LNK, JumpLists or Recent files, if available.

Use these artifacts as corroboration. Some sources show execution strongly, while others show presence, interaction or historical context.

## I. Created Files

Search under:

```text
C:\Users\analyst\Documents\KaironLab01
```

Expected files include:

- `activity.log`
- `whoami.txt`
- `hostname.txt`
- `network.txt`
- `systeminfo.txt`
- `tasklist.txt`
- `net_user.txt`
- `local_admins.txt`
- `local_admins_es.txt`
- `readme.txt`
- `stage1.txt`
- `invoice_update.js`
- `notes.txt`
- `users_dir.txt`
- `cmd_output.txt`
- `encoded_command_was_here.txt`
- `encoded_output.txt`
- `wmi_os.txt`
- `scheduled_task_payload.ps1`
- `scheduled_task_ran.txt`
- `run_key_payload.ps1`
- `run_key_persistence_ran.txt`
- `expected_summary.txt`
- `run_key_expected_finding.txt`
- `invoice_update_hash.txt`

If filesystem artifacts are not present, use command lines, PowerShell logs, task definitions and registry artifacts to corroborate file paths.

## J. Conclusion

End the investigation with:

- a short timeline of key events;
- a list of commands observed;
- the scheduled task and Run Key persistence simulations;
- the evidence supporting each finding;
- the artifact sources used to corroborate execution;
- a brief conclusion based on observed data in Kairon DFIR.
