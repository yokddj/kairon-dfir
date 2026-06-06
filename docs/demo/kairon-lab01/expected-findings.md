# Expected Findings

This is an orientative answer key for a benign lab. Use it after completing the investigation, not as a substitute for evidence review.

## Scope

- Host: `KAIRON-LAB01`
- User: `analyst`
- Main directory: `C:\Users\analyst\Documents\KaironLab01`
- Markers: `KAIRON-LAB01-MARKER`, `KAIRON-LAB01-RUNKEY-MARKER`

## Suspicious Simulated Behaviors

Expected behaviors include:

- PowerShell execution;
- encoded PowerShell command execution;
- `ExecutionPolicy Bypass`;
- `WindowStyle Hidden`;
- reconnaissance commands;
- file creation under the user profile;
- scheduled task persistence simulation;
- HKCU Run Key persistence simulation;
- Notepad execution for user activity artifacts;
- `certutil` hash calculation.

## Scheduled Task

- Name: `KaironLab01Updater`
- Payload: `scheduled_task_payload.ps1`
- Expected output: `scheduled_task_ran.txt`

Validate this with scheduled task artifacts, TaskScheduler Operational events, process creation events and filesystem artifacts if collected.

## Registry Persistence

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Value: `KaironLab01Run`
- Payload: `run_key_payload.ps1`
- Expected output: `run_key_persistence_ran.txt`

Validate this with registry artifacts, Sysmon registry events if collected, process execution evidence and the marker `KAIRON-LAB01-RUNKEY-MARKER`.

## Analyst Conclusion

A reasonable conclusion is that the host contains a controlled simulation of suspicious PowerShell activity. The activity includes reconnaissance, staged file creation and two benign persistence mechanisms. The evidence should be treated as a lab for validating Kairon DFIR ingest, search, timeline reconstruction, pivots and finding validation.
