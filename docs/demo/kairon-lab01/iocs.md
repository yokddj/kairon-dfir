# Lab Indicators

These are laboratory indicators for a benign DFIR demo. They are not malicious IOCs and should not be added to production blocklists without context.

## Host And User

- Hostname: `KAIRON-LAB01`
- Username: `analyst`

## Paths

- `C:\Users\analyst\Documents\KaironLab01`
- `C:\Users\analyst\Documents\KaironLab01\scheduled_task_payload.ps1`
- `C:\Users\analyst\Documents\KaironLab01\run_key_payload.ps1`

## Registry

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `KaironLab01Run`

## Scheduled Task

- `KaironLab01Updater`

## Processes

- `powershell.exe`
- `cmd.exe`
- `notepad.exe`
- `certutil.exe`

## Command-Line Fragments

- `-EncodedCommand`
- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden`
- `whoami`
- `hostname`
- `ipconfig /all`
- `systeminfo`
- `tasklist`
- `net user`
- `net localgroup administrators`
- `net localgroup administradores`

## Marker Strings

- `KAIRON-LAB01-MARKER`
- `KAIRON-LAB01-RUNKEY-MARKER`

## File Names

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
