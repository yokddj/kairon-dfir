# Artifact Map

This map lists expected evidence paths through the investigation. Availability depends on the Velociraptor collection profile, Windows logging configuration and Kairon DFIR parser support.

| Activity | Expected evidence | Possible artifact source | Useful Kairon DFIR view |
| --- | --- | --- | --- |
| PowerShell execution | `powershell.exe` command line | Sysmon, Security `4688`, PowerShell Operational, Prefetch | Timeline, Search, Command History |
| Encoded PowerShell | `-EncodedCommand` | PowerShell Operational, Sysmon, Security `4688`, command history | Search, Detections |
| Execution policy bypass | `-ExecutionPolicy Bypass` | PowerShell Operational, Sysmon, Security `4688` | Search, Detections |
| Hidden PowerShell window | `-WindowStyle Hidden` | PowerShell Operational, Sysmon, Security `4688` | Search, Detections |
| Reconnaissance | `whoami`, `hostname`, `ipconfig /all`, `systeminfo`, `tasklist`, `net user` | Process creation logs, command history, output files | Search, Command History, Timeline |
| Scheduled Task | `KaironLab01Updater` | TaskScheduler Operational, XML task artifact, Security events | Artifact Explorer, Timeline, Search |
| Scheduled Task payload | `scheduled_task_payload.ps1`, `scheduled_task_ran.txt` | Task XML, PowerShell logs, filesystem artifacts | Artifact Explorer, Search |
| Run Key | `KaironLab01Run` | Registry artifacts, Sysmon Event ID 13 if collected | Artifact Explorer, Search |
| Run Key payload | `run_key_payload.ps1`, `run_key_persistence_ran.txt` | Registry, PowerShell logs, filesystem artifacts | Artifact Explorer, Search, Timeline |
| File creation | files under `C:\Users\analyst\Documents\KaironLab01` | Filesystem artifacts, MFT, USN if available | Artifact Explorer, Search |
| Notepad execution | `notepad.exe` or `NOTEPAD.EXE` evidence | Prefetch, UserAssist, Recent files, JumpLists | Artifact Explorer, Search |
| Hash calculation | `certutil` command and `invoice_update_hash.txt` | Process creation logs, command history, filesystem artifacts | Search, Command History |
| Browser or manual activity, if present | browser history or recent file traces | Edge or other browser artifacts, LNK, JumpLists | Artifact Explorer, Search |
