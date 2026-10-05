# Investigation guide: where to look, and what to search

Short recipes for the questions most investigations start with. Each one says where the operating
system records the answer, which Kairon view shows it, and searches to run. The grouping follows
the categories the [SANS DFIR posters](https://www.sans.org/posters/) popularised (program
execution, persistence, account usage, lateral movement…); the posters themselves go much deeper
and are worth keeping at hand.

Searches are written in Kairon's search syntax (see [Search](search.md)): `field:value`, `AND`,
`OR`, `NOT`, quotes for phrases and `*` wildcards. In the app, the **Search** button next to each
one runs it on the active case. No result does not prove the activity did not happen: it may not
have been logged, or the logs may not be in the evidence.

> Tip: start from **Overview** and **Detections** (run the Sigma rules), then come here for the
> question at hand. Note the time and the host of anything relevant and pivot on them in
> **Timeline**.

> Event IDs are reused across logs: 104 is a cleared System log for `Microsoft-Windows-Eventlog`
> but something else for a dozen other providers. When an ID could belong to several logs, the
> searches below add `channel:` or `provider:`; do the same when you write your own.

## Windows

### What ran? (program execution)

Where it is recorded: Prefetch (`C:\Windows\Prefetch`, last run times and run count), Amcache
(`Amcache.hve`, path and SHA-1 of executables), Shimcache (`AppCompatCache` in the SYSTEM hive,
presence and order), process creation in the Security log (4688, when auditing is on) and Sysmon
(event 1, with the command line, parent and hashes).

In Kairon: **Artifact Views → Prefetch**, **Amcache**, **Shimcache**, and **Process Graph** to see
who started what.

```kairon
eventid:4688
```

```kairon
eventid:1 AND channel:*Sysmon*
```

```kairon
artifact:prefetch
```

```kairon
path:*\\AppData\\Local\\Temp\\*
```

Look for: binaries in user-writable folders (`AppData`, `Temp`, `ProgramData`, `Downloads`), names
that imitate system tools, Office or browsers starting `cmd.exe`/`powershell.exe`.

### How does it survive a reboot? (persistence)

Where it is recorded: Run and RunOnce keys (`HKLM\…\CurrentVersion\Run`, `HKCU\…\Run`), services
(new service: System 7045, Security 4697), scheduled tasks (Security 4698, Task Scheduler 106,
`C:\Windows\System32\Tasks`), WMI event subscriptions (WMI-Activity 5861) and the Startup folders.

In Kairon: **Artifact Views → Startup & Persistence**, **Services**, **Scheduled Tasks**, **WMI**,
**Autoruns** (when an Autoruns export is in the evidence).

```kairon
eventid:7045 OR eventid:4697
```

```kairon
eventid:4698 OR (eventid:106 AND channel:*TaskScheduler*)
```

```kairon
artifact:scheduled_task
```

```kairon
registry.key_path:*CurrentVersion\\Run*
```

Look for: services or tasks pointing at user folders or script interpreters, random-looking names,
anything created close to the first suspicious activity.

### Who logged on, and from where? (account usage)

Where it is recorded: Security log: 4624 successful logon (the logon type says how: 2 at the
keyboard, 3 over the network, 10 by Remote Desktop), 4625 failed logon, 4648 logon with explicit
credentials, 4672 administrative privileges, 4720 account created, 4732 user added to a local group.

In Kairon: **Search**, **Host Information → Local Accounts**, **Timeline** around the logons.

```kairon
eventid:4624 AND logontype:10
```

```kairon
eventid:4624 AND logontype:3
```

```kairon
eventid:4625
```

```kairon
eventid:4720 OR eventid:4732
```

Look for: many 4625 followed by a 4624 from the same address (password guessing that worked),
logons at unusual hours, accounts created and used shortly after.

### Did it move to other machines? (lateral movement)

Where it is recorded: Remote Desktop (4624 type 10, RDP connection logs), admin shares (5140/5145
for `ADMIN$`, `C$`), PsExec and similar tools (a new `PSEXESVC` service, 7045), remote scheduled
tasks and WinRM (`wsmprovhost.exe`).

```kairon
eventid:5140 OR eventid:5145
```

```kairon
service:PSEXESVC
```

```kairon
process:wsmprovhost.exe
```

Look for: the same account logging on to several hosts in a short time, services installed on a
host right after a network logon from another.

### What did PowerShell do?

Where it is recorded: PowerShell Operational log (4104 script block logging, 4103 module logging),
Windows PowerShell log (800), the PSReadLine history file of each user.

In Kairon: **Artifact Views → PowerShell**, **Command History**.

```kairon
eventid:4104
```

```kairon
artifact:powershell AND command:*-enc*
```

```kairon
command:*DownloadString* OR command:*IEX*
```

Look for: encoded commands (`-enc`), downloads (`DownloadString`, `Invoke-WebRequest`), execution
policy bypasses, AMSI tampering.

### Which files and folders were opened?

Where it is recorded: LNK shortcuts (Recent folder), Jump Lists, ShellBags (folders browsed),
RecentDocs and OpenSaveMRU (registry), Office recent files.

In Kairon: **Artifact Views → LNK / Shortcuts**, **Jump Lists**, **User Activity** (Shellbags,
RecentDocs, OpenSaveMRU…).

```kairon
artifact:lnk
```

```kairon
artifact:jumplist
```

Look for: archives or documents opened from removable drives or network shares, folders browsed on
other hosts.

### Where did it come from? (downloads and initial access)

Where it is recorded: browser history, the `Zone.Identifier` stream of downloaded files (Mark of the
Web, with the source URL), e-mail attachments, Office trust and alert records.

In Kairon: **Artifact Views → Browser History**, **MOTW / Downloaded Files**, **Email Artifacts**.

```kairon
artifact:browser
```

```kairon
artifact:motw
```

### Were USB devices used?

Where it is recorded: `setupapi.dev.log` (first connection), USBSTOR and MountedDevices keys
(SYSTEM hive), Partition/Diagnostic and DriverFrameworks logs, LNK files pointing at removable
drives.

In Kairon: **Artifact Views → USB**.

```kairon
artifact:usb
```

### What was deleted? (file system)

Where it is recorded: the MFT and the USN journal (creation, rename and deletion of files), the
Recycle Bin (`$I` files with the original path and deletion time).

In Kairon: **Artifact Views → MFT**, **NTFS / USN Journal**, **Recycle Bin**, and **File history**
from any MFT row.

```kairon
artifact:recycle_bin
```

### Were the tracks covered? (defence evasion)

Where it is recorded: Security log cleared (1102), System log cleared (104), Defender detections and
configuration changes (1116, 1117, 5001), audit policy changes (4719).

```kairon
(eventid:1102 OR eventid:104) AND provider:*Eventlog*
```

```kairon
artifact:defender
```

### What did it connect to? (network)

Where it is recorded: Sysmon network connections (3) and DNS queries (22), the Windows Firewall
log, RDP and SMB events above.

In Kairon: **Artifact Views → DNS** (shown when the case has DNS events), **Network**.

```kairon
eventid:3 AND channel:*Sysmon*
```

```kairon
eventid:22 AND channel:*Sysmon*
```

## Linux

### Who logged in, and who tried? (authentication)

Where it is recorded: `/var/log/auth.log` or `/var/log/secure` (SSH, sudo, su), `wtmp` (logins,
reboots), `btmp` (failed logins), `lastlog` (last login per account), the journal.

In Kairon: **Artifact Views → Auth Logs**, **Lastlog**, **Linux Authentication**.

```kairon
artifact:linux_auth AND action:login_failure
```

```kairon
artifact:linux_auth AND action:login_success
```

```kairon
linux.event_action:max_auth_attempts
```

Look for: bursts of failures from one address followed by a success, logins as `root`, accounts
that never log in suddenly doing so.

### What was run as root? (privilege use)

Where it is recorded: sudo and su lines in the auth log (user, target account, directory, command).

```kairon
linux.event_action:sudo_command
```

```kairon
runas:root AND linux.event_action:sudo_command
```

### How does it survive a reboot? (persistence)

Where it is recorded: crontabs (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`), systemd units,
`/etc/rc.local`, `/etc/ld.so.preload`, PAM configuration, shell start-up files (`.bashrc`,
`/etc/profile.d`), SSH `authorized_keys`, `at` jobs.

In Kairon: **Artifact Views → Cron**, **Systemd Units**, **Persistence Config**, **SSH**.

```kairon
artifact:linux_cron
```

```kairon
artifact:linux_persistence AND (indicator:download_and_run OR indicator:reverse_shell OR indicator:obfuscation OR indicator:preload_library OR indicator:pam_exec OR indicator:auth_always_permit OR indicator:shadowed_command_alias)
```

Look for: jobs or units running from `/tmp`, `/dev/shm` or hidden folders, `curl … | sh`, preloaded
libraries, PAM modules outside the standard ones, keys in `authorized_keys` nobody can explain.

### What commands were typed?

Where it is recorded: each user's `.bash_history` / `.zsh_history` (usually without times), the
audit log (`execve`) when auditd runs.

In Kairon: **Artifact Views → Shell History**, **Command History**.

```kairon
artifact:linux_shell_history AND command:*wget*
```

```kairon
artifact:linux_shell_history AND (command:*curl* OR command:*nc* OR command:*base64*)
```

### Was the web server attacked?

Where it is recorded: Apache/nginx access and error logs. Requests are decoded (URL encoding and
base64) and flagged with what they contain: `base64_decode`, `eval`, `system`, `cmd=`, `../../`,
`embedded_base64`, `ip_port_reference` (an address and port, typical of reverse shells)…

In Kairon: **Artifact Views → Web Server Logs**.

```kairon
artifact:linux_apache AND indicator:embedded_base64
```

```kairon
indicator:base64_decode OR indicator:eval OR indicator:ip_port_reference
```

### What was installed?

Where it is recorded: `dpkg.log`, apt `history.log`, `yum.log`/`dnf.log`.

In Kairon: **Artifact Views → Packages**.

```kairon
pkgaction:install
```

```kairon
package:netcat* OR package:nmap* OR package:gcc*
```

### Which accounts exist?

Where it is recorded: `/etc/passwd`, `/etc/group`, `/etc/shadow` (only whether a password is set
is kept, never the hash), sudoers.

In Kairon: **Artifact Views → Users & Groups**, **Sudoers**, **Host Information**.

```kairon
artifact:linux_identity
```

```kairon
artifact:linux_sudoers
```

Look for: a second account with UID 0, service accounts with a login shell, new members of the
`sudo`/`wheel` groups.

### Can the times be trusted?

Syslog-style lines have no year and most logs have no time zone. Kairon converts them with the host's
own time zone and infers the year from boot records; the **Time Quality** column says what was done.
Before relying on an exact time, check it:

```kairon
timequality:inferred_year_host_timezone OR timequality:inferred_year OR timequality:assumed_year_utc OR timequality:assumed_utc
```
