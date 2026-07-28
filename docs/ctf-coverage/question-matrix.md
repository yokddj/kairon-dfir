# CTF Question Matrix

This matrix tracks investigative questions, not artifacts. Expected answers remain `Unknown` until confirmed from source material or a local ground-truth import.

## Webserver / VulnOSv2

| ID | Question | Expected answer | Specialist path | Search path | Source pivot | Status | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| WV-Q01 | What Linux host or OS is represented by the image? | Unknown; local anchors include `VulnOSv2`. | Artifact Explorer: `linux_os_info`; Evidence detail inventory. | Search `platform=linux artifact_type=linux_os_info VulnOSv2` or hostname terms. | `/etc/hostname`, `/etc/os-release`, evidence ID. | Partial | Needs real import validation and exact answer key. |
| WV-Q02 | Can Kairon read the root filesystem from `Webserver.E01`? | Unknown for current real evidence. | Evidence preflight and processing diagnostics. | Search only applies after materialization. | Volume diagnostics and extracted artifact source paths. | Partial | LVM parsing has tests, but real `Webserver.E01` needs validation. |
| WV-Q03 | Which accounts exist on the compromised server? | Unknown. | Artifact Explorer: `linux_identity`. | Search `platform=linux artifact_type=linux_identity <username>`. | `/etc/passwd`, `/etc/group`, `/etc/shadow` presence note. | Partial | No dedicated Linux identity capability page. |
| WV-Q04 | Who logged in successfully and from where? | Unknown; fixture includes `mail` from `192.168.210.131`. | Linux Authentication page sessions/last-login. | Search `platform=linux artifact_type=linux_auth "Accepted password"` plus username/IP. | `/var/log/auth.log`, `wtmp`, `lastlog`. | Partial | Needs imported CTF data regression. |
| WV-Q05 | Were there failed SSH logins or brute-force attempts? | Unknown; fixture includes `ulysses` from `192.168.56.1`. | Linux Authentication page brute-force groups. | Search `platform=linux artifact_type=linux_auth "Failed password"` or `ulysses`. | `/var/log/auth.log`, `btmp`. | Partial | Search lacks first-class Linux field syntax for `linux.source_ip` and `linux.username`. |
| WV-Q06 | What commands did users run? | Unknown. | Linux Command History route backed by command-history service when source_category/artifact supports it; Artifact Explorer for `linux_shell_history`. | Search `platform=linux artifact_type=linux_shell_history <command>`. | `.bash_history`, `.zsh_history`, source file and line number. | Partial | Shell history timestamps are often low-confidence; command-history Linux route needs CTF validation. |
| WV-Q07 | Did a user attempt privilege escalation with sudo or su? | Unknown. | Linux Authentication page exposes auth events; Artifact Explorer `linux_auth`/`linux_sudoers`. | Search `platform=linux sudo` or `artifact_type=linux_sudoers`. | `/var/log/auth.log`, `/etc/sudoers`, `/etc/sudoers.d/*`. | Partial | Sudo command semantics are parser-level only; no privilege-escalation capability. |
| WV-Q08 | What persistence exists through cron, systemd, SSH keys, or sudoers? | Unknown. | Artifact Explorer for `linux_cron`, `linux_systemd`, `linux_ssh`, `linux_sudoers`. | Search by artifact types and command/key/comment terms. | Cron files, unit files, authorized keys, sudoers files. | Partial | No dedicated Linux persistence overview and limited Search field filters. |
| WV-Q09 | What packages or software changes are relevant? | Unknown. | Packages capability / Artifact Explorer `linux_packages`. | Search `platform=linux artifact_type=linux_packages <package>`. | dpkg/yum/dnf/apt logs or dpkg status. | Partial | Package support is partial and package inventory vs package event distinction needs CTF validation. |
| WV-Q10 | What network configuration or host mappings matter? | Unknown. | Artifact Explorer `linux_network`. | Search `platform=linux artifact_type=linux_network <ip-or-host>`. | `/etc/hosts`, resolv.conf, interfaces, netplan. | Partial | No dedicated Linux network capability. |
| WV-Q11 | Can deleted web or attacker files be recovered from ext4? | Unknown. | None. | None unless files were live and materialized. | Disk image filesystem metadata. | Missing | Deleted-file recovery from ext4 is out of current materialization scope. |
| WV-Q12 | Can binary systemd journal entries be parsed? | Unknown. | None for binary journals. | None unless exported JSON/export logs exist. | `/var/log/journal/*/*.journal`. | Missing | Binary journal parsing is explicitly unsupported. |

## Victoria

| ID | Question | Expected answer | Specialist path | Search path | Source pivot | Status | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| VIC-Q01 | What kind of evidence is `victoria-v8.kcore.img`? | Linux memory-like image accepted/preserved; exact CTF role unknown. | Evidence upload/classification and Memory views. | Search is not available for advanced Linux memory artifacts. | Evidence metadata, SHA256, platform classification. | Partial | Advanced Linux memory analysis is not available. |
| VIC-Q02 | What host is represented? | `victoria` appears in local fixtures. | Evidence detail Linux inventory or `linux_os_info`. | Search `platform=linux victoria`. | `/etc/hostname`, auth logs. | Partial | Needs real evidence import and source confirmation. |
| VIC-Q03 | Which invalid user was attacked over SSH? | `ulysses` in local fixtures. | Linux Authentication brute-force/failed-auth views. | Search `platform=linux artifact_type=linux_auth ulysses` or `192.168.56.1`. | `/var/log/auth.log`. | Partial | Fixture confirms parser/service behavior, not full CTF expected answer. |
| VIC-Q04 | What source IP attacked SSH? | `192.168.56.1` in local fixtures. | Linux Authentication filters by attempted username/source IP. | Search `platform=linux artifact_type=linux_auth 192.168.56.1`. | `/var/log/auth.log`. | Partial | Search source-IP field is not first-class for Linux. |
| VIC-Q05 | Was SSH brute force followed by success? | Fixture says `followed_by_success=false` for `ulysses`. | Linux Authentication brute-force groups. | Search failures and successes around same source/user/time. | Auth events with timestamps. | Partial | Needs real CTF sequence and regression. |
| VIC-Q06 | Who logged in successfully from `192.168.210.131`? | `mail` in local fixtures. | Linux Authentication sessions/last-login. | Search `platform=linux artifact_type=linux_auth 192.168.210.131`. | `/var/log/auth.log`, `lastlog`. | Partial | Needs real CTF confirmation. |
| VIC-Q07 | What commands or attacker actions followed login? | Unknown. | Linux Command History if disk/triage is present. | Search `platform=linux artifact_type=linux_shell_history <term>`. | Shell history files. | Unknown | Memory-only evidence cannot answer this today; disk/triage companion evidence not confirmed. |
| VIC-Q08 | What Linux processes, network sockets, modules, or files are visible in memory? | Unknown. | None for advanced Linux memory. | None for Linux memory plugin output. | Linux memory image. | Missing | Requires Linux Volatility/profile support and Search indexing. |

## Regression Rule

When source material is confirmed, every row with a known expected answer must get a regression fixture or end-to-end validation that proves:

| Check | Requirement |
| --- | --- |
| Specialist | The answer is visible in the relevant capability or artifact page. |
| Search | The answer is discoverable through global Search without knowing internal OpenSearch fields. |
| Provenance | The answer can be traced to source file/evidence/host/time. |
