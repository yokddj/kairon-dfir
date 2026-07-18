# Linux Support

Kairon accepts Linux evidence collections as uploaded archives, folders, manual collections, and Velociraptor-style exports. Linux support is focused on auto-discovery, inventory, parser coverage, Search, Artifact Explorer, host assignment, and findings.

## Accepted Collection Formats

- ZIP
- TAR
- TAR.GZ
- TGZ
- Uploaded folder collections
- Manual triage folders
- Velociraptor exports that contain Linux paths or Linux artifacts

Kairon does not require a fixed root layout. It scans paths such as `/etc`, `/var/log`, `/home`, `/root`, `/usr`, `/boot`, and nested equivalents inside archives.

## Auto-Discovery

Kairon attempts to detect:

- Distribution from `os-release`
- Hostname from `hostname`
- Kernel from `proc/version` or `boot/vmlinuz-*`
- Users from `passwd`
- Auth logs
- Syslog/messages/kern logs
- Audit logs
- Shell history
- Cron files
- systemd service/timer units
- SSH artifacts
- Identity files
- sudoers
- Package manager logs
- Network configuration

## Parsed Artifacts

Current Linux parsers cover:

- `linux_auth`
- `linux_syslog`
- `linux_audit`
- `linux_shell_history`
- `linux_cron`
- `linux_systemd`
- `linux_ssh`
- `linux_identity`
- `linux_sudoers`
- `linux_packages`
- `linux_network`
- `linux_os_info`

Coverage is calculated from detected artifacts only:

`supported_detected / total_detected`

Kairon does not invent a percentage for artifacts that were not present in the collection.

## Unsupported Or Limited

Not supported yet:

- Full Linux memory analysis with Volatility
- ext4 filesystem parsing
- Full automatic filesystem mounting for every Linux disk-image layout
- Write-capable disk-image mounting
- Binary systemd journal parsing
- SELinux policy database parsing
- macOS collection parsing
- Executing uploaded scripts or binaries

Unsupported artifacts can still appear in inventory so analysts know they were present but not parsed.

## Linux Memory

Linux memory uploads are accepted, classified, preserved, assignable to hosts, and usable for findings. Advanced Linux memory analysis is not available yet. The UI explicitly shows Linux Memory as accepted with analysis not available yet.
