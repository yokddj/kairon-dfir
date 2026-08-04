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

### Expected Collection Layout

Linux triage collections should preserve directory structure:

```
linux-triage.tar.gz
  etc/
    hostname
    passwd
    group
    sudoers
    ssh/
      sshd_config
    cron.d/
    systemd/system/
  var/
    log/
      auth.log
      syslog
      dpkg.log
      audit/
        audit.log
  root/
    .bash_history
  home/
    user/
      .bash_history
      .ssh/
        authorized_keys
```

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

## Parsed Artifact Families

Current Linux parsers cover 12 families. Coverage is calculated from detected artifacts only (`supported_detected / total_detected`) — Kairon does not invent a percentage for artifacts that were not present in the collection.

### Linux Authentication (`linux_auth`)
- Sources: `/var/log/auth.log`, `/var/log/secure`
- Events: SSH accepted/failed, sudo, su, PAM sessions, invalid users, authentication failures
- Fields: `timestamp`, `username`, `process`, `pid`, `source_ip`, `auth_method`, `event_action`, `message`

### Linux Syslog (`linux_syslog`)
- Sources: `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log`
- Events: Generic syslog lines with timestamp, host, process, pid, severity
- Fields: `timestamp`, `detected_host`, `process`, `pid`, `severity`, `message`

### Linux Audit (`linux_audit`)
- Sources: `/var/log/audit/audit.log`
- Events: SYSCALL, EXECVE, USER_AUTH, USER_LOGIN, PATH
- Fields: `timestamp`, `audit_type`, `uid`, `auid`, `pid`, `exe`, `command`, `success`, `message`
- Limitations: multi-line event reconstruction is partial in v1

### Linux Shell History (`linux_shell_history`)
- Sources: `.bash_history`, `.zsh_history`
- Events: shell commands with inferred username
- Fields: `username`, `shell`, `command`, `source_file`, `line_number`
- ZSH extended history timestamps are extracted; history without extended timestamps has no time context

### Linux Cron (`linux_cron`)
- Sources: `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`
- Events: scheduled jobs with schedule, username, command
- Fields: `schedule`, `username`, `command`, `source_file`, `line_number`

### Linux Systemd (`linux_systemd`)
- Sources: `*.service`, `*.timer` files
- Events: unit definitions with description, exec, dependencies
- Fields: `unit_name`, `unit_type`, `description`, `exec_start`, `wanted_by`, `enabled_hint`
- Limitations: timer expressions are not fully parsed

### SSH Artifacts (`linux_ssh`)
- Sources: `authorized_keys`, `known_hosts`, `ssh_config`, `sshd_config`
- Events: key fingerprints (redacted), host patterns, config options
- Fields: `key_type`, `key_fingerprint`, `key_comment`, `host_pattern`, `option`, `value`
- Security: full public keys are never stored, only fingerprints

### Linux Identity (`linux_identity`)
- Sources: `/etc/passwd`, `/etc/group`, `/etc/shadow`
- Events: users, groups, shadow presence notes
- Fields: `username`, `uid`, `gid`, `home`, `shell`, `gecos`, `group_name`, `members`
- Security: shadow hashes are never stored. See [Host Information](../evidence/host-information.md) for how this feeds the Local Accounts inventory.

### Linux Sudoers (`linux_sudoers`)
- Sources: `/etc/sudoers`, `/etc/sudoers.d/*`
- Events: sudo rules with principal, host, runas, command, options
- Fields: `principal`, `host_spec`, `run_as`, `command_spec`, `options`, `source_file`

### Linux Packages (`linux_packages`)
- Sources: `/var/log/dpkg.log`, `/var/log/yum.log`, `/var/log/dnf.log`
- Events: package install/upgrade/remove actions
- Fields: `timestamp`, `package_manager`, `action`, `package`, `version`
- Limitations: package manager detection is format-based, not exhaustive

### Linux Network Config (`linux_network`)
- Sources: `/etc/hosts`, `/etc/resolv.conf`, `/etc/network/interfaces`, netplan
- Events: IP mappings, DNS config, interface settings
- Fields: `config_type`, `interface`, `address`, `gateway`, `dns`, `hostname`

### Linux OS Information (`linux_os_info`)
- Sources: `/etc/os-release`, `/etc/hostname`, `/proc/version`
- Events: OS name, version, kernel, hostname
- Fields: `hostname`, `os_name`, `os_version`, `kernel_version`
- Detected host is extracted from `/etc/hostname` when available. Feeds the platform-agnostic Host Facts layer — see [Host Information](../evidence/host-information.md).

### Linux Memory Images (`linux_memory`)
- Sources: `.raw`, `.mem`, `.lime` files detected as Linux
- Accepted, classified, preserved, assignable to hosts, and usable for findings
- Advanced Linux memory analysis with Volatility is not available yet — the UI explicitly shows Linux Memory as accepted with analysis not available

## Viewing Linux Artifacts

Linux artifacts appear in:
- **Search** — query by `artifact_family:linux_*` or `platform:linux`
- **Artifact Explorer** — Linux families listed alongside Windows artifacts
- **Findings** — create findings from Linux events

## Limitations

- Linux parser coverage is partial. Not all log formats are supported.
- Full Linux memory analysis with Volatility is not available.
- ext4 filesystem parsing is not implemented.
- Full automatic filesystem mounting for every Linux disk-image layout is not implemented.
- Write-capable disk-image mounting is not implemented.
- Binary systemd journal parsing is not implemented.
- SELinux policy database parsing is not implemented.
- macOS collection parsing is not implemented.
- Executing uploaded scripts or binaries is never done.
- Multi-line audit events are parsed per-line in v1.
- Systemd timer expressions are not fully parsed.
- ZSH history without extended timestamps has no time context.
- Package manager detection is format-based, not exhaustive.

Unsupported artifacts can still appear in inventory so analysts know they were present but not parsed.
