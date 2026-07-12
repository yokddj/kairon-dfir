# Linux Artifact Support

Kairon supports a growing set of Linux artifacts from triage collections. This page describes exact parser coverage and limitations.

## Supported Families

### Linux Authentication (linux_auth)
- Sources: /var/log/auth.log, /var/log/secure
- Events: SSH accepted/failed, sudo, su, PAM sessions, invalid users, authentication failures
- Fields: timestamp, username, process, pid, source_ip, auth_method, event_action, message

### Linux Syslog (linux_syslog)
- Sources: /var/log/syslog, /var/log/messages, /var/log/kern.log
- Events: Generic syslog lines with timestamp, host, process, pid, severity
- Fields: timestamp, detected_host, process, pid, severity, message

### Linux Audit (linux_audit)
- Sources: /var/log/audit/audit.log
- Events: SYSCALL, EXECVE, USER_AUTH, USER_LOGIN, PATH
- Fields: timestamp, audit_type, uid, auid, pid, exe, command, success, message
- Limitations: Multi-line event reconstruction is partial in v1

### Linux Shell History (linux_shell_history)
- Sources: .bash_history, .zsh_history
- Events: Shell commands with inferred username
- Fields: username, shell, command, source_file, line_number
- ZSH extended history timestamps are extracted

### Linux Cron (linux_cron)
- Sources: /etc/crontab, /etc/cron.d/*, /var/spool/cron/*
- Events: Scheduled jobs with schedule, username, command
- Fields: schedule, username, command, source_file, line_number

### Linux Systemd (linux_systemd)
- Sources: *.service, *.timer files
- Events: Unit definitions with description, exec, dependencies
- Fields: unit_name, unit_type, description, exec_start, wanted_by, enabled_hint

### SSH Artifacts (linux_ssh)
- Sources: authorized_keys, known_hosts, ssh_config, sshd_config
- Events: Key fingerprints (redacted), host patterns, config options
- Fields: key_type, key_fingerprint, key_comment, host_pattern, option, value
- Security: Full public keys are never stored. Only fingerprints shown.

### Linux Identity (linux_identity)
- Sources: /etc/passwd, /etc/group, /etc/shadow
- Events: Users, groups, shadow presence notes
- Fields: username, uid, gid, home, shell, gecos, group_name, members
- Security: Shadow hashes are never stored.

### Linux Sudoers (linux_sudoers)
- Sources: /etc/sudoers, /etc/sudoers.d/*
- Events: Sudo rules with principal, host, runas, command, options
- Fields: principal, host_spec, run_as, command_spec, options, source_file

### Linux Packages (linux_packages)
- Sources: /var/log/dpkg.log, /var/log/yum.log, /var/log/dnf.log
- Events: Package install/upgrade/remove actions
- Fields: timestamp, package_manager, action, package, version

### Linux Network Config (linux_network)
- Sources: /etc/hosts, /etc/resolv.conf, /etc/network/interfaces, netplan
- Events: IP mappings, DNS config, interface settings
- Fields: config_type, interface, address, gateway, dns, hostname

### Linux OS Information (linux_os_info)
- Sources: /etc/os-release, /etc/hostname, /proc/version
- Events: OS name, version, kernel, hostname
- Fields: hostname, os_name, os_version, kernel_version
- Detected host is extracted from /etc/hostname when available

### Linux Memory Images (linux_memory)
- Sources: .raw, .mem, .lime files detected as Linux
- Accepted and preserved. Host assignment and findings supported.
- Advanced memory analysis is not available in this release.

## Expected Collection Layout

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

## Viewing Linux Artifacts

Linux artifacts appear in:
- **Search** - Query by artifact_family:linux_* or platform:linux
- **Artifact Explorer** - Linux families listed alongside Windows artifacts
- **Findings** - Create findings from Linux events

## Limitations

- Linux parser coverage is partial. Not all log formats are supported.
- Multi-line audit events are parsed per-line in v1.
- Linux memory advanced analysis is not available.
- Systemd timer expressions are not fully parsed.
- ZSH history without extended timestamps has no time context.
- Package manager detection is format-based, not exhaustive.
