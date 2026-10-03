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

### Linux Journal (`linux_journal`)
- Sources: binary systemd journals (`/var/log/journal/<machine-id>/system.journal`, `user-<uid>.journal`, rotated `system@<id>.journal`, the `.journal~` left by an unclean shutdown, and the volatile `/run/log/journal`), plus `journalctl -o export` and `-o json` text exports.
- Why it matters: Debian 12+, Fedora, Arch and recent RHEL/SUSE can run on journald alone, with no `auth.log` or `syslog` at all. Without this parser those hosts produce almost no log evidence.
- Format: both the regular and the compact object layouts (systemd 252+), with XZ, LZ4 and ZSTD compressed fields. Files are recognised by their magic bytes, so a renamed or extensionless copy still parses. A copy-off of a live journal that is shorter than its declared size is read normally.
- Fields: `timestamp` (microsecond precision), `message`, `hostname`, `process` (`SYSLOG_IDENTIFIER`, else `_COMM`), `pid`, `username` (the numeric `_UID`, as in the text exports), `severity` (the syslog `PRIORITY` number), `event_action` (the systemd unit), plus `exe`, `unit`, `transport`, `boot_id`, `uid`, `gid` and the entry `seqnum`.
- Method: a forensic scan of the file's objects from the header to the tail, not a walk of its hash tables, so entries the file's own index no longer links are still recovered.
- Safety: journals are untrusted evidence. Every offset and size is bounds-checked, a single field is capped at 1 MiB decompressed, at most 1,000,000 entries are read per file, and a damaged file yields the entries read before the damage plus an explicit "incomplete" event instead of failing.
- Not verified: checksums and Forward Secure Sealing are not checked.

### Linux Syslog (`linux_syslog`)
- Sources: `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log`
- Events: Generic syslog lines with timestamp, host, process, pid, severity
- Fields: `timestamp`, `detected_host`, `process`, `pid`, `severity`, `message`
- Firewall packet logs: lines logged by netfilter (iptables, nftables, ufw, firewalld) are expanded in `kern.log`, `syslog`, `messages`, `ufw.log`, `iptables.log` and the systemd journal. Extracted: `source_ip`, `destination_ip`, source and destination port, `network_protocol`, `interface_in`, `interface_out`, TCP flags and `firewall_action`. The verdict is read from the rule's log prefix (`[UFW BLOCK]`, `FINAL_REJECT:`, ...) as `block`, `reject`, `drop`, `allow`, `audit` or `limit`, and a prefix this does not recognise is reported as plain `log`; the prefix text itself is kept in `firewall_prefix`. The addresses and ports are also placed on the standard network fields, so these events appear in network views and can be pivoted on.
- Firewall limits: only packet lines are expanded, not the rule configuration; a custom prefix that names no verdict word reads as `log`. `firewalld`'s own daemon log (`/var/log/firewalld`) is not syslog-formatted and is read by the generic text parser.

### Searching Linux events
Search accepts the Linux fields directly (`linux.jail:sshd`, `linux.firewall_action:block`, `network.source_ip:203.0.113.9`) and these shortcuts, which combine with `AND`, `OR`, `NOT` and parentheses like any other field:

| Shortcut | Searches | Example |
| --- | --- | --- |
| `ip:` | every place an address is stored: `source.ip`, `destination.ip`, `network.source_ip`, `network.destination_ip`, `linux.source_ip`, `linux.destination_ip` | `ip:203.0.113.9` |
| `port:` | `network.source_port`, `network.destination_port` | `port:22` |
| `proto:` | `network.protocol`, `linux.network_protocol` | `proto:udp` |
| `process:` | `process.name`, `linux.process` | `process:sshd` |
| `user:` / `host:` | the standard field and its `linux.*` counterpart | `user:alice` |
| `verdict:` | firewall verdict (`block`, `reject`, `drop`, `allow`, `audit`, `limit`) | `verdict:block ip:203.0.113.9` |
| `action:` | `event.action` | `action:fail2ban_ban` |
| `jail:` | fail2ban jail | `jail:sshd` |
| `xff:` | original client behind a proxy (`X-Forwarded-For`) | `xff:198.51.100.77` |
| `webserver:` | `apache` or `nginx` | `webserver:nginx` |
| `indicator:` | a flagged marker on a persistence line or web request | `indicator:reverse_shell` |
| `library:` / `pam:` | `ld.so.preload` library path, PAM module | `library:*hook*` |
| `exe:` | executable (auditd, journal) | `exe:*/curl` |
| `audit:` / `auditkey:` | auditd record type / key | `audit:EXECVE` |
| `timequality:` | how far the time can be trusted (`ok`, `assumed_utc`, `assumed_year_utc`, `missing`) | `NOT timequality:ok` |

Plain text still searches every field, so `203.0.113.9` alone finds an address anywhere. The fields above are declared in the index mapping when an evidence item is ingested or reprocessed: events indexed before then still answer to plain text, but not to the newer field names, and authentication events indexed earlier lack `network.source_ip` until they are reprocessed.

### Sigma rules on Linux logs
Sigma rules with `logsource: product: linux` run against Linux events. What each source contributes:

| Source | Treated as `process_creation` | Fields Sigma can use |
| --- | --- | --- |
| Shell history (`.bash_history`, `.zsh_history`, BSD `bash.log`/`sh.log`) | yes, one command per line | `CommandLine`, `Image` (by name, see below), `User` |
| auditd `EXECVE` record | yes (the canonical process-creation record) | `CommandLine`, `Image`, `a0`..`a7`, `type`, `User` |
| auditd `USER_CMD` record (sudo) | yes | `CommandLine`, `exe`, `cwd` |
| auditd `SYSCALL`, `PATH`, `PROCTITLE` | no (auditd rules without a category still match them) | `exe`, `key`, `euid`, `SYSCALL`, `name`, `type`, `cwd` |

- **`Image` without a path.** Shell history records a command as typed (`wget http://...`), never the path it resolved to, and Kairon does not invent one. A rule value that is a bare name with a single leading slash (`Image|endswith: '/wget'`) therefore also matches when the process **name** equals `wget`; such matches carry the data-quality flag `sigma_image_matched_by_process_name`. A value with a directory (`'/usr/bin/wget'`) stays strict and only matches a real path (an auditd `exe`, or a path typed in full). Launchers (`sudo`, `env`, `nohup`...) and leading `VAR=value` assignments are skipped when naming the program.
- **auditd command lines.** `EXECVE` argv is rebuilt from `a0..aN`, including the hex-encoded form auditd uses for arguments with spaces or special characters. Fields inside `msg='...'` (as in `USER_CMD`) are extracted. For records without a command line, `linux.command` keeps its earlier meaning (`comm=`).
- **Index fields.** `linux.exe`, `linux.cwd`, `linux.euid`, `linux.syscall`, `linux.audit_type`, `linux.audit_key`, `linux.audit_name`, `linux.audit_a0`..`a7`, `linux.timestamp_status` and `linux.log_format` are declared in the index mapping, so they are searchable and filterable. Documents indexed before this change have them only in the stored document: reprocess the evidence to make those events searchable by the new fields.
- **Keyword rules.** A selection that is a bare list of strings (`keywords: ['Failed password', ...]`, the usual shape of `auth`, `syslog` and `sshd` rules) is searched as free text in the event message, case-insensitively, with Sigma `*` and `?` wildcards (`\*` for a literal star). It is supported **only for `logsource: product: linux`**; for any other product such a rule is still refused (`keyword_only_detection`). Rules with `service: auth`, `sshd`, `sudo`, `syslog`, `cron` or `auditd` are only tested against the Linux log types that can carry that service (for example an `sshd` rule is never tested against shell history). A keyword that carries almost no literal text (fewer than 3 literal characters, such as `*`, `-t` or `(){:;};`) is refused with `keyword_too_broad`, because on its own it would match nearly every event; so are lists of more than 200 keywords. Refusal is deliberate: a rule that looks armed but matches everything is worse than one that does not load.
- **Not supported yet.** Fields no Linux source carries (`unit`, `LogonId`), and Linux rules with `category: file_event` or `category: network_connection`: no Linux source is labelled with those categories.
- **Shell history is not proof of execution.** A history line shows a command was typed, not that it ran or succeeded; a Sigma hit on it is a lead to verify.

### Other Text Logs (`linux_generic_log`)
- Sources: any `.log`, `.out` or `.err` file (plain, rotated such as `app.log.1` / `app.log-20240101`, or compressed with gzip, bzip2 or xz) under `/var/log`, `/var/lib/docker/containers`, `/var/www`, `/opt`, `/srv`, `/usr/local`, `/home`, `/root` or `/tmp`; plus `.txt` files and a short list of well-known extensionless logs (`dmesg`, `debug`, `daemon`, `mail`, `ufw`...) directly under `/var/log`. Typical finds: database, Docker container, cloud-init and application logs (Apache and nginx have their own parser, below).
- Last resort: a file is only routed here after every dedicated parser (auth, syslog, audit, Apache, Exim, packages, ...) has declined it, so it never changes how a recognised artifact is parsed.
- Format: sniffed once per file from a sample of lines. Supported: JSON lines, ISO 8601 / `YYYY-MM-DD HH:MM:SS` / `YYYY/MM/DD HH:MM:SS`, BSD syslog, and Common/Combined Log Format. Lines that do not start a new entry (stack traces, wrapped output) are folded into the entry before them.
- Fields: `timestamp`, `message`, `process`, `pid`, `severity`, `username`, `source_ip`, `host` (syslog format), `log_format`, `timestamp_status`, `source_file`, `line_number`. User, IP, process and severity are extracted heuristically from the text; the original line is always kept.
- Timestamps: `timestamp_status` says how far to trust the time: `ok` (explicit offset or epoch), `assumed_utc` (no timezone in the log, read as UTC), `assumed_year_utc` (syslog lines carry no year; the current year is assumed, rolling back a year if that would land in the future) or `missing` (undated; the line is still indexed and searchable). Dates before 1990 or more than a year ahead are rejected.
- Limits: at most 256 MiB of text is read per file (the decompressed size for compressed logs); a truncated or damaged archive keeps what could be read and adds an explicit "log truncated" event. Binary files produce no events.
- Limitations: heuristic extraction, not a schema-aware parser. A loose `.log` or `.txt` uploaded on its own, with no Linux path around it, is not routed here.

### Web Server Logs: Apache and nginx (`linux_apache`)
- Sources: `/var/log/apache2/`, `/var/log/httpd/` and `/var/log/nginx/` access and error logs, including per-site files (`shop.access.log`, `site-error.log`) and rotated or compressed copies.
- Access formats: Common/Combined Log Format (the default for both servers) and JSON lines, as written by an nginx `log_format ... escape=json` (field names such as `remote_addr`, `request`, `status`, `http_user_agent`, `time_iso8601` are recognised).
- Error formats: the Apache error log and the nginx error log, from which `client`, `server`, `request`, `upstream` and `host` are extracted.
- Fields: `timestamp`, `source_ip`, `username`, `http_method`, `url_path` (query string included), `http_status`, `bytes_sent`, `http_referrer`, `http_user_agent`, `web_server` (`apache` or `nginx`, taken from the path and left blank when the path does not say), `x_forwarded_for`, and for nginx errors `server_name`, `upstream` and `http_host`.
- Behind a proxy or load balancer, `source_ip` is the proxy that connected. When the access log carries an `X-Forwarded-For` value as a trailing quoted field, the first valid address in it is kept in `x_forwarded_for` as the original client; any other trailing quoted value (a request time, `-`, text) is ignored.
- Request lines are decoded passively (percent-decoding and printable base64) to flag web-shell and reverse-shell indicators in `suspicious_url_indicators`. Nothing is executed or fetched.
- Timestamps: access logs carry their own offset. The nginx error log carries none, so it is read as UTC and marked `timestamp_status: assumed_utc`.
- Limitations: custom `log_format` layouts other than the ones above fall back to an undated line with the original text; Sigma `webserver` rules (W3C field names such as `cs-uri-query`) are not mapped yet.

### Persistence configuration (`linux_persistence`)
- Sources: `/etc/ld.so.preload`, `/etc/ld.so.conf` and `ld.so.conf.d/*`, `/etc/rc.local`, PAM rules (`/etc/pam.d/*`), shell start-up files (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/update-motd.d/*`, and each user's `~/.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`), and queued `at` jobs (`/var/spool/cron/atjobs/*`, `/var/spool/at/*`).
- Why it matters: these are where an intruder keeps access or hides on Linux: a library preloaded into every process, a command run at boot or at every login, a PAM rule that weakens authentication, a job queued with `at`.
- Method: every active line (not blank, not a comment) is one row with the original text. `ld.so.preload` yields one row per library. PAM lines are split into `pam_type`, `pam_control`, `pam_module` and `pam_args`. Files under `/usr/share` and `/usr/lib` (package templates) are ignored. Nothing is executed.
- Flags, not verdicts: `suspicious_indicators` lists generic markers for an analyst to review. For scripts: `download_and_run`, `reverse_shell`, `obfuscation`, `inline_interpreter`, `world_writable_path`, `hidden_path`, `ld_preload_set`, `prompt_command_hook`, `shadowed_command_alias`. For `ld.so.preload`: every entry is `preload_library` (any preload is unusual) and one outside the standard library directories is also `unusual_preload_path`. For PAM: `pam_exec`, `auth_always_permit` (`auth sufficient pam_permit.so`), `nonstandard_pam_module`. A flagged line is `medium` severity and an unusual preload path is `high`; nothing is confirmed malicious by this parser, and ordinary lines stay `info`.
- Timestamps: these are configuration snapshots with no time in their content, so rows are undated (`timestamp_status: missing`) and are not shown on the timeline. The file's modification time is not read here.
- Limitations: the indicator list is a fixed, generic vocabulary and will miss anything it does not name; `init.d` scripts, systemd units (see `linux_systemd`), cron (see `linux_cron`), `.bash_history` (see shell history) and `authorized_keys` (see SSH) are handled by their own parsers.

### fail2ban (`linux_fail2ban`)
- Sources: `/var/log/fail2ban.log`, including rotated and compressed copies.
- Why it matters: fail2ban bans an address after repeated failures against a service, so its log is a ready-made record of who attacked the host, which service (the *jail*, e.g. `sshd`) they hit, and when they were banned and released.
- Events (`event_action`): `found` (a failed attempt was detected), `ban`, `unban`, `restore_ban` (a ban re-applied after a restart), `already_banned`, `ignore`, `jail_started`, `jail_stopped`, `jail_configured`, and `log` for anything else.
- Fields: `timestamp`, `severity`, `jail`, `source_ip` (the address concerned; IPv4 and IPv6), `event_action`, `component`, `pid` (absent in older releases, which are still parsed), `message`. The address is also placed on `network.source_ip`.
- Timestamps: fail2ban writes the server's local time with no zone, so it is read as UTC and marked `timestamp_status: assumed_utc`. On a `found` line the time of the failed attempt itself is only in the message; the row's time is when fail2ban logged it.
- Limitations: lines that do not follow the fail2ban layout are kept undated rather than dropped. The jail and filter configuration (`/etc/fail2ban`) is not parsed.

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
- Binary systemd journals are parsed (see below), but not verified: the journal's per-object checksums and sealing (FSS) are not checked, so a tampered journal is read as written.
- SELinux policy database parsing is not implemented.
- macOS collection parsing is not implemented.
- Executing uploaded scripts or binaries is never done.
- Multi-line audit events are parsed per-line in v1.
- Systemd timer expressions are not fully parsed.
- ZSH history without extended timestamps has no time context.
- Package manager detection is format-based, not exhaustive.

Unsupported artifacts can still appear in inventory so analysts know they were present but not parsed.
