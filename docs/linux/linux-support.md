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
- Fields: `timestamp` (microsecond precision), `message`, `hostname`, `process` (`SYSLOG_IDENTIFIER`, else `_COMM`), `pid`, `event_action` (the systemd unit), `severity`, plus `exe`, `unit`, `transport`, `boot_id`, `uid`, `gid` and the entry `seqnum`, all searchable (`linux.exe`, `linux.unit`, `linux.transport`, ...).
- User: the journal records a numeric `_UID`. UID 0 is shown as `root`; any other uid is kept as `user.id` and **not** presented as a user name, because the journal does not say which account it is.
- Method: a forensic scan of the file's objects from the header to the tail, not a walk of its hash tables, so entries the file's own index no longer links are still recovered.
- Safety: journals are untrusted evidence. Every offset and size is bounds-checked, a single field is capped at 1 MiB decompressed, at most 1,000,000 entries are read per file, and a damaged file yields the entries read before the damage plus an explicit "incomplete" event instead of failing.
- Not verified: checksums and Forward Secure Sealing are not checked.

### Times of log lines without a zone or a year

Most Linux logs write the host's local time with no zone, and syslog-style lines (`Apr  3 18:15:13`) write no year either. Each parser first marks such lines `assumed_utc` or `assumed_year_utc`; Kairon then corrects them per host, using the rest of the same evidence:

- **Zone.** The host's timezone is read from `/etc/timezone` or the `/etc/localtime` TZif file, and local times are converted to UTC with it, daylight saving included. Such lines are marked `host_timezone`.
- **Year.** A line was written while the machine was running, and `wtmp` records every boot and shutdown with an exact UTC time. The year chosen is the one in which the line falls inside a boot-to-shutdown interval (the last boot runs until the last login record seen). Without `wtmp`, or when no year fits, the year comes from the file itself as plaso does it: the last line belongs to the year of the file's modification time, and walking back up the file a jump forward in the calendar means the previous year. These lines are marked `inferred_year_host_timezone`, or `inferred_year` when the zone is unknown and the time is read as UTC.
- Disk images keep each file's modification time on extraction so this works; collections that do not keep it (a ZIP extracted without times) fall back to the extraction date, which assumes the current year as before.
- `assumed_utc` and `assumed_year_utc` therefore remain only on hosts whose timezone could not be found. Check a line's `timestamp_status` (search `timequality:`) before relying on its exact time.

### Severity of log lines
For syslog, the systemd journal, the generic text parser and fail2ban, the severity column reflects the line's own level instead of a blanket `info`: syslog and journal priorities 0-2 (emerg, alert, crit) are `high`, 3 (err) `medium`, 4 (warning) `low` and 5-7 `info`; level words (`error`, `WARNING`, `crit`, ...) and the `facility.level` form (`auth.err`) map the same way. A line with no recognisable level keeps the previous default. This is the log's own claim about itself, not an assessment of whether the event matters.

### Mail servers: Postfix and Dovecot (inside syslog and the journal)
- Sources: `/var/log/mail.log`, `/var/log/maillog`, `mail.info`, `mail.warn`, `mail.err` (rotated and compressed copies included) and the systemd journal. Lines are recognised by the process name (`postfix/smtpd`, `postfix/qmgr`, `dovecot`, `imap-login`...), so syslog and journal copies are treated the same. Exim has its own parser.
- Why it matters: mail abuse shows up here: a password-guessing run against SMTP or IMAP, an open relay being tried, a compromised account sending spam.
- Postfix: refused relay attempts (`NOQUEUE: reject`) with the client address, SMTP code and reason, the sender, recipient and HELO; SASL authentication failures with the client address and method; authenticated submissions with the user (`sasl_username`) and client; connect, disconnect and lost-connection lines; and the queue lifecycle (message id, sender, then each delivery with its recipient, relay, status `sent`, `bounced` or `deferred` and SMTP code), all tied together by the **queue id**.
- Dovecot: IMAP/POP3 logins with the user, method, client and server address; failed logins (`auth failed`, `Aborted login`, and backend failures from `pam`, `sql`, `ldap`, `passwd-file`) naming the targeted account and the source; session ends. A login process disconnecting (no session) is recorded as a disconnect, a session ending as a logout.
- Fields: `mail_service` (`postfix` or `dovecot`), `mail_component`, the action in `event.action` (`mail_reject`, `mail_auth_failed`, `mail_login`, `mail_received_authenticated`, `mail_queued`, `mail_delivery`...), `mail_status` (`sent`, `bounced`, `deferred`, `reject`, `failed`, `success`), `sender`, `recipient`, `queue_id`, `smtp_status`, `helo`, `message_id`, the client address in `network.source_ip`, the server or relay address in `destination.ip`, the authenticated user in `user.name`, `mail_relay`, `mail_reason`. Searchable with `sender:`, `recipient:`, `queue:`, `mailstatus:`, `mailservice:`, `relay:`, `ip:`, `user:`.
- Severity: a failed login is `medium` whatever level the line carries, a refused relay, bounce or deferral is `low`, and a higher level the line itself carries is kept. These are the log's own outcomes, not an assessment that the activity is malicious.
- Limits: only the shapes above get dedicated fields; other Postfix and Dovecot lines remain plain syslog text. The queue id is the only link between the lines of one message, so a queue id reused after a restart is not told apart. `sender`, `recipient` and `queue_id` were also written by the Exim parser but were never declared in the index mapping, so they were not searchable for Exim either; they are now, for newly ingested or reprocessed evidence.

### Sysmon for Linux (events inside syslog and the journal)
- Sources: Sysmon for Linux writes each event as one line of Windows-style XML to syslog (tag `sysmon`: `/var/log/syslog`, `/var/log/messages`, or the systemd journal). They are recognised by content (`Linux-Sysmon` in an `<Event>` line), so no particular file name is needed.
- Why it matters: these are the structured events Sigma's Linux `process_creation`, `network_connection` and `file_event` rules were written for. Shell history and auditd cover part of the same ground, but without a parent process, a working directory or a hash.
- Events extracted: process created (1), network connection (3), process terminated (5), file created (11), file deleted (23), and any other event id with its image and fields (shown as `Sysmon event N`).
- Fields: for a process, `process.path` / `executable` / `name`, `command_line`, `current_directory`, `pid`, the user, the SHA-256 when logged, and the parent's image, command line and PID, with `ProcessGuid` / `ParentProcessGuid` as the process and parent entity ids. For a network connection, `network.*` and `destination.*` (address, port, protocol). For files, `file.path`. `event.code` carries the Sysmon event id and `event.type` the Sigma-recognised label (`sysmon_process_created`, `sysmon_network_connection`, `sysmon_file_created`).
- Time: the event's own UTC time (`TimeCreated`, else `UtcTime`) is used, which is exact and carries no year or timezone guess; the syslog header's time is not needed.
- Text: the row's message becomes a readable summary (`Process created: curl ... (parent /bin/bash)`); the original line stays in the raw excerpt.
- Safety: the XML is read with fixed, bounded patterns rather than an XML parser, so a hostile line cannot trigger entity expansion or external references; an event larger than 64 KiB, or with more than 128 data items, is read only as far as those limits. A line cut off mid-event keeps what was readable.
- Limitations: only the event shapes above are given dedicated fields; events written in a different layout (a forwarder that rewrites the XML) are left as plain syslog text.

### Linux Syslog (`linux_syslog`)
- Sources: `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log`
- Events: Generic syslog lines with timestamp, host, process, pid, severity
- Fields: `timestamp`, `detected_host`, `process`, `pid`, `severity`, `message`
- Firewall packet logs: lines logged by netfilter (iptables, nftables, ufw, firewalld) are expanded in `kern.log`, `syslog`, `messages`, `ufw.log`, `iptables.log` and the systemd journal. Extracted: `source_ip`, `destination_ip`, source and destination port, `network_protocol`, `interface_in`, `interface_out`, TCP flags and `firewall_action`. The verdict is read from the rule's log prefix (`[UFW BLOCK]`, `FINAL_REJECT:`, ...) as `block`, `reject`, `drop`, `allow`, `audit` or `limit`, and a prefix this does not recognise is reported as plain `log`; the prefix text itself is kept in `firewall_prefix`. The addresses and ports are also placed on the standard network fields, so these events appear in network views and can be pivoted on.
- Firewall limits: only packet lines are expanded, not the rule configuration; a custom prefix that names no verdict word reads as `log`. `firewalld`'s own daemon log (`/var/log/firewalld`) is not syslog-formatted and is read by the generic text parser.

### Viewing Linux logs
Each Linux log family has its own table layout in Artifact Explorer (open **Linux Artifacts** and pick a family). Every layout shows the log's own text in a **Message** column, so the content that matters is on screen even when no parser pulled it into a dedicated field; for the generic text parser the message is the event. Secondary fields are in the **Columns** chooser, not hidden away.

| Family | Columns shown by default |
| --- | --- |
| Syslog | Timestamp, Host, Process, Severity, Message |
| Syslog with Postfix / Dovecot lines (30% or more of the rows) | Timestamp, Service, Action, Client IP, User, Sender, Recipient, Status, Queue ID, Severity, Message |
| Syslog with Sysmon for Linux events (30% or more of the rows) | Timestamp, Event, User, Image, Command Line, Parent Image, Destination IP, Dst Port, Target File, Host, Message |
| Syslog with firewall packets (30% or more of the rows) | Timestamp, Verdict, Proto, Source IP, Destination IP, Dst Port, In (interface), Host, Severity, Message |
| systemd journal | Timestamp, Host, Unit, Process, Severity, User, Message |
| Authentication | Timestamp, Host, User, Event, Source IP, Method, Result, Process, Severity, Message |
| auditd | Timestamp, Host, Record, Executable, Command, User, Key, Severity, Message |
| Web server (Apache, nginx) access | Timestamp, Source IP, Host, Method, Request, HTTP Status, User Agent, plus Web Server and Real Client (X-Forwarded-For) when present |
| Web server error | Timestamp, Severity, Host, Source IP, Event Type, Server, Request, Message |
| fail2ban | Timestamp, Jail, Action, Address, Severity, Message |
| Text log (generic) | Timestamp, Host, Process, Severity, User, Source IP, Message |
| Container logs | Timestamp, Container, Stream, Severity, Message (Pod and Namespace appear for Kubernetes logs) |
| Container configuration | Created, Kind, Name, Image, State, Command, Flags, Privileged, Network, Severity, Message |
| Kubernetes audit | Timestamp, User, Verb, Resource, Namespace, Name, Source IP, Status, Decision, Flags, Severity, Message (Subresource appears when a request has one) |
| Persistence configuration | Kind, Severity, Owner, Entry / Command, PAM, Flags, Source File, Line |

- **Time Quality** appears automatically when any row on screen has a time that is not exact (`Assumed UTC`, `Assumed year and UTC`, `No time in the log`), so a time the parser had to assume is never mistaken for an exact one. It can also be switched on from the Columns chooser.
- **Pivot**: click a source or destination address, process, verdict, jail, protocol, executable, auditd record type, web server or `X-Forwarded-For` value to filter on it or exclude it. Addresses use the standard address filter; the others add a term such as `verdict:"block"` to the search box, where it stays visible and editable (see *Searching Linux events*). Cells that combine several values are not pivotable: the process name and its PID are separate columns for that reason.
- **Row details**: opening a row adds a section for what the family carries: *Firewall packet*, *Journal*, *Authentication*, *Audit record*, *fail2ban*, *Persistence entry*, *Web server*, *Time*.
- **Search page**: for a Linux network event the key entity is the remote (source) address, and a label that replaced the log line (such as an authentication result) is shown next to the original text instead of hiding it.
- Mixed results (several artifact types in one table) fall back to the general columns, which include a summary column.

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
| `timequality:` | how far the time can be trusted (`ok`, `host_timezone`, `inferred_year_host_timezone`, `inferred_year`, `assumed_utc`, `assumed_year_utc`, `missing`) | `NOT timequality:ok` |

Plain text still searches every field, so `203.0.113.9` alone finds an address anywhere. The fields above are declared in the index mapping when an evidence item is ingested or reprocessed: events indexed before then still answer to plain text, but not to the newer field names, and authentication events indexed earlier lack `network.source_ip` until they are reprocessed.

### Sigma rules on Linux logs
Sigma rules with `logsource: product: linux` run against Linux events. What each source contributes:

| Source | Treated as `process_creation` | Fields Sigma can use |
| --- | --- | --- |
| Shell history (`.bash_history`, `.zsh_history`, BSD `bash.log`/`sh.log`) | yes, one command per line | `CommandLine`, `Image` (by name, see below), `User` |
| Sysmon for Linux events | yes: process created (1); network connection (3) and file created/deleted (11, 23) for their categories | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `DestinationIp`, `DestinationPort`, `TargetFilename` |
| auditd `EXECVE` record | yes (the canonical process-creation record) | `CommandLine`, `Image`, `a0`..`a7`, `type`, `User` |
| auditd `USER_CMD` record (sudo) | yes | `CommandLine`, `exe`, `cwd` |
| auditd `SYSCALL`, `PATH`, `PROCTITLE` | no (auditd rules without a category still match them) | `exe`, `key`, `euid`, `SYSCALL`, `name`, `type`, `cwd` |

- **`Image` without a path.** Shell history records a command as typed (`wget http://...`), never the path it resolved to, and Kairon does not invent one. A rule value that is a bare name with a single leading slash (`Image|endswith: '/wget'`) therefore also matches when the process **name** equals `wget`; such matches carry the data-quality flag `sigma_image_matched_by_process_name`. A value with a directory (`'/usr/bin/wget'`) stays strict and only matches a real path (an auditd `exe`, or a path typed in full). Launchers (`sudo`, `env`, `nohup`...) and leading `VAR=value` assignments are skipped when naming the program.
- **auditd command lines.** `EXECVE` argv is rebuilt from `a0..aN`, including the hex-encoded form auditd uses for arguments with spaces or special characters. Fields inside `msg='...'` (as in `USER_CMD`) are extracted. For records without a command line, `linux.command` keeps its earlier meaning (`comm=`).
- **Index fields.** `linux.exe`, `linux.cwd`, `linux.euid`, `linux.syscall`, `linux.audit_type`, `linux.audit_key`, `linux.audit_name`, `linux.audit_a0`..`a7`, `linux.timestamp_status` and `linux.log_format` are declared in the index mapping, so they are searchable and filterable. Documents indexed before this change have them only in the stored document: reprocess the evidence to make those events searchable by the new fields.
- **Keyword rules.** A selection that is a bare list of strings (`keywords: ['Failed password', ...]`, the usual shape of `auth`, `syslog` and `sshd` rules) is searched as free text in the event message, case-insensitively, with Sigma `*` and `?` wildcards (`\*` for a literal star). It is supported **only for `logsource: product: linux`**; for any other product such a rule is still refused (`keyword_only_detection`). Rules with `service: auth`, `sshd`, `sudo`, `syslog`, `cron` or `auditd` are only tested against the Linux log types that can carry that service (for example an `sshd` rule is never tested against shell history). A keyword that carries almost no literal text (fewer than 3 literal characters, such as `*`, `-t` or `(){:;};`) is refused with `keyword_too_broad`, because on its own it would match nearly every event; so are lists of more than 200 keywords. Refusal is deliberate: a rule that looks armed but matches everything is worse than one that does not load.
- **Web-server rules.** Sigma `webserver` rules (`logsource: category: webserver`, no product) run on Apache and nginx **access** log lines; error-log lines are not requests and are never tested against them. Their W3C field names map to the parsed request: `cs-method` (method), `sc-status` (HTTP status), `cs-uri-stem` (the request path before the first `?`), `cs-uri-query` (the raw query string after it), `cs-uri` / `c-uri` (the whole target), `cs-user-agent` / `c-useragent`, `cs-referer`, `cs-username`, `c-ip` (the client address as the server saw it), `cs-version` and `sc-bytes`. The target is matched as logged, **percent-encoded**: a rule that looks for `../` and a rule that looks for `..%2f` are different rules, as in any web log. Matching is case-insensitive.
- **Web-server rule limits.** A rule is skipped as `missing fields` when no line in the case records what it needs (for example `cs-host`, because the default access-log format does not log the `Host` header, or a referrer when every request has none). Rules that search the request **body**, or the text of the whole line, cannot work on an access log and are refused. `field: null` (a field absent or empty) is not evaluated by the engine for any product, so the few web rules that use it, such as ReGeorg, do not fire; this is a general engine limit, not specific to web logs. Percent-decoded variants of a value are not tried automatically.
- **Candidate search.** To find candidate events a rule queries the `linux.*` web fields, which are exact-case keyword fields; those clauses are built case-insensitively, list every value of the rule, and fall back to "the field is present" for a list of more than 400 values, so the in-memory test (which is the one that decides) never loses an event to the pre-filter. Values longer than the field's limit (4096 characters for URLs, 2048 for user agents and referrers) are not indexed and are matched only when the event is read directly.
- **Not supported yet.** Fields no Linux source carries (`unit`, `LogonId`), and Linux rules with `category: file_event` or `category: network_connection`: no Linux source is labelled with those categories.
- **Shell history is not proof of execution.** A history line shows a command was typed, not that it ran or succeeded; a Sigma hit on it is a lead to verify.

### Other Text Logs (`linux_generic_log`)
- Sources: any `.log`, `.out` or `.err` file (plain, rotated such as `app.log.1` / `app.log-20240101`, or compressed with gzip, bzip2 or xz) under `/var/log`, `/var/lib/docker/containers`, `/var/www`, `/opt`, `/srv`, `/usr/local`, `/home`, `/root` or `/tmp`; plus `.txt` files and a short list of well-known extensionless logs (`dmesg`, `debug`, `daemon`, `mail`, `ufw`...) directly under `/var/log`. Typical finds: cloud-init and application logs (Apache, nginx, databases and containers have their own parsers, below).
- Last resort: a file is only routed here after every dedicated parser (auth, syslog, audit, Apache, Exim, packages, ...) has declined it, so it never changes how a recognised artifact is parsed.
- Format: sniffed once per file from a sample of lines. Supported: JSON lines, ISO 8601 / `YYYY-MM-DD HH:MM:SS` / `YYYY/MM/DD HH:MM:SS`, BSD syslog, and Common/Combined Log Format. Lines that do not start a new entry (stack traces, wrapped output) are folded into the entry before them.
- Fields: `timestamp`, `message`, `process`, `pid`, `severity`, `username`, `source_ip`, `host` (syslog format), `log_format`, `timestamp_status`, `source_file`, `line_number`. User, IP, process and severity are extracted heuristically from the text; the original line is always kept.
- Timestamps: `timestamp_status` says how far to trust the time: `ok` (explicit offset or epoch), `assumed_utc` (no timezone in the log, read as UTC), `assumed_year_utc` (syslog lines carry no year; it is then inferred as described in *Times of log lines without a zone or a year*) or `missing` (undated; the line is still indexed and searchable). Dates before 1990 or more than a year ahead are rejected.
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
- Limitations: custom `log_format` layouts other than the ones above fall back to an undated line with the original text; see *Sigma rules on Linux logs* for the web-server rules that run on these logs.

### Containers (`linux_container`)
- Sources: Docker `json-file` logs (`/var/lib/docker/containers/<id>/<id>-json.log`), CRI logs written by containerd or CRI-O for Kubernetes (`/var/log/pods/<namespace>_<pod>_<uid>/<container>/<n>.log` and the `/var/log/containers/<pod>_<namespace>_<container>-<id>.log` links), and Docker's `config.v2.json` and `hostconfig.json`; rotated and compressed copies included.
- Log lines: one event per line of container output with the exact time Docker or the runtime recorded, the stream (`stdout` or `stderr`), the container id, and for Kubernetes the pod, namespace and container name taken from the path. A line the runtime split in pieces (a Docker entry with no trailing newline, a CRI `P` entry) is joined back into one under the first piece's time. An application that logs JSON has its message and level lifted out of the object; a level word in plain text sets the severity. The first IPv4 address and a `user=` value in the text are extracted the same way as for generic text logs.
- Configuration: one row per file describing what the container is (name, image, state, exit code, command, user) and what it may do (privileged mode, network, PID and IPC mode, added capabilities, device and bind mounts, security options). It is dated by the container's creation time.
- Flags for review, never verdicts: `privileged_container`, `host_network`, `host_pid`, `host_ipc`, `host_userns`, `dangerous_capability`, `unconfined_security` (seccomp, AppArmor or SELinux label disabled), `host_device`, `host_path_mount`, `sensitive_host_mount` (a host path such as `/etc`, `/root`, `/proc` or `/var/lib/docker`), `host_root_mount`, `docker_socket_mount` (the Docker, containerd or CRI-O socket mounted in), `ld_preload_env` and `secret_in_environment`. Privileged mode, the Docker socket and the host root are `high` severity; any other flag is `medium`. A named volume is not a host path and is not flagged.
- **Environment variable values are never stored**, only their names, because they routinely hold credentials; a name that looks like a secret (`PASSWORD`, `TOKEN`, `API_KEY`...) is what raises `secret_in_environment`. The values stay in the original evidence file.
- Search: `container:` (name or id), `image:`, `pod:`, `namespace:`, `stream:`, and `indicator:privileged_container`.
- Limits: a Docker log is only as complete as Docker's own rotation left it, and `docker logs` output kept by a different logging driver (journald, syslog, fluentd) is read from there instead. `hostconfig.json` is parsed on its own, so its flags are not merged into the container's `config.v2.json` row. Image layers, volumes' contents and the Docker daemon's own log are not parsed here.

### Databases (`linux_database`)
- Sources: MySQL, MariaDB and Percona logs (`/var/log/mysql*`, `/var/log/mariadb`, `/var/log/mysqld.log`, `*.err` and `*.log` in `/var/lib/mysql`): the error log, the general query log, the slow query log and the MariaDB `server_audit` plugin log; PostgreSQL logs in `/var/log/postgresql` or the data directory (`log`, `pg_log`) in the default text layout, `csvlog` and `jsonlog`. Rotated and compressed copies are read, and the layout is chosen from the content because the file names vary.
- Why it matters: they are the record of who connected to the database, from where, whether authentication failed, and (when statement logging is on) what was run.
- Events (`event_action`): `db_connect`, `db_auth_failed`, `db_connection_received`, `db_connection_aborted`, `db_disconnect`, `db_query`, `db_slow_query`, `db_host_blocked`, `db_error` and `log`.
- Fields: `timestamp`, `username`, `source_ip` and `source_port` (also on `network.*`), `db_engine`, `db_name`, `db_command`, `db_statement` (a multi-line statement is kept whole and searchable), `db_status`, `db_level`, `db_error_code`, `db_thread_id`, `db_application`, and for the slow log `db_query_time`, `db_rows_sent` and `db_rows_examined`. A PostgreSQL `STATEMENT:` line is attached to the error above it. Search shortcuts: `dbengine:`, `database:`, `dbcommand:`, `dbstatus:`, `dberror:`, `sql:`.
- Flags for review, never verdicts (`suspicious_indicators`): `account_change` (`GRANT`, `CREATE USER`, `ALTER ROLE`, `SET PASSWORD`), `destructive_statement` (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`), `file_access` (`LOAD_FILE`, `INTO OUTFILE`, `LOAD DATA INFILE`, `pg_read_file`, `COPY` from a file), `command_execution` (`COPY ... PROGRAM`, `sys_exec`, a UDF from a shared library), `credential_table_access` (`mysql.user`, `pg_shadow`), `schema_enumeration` (`information_schema`) and `sql_injection_pattern` (`UNION SELECT`, tautologies, `SLEEP`/`pg_sleep`, error-based functions). A failed login or any flag is `medium`; otherwise the severity follows the log level (`PANIC`/`FATAL` high, error/warning medium).
- Timestamps: MySQL 8 and PostgreSQL write an exact time with a zone; MariaDB's error log, the MySQL 5.5/5.6 error log (`160403 19:02:55`) and the older MySQL general log have none and are local times converted with the host's timezone when it is known. The slow log's `SET timestamp=` epoch is used when present, and the general log's older layout, which prints the time only when it changes, inherits the previous time.
- Limits: statements appear only if the server was configured to log them (general log, `log_statement`, audit plugin); a log without them records connections and errors only. Statement text is capped, and the flags are pattern matches that miss obfuscated or split statements. Redo/binary logs, table files and the MongoDB, Redis and Oracle logs are not parsed here.

### VPN gateways (`linux_vpn`)
- Sources: the OpenVPN server log (`/var/log/openvpn/*.log`, `/var/log/openvpn.log`), the OpenVPN status file (`openvpn-status.log`, versions 1, 2 and 3), and the strongSwan `charon` log (`/var/log/charon.log`, `/var/log/strongswan/charon.log`); rotated and compressed copies included. strongSwan lines that went to syslog or the journal are read there, as syslog and journal events.
- Why it matters: the gateway records who got into the network, from which address, with which account or certificate, and what tunnel address they were given: the trail of a password-guessing run, or a valid credential used from somewhere new.
- Events (`event_action`): `vpn_connect`, `vpn_auth_failed`, `vpn_auth_ok`, `vpn_cert_verified`, `vpn_address_assigned`, `vpn_connection_received`, `vpn_tunnel_established`, `vpn_disconnect`, `vpn_session` (a session open when the status file was written), `vpn_error`; other lines are kept with their text.
- Fields: `timestamp`, `username` (the account, certificate name or IKE identity), `source_ip` and `source_port` (also on `network.*`), `vpn_software`, `vpn_status`, `vpn_assigned_ip` (the tunnel address), `vpn_connection`, `vpn_local_ip`, `vpn_traffic_selectors`, `vpn_component`, and for status files `vpn_bytes_received`, `vpn_bytes_sent` and `vpn_status_updated`. Search shortcuts: `vpn:`, `vpnstatus:`, `vpnip:`, `vpnconn:`.
- Flags for review, never verdicts: `repeated_auth_failures` on failed-authentication rows from a source address with five or more failures in the file. A failed authentication or any flag is `medium`.
- Timestamps: OpenVPN's classic prefix and strongSwan's ISO prefix carry no zone and are read as UTC (`assumed_utc`); strongSwan's syslog prefix carries no year, so the current year is assumed (`assumed_year_utc`). The status file's connection time uses the Unix epoch when present (exact).
- Limits: a status file is a snapshot, not a history; a username in the OpenVPN log appears only once the TLS handshake has identified it, so earlier lines of the same session carry the address only. WireGuard keeps no connection log and IPsec daemons other than strongSwan are not parsed here.

### Kubernetes audit (`linux_k8s_audit`)
- Sources: the API-server audit log (`audit.k8s.io` JSON lines): `/var/log/kubernetes/audit.log` (and files in a `kubernetes`, `kube-apiserver` or `k8s` directory with `audit` in the name), `/var/log/kube-apiserver/audit-*.log`, any file named like `kube-apiserver-audit.log`, rotated or compressed copies. A file called plain `audit.log` whose first line is an `audit.k8s.io` event is also read as Kubernetes rather than as auditd.
- Why it matters: it is the record of who did what in a cluster: the caller, the verb, the object, where the request came from and whether it was allowed.
- Fields: `timestamp` (the request time, exact), `username`, `source_ip` (the first valid address of `sourceIPs`), `k8s_verb`, `k8s_resource`, `k8s_subresource`, `k8s_namespace`, `k8s_object`, `k8s_decision` (the authorization annotation), the caller's groups and any impersonated user, the HTTP status, user agent, request URI, audit ID, stage and level. Searchable as `linux.k8s_*`, with the shortcuts `verb:`, `resource:`, `namespace:`, `decision:`.
- Flags for review, never verdicts: `pod_exec`, `pod_attach`, `pod_portforward`, `secret_access` (get/list/watch), `secret_change`, `rbac_change`, `cluster_admin_binding`, `token_request`, `impersonation`, `anonymous_request`, and `anonymous_success` when such a request returned a success status. For requests that create or change a pod, deployment, daemonset, statefulset, replicaset, job or cronjob and whose request body was logged (audit level `Request` or `RequestResponse`): `privileged_container`, `privilege_escalation_allowed`, `dangerous_capability`, `host_network`, `host_pid`, `host_ipc`, `host_path_mount`, `host_root_mount`, `docker_socket_mount`.
- Severity: a privileged or Docker-socket-mounting workload, a `cluster-admin` binding, or an anonymous request that succeeded is `high`; any other flag is `medium`; the rest `info`. A denied request (status 400 or above) is an outcome of `failure`.
- Limits: the workload flags need the audit policy to log request bodies; at the `Metadata` level only the verb, object and caller are available. An event over 2 MiB is not parsed and is reported as such, because request and response bodies can be very large.

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
