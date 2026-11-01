# Changelog

## Unreleased

### Added

- **Files** in the sidebar, listed when the case has a disk image or a collection: the case's browsable evidence by host, or the file explorer directly when there is only one. Host Information links to the files of the selected host.
- **Windows notifications** (`wpndatabase.db`): toast, tile and badge notifications with the sending app, title, body text, launch target and arrival time, and each app registered to send notifications. Read with the database's WAL on a scratch copy. Discovery lists it in raw collections with its `-wal`/`-shm`; before, it was only an inventory entry. See [docs/artifacts/windows_notifications.md](docs/artifacts/windows_notifications.md).
- **Browse files** for collections (ZIP/7z/TAR archives, uploaded folders, AD1 logical images): the disk file explorer shows the collection as one volume, with find and password-protected export. For AD1 images, the NTFS times, MD5/SHA1, owner and attributes FTK recorded at acquisition are shown and exports are checked against FTK's MD5.
- **AD1 logical images** (FTK Imager folder and custom-content images) can be uploaded, alone or as the only file of a ZIP. Preflight lists their files in place and registration repacks them into a ZIP that goes through the normal collection pipeline (discovery, hives, SRUM, Shellbags, LNK, Jump Lists, browsers...); the `.ad1` stays the hashed original. Multi-segment and ADCRYPT-encrypted images are rejected with that reason.
- **Folder uploads** from the evidence wizard are packed into one uncompressed ZIP in the browser and sent through the resumable upload, like any archive. Before, the whole folder went in one request: refused unless the experimental folder upload was enabled, limited to 2,000 files and 2 GB, and cut off by the proxy above 2 GB.
- **Password-protected ZIP archives**: preflight detects them and the wizard asks for the password; the archive is decrypted once into a plain ZIP and processed normally. The password is checked before registration and is not stored. Before, every member failed to extract with unrelated errors and almost nothing was indexed.
- Built-in detection **Possible mass file encryption**: five or more data files that reappear with one appended extension (`Memo.docx` -> `Memo.docx.enc`) within ten minutes on one host, the mark ransomware leaves when it encrypts in place. Reads any indexed file event with a name (MFT and USN from disk, the MFT MemProcFS recovers from memory), at the end of an evidence's ingest and after a memory image's timeline is indexed. Extensions Windows and applications append themselves (`.lnk`, `.crdownload`, `.tmp`, `.bak`...) do not count.
- Raw **SRUM** (`SRUDB.dat`) is parsed on the Linux worker. SrumECmd refuses to run outside Windows, so the database is read natively with `dissect.esedb` into SrumECmd's tables and columns (network usage, network connections, application resource use, app timeline, energy, push notifications, vfuprov); compared with SrumECmd's output for the same machine. User SIDs are named from the `SOFTWARE` hive's ProfileList when it was collected.
- Raw **Shellbags**: SBECmd now ships in the image and parses each profile's `UsrClass.dat` and `NTUSER.DAT` (with their transaction logs) on the Linux worker.
- SRUM and Shellbags are steps of recommended indexing when discovery finds their sources, and scoped actions (`POST /api/evidences/{id}/srum-index`, `/shellbags-index`).

### Changed

- **Recommended follow-up indexing runs on its own** after an evidence's core ingest: user activity from the registry hives (RECmd), Shellbags, SRUM and Defender start in sequence when the evidence holds their sources, as **Run recommended indexing** did by hand. Heavy steps (Full MFT) stay on demand, and so does everything in usable-search mode.
- Resumable uploads read each 64 MB chunk into memory before sending it, instead of letting the browser stream it from disk during the request. A file the browser can no longer read (moved, renamed, permission lost) now says so instead of failing as a network error.
- Shellbags: the drive or UNC path is derived from SBECmd's shell-namespace path (`Desktop\This PC\C:\Users` -> `C:\Users`, `...\Computers and Devices\srv01\srv01\share` -> `\\srv01\share`), so network shares, user folders and suspicious folders are recognised; folders browsed on the RDP client's drive (`\\tsclient\...`) are tagged `rdp_client_drive`.
- SRUM leads are raised only on network-usage rows and match tool names on the application name; OneDrive, Dropbox and Google Drive are context (`cloud_sync`), an AppData executable alone is a low-risk lead, the Defender platform folder is not user-writable and Delivery Optimization (`DoSvc`) uploading updates is not a volume lead.
- Memory: the event log records and Amcache entries MemProcFS recovers are normalized like their EVTX and Amcache copies from disk (tags, risk, user, process and Defender detection fields) and get the built-in detections disk evidence gets; Sigma's Windows rules now run on them too (the engine only accepted EVTX documents as Windows event logs). A memory-only case therefore gets detections, and with them leads for **Suggest findings with AI**, instead of only the antivirus records Find Evil lists. The memory index (processes, Find Evil, network) still does not reach Detections. NTFS records are not put through the MFT normalizer, which flags every program under AppData; a Prefetch file seen being created in the MFT in memory is recorded as a program run.

### Fixed

- **Re-index evidence** left SRUM and Shellbags marked as indexed after deleting their events, so they were never indexed again.
- **Windows notifications** show what they said: the event message carries the sender, title and full text; a browser's web push notification is attributed to its site (Chromium launch arguments), packaged apps get a readable name, and the notification text is kept unredacted (a shared password or file name is the evidence). Notifications are attributed to the profile's user in wrapped collections. Search's event detail lists only the fields an event carries, including the notification's sender, text, type and launch target, instead of a fixed list of empty file and MOTW fields.
- **Re-index evidence** of a raw collection now also parses artifacts discovery finds that did not exist at the previous run (a parser added since, such as Windows notifications). Before, it repeated the previous selection exactly and new artifacts stayed unparsed with no way to add them from the evidence page. Artifacts the analyst left out are still left out.
- Raw collections: selected Windows notification databases and network candidates (WLAN profile XML, `hosts`) were extracted and then never parsed, because no artifact mapping existed for their category. Both are mapped now, and a supported candidate without a mapping is logged instead of dropped silently.
- Collections that name the volume as a folder (`C/Users/...`, as KAPE and AD1 repacks do) or wrap the tree in their own folders (`challenge/Users/...`) got no user from artifact paths: path normalization now finds the Windows tree by its layout (`Windows\System32`, `Users\<name>\AppData`...) and takes a one-letter folder before it as the drive.
- Artifact Views: MOTW and email artifact details open in the side panel, like event details, instead of below the whole table.
- Files extracted from a ZIP, AD1 image or 7z entry kept the extraction time as their modification time, so artifacts dated by their file's mtime when they carry no time of their own (PowerShell scripts, Jump Lists, scheduled task XML...) landed on the timeline at the moment of processing. Extracted copies now get the time the archive recorded (the UTC extended timestamp when present). Evidence processed before needs **Re-index evidence**.
- Merging hosts failed with a server error when the host being merged away had ever been assigned to an evidence (its assignment history pointed at it). The evidence, findings, host facts and history of that host now move to the host kept; before, the evidence would also have been left unassigned.
- The evidence page header shows the assigned host instead of the name typed at upload.
- A resumable upload could end in "Inspection failed: This upload session is busy": the last chunk queues a background preflight and the wizard also finalizes, and whichever lost the lock failed. The wizard's finalize now waits for the background inspection and reuses its report; the background job steps aside when the wizard got there first.
- SrumECmd CSVs: the application was taken from `AppId`, which is an index, so every row was named by a number and no SRUM rule could match; Network Connections rows were an unknown table dated in year 2059+ (`ConnectedTime` is seconds, not a date); App Timeline and vfuprov rows were filed as resource usage; Push Notifications were read as a notification store.
- Shellbags: every folder under "This PC" / "My Computer" was classified as a Control Panel item, while real Control Panel items (`ControlPanelHome`) were not.
- Defender's 1116 (malware detected) got the generic "High-risk event" built-in detection instead of **Defender High Severity Detection** and its sibling rules.
- Terminal Services session manager records of console sessions (`Address: LOCAL`, and logoff or disconnect records that name no address) were tagged as RDP and produced "RDP activity" detections. Only a record naming a network address is remote access now.
- Event ids 106 and 140 were tagged as scheduled-task persistence whatever wrote them; AppReadiness uses 106 for unrelated records. Now only the Task Scheduler's log counts.
- Sigma matched records a rule was not written for, on disk and memory cases alike:
  - A selection written as a list of maps (`- ServiceName: PSEXESVC` / `- ImagePath|endswith: \PSEXESVC.exe`) was dropped when compiling, so `all of selection_*` kept only the event id: every 7045 matched PsExec, AnyDesk, PDQDeploy and a dozen other service-installation rules.
  - `contains|all` matched a field holding any one of the values instead of all of them.
  - A rule's `service` restricted the channel for five services only, by substring, and `windefend` was not one of them. Each Windows service now maps to its channels as in the Sigma Windows pipeline (AppLocker's 8025 no longer matches Windows Hello's), Sysmon categories need Sysmon records (WMI Event Subscription matched any event 19-21), script-block rules need the PowerShell Operational log, and Linux rules no longer run on Windows records (Modifying Crontab matched the word REPLACE anywhere).
  - The channels a case has were read from a 1000-event sample, so on a memory image (all registry writes in the sample) every Defender rule was skipped. They now come from an aggregation over the scope; and the evaluated documents now carry the channel, provider and type the log-source checks read.
  - Stored compilations are refreshed when the engine changes.
- 7040 (a service's start type changed) was tagged as persistence and scored high enough to become a "High-risk event"; Windows switches its own services between automatic and manual start constantly. It is now a low-severity service event.

## 1.2.0 - 2026-10-30

Full notes: [docs/releases/1.2.0.md](docs/releases/1.2.0.md).

### Highlights

- Memory Analysis promoted from Experimental to Core DFIR Capability — Preview, with a real activation boundary, and then to Stable (2026-10-25): its results reach Timeline, Search, Command History, Persistence, Findings and the report.
- Case navigation restructured around a Surface Registry, with Domain Tabs, Capability Cards, and capability-derived investigation breadcrumbs.
- Host Information now includes a Windows Local Accounts inventory (SAM hive, corroborated by ProfileList) alongside the existing Linux Host Facts foundation. See `docs/evidence/host-information.md`.
- General evidence uploads now detect duplicates the same way Memory uploads already did.
- Archive extraction failures are classified instead of surfacing raw tool errors.

### Added

- Linux packages: pacman (log and local database with install dates), zypper history (installs, patches, command lines with the user, repositories added), apk (installed database, world, repositories), dnf 4 `dnf.rpm.log`/`dnf.log`, dnf 5 `dnf5.log`, and the dnf/dnf5/yum transaction databases (who ran each transaction, the command line, repository and reason) and `rpmdb.sqlite` (install time of every RPM). apt history is read per transaction: one row per package with the command line and the `Requested-By` user. Every format was checked against files written by the real tools.
- Memory: **Create finding** on Find Evil indicators and processes, network connections and suspicious memory regions (title from what was seen and the process, severity from Find Evil's priority, the row kept as snapshot), and a **Memory Analysis** section in the case report: per image the system and capture time, the analyses run with their item counts, and the Find Evil triage with the processes marked suspicious or important. Shown only when the case has memory images.
- Linux **application histories**: what was typed into database clients and REPLs — `.mysql_history`, `.mariadb_history`, `.psql_history`, `.sqlite_history`, `.python_history`, `.node_repl_history` — in typing order, with the user and the client, also in Command History. libedit escapes, psql and Python 3.13 multi-line entries and Node.js's newest-first order are handled. Kept apart from shell history, so Sigma's process-creation rules do not run on SQL. Checked against files written by MySQL 8.4, MariaDB 11, psql 16, sqlite3, Python 3.12/3.13 and Node.js 22.
- Linux RPM databases in Berkeley DB (`/var/lib/rpm/Packages`: RHEL/CentOS 7-8, Amazon Linux 2) and NDB (`Packages.db`: SUSE 15) formats are read like `rpmdb.sqlite`: every installed package with its install time. Checked against `rpm -qa` on CentOS 7, Amazon Linux 2 and openSUSE Leap 15.6.
- Linux shell history: bash's `#<epoch>` lines (written when `HISTTIMEFORMAT` is set) date the next command instead of being read as commands.
- Linux **cloud-init**: the debug and console logs (commands run, files written, users added, per stage), user-data and vendor-data decoded like cloud-init does (cloud-config, scripts, boothooks, `#include`, MIME, gzip, Jinja), the boot scripts in `/var/lib/cloud/scripts`, `cloud.cfg` and the instance state, with generic flags for review. Passwords in user-data are not copied.

- **Source Tables**: a Timeline Explorer style view for CSV/TSV files. A file is indexed whole, with every column it brings, in its own index (`dfir-tables-<case>-<table>`), so it can be sorted and filtered by any column (contains, is, is not, empty), with the most frequent values per column, hidden columns, row detail and filtered CSV export. Opt-in: *Full CSV tables* in the evidence wizard for every CSV of an upload, or per file from the evidence detail. Search, Timeline and detections never read these indices, so nothing shows up twice.
- Source Tables: columns with no value in the whole file are flagged (muted name, *empty* tag in the column picker) and can be hidden in one click.
- Memory analysis: **Find Evil**. MemProcFS's FindEvil runs as a new profile (in Run all) and its indicators (hidden or masquerading processes, injected or patched modules, executable private memory, unusual threads, Defender detections in memory) are listed in a Find Evil tab, sorted by review priority with a plain explanation each. MemProcFS is installed in the memory-worker image from its pinned release (SHA-256 checked) and runs in a separate process, offline, with the same limits as Volatility. Upgrading adds the profile to `.env` when its memory allowlists are still the setup defaults.
- Memory timeline from MemProcFS: the forensic scan Find Evil already runs now also feeds the case **Timeline** with what Volatility has no equivalent for: NTFS records (MFT in memory), registry key writes, event log records, browser history, scheduled tasks, Amcache, Prefetch and kernel objects (`artifact.parser: memprocfs`, `artifact.type: memprocfs_*`). Process, network and thread timelines are left out (pslist/psscan and netscan already give them). NTFS and registry are hidden from the default Timeline like MFT and shown when filtered by type or searched for; the **Memory (MemProcFS)** quick filter shows them all. No second scan; if the forensic scan does not finish, nothing changes for Find Evil.
- Memory **Files** (`files_basic`, windows.filescan) now appears in the analysis catalogue and runs with **Run all**. The catalogue modal only drew profiles in its own section list, which missed Files although the server offered it, and Run all had left it out as a heavy scan; shell history has since run the same filescan for PowerShell history files. Contract tests now fail when a catalogue profile is missing from Run all or from the modal.
- Memory: raw memory images with no header (DumpIt/WinPmem `.raw`, `dd` of physical memory, `.vmem`) are recognised by the running kernel's name string, with no symbols: Windows by the kernel's CodeView record (PDB name, GUID and age), Linux by its banner, macOS by its Darwin version. The upload wizard classifies them as memory instead of "Ambiguous", and the memory worker identifies their platform before trying Volatility, which offline could not identify a Windows raw image whose symbols were not cached yet (analysis stayed blocked with "platform not identified").
- Memory: no more authorization checkbox for uploading RAM, confirming a memory type or starting analyses (wizard, direct upload, type confirmation, Run all). Anyone could tick it, so it controlled nothing; login, case access and the server's memory settings decide who may. It also blocked the upload wizard when a `.raw` image was forced to Memory with the manual override: the checkbox only appeared for files Kairon itself recognised as memory, but the server required it anyway. Symbol downloads from Microsoft still ask for approval (a connection out of an offline install).
- **Source Tables** lists every CSV/TSV of the case that has no table yet, by evidence, with **Full table** (one file) and **Full table for all** (one evidence): no need to open each evidence's detail. The upload wizard option and the evidence detail panel stay.
- Removed the NetScaler parsers tied to one campaign (CVE-2026-88771/88772: known web shell name, passphrase, RC4 key, dropper hash, LogonPoint/httpd.conf/ns.log/VPN-log/.deb checks). Kairon keeps generic NetScaler support (ns.conf and its backups, appliance detection in disk images); ns.log and the access logs go to the generic log parser as before. Events already indexed as "NetScaler compromise indicators" stay until the evidence is reprocessed.
- Sidebar: one flat list without the **Investigation Surfaces** section. **Memory** moves above Timeline, **Execution Stories** (Windows) and **Linux Authentication** (Linux) are direct entries, shown only when the case has that evidence; the surfaces' other entries were already in the list (Command History) or in Artifact Views (persistence, packages).
- Case **Timeline**: dated Volatility events of memory images (process start/exit, network connections, suspicious memory, timed shell commands) now appear in the default (lightweight) view too, merged page by page with exact paging; **Memory (Volatility)** quick filter.
- Memory **MemProcFS** tab: MemProcFS's inventories from the Find Evil scan (scheduled tasks, services, DNS cache with unreadable entries hidden, drivers, devices, Prefetch, Amcache applications/files/shortcuts/drivers/devices, YARA matches), with text filter. Scheduled tasks and services also feed the case **Persistence** view (source "Memory (MemProcFS)").
- Docs: memory is no longer described as isolated from the case-wide views; README, feature map, parser coverage and roadmap say which views read memory results (Timeline, Search, Command History, Persistence) and which do not (Detections, Reports, SIEM).
- Memory **Timeline** tab per memory evidence: only that image's events in time order, Volatility's (process start/exit, network connections) merged with MemProcFS's timelines, with per-type chips and counts, text search and cursor paging.
- Memory Shell History: a **PowerShell event log** list with the PowerShell records MemProcFS recovers from memory (4104 script blocks, 4103 command invocations, 400/800 host command lines), each with its logged time. They are indexed with `powershell.*` fields, so the case Command History and searches show the command itself.
- Memory Shell History: PowerShell's own history file (PSReadLine's `ConsoleHost_history.txt`, any user, any host) is recovered when Windows still has it cached (`windows.filescan` + `windows.dumpfiles`, plugin `kairon.psreadline`), with commands from earlier sessions too, in file order and with the user whose profile holds it.
- Memory Find Evil: Kairon's own checks over standard Volatility output run next to MemProcFS, so Find Evil has indicators on any image Volatility reads: hidden processes (in `psscan`, not in the process list, still with threads), unexpected parents of system processes (ignoring reused PIDs), duplicate singletons, lookalike names, system binaries outside System32, programs run from temporary or user-writable folders, shells started by Office or browsers, attacker command-line patterns, PE headers in private memory and unlinked modules outside Windows folders. A Source column says which tool reported each indicator.
- Memory Shell History: `windows.cmdscan` next to `windows.consoles` (it still recovers console history where `windows.consoles` reports "Console Information Not Found", as on Windows 11 24H2; commands found by both are listed once), and a **Commands executed** list with the command line of every process in memory, in start order.
- **Command History** in the sidebar: every command in the case, from disk and memory, one click away (it was only reachable inside the Windows or Linux surface).
- An `integration` CI job that ingests three synthetic evidence items (demo pack, Linux triage archive, Velociraptor collection) against real PostgreSQL, OpenSearch and Redis with a real RQ worker, and checks the results through the API: exact event counts per artifact type, searches, timeline, command history, report preview, and reprocessing without duplicates. It fails on the ingest regression of 2026-10-01. See `docs/operations/testing.md`.
- An Investigation Guide page (sidebar, under Docs): one card per question (what ran, persistence, logons, lateral movement, PowerShell, USB, deleted files, Linux logins, sudo, cron, web attacks…) with ready searches that run on the active case, links to the right views, where the system records the answer and what stands out; filterable by platform, topic and text. Windows event fields are searchable: `eventid:`, `logontype:`, `channel:`, `provider:`, `service:`, `task:`.
- An optional, case-scoped AI assistant with read-only lookups over the case's data; off until an administrator configures a model provider (`docs/operations/ai-assistant.md`).
- Linux: the binary systemd journal, a generic reader for other text logs (always showing the message), nginx next to Apache, firewall and fail2ban logs, persistence hooks (ld.so.preload, rc.local, PAM, shell start-up files, at jobs), Sysmon for Linux, Kubernetes audit, Docker and Kubernetes container logs and configuration, Postfix/Dovecot mail, MySQL/MariaDB/PostgreSQL, and OpenVPN/strongSwan. Syslog and journal priorities set the severity.
- Linux events are searchable by their own fields (`linux.*`, and shortcuts such as `ip:`, `process:`, `jail:`, `container:`, `sql:`, `vpn:`), and Artifact Views has a table layout per Linux log family with a message column and click-to-filter cells.
- Sigma: Linux rules run on the Linux logs (including keyword rules), and the web-server rules run on Apache and nginx access logs.
- A single `memory_enabled` setting as the sole authority for activating Memory at the application-composition level (default true, preserving existing deployment behavior).
- A dependency-free `GET /api/system/capabilities` endpoint exposing declarative capability activation state.
- Case-scoped, content-based (SHA-256) duplicate evidence detection across every general evidence-creation path: direct upload, disk-image upload, folder upload, register-by-path, and the legacy Velociraptor upload routes.
- Classified archive extraction errors (`archive_corrupted`, `archive_password_protected`, `archive_unsupported_format`, `archive_tool_missing`, `archive_extraction_timeout`, `archive_insufficient_disk_space`, `archive_extraction_limit_exceeded`, and a generic fallback) with analyst-facing messages separate from technical detail kept for logs.
- A configurable extraction timeout for the 7z-family archive backend (previously unbounded).
- A Surface Registry driving case navigation: Domain Tabs, Capability Cards summarizing each surface's coverage, and investigation breadcrumbs derived from capability state instead of hardcoded per-screen lists.
- Memory Process Entity page infrastructure.
- Windows local account inventory parsed natively from the SAM registry hive (RID, account-control flags, last logon/password-set, logon/bad-password counters), corroborated by ProfileList profile-path entries, feeding the existing Host Information Local Accounts view alongside Linux accounts.

### Changed

- **Case report (PDF and Markdown) redesigned for delivery**: cover page, table of contents with PDF bookmarks, numbered sections that flow instead of one page each, header and "Page X of Y" footer, tables sized to their content with severity in colour, and times as `YYYY-MM-DD HH:MM:SS` in UTC (stated once). Sections with no matching data (Defender or SRUM in a Linux case, for example) are left out of the export and named once in the appendix instead of filling empty pages; the evidence table carries type, size and SHA-256; the executive summary leads with the analyst's text, lists key findings and says how many findings still await review; detections are summarised per rule; one command seen by several sources (Sysmon, 4688, memory) is reported once with every source; filters appear as a readable table instead of a Python dict. The builder preview marks the sections that will be left out.

- `dfir-backup.sh --db-only` saves the database, the configuration and the index inventory in seconds, enough before an upgrade (which changes the database, not the evidence); `--run` keeps the full backup, also saves `.env` now, and no longer aborts when a file changes while the data folder is archived. The unused `KAIRON_CSRF_SECRET` is no longer generated or required (cross-site requests are refused by origin, see Fixed).
- Artifact Views: a column that is empty on every row of the page is hidden (the column chooser marks it and can show it again), and Linux packages, shell history, users and groups, cron, SSH, sudoers, last logins, host facts, network configuration and hosts-file entries have tables of their own fields instead of Windows task, prefetch or web layouts whose columns were all empty.
- Artifact Views: SSH configuration and Linux network configuration have their own names instead of three entries called "Network", Linux artifact names no longer repeat "Linux", and the mixed-type table shows the artifact's name and a Message column instead of raw ids in Category and Artifact.
- CI runs the frontend test suite, every job has a time limit, and the backend tests point the service hosts at a closed local port so a connection attempt fails at once instead of hanging on DNS. Tests on SQLite store UUID columns as text, which removes a rare random failure.
- Top bar: only warnings the analyst can act on (failed evidence, parser errors) are shown, in plain words and linking to the evidence list; informational codes such as `multi_host_case` are no longer shown raw. The technical API address and a clock that did not tick are gone, and the host and evidence chips appear only while that filter is active, each with a button to clear it.
- Home: counts use the locale's number format, the stat cards without data ("via OpenSearch", "Ready") are replaced with open and total cases, and the 10,000-result paging note moved next to the paging it describes.
- Findings has its own icon in the sidebar (it shared Detections').
- The Search table no longer has a separate Parser column; the parser is in the Source badge and the event detail.
- The API port (8000) is published on the host's loopback address only; the UI reaches the API through the frontend's `/api` proxy and other machines keep using the UI port. Set `KAIRON_API_BIND=0.0.0.0` to expose it again.
- Memory's routers and startup reconciliation hooks are now mounted/run only when `memory_enabled` is true, instead of unconditionally.
- Duplicate evidence requests now return `409` with `{error_code: EVIDENCE_DUPLICATE, duplicate: true, existing_evidence_id, existing_filename}` instead of silently creating a second Evidence row.
- The top-level ingest failure classifier now recognizes classified archive extraction errors and surfaces their analyst-facing message through the existing evidence-status path, instead of a raw exception string.
- Sidebar navigation simplified to surface-level, with a shared surface icon resolver across the navigation UI.
- Required host selection is now shown consistently across all evidence, not only a subset of intake paths.

### Fixed

- An uploaded archive that carries a memory image or a packet capture next to the collection (one .zip per host with everything taken from it) now says so on the evidence: **Not processed with this upload** lists those members, recognised by content (the memory classifier's header read, held to image-sized files and ELF core dumps; pcap/pcapng signatures), with the advice to upload each as its own evidence. They used to be skipped without a word. Disk images inside archives are still mounted and ingested. Applies to new uploads and re-indexing.
- Case report: a **Lateral Movement** section with the remote logons between machines (routine machine, anonymous and built-in accounts left out and counted), in English or Spanish, following the report's host filter. The AI report draft receives the same rows and may cite them by time.
- Case report: **execution trees** under Process Chains. For each finding the analyst ticks, the report resolves the process behind it (as Execution Stories does) and draws its tree -- ancestors, the process, what it started -- as a diagram in the PDF and an indented tree in Markdown. Any finding with events can be ticked now, not only findings that stored process nodes.
- **Draft with AI** and **Suggest findings with AI** run as background jobs: the page can be closed while a slow local model works, the last draft of each report and the last suggestions of each case stay available after a reload (**Load AI draft**; suggestions already turned into findings are marked), and a failure or a job that never finished is shown instead of a request that hangs.
- Case assistant: three more lookups -- `list_lateral_movement` (remote logons between hosts), `get_memory_triage` (antivirus detections still in memory and marked processes per image) and `get_host_coverage` (what each host's evidence covers, log clears) -- so it can answer "where did this account log on from", explain a tool seen only in memory and check coverage before saying something did not happen.
- **Hide routine system activity** in Search and Timeline (off by default): hides the process starts of core Windows and Linux system processes only when the image directory and the parent match the known-good baseline, so masquerading processes stay visible and attacker-usable tools are never hidden. Shown as a NOT chip.
- **Suggest findings with AI** on the Findings page (only when an AI provider is configured): the model receives the case's open leads -- rule detections no finding covers yet, suspicious commands, antivirus detections in memory, marked memory processes and non-routine remote logons -- and proposes findings with severity, confidence and MITRE techniques, citing the leads. Suggestions citing no lead are left out; facts absent from the cited leads are shown for review. A finding is created only when the analyst accepts the suggestion, tagged `ai-suggested`, with its links taken from the leads. Same consent dialog as report drafting.
- **Lateral Movement** page: remote logons between machines on any platform (Windows network, cleartext and Remote Desktop logons from 4624/4625; Linux SSH and other remote logins), one row per target, source address, account and method with first/last time and succeeded/failed counts, in the order they began, each linked to its events in Search. The source address is named as a case host only through addresses observed on that host; an address seen on several hosts lists them all, and a Windows workstation name that points to a different host than the address is flagged as a lead. Machine accounts, anonymous and built-in logons are marked routine and hidden until asked. The page also lists the observed host addresses.
- Memory: Find Evil's antivirus detections (`AV_DETECT`) are parsed into time, threat, what detected it (real-time, system scan, AMSI...) and the target (file, command line, scanned script), with the records of one detection grouped. Shown above the Find Evil processes and in the report's Memory Analysis section. They survive cleared event logs, so they can be the only record of what a tool ran. Works on images already analysed.
- Report: **Draft with AI** in the report builder when the AI assistant is configured. One request to the configured provider with only the report's curated material (confirmed findings, its timeline, IOCs, coverage notes, memory triage; never raw events), after a consent step that names the provider and warns when it is not local. The reply fills the executive summary, the new *Attack narrative* section, recommendations and limitations for the analyst to edit; every fact must cite a finding (`[F2]`) or a timeline time, and citations, IP addresses, times and numbers not found in the material are listed before saving. Nothing is stored until the analyst saves, and the report appendix then records which provider and model drafted those sections and who reviewed them. Drafting asks for at least 16,000 output tokens (reasoning models can spend a chat-sized limit thinking), and a reply cut at the limit says so instead of failing as malformed.
- Report language: the report can be written in English or Spanish (selector in the report builder). Kairon's own text is translated (titles, headers, sentences, cover, contents, page header and footer); evidence values, rule and finding titles and the analyst's text are kept as written. The builder also gains the "Prepared by" field shown on the cover.
- Built-in detections: "High-risk event" fired on any event-log record of level Error or Critical (a CloudStore or WMI error becomes severity high), burying real detections; it now needs a security signal (suspicion reason, risk 70+, or a suspicion tag). On a four-host case this left 21 of 981. Detections already created stay until the rules are re-run.
- Report: MITRE ATT&CK section (techniques of the reported findings by tactic, in attack order, with names); IOCs now include hashes and binaries from the events each finding links (Sysmon `Hashes`, `process.hashes`), labelled with their file; one timeline merging key events, marked events and accepted Incident Timeline items, with host and phase per row.
- Host coverage: telemetry capabilities by normalized event type on every platform (process creation, network connections, logons, script/command logging), when each begins per host, and event-log clears (when, by whom); hosts missing one their peers have, or whose logs were cleared, are flagged in the host page and the report's coverage notes.
- Host addresses: an inbound Sysmon network connection (event 3 with `Initiated=false`, for example an RDP session from another machine) attributed the remote client's address to the receiving host, because Sysmon names the initiator as Source. The receiving host's address is now read from the destination of inbound connections; on a four-host case three addresses had been assigned to two or three hosts each.
- AI report draft: a time cited from a finding's supporting events was flagged as unknown; it is citable like a timeline entry.
- Search: memory-image rows ignored most filters in a case-wide search. A non-memory artifact type (`windows_event`, `linux_auth`) selected every memory family, and event type, account, IP, severity, exclusions and host filters were not applied to them. Memory rows now follow the artifact type, its exclusion, the host filters (via the image's host) and text exclusions, and are left out when a filter they cannot satisfy is active; a memory-only search says which filters do not apply.
- Command History: on a case with more candidate events than the fetch cap (5,000), the suspicious view showed only the commands of one end of the timeline, typically one host. When suspicious commands or a minimum risk are asked for, every candidate is now scored on a light projection and the risky ones are fetched in full, whatever host or time they belong to; the fetch also leaves out fields it never reads.
- Incident Timeline: phases came from keywords first (a ransomware finding mentioning PowerShell became "execution", many items "unknown"). A finding's phase now comes from its type, then its MITRE techniques, then keywords (Windows, Linux and macOS tradecraft); marked events attached to a finding share its phase; "command and control" is a phase. The phase can be corrected and is saved (the selector used to change it only in the browser), and accept/dismiss, notes and phase corrections are kept when the timeline is regenerated.
- Report: the Defender section listed health and housekeeping records (1150/1151, 1013); it now lists detections and changes to the protection only. Memory images counted only findings created from them; findings holding a marked item of the image now count too. An archive bundling several kinds of evidence shows as "Archive" instead of "-". A PowerShell log event naming a script recorded the script as the process; the script is shown as such and the process is the PowerShell engine (new ingests also keep scripts out of `process.path`).
- Report: the analyst's executive summary, recommendations, limitations and finding descriptions were cut at 1,200 characters, mid-sentence. The Hosts table showed 0 findings for every host; it now counts the findings in the report. The Investigation Timeline listed each key event twice (as key event and as marked event) and memory-process marks with an "unknown" time; both are gone (memory marks stay in Memory Analysis). IOCs no longer list hosts in scope, command lines or Windows system binaries. UNC paths (`\\server\share`) lost a backslash in the PDF, multi-line script commands broke their code formatting, and internal source caps of other sections showed up as Email Artifacts notes.
- PowerShell: a script argument such as a UNC share (`.\x.ps1 -e \\server\share`) was recorded as a downloaded file; without a URL only `-OutFile`/`-Destination` names a download target.
- Startup & Persistence: Defender's own maintenance tasks and services scored as suspicious (risk 55-75): its platform folder under `ProgramData\Microsoft\Windows Defender\Platform\<version>` counted as user-writable, and any mention of "Defender" counted as a settings change. That folder is now a system location (elsewhere under ProgramData stays user-writable), and only real settings words (exclusion, real-time monitoring, tamper protection, SpyNet, DisableAntiSpyware) count as a change. Tasks created with `schtasks /tn` are named after the task instead of the event action.
- Built-in detections now record the matched event's time (as Sigma and YARA matches already did). For detections created before, the report reads the time from the matched events.
- Report: detections without an event time showed the time the rule ran as if it were evidence time; that column is now left empty. The Incident Timeline section no longer includes findings the analyst archived or marked false positive, and the timeline draft no longer seeds them.

- Linux and NetScaler rows are normalized by their own family before the Windows and browser name heuristics; a Linux file named like a browser or Windows artifact (zypper's `history`) could be indexed as one.
- zypper's `/var/log/zypp/history` was taken for a Chrome `History` database and gave no rows: outside a browser profile, a file with that name must now be SQLite.
- Linux packages: `/var/lib/dpkg/status` gave one row per line (descriptions, conffiles) instead of one per package; dpkg, apt and zypper local times were read as UTC instead of the host's timezone; yum.log rows named the action ("Installed") as the package; modern dnf logs (ISO times) were not parsed.
- Large OpenSearch deletions (an evidence's events, a memory image's previous MemProcFS timeline) no longer fail with "got more than 100 headers": OpenSearch 2.x sends one `TASK_RESOURCE_USAGE` header per scroll batch, so a deletion of more than ~100 batches broke the HTTP response while the deletion went on in the background, and was reported as 0 deleted (or as a failure when deleting evidence). They now run as a server-side task that Kairon waits for.
- Memory Find Evil no longer hangs a whole analysis batch when MemProcFS's forensic scan stops making progress (seen at 90 % on a Windows 11 24H2 crash dump): after 10 minutes without progress it gives up with that reason instead of waiting for the worker to be killed 80 minutes later, and leaves without the MemProcFS shutdown call that never returned.
- Memory Find Evil: MemProcFS's forensic scan no longer stays at 90 % on Windows 11+ images. Its DNS cache lookup looped forever (an inner loop reused the outer loop's index); the memory-worker image now rebuilds MemProcFS 5.19's `vmm.so` from source with a one-line patch (`docker/memory-worker/patches/`). On the Windows 11 24H2 dump that hung, the scan finishes in about 30 seconds with 132 indicators, including Defender detections still in memory.
- MemProcFS's Find Evil child is ended by a watchdog thread even when a call into the native library never returns, and dies with the worker that started it, so a stuck scan can neither block the analysis nor keep running on its own.
- Memory runs left "running" by a worker that died are closed as failed (`WORKER_LOST`) by the next analysis, or when an analysis is started from the app, instead of showing as running forever and blocking a new run with "an active run already exists".
- Memory Find Evil: an indicator both Kairon's checks and MemProcFS report is one row whose Source names both; a process base mismatch (`PROC_BASEADDR`) whose PEB value cannot be an image base (an unreadable PEB, not hollowing) is low priority.

- Search: substring matching works again. OpenSearch 2.15's `wildcard` field type returns no hits for a wildcard query with `case_insensitive: true`, even on an exact-case match, and every substring fallback over `search_text` used that flag. So a bare stem never found a file name with its extension (`psexesvc` vs `PSEXESVC.exe`, `Invoke-Mimikatz` vs `Invoke-Mimikatz.ps1`, `comsvcs` vs `comsvcs.dll`), and the *contains* mode found nothing in `search_text`. A new `search_text.wildcard_lc` subfield lowercases through the built-in normalizer and is queried without the flag. Existing case indices get the subfield and are filled in the background on the next backend start, without re-ingesting.
- Search: events from uploaded EvtxECmd CSVs can now be found by every EventData value (WorkstationName, ShareName, RelativeTargetName, DisplayName...) and by EvtxECmd's summary columns (PayloadData1-6, UserName, RemoteHost, ExecutableInfo, MapDescription). EvtxECmd had its own search text builder that never got the EventData fold-in native EVTX already had, so for example a share access to `ADMIN$` writing `PSEXESVC.exe` returned no results. Already indexed cases: `backend/scripts/backfill_event_data_search_text.py <case_id>` updates them in place, no re-ingest needed.
- Memory: the analysis catalogue's link to Kernel modules pointed at a route that does not exist.
- Memory analysis, Windows shell history: **Run all** now includes it (it never ran unless started by hand), and commands are also recovered from the console screen text after each `PS …>` or `C:\…>` prompt, with the directory they ran in. PowerShell windows keep no conhost command history, so on real Windows 10/Server images the list was empty even when the commands were plainly on screen. A Windows build that `windows.consoles` does not support (e.g. 10.0.17134) is reported as unsupported for that build instead of a failed plugin.
- Linux authentication logs: `sudo` refusals written as `user NOT in sudoers`, `user NOT allowed to execute` or `command not allowed` were recorded as commands that ran; they are `sudo_failed` now. util-linux console logins (`ROOT LOGIN ON tty1 [FROM host]`) were not recognised. And `action:` searched only the generic event action, so `action:sudo_command`, `action:max_auth_attempts` and the other Linux actions found nothing; it now also searches `linux.event_action`. All three were found by the new integration test.
- A backup that failed (for example with Docker not running) left a folder in `backups/` with an empty dump that looked like a backup; it is now removed. The CI check for flags written with an en/em dash (`–upgrade`) never matched anything, because in a UTF-8 locale the byte pattern is not a character; it now compares bytes and only flags a dash used as a flag, not dashes in prose.
- Retrying a raw EVTX that stopped partway indexed the records of the interrupted run a second time (event ids are random), and a retry that failed again left its documents uncounted, so the next retry added a third copy. After a retry, Kairon now keeps the events of whichever run reached more records and removes the other run's, for every earlier run of the same file; nothing is lost when the retry stops sooner. Evidence retried before this change keeps its duplicates until it is reprocessed.
- `scripts/restore.sh` only knew the file names of the old `backup.sh` draft, so with a backup from `dfir-backup.sh` it restored the database alone, and a database restore over existing tables failed silently. It now reads both layouts, empties the schema before loading the dump, stops at the first error, and runs from the installation directory instead of a fixed `/root` path. The unused `scripts/backup.sh` draft is removed.
- Documentation brought up to date: backups and restore, upgrades, request protection (cross-site check, CORS, failed-login limit), search shortcuts, Linux logs, temporary storage for disk images, Artifact Views, the Investigation Guide, process-graph activity and scheduled-task scope.
- Process graph: Sysmon registry events (12/13/14) no longer attached to their process. The EVTX normalizer stores them under the generic registry event names, which the graph did not recognise.
- Scheduled tasks were all reported as system-scope because every task is stored under `System32\Tasks`. The task's principal now decides; the location is only a fallback.
- PowerShell events without a user stored the placeholder `-` as the user name.
- A compressed (MAM) Prefetch file smaller than the uncompressed header size was rejected before being decompressed.
- Command history opened a second database connection for memory commands even when the caller had one.
- Raw SRUM databases found in a collection now show the hint to use the SRUM action.
- Backend tests: the 89 entries in `tests/known_failures.txt` are gone. Some were real bugs (above); the rest were tests of behaviour that changed on purpose, environment assumptions (group ids, cached settings), or state leaking between tests.
- Rotated logs compressed on their own (`sh.log.1.gz`, `auth.log.2.gz`) were indexed twice: they were unpacked as nested archives while the original stayed in place and was read too. A gzip text log that a Linux parser recognises is now read once, in place, keeping its original path; tar archives and binary records (wtmp, journals) are still unpacked.
- A folder of logs uploaded as it is was mostly ignored: generic logs were only read under `var/log` and similar system paths. Logs in any folder named `log` or `logs` are read now (except in Windows layouts), with web-server logs there going to the web parser; and `sh.log`/`bash.log` keep every line, not only the commands in the expected format.
- Collection evidence (Velociraptor and other ZIP/TAR collections) failed to ingest with "cannot access local variable 'disk_image_materialization'" since 2026-10-01: the platform detection read a value only the disk-image path set.
- 37 of the 46 documents in the in-app documentation could not be opened: the catalog still pointed at their old locations after the docs were reorganised into folders. Paths are corrected, documents that no longer exist are removed, and a test fails if an entry points at a missing file.
- Thin virtual disks (VMDK, VHD/VHDX, QCOW2, VDI) were refused unless the temp folder could hold their full virtual size, though the temporary RAW copy is written sparse and takes only the image's real data. Preflight and the conversion step now measure that data (`qemu-img map`) and block only when it does not fit, noting the worst case otherwise; in Docker deployments the advice explains how to free space or mount a larger disk at `/app/data/tmp`, since changing `BACKEND_TEMP_DIR` in `.env` does not move it to another disk.
- Artifact Views offered the DNS view on every case, even with no DNS events; it is offered only when the case has some (the facets now count them), and kept while selected.
- dpkg.log lines name the right package and versions (`status installed man-db 2.6.7` was read as package "installed"), and package name, version, action and status are indexed and searchable (`package:`, `pkgaction:`).
- Linux log times are real UTC times. Lines without a zone were read as UTC and syslog-style lines without a year got the current year, so on a 2016 disk image every syslog and auth.log line landed in the ingestion year and hours off. The host's timezone (`/etc/timezone`, `/etc/localtime`) now converts local times, the year is the one in which the machine was running according to `wtmp` (or the file's modification time), and disk images keep file modification times on extraction. `timestamp_status` says what was applied.
- `wtmp` and `btmp` from disk images were decoded as text, which showed binary garbage and lost the login records; they are read as binary, IPv4 addresses with the high bit set no longer fail, and boots, shutdowns and runlevel changes are named.
- The MySQL 5.5/5.6 error log layout (`160403 19:02:55 [Note] ...`) is dated, syslog lines without a host name (the installer's syslog) are dated, and dpkg's backup database (`status-old`) is no longer listed as a second copy of every package.
- auth.log: sudo commands are recognised (the program name is split off the message, so none were): the user who ran sudo, the account it ran as, the directory, terminal and command are kept, and the user is the one who ran it rather than the target account. "Maximum authentication attempts exceeded" counts as a failed login with its source, console logins and other sshd lines are named, and the web-request flags, sudo target accounts and terminals are searchable (`indicator:`, `runas:`). A PostgreSQL FATAL, which ends one session, is medium rather than high.
- Search results for Linux events are summarised by their log line instead of a `field=value | ...` dump of the parsed row.
- The API no longer accepts cross-origin requests carrying the analyst's session from any web page: a catch-all CORS origin pattern overrode the configured `KAIRON_ALLOWED_ORIGINS`. Only the configured origins are allowed now; `BACKEND_CORS_ORIGIN_REGEX` remains available as an explicit opt-in.
- State-changing API requests (POST, PUT, PATCH, DELETE) sent by a browser from another origin, including another port of the same host, are refused (cross-site request forgery). The check uses the browser's `Origin`/`Referer` against the server's own address and `KAIRON_ALLOWED_ORIGINS`; requests without either header (curl, scripts) are unaffected. The bundled Nginx now forwards the `Host` header with its port.
- Sign-in throttling no longer locks legitimate users out. Behind the bundled Nginx every request came from the proxy's address, so five sign-ins (successful ones included) within five minutes blocked everybody. Only failed attempts now count, per client address and username, and a successful sign-in clears them: guessing one account's password from one address is slowed down while nobody else is refused. A refused sign-in explains why instead of reporting invalid credentials. Audit records and sessions keep the real client address.
- Artifact Views shows the User Activity tabs (Shellbags, UserAssist, RecentDocs, RunMRU, OpenSaveMRU) for Shellbags again: the view id was compared before being resolved from its `shellbag` alias.
- Shortcut (LNK) targets keep the file name: the target is the base path followed by the common path suffix, so `C:\Users\alex` + `Desktop\note.txt` and network shares (`\\server\share` + `docs\plan.docx`) no longer resolve to the folder only.
- USB device class GUIDs keep their closing brace when the setupapi line carries an extra trailing one.
- A USB event whose only host clue was the setupapi file name no longer gets that file name as its host.
- Process trees no longer count a child with only a descriptive badge (such as `cmd.exe` marked `lolbin`, with no risk) as a suspicious chain.
- Search and Artifact Views no longer offer a next or last page beyond the first 10,000 results, which the server refuses; they say when more results match than can be paged.
- Stale indexing-plan completion state now reconciles correctly instead of leaving a plan looking incomplete after it finished.
- Memory tab parameter routing and the Memory runs evidence route.

### Removed

- Debug Export (the technical ZIP export of ingest, process-graph, and rules diagnostics). Its shared process-tree/execution-story code was decoupled into `app/services/process_tree.py` and continues to power the `/process-tree`, `/process-tree/expand`, `/process-tree/focused`, and `/execution-story` endpoints as well as correlation findings.
- Validation Matrix (the demo/training ground-truth coverage view and its report section, timeline seeding, and case-mode visibility gating). The underlying case mode classification (`investigation`/`demo`/`training`/`validation`) and demo cases remain.

## 1.1.0 - 2026-08-28

Full notes: [docs/releases/1.1.0.md](docs/releases/1.1.0.md).

### Highlights

- Sigma rulesets are imported once and run repeatedly against the case, only against the data the case actually holds.
- Linux cases became searchable: evidence was indexed correctly but could not be queried. Linux Sigma rules now run against them.
- A pass over silent failures — searches, filters and limits that returned zero or incomplete results indistinguishably from "no such data exists" — across incident timeline, reports, Command History, persistence, host filters and Linux memory platform identification.

### Removed

- The YARA engine.
- The OpenSearch console, including its deployment option, its configuration panel and the links into it from the interface.

## 0.9.0-beta - 2026-07-18

### Highlights

- Canonical Host Resolution Service.
- Unified evidence intake host behavior.
- Unified memory wizard and legacy upload flow.
- First-class Linux collection ingestion.
- Improved Linux disk-image handling.
- Canonical hostname normalization and deduplication.

### Added

- Central evidence host policy table.
- Structured host-resolution outcomes for resolved, created, unassigned, ambiguous, required, and conflict states.
- Host-resolution provenance through evidence metadata, custody events, and assignment fields.
- Host assignment and host creation custody events across supported intake paths.
- Linux triage collection support for archive and folder-style evidence.
- Linux hostname and platform detection from common collection metadata.
- Support for journal, cron, auth/syslog, package, identity, network, service, and common Linux triage metadata.

### Changed

- Generic upload, disk upload, and register-path flows now use Host Resolution.
- Velociraptor upload and selection now use the canonical host service.
- Memory lifecycle and wizard promotion now use the canonical host service.
- Analyst reassignment now delegates to the canonical host assignment service.
- Memory evidence consistently requires an explicit source host.
- Linux intake uses canonical platform and capability handling.

### Fixed

- Memory wizard incorrectly offering Auto Assign for memory evidence.
- Equivalent hostname variants creating avoidable duplicate hosts.
- Host ownership validation inconsistencies across evidence routes.
- Duplicate custody events on idempotent host assignment retries.
- Linux artifact identity being overwritten during indexing.
- Nested Linux gzip/tar intake behavior.
- Linux hostname fallback behavior during collection processing.
- Recommended indexing being blocked when evidence had a valid assigned host but no legacy `provided_host` metadata.
- Recommended indexing now uses the canonical assigned host before falling back to legacy hostname metadata.

### Validation

- Real Windows memory validation passed.
- Real Windows collection validation passed.
- Real parsed Windows archive validation passed.
- Real Linux disk-image validation passed.
- Real Linux collection validation passed.
- Repeated Linux collection upload reused one canonical host and did not create duplicates.
- Validated the full Velociraptor collection workflow from upload through recommended indexing and processing.
- Confirmed assigned-host indexing without backfilling legacy `provided_host`.
- Confirmed 30,236 indexed events in isolated real-evidence validation.
- Terminal `completed_with_errors` was caused by parser-specific EVTX stalls/empty channels, not host resolution.
- Backend and frontend regression comparisons found no branch-specific failures.
- Focused backend tests, frontend build, quality gate, and diff check passed before release preparation.

## Private Beta Candidate - 2026-06-02

### Added

- Recommended/Fast/Advanced evidence indexing UX.
- Search command phrase handling for flags, paths and relative script references.
- Case modes and conditional Validation Matrix visibility.
- Incident Timeline curation workflow with accepted/candidate provenance.
- Timeline-to-story linking with Evidence Bundle, Movement Story and File Story pivots.
- Finding correlation scope metadata, source breakdown and pagination.
- Generic indicator extraction and evidence resolution.
- Startup & Persistence Artifact View.
- MOTW / Zone.Identifier artifact normalization and reporting.
- Beta deployment, backup/restore, update/rollback and troubleshooting docs.
- Healthcheck and backup helper scripts.

### Validated

- Demo scenario multi-host demo case with four hosts.
- Validation Matrix with 26 expected findings.
- Curated Incident Timeline with 78 items.
- Demo/playbook/report workflows.

### Known Limitations

- SRUM requires a Windows parser worker.
- Shellbags parser is pending.
- Outlook/OST/PST mail-store triage is pending.
- Public Internet deployment requires an external security boundary.
