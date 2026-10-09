# Changelog

## Unreleased

### Highlights

- Memory Analysis promoted from Experimental to Core DFIR Capability — Preview, with a real activation boundary.
- Case navigation restructured around a Surface Registry, with Domain Tabs, Capability Cards, and capability-derived investigation breadcrumbs.
- Host Information now includes a Windows Local Accounts inventory (SAM hive, corroborated by ProfileList) alongside the existing Linux Host Facts foundation. See `docs/evidence/host-information.md`.
- General evidence uploads now detect duplicates the same way Memory uploads already did.
- Archive extraction failures are classified instead of surfacing raw tool errors.

### Added

- **Source Tables**: a Timeline Explorer style view for CSV/TSV files. A file is indexed whole, with every column it brings, in its own index (`dfir-tables-<case>-<table>`), so it can be sorted and filtered by any column (contains, is, is not, empty), with the most frequent values per column, hidden columns, row detail and filtered CSV export. Opt-in: *Full CSV tables* in the evidence wizard for every CSV of an upload, or per file from the evidence detail. Search, Timeline and detections never read these indices, so nothing shows up twice.
- Source Tables: columns with no value in the whole file are flagged (muted name, *empty* tag in the column picker) and can be hidden in one click.
- Memory analysis: **Find Evil**. MemProcFS's FindEvil runs as a new profile (in Run all) and its indicators (hidden or masquerading processes, injected or patched modules, executable private memory, unusual threads, Defender detections in memory) are listed in a Find Evil tab, sorted by review priority with a plain explanation each. MemProcFS is installed in the memory-worker image from its pinned release (SHA-256 checked) and runs in a separate process, offline, with the same limits as Volatility. Upgrading adds the profile to `.env` when its memory allowlists are still the setup defaults.
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
