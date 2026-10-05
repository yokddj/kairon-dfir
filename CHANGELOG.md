# Changelog

## Unreleased

### Highlights

- Memory Analysis promoted from Experimental to Core DFIR Capability — Preview, with a real activation boundary.
- Case navigation restructured around a Surface Registry, with Domain Tabs, Capability Cards, and capability-derived investigation breadcrumbs.
- Host Information now includes a Windows Local Accounts inventory (SAM hive, corroborated by ProfileList) alongside the existing Linux Host Facts foundation. See `docs/evidence/host-information.md`.
- General evidence uploads now detect duplicates the same way Memory uploads already did.
- Archive extraction failures are classified instead of surfacing raw tool errors.

### Added

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
