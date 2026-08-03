# Changelog

## Unreleased

### Highlights

- Memory Analysis promoted from Experimental to Core DFIR Capability — Preview, with a real activation boundary.
- Case navigation restructured around a Surface Registry, with Domain Tabs, Capability Cards, and capability-derived investigation breadcrumbs.
- Host Information now includes a Windows Local Accounts inventory (SAM hive, corroborated by ProfileList) alongside the existing Linux Host Facts foundation. See `docs/host-information.md`.
- General evidence uploads now detect duplicates the same way Memory uploads already did.
- Archive extraction failures are classified instead of surfacing raw tool errors.

### Added

- A single `memory_enabled` setting as the sole authority for activating Memory at the application-composition level (default true, preserving existing deployment behavior).
- A dependency-free `GET /api/system/capabilities` endpoint exposing declarative capability activation state.
- Case-scoped, content-based (SHA-256) duplicate evidence detection across every general evidence-creation path: direct upload, disk-image upload, folder upload, register-by-path, and the legacy Velociraptor upload routes.
- Classified archive extraction errors (`archive_corrupted`, `archive_password_protected`, `archive_unsupported_format`, `archive_tool_missing`, `archive_extraction_timeout`, `archive_insufficient_disk_space`, `archive_extraction_limit_exceeded`, and a generic fallback) with analyst-facing messages separate from technical detail kept for logs.
- A configurable extraction timeout for the 7z-family archive backend (previously unbounded).
- A Surface Registry driving case navigation: Domain Tabs, Capability Cards summarizing each surface's coverage, and investigation breadcrumbs derived from capability state instead of hardcoded per-screen lists.
- Memory Process Entity page infrastructure.
- Windows local account inventory parsed natively from the SAM registry hive (RID, account-control flags, last logon/password-set, logon/bad-password counters), corroborated by ProfileList profile-path entries, feeding the existing Host Information Local Accounts view alongside Linux accounts.

### Changed

- Memory's routers and startup reconciliation hooks are now mounted/run only when `memory_enabled` is true, instead of unconditionally.
- Duplicate evidence requests now return `409` with `{error_code: EVIDENCE_DUPLICATE, duplicate: true, existing_evidence_id, existing_filename}` instead of silently creating a second Evidence row.
- The top-level ingest failure classifier now recognizes classified archive extraction errors and surfaces their analyst-facing message through the existing evidence-status path, instead of a raw exception string.
- Sidebar navigation simplified to surface-level, with a shared surface icon resolver across the navigation UI.
- Required host selection is now shown consistently across all evidence, not only a subset of intake paths.

### Fixed

- Stale indexing-plan completion state now reconciles correctly instead of leaving a plan looking incomplete after it finished.
- Memory tab parameter routing and the Memory runs evidence route.

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
