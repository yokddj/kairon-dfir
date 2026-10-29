# API Summary

A map of the HTTP API by area. A running deployment serves the exact request
and response schemas at `/docs` (OpenAPI). Every route lives in
`backend/app/api/routes_*.py`; most are case-scoped under
`/api/cases/{case_id}/…`.

## Route modules

| Module | Area | Representative endpoints |
| --- | --- | --- |
| `routes_auth.py` | Login, session, password change, first-run admin setup | `/api/auth/login`, `/api/auth/setup` |
| `routes_admin.py` | Users and administration (Administrator only) | `/api/admin/*` |
| `routes_system.py` | Version, health, schema health, capabilities, task registry, settings | `GET /api/system/health`, `GET /api/system/capabilities` |
| `routes_cases.py` | Cases: create, status, priority, tags, archive, delete | `/api/cases` |
| `routes_evidence.py` | Evidence upload, register by path, reprocess, status repair, integrity, MFT/EZ actions | `/api/cases/{case_id}/evidences…`, `/api/evidences/{evidence_id}…` |
| `routes_evidence_preflight.py` | Resumable upload sessions, preflight, ingestion readiness, evidence operations | `/api/cases/{case_id}/evidence-uploads…` |
| `routes_evidence_companions.py` | Companion files (e.g. VMware `.vmsn` next to `.vmem`) | `/api/cases/{case_id}/evidences/{evidence_id}/companions` |
| `routes_velociraptor.py` | Velociraptor collection discovery and selective parsing | |
| `routes_disk_files.py` | File browser over disk images | |
| `routes_hosts.py`, `routes_host_facts.py`, `routes_host_users.py`, `routes_host_network.py` | Host canonicalization, Host Facts, Local Accounts, network configuration | `/api/cases/{case_id}/hosts…` |
| `routes_search.py` | Search, field facets, SIEM view (saved searches, history) | `POST /api/search` |
| `routes_timeline.py` | Timeline, quick filters, events around an event, Incident Timeline draft and export | `/api/cases/{case_id}/timeline`, `/incident-timeline/draft` |
| `routes_events.py` | Events of an artifact, event markings | `POST /api/events/{event_id}/mark` |
| `routes_command_history.py` | Command History | `GET /api/cases/{case_id}/command-history` |
| `routes_persistence.py`, `routes_motw.py`, `routes_email_artifacts.py`, `routes_linux_auth.py` | Derived views: persistence, Mark of the Web, email artifacts, Linux authentication | |
| `routes_source_tables.py` | Source Tables ([source-tables.md](../search-and-investigation/source-tables.md)) | `/api/cases/{case_id}/source-tables…` |
| `routes_rules.py` | Sigma/YARA rule import, rule sets, runs, detections | |
| `routes_hunting.py` | Correlation findings, detection runs, hunting rule evaluation | `/api/cases/{case_id}/findings`, `/detection-runs` |
| `routes_findings.py`, `routes_indicators.py`, `routes_tags.py` | Investigation findings and correlation, indicators, tags | `POST /api/cases/{case_id}/correlate` |
| `routes_reports.py` | Report templates, drafts, preview, Markdown/PDF export | `/api/cases/{case_id}/reports/{report_id}/export` |
| `routes_activity.py` | Activity feed and case activity log | `/api/activity`, `/api/cases/{case_id}/activity-log` |
| `routes_memory.py`, `routes_memory_experimental.py`, `routes_memory_recovery.py` | Memory Analysis: upload, preparation, runs, results, Find Evil, symbols (mounted only when `memory_enabled`) | `/api/…/memory…`, `/api/admin/memory/symbols…` |
| `routes_ai.py` | AI provider configuration, case chat, natural-language search, conversations | `/api/ai/*`, `/api/cases/{case_id}/ai/*` |

## Behaviour worth knowing

| Workflow | Notes |
| --- | --- |
| Evidence upload | SHA-256 is computed and a duplicate inside the case returns `409`. |
| Evidence status repair | Reconciles `failed` versus `completed_with_warnings` when indexed data is investigation-ready. |
| Search | Command/path phrases, host alias expansion, include/exclude filters, field shortcuts (`eventid:`, `ip:`, `process:`…), advanced backend filters. |
| Timeline | Shares Search filters. MFT/filesystem and MemProcFS NTFS/registry events are opt-in. |
| Command History | Filters by evidence, host, user, family, launcher, source, query and risk; includes memory-recovered commands. |
| Execution Story | Exact identity pivots prefer `source_event_id`, then process GUID, then PID+timestamp+host+evidence. |
| Findings | Consolidate marked events, detections, commands, memory rows and analyst notes. |
| Reports | Sections include findings, detections, marked events, Command History, Execution Story, Defender and Memory Analysis where present. |
| Detections | Run on demand. Sigma is event-focused; YARA must be scoped to preserved files. |

## API safety principles

- Evidence documents are not deleted by parser status repair.
- Optional parser failures do not make an investigation-ready evidence failed.
- Advanced parsers should write audit metadata and avoid duplicate default Search results.
- Exact process pivots should never choose a similar command by text when stable IDs exist.
- A field must be declared in the response schema (`backend/app/schemas/`) to reach the client.
- State-changing requests from another origin are refused.
