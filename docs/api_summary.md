# API Summary

This is a high-level API map for current user-facing workflows. See `/docs` in a running deployment for exact request and response schemas.

| Workflow | Representative endpoints | Notes |
| --- | --- | --- |
| Evidence upload and processing | evidence upload/register/reprocess endpoints | Upload wizard requires host context and records parser/status metadata. |
| Evidence status repair | evidence status recompute/repair endpoint | Reconciles `failed` versus `completed_with_warnings` when indexed data is investigation-ready. |
| Search | `POST /api/search`, case search endpoints | Supports command/path phrases, host alias expansion, include/exclude filters and advanced backend filters. |
| Timeline | Search timeline endpoints / `/search?view=timeline` | Shares Search filters. MFT/filesystem timeline is opt-in. |
| Command History | `GET /api/cases/{case_id}/command-history` | Filters by evidence, host, user, family, launcher, source, query and risk. |
| Execution Story | `GET /api/cases/{case_id}/execution-story` and focused tree endpoints | Exact identity pivots prefer `source_event_id`, then process GUID, then PID+timestamp+host+evidence. |
| Event markings | event marking endpoints | Used from Search, Command History, Execution Story and Reports. |
| Findings | finding CRUD and linked-event endpoints | Findings consolidate marked events, detections, commands and analyst notes. |
| Reports | report preview/generate/export endpoints | Markdown export is validated; sections include findings, detections, marked events, Command History, Execution Story summaries and Defender where selected. |
| MFT actions | MFT diagnostic/summary/full actions | Full MFT indexing is explicit and updates MFT metadata without marking evidence failed on optional-parser errors. |
| Defender | Search/report/artifact endpoints over `artifact.type=defender` | No-data Defender logs are represented as no-data, not failure. |
| User Activity | scoped RECmd extraction/search endpoints | Selected user activity families are indexed where hive data exists. |
| EZ Tool rebuilds | scoped advanced rebuild endpoints | LNK/Jumplist/Amcache/Shimcache advanced rebuilds are separate from default Search. |
| Rules and detections | rules import/run and detections endpoints | Sigma is event-focused. YARA must be scoped to preserved files. |

## API safety principles

- Evidence documents are not deleted by parser status repair.
- Optional parser failures do not make an investigation-ready evidence failed.
- Advanced parsers should write audit metadata and avoid duplicate default Search results.
- Exact process pivots should never choose a similar command by text when stable IDs exist.

