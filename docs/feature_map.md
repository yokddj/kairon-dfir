# Feature Map

Estado de capacidades actualizado para la plataforma DFIR. Las etiquetas significan:

- `stable`: usable por defecto en flujo normal.
- `advanced`: disponible con acción explícita, warning o filtro avanzado.
- `experimental`: operativo pero sujeto a validación limitada.
- `planned`: diseñado o pendiente.
- `tooling_missing`: fuente detectada, pero falta backend viable en este despliegue.

| Area | Status | Backend / data source | Default / advanced | UI route | API / operations | Limitations | Next action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Evidence upload/indexing | stable | FastAPI worker, archive extraction, parser selection | default | Evidence & Ingest | evidence upload/reprocess endpoints | Large evidence should prefer mounted paths or scoped parsing. | Keep parser coverage matrix current. |
| Evidence status / `investigation_ready` | stable | PostgreSQL evidence metadata + indexed document counts | default | Evidence Detail, Reports | status recompute/repair action | `completed_with_warnings` can still be investigation-ready. | Keep warnings actionable. |
| Host canonicalization | stable | `host_identity` service, evidence aliases, query-time alias expansion | default | Case host management, Search filters | host merge/split/search expansion | Alias merges require analyst judgment. | Continue avoiding unrelated-host matches. |
| Search workspace | stable | OpenSearch case index | default | `/search` | `/api/search`, `/api/cases/{case_id}/search` | Expensive wildcard clauses are bounded. | Continue phrase/path regression tests. |
| Search Timeline | stable | Search view over matching events ordered by time | default, MFT gated | `/search?view=timeline` | timeline/search endpoints | MFT/filesystem excluded by default to avoid flooding. Legacy `/timeline` redirects here. | Keep filters shared with Search. |
| Incident Timeline | stable | Curated reportable incident chronology | default, high-signal sources only | `/cases/{case_id}/incident-timeline` | incident timeline endpoints | Not an all-events timeline; draft can be validation-seeded in training cases. | Improve curation workflow. |
| Artifact Views | stable | Specialized views over indexed artifacts | default plus advanced variants | `/artifacts` | artifact/search endpoints | Not a second global search engine. | Add views only where fields justify it. |
| Memory Analysis | planned experimental | PostgreSQL memory metadata tables only | disabled by default | `/cases/{case_id}/memory` | `/api/cases/{case_id}/memory`, `/api/evidences/{evidence_id}/memory/scan` | Isolated foundation only. No Volatility/MemProcFS execution, no bundled tools, no memory artifacts in global Search/Timeline/Detections/Findings/Reports/SIEM. Use only authorized RAM evidence. | Metadata-only runner design. |
| Command History | stable | Derived endpoint over Sysmon/Security/PowerShell/other command sources | default | Command History | `/api/cases/{case_id}/command-history` | Prefetch is supporting context, not exact command line. | Reports integration and family/launcher refinements continue. |
| Execution Story | stable | Process tree/story services over source event identity | default | Execution Story / Process Graph workspace | `/api/cases/{case_id}/execution-story`, focused tree endpoints | Graph links are evidence-derived and still show uncertainty. | Keep exact identity pivots guarded. |
| Markings / Findings | stable | PostgreSQL analyst annotations and findings | default | Search, Findings, Reports | event marking and finding endpoints | Markings annotate source events; they do not mutate original evidence. | Improve report UX as needed. |
| Reports | stable | Report service, Markdown export | default | Reports | preview/generate/export endpoints | Markdown is the validated deliverable. PDF should not be treated as primary/stable unless validated in deployment. | Continue report section coverage. |
| Sigma rules / detections | stable | Sigma engine over normalized events | explicit analyst run | Rules, Detections | rules/run/detections endpoints | Avoid full-pack noisy runs without scope. | Sigma smoke UX. |
| YARA | advanced | YARA over preserved files | explicit scoped run | Rules | YARA rule run endpoints | Must be scoped by size/root/type. | Keep safeguards visible. |
| EVTX | stable | EvtxECmd CSV backend | default | Search, Timeline, Artifact Views | ingest parser | Message rendering depends on available event data. | Maintain channel/event mappings. |
| Sysmon rich fields | stable | EvtxECmd normalized Sysmon fields | default | Search, Command History, Execution Story | search/story endpoints | Requires Sysmon channel in evidence. | Continue field coverage tests. |
| Security 4688 / 4663 | stable | EvtxECmd normalized Security fields | default | Search, Command History, Execution Story | search/story endpoints | 4688 command line depends on audit policy. | Maintain object name normalization. |
| MFT full | stable | MFTECmd CSV from raw `$MFT` cache/output | explicit advanced action after detection | Evidence Detail, Artifact Views MFT, Search | MFT summary/full actions | Full MFT can add hundreds of thousands of docs; Timeline excludes it by default. | MFT Full Indexing Advanced follow-up only for more controls. |
| Defender | stable | Defender EVTX parser over EvtxECmd rows/raw Defender EVTX | default when channel exists | Artifact Views Defender, Search, Reports | defender/search/report sections | If log has only configuration/health events, threat queries can correctly return zero. | Broaden Defender sources if needed. |
| RECmd User Activity | stable partial | RECmd CSV extraction from NTUSER.DAT / UsrClass.dat for selected families | scoped action | Artifact Views User Activity, Search | user activity extraction/search | UserAssist, RecentDocs, RunMRU, OpenSaveMRU work where hive data exists; Shellbags pending separate backend. | Shellbags Parser v1. |
| Prefetch | stable partial | Internal raw parser | default | Artifact Views Prefetch, Search | ingest parser | PECmd raw `.pf` parsing disabled on Linux because Windows decompression support is missing. | Consider Windows worker or keep internal. |
| LNK | advanced | Internal default; LECmd advanced rebuild | advanced-only | Artifact Views LNK | EZ scoped rebuild action | EZ output had richer fields but lower coverage on HOSTA. | EZ Backend Default Activation Decision. |
| Jumplist | advanced | Internal default; JLECmd advanced rebuild | advanced-only | Artifact Views Jumplist | EZ scoped rebuild action | EZ output had richer fields but lower coverage on HOSTA. | EZ Backend Default Activation Decision. |
| Amcache | advanced | Internal default; AmcacheParser advanced rebuild | advanced-only | Artifact Views Amcache | EZ scoped rebuild action | Advanced docs are hidden from default Search unless selected. | Decide default after more evidence. |
| Shimcache / AppCompatCache | advanced | Internal default; AppCompatCacheParser advanced rebuild | advanced-only | Artifact Views Shimcache | EZ scoped rebuild action | Shimcache is not proof of execution by itself. | Decide default after more evidence. |
| SRUM | tooling_missing | SRUDB.dat detected; SrumECmd requires Windows ESE libraries | unavailable on Linux worker | Artifact Views SRUM empty/tooling state | parser backend status | No fake SRUM data is generated. | SRUM Windows Worker Parser v1. |
| Shellbags | planned | NTUSER.DAT / UsrClass.dat candidates detected | not parsed by current selected user activity backend | User Activity planned tab/state | none stable yet | Shellbags should not be documented as implemented for raw hives. | Shellbags Parser v1. |
| Windows worker | planned | Optional remote Windows parser worker | disabled by default | System / parser backend status planned | parser job model planned | Needed for SrumECmd and possibly some Windows-only tooling. | Windows worker implementation. |
