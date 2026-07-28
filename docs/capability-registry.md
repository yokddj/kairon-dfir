# Capability Registry

Phase 0 introduced a server-side, case-scoped capability registry at `GET /api/cases/{case_id}/capabilities`.

The endpoint is additive to evidence and artifact APIs. The registry owns workbench metadata and canonical route metadata for capability navigation.

## Response Shape

- `registry_version`: version of the declared registry payload.
- `generated_at`: response generation timestamp.
- `case`: case identity and status.
- `platforms`: OS platforms present in evidence (`windows`, `linux`, `macos`, `unknown`).
- `evidence_domains`: acquisition domains present in evidence, currently `filesystem` and `memory`.
- `workbenches`: visible workbench grouping derived from shipped capabilities and case scope.
- `capabilities`: declared capability entries with evaluated `readiness`, `visible`, counts, route, nav, and Search metadata.
- `hosts`: host-level evidence/platform/domain summary.
- `evidence`: evidence-level platform/domain projection.

## Memory Semantics

Memory is represented as `evidence_domain = "memory"`, not as an OS platform. Existing persisted `EvidencePlatform.memory` values remain supported as legacy inputs, but the new registry projects memory evidence to an OS platform of `windows`, `linux`, `macos`, or `unknown`.

If memory evidence still has `effective_platform = "memory"`, the registry uses metadata such as `probable_os`, `detected_os`, `os`, or `platform` when present. Otherwise, it returns `platform = "unknown"` and keeps `legacy_effective_platform = "memory"` for auditability.

## Readiness States

- `not_applicable`: the capability's platform/domain is not present in the case.
- `not_collected`: the platform/domain is present, but no matching artifacts or memory summaries are present.
- `empty`: matching artifacts exist but have no records.
- `has_data`: matching records exist.
- `degraded`: matching data exists, but parser/plugin status indicates partial failure.

## Sidebar Generation

The sidebar consumes `GET /api/cases/{case_id}/capabilities` for all workbench content. It no longer owns platform logic, workbench visibility, capability visibility, or capability ordering.

Frontend responsibilities:

- Render the fixed shell groups: `Investigation` and `Case Tools`.
- Render registry-provided `workbenches`, `domains`, and visible `capabilities` generically.
- Respect `nav.order` and backend-provided workbench/domain grouping.
- Preserve each capability's declared `route` unchanged, with `:caseId` substitution and `:evidenceId` substitution when the analyst is already in a memory evidence context.
- Show loading, failure, and capability state indicators without deciding whether a platform or capability should exist.

Backend responsibilities:

- Declare capabilities, labels, routes, domains, parent paths, and ordering metadata.
- Evaluate platform/domain scope, readiness, and `visible` per case.
- Keep memory modeled as `evidence_domain = "memory"` while projecting its OS platform separately.
- Add future workbenches or capabilities by extending the registry, not Sidebar code.

## Canonical Routes

Phase 2 makes registry routes canonical for capability navigation. Current canonical capability paths use compact workbench prefixes:

- Windows execution stories: `/cases/:caseId/w/execution/stories`.
- Windows command history: `/cases/:caseId/w/execution/command-history`.
- Linux authentication: `/cases/:caseId/l/access/authentication`.
- Linux command history: `/cases/:caseId/l/execution/command-history`.
- Memory landing: `/cases/:caseId/m`.
- Memory evidence views: `/cases/:caseId/m/:evidenceId/{overview,processes,process-graph,network,modules,handles,vads,suspicious,system,raw,artifacts}`.
- Memory runs: `/cases/:caseId/m/runs`.

Memory routes are path-based. The public `process-graph` segment maps to the internal memory tab key `graph`.

## Legacy Redirects

Old bookmarks remain supported as single-hop redirects and should not be used for new UI links:

- `/cases/:caseId/linux-authentication` redirects to `/cases/:caseId/l/access/authentication`.
- `/cases/:caseId/command-history` redirects to `/cases/:caseId/l/execution/command-history`.
- `/cases/:caseId/process-graph` and `/cases/:caseId/process-tree` redirect to `/cases/:caseId/w/execution/stories`.
- `/cases/:caseId/artifact-search` redirects to `/cases/:caseId/artifacts`.
- `/cases/:caseId/memory/:evidenceId/:tab` redirects to `/cases/:caseId/m/:evidenceId/:tab`, with legacy `graph` rewritten to `process-graph`.
- `/cases/:caseId/memory?tab=runs` redirects to `/cases/:caseId/m/runs`.
- `/cases/:caseId/memory?tab=...` redirects to the specific memory image only when exactly one memory image exists; otherwise it redirects to `/cases/:caseId/m` without guessing evidence identity.

Search behavior and Search result semantics are intentionally unchanged by Phase 2; only navigation targets were moved to canonical routes.
