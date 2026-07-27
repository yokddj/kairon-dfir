# Capability Registry

Phase 0 introduces a server-side, case-scoped capability registry at `GET /api/cases/{case_id}/capabilities`.

The endpoint is additive. Existing platform enums, routes, sidebar behavior, and Search filters are unchanged.

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
