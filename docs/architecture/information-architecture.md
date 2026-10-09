# Information Architecture

Kairon information architecture is registry-driven. The capability registry is the source of truth for investigator-facing capability metadata; frontend navigation renders from the registry instead of keeping platform policy lists.

## Capability Registry

Owner: `backend/app/services/case_capabilities.py`.

The static `CAPABILITY_REGISTRY` owns capability identity and metadata:

- `id`, `platform`, `evidence_domain`, `domain`, `title`
- canonical `route`
- `artifact_families`
- sidebar `nav` grouping and order
- overview metadata: `priority`, `featured`, `quick_action`
- readiness source and availability

No frontend component should maintain its own list of Windows, Linux or Memory capabilities.

## Capability State

Owner: `build_case_capabilities` in `backend/app/services/case_capabilities.py`.

Capability state is computed per case from evidence, artifact counts, artifact statuses, memory summaries, memory scan runs and memory plugin runs. The registry supplies identity and ownership; the state layer supplies `artifact_count`, `record_count`, `status_counts`, `readiness` and `visible`.

## Workbench Summary

Owner: helper functions in `backend/app/services/case_capabilities.py`.

Workbench summaries are derived from visible capabilities and scoped evidence. They include:

- workbench `overview_route`
- host and evidence counts
- aggregate processing state
- coverage status counts
- quick actions
- warnings
- recent detections/findings scoped to workbench evidence
- memory image summaries for the Memory workbench

The HTTP endpoint remains `GET /api/cases/{case_id}/capabilities`; the internal model is separated for clarity, not for API redesign.

## Routing

Canonical capability routes live in the backend registry. React route registrations in `frontend/src/App.tsx` are the executable router surface for those registry paths and are covered by backend architecture tests.

Frontend code that must build canonical deep links uses `frontend/src/lib/canonicalRoutes.ts` instead of embedding route strings repeatedly. These helpers centralize canonical route spelling for pivots that carry runtime query state, such as memory evidence links and execution story focus links.

Intentional compatibility redirects remain in `App.tsx` for shipped legacy URLs. Redirects must be single-hop and must terminate on canonical routes.

## Sidebar

Owner: `frontend/src/components/Sidebar.tsx`.

The sidebar is one flat **Investigation** list, with no submenus and no per-surface section (the former "Investigation Surfaces" rows were removed in 2026-10: their views were either already in the list -- Command History, Artifact Views for persistence and packages -- or are now in it directly). Three entries exist only for some evidence and are shown when the registry's `workbenches` say the case has it: **Memory** (`memory`, placed above Timeline), **Execution Stories** (`windows`) and **Linux Authentication** (`linux`). While the registry loads they are hidden; if it cannot be read they are all shown rather than hidden. The surface home pages (`/w`, `/l`, `/m`) still exist for breadcrumbs and the case overview's links.

## Overview

Owner: `frontend/src/components/workbench/WorkbenchOverview.tsx` and `frontend/src/pages/WorkbenchOverviewPage.tsx`.

Workbench overview rendering is generic. It does not branch into Windows/Linux/Memory capability lists. Platform-specific behavior comes from backend registry metadata and workbench summary payloads. The only visual platform distinction is a generic icon choice by workbench id.

## Compatibility Boundary

Compatibility redirects are not IA policy. They preserve old bookmarks and external links until removal is explicitly scheduled. They must not be used by internal navigation.

The old memory landing implementation has been replaced by a compatibility wrapper around the generic registry workbench page.

## Search Boundary

Search is intentionally unchanged in Phase 2.6. Capability-aware Search redesign belongs to Phase 3.
