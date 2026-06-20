# Sprint: Memory Analysis UX Consolidation v1

## Status

`closed` — Memory Analysis is now a 6-tab workspace. Legacy raw views moved to a dedicated tab. No backend, no reanalysis, no disk writes.

## Files changed

* `frontend/src/components/MemoryWorkspace.tsx` (new)
* `frontend/src/lib/memoryWorkspaceState.ts` (new)
* `frontend/src/components/memory/MemoryOverviewTab.tsx` (new)
* `frontend/src/components/memory/MemoryProcessesTab.tsx` (new)
* `frontend/src/components/memory/MemoryGraphTab.tsx` (new)
* `frontend/src/components/memory/MemorySystemTab.tsx` (new)
* `frontend/src/components/memory/MemoryRunsTab.tsx` (new)
* `frontend/src/components/memory/MemoryRawTab.tsx` (new)
* `frontend/src/components/memory/MemoryAnalyzeAction.tsx` (new)
* `frontend/src/components/MemoryCanonicalView.tsx` (controlled entityId)
* `frontend/src/components/MemoryProcessGraph.tsx` (controlled entityId)
* `frontend/src/pages/MemoryAnalysisPage.tsx` (14 lines)
* `frontend/src/pages/MemoryAnalysisPage.test.tsx` (20 tests)

## Commit

`7f7194d` Consolidate Memory Analysis workspace

## Tabs

Overview · Processes · Graph · System · Runs · Raw observations.
URL `?tab=…` is persisted; `role=tab`/`aria-selected` set.

## Legacy views moved

* Legacy `Processes` table → Raw tab (`raw-table`)
* Legacy `Process tree` → Raw tab (`raw-toggle-tree`)
* `windows.info` history → System tab, collapsed by default

## System info latest vs historical

* `system-info-card-primary` shows the latest successful.
* `system-info-card-secondary` shows the rest, behind a toggle.
* Missing fields surface a compact "not normalized" warning.

## Graph metrics renamed

Visible, Matching, Context ancestors, Collapsed, Not loaded, Case roots, Orphans, Scan only (in tab header). The canvas-internal `Visible/Truncated/Omitted` are kept as a separate block.

## Process detail layout

* Processes tab uses a left/right split: table + side detail panel.
* Graph tab keeps a right-side detail panel; opens "Open process details" navigates to Processes tab with the same selection.

## Tests

* Frontend: 20 new in `MemoryAnalysisPage.test.tsx`; 18 in `MemoryCanonicalView.test.tsx`; 18 in `MemoryProcessGraph.test.tsx`; 13 in `MemoryAnalysisPage.test.tsx` pre-existing. Total relevant: 69 pass.
* Backend: untouched. 119 existing pass.

## Build

`tsc -b --noEmit` clean; `vite build` 14.37s.

## Playwright

16/16 pass against `http://192.168.1.19:5173/`. Screenshot deleted.

## Services recreated

Only `dfir_app-backend-1` + `dfir_app-frontend-1`. Memory worker, symbol fetcher, symbol-egress gateway, postgres, redis, opensearch untouched (verified by `docker ps`).

## Disk regression

`dfir-events-c01c0be4-2381-4208-8af6-266e2579a893`: 1,336,751 docs unchanged, search/timeline/artifacts HTTP 200.

## Confirmation

* No local deployment was started.
* No Volatility reanalysis.
* Evidence, PDB, ISF, symbol cache, OpenSearch indices untouched.
* No `dfir-events-*` writes.
* No `NormalizedEvent` creation.
* ProcessTreePanel and CaseProcessGraphPage (Execution Stories) untouched.
