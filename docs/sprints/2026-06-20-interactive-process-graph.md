# Sprint: Interactive Memory Process Graph v1

## Status

`closed` — graph is interactive, scalable, and bound to canonical
memory entities; Execution Stories unaffected; disk regression
passes; no local deployment was started.

## Components reused

* Visual conventions of `ProcessTreePanel` (Execution Stories): SVG
  for edges, absolutely-positioned buttons for node cards, depth
  bucketing, layout columns, `border-line` / `bg-panel` /
  `bg-abyss` / `text-muted` / `text-accent` tokens.
* Lucide icons (`Network`, `GitBranch`, `Workflow`, `Layers`,
  `ShieldAlert`, `Table`, `ZoomIn`, `ZoomOut`, `RotateCcw`,
  `ChevronDown`, `ChevronRight`, `Eye`, `Copy`).
* Existing `api.getCanonicalProcessTree` endpoint (extended, not
  duplicated).

## Components extracted

* `frontend/src/lib/processGraphLayout.ts` — generic BFS layout
  (`buildProcessGraphLayout`) reusable by future adapters
  (`ExecutionStoryGraphAdapter`, `CorrelatedProcessGraphAdapter`).
* New `MemoryProcessGraph.tsx` — domain-specific adapter for
  canonical memory entities (no new graph library; same SVG +
  positioned buttons pattern as `ProcessTreePanel`).

## Files changed

* `backend/app/services/memory/process_entities.py`
* `backend/app/api/routes_memory.py`
* `backend/app/schemas/memory.py`
* `backend/tests/test_canonical_process_tree.py` (new, 11 tests)
* `frontend/src/api/client.ts`
* `frontend/src/components/MemoryCanonicalView.tsx`
* `frontend/src/components/MemoryCanonicalView.test.tsx`
* `frontend/src/components/MemoryProcessGraph.tsx` (new)
* `frontend/src/components/MemoryProcessGraph.test.tsx` (new, 18 tests)
* `frontend/src/lib/processGraphLayout.ts` (new)
* `docs/sprints/2026-06-20-interactive-process-graph.md` (this file)

## Commits

* `f756263` Add search_results field to MemoryProcessTreeEntityRead schema
* `2c9a273` Track matched search entity IDs
* `32c7566` Use page_size=200 in tree builder to match API max
* `2687981` Add interactive memory process graph v1

## Local repository path

`/root/kairon`

## Remote deployment path

`192.168.1.19:/root/DFIR_APP`

## Tests

* Backend: 11/11 new in `test_canonical_process_tree.py`; 32/32 in
  `test_canonical_process_entities.py`; 76/76 in
  `test_memory_analysis.py`. Total relevant: 119 pass.
* Frontend: 18/18 new in `MemoryProcessGraph.test.tsx`; 20/20 in
  `MemoryCanonicalView.test.tsx`; 13/13 in
  `MemoryAnalysisPage.test.tsx`. Total relevant: 51 pass.
* Three pre-existing failures in unrelated files
  (`ProcessTreePanel`, `ArtifactExplorer`, `Rules`) persist but are
  not caused by this sprint.

## Build

* `tsc -b --noEmit`: clean.
* `vite build`: succeeded in 14.89s.

## Initial view

* Default: depth 2, max_nodes 60, scope "main tree".
* With 255 canonical entities, the initial canvas renders 156 DOM
  nodes (1 actual root + 2 visible children + 153 truncated
  placeholders). No client-side iteration over 255 entities.
* Truncation message: "The full process graph contains N canonical
  processes. Select a root, search for a process, or use the filters
  above."

## Maximum valid expansion

* `max_nodes=2000` (route validator cap), `depth=10` (route validator
  cap). Verified `max_nodes=10` returns 10 actual + truncated
  placeholders; `max_nodes=200` returns the full tree.

## PID 4

* Appears exactly once as a root.
* Playwright test verifies `systemCount === 1`.
* Other roots (Idle, orphans) deduplicate against System when their
  parent is in the visible set.

## Orphans

* 11 orphans in run `33440dac` (extended).
* Orphans scope returns them only, with their own dedicated view.
* Playwright test verifies `orphan_nodes === 11`.

## Scan-only

* Extended run surfaces 2 scan-only / hidden-candidate entities
  (svchost.exe PID 8112, TrustedInstall PID 11388).
* Basic run does not surface any scan-only (no psscan).
* Playwright test verifies the visibility filter surfaces them.

## PID 1116 validation

* Single canonical entity with PPID 808, name `svchost.exe`.
* Merged command line: `C:\Windows\system32\svchost.exe -k NetworkService -p`.
* Sources: `windows.pslist` + `windows.cmdline`.
* Search by PID 1116 returns the entity with 2 ancestors
  (services.exe, wininit.exe).
* Playwright test confirms.

## Playwright validation

16/16 pass against `http://192.168.1.19:5173/`. Screenshot deleted.

## Services recreated

* `dfir_app-backend-1` (3 times for fix iterations).
* `dfir_app-frontend-1` (1 time).
* NOT recreated: `dfir_app-memory-worker-1`,
  `dfir_app-symbol-fetcher-1`, `dfir_app-symbol-egress-gateway-1`,
  `dfir_app-postgres-1`, `dfir_app-redis-1`, `dfir_app-opensearch-1`,
  `dfir_app-worker-1`.

## Execution Stories regression

* `frontend/src/components/ProcessTreePanel.tsx`: untouched.
* `frontend/src/pages/CaseProcessGraphPage.tsx`: untouched.
* No Execution Story code path is exercised by the new code.

## Disk regression

* `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893` count: 1,336,751
  (unchanged).
* `search` / `timeline` / `artifacts`: HTTP 200.
* Zero `memory_process_entity` documents in disk index.

## No local deployment

* No second Kairon instance was launched from `/root/kairon`.
* The only deployment mechanism was `scripts/deploy_remote.sh`
  against `192.168.1.19:/root/DFIR_APP`.
* No new memory analyses were started; renormalized data from the
  prior sprint is reused.
