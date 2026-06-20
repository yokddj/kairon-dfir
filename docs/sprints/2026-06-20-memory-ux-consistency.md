# Sprint: Memory UX Consistency & Centered Process Inspector

## Status
Closed. Single canonical commit `fe4ba9b`. Single remote deployment on
`192.168.1.19:/root/DFIR_APP`. 14/14 Playwright checks pass; 360 frontend
tests pass; 132 backend tests pass.

## Cause of the duplicate "metrics at zero" row
`MemoryGraphTab` held an internal `graphMetrics` state initialized to
zeroes, and `MemoryProcessGraph` re-rendered its own 6-stat row below
the canvas. The two never talked to each other; the tab-level row was
only refreshed when the inner component fired a callback, so for any
load that did not start a search the user saw `0` next to the real
`Case roots=1` from the underlying query. The fix is a single source
of truth: `useMemoryTreeMetrics` returns one metrics object derived
from `_build_tree_response.metrics`, and the tab-level `MetricsStrip`
is the only place these numbers are rendered.

## roots / orphans semantics
`_build_tree_response` now returns:
* `roots` — strictly the entities flagged `tree.is_root=True`,
  **excluding** PID 0 (Idle). For the extended run, length 1 (System, PID 4).
* `orphans` — entities whose expected parent is missing in the canonical
  set, excluding roots and PID 0. For the extended run, length 11.
* `top_level_nodes` — presentational union (roots + orphans), length 12.
* `nodes` — alias of `top_level_nodes` for backward compatibility.

`metrics` adds `case_roots`, `current_view_roots`, `visible_processes`,
`context_ancestors`, `collapsed_branches`, `processes_not_loaded` so the
UI can drive a single strip.

## PID 0 treatment
PID 0 (Idle) is a technical entity used as a back-reference target. It
is **never** a user-visible root in the tree response; if it is
incorrectly flagged `is_root=True` by a legacy document, the response
drops it. PID 0 never replaces System as the visible root, never
introduces a second user-visible root, and never increments
`case_roots`. `metrics.pid_zero_count` is preserved for audit
purposes only.

## Pending fix from previous sprint
The dedup branch in `_build_tree_response` (which previously removed
the System root because its parent in the root set was Idle) is now
versioned in this sprint: it is included in commit `fe4ba9b`, the
backend test `test_no_duplicate_entities_in_tree` covers it, and the
remote container now runs the same code as `/root/kairon`.

## Files
* `backend/app/services/memory/process_entities.py` — new roots/orphans
  split, metrics extension, dedup fix.
* `backend/app/schemas/memory.py` — `MemoryProcessTreeEntityRead`
  adds `roots`, `orphans`, `top_level_nodes`.
* `backend/tests/test_canonical_process_tree.py` — 7 new tests
  (roots=1, orphans=11, PID 0 not root, filtered view, no orphan
  inflation, idempotence, dedup).
* `frontend/src/api/client.ts` — `MemoryProcessTreeEntity` types
  include `roots`, `orphans`, `top_level_nodes` and the new metrics
  fields.
* `frontend/src/components/memory/ProcessDetailModal.tsx` — new
  centered modal (replaces `ProcessDetailDrawer.tsx`, deleted).
* `frontend/src/components/memory/MetricsStrip.tsx` — single metrics
  strip, skeleton during loading.
* `frontend/src/lib/useMemoryTreeMetrics.ts` — single source of
  metrics.
* `frontend/src/components/memory/MemoryGraphTab.tsx` — uses
  `MetricsStrip`; opens detail in modal.
* `frontend/src/components/memory/IndentedTreeView.tsx` — splits
  Main tree and Orphans; removes the misleading "N root(s)" string;
  branch grouping preserved.
* `frontend/src/components/memory/MemoryProcessesTab.tsx` — uses
  the new modal.
* `frontend/src/components/memory/MemoryRawTab.tsx` — "Open
  canonical" opens the same modal.
* `frontend/src/components/MemoryProcessGraph.tsx` — internal
  metrics row reduced to canvas-only state (visible / truncated /
  omitted); no more duplicate "roots/orphans" line.
* `frontend/src/pages/MemoryAnalysisPage.test.tsx`,
  `frontend/src/pages/MemoryAnalysisPage.ux.test.tsx` — updated to
  the new testids and tree fixture; 6 new UX assertions.

## Modal
* `max-w-[min(1100px,92vw)]`, `max-h-[88vh]`, `role=dialog`,
  `aria-modal=true`, `aria-labelledby` heading id.
* Focus trap on Tab/Shift+Tab; Escape closes; focus restored to the
  trigger.
* Overlay click closes (no pending operation).
* Four internal tabs: Overview, Relationships, Observations, Raw
  references. Command line wraps + copies. Tree path uses names+pids.
* Actions: Open parent, Open child, Focus in visual graph, Show in
  indented tree, Copy PID.

## Relationships tab
* Parent, child count, tree state, missing-parent state.
* Tree path breadcrumb with names+PIDs.
* "Open parent" / "Open child" buttons update the modal in place.
* "Focus in visual graph" / "Show in indented tree" switch the tab.

## Indented tree
* Two sections: "Main tree · N root" and "Orphans · N".
* Orphans section starts collapsed; "Show orphan processes" button
  expands.
* Grouped children share style with expandable groups (e.g.
  `svchost.exe × 42`).
* Connectors use `├─` / `└─` glyphs, not asterisks.
* Child count badge next to each process.

## Tests
* Backend: 18 tree tests pass (11 prior + 7 new). 132 tests pass
  for tree/entities/normalizer/analysis.
* Frontend: 360 tests pass (including 26 UX tests, 6 new this
  sprint). 3 pre-existing failures unchanged
  (Rules/ProcessTreePanel/ArtifactExplorer, unrelated).

## Build
* `tsc -b --noEmit` clean.
* `vite build` 15.19s.
* Backend container rebuilt via `docker compose build --no-cache
  frontend` and `up -d frontend`; backend via
  `docker compose restart backend`.

## Playwright (against http://192.168.1.19:5173/)
14/14 pass:
* Frontend serves the new modal bundle.
* Memory workspace loads with the tablist.
* Processes tab: no global horizontal overflow.
* Inspect opens a centered modal (no side drawer).
* Escape closes the modal.
* Graph tab: single metrics strip, no legacy `graph-tab-stat-*`.
* Case roots = 1, Orphans = 11.
* Indented tree: "Main tree · 1 root" / "Orphans · 11" / no
  "N root(s)".
* Search matches a deep child row.
* Raw tab "Open canonical" opens the same modal.
* System tab: normalized data preserved (22621, x64).
* Overview tab: Case roots card = 1, Orphans card = 11.
* No JS errors in console.
* No 4xx/5xx for memory endpoints.

## Services recreated
* `dfir_app-frontend-1` — `docker compose build --no-cache frontend`
  + `up -d frontend`.
* `dfir_app-backend-1` — `docker compose restart backend`.

## Services NOT recreated
* `dfir_app-memory-worker-1` (27h uptime, healthy).
* `dfir_app-symbol-fetcher-1` (7h uptime, healthy).
* `dfir_app-symbol-egress-gateway-1` (7h uptime, healthy).
* `dfir_app-postgres-1` (10h uptime, healthy).
* `dfir_app-redis-1` (10h uptime).
* `dfir_app-opensearch-1` (37h uptime, healthy).

## Disk regression
* `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893` count:
  1,336,751 (unchanged from previous sprint).
* No Volatility reanalyze, no `memory_process_entity` writes
  outside the canonical index, no `NormalizedEvent` creation.

## Single deployment confirmed
* Local commit `fe4ba9b`, pushed to `origin/main`.
* Remote `/root/DFIR_APP` source updated via rsync (no `--delete`,
  no `.env` overwrite).
* Backend container files replaced via `docker cp` + restart;
  frontend image rebuilt and container recreated.
* `.env`, `data/`, `volatility-cache/`, `node_modules/` left
  untouched.
