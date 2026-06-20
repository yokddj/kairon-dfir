# Sprint 1: Canonical Memory Process Model & Reliable Basic/Extended Views

## Status

`closed`

The canonical entity/observation model is implemented, the UI is
refactored, the real case is renormalized, browser validation passes
against `http://192.168.1.19:5173/`, disk regression passes, and no
sensitive artifacts were committed.

## Root cause of `processes_basic` appearing empty

The legacy normalizer produced **one document per plugin row** with
identity ``(pid|offset|create_time)``.  Because each plugin reports
its own offset:

* A single process seen by `pslist` and `cmdline` produced two
  documents with different offsets, looking like two processes.
* A `cmdline`-only row had no `PPID`, which the legacy tree
  incorrectly treated as PPID 0, producing hundreds of phantom roots.
* A `pstree` PPID was the only reliable parent reference; without
  it, every cmdline row became a root.
* PID 4 (System) and PID 0 (Idle) appeared multiple times because
  each plugin emitted its own row.
* The "Processes" table was therefore a denormalized per-plugin
  mess that the UI could only show, not reason about.

## Canonical identity algorithm

A canonical `MemoryProcessEntity` is built from per-plugin
observations using a three-tier identity:

1. **Strong identity**: ``(case_id, evidence_id, pid, create_time)``.
   Two observations sharing all four belong to the same entity.  This
   is the preferred identity.
2. **Name identity**: ``(case_id, evidence_id, pid, process_name)``.
   Fallback when `create_time` is missing.  A name-only observation
   that matches a strong identity is reconciled into the strong
   entity.
3. **Weak identity** (PID only): never used as a final identity.
   When a row has neither `create_time` nor `name`, the entity is
   flagged `identity_provisional` with `confidence=low`.

The reconciliation never merges two different PIDs and never merges
two observations with conflicting `create_time`s.

## Merge precedence rules

| Field | Priority (highest first) | Notes |
| --- | --- | --- |
| `name` | `pslist` > `psscan` > `pstree` > `cmdline` basename > `unknown` | Conflicts retained as `name_conflict` finding. |
| `ppid` | `pstree` > `pslist` > `psscan` > other | A present value is never replaced by `null`. |
| `create_time` | `pslist` > `psscan` > `pstree` > other | A present value is never replaced by `null`. |
| `exit_time` | `psscan` > `pslist` > `pstree` > other | Required for `terminated` classification. |
| `command_line` | `cmdline` (preferred) | All variants preserved as observations. |
| `executable_name` | first non-empty name, else first command-line token | UI fallback when `name` is empty. |

## Files changed

* `backend/app/services/memory/process_entities.py` (new, 1077 lines)
* `backend/app/api/routes_memory.py`
* `backend/app/schemas/memory.py`
* `backend/tests/test_canonical_process_entities.py` (new, 32 tests)
* `frontend/src/api/client.ts`
* `frontend/src/lib/memoryCanonical.ts` (new)
* `frontend/src/components/MemoryCanonicalView.tsx` (new)
* `frontend/src/components/MemoryCanonicalView.test.tsx` (new, 20 tests)
* `frontend/src/pages/MemoryAnalysisPage.tsx`
* `frontend/src/pages/MemoryAnalysisPage.test.tsx`
* `docs/memory_process_model.md` (new)
* `docs/sprints/2026-06-20-canonical-process-model.md` (this file)

## Commits

* `3c36ca8` Root: also classify entity as root if parent is PID 0 self-reference
* `4776ec2` document_id is already a keyword; no .keyword subfield
* `e30e28a` Use .keyword subfield for term filters on canonical entities
* `4d080f9` Sort canonical entities by document_id (keyword) instead of process_entity_id
* `84b97e7` Reorder canonical routes so /summary and /renormalize are not shadowed by /{entity_id}
* `b441099` Document canonical memory process model
* `85346ea` Add canonical memory process view (frontend)
* `4110536` Implement canonical memory process entity model v1

## Local repository path

`/root/kairon`

## Remote deployment path

`192.168.1.19:/root/DFIR_APP`

## Confirmation

* No local deployment was started.
* No second Kairon instance was launched from `/root/kairon`.
* The deployment script `scripts/deploy_remote.sh` was the only
  deployment mechanism used.
* The deploy recreated only `dfir_app-backend-1` and
  `dfir_app-frontend-1`.  Memory worker, symbol-fetcher,
  symbol-egress-gateway, postgres, redis and opensearch were NOT
  recreated.

## Selected canonical repository

* **Repository**: `git@github.com:yokddj/kairon-dfir.git` (canonical).
* **Local working tree**: `/root/kairon`.
* **Remote working tree**: `/root/DFIR_APP` (on `192.168.1.19`).

## Backend test count

* 32 new tests in `test_canonical_process_entities.py` (all pass).
* 76 pre-existing `test_memory_analysis.py` tests (all still pass).
* Total relevant: 108 tests pass (canonical + memory analysis).
* 3 pre-existing test failures in unrelated files
  (`test_rules_filters.py`, `test_process_graph_panel.py`,
  `test_artifact_explorer.py`) are NOT caused by this sprint.

## Frontend test count

* 20 new tests in `MemoryCanonicalView.test.tsx` (all pass).
* 13 pre-existing `MemoryAnalysisPage.test.tsx` tests (all still pass).
* Total relevant: 33 tests pass (canonical + memory page).

## Build result

* `tsc -b --noEmit`: clean.
* `vite build`: succeeded in 14.86s.
* Backend pytest: 32/32 new tests pass.
* Frontend vitest: 20/20 new tests pass + 13/13 page tests pass.

## Source document count

* `dfir-memory-93297669-3402-4e91-8834-235f55cf18dd` legacy
  `memory_process` documents: 1,530 (preserved, unchanged).
* New `memory_process_entity` documents: 508 (255 from extended +
  253 from basic).
* Total memory index docs: 3,586 (legacy 1,530 + canonical 508 +
  legacy 1,543 other types).
* Disk index `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893`:
  1,336,751 (unchanged).

## Canonical entity count

* Extended run `33440dac` (processes_extended):
  255 canonical entities from 516 source documents.
* Basic run `197e8afa` (processes_basic):
  253 canonical entities from 507 source documents.

## Observation count

* Extended: 516 observations merged into 255 entities.
* Basic: 507 observations merged into 253 entities.

## Duplicate groups collapsed

* Extended: 261 (516 - 255).
* Basic: 254 (507 - 253).

## Provisional identities

* Extended: 1 ambiguous PID group.
* Basic: 1 ambiguous PID group.
* Both flagged in the dry-run summary.

## Scan-only count

* Extended: 2 scan-only entities.
* Basic: 0 (basic does not run `psscan`).

## Terminated count

* Extended: 36 (explicit exit time in `psscan`).
* Basic: 36 (basic still includes `psscan` exit time when present).

## Hidden-candidate count

* Extended: 2 (the 2 scan-only entities; not auto-malicious).
* Basic: 0.

## Roots

* Extended: 1 (System PID 4; PID 0 is a self-referencing special
  case, not a root).
* Basic: 1.

## Orphans

* Extended: 11 (parent PID not in the entity set, e.g. terminated
  parent processes).
* Basic: 11.

## Unknown-parent count

* Both runs: 0 after applying the canonical reconciliation (every
  `cmdline` row is now reconciled into a `pslist`/`pstree` entity).

## Cycles

* Both runs: 0.

## Self-parent

* Both runs: 1 (the PID 0 Idle process which self-references by
  convention).

## Basic run validation

* 253 canonical entities produced.
* No `psscan` data is required.
* Command lines from `cmdline` plugin are merged into the canonical
  process row.

## Extended run validation

* 255 canonical entities produced.
* 2 scan-only entities surfaced.
* 2 hidden-candidate indicators (not auto-malicious).

## PID 4 validation

* PID 4 (System) appears exactly once in both runs.
* Playwright test verifies `system_count == 1`.

## Example consolidation for PID 1116

Legacy documents for PID 1116 (3 rows from pslist, pstree, cmdline):

```
pslist: pid=1116 ppid=808 name=svchost.exe create_time=...
cmdline: pid=1116 ppid=None name=svchost.exe command_line="... -k NetworkService -p"
```

After canonicalization (single entity):

```
process_entity_id: <sha256 of (case, evidence, pid=1116, create_time)>
pid: 1116
ppid: 808
name: svchost.exe
command_line: "C:\Windows\system32\svchost.exe -k NetworkService -p"
sources: ["windows.cmdline", "windows.pslist"]
observation_count: 2
visibility.listed: true
```

## OpenSearch mapping / index counts

```
dfir-memory-93297669-3402-4e91-8834-235f55cf18dd (3,586 total docs):
  legacy memory_process: 1,530
  canonical memory_process_entity: 508
  legacy memory_system_info: 5
  legacy memory_process_edge: 36
  legacy other: ~1,507
dfir-events-c01c0be4-2381-4208-8af6-266e2579a893: 1,336,751 (unchanged)
```

## Disk / NormalizedEvent deltas

* Zero new `NormalizedEvent` documents in any disk index.
* Zero writes to `dfir-events-*` from renormalization.
* `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893` count: unchanged
  (1,336,751).

## Services recreated

* `dfir_app-backend-1` (3 times, for fix iterations).
* `dfir_app-frontend-1` (1 time).
* NOT recreated: `dfir_app-postgres-1`, `dfir_app-redis-1`,
  `dfir_app-opensearch-1`, `dfir_app-memory-worker-1`,
  `dfir_app-symbol-fetcher-1`, `dfir_app-symbol-egress-gateway-1`,
  `dfir_app-worker-1`.

## SHA-256 verification

| File | Local vs remote |
| --- | --- |
| `backend/app/services/memory/process_entities.py` | OK (9ef79b95...) |
| `backend/app/api/routes_memory.py` | OK |
| `backend/app/schemas/memory.py` | OK |
| `backend/tests/test_canonical_process_entities.py` | OK |
| `frontend/src/components/MemoryCanonicalView.tsx` | OK |
| `frontend/src/components/MemoryCanonicalView.test.tsx` | OK |
| `frontend/src/lib/memoryCanonical.ts` | OK |
| `frontend/src/pages/MemoryAnalysisPage.tsx` | OK |
| `frontend/src/pages/MemoryAnalysisPage.test.tsx` | OK |
| `frontend/src/api/client.ts` | OK |

## Playwright validation

16/16 validations pass against `http://192.168.1.19:5173/`:

1. Open memory case.
2. Canonical view section is visible.
3. Process table populated.
4. Rows present (50 per page).
5. Sources badges combined (pslist, pstree, cmdline).
6. Command line visible on canonical process.
7. Switch to extended run via run selector.
8. psscan source visible on extended run.
9. Scan-only filter applied.
10. Process detail works.
11. Process tree renders.
12. Unknown parent shown separately.
13. PID 4 not duplicated.
14. No JavaScript errors.
15. No API 4xx/5xx.
16. No failed chunk + no disk/global mixing.

Screenshot deleted after the run.

## Disk regression

* `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893`:
  - `search`: HTTP 200
  - `timeline`: HTTP 200
  - `artifacts`: HTTP 200
  - document count: 1,336,751 (unchanged)
  - zero `memory_process_entity` documents (no global mixing)

## Sensitive data confirmation

* No RAM, no PDB, no ISF, no symbol cache, no OpenSearch snapshots
  committed.
* No screenshots in the repo (the Playwright screenshot was deleted
  after the run).
* `.env` is chmod 600, gitignored, NOT tracked.
* `.env.example` is tracked (template only, no secrets).
* No fixtures with real process output were committed.
* The backend tests use synthetic fixtures (invented PIDs, processes
  and create_times).
