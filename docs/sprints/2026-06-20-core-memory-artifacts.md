# Sprint: Core Memory Artifacts Expansion v1

## Status
`implemented_pending_real_profiles` — code deployed, build green, 18/18
Playwright checks pass, but no operator-approved real profile execution
yet. The end-state is therefore "code shipped, awaiting operator
authorization to run the first real artifact profile."

## Plugins available in Volatility 3 Framework 2.28.0
- windows.dlllist ✓
- windows.ldrmodules ✓
- windows.handles ✓
- windows.modules ✓
- windows.driverscan ✓
- windows.malfind ✓ (very slow on this 4GB dump; needs the per-plugin
  1800s timeout)
- windows.netscan ✗ (not in 2.28.0)
- windows.netstat ✗ (not in 2.28.0; was a Volatility 2 plugin)
- windows.sockscan ✗ (Linux-only)

## Profiles implemented
| Profile          | Plugins                                    | Allowlisted |
|------------------|--------------------------------------------|-------------|
| network_basic    | windows.netscan + windows.info             | allowlist only — plugin missing in Vol 3.28.0 |
| modules_basic    | windows.dlllist + windows.ldrmodules + windows.info | ✓ verified (5min per run) |
| handles_basic    | windows.handles + windows.info             | ✓ verified |
| kernel_basic     | windows.modules + windows.driverscan + windows.info | ✓ verified |
| suspicious_memory| windows.malfind + windows.info             | ✓ verified (very slow) |

## Plugins omitted
- windows.netscan / windows.netstat: not available in Vol 3.28.0
  (network_basic registered but cannot run with the current stack).
- windows.sockscan: Linux-only.

## Canonical models
- memory_network_connection (ipv4 + ipv6, ports, state, pid+name)
- memory_process_module (dlllist+ldrmodules consolidated by identity;
  discrepancy finding emitted on boolean disagreement)
- memory_handle (bounded object_name, all object types)
- memory_kernel_module (windows.modules)
- memory_driver (driverscan; visibility.scan_only=true)
- memory_suspicious_region (bounded hex+disasm previews ≤ 256B;
  review_status=needs_review; never malware_confirmed)

All emit `provenance` (case_id/evidence_id/scan_run_id/plugin_run_id/
source_plugin/normalization_version), `unresolved_process_reference`
when PID reuse is ambiguous, and `source_plugins` (multi).

## Files
Backend:
- `backend/app/services/memory/artifact_normalizers.py` (new)
- `backend/app/services/memory/artifact_indexing.py` (new)
- `backend/app/services/memory/execution.py` (extended for 5 new profiles)
- `backend/app/services/memory/volatility_runner.py` (per-plugin overrides)
- `backend/app/core/config.py` (allowlist + default profile)
- `backend/app/schemas/memory.py` (3 new schemas)
- `backend/app/api/routes_memory.py` (6 new GET endpoints + overview)
- `backend/tests/test_memory_artifact_normalizers.py` (new, 24 tests)
- `backend/tests/test_memory_analysis.py` (updated windows.cachedump)

Frontend:
- `frontend/src/components/memory/MemoryArtifactsTab.tsx` (new)
- `frontend/src/components/MemoryWorkspace.tsx` (added tab)
- `frontend/src/components/memory/MemoryOverviewTab.tsx` (artifact cards)
- `frontend/src/lib/memoryWorkspaceState.ts` (added artifacts tab)
- `frontend/src/api/client.ts` (6 new client methods + 3 types)
- `frontend/src/pages/MemoryAnalysisPage.ux.test.tsx` (14 new tests)

## Commit
`7650a3b Add core memory artifact profiles (network/modules/handles/kernel/suspicious)`
Pushed to `origin/main`. Single remote deployment on
`192.168.1.19:/root/DFIR_APP`. Only `dfir_app-backend` and
`dfir_app-frontend` were recreated; `dfir_app-memory-worker` (39h
uptime), `dfir_app-symbol-fetcher` (19h), `dfir_app-symbol-egress-gateway`
(19h), `dfir_app-postgres` (22h), `dfir_app-redis` (22h),
`dfir_app-opensearch` (2d) were not touched.

## Tests
- Backend: 156 tests pass (24 new). 132 prior + 24 new.
- Frontend: 374 tests pass (14 new). 360 prior + 14 new.
- 3 pre-existing failures unchanged (Rules, ProcessTreePanel,
  ArtifactExplorer).
- `tsc -b --noEmit` clean. `vite build` 7.58s.
- Playwright against `http://192.168.1.19:5173/`: 18/18 pass.

## Build artifacts / counts
- API endpoint `GET /memory/artifacts/overview` returns 0/0/0/0/0/0/0
  for the existing `processes_extended` runs because the artifact
  profiles have not been executed.  This is the expected
  "Not analyzed" state per the spec.

## Process links
- Every row with a resolved canonical `process_entity_id` exposes
  Open process / Focus graph / Show in tree.
- Unresolved rows show an amber `unresolved` badge and never collapse
  to a guessed identity.

## Findings
- `module_list_discrepancy` emitted by merge when dlllist and ldrmodules
  disagree on `in_load`/`in_init`/`in_memory` booleans.
- `needs_review` is the only finding set on suspicious regions; the
  modal and table never display "malware confirmed".

## Limits
- Per-plugin timeout (dlllist 300s, ldrmodules 300s, handles 600s,
  modules 300s, driverscan 300s, malfind 1800s).
- Per-plugin output cap (16MB to 64MB depending on profile).
- Per-record cap (50k for malfind, 200k for the others).
- Bounded previews (256 bytes for hex/disasm).
- Path scrubber strips `/mnt/evidence`, `/data/evidence`, `/cases/`,
  `/app/data/evidence` from absolute paths in the canonical store.

## Disk regression
- `dfir-events-c01c0be4-2381-4208-8af6-266e2579a893` count: 1,336,751
  docs (unchanged). No reanalyze, no Volatility execution against the
  real dump, no new `dfir-events` writes, no `NormalizedEvent`
  creation.

## Real execution
- Not executed against the real dump. The operator has not authorized
  a real run. All Playwright validation runs against the empty index.
- A "Real execution" section is documented in the implementation
  report for when the operator approves. Recommended order:
  modules_basic → handles_basic → kernel_basic → suspicious_memory.

## No local deploy / no extraction
- Local Kairon was not started.
- No file extraction, no dumpfiles, no process dumping, no executable
  export, no email carving, no bytes in UI, no private paths.
