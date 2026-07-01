# Memory Process Model

This document describes the canonical entity/observation model used by
the Memory Analysis subsystem to represent processes extracted from a
Volatility 3 memory image.

## Why a canonical model is necessary

A single memory image produces multiple process "rows" per real
process:

* `windows.pslist` enumerates the active process list.
* `windows.psscan` scans for `_EPROCESS` structures in kernel memory.
* `windows.pstree` produces a parent/child tree.
* `windows.cmdline` produces command-line strings.

Windows recycles PIDs and the same process can appear in different
plugin outputs with different field sets.  Treating each plugin-row
as a distinct process leads to:

* duplicated rows in the process table;
* lost context (a `cmdline` row with no PPID becomes a phantom root);
* over-counted processes (a single process seen by `pslist` and
  `psscan` looks like two);
* a process tree that misclassifies every `cmdline`-only row as a
  root.

The canonical model collapses observations into a single entity per
real process and keeps the per-plugin rows as observations for full
provenance.

## Entities and observations

### `MemoryProcessEntity`

A canonical process.  One row in the UI.

Fields:

* `process_entity_id` — SHA-256 of `(case_id, evidence_id, pid, create_time)`.
* `case_id`, `evidence_id`, `scan_run_id` — provenance.
* `process.pid`, `process.ppid`, `process.name`, `process.executable_name`,
  `process.command_line`, `process.create_time`, `process.exit_time`,
  `process.session_id`, `process.wow64`.
* `visibility.listed`, `visibility.scan_only`, `visibility.terminated`,
  `visibility.unknown`, `visibility.hidden_candidate`.
* `sources` — ordered, unique list of contributing plugins.
* `observation_count` — number of observations merged into the entity.
* `observation_summary.has_pslist` / `has_psscan` / `has_pstree` /
  `has_cmdline`.
* `confidence` — `high` / `medium` / `low`.
* `findings` — analyst flags (`scan_only`, `hidden_candidate`,
  `terminated`, `missing_parent_in_pslist_or_pstree`, `name_conflict`,
  `command_line_missing`, `identity_provisional`).
* `tree.is_root` / `is_orphan` / `is_unknown_parent` / `is_cycle` /
  `is_self_parent` / `is_pid_zero`.
* `parent_entity_id`, `child_count`.
* `normalization_version` — `memory_process_canonical_v1`.
* `materialized_from_run_id` — the run the entity was first written
  for.

### `MemoryProcessObservation`

A per-plugin row.  Multiple observations can belong to the same
entity.  The observation is preserved for full provenance and analyst
detail (alternate command lines, raw source fields).

Fields:

* `observation_id` — SHA-256 of the legacy source document.
* `case_id`, `evidence_id`, `scan_run_id`, `process_entity_id`.
* `plugin_run_id`, `plugin_name`, `source_record_id`.
* `observed.pid`, `observed.ppid`, `observed.name`,
  `observed.command_line`, `observed.create_time`, `observed.exit_time`.
* `raw_status`, `confidence`, `indexed_at`.

### `MemoryProcessEdge`

A parent/child relationship between canonical entities.  Edges are
materialized by the renormalization step; the source plugin is
`windows.pstree` if available, else `windows.pslist`.

## Identity

The entity identity is computed deterministically and idempotently:

1. **Strong identity**:
   `(case_id, evidence_id, pid, create_time)`.  Two observations
   that share all four values always belong to the same entity.  This
   is the preferred identity.
2. **Name identity**:
   `(case_id, evidence_id, pid, process_name)`.  Used as a fallback
   when `create_time` is missing.  A name-only observation that
   matches a strong identity is reconciled into the strong entity.
   Two name-only observations with the same PID and the same name
   share an entity.
3. **Weak identity** (PID only): never used as a final identity.
   `pslist`/`psscan`/`pstree`/`cmdline` always provide at least a
   `name`.  If a row is missing both `create_time` and `name`, the
   entity is marked `identity_provisional` with `confidence=low`.

The reconciliation algorithm never merges two different PIDs and never
merges two observations with conflicting `create_time`s.

## Merge precedence

| Field | Priority (highest first) | Notes |
| --- | --- | --- |
| `name` | `pslist` > `psscan` > `pstree` > `cmdline` basename > `unknown` | Conflicts retained as `name_conflict` finding. |
| `ppid` | `pstree` > `pslist` > `psscan` > other | A present value is never replaced by `null`. |
| `create_time` | `pslist` > `psscan` > `pstree` > other | A present value is never replaced by `null`. |
| `exit_time` | `psscan` > `pslist` > `pstree` > other | Required for `terminated` classification. |
| `command_line` | `cmdline` (preferred) | All variants preserved as observations; the preferred value is the first. |
| `executable_name` | first non-empty name across plugins, else first command-line token | Used for the UI when `name` is empty. |

## Visibility classification

* `listed` — observed in `pslist` (may also be in `psscan`).
* `scan_only` — observed in `psscan` only.
* `terminated` — only when an explicit `exit_time` is recorded.
* `unknown` — insufficient data (no plugin contributed a useful name
  or create_time).
* `hidden_candidate` — `psscan` present, `pslist` absent, no explicit
  exit time.  This is **an analyst indicator, not a detection**.
  Memory Analysis surfaces it for review.

## Tree semantics

* `root` — PPID == 0 and PPID is well known.  PID 0 is special-cased
  only to deduplicate, never to be hidden or treated as a magic root.
* `orphan` — PPID points to a PID that does not exist as an entity.
* `unknown_parent` — PPID is `null`.  This is **not** a root.
* `cycle` — following the parent chain returns to the starting node.
* `self_parent` — `pid == ppid`.  Flagged but the entity is not
  dropped.
* PID 4 (System) deduplicates automatically: every observation with
  the same PID and `create_time` joins the same entity.

## Basic vs Extended runs

* `processes_basic` produces entities from `pslist` + `pstree` +
  `cmdline`. Provides process topology, identities, and command lines.
  A basic run can run without symbols.
* `processes_extended` runs `psscan` + `envars` + `getsids` + `privileges`.
  Provides enrichment: scan-only detection, environment variables,
  security identifiers, and privilege tokens. Does **not** create a
  second process list — it enriches the same model.
* `windows.info` runs as part of both profiles and provides system-layer
  metadata (kernel version, DTB, etc.).
* `network_basic`, `modules_basic`, `handles_basic`, `kernel_basic`,
  and `suspicious_memory` run as separate profiles and provide
  independent artifact families.

### Federated process context

Since `processes_basic` and `processes_extended` are separate profiles,
a federated process context automatically merges observations from both
runs into one coherent workspace:

```text
latest completed processes_basic
+ latest completed processes_extended
= one federated process context
```

The federation service (`app.services.memory.process_federation`)
resolves the best compatible basic and extended runs for one Evidence
and returns:

* `basic_run_id` — the basic run providing topology (pstree), identity
  (pslist), and command lines (cmdline).
* `extended_run_id` — the extended run providing enrichment (psscan,
  envars, getsids, privileges).
* `contributing_runs` — both run IDs with metadata.
* `compatibility` — `both_successful`, `basic_only`, `extended_only`,
  or `unavailable`.

The merge uses PID as the primary identity key. Entities from basic
and extended runs with the same PID are merged with basic precedence
for identity fields (name, PPID, create_time) and extended enrichment
for visibility (scan_only, hidden_candidate).

### Automatic mode

In the UI, the default process context mode is **Automatic**.  The
analyst does not need to know whether a specific observation comes from
`processes_basic` or `processes_extended`.

The automatic context feeds:
* Processes table
* Embedded process graph
* Top-level Graph
* Indented tree
* Command Line History
* ProcessDetailModal

## Run selection

The Memory Analysis UI defaults to **Automatic** process context.
The legacy single-run selector is available under **Advanced** mode
for historical or single-profile inspection.

In Automatic mode:
* Process topology comes from `processes_basic` (windows.pstree).
* Command lines come from `processes_basic` (windows.cmdline).
* Visibility enrichment comes from `processes_extended` (windows.psscan).
* Extended observations (envars, SIDs, privileges) are available in
  the ProcessDetailModal.
* Results from different Evidences are never mixed.
* If both profiles completed, the federation auto-selects both.
* If only one completed, the available data is shown with a note
  about the missing profile.

### PID reuse in federation

Within the federated context, PID reuse is handled by merging entities
with the same PID from basic and extended runs. If two genuinely
different process incarnations share the same PID, the federation
preserves the basic-run entity and notes the discrepancy. Full
disambiguation (by creation time) remains available in historical
single-run inspection.

## Why Memory Analysis does not auto-create NormalizedEvents

Memory Analysis remains the *technical* view of memory evidence.  The
canonical model preserves per-plugin provenance and special-cases
memory-specific signals (PID reuse, `hidden_candidate`, exit-time
semantics) that have no direct equivalent in the disk-event model.

A future sprint will provide a Search Federation layer that joins
canonical memory entities with disk events (`EVTX 4688`, Sysmon
Event 1, Prefetch, Amcache, UserAssist) and *then* materializes
correlated `NormalizedEvent` rows.  This is intentionally outside
the scope of the current sprint.

## Future Architecture

### Future search federation

* The Memory Analysis backend will keep the canonical entity in
  `dfir-memory-{case_id}`.
* A federation endpoint (next sprint) will:
  1. Resolve `process_entity_id` -> process identity
     (PID, create_time, host_id).
  2. Build a time-windowed query against `dfir-events-{case_id}` for
     matching `process.entity_id` / `process.pid + process.create_time`.
  3. Return merged hits with provenance.

### Future Artifact Views

* The `memory_process_entity` document type already contains the
  fields required by the future Artifact Views pipeline:
  `host_id`, `entity_type`, `entity_key`, `process_identity`,
  `executable_name`, `command_line`, `parent_process_identity`.
* A separate migration sprint will teach the Artifact Views
  subsystem to consume memory entities without changing the disk
  artifact shape.

### Future correlation

The entity schema includes placeholder fields for the future
correlation pass:

* `entity_type: "process"`
* `entity_key` (deterministic, run-independent)
* `process_identity` (case + evidence + identity tuple)
* `source_kind: "memory"`
* `source_plugins`
* `first_seen` / `last_seen`
* `executable_name`
* `command_line`
* `parent_process_identity`

The correlation logic itself is **not** implemented in this sprint.

## Acceptance criteria recap

* processes_basic displays processes correctly.
* Basic does not depend on psscan.
* Extended enriches the same logical model.
* One process is one row.
* Plugin results are observations, not duplicate processes.
* PID reuse is handled.
* Command lines merge correctly.
* PPID values are not lost.
* Process tree uses canonical entities.
* Unknown parent is not counted as root.
* PID 4 is not duplicated.
* Scan-only is visible but not automatically malicious.
* Run selection is explicit.
* Results from different runs are not silently mixed.
* Existing source documents remain preserved (renormalization is
  idempotent and additive).
* No Volatility rerun required for migration.
* No disk index writes.
* No NormalizedEvent creation.
* Browser validation passes against `http://192.168.1.19:5173/`.
* Disk regression passes (no writes to `dfir-events-*`).
* No sensitive artifacts committed.
