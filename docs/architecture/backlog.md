# Implementation Backlog — Architecture Review Follow-up

Derived from the Kairon architecture review and `docs/architecture/optional-capability-boundary.md`. Every item below is independently verifiable and scoped to avoid overlap with the others. Most of this document is still planning output only; the P0 item below is the one exception, and its status line says exactly how far it got.

Priorities: **P0** — Immediate, **P1** — High, **P2** — Medium. (No P3/long-term item is opened here; the one long-term item identified by the review — a storage-path abstraction for distributed/remote workers — is intentionally not opened until the scalability ceiling decision below is made, since building it speculatively is out of scope.)

---

## P0 — Memory activation boundary

**Status**: Mostly done. A single `memory_enabled` flag (`backend/app/core/config.py`) now gates both router mounting and startup reconciliation hooks in `backend/app/main.py`, and an automated boot smoke test (`backend/tests/test_memory_activation_boundary.py`) proves the Core Platform is unaffected either way. The one item below still not done is `core/storage.py`'s unconditional import of `services.memory.*`.

**Goal**: make Memory's activation genuinely optional at the process level.

**Scope**:
- Introduce or consolidate one top-level `memory_enabled` authority (single settings flag; existing narrower flags may remain underneath it but must not act as independent master switches). **Done.**
- Conditionally import and mount Memory's routers (`routes_memory`, `routes_memory_experimental`, `routes_memory_recovery`) only when the flag is enabled. **Done** — see `_configure_memory_capability` in `backend/app/main.py`.
- Skip Memory's startup reconciliation hooks (batch reconciliation, symbol readiness backfill/reconciliation, upload lifecycle reconciliation, upload session cleanup) when the flag is disabled. **Done.**
- Verify, with an automated boot smoke test, that the backend starts and fully serves the core investigation loop (Case/Evidence/Host, ingestion, Search/Timeline, Findings/Reports) with Memory disabled. **Done** — `backend/tests/test_memory_activation_boundary.py`.

**Explicitly out of scope for this item**:
- No ORM/schema changes (see the separate Evidence/Memory ORM investigation below).
- `core/opensearch.py` is not touched here (see the separate Core OpenSearch item below) — its imports are a general core-purity concern, unrelated to Memory's minimum activation boundary.
- `core/storage.py`'s import of `services.memory.*` is in scope for this item, since it directly blocks activation-level optionality. **Not done** — `core/storage.py` still imports `app.services.memory.upload_capacity` and `app.services.memory.evidence_access` unconditionally at module level.

**Definition of done**: checklist items 1, 2, and 5 of the Optional Capability Boundary verification checklist (§13) pass. Items 1, 2, and 5 pass; item 3 (no `core/` file imports the capability's package) does not yet, because of the `core/storage.py` import above.

---

## Investigation — Evidence/Memory ORM boundary

**Type**: investigation only. No production changes.

**Determine**:
- Every relationship between `Evidence` and Memory models (`MemoryScanRun`, `MemoryArtifactSummary`, and any others discovered).
- Every consumer of each relationship (which code paths actually navigate it, vs. relationships that are declared but unused).
- Cascade and deletion behavior implied by each relationship, and whether that behavior is relied upon anywhere in the core evidence-deletion path.
- Whether any of these relationships are required at import time for `Evidence` (or other core models) to load successfully.
- Schema and migration consequences of any change, should one later be justified.
- Whether each relationship represents legitimate ownership/navigation metadata (acceptable under the refined database rule in the RFC, §11) or an actual functional dependency of the Core Platform on Memory (not acceptable).

**Output**: a short findings note (not a code change) stating, per relationship, which category it falls into, and — only where a functional dependency is found — a proposed, separately-scoped remediation. No remediation should be treated as decided until this investigation produces its findings.

**Depends on**: nothing; can run independently of the P0 item above.

---

## P1 — Frontend capability state

**Goal**: make the frontend aware of backend capability state instead of hardcoding Memory as always-present.

**Scope**:
- Expose active capability state from the backend (a minimal read — e.g., whether Memory is enabled — consumable by the frontend at load time).
- Hide the Memory navigation section when the capability is disabled.
- Prevent or redirect Memory routes when the capability is disabled (rather than serving a broken or misleading screen).
- Preserve the existing lazy-loading behavior for Memory's pages — this item changes *when/whether* the routes are reachable, not how they're bundled.

**Explicitly out of scope**: no reorganization of `frontend/src/features/`, `components/`, or `api/client.ts`. This item is about gating existing structure, not restructuring it.

**Depends on**: the backend exposing a stable capability-state signal (naturally follows from the P0 item, though the exact transport is an implementation decision for that PR, not this document).

---

## P1 — Memory package perimeter

**Goal**: make `services/memory/` the actual, complete perimeter of Memory's backend logic.

**Scope**:
- Investigate `services/investigation_memory.py` and `services/evidence_memory_workflow.py`: confirm both depend on Memory internals and sit outside the `services/memory/` subpackage.
- If justified (expected, given the investigation above), relocate them under `services/memory/` (or an explicitly named integration seam within it).

**Explicitly out of scope**: this is kept separate from the P0 activation work — relocating files is a package-boundary concern, not an activation-flag concern, and the two should not be bundled into one PR.

---

## P1 — Linux parity program

**Goal**: define, not yet execute, a multi-stage plan to close the gap between Linux's Core DFIR Capability classification and its current coverage depth.

**Scope**:
- Enumerate currently-supported Linux artifact families vs. currently-missing ones, using the existing Artifact Registry as the source of truth (this is largely a registration/parser-authoring exercise, not new plumbing, given the registry pattern already in place).
- Prioritize by forensic investigative value, not by matching Windows' artifact count 1:1 — some Windows-only families (e.g. Shellbags-equivalent concepts) may have no direct Linux analogue, and some Linux-native artifact classes may have no Windows equivalent at all.
- Produce a staged plan (which families first, and why) as a separate planning output, not as code in this backlog entry.

**Depends on**: nothing technically; this is a prioritization exercise that can start immediately, independent of the Memory-related items above.

---

## Separate architectural item — Core OpenSearch dependencies

**Goal**: resolve `core/opensearch.py`'s imports from `app.ingest.fingerprints` and `app.services.host_identity`.

**Type**: investigation, then — only if justified — a scoped, separate change.

**Scope**:
- Determine why `core/opensearch.py` (a Core Platform file) currently imports capability/service-layer code for event fingerprinting and host-identity application during indexing.
- Assess whether this reflects a missing seam in the Core Platform (e.g., fingerprinting/host-identity logic that conceptually belongs in `core/` and was placed in `ingest`/`services` instead) or a genuine capability dependency that needs inversion.

**Explicitly independent of Memory optionality**: this concern predates and is unrelated to the Memory work above; it must not be bundled into the Memory activation PR, and Memory's Preview→Stable criteria do not depend on it being resolved.

---

## P2 — Scalability ceiling policy

**Goal**: document, not implement, Kairon's current and future scaling posture.

**Scope**:
- Document the conditions under which Kairon is expected to remain: single-node; vertical-scale only; local-filesystem evidence storage.
- Document the concrete triggers that would justify moving beyond that posture:
  - OpenSearch clustering (e.g., evidence/event volume approaching single-node heap or disk limits for a target case size).
  - Shared or object-based evidence storage (e.g., a decision to support workers on more than one host).
  - Remote workers (dependent on the above — remote workers cannot read evidence under the current local-bind-mount model).
  - Multi-node operation more generally.

**Output**: a decision document, not a project. Implementation of any of the above (clustering, storage abstraction, remote workers) is explicitly out of scope until this policy is written and a trigger is actually met or a product decision is made to pursue one ahead of a trigger.

---

## Summary table

| Item | Priority | Type | Touches ORM/schema? | Touches `core/opensearch.py`? |
|---|---|---|---|---|
| Memory activation boundary | P0 | Implementation | No | No |
| Evidence/Memory ORM boundary | Investigation | Investigation only | Investigates, does not change | No |
| Frontend capability state | P1 | Implementation | No | No |
| Memory package perimeter | P1 | Investigation → implementation if justified | No | No |
| Linux parity program | P1 | Planning | No | No |
| Core OpenSearch dependencies | Separate | Investigation → implementation if justified | No | Yes (its whole subject) |
| Scalability ceiling policy | P2 | Documentation/decision | No | No |
