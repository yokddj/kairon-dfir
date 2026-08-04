# RFC/ADR — Optional Capability Boundary

- **Status**: Accepted
- **Origin**: Kairon architecture review (Core Platform / Core DFIR Capability classification), covering backend and frontend organization, scalability, and roadmap alignment.
- **Applies to**: Memory Analysis (Core DFIR Capability — Preview) today; any future optional capability (including AI) from its first commit.

## 1. Purpose

Kairon is not becoming a generic plugin platform. Optional capabilities remain part of the repository and the normal release process — they are built, tested, and shipped together with everything else. What must be true is narrower and more mechanical: **the core investigation loop (Evidence → Normalized Artifact → Correlated Timeline/Search → Analyst Finding → Report) must start, run, and be fully usable with an optional capability disabled**, without special handling, without errors standing in for absence, and without the rest of the platform needing to know why it's disabled.

This document defines what "optional" has to mean technically for that to hold, using only mechanisms already present in Kairon's architecture: settings flags, conditional imports, existing worker/queue separation, and existing Docker Compose profiles. No plugin framework, dependency-injection container, or microservice split is introduced or implied.

## 2. Definition of an optional capability in Kairon

A capability is optional if all of the following hold:

- It ships in the same repository and release as everything else.
- Its activation is controlled by exactly one flag.
- Its absence (flag disabled) does not change the behavior, availability, or startup success of the Core Platform or of any other Core DFIR Capability.
- Its own workers, queues, and specialized infrastructure are owned entirely by it.
- Its code lives inside its own package perimeter, not scattered across shared modules.

Being "optional" is a statement about the *dependency direction* between the capability and the rest of the platform — not about deployment topology, packaging format, or how much internal complexity the capability is allowed to have.

## 3. Allowed dependency direction

```
Core Platform
    ↓
Capability contracts / registries
    ↓
Windows · Linux · Rules Engine · Memory (Preview) · future capabilities
```

Capabilities may depend on the Core Platform (its registries, its database primitives, its session/config layer). The Core Platform must never depend on a specific capability. This direction is not new — it is the same rule established for Windows and Linux via the Artifact/Platform Registry, extended explicitly to optional capabilities.

## 4. Layers that may know a capability exists

- **Settings/config** — owns the single activation flag (§6).
- **The Artifact/Platform Registry** — may hold declarative metadata a capability contributes (artifact families, UI-facing flags), as data, not behavior.
- **The composition point** (§7) — the one place allowed to conditionally wire a capability's routers and startup hooks.
- **The capability's own worker entrypoint and Docker Compose profile.**
- **The frontend's capability-state consumer** (e.g. navigation, route guards) — may read capability state exposed by the backend; it does not decide it.

## 5. Layers that must remain capability-agnostic

- **`core/`** — no exceptions. No file under `core/` may import a capability's package, regardless of whether the capability is enabled.
- **Base/core database models** (`Evidence`, `Case`, `CaseHost`, ...) — see §11 for the refined relationship rule; in no case may a core model require a capability's module to be importable or initialized in order to function.
- **Generic/shared services** — any service consumed by more than one capability or by the core loop itself (search, timeline, host identity, evidence integrity) must not import a specific capability's internals.
- **Core workers** — the workers serving the core ingestion/rules/analysis queues must never import a capability-specific task module.

## 6. Single activation flag

Each optional capability is governed by exactly one settings flag (e.g. `memory_enabled`). Finer-grained, behavior-level flags may exist underneath it (e.g. an upload-specific toggle), but they are not substitutes for the master flag, and none of them may independently mount routes or run startup hooks — the master flag is the only authority on whether the capability is active at all.

## 7. Guarded composition point

Exactly one place in the backend (the application composition step — today, `main.py`) is allowed to import a capability's routers and startup/reconciliation hooks, and it does so only inside a branch keyed to the capability's flag, using a local (lazy) import at that point — never a top-level, unconditional import. When the flag is disabled, the capability's modules are not imported into the process at all through this path.

## 8. Worker and queue ownership

A capability that needs background execution owns its own worker entrypoint and its own named queue, entirely separate from the core queues (`dfir-ingest`, `dfir-rules`, `dfir-analysis`). Core workers must never import or dispatch a capability's task modules. This is not a new rule to introduce — it is already how Memory's worker is built, and it is the pattern every future capability should copy without modification.

## 9. Deployment-profile behavior

If a capability has its own Docker Compose profile(s), the backend process must be able to run with that profile absent — the process should behave as if the capability is inactive, not as if it is present-but-erroring. Deployment-level optionality (which container/profile is running) and code-level optionality (whether the flag is enabled) must agree: a deployment that never starts a capability's worker/profile should also be a deployment where that capability's flag is disabled, and vice versa should not be required to work around missing infrastructure.

## 10. Package perimeter

All of a capability's backend logic lives under its own subpackage/module family: `services/<capability>/`, clearly-named `api/routes_<capability>*.py`, `models/<capability>.py`. No file outside that perimeter may hold capability-specific logic, however convenient it seemed at the time it was written. On the frontend, the equivalent is a dedicated component/page namespace (as already exists for Memory) — this document does not change that pattern, only names it as the standard for future capabilities.

## 11. Database relationship policy (refined)

**Core models must not require capability models or capability-specific behavior in order to function.**

Referential ORM relationships between a core model and a capability model are **not automatically forbidden**. They are acceptable when they express legitimate ownership or navigation (e.g., "this evidence has related memory scan runs") **and** they do not make the Core Platform dependent on the capability's initialization, imports, cleanup logic, or availability. A relationship that only affects what a query can navigate to, and that behaves safely (no error, no missing functionality) when the capability is disabled, is acceptable. A relationship that is required for the core model to import, that drives cascade/delete behavior the Core Platform relies on, or that would break core functionality if the capability's module were unavailable, is not.

Whether any specific existing relationship (e.g., `Evidence` → Memory models) satisfies this test is a factual question, not a policy question, and is intentionally **not answered by this document**. It requires its own investigation into actual consumers, cascade behavior, deletion semantics, and import-time requirements — tracked separately as a dedicated investigation. This RFC defines the test; it does not pre-judge the result.

## 12. Public integration surface

Where a capability legitimately needs to react to a Core Platform event (for example, cleanup when an evidence record is deleted), the preferred shape is one of:

- The capability manages its own consistency independently (e.g., a reconciliation pass that notices and cleans up orphaned rows on its own schedule), requiring no hook from core at all; or
- The Core Platform calls into a capability through the same kind of declarative registration already used for the Artifact/Platform Registry, rather than importing the capability's internals directly.

What is not acceptable is the Core Platform importing a capability's implementation module to satisfy this need, which is the pattern this document is written to prevent. This section states the direction to design toward; it does not mandate a specific mechanism or schema, and no implementation is proposed here.

## 13. Verification checklist

A capability qualifies as "optional" under this policy when all of the following are true:

- [ ] A single settings flag controls activation; no secondary flag acts as a de facto master switch.
- [ ] The backend process starts and fully serves the core investigation loop (Case/Evidence/Host, ingestion, registries, Search/Timeline) with the flag disabled, verified by a boot smoke test.
- [ ] No file under `core/` imports the capability's package.
- [ ] No generic/shared service (outside the capability's own subpackage) imports the capability's internals.
- [ ] Router mounting and startup/reconciliation hooks for the capability occur only inside the guarded composition point, via local imports.
- [ ] The capability's background work runs on its own worker entrypoint and its own named queue; no core worker imports its task modules.
- [ ] The capability's Docker Compose profile(s) can be absent from a deployment without breaking the core backend.
- [ ] All of the capability's backend code lives under its own package perimeter (§10) — no stray files outside it.
- [ ] Any ORM relationship between a core model and the capability's models has been evaluated against §11 and is either compliant or tracked as a known, investigated exception.
- [ ] The frontend reflects backend-exposed capability state (navigation, routing) rather than hardcoding the capability as always-present.

## 14. Example — Memory Analysis today

Applying the checklist to Memory as it stands today (per the architecture review):

| Checklist item | Status |
|---|---|
| Single activation flag | **Done** — `settings.memory_enabled` (`backend/app/core/config.py`) is the sole master flag; narrower behavioral flags (`memory_analysis_enabled`, `memory_allow_external_tool_execution`, ...) sit underneath it and do not act as independent master switches. |
| Backend starts core loop with capability disabled | **Done** — routers and every startup reconciliation call are now conditional on `memory_enabled` in `main.py`, verified by an automated boot smoke test (`backend/tests/test_memory_activation_boundary.py`). |
| No `core/` import of the capability | Partially — `core/storage.py` imports `services.memory.*` directly. (`core/opensearch.py`'s unrelated imports from `ingest.fingerprints`/`services.host_identity` are a separate, general core-purity concern, not part of this boundary.) |
| No generic/shared service imports the capability | Partially — two files (`services/investigation_memory.py`, `services/evidence_memory_workflow.py`) sit outside `services/memory/` while depending on its internals. |
| Guarded composition point | **Done** — router and startup-hook imports are local imports inside `_configure_memory_capability`/the `memory_enabled` branches in `main.py`, not top-level unconditional imports. |
| Worker/queue ownership | **Already satisfied** — Memory's worker runs as its own process on its own named queue, separate from the core queues. |
| Deployment-profile behavior | **Already satisfied** — Memory, its native-probe worker, and its symbol infrastructure each have their own Compose profile. |
| Package perimeter | Mostly satisfied, with the two exceptions noted above. |
| Database relationship policy | Open — `Evidence` carries `relationship()` fields into Memory models; whether this is legitimate ownership metadata or a functional dependency is exactly the open question §11 defers to a dedicated investigation. |
| Frontend reflects backend capability state | Not yet — Memory's navigation and routes render unconditionally regardless of backend state, though they are already correctly code-split via lazy loading. |

Memory already gets the *runtime infrastructure* half of this policy right (workers, queues, deployment profiles), and the activation boundary itself (flag, composition point, boot-disabled smoke test) now also passes. What remains is the narrower *import-boundary* half — `core/storage.py`'s import, the two service files outside `services/memory/`, the ORM question, and the frontend capability-state consumer — a bounded, well-understood set of changes, not a redesign.

## 15. Applicability to future AI work

Any future AI capability must satisfy this checklist from its first commit, not retrofit it later:

- Its own settings flag, its own package perimeter, its own worker/queue if it needs background execution.
- No Core Platform or generic-service file may import it.
- No core model may declare a relationship into it without first passing the §11 test.
- If it needs a heavy runtime (e.g. local inference, GPU access), that runtime is isolated the same way Memory's symbol infrastructure is isolated — as the optional capability's own responsibility, never a Core Platform dependency.

The cost of building a capability against this checklist from the start is a small fraction of the cost of unwinding violations after the fact, which is precisely the situation this document exists to close out for Memory.
