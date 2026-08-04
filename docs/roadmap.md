# Roadmap

This roadmap is organized around the product/architecture classification produced by the Kairon architecture review: **Core Platform**, **Core DFIR Capability**, and **Core DFIR Capability — Preview**. Items are only listed as completed when the repository supports that claim (code, docs, or both); no completion is inferred beyond what's verifiable.

## Core Platform

Foundational and shared by every capability. Not optional, not capability-specific.

- Case / Evidence / Host substrate — completed. Includes host canonicalization, evidence integrity/custody, and case lifecycle (status, priority, tags, archive/close).
- Artifact and Platform Registries — completed. Single source of truth for supported platforms and artifact families (`backend/app/core/artifact_registry.py`, `evidence_platforms.py`), mirrored on the frontend (`frontend/src/lib/artifactRegistry.ts`, `platformRegistry.ts`).
- Generic ingestion pipeline (discovery → parser dispatch → normalization → indexing) — completed.
- Search / Timeline — completed (Search v2, Timeline v2, Search UI v2, guardrails against noisy/expensive queries).
- Findings / Reports — completed (Investigation Findings, Findings UI, Case Report / Investigation Narrative export, real PDF output).

No open items are tracked here directly.

## Core DFIR Capabilities

Expected, standard capabilities of a serious DFIR platform. Installed by default; consume the Core Platform, do not shape it.

### Windows

- Completed: core Windows parsers, MFT/Filesystem Timeline, Registry Persistence/Autoruns, Process Tree/Execution Graph, Email Artifacts v1, User Activity Registry Artifacts v1, NTFS Deep Artifacts v1, Windows UI/Local DB Artifacts v1, Defender.
- Completed: disk image ingestion (RAW `.dd/.img/.raw`, EWF `.E01/.Ex01`, VMDK, VHD/VHDX, QCOW/QCOW2, VDI) with partition discovery, volume inspection, and OS detection, reusing the existing Windows/Linux pipelines. Confirmed by `docs/evidence/disk-image-ingestion.md` and the repository's `disk_images` module.

### Linux

- Completed (partial coverage): auth logs, syslog/messages, shell history, cron, systemd units, SSH artifacts, passwd/group/shadow presence, sudoers, package manager logs, network configuration, OS release/hostname/kernel/users.
- Not yet available: full advanced Linux memory analysis (Linux memory uploads are accepted and preserved for host assignment/findings only). Linux's depth of coverage is not yet at parity with Windows within several supported artifact families.

### Rules Engine

- Completed: Detection Rules Engine v2 (Sigma + YARA operationalization), explicit analyst-triggered run model (not an always-on background scan).

## Core DFIR Capability — Preview

### Memory Analysis

- **Status**: Preview. Deliberately promoted from Experimental Capability during the architecture review; not yet Stable.
- **Deployment**: optional — its own Docker Compose profiles (`memory`, `experimental`, `native-probe`, `memory-symbols`) allow a deployment to run without it.
- **Activation**: a single top-level flag (`memory_enabled`) is the sole authority for mounting Memory's routers and startup hooks; a small number of concrete backend dependency-direction violations remain, tracked in `docs/architecture/optional-capability-boundary.md`.
- **Isolation today**: its own worker process and queue, its own database tables, its own OpenSearch index, its own UI surface (dedicated components, lazy-loaded routes) — already correctly separated from global Search/Timeline/Detections/Findings/Reports/SIEM.
- **Not yet isolated**: an open, separately-investigated question about whether its ORM relationships to `Evidence` represent legitimate ownership metadata or a functional dependency.
- **Preview → Stable exit criteria** (explicit, evaluated against evidence — not against continued investment):
  1. Passes the Optional Capability Boundary verification checklist (`docs/architecture/optional-capability-boundary.md`, §13).
  2. Backend boots and serves the full core investigation loop with Memory disabled, verified by an automated smoke test.
  3. Frontend navigation/routes reflect backend-exposed capability state rather than always rendering Memory as present.
  4. Volatility metadata/process-profile coverage and correctness bar agreed separately as a Memory-specific quality gate (out of scope for this architecture document).

## Authentication, roles, and multi-user (corrected)

Distinguishing what exists today from what is planned, since prior wording conflated these:

- **Existing today**: authentication with two roles — Administrator and Standard user. Both can use all investigation features; only Administrators can view/manage other users.
- **Not yet enabled**: per-case user/team access control. Per-case user assignment is explicitly not enabled in the current beta — all users with platform access can currently see all cases.
- **Not designed at all**: true multi-tenant isolation (separate trust/data boundaries per organization sharing one deployment). Per the architecture review's scalability analysis, this would be a major architectural redesign, not a configuration change, and is not currently scoped or planned.

## Reading criteria

- `completed`: usable and functionally validated in the current repository.
- `preview`: operational under an explicit optional/activation model, with defined, evidence-based promotion criteria to Stable.
- Capabilities are not documented as closed if they exist only in design or in unvalidated branches.
