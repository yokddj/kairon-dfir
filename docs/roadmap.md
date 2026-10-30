# Roadmap

This roadmap is organized around the product/architecture classification produced by the Kairon architecture review: **Core Platform** and **Core DFIR Capability** (Memory Analysis was a third class, **Core DFIR Capability — Preview**, until 2026-10-25). Items are only listed as completed when the repository supports that claim (code, docs, or both); no completion is inferred beyond what's verifiable.

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
- Linux memory: analysed with Volatility 3 under Memory Analysis (processes, network, open files, kernel modules, suspicious memory, bash history, page-cache files and a Linux Find Evil) once a symbol file for the exact kernel is provided (Volatility 3 ISF or Volatility 2 profile); see `docs/memory/linux_symbols.md`.
- Linux's depth of coverage is not yet at parity with Windows within several supported artifact families.

### Memory Analysis

- **Status**: Stable (2026-10-25). Promoted from Experimental to Preview during the architecture review, and from Preview to Stable by maintainer decision: Memory is part of every Kairon deployment in use, so the Preview exit criteria written for running Kairon without it (a boundary checklist and a "Memory disabled" smoke test) were dropped rather than met.
- **Deployment**: its own Docker Compose profiles (`memory`, `experimental`, `native-probe`, `memory-symbols`) and worker; a single top-level flag (`memory_enabled`) mounts its routers and startup hooks. Running without Memory remains possible but is not a tested configuration.
- **Where its results go**: its own database tables, OpenSearch index and UI views, and case-wide the Timeline (Volatility's dated events and MemProcFS's timelines, the latter as events of the memory evidence in the case's events index), Search, Command History and Persistence; Findings can be created from Find Evil (per indicator or per process), process, network and suspicious-memory rows, and the case report has a Memory Analysis section (per image: system, analyses run, Find Evil triage with the processes marked suspicious or important). Detections and SIEM export do not read the memory index (processes, Find Evil, network); the event log records and Amcache entries MemProcFS recovers are normalized like their disk copies and get Sigma and built-in detections.
- **Not validated yet**: PSReadLine history and PowerShell 4104/4103 records recovered from memory (no available image contains them).

### Rules Engine

- Completed: Detection Rules Engine v2 (Sigma + YARA operationalization), explicit analyst-triggered run model (not an always-on background scan).

## Authentication, roles, and multi-user (corrected)

Distinguishing what exists today from what is planned, since prior wording conflated these:

- **Existing today**: authentication with two roles — Administrator and Standard user. Both can use all investigation features; only Administrators can view/manage other users.
- **Not yet enabled**: per-case user/team access control. Per-case user assignment is explicitly not enabled in the current beta — all users with platform access can currently see all cases.
- **Not designed at all**: true multi-tenant isolation (separate trust/data boundaries per organization sharing one deployment). Per the architecture review's scalability analysis, this would be a major architectural redesign, not a configuration change, and is not currently scoped or planned.

## Reading criteria

- `completed`: usable and functionally validated in the current repository.
- Capabilities are not documented as closed if they exist only in design or in unvalidated branches.
