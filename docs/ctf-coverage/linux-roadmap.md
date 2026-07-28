# Linux CTF Roadmap

This backlog is Linux-only. Windows gaps are tracked separately and intentionally not planned here.

## P0: Blocks A CTF Question

| ID | Item | Why | Done when |
| --- | --- | --- | --- |
| LNX-P0-001 | Import and validate the real `Webserver.E01`/VulnOSv2 evidence | Local tests reference the case, but full real solveability is not proven. | A runtime case imports the image, extracts the Linux root, indexes expected artifacts, and answers every confirmed Webserver question through specialist/Search paths. |
| LNX-P0-002 | Confirm Victoria source material and evidence set | Current repo only confirms `victoria-v8.kcore.img` and auth fixtures, not the full CTF contract. | Public/local source, walkthrough, evidence list, and expected answers are recorded in `coverage.json`. |
| LNX-P0-003 | Add CTF answer-key regression fixtures | Without answer-key tests, coverage can regress silently. | Every confirmed expected answer has a test proving parser/normalizer/Search or specialist visibility. |
| LNX-P0-004 | Support binary systemd journal or prove CTF does not require it | Linux docs mark binary journal parsing unsupported. | Either parser support exists with Search/provenance, or the CTF contract marks no required answers depend on binary journals. |
| LNX-P0-005 | Support deleted ext filesystem recovery or prove CTF does not require it | Disk materialization intentionally skips deleted entries. | Either deleted-file recovery exists with provenance, or the CTF contract marks no required answers depend on deleted files. |
| LNX-P0-006 | Implement Linux memory analysis if Victoria is memory-answer dependent | Linux memory is currently accepted/preserved only. | Process/network/module/file outputs are parsed, normalized, searchable, and validated against Victoria expected answers. |

## P1: Solvable Only With Specialist Knowledge Or Raw Terms

| ID | Item | Why | Done when |
| --- | --- | --- | --- |
| LNX-P1-001 | Add Linux Search field aliases | Analysts should not need internal field names. | Search supports aliases for Linux username, command, source IP, source port, hostname, service, process, package, unit, and source file. |
| LNX-P1-002 | Add Linux persistence overview | Cron/systemd/SSH/sudoers are scattered across Artifact Explorer. | One page summarizes persistence candidates with Search pivots and source provenance. |
| LNX-P1-003 | Add Linux host/identity overview | Host, OS, users, groups, and shells are common CTF questions. | One page answers host/user inventory questions and links to source evidence. |
| LNX-P1-004 | Strengthen Linux audit reconstruction | Multi-line audit events can split command/path semantics. | EXECVE/SYSCALL/PATH records are grouped into coherent events where audit IDs match. |
| LNX-P1-005 | Add Linux network overview | IP/DNS/interface questions are common CTF tasks. | One page summarizes hosts, DNS, interface addresses, gateways, and source files. |

## P2: General Linux DFIR Improvements

| ID | Item | Why |
| --- | --- | --- |
| LNX-P2-001 | Improve package inventory/event separation | Package manager logs and dpkg status answer different questions. |
| LNX-P2-002 | Add parser coverage metrics by CTF question | Keeps product progress tied to actual solveability. |
| LNX-P2-003 | Add Linux detections after primary paths exist | Detections accelerate investigations but cannot be the only answer path. |
| LNX-P2-004 | Add richer Linux timeline labeling | Helps analysts understand low-confidence timestamps. |

## Sprint Plan

Each sprint must finish artifact discovery, parser, normalizer, UI/Search, provenance, and CTF regression.

| Sprint | Scope | Exit criteria |
| --- | --- | --- |
| 1 | Ground truth and imports | Confirm CTF source material, import real evidence locally, create expected-answer rows with `Unknown` replaced where proven. |
| 2 | Webserver disk pipeline | Prove EWF/LVM/ext root extraction, Linux artifact indexing, and source pivots for Webserver/VulnOSv2. |
| 3 | Linux Search hardening | Add field aliases, Linux presets, source pivots, and Search regression tests for confirmed CTF answers. |
| 4 | Linux persistence/identity overviews | Add focused pages for user/host and persistence questions. |
| 5 | Blocker closure | Implement binary journal, deleted ext recovery, or Linux memory analysis only if confirmed CTF questions require them. |

## Implementation Rule

Do not implement a parser or page in isolation. Every change must carry an end-to-end CTF regression:

| Layer | Required proof |
| --- | --- |
| Discovery | Source file is recognized from archive/folder/disk image. |
| Parser | Expected fields are extracted. |
| Normalizer | Fields land in stable event/document schema. |
| Database/index | Rows are persisted and queryable. |
| UI | Specialist or artifact page presents the answer. |
| Search | Global Search can discover the same answer. |
| Provenance | Source file, evidence, host, timestamp/line/record context are visible. |
