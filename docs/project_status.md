# Project Status

## Current status

Kairon DFIR is a case-centric DFIR platform for Windows, Linux, disk-image and
memory evidence, at version 1.1.0 with further work under `Unreleased` in the
[CHANGELOG](../CHANGELOG.md). It is a self-hosted beta for trusted labs.

[roadmap.md](roadmap.md) is the source of truth for maturity; this page is a
short summary. For per-feature status see [feature_map.md](feature_map.md), for
per-parser status [artifacts/parser-coverage.md](artifacts/parser-coverage.md).

## Stable

- Evidence intake: guided wizard with preflight, resumable uploads, folders,
  server paths, SHA-256 integrity, custody events and duplicate detection.
- Read-only disk images: RAW, EWF, VMDK, VHD/VHDX, QCOW/QCOW2, VDI.
- Windows artifacts: EVTX (Sysmon, Security 4688/4663, PowerShell, Defender),
  MFT/USN, registry persistence and user activity, Prefetch, LNK, Jump Lists,
  Amcache, Shimcache, browsers, scheduled tasks, SAM local accounts and more.
- Linux artifacts: authentication and system logs, systemd journal, audit, web
  servers, databases, mail, VPN, firewalls, containers and Kubernetes, shell and
  application histories, packages (apt, dnf/yum, rpm, zypper, pacman, apk),
  cloud-init, persistence and OS identity. See
  [linux/linux-support.md](linux/linux-support.md).
- Memory Analysis (Stable since 2026-10-25): Volatility 3 and MemProcFS for
  Windows, Volatility 3 for Linux with a matching symbol file, Find Evil, process
  graph, shell history; results reach Timeline, Search, Command History,
  Persistence, Findings and the report.
- Host canonicalization, Host Facts and Local Accounts.
- Search, Timeline, Artifact Views, Source Tables, Command History, Execution
  Story, Linux Authentication, Investigation Guide.
- Sigma and YARA detections (analyst-triggered), built-in heuristics,
  correlation findings.
- Event markings, findings, Incident Timeline, reports in Markdown and PDF.

## Optional

- AI assistant scoped to the open case, read-only, off until an administrator
  configures a provider ([operations/ai-assistant.md](operations/ai-assistant.md)).
- Memory plugin execution and Windows symbol downloads are opt-in per
  deployment ([memory/memory_operations.md](memory/memory_operations.md)).

## Not available

- Raw SRUM (`SRUDB.dat`) and raw Shellbags hive parsing; their EZ Tools CSV
  output is supported.
- Outlook OST/PST parsing.
- Per-case access control and multi-tenant isolation.
- A Windows parser worker for Windows-only tools.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
