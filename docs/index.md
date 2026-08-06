# Kairon DFIR Documentation

This documentation describes the real state of the platform. Partial capabilities are labeled `stable`, `partial`, `experimental`, `planned`, `unsupported`, or `deprecated` (see [artifacts/parser-coverage.md](artifacts/parser-coverage.md) for the exact meaning of each status).

## Getting Started

- [getting-started/quickstart.md](getting-started/quickstart.md): quick start.
- [getting-started/first-run.md](getting-started/first-run.md): first launch, admin creation, and troubleshooting.
- [getting-started/roles-and-permissions.md](getting-started/roles-and-permissions.md): Administrator/Standard user roles.
- [getting-started/user_guide.md](getting-started/user_guide.md): analyst flow from upload to report.
- [getting-started/windows-wsl.md](getting-started/windows-wsl.md): installing on Windows via WSL2.
- [getting-started/evaluation-guide.md](getting-started/evaluation-guide.md): what to test and how to give feedback.
- [getting-started/demo_mvp.md](getting-started/demo_mvp.md): guided end-to-end walkthrough.

## Status and Maps

- [roadmap.md](roadmap.md): roadmap by Core Platform / Core DFIR Capability / Preview classification — source of truth for maturity.
- [project_status.md](project_status.md): project maturity summary.
- [feature_map.md](feature_map.md): capability map, status, routes, backends, and limitations.
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md): current known limitations.

## Architecture

- [architecture/overview.md](architecture/overview.md): general architecture overview and per-artifact-family decisions.
- [architecture/platform-architecture.md](architecture/platform-architecture.md): multi-platform architecture, capabilities, artifact registry, and UI flow.
- [architecture/information-architecture.md](architecture/information-architecture.md): capability registry and navigation.
- [architecture/capability-registry.md](architecture/capability-registry.md): server-side capability registry and canonical routes.
- [architecture/optional-capability-boundary.md](architecture/optional-capability-boundary.md): RFC/ADR — what it technically means for a capability to be optional in Kairon (Memory today, AI in the future).
- [architecture/routing.md](architecture/routing.md): canonical routes and legacy redirects reference.

## Evidence

- [evidence/unified-evidence-ingestion.md](evidence/unified-evidence-ingestion.md): guided 7-step wizard (includes Server Health Check) for adding evidence.
- [evidence/preflight-inspection.md](evidence/preflight-inspection.md): read-only inspection before processing.
- [evidence/disk-image-ingestion.md](evidence/disk-image-ingestion.md): read-only ingestion of RAW/EWF images, volumes, OS detection, and traceability.
- [evidence/evidence-platforms.md](evidence/evidence-platforms.md): evidence platform selection.
- [evidence/evidence-integrity.md](evidence/evidence-integrity.md): SHA-256 hashing and chain of custody.
- [evidence/host-information.md](evidence/host-information.md): Host Facts and Local Accounts — coverage by platform, conflict resolution, and what is (and isn't) decoded from SAM/ProfileList on Windows.
- [evidence/large_evidence.md](evidence/large_evidence.md): handling large evidence, mounted paths.
- [evidence/processing-queue.md](evidence/processing-queue.md): per-case processing queue.
- [evidence/ingestion.md](evidence/ingestion.md): ingestion pipeline.
- [evidence/velociraptor_ingest.md](evidence/velociraptor_ingest.md): discovery and selective parsing of Velociraptor collections.

## Artifacts and Parsers

- [artifacts/parser-coverage.md](artifacts/parser-coverage.md): canonical matrix of parser status, formats, backends, and limitations.
- [artifacts/evtx.md](artifacts/evtx.md)
- [artifacts/filesystem_mft_usn.md](artifacts/filesystem_mft_usn.md)
- [artifacts/defender.md](artifacts/defender.md)
- [artifacts/powershell_artifacts.md](artifacts/powershell_artifacts.md)
- [artifacts/prefetch.md](artifacts/prefetch.md)
- [artifacts/lnk.md](artifacts/lnk.md)
- [artifacts/jumplists.md](artifacts/jumplists.md)
- [artifacts/registry.md](artifacts/registry.md)
- [artifacts/srum.md](artifacts/srum.md)
- [artifacts/shellbags.md](artifacts/shellbags.md)
- [artifacts/browser.md](artifacts/browser.md)
- [artifacts/scheduled_tasks.md](artifacts/scheduled_tasks.md)
- [artifacts/usb.md](artifacts/usb.md)
- [artifacts/recycle_bin.md](artifacts/recycle_bin.md)
- [artifacts/autoruns.md](artifacts/autoruns.md)
- [artifacts/bits.md](artifacts/bits.md)
- [artifacts/cloud_sync.md](artifacts/cloud_sync.md)
- [artifacts/network.md](artifacts/network.md)
- [artifacts/wmi.md](artifacts/wmi.md)
- [artifacts/execution_artifacts.md](artifacts/execution_artifacts.md)

## Linux

- [linux/linux-support.md](linux/linux-support.md): full Linux support — collection formats, auto-discovery, the 12 parsed families, and limitations.

## Memory

- [memory/memory_analysis.md](memory/memory_analysis.md): status, plugins, and profiles of Memory Analysis (Preview).
- [memory/memory_operations.md](memory/memory_operations.md): enablement, optional worker, build, configuration, isolation, and troubleshooting.
- [memory/memory_upload.md](memory/memory_upload.md): dedicated memory image upload — flow, limits, streaming, and maintenance CLI.
- [memory/memory_process_model.md](memory/memory_process_model.md): canonical process entity/observation model.
- [memory/memory_process_graph.md](memory/memory_process_graph.md): process graph UX.
- [memory/memory_runner_security.md](memory/memory_runner_security.md): threat model of the Memory runner.
- [memory/memory_symbols.md](memory/memory_symbols.md): managed Windows symbols.
- [memory/memory_symbol_operator_approval.md](memory/memory_symbol_operator_approval.md): operator approval flow for symbols.
- [memory/symbol_egress_gateway.md](memory/symbol_egress_gateway.md): symbol egress gateway architecture.
- [memory/symbol_fetcher_security.md](memory/symbol_fetcher_security.md): threat model of the symbol-fetcher.

## Search and Investigation

- [search-and-investigation/search.md](search-and-investigation/search.md): Search workspace, filters, command-style phrases, and Timeline.
- [search-and-investigation/timeline_reports.md](search-and-investigation/timeline_reports.md): timeline and reports.
- [search-and-investigation/process_graph.md](search-and-investigation/process_graph.md): Execution Story / Process Graph.
- [search-and-investigation/findings-notes.md](search-and-investigation/findings-notes.md): investigative notes and findings.
- [search-and-investigation/findings_correlation.md](search-and-investigation/findings_correlation.md): taxonomy of auto-generated correlation findings.
- [search-and-investigation/case-management.md](search-and-investigation/case-management.md): case status, priority, tags, archiving, and filters.
- [search-and-investigation/app_sections.md](search-and-investigation/app_sections.md): index of UI sections.
- [search-and-investigation/semi_automatic_analysis.md](search-and-investigation/semi_automatic_analysis.md): catalog of semi-automatic analysis sections.
- [search-and-investigation/investigation-workflow.md](search-and-investigation/investigation-workflow.md): scope/host-filtering mechanics across views.

## Rules

- [rules/rules_sigma_yara.md](rules/rules_sigma_yara.md): Sigma, YARA, and detections.
- [rules/rule_authoring.md](rules/rule_authoring.md): how to write heuristic/Sigma/YARA rules.
- [rules/builtin_rules.md](rules/builtin_rules.md): catalog of builtin detections.

## Deployment

- [deployment/deployment.md](deployment/deployment.md): canonical deployment guide — requirements, environment variables, volumes, operations, and security.
- [deployment/deployment-modes.md](deployment/deployment-modes.md): localhost/lan/https modes.
- [deployment/deployment-remote.md](deployment/deployment-remote.md): remote deployment runbook.
- [deployment/backup-restore.md](deployment/backup-restore.md): backup and restore.
- [deployment/update-rollback.md](deployment/update-rollback.md): update and rollback.
- [deployment/troubleshooting.md](deployment/troubleshooting.md): operational/infrastructure troubleshooting.

## Operations

- [operations/troubleshooting.md](operations/troubleshooting.md): application-level functional troubleshooting.
- [operations/performance.md](operations/performance.md): performance profiles.
- [operations/opensearch.md](operations/opensearch.md): OpenSearch mapping and behavior.
- [operations/api_summary.md](operations/api_summary.md): high-level endpoint map.
- [operations/testing.md](operations/testing.md): backend/frontend test suite.
- [operations/demo_checklist.md](operations/demo_checklist.md): QA checklist for demos.

## Releases

- [releases/0.9.0-beta.md](releases/0.9.0-beta.md): release notes for 0.9.0-beta (historical).

## Community

- [../CONTRIBUTING.md](../CONTRIBUTING.md): how to build, test, and propose changes.
- [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md): community standards.
- [../SECURITY.md](../SECURITY.md): security policy, self-hosted deployment boundary, and vulnerability reporting.
- [../LICENSE](../LICENSE) / [../NOTICE](../NOTICE): AGPL-3.0 license and third-party notices.
