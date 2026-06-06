# Documentation Inventory

Inventory for `Documentation & Demo Folder Structure Cleanup v1`.

- Files reviewed: 88
- Scope: `README.md`, `docs/**/*.md`, `demo/**/*.md`, `docs/assets/*`, `demo/**/*`
- Decision rules: keep user/product docs in `docs/`, deployment/operator docs in `docs/deployment/`, reusable validation docs in `docs/validation/`, demo/lab docs in `docs/demo/`, and internal maintenance notes in `docs/maintenance/`.

## Summary

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `README.md` | Project overview, quick start and top-level doc links | user | keep | overlaps only as top-level summary | `README.md` | Primary entry point; links simplified to clean docs. |
| `demo/README.md` | Short operational note for local demo folder | demo | keep | replaces long demo instructions in `demo/` | `demo/README.md` | Keeps `demo/` operational only. |
| `demo/evidence/README.md` | Short local evidence placement note | demo | keep | overlaps with old demo evidence README | `demo/evidence/README.md` | Operational note only; long docs live in `docs/demo/`. |
| `demo/evidence/.gitkeep` | Preserve empty evidence directory | developer | keep | none | `demo/evidence/.gitkeep` | Allows ignored local evidence folder to exist. |
| `demo/evidence/Collection-KAIRON-LAB01-2026-06-06T18_23_56Z.zip` | Local demo evidence archive | demo | delete | should not be versioned | removed from repo | Heavy evidence archives must stay local and ignored. |
| `docs/assets/kairon-dfir-execution-story.png` | README screenshot | user | keep | none | `docs/assets/` | Referenced by `README.md`. |
| `docs/assets/kairon-dfir-investigation-workspace.png` | Old screenshot asset | user | delete | unused screenshot | removed from repo | No README/docs references. |
| `docs/assets/kairon-dfir-investigation-workspace.svg` | Old screenshot/vector asset | user | delete | unused screenshot | removed from repo | No README/docs references. |
| `docs/assets/.DS_Store` | OS metadata | internal | delete | none | removed from repo | Generated local file. |
| `demo/.DS_Store` | OS metadata | internal | delete | none | removed from repo | Generated local file. |

## Product And User Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/index.md` | Documentation index | user | keep | README summary | `docs/index.md` | Main docs route index. |
| `docs/user_guide.md` | Analyst workflow | user | keep | README first workflow | `docs/user_guide.md` | Detailed user guidance. |
| `docs/quickstart.md` | Quick start | user | keep | README quick start | `docs/quickstart.md` | Useful direct onboarding doc. |
| `docs/feature_map.md` | Capability map | user | keep | project status | `docs/feature_map.md` | Product state map. |
| `docs/artifacts_matrix.md` | Artifact support matrix | user | keep | artifact docs | `docs/artifacts_matrix.md` | Central support matrix. |
| `docs/parser_backends.md` | Parser backend support | user | keep | raw parser docs | `docs/parser_backends.md` | User-facing parser backend state. |
| `docs/search.md` | Search workspace guide | user | keep | user guide | `docs/search.md` | High-value workflow doc. |
| `docs/timeline_reports.md` | Timeline and report behavior | user | keep | report/user guide | `docs/timeline_reports.md` | Specific workflow detail. |
| `docs/process_graph.md` | Execution story/process graph | user | keep | command/process docs | `docs/process_graph.md` | Product feature doc. |
| `docs/rules_sigma_yara.md` | Rules and detections | user | keep | rule authoring | `docs/rules_sigma_yara.md` | Analyst rule workflow. |
| `docs/rule_authoring.md` | Rule authoring | developer | keep | rules guide | `docs/rule_authoring.md` | Maintainer/user extension doc. |
| `docs/builtin_rules.md` | Built-in rule reference | user | keep | rules guide | `docs/builtin_rules.md` | Analyst interpretation doc. |
| `docs/troubleshooting.md` | General troubleshooting | operator | keep | deployment troubleshooting | `docs/troubleshooting.md` | App-level diagnostics. |
| `docs/performance.md` | Performance tuning | operator | keep | deployment docs | `docs/performance.md` | Runtime tuning reference. |
| `docs/large_evidence.md` | Large evidence guidance | operator | keep | deployment docs | `docs/large_evidence.md` | Helps avoid upload/path confusion. |
| `docs/api_summary.md` | API summary | developer | keep | architecture | `docs/api_summary.md` | Useful technical reference. |
| `docs/opensearch.md` | OpenSearch behavior | operator | keep | deployment troubleshooting | `docs/opensearch.md` | Indexing/search operations doc. |
| `docs/architecture.md` | Architecture | developer | keep | API docs | `docs/architecture.md` | Maintainer technical context. |
| `docs/raw_parsers.md` | Raw parser/tool details | developer | keep | parser backends | `docs/raw_parsers.md` | Maintainer parser context. |
| `docs/ingestion.md` | Evidence ingest flow | user | keep | user guide | `docs/ingestion.md` | Ingest behavior and limitations. |
| `docs/artifacts.md` | Supported artifacts overview | user | keep | artifacts matrix | `docs/artifacts.md` | Narrative artifact guide. |
| `docs/debug_export_pack.md` | Debug export pack | developer | keep | troubleshooting | `docs/debug_export_pack.md` | Support/debug feature doc. |
| `docs/project_status.md` | Current maturity state | tester | keep | feature map | `docs/project_status.md` | Useful beta status snapshot. |
| `docs/roadmap.md` | Product roadmap | user | keep | project status | `docs/roadmap.md` | Planning context. |
| `docs/testing.md` | Test guidance | developer | keep | maintenance docs | `docs/testing.md` | Developer validation workflow. |
| `docs/BETA_NOTES.md` | Beta notes | tester | keep | deployment docs | `docs/BETA_NOTES.md` | Beta audience context. |
| `docs/KNOWN_LIMITATIONS.md` | Known limitations | user | keep | README limitations | `docs/KNOWN_LIMITATIONS.md` | Top-level limitation reference. |
| `docs/SECURITY.md` | Security notes | operator | keep | README warning | `docs/SECURITY.md` | Security reference. |

## Artifact Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/autoruns.md` | Autoruns/ASEP artifact behavior | user | keep | registry/startup docs | `docs/autoruns.md` | Artifact-specific reference. |
| `docs/bits.md` | BITS artifact behavior | user | keep | network/persistence docs | `docs/bits.md` | Artifact-specific reference. |
| `docs/browser.md` | Browser artifacts | user | keep | artifacts overview | `docs/browser.md` | Artifact-specific reference. |
| `docs/cloud_sync.md` | Cloud sync artifacts | user | keep | artifacts overview | `docs/cloud_sync.md` | Artifact-specific reference. |
| `docs/defender.md` | Microsoft Defender artifacts | user | keep | builtin rules | `docs/defender.md` | Artifact-specific reference. |
| `docs/evtx.md` | EVTX/EvtxECmd | user | keep | parser backends | `docs/evtx.md` | Core artifact reference. |
| `docs/execution_artifacts.md` | Amcache/Shimcache/AppCompat | user | keep | artifacts overview | `docs/execution_artifacts.md` | Artifact-specific reference. |
| `docs/filesystem_mft_usn.md` | MFT/filesystem artifacts | user | keep | large evidence | `docs/filesystem_mft_usn.md` | Artifact-specific reference. |
| `docs/findings_correlation.md` | Findings and correlation | user | keep | user guide | `docs/findings_correlation.md` | Investigation workflow reference. |
| `docs/jumplists.md` | Jump Lists | user | keep | LNK/user activity | `docs/jumplists.md` | Artifact-specific reference. |
| `docs/lnk.md` | LNK artifacts | user | keep | Jump Lists | `docs/lnk.md` | Artifact-specific reference; local paths sanitized. |
| `docs/network.md` | Network/WLAN/DNS | user | keep | artifacts overview | `docs/network.md` | Artifact-specific reference. |
| `docs/powershell_artifacts.md` | PowerShell artifacts | user | keep | EVTX/command history | `docs/powershell_artifacts.md` | Artifact-specific reference. |
| `docs/prefetch.md` | Prefetch | user | keep | execution artifacts | `docs/prefetch.md` | Artifact-specific reference. |
| `docs/recycle_bin.md` | Recycle Bin | user | keep | filesystem docs | `docs/recycle_bin.md` | Artifact-specific reference. |
| `docs/registry.md` | Registry/RECmd | user | keep | autoruns | `docs/registry.md` | Artifact-specific reference. |
| `docs/scheduled_tasks.md` | Scheduled Tasks | user | keep | persistence docs | `docs/scheduled_tasks.md` | Artifact-specific reference. |
| `docs/semi_automatic_analysis.md` | Semi-automatic analysis | user | keep | findings/correlation | `docs/semi_automatic_analysis.md` | Feature reference. |
| `docs/shellbags.md` | Shellbags | user | keep | registry docs | `docs/shellbags.md` | Artifact-specific reference. |
| `docs/srum.md` | SRUM | user | keep | network docs | `docs/srum.md` | Artifact-specific reference. |
| `docs/usb.md` | USB artifacts | user | keep | setupapi/network | `docs/usb.md` | Artifact-specific reference. |
| `docs/velociraptor_ingest.md` | Velociraptor ingest | user | keep | ingestion docs | `docs/velociraptor_ingest.md` | Collection-specific ingest guidance; local paths sanitized. |
| `docs/wmi.md` | WMI artifacts | user | keep | persistence docs | `docs/wmi.md` | Artifact-specific reference. |
| `docs/artifact_coverage_gap.md` | Artifact coverage gaps | developer | review | artifacts matrix | `docs/artifact_coverage_gap.md` | Useful but should be reviewed before public release. |

## Deployment Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/deployment.md` | General deployment overview | operator | keep | beta deployment | `docs/deployment.md` | General deployment entry. |
| `docs/deployment/beta-deployment.md` | Beta deployment | operator | keep | deployment overview | `docs/deployment/beta-deployment.md` | Primary deployment guide. |
| `docs/deployment/backup-restore.md` | Backup/restore | operator | keep | troubleshooting | `docs/deployment/backup-restore.md` | Operational safety doc. |
| `docs/deployment/update-rollback.md` | Update/rollback | operator | keep | backup/restore | `docs/deployment/update-rollback.md` | Operational safety doc. |
| `docs/deployment/troubleshooting.md` | Deployment troubleshooting | operator | keep | general troubleshooting | `docs/deployment/troubleshooting.md` | Deployment-specific diagnostics and cleanup policy. |
| `docs/deployment/beta-vs-demo-mode.md` | Beta vs demo mode separation | operator | keep | demo README | `docs/deployment/beta-vs-demo-mode.md` | Keeps demo/validation separation explicit. |

## Validation Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/validation/README.md` | Validation feature overview | tester | keep | demo docs | `docs/validation/README.md` | Generic validation docs; no dataset-specific content. |
| `docs/validation/validation-matrix-format.md` | Validation matrix schema | tester | keep | validation README | `docs/validation/validation-matrix-format.md` | Generic import format. |

## Demo Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/demo/README.md` | Demo index | demo | keep | old demo README | `docs/demo/README.md` | Single demo/lab entry point. |
| `docs/demo/generic-demo-guide.md` | Generic demo walkthrough | demo | keep | MVP demo guide | `docs/demo/generic-demo-guide.md` | Dataset-neutral demo guidance. |
| `docs/demo/mvp-demo-guide.md` | Synthetic MVP demo route | demo | move | old `docs/demo_mvp.md` | `docs/demo/mvp-demo-guide.md` | Consolidated under demo docs. |
| `docs/demo/mvp-demo-checklist.md` | Synthetic demo checklist | demo | move | old `docs/demo_checklist.md` | `docs/demo/mvp-demo-checklist.md` | Consolidated under demo docs. |
| `docs/demo/mvp-demo-route-quick.md` | Short synthetic demo route | demo | move | old `docs/demo_route_quick.md` | `docs/demo/mvp-demo-route-quick.md` | Consolidated and sanitized. |
| `docs/demo/kairon-lab01/README.md` | Lab 01 entry | demo | move | old `docs/demo-cases/kairon-lab01/README.md` | `docs/demo/kairon-lab01/README.md` | Consolidated under demo docs. |
| `docs/demo/kairon-lab01/scenario.md` | Lab scenario | demo | move | lab README | `docs/demo/kairon-lab01/scenario.md` | Multi-page lab is useful. |
| `docs/demo/kairon-lab01/investigation-guide.md` | Lab investigation guide | demo | move | lab README | `docs/demo/kairon-lab01/investigation-guide.md` | Multi-page lab is useful. |
| `docs/demo/kairon-lab01/questions.md` | Lab questions | demo | move | lab guide | `docs/demo/kairon-lab01/questions.md` | Analyst training questions. |
| `docs/demo/kairon-lab01/expected-findings.md` | Lab expected findings | demo | move | questions | `docs/demo/kairon-lab01/expected-findings.md` | Answer key, clearly lab-only. |
| `docs/demo/kairon-lab01/validation-checklist.md` | Lab validation checklist | demo | move | expected findings | `docs/demo/kairon-lab01/validation-checklist.md` | Platform validation checklist. |
| `docs/demo/kairon-lab01/iocs.md` | Lab indicators | demo | move | expected findings | `docs/demo/kairon-lab01/iocs.md` | Lab-only indicators, not real IOCs. |
| `docs/demo/kairon-lab01/artifact-map.md` | Lab artifact map | demo | move | investigation guide | `docs/demo/kairon-lab01/artifact-map.md` | Useful investigator map. |
| `docs/demo-cases/kairon-lab01/*` | Old Lab 01 location | demo | delete | moved to `docs/demo/kairon-lab01/` | removed from repo | Avoids duplicated demo roots. |

## Maintenance Docs

| Path | Purpose | Audience | Status | Duplicates or overlaps | Recommended destination | Reason |
|---|---|---|---|---|---|---|
| `docs/maintenance/documentation-inventory.md` | Documentation cleanup inventory | internal | keep | none | `docs/maintenance/documentation-inventory.md` | Records cleanup decisions. |
| `docs/maintenance/documentation-maintenance.md` | Documentation maintenance checklist | internal | move | old `docs/documentation_maintenance.md` | `docs/maintenance/documentation-maintenance.md` | Maintainer-only process doc. |
| `docs/maintenance/release-repository-cleanup.md` | Repository hygiene notes | internal | move | old `docs/release_repository_cleanup.md` | `docs/maintenance/release-repository-cleanup.md` | Maintainer/internal release hygiene. |
| `docs/maintenance/task-inventory.md` | Queue/task contract | developer | move | old `docs/task_inventory.md` | `docs/maintenance/task-inventory.md` | Developer maintenance context. |
| `docs/maintenance/internal-evaluation.md` | Internal evaluation notice | internal | move | old `docs/internal_evaluation.md` | `docs/maintenance/internal-evaluation.md` | Internal-only note. |
| `docs/maintenance/github-about.md` | Suggested GitHub metadata | internal | move | old `docs/github-about.md` | `docs/maintenance/github-about.md` | Repository maintenance context. |
