# Phase 2 Routing Audit

## Canonical Routes

- `/cases/:caseId/overview`
- `/cases/:caseId/hosts`
- `/cases/:caseId/search`
- `/cases/:caseId/findings`
- `/cases/:caseId/timeline`
- `/cases/:caseId/l/access/authentication`
- `/cases/:caseId/l/execution/command-history`
- `/cases/:caseId/w/execution/stories`
- `/cases/:caseId/w/execution/command-history`
- `/cases/:caseId/artifacts`
- `/cases/:caseId/incident-timeline`
- `/cases/:caseId/validation-matrix`
- `/cases/:caseId/evidence`
- `/cases/:caseId/ingest`
- `/cases/:caseId/detections`
- `/cases/:caseId/reports`
- `/cases/:caseId/debug-export`
- `/cases/:caseId/m`
- `/cases/:caseId/m/runs`
- `/cases/:caseId/m/:evidenceId/overview`
- `/cases/:caseId/m/:evidenceId/processes`
- `/cases/:caseId/m/:evidenceId/process-graph`
- `/cases/:caseId/m/:evidenceId/network`
- `/cases/:caseId/m/:evidenceId/modules`
- `/cases/:caseId/m/:evidenceId/handles`
- `/cases/:caseId/m/:evidenceId/vads`
- `/cases/:caseId/m/:evidenceId/suspicious`
- `/cases/:caseId/m/:evidenceId/system`
- `/cases/:caseId/m/:evidenceId/raw`
- `/cases/:caseId/m/:evidenceId/artifacts`

## Registry-Owned Capability Routes

- `windows.execution.command_history` -> `/cases/:caseId/w/execution/command-history`
- `windows.execution.stories` -> `/cases/:caseId/w/execution/stories`
- `windows.persistence.overview` -> `/cases/:caseId/findings?preset=persistence`
- `linux.access.authentication` -> `/cases/:caseId/l/access/authentication`
- `linux.execution.command_history` -> `/cases/:caseId/l/execution/command-history`
- `linux.software.packages` -> `/cases/:caseId/artifacts?artifact_type=linux_packages`
- `memory.overview` -> `/cases/:caseId/m`
- `memory.processes` -> `/cases/:caseId/m/:evidenceId/processes`
- `memory.network` -> `/cases/:caseId/m/:evidenceId/network`

## Legacy Redirects

- `/cases/:caseId/linux-authentication` -> `/cases/:caseId/l/access/authentication`
- `/cases/:caseId/command-history` -> `/cases/:caseId/l/execution/command-history`
- `/cases/:caseId/process-graph` -> `/cases/:caseId/w/execution/stories`
- `/cases/:caseId/process-tree` -> `/cases/:caseId/w/execution/stories`
- `/cases/:caseId/artifact-search` -> `/cases/:caseId/artifacts`
- `/cases/:caseId/memory` -> `/cases/:caseId/m` for zero or multiple memory images
- `/cases/:caseId/memory?tab=runs` -> `/cases/:caseId/m/runs`
- `/cases/:caseId/memory?tab=:tab` -> `/cases/:caseId/m/:evidenceId/:tab` only when exactly one memory image exists
- `/cases/:caseId/memory/landing` -> `/cases/:caseId/m`
- `/cases/:caseId/memory/upload` -> `/cases/:caseId/evidence?tab=evidences&add_evidence=1&expected_kind=memory_dump`
- `/cases/:caseId/memory/:evidenceId` -> `/cases/:caseId/m/:evidenceId/overview`
- `/cases/:caseId/memory/:evidenceId/:memoryTab` -> `/cases/:caseId/m/:evidenceId/:memoryTab`
- `/cases/:caseId/dashboard` -> `/cases/:caseId/overview`
- `/timeline` -> `/cases/:activeCaseId/timeline`
- `/process-tree` -> `/cases/:activeCaseId/w/execution/stories`
- `/command-history` -> `/cases/:activeCaseId/l/execution/command-history`
- `/dashboard` -> `/cases/:activeCaseId/overview`
- `/analysis/semi-auto` -> `/cases/:activeCaseId/findings`
- `/semi-auto` -> `/cases/:activeCaseId/findings`

## Audit Result

- Remaining legacy UI route literals in production code are limited to `frontend/src/App.tsx` redirect registrations and legacy tab translation.
- Remaining `/cases/.../memory/...` literals outside UI routing are backend API endpoints or API client calls, not frontend routes.
- Capability navigation is registry-driven through `backend/app/services/case_capabilities.py`; Sidebar substitutes `:caseId` and contextual `:evidenceId` only.
- Static route contract tests assert every registry route is registered in `App.tsx` and registry routes do not use legacy aliases.
- Redirect contract tests assert legacy targets are terminal canonical routes, preventing redirect chains and loops.
- Runtime memory routing tests cover single image, multiple images, old bookmarks, invalid image ids, refresh-style deep links, runs, and back-button replacement behavior.
