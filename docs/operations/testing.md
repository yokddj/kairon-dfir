# Testing

## Operational Smoke Suite

Run this shortlist before closing a backend/frontend hardening pass:

```bash
python3 -m compileall /app/app /app/tests
pytest -q /app/tests/test_search_v2.py /app/tests/test_search_query_syntax.py /app/tests/test_event_identity.py /app/tests/test_findings.py /app/tests/test_rules_v2.py /app/tests/test_timeline.py /app/tests/test_reports.py /app/tests/test_evidence_storage.py
pytest -q /app/tests/test_ingest.py -k "ntfs or windows_ui or user_activity or debug_pack_creates_expected_artifacts"
npx vitest run src/pages/Search.test.tsx src/pages/TimelinePage.test.tsx src/components/ProcessTreePanel.test.tsx src/pages/CaseReportsPage.test.tsx src/pages/Rules.test.tsx src/pages/Detections.test.tsx src/components/NavigationWorkspace.test.tsx src/components/EvidenceUpload.test.tsx src/pages/Siem.test.tsx src/pages/DocsPage.test.tsx src/App.test.tsx
npm run build
```

This covers:

- advanced Search and cursor pagination
- stable event identity / reconciliation after reprocess
- findings / detections / timeline status preservation
- evidence path validation and mounted path UX
- System / Performance Evidence storage guidance and deployment metadata
- targeted ingest families with debug export
- route-level lazy loading and the main frontend workspaces

## Backend

### Basic Validation

```bash
python3 -m compileall backend/app backend/tests
pytest -q
```

### Suites by Family

```bash
pytest -q /app/tests/test_rules_v2.py
pytest -q /app/tests/test_ingest.py -k process_graph
pytest -q /app/tests -k "rules or detections or sigma or yara or debug_export"
pytest -q /app/tests -k "timeline or reports or search or host"
pytest -q /app/tests/test_event_identity.py
pytest -q /app/tests/test_search_query_syntax.py
```

## Frontend

```bash
cd frontend
npm test
npx vitest run src/pages/Rules.test.tsx src/pages/Detections.test.tsx
npx vitest run src/pages/CaseOverviewPage.test.tsx
npm run build
```

## Examples by Feature Area

- rules: `test_rules_v2.py`
- process graph: `test_ingest.py -k process_graph`
- reports: `CaseReportsPage.test.tsx`
- timeline: `TimelinePage.test.tsx`
- search: relevant `Search` suites
- host attribution / debug export: backend suites by keyword
- stable IDs / reconciliation: `test_event_identity.py`, `test_rules_v2.py`, `test_timeline.py`, `test_search_query_syntax.py`

## Reprocess / Reconciliation v1

Minimum recommended coverage if you touch event identity or reprocess:

```bash
python3 -m compileall /app/app /app/tests
pytest -q /app/tests/test_event_identity.py /app/tests/test_findings.py /app/tests/test_rules_v2.py /app/tests/test_timeline.py /app/tests/test_search_query_syntax.py
```

What it validates:

- deterministic `stable_event_id` for the same logical event
- findings/detections preserve state after reprocess
- `ingest_plan` is persisted on the first ingest
- `previous_selection` reuses the exact same candidate IDs when they remain available
- `updated_discovery` shows new candidates without auto-adding them to `previous_selection`
- `full_rediscovery` makes clear that the plan may change
- key events remap by `stable_event_id` or become `stale`
- Search can query by `stable_event_id`

## Known Non-Blocking Warnings

- `React Router` may still emit future-flag warnings in frontend tests; these do not block runtime or build.
- if a skip/xfail appears, it must be justified in the suite or in this document.

## Closed Technical Debt Cleanup

These should no longer appear in the main suite:

- `SQLAlchemy overlaps` relationship warnings
- `datetime.utcnow()` deprecations in touched runtime code
- `422` from `POST /api/cases/{case_id}/correlate` due to a missing body
- broken `compileall` in `/app/app` or `/app/tests`
- a single, enormous main chunk from missing route-level lazy loading

## Practical Recommendation

- if you only change docs, a full pytest run is not required
- if you change frontend labels or navigation, run at least `npm run build`
- if you touch Rules/Detections/Process Graph integration, run its specific suite in addition to the build
