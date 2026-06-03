# Testing

## Operational smoke suite

Run this shortlist before closing a backend/frontend hardening sprint:

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

## Demo MVP smoke

Before a live MVP demo, also run:

```bash
python3 tools/demo/generate_demo_evidence.py
pytest -q /app/tests/test_demo_pack.py
```

Optional end-to-end bootstrap on a running stack:

```bash
python3 tools/demo/bootstrap_demo_case.py
```

## Backend

### Validación básica

```bash
python3 -m compileall backend/app backend/tests
pytest -q
```

### Suites por familias

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

## Ejemplos por sprint

- rules: `test_rules_v2.py`
- process graph: `test_ingest.py -k process_graph`
- reports: `CaseReportsPage.test.tsx`
- timeline: `TimelinePage.test.tsx`
- search: `Search` suites relevantes
- host attribution / debug export: suites backend por keyword
- stable IDs / reconciliation: `test_event_identity.py`, `test_rules_v2.py`, `test_timeline.py`, `test_search_query_syntax.py`

## Reprocess / reconciliation v1

Cobertura mínima recomendada si tocas identidad de eventos o reprocess:

```bash
python3 -m compileall /app/app /app/tests
pytest -q /app/tests/test_event_identity.py /app/tests/test_findings.py /app/tests/test_rules_v2.py /app/tests/test_timeline.py /app/tests/test_search_query_syntax.py
```

Qué valida:

- `stable_event_id` determinístico para el mismo evento lógico
- findings/detections preservan estado tras reprocess
- `ingest_plan` se persiste en el primer ingest
- `previous_selection` reutiliza exactamente los mismos candidate IDs cuando siguen disponibles
- `updated_discovery` muestra candidatos nuevos sin autoañadirlos en `previous_selection`
- `full_rediscovery` deja claro que el plan puede cambiar
- key events remapean por `stable_event_id` o quedan `stale`
- Search puede consultar por `stable_event_id`

## Warnings conocidos no bloqueantes

- `React Router` puede seguir emitiendo warnings de future flags en tests de frontend; no bloquean runtime ni build
- si aparece un skip/xfail, debe quedar justificado en la suite o en este documento

## Limpieza de deuda técnica cerrada

Ya no deberían aparecer en la suite principal:

- warnings de relaciones `SQLAlchemy overlaps`
- deprecations de `datetime.utcnow()` en código runtime tocado
- `422` de `POST /api/cases/{case_id}/correlate` por body ausente
- `compileall` roto en `/app/app` o `/app/tests`
- un único chunk principal enorme por falta de lazy loading de rutas

## Recomendación práctica

- si cambias solo docs, no hace falta pytest completo
- si cambias labels o navegación del frontend, al menos `npm run build`
- si tocas integración Rules/Detections/Process Graph, ejecuta su suite específica además del build
