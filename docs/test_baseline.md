# Test Baseline

Baseline recorded on remote host `192.168.1.19` from `/root/DFIR_APP`.

## Focused Memory Analysis Checks

```sh
docker compose run --rm backend pytest tests/test_memory_analysis.py -q
```

Result:

- `26 passed`

```sh
docker compose run --rm frontend npm test -- src/pages/MemoryAnalysisPage.test.tsx --run
```

Result:

- `9 passed`

```sh
docker compose run --rm frontend npm run build
```

Result:

- passed

## Full Backend Suite

Command:

```sh
docker compose run --rm backend pytest -q
```

Current result:

- `98 failed`
- `1049 passed`
- `6 skipped`
- `1 error`

Known groups observed in the current remote baseline:

- repository root docs/scripts missing from backend image during tests (`README.md`, `.gitignore`, `.env.example`, scripts)
- missing `sqlite_session` fixture
- tests using fake IDs such as `case-1` against real Postgres UUID columns
- ingest/search/case-context expectations outside Memory Analysis scope

These are recorded as existing baseline failures of unknown origin unless separately proven by history or by reproducing at an earlier commit.

## Full Frontend Suite

Command:

```sh
docker compose run --rm frontend npm test -- --run
```

Current result:

- `4 failed`
- `21 passed`

Known groups observed in the current remote baseline:

- `Rules`
- `ArtifactExplorer`
- `ProcessTreePanel`
- stray `src/EvidenceUpload.tsx` import path failure

These are recorded as existing baseline failures of unknown origin unless separately proven by history or by reproducing at an earlier commit.

## Policy

New sprints must not increase this baseline. Focused tests for changed behavior must pass even while unrelated baseline failures remain open.
