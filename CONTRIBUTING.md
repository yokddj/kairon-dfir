# Contributing to Kairon DFIR

Thanks for your interest in contributing. This document covers the practical basics: how to build, test, document, and submit changes.

## Before you start

- Read [`README.md`](README.md) for what Kairon DFIR does and how to run it locally.
- Read [`docs/roadmap.md`](docs/roadmap.md) to understand what's Core Platform, Core DFIR Capability, and Preview/Strategic — it helps place where a change belongs.
- By contributing, you agree your contribution is licensed under the project's [AGPL-3.0 license](LICENSE).

## Development setup

Backend (Python/FastAPI):

```bash
python3 -m compileall backend/app backend/tests
pytest -q
```

Frontend (React/TypeScript/Vite):

```bash
cd frontend
npm install
npm test
npm run build
```

See [`docs/testing.md`](./docs/operations/testing.md) for the full test suite breakdown, targeted test suites per feature area, and what each covers.

## Before opening a pull request

Run the local quality gate:

```bash
./scripts/quality-gate.sh --fast   # quick check during development
./scripts/quality-gate.sh --full   # full check before opening a PR
```

Your PR needs to pass the CI checks the repository already enforces:

| Check | Workflow | What it verifies |
|-------|----------|-------------------|
| `repo-sanity` | CI | Repository structure, no em-dash in flags |
| `backend-tests` | CI | Backend test suite |
| `frontend-typecheck` | CI | TypeScript compilation |
| `frontend-build` | CI | Vite production build |
| `scripts-check` | CI | Bash syntax validation |
| `setup-smoke` | CI | Setup script smoke tests |
| `compose-config` | CI | Docker Compose configuration |
| `docs-check` | Docs | Documentation consistency (see `.github/workflows/docs.yml`) |
| `secret-scan` | Security | No leaked secrets, keys, or real infrastructure metadata |

## Adding or changing a parser

Kairon's ingestion pipeline is registry-driven (see [`docs/parser-coverage.md`](./docs/artifacts/parser-coverage.md) and [`docs/platform-architecture.md`](./docs/architecture/platform-architecture.md)). When you add or materially change a parser:

1. Register it in the appropriate registry (`backend/app/core/artifact_registry.py` and, for native raw parsers, `backend/app/ingest/raw_parsers/`).
2. Add or update its dedicated doc under `docs/artifacts/` (e.g. `docs/artifacts/prefetch.md`, `docs/artifacts/registry.md`), and update `docs/artifacts/parser-coverage.md` with its real status — `stable`, `partial`, `experimental`, `planned`, `unsupported`, or `deprecated`. Don't mark something supported that isn't runnable in this deployment, and don't leave a shipped parser marked `planned`.
3. If it introduces a new `event.type` or normalized field family, update `docs/search-and-investigation/semi_automatic_analysis.md` if it participates in semi-automatic analysis, and `docs/search-and-investigation/app_sections.md` if it changes what a UI section shows.
4. Add tests under `backend/tests/`.

`docs/maintenance/documentation-maintenance.md` has a more exhaustive per-file checklist of which doc to touch for which artifact family — check it if your change touches an existing family.

## Documentation changes

- Keep documentation in sync with what the code actually does today — don't document planned-but-unbuilt behavior as shipped, and don't leave shipped behavior undocumented.
- English is the canonical language for this repository's documentation. New documents should be written in English.
- Cross-check status/maturity claims (`stable`, `Preview`, `experimental`, `planned`, etc.) against [`docs/roadmap.md`](docs/roadmap.md), which is the canonical source for capability maturity.

## Commit and PR style

- Prefer focused commits: one coherent change per commit, imperative present-tense subject line (e.g. "Add Windows local account inventory", not "Added" or "Adding").
- Explain *why* in the commit body when the reason isn't obvious from the diff alone.
- In the PR description, state what changed and, if relevant, what was deliberately left out of scope.

## Reporting bugs

See the "Bug Reports" section of [`SECURITY.md`](SECURITY.md) for what to include (and what never to attach) when filing an issue — this applies to functional bugs, not just security reports. Security vulnerabilities should go through GitHub's private reporting flow instead of a public issue; see [`SECURITY.md`](SECURITY.md) for details.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're expected to uphold it.
