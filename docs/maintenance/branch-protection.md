# Branch Protection Setup

> Documentation status: technical draft pending maintainer review.

## Recommended Configuration

After the CI workflows are green, configure branch protection on `main`:

1. Go to **GitHub repository → Settings → Branches**.
2. Click **Add branch protection rule**.
3. Set **Branch name pattern**: `main`
4. Enable:
   - **Require a pull request before merging**
   - **Require approvals**: 1
   - **Require status checks to pass before merging**
   - **Require branches to be up to date before merging**

## Status Checks to Require

Mark these as required in the branch protection settings:

| Check | Workflow | Description |
|-------|----------|-------------|
| `repo-sanity` | CI | Repository structure, no em-dash flags |
| `frontend-typecheck` | CI | TypeScript compilation |
| `frontend-build` | CI | Vite production build |
| `scripts-check` | CI | Bash syntax validation |
| `setup-smoke` | CI | Setup script smoke tests |
| `compose-config` | CI | Docker Compose configuration |
| `docs-check` | Docs | Documentation consistency |
| `secret-scan` | Security | No leaked secrets or keys |

## Optional

- **Do not allow bypassing the above settings**: Enable for administrators.
- **Restrict who can push to matching branches**: Keep empty or restrict to maintainers.
- **Allow force pushes**: Disable.
- **Allow deletions**: Disable.

## Local Verification

Before pushing, run the local quality gate:

```bash
./scripts/quality-gate.sh --fast   # quick check during development
./scripts/quality-gate.sh --full   # full check before PR
```

## GitHub Actions Status Badges

Add to README:

```markdown
![CI](https://github.com/yokddj/kairon-dfir/actions/workflows/ci.yml/badge.svg)
![Docs](https://github.com/yokddj/kairon-dfir/actions/workflows/docs.yml/badge.svg)
![Security](https://github.com/yokddj/kairon-dfir/actions/workflows/security.yml/badge.svg)
```
