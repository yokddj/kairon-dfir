# Legacy Code Audit

> Base commit: `e177ebf` — 2026-07-08
> Methodology: grep patterns, import analysis, route inventory, reference counting

## Summary

| Category | Total | Removed | Deprecated | Kept | Investigation |
|----------|-------|---------|------------|------|---------------|
| Role references (analyst/viewer) | 0 active | 0 | 0 | N/A | 0 |
| CaseAccess | 1 model + 3 usages | 0 | 0 | 1 model (reserved) | 0 |
| Dead API endpoints | 0 | 0 | 0 | 24 routers | 0 |
| Dead frontend components | 0 | 0 | 0 | N/A | 0 |
| Dead scripts | 0 | 0 | 0 | 15 scripts | 0 |
| Obsolete env vars | 0 | 0 | 0 | All active | 0 |
| Contradictory docs | 1 text | 1 | 0 | N/A | 0 |
| Migration comments | 1 | 1 comment | 0 | Schema kept | 0 |

## Removed

1. **AdminUsersPage line 76**: "Manage platform users, roles, and case access" → "Manage platform users and roles."
   - Reason: CaseAccess is not an active beta feature.

2. **CaseAccess model comment**: `# owner, analyst, viewer` → `# Reserved for future per-case role enforcement; not active in beta`
   - Reason: Legacy role names, misleading.

## Deprecated

None.

## Kept for Compatibility

| Item | Reason |
|------|--------|
| `bootstrap_admin()` | Active fallback for CI/automation |
| CaseAccess model + table | Schema integrity; future use |
| `get_effective_case_role()` | Reserved infrastructure |
| `preserve_analyst_state` | Active pipeline field (not a role) |
| `analyst_notes` | Active report feature (not a role) |

## Needs Investigation

None.

## Verification

| Check | Result |
|-------|--------|
| TypeScript | 0 errors |
| Backend syntax | OK |
| 24 routers accounted | All imported + included |
| No dead scripts (bash -n) | All 15 pass |
| No `assigned cases` in docs | Confirmed |

## Follow-up Issues

- CaseAccess table: migrate `role` default from `viewer` to `user` when next DB migration is needed.
- Consider removing `require_case_access` dependency if it remains unused after beta.
