# Documentation Inventory

Last reviewed: 2026-06-06

Purpose: track the public documentation surface after removing low-quality training material from the repository. Product, deployment, security, troubleshooting and generic validation documentation remain public. Evidence archives, generated case data and answer keys are intentionally excluded from version control.

## Current Structure

| Path | Purpose | Audience | Status | Recommended destination | Reason |
| --- | --- | --- | --- | --- | --- |
| `README.md` | Public project overview and quick start | user | keep | root | Primary entry point for the repository. |
| `docs/index.md` | Documentation catalog | user | keep | `docs/index.md` | Single navigable docs index. |
| `docs/user_guide.md` | Investigation workflow | user | keep | `docs/user_guide.md` | Core analyst guide. |
| `docs/quickstart.md` | Local startup and first run | user | keep | `docs/quickstart.md` | Practical onboarding without bundled datasets. |
| `docs/feature_map.md` | Feature status map | user/developer | keep | `docs/feature_map.md` | Useful product status reference. |
| `docs/artifacts_matrix.md` | Artifact support matrix | user | keep | `docs/artifacts_matrix.md` | Public parser coverage overview. |
| `docs/parser_backends.md` | Parser backend status | developer/operator | keep | `docs/parser_backends.md` | Explains parser dependencies and limits. |
| `docs/search.md` | Search workspace guidance | user | keep | `docs/search.md` | Core workflow documentation. |
| `docs/timeline_reports.md` | Timeline and reports workflow | user | keep | `docs/timeline_reports.md` | Core workflow documentation. |
| `docs/process_graph.md` | Execution Story / Process Graph | user | keep | `docs/process_graph.md` | Core workflow documentation. |
| `docs/rules_sigma_yara.md` | Rules and detections | user/developer | keep | `docs/rules_sigma_yara.md` | Core detection documentation. |
| `docs/* artifact pages` | Artifact-specific parser notes | user/developer | keep | `docs/` | Useful reference for supported families. |
| `docs/deployment/*` | Deployment and operations | operator | keep | `docs/deployment/` | Private beta and operations guidance. |
| `docs/validation/*` | Generic Validation Matrix workflow | tester | keep | `docs/validation/` | Metadata-only QA feature docs; no bundled dataset. |
| `docs/maintenance/*` | Internal documentation maintenance notes | maintainer | keep | `docs/maintenance/` | Maintenance-only references. |
| Public training material removed in this cleanup | Low-quality public walkthroughs and local archive notes | training | delete | removed from repo | Not ready for publication and should not define the public onboarding path. |

## Maintenance Rules

- Keep public docs focused on product use, installation, security, deployment and generic validation.
- Do not commit evidence archives, generated case data, search indexes, database dumps, reports, customer datasets or answer keys.
- Keep validation docs dataset-neutral.
- Move internal notes to `docs/maintenance/` when they are useful to maintainers but not part of public onboarding.
- Remove or rewrite links immediately when documentation is moved or deleted.
