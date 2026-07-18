# Release Checklist

Use this checklist for each Kairon DFIR release candidate. Mark items only when actually completed.

- [x] release version selected
- [x] all version sources updated
- [x] changelog updated
- [x] release notes added
- [x] migrations reviewed
- [x] clean install validated
- [x] upgrade validated
- [x] data persistence after restart validated
- [x] Docker images built
- [x] backend health validated
- [x] frontend production build validated
- [x] focused backend tests passed
- [x] baseline regression comparison recorded
- [x] configuration audit passed
- [x] secrets audit passed
- [x] evidence/path audit passed
- [x] known issues documented
- [ ] release commit created
- [ ] release branch pushed
- [ ] release PR opened
- [ ] final tag pending merge
- [ ] GitHub release pending final tag

## 0.9.0-beta Migration Matrix

| Change | Existing schema support | Migration required | Risk | Action |
| --- | --- | --- | --- | --- |
| Unique canonical host per case | `case_hosts` unique `(case_id, canonical_name)` | No | Existing duplicate data would already violate the model constraint | No new migration |
| Unique alias per case | `case_host_aliases` unique `(case_id, normalized_alias)` | No | Existing duplicate data would already violate the model constraint | No new migration |
| Evidence host assignment | `evidences.host_id` and host assignment metadata columns | No | Nullable fields support historical unassigned evidence | No new migration |
| Custody and provenance | `evidence_custody_events`, `ingest_source`, `metadata_json` | No | Historical evidence may not have new provenance keys | Document expected behavior |
| Memory upload parity | Existing `memory_uploads` and evidence tables | No | Memory still requires explicit source host | Covered by focused tests |
| Platform detection | Existing evidence platform columns | No | Historical evidence may retain previous platform values | No automatic rewrite |

## Final Tag Commands

Do not run until the release PR is merged and final approval is complete:

```bash
git tag -a v0.9.0-beta -m "Kairon DFIR v0.9.0-beta"
git push origin v0.9.0-beta
```
