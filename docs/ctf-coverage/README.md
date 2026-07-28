# CTF Coverage Contract

This directory defines the product baseline for making Linux CTF cases solvable inside Kairon.

The contract is question-centered: every investigative question must have at least one specialist path and one generic Search path when feasible. Detections can accelerate work, but they are never allowed to be the only path to an answer.

## Current Baseline

| Case | Status | Evidence | Platform | Local confirmation |
| --- | --- | --- | --- | --- |
| CyberDefenders Webserver / VulnOSv2 | Confirmed anchor, incomplete answer key | `Webserver.E01` | Linux disk image, LVM-backed | Tests and comments reference `Webserver.E01`, `VulnOSv2`, and LVM root/swap discovery. |
| Victoria | Probable anchor, incomplete source material | `victoria-v8.kcore.img` plus likely disk image/triage evidence | Linux memory/disk | Tests reference `victoria-v8.kcore.img`, host `victoria`, user `ulysses`, and SSH brute-force examples. |

## Non-Negotiable Solve Paths

Each CTF question row in `question-matrix.md` tracks:

| Path | Requirement |
| --- | --- |
| Specialist path | A capability page, focused artifact view, or investigation endpoint answers the question without raw-index knowledge. |
| Search path | An analyst can answer from global Search using platform/artifact/query filters and visible provenance. |
| Source evidence path | The UI exposes source file, evidence ID, host, timestamp, and event/detail pivot sufficient to defend the answer. |

## Status Meanings

| Status | Meaning |
| --- | --- |
| `Implemented` | End-to-end path exists and is covered by tests or docs. |
| `Partial` | Some path exists, but solveability depends on assumptions, specialist knowledge, or limited parser support. |
| `Missing` | Required capability is not implemented. |
| `Broken` | Implemented but known not to work for the CTF requirement. |
| `Unknown` | Not locally confirmed yet. |

## Documents

| Document | Purpose |
| --- | --- |
| `question-matrix.md` | CTF question-centered coverage and gaps. |
| `artifact-matrix.md` | Artifact pipeline audit: discovery through source pivot. |
| `search-matrix.md` | Independent Search discoverability audit. |
| `linux-roadmap.md` | Linux-only implementation backlog and sprint plan. |
| `windows-gap-list.md` | Deferred Windows gaps noted during this audit. |
| `coverage.json` | Structured source of truth for automation/regression planning. |

## Audit Sources

Confirmed local sources:

| Source | Evidence |
| --- | --- |
| `backend/tests/test_disk_image_walk_linearity.py` | Real ext4 image comment: `Webserver.E01 / VulnOS`. |
| `backend/tests/test_evidence_preflight.py` | CyberDefenders `Webserver.E01` regression and LVM physical volume diagnostic. |
| `frontend/src/components/EvidenceIngestionWizard.test.tsx` | CyberDefenders `Webserver.E01`, `VulnOSv2-vg`, root/swap partition preview. |
| `backend/tests/test_evidence_disk_image_upload.py` | `victoria-v8.kcore.img` upload reference. |
| `backend/tests/test_linux_auth_investigation.py` | Host `victoria`, users `mail` and `ulysses`, SSH success/brute-force examples. |
| `frontend/src/pages/LinuxAuthenticationPage.test.tsx` | UI fixture for `victoria`, `VulnOSv2`, `ulysses`, `192.168.56.1`, `192.168.210.131`. |
| `docs/linux-support.md` | Linux support and unsupported/limited areas. |
| `docs/linux-artifacts.md` | Current Linux parser family details. |
| `docs/parser-coverage.md` | Cross-platform parser coverage matrix. |

Not locally confirmed yet:

| Item | Why it matters |
| --- | --- |
| Public walkthrough URLs for both CTFs | Required to convert candidate questions into exact expected-answer regression tests. |
| Complete answer key for Webserver/VulnOSv2 | Required to prove full solveability, not just artifact ingestion. |
| Complete answer key for Victoria | Required to separate memory-only, disk-only, and combined solve paths. |
