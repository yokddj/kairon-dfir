# Artifact Pipeline Matrix

Status values use the definitions in `README.md`.

| Artifact | Discovery | Recognition | Parser | Normalizer | Database | API | Capability page | Search | Detection | Source pivot | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EWF disk image (`Webserver.E01`) | Implemented | Implemented | Partial | Partial | Implemented | Implemented | Evidence preflight/detail | Partial | Missing | Partial | Partial | EWF streaming and LVM tests exist, but real Webserver solve path needs validation. |
| Linux LVM logical volumes | Implemented | Implemented | Partial | Partial | Implemented | Implemented | Evidence diagnostics | Partial | Missing | Partial | Partial | Synthetic LVM test covers readable logical volume extraction; previous Webserver regression was unreadable LVM diagnostic. |
| Live ext filesystem tree | Partial | Partial | Partial | Partial | Implemented | Implemented | Artifact Explorer | Partial | Missing | Partial | Partial | Materialization walks live allocated entries only; deleted-file recovery is not covered. |
| `linux_os_info` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | No dedicated OS/host capability page. |
| `linux_identity` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Shadow hashes are intentionally not exposed. |
| `linux_auth` text logs | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Linux Authentication | Partial | Missing | Implemented | Partial | Specialist page reconstructs sessions/brute-force; Search lacks first-class Linux field builder entries. |
| `wtmp` / `btmp` / `lastlog` | Implemented | Implemented | Partial | Implemented | Implemented | Implemented | Linux Authentication | Partial | Missing | Implemented | Partial | Parser tests exist; binary layout support is scoped. |
| `linux_syslog` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Generic syslog parsing; no specialist system-events page. |
| `linux_audit` | Implemented | Implemented | Partial | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Multi-line audit event reconstruction is partial. |
| `linux_shell_history` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Command History / Artifact Explorer | Partial | Missing | Implemented | Partial | Bash/ZSH support exists; timestamps can be file-level/low-confidence. |
| `linux_cron` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | No Linux persistence summary page. |
| `linux_systemd` unit files | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Timer semantics are limited. |
| Binary systemd journal | Partial | Implemented | Missing | Missing | Missing | Missing | Missing | Missing | Missing | Missing | Missing | Explicitly unsupported unless exported as `.export`, JSON, or NDJSON. |
| `linux_ssh` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Full public keys are intentionally not stored; fingerprints/comments are stored. |
| `linux_sudoers` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | Needs privilege-escalation interpretation layer. |
| `linux_packages` | Implemented | Implemented | Partial | Implemented | Implemented | Implemented | Packages / Artifact Explorer | Partial | Missing | Implemented | Partial | Package log support is format-based and partial. |
| `linux_network` | Implemented | Implemented | Implemented | Implemented | Implemented | Implemented | Artifact Explorer | Partial | Missing | Implemented | Partial | No dedicated Linux network capability page. |
| Linux memory image | Implemented | Implemented | Missing | Missing | Implemented as evidence metadata | Implemented as evidence/memory record | Memory evidence pages | Missing | Missing | Partial | Missing | Accepted/preserved, but advanced Linux memory analysis is unavailable. |

## P0 Pipeline Breaks

| Break | Impact |
| --- | --- |
| Real Webserver/VulnOSv2 LVM/ext root validation is not recorded as passing | Cannot prove CTF disk image questions are solvable. |
| Deleted ext filesystem recovery is missing | Any CTF answer relying on deleted files is blocked. |
| Binary journal parsing is missing | Any CTF answer only present in `.journal` files is blocked. |
| Linux memory analysis is missing | Any Victoria memory-only process/network/module question is blocked. |

## P1 Pipeline Weaknesses

| Weakness | Impact |
| --- | --- |
| Search does not expose Linux-specific field syntax/facets for username, command, source IP, hostname | CTFs may be solvable only by knowing raw terms/artifact types. |
| Linux persistence artifacts have no specialist overview | Analysts must manually inspect cron/systemd/ssh/sudoers in Artifact Explorer or Search. |
| Linux audit multi-line reconstruction is partial | Exec/path context can be fragmented. |
