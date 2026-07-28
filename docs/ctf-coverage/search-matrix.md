# Search Matrix

Search is a required independent path. This matrix audits whether an analyst can discover answers without using a specialist page.

| Artifact | Free-text discoverability | Filtering | Important field search | Provenance | Evidence/host/time filters | Source pivot | Status | Required improvement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `linux_auth` | Implemented through `message`/`search_text` | Partial via platform/artifact/host/time | Partial for username/IP because Linux fields are not first-class query builder fields | Implemented | Implemented | Implemented | Partial | Add Linux-aware field aliases for username, source IP, source port, auth result, service. |
| `linux_shell_history` | Implemented through command text/search_text | Partial via platform/artifact/host/time | Partial for `linux.command`/`linux.username` | Implemented | Implemented | Implemented | Partial | Add command/user/source-file field aliases and command-history preset validation. |
| `linux_identity` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for username, uid, gid, shell, home | Implemented | Implemented | Implemented | Partial | Add identity field aliases and useful presets. |
| `linux_sudoers` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for principal/runas/command | Implemented | Implemented | Implemented | Partial | Add sudoers aliases and persistence preset. |
| `linux_cron` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for schedule/user/command | Implemented | Implemented | Implemented | Partial | Add cron aliases and persistence preset. |
| `linux_systemd` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for unit/exec/wanted-by | Implemented | Implemented | Implemented | Partial | Add unit/exec aliases and persistence preset. |
| `linux_ssh` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for key fingerprint/comment/host pattern | Implemented | Implemented | Implemented | Partial | Add SSH aliases and authorized-key preset. |
| `linux_audit` | Implemented through message/search_text | Partial via platform/artifact/host/time | Partial for audit type, command, exe, pid, uid | Implemented | Implemented | Implemented | Partial | Add audit aliases and event reconstruction. |
| `linux_syslog` | Implemented through message/search_text | Partial via platform/artifact/host/time | Partial for process, pid, hostname, severity | Implemented | Implemented | Implemented | Partial | Add syslog aliases and service/system presets. |
| `linux_packages` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for package/action/version/manager | Implemented | Implemented | Implemented | Partial | Add package aliases and install/remove presets. |
| `linux_network` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for address, gateway, DNS, hostname | Implemented | Implemented | Implemented | Partial | Add network config aliases and IP/host presets. |
| `linux_os_info` | Implemented through search_text | Partial via platform/artifact/host/time | Partial for hostname, OS name/version, kernel | Implemented | Implemented | Implemented | Partial | Add OS/host aliases. |
| Linux memory analysis artifacts | Missing | Missing | Missing | Partial evidence metadata only | Partial | Partial | Missing | Implement Linux memory plugin output indexing before Search can be a solve path. |

## Generic Search Requirements For CTF Readiness

| Requirement | Current state | Priority |
| --- | --- | --- |
| `platform=linux` preset from capability registry | Implemented | Done |
| Artifact type filtering for all `linux_*` families | Implemented | Done |
| Query `q` finds Linux messages and normalized values | Partial | P1 |
| Field syntax for `linux.username`, `linux.command`, `linux.source_ip`, `linux.hostname` | Missing as allowlisted first-class syntax | P1 |
| Linux source file pivots in result detail | Partial/implemented through source metadata | P1 |
| Search presets for persistence/auth/package/network questions | Partial | P1 |
| Search regression fixtures for known CTF expected answers | Missing | P0 after answer key confirmation |
