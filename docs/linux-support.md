# Linux Support

This page describes what Kairon actually does with Linux evidence today.
See [`docs/KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) for the
cross-cutting limitations list and [`docs/parser-coverage.md`](parser-coverage.md)
for per-family detail.

## Evidence ingestion

Linux evidence arrives as a ZIP or TAR container (including `.tar.gz` and
`.tar.xz`) — either a manual triage collection or a Velociraptor ZIP — and
is extracted and normalized by the same archive-ingestion pipeline used
for Windows evidence. Auto-Discovery walks the extracted tree and
recognizes conventional Linux triage layouts (`var/log/`, `etc/`, user
home directories) without requiring an operator to hand-map file paths.

Recognized artifact families include:

- **Authentication** — `auth.log`/`secure` (SSH accepted/failed, sudo,
  su, PAM sessions)
- **Syslog** — `syslog`, `messages`, `kern.log`
- **Audit** — `audit.log` (SYSCALL, EXECVE, USER_AUTH, USER_LOGIN, PATH)
- **Shell history** — `.bash_history`, `.zsh_history`
- **Cron** — `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/*`
- **Systemd** — `.service`/`.timer` unit files
- **SSH** — `authorized_keys`, `known_hosts`, `ssh_config`, `sshd_config`
  (key fingerprints only; full public keys are never stored)
- **Identity** — `/etc/passwd`, `/etc/group` (shadow hashes are never
  stored, only their presence is noted)
- **Sudoers** — `/etc/sudoers` and `/etc/sudoers.d/*`
- **Package logs** — `dpkg.log`, `yum.log`, `dnf.log`
- **Network config** — `/etc/hosts`, `/etc/resolv.conf`,
  `/etc/network/interfaces`, netplan YAML
- **OS info** — `/etc/os-release`, `/etc/hostname`, `/proc/version`

All of these feed Search, and most feed the case Timeline; see
`docs/data/parser-coverage.json` for the exact fields and per-family
Coverage status (`stable`/`partial`/`experimental`).

## Linux Memory

Linux memory images (`.vmem`, `.mem`, `.raw`, `.lime`) are accepted,
hashed, and analyzed via Volatility 3. Supported plugins today are
process listing (`linux.pslist`, `linux.pstree`), network connections
(`linux.sockstat`), and shell command history recovered from process
memory (`linux.bash`). Volatility's Linux memory profile support depends
on matching debug symbols (ISF) for the exact kernel; Kairon resolves
these automatically where possible and surfaces a clear symbol-missing
state when it cannot.

Kairon does not provide full advanced Linux memory analysis yet — plugins
covering kernel modules, handles, loaded libraries, and broader memory
forensics beyond process/network/shell-history are not yet wired up, the
same way they are for Windows.

## Known gaps

- Full-disk Linux filesystem/inode-level analysis (equivalent to Windows
  MFT parsing) is not available yet.
- Advanced Linux memory forensics beyond process/network/shell-history is
  not available yet.
- `linux.sockstat` walks every thread's file-descriptor table and can
  take several minutes on memory images with many processes; it runs
  under a generous but finite timeout rather than indefinitely.
