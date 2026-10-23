"""Package manager history and installed-package databases (app.ingest.linux.packages).

The sample lines are copied from files written by the real tools (apt 2.8, dpkg 1.22, yum 3.4,
dnf 4.14, dnf5, pacman 7, zypper 1.14, apk 2.14); the SQLite tables use the tools' own schemas.
"""
from __future__ import annotations

import sqlite3
import struct

import pytest

from app.ingest.linux import local_time
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.packages import parse_package_database, parse_packages, parse_rpm_header, split_nevra


def _by_action(rows, action):
    return [row for row in rows if row["action"] == action]


# ------------------------------------------------------------------ routing

@pytest.mark.parametrize(
    ("path", "artifact_type"),
    [
        ("var/log/dpkg.log", "dpkg_log"),
        ("var/log/apt/history.log.1.gz", "apt_history"),
        ("var/lib/dpkg/status", "dpkg_status"),
        ("var/log/yum.log", "yum_log"),
        ("var/log/dnf.log", "dnf_log"),
        ("var/log/dnf.rpm.log", "dnf_rpm_log"),
        ("var/log/dnf5.log", "dnf5_log"),
        ("var/log/pacman.log", "pacman_log"),
        ("var/lib/pacman/local/nano-9.2-1/desc", "pacman_local"),
        ("var/log/zypp/history", "zypper_history"),
        ("var/log/zypp/history-20240101.xz", "zypper_history"),
        ("lib/apk/db/installed", "apk_installed"),
        ("etc/apk/world", "apk_world"),
        ("etc/apk/repositories", "apk_repositories"),
        ("var/lib/dnf/history.sqlite", "dnf_history"),
        ("usr/lib/sysimage/libdnf5/transaction_history.sqlite", "dnf5_history"),
        ("var/lib/yum/history/history-2024-01-21.sqlite", "yum_history"),
        ("var/lib/rpm/rpmdb.sqlite", "rpmdb"),
        ("usr/lib/sysimage/rpm/rpmdb.sqlite", "rpmdb"),
    ],
)
def test_package_artifacts_are_routed(path, artifact_type):
    assert looks_like_linux_artifact(f"volume-1/{path}") == ("linux_packages", artifact_type, "linux_packages_raw")


def test_unrelated_files_with_similar_names_are_not_packages():
    assert looks_like_linux_artifact("var/lib/pacman/local/nano-9.2-1/files") is None
    assert looks_like_linux_artifact("var/lib/rpm/rpmdb.sqlite-shm") is None
    assert looks_like_linux_artifact("var/lib/dnf/history.sqlite-wal") is None


# ------------------------------------------------------------------ dpkg / apt

APT_HISTORY = """
Start-Date: 2026-09-17  02:17:09
Commandline: apt-get --yes dist-upgrade
Install: libdb5.3t64:arm64 (5.3.28+dfsg2-7, automatic)
Upgrade: libpam-modules:arm64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.7), libpam-modules-bin:arm64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.7)
End-Date: 2026-09-17  02:17:10

Start-Date: 2026-10-23  18:14:08
Commandline: apt-get install -y nano
Requested-By: ubuntu (1000)
Install: nano:arm64 (7.2-2ubuntu0.2)
End-Date: 2026-10-23  18:14:08

Start-Date: 2026-10-23  18:20:00
Commandline: apt-get install -y nmap
Requested-By: ubuntu (1000)
Error: Sub-process /usr/bin/dpkg returned an error code (1)
End-Date: 2026-10-23  18:20:01
"""


def test_apt_history_gives_one_row_per_package_with_command_and_user():
    rows = parse_packages(APT_HISTORY, source_path="var/log/apt/history.log")
    assert [(row["action"], row["package"]) for row in rows] == [
        ("install", "libdb5.3t64:arm64"),
        ("upgrade", "libpam-modules:arm64"),
        ("upgrade", "libpam-modules-bin:arm64"),
        ("install", "nano:arm64"),
        ("error", None),
    ]
    dependency, upgrade, _, nano, error = rows
    assert dependency["package_reason"] == "automatic" and dependency["version"] == "5.3.28+dfsg2-7"
    assert (upgrade["previous_version"], upgrade["version"]) == ("1.5.3-5ubuntu5", "1.5.3-5ubuntu5.7")
    assert upgrade["command"] == "apt-get --yes dist-upgrade" and upgrade["username"] is None
    assert (nano["username"], nano["uid"], nano["command"]) == ("ubuntu", 1000, "apt-get install -y nano")
    assert nano["timestamp"] == "2026-10-23T18:14:08+00:00" and nano["timestamp_status"] == "assumed_utc"
    assert error["package_status"] == "error" and "dpkg returned an error" in error["message"]
    assert error["username"] == "ubuntu" and error["command"] == "apt-get install -y nmap"


def test_apt_term_log_rows_take_the_run_time_and_skip_progress_lines():
    content = (
        "\nLog started: 2026-10-23  18:14:08\nSelecting previously unselected package nano.\n"
        "(Reading database ... 5%(Reading database ... 100%\n"
        "Preparing to unpack .../nano_7.2-2ubuntu0.2_arm64.deb ...\nUnpacking nano (7.2-2ubuntu0.2) ...\n"
        "Setting up nano (7.2-2ubuntu0.2) ...\nLog ended: 2026-10-23  18:14:08\n"
    )
    rows = parse_packages(content, source_path="var/log/apt/term.log")
    assert [(row["action"], row.get("package")) for row in rows] == [("output", None), ("unpack", "nano"), ("configure", "nano")]
    assert {row["timestamp"] for row in rows} == {"2026-10-23T18:14:08+00:00"}


def test_dpkg_status_gives_one_row_per_package_not_per_line():
    content = (
        "Package: apt\nStatus: install ok installed\nPriority: important\nArchitecture: arm64\nVersion: 2.8.3\n"
        "Conffiles:\n /etc/apt/apt.conf.d/01autoremove 879455db9b938ce287b23383629aedce\n"
        "Description: commandline package manager\n This package provides commandline tools\n .\n\n"
        "Package: zsh\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 5.8-6\n\n"
        "Package: tzdata\nStatus: install ok installed\nArchitecture: all\nVersion: 2024a-0ubuntu1\n"
    )
    rows = parse_packages(content, source_path="var/lib/dpkg/status")
    assert [(row["package"], row["action"], row["version"]) for row in rows] == [
        ("apt:arm64", "installed", "2.8.3"),
        ("zsh:amd64", "config-files", "5.8-6"),
        ("tzdata", "installed", "2024a-0ubuntu1"),
    ]
    assert rows[1]["package_status"] == "deinstall ok config-files" and rows[0]["timestamp"] is None


def test_dpkg_log_local_times_are_converted_with_the_host_zone(tmp_path):
    local_time._host_clock_for_root.cache_clear()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "timezone").write_text("Europe/Madrid\n")
    log = tmp_path / "var" / "log" / "dpkg.log"
    log.parent.mkdir(parents=True)
    log.write_text("2024-07-10 14:23:01 install nginx:amd64 <none> 1.18.0-0ubuntu1.4\n")
    row = parse_linux_artifact_file(log, parser="linux_packages_raw", artifact_type="linux_packages", source_path="var/log/dpkg.log")[0]
    assert row["timestamp"] == "2024-07-10T12:23:01+00:00" and row["timestamp_status"] == "host_timezone"
    assert (row["package"], row["previous_version"], row["version"], row["package_arch"]) == ("nginx:amd64", None, "1.18.0-0ubuntu1.4", "amd64")


# ------------------------------------------------------------------ yum / dnf

def test_split_nevra_handles_both_epoch_placements():
    assert split_nevra("1:mariadb-libs-5.5.68-1.el7.x86_64") == ("mariadb-libs", "1:5.5.68-1.el7", "x86_64")
    assert split_nevra("openssl-libs-1:3.0.7-25.el9_3.x86_64") == ("openssl-libs", "1:3.0.7-25.el9_3", "x86_64")
    assert split_nevra("nano-0:8.7.1-2.fc44.aarch64") == ("nano", "8.7.1-2.fc44", "aarch64")


def test_yum_log_names_the_package_not_the_action():
    rows = parse_packages(
        "Oct 23 18:14:08 Installed: nano-2.9.8-2.amzn2.0.2.aarch64\nOct 23 18:14:09 Updated: 1:openssl-1.0.2k-21.el7_9.x86_64\n"
        "Oct 23 18:14:10 Erased: nano-2.9.8-2.amzn2.0.2.aarch64\n",
        source_path="var/log/yum.log",
    )
    assert [(row["action"], row["package"], row["version"]) for row in rows] == [
        ("install", "nano", "2.9.8-2.amzn2.0.2"),
        ("upgrade", "openssl", "1:1.0.2k-21.el7_9"),
        ("remove", "nano", "2.9.8-2.amzn2.0.2"),
    ]
    assert rows[0]["timestamp_status"] == "assumed_year_utc"


def test_dnf_rpm_log_actions_have_exact_times():
    rows = parse_packages(
        "2026-10-23T18:14:01+0000 INFO --- logging initialized ---\n"
        "2026-10-23T18:14:13+0000 SUBDEBUG Installed: nano-5.6.1-7.el9.aarch64\n"
        "2026-10-23T20:14:13+0200 SUBDEBUG Upgrade: openssl-libs-1:3.0.7-25.el9_3.x86_64\n"
        "2026-10-23T18:14:13+0000 SUBDEBUG Erase: nano-5.6.1-7.el9.aarch64\n",
        source_path="var/log/dnf.rpm.log",
    )
    assert [(row["action"], row["package"]) for row in rows] == [("install", "nano"), ("upgrade", "openssl-libs"), ("remove", "nano")]
    assert rows[1]["timestamp"] == "2026-10-23T18:14:13+00:00" and rows[1]["timestamp_status"] == "ok"


def test_dnf_log_keeps_only_command_lines():
    rows = parse_packages(
        "2026-10-23T18:14:01+0000 DDEBUG timer: config: 8 ms\n2026-10-23T18:14:01+0000 DDEBUG Command: dnf -y install nano \n"
        "2026-10-23T18:14:01+0000 DEBUG repo: downloading from remote: baseos\n",
        source_path="var/log/dnf.log",
    )
    assert [(row["action"], row["command"]) for row in rows] == [("command", "dnf -y install nano")]


def test_dnf5_log_commands_and_rpm_callbacks():
    rows = parse_packages(
        '2026-10-23T18:14:01+0000 [7] INFO --- DNF5 launched with arguments: "dnf -y install nano" ---\n'
        '2026-10-23T18:14:14+0000 [7] INFO RPM callback install start "nano-0:8.7.1-2.fc44.aarch64" total 3067096\n'
        '2026-10-23T18:14:14+0000 [7] INFO RPM callback install stop "nano-0:8.7.1-2.fc44.aarch64" amount 1 total 1\n'
        '2026-10-23T18:14:14+0000 [1] INFO RPM callback uninstall start "nano-0:8.7.1-2.fc44.aarch64" total 107\n',
        source_path="var/log/dnf5.log",
    )
    assert [(row["action"], row.get("package"), row.get("command")) for row in rows] == [
        ("command", None, "dnf -y install nano"), ("install", "nano", None), ("remove", "nano", None),
    ]


# ------------------------------------------------------------------ pacman / zypper / apk

def test_pacman_log_new_and_old_formats():
    rows = parse_packages(
        "[2026-10-23T18:15:47+0000] [PACMAN] Running 'pacman -S --noconfirm nano'\n"
        "[2026-10-23T18:15:47+0000] [ALPM] transaction started\n"
        "[2026-10-23T18:15:47+0000] [ALPM] installed nano (9.2-1)\n"
        "[2026-10-23T18:15:47+0000] [ALPM-SCRIPTLET] Generating locales...\n"
        "[2019-01-21 10:00] [ALPM] upgraded linux (4.20.1-1 -> 4.20.3-1)\n"
        "[2012-04-11 10:28] removed foo (1.0-1)\n",
        source_path="var/log/pacman.log",
    )
    assert [row["action"] for row in rows] == ["command", "log", "install", "output", "upgrade", "remove"]
    assert rows[0]["command"] == "pacman -S --noconfirm nano"
    assert (rows[4]["previous_version"], rows[4]["version"]) == ("4.20.1-1", "4.20.3-1")
    assert rows[2]["timestamp_status"] == "ok" and rows[4]["timestamp"] == "2019-01-21T10:00:00+00:00"
    assert rows[4]["timestamp_status"] == "assumed_utc" and rows[5]["package"] == "foo"


def test_pacman_local_desc_install_date_and_reason():
    desc = "%NAME%\nnano\n\n%VERSION%\n9.2-1\n\n%ARCH%\nx86_64\n\n%INSTALLDATE%\n1792779347\n\n%REASON%\n1\n"
    row = parse_packages(desc, source_path="var/lib/pacman/local/nano-9.2-1/desc")[0]
    assert (row["package"], row["version"], row["package_reason"]) == ("nano", "9.2-1", "dependency")
    assert row["timestamp"] == "2026-10-23T18:15:47+00:00"


def test_zypper_history_actions_commands_and_repositories():
    rows = parse_packages(
        "2026-10-23 18:14:01|radd   |util|https://download.opensuse.org/repositories/utilities/15.6/|\n"
        "2026-10-23 18:14:40|command|root@553fe85cbf4d|'zypper' '-n' '--gpg-auto-import-keys' 'in' 'nano'|\n"
        "# 2026-10-23 18:14:40 nano-7.2-bp156.3.3.1.aarch64.rpm installed ok\n"
        "2026-10-23 18:14:40|install|nano|7.2-bp156.3.3.1|aarch64|root@553fe85cbf4d|repo-backports-update|4d635af32d2a|\n"
        "2026-10-23 18:14:40|patch  |openSUSE-2024-157|1|noarch|repo-backports-update|important|security|not-needed|applied|\n"
        "2026-10-23 18:14:40|remove |nano|7.2-bp156.3.3.1|aarch64|root@553fe85cbf4d|\n",
        source_path="var/log/zypp/history",
    )
    assert [row["action"] for row in rows] == ["repo_add", "command", "install", "patch", "remove"]
    repo, command, install, patch, remove = rows
    assert (repo["package_repository"], repo["repository_url"]) == ("util", "https://download.opensuse.org/repositories/utilities/15.6/")
    assert (command["username"], command["command"]) == ("root", "zypper -n --gpg-auto-import-keys in nano")
    assert (install["package"], install["version"], install["package_repository"], install["username"]) == ("nano", "7.2-bp156.3.3.1", "repo-backports-update", "root")
    assert patch["package_status"] == "applied" and remove["timestamp_status"] == "assumed_utc"


def test_apk_installed_world_and_repositories():
    installed = parse_packages(
        "C:Q1R9ZP0tsvI8T8g9RLcTlCnsFt8l4=\nP:alpine-baselayout\nV:3.6.5-r0\nA:aarch64\nt:1714981135\nF:etc\nR:motd\n\n"
        "C:Q1abc=\nP:nano\nV:8.0-r0\nA:aarch64\n",
        source_path="lib/apk/db/installed",
    )
    assert [(row["package"], row["version"], row["package_arch"]) for row in installed] == [
        ("alpine-baselayout", "3.6.5-r0", "aarch64"), ("nano", "8.0-r0", "aarch64"),
    ]
    world = parse_packages("alpine-baselayout\nnano>=8.0\nfoo@testing\n", source_path="etc/apk/world")
    assert [row["package"] for row in world] == ["alpine-baselayout", "nano", "foo"]
    repositories = parse_packages(
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n#http://disabled/\n@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing\n",
        source_path="etc/apk/repositories",
    )
    assert [(row.get("package_repository"), row["repository_url"]) for row in repositories] == [
        (None, "https://dl-cdn.alpinelinux.org/alpine/v3.20/main"),
        ("@testing", "https://dl-cdn.alpinelinux.org/alpine/edge/testing"),
    ]


# ------------------------------------------------------------------ SQLite databases

def _database(path, statements):
    connection = sqlite3.connect(path)
    connection.executescript(statements)
    connection.commit()
    connection.close()
    return path


PASSWD = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"


def test_dnf4_history_with_user_command_repo_and_reason(tmp_path):
    db = _database(tmp_path / "history.sqlite", """
        CREATE TABLE trans (id INTEGER PRIMARY KEY, dt_begin INTEGER NOT NULL, dt_end INTEGER, rpmdb_version_begin TEXT,
            rpmdb_version_end TEXT, releasever TEXT NOT NULL, user_id INTEGER NOT NULL, cmdline TEXT, state INTEGER NOT NULL, comment TEXT DEFAULT '');
        CREATE TABLE repo (id INTEGER PRIMARY KEY, repoid TEXT NOT NULL);
        CREATE TABLE item (id INTEGER PRIMARY KEY, item_type INTEGER NOT NULL);
        CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER, item_id INTEGER, repo_id INTEGER, action INTEGER NOT NULL, reason INTEGER NOT NULL, state INTEGER NOT NULL);
        CREATE TABLE rpm (item_id INTEGER UNIQUE NOT NULL, name TEXT NOT NULL, epoch INTEGER NOT NULL, version TEXT NOT NULL, release TEXT NOT NULL, arch TEXT NOT NULL);
        INSERT INTO trans VALUES (1, 1792779253, 1792779253, 'a', 'b', '9', 1000, 'install nmap', 1, '');
        INSERT INTO trans VALUES (2, 1792779300, 1792779300, 'b', 'a', '9', -1, '-y remove nmap', 1, '');
        INSERT INTO repo VALUES (1, 'baseos'), (2, '@System');
        INSERT INTO item VALUES (1, 1);
        INSERT INTO rpm VALUES (1, 'nmap', 3, '7.92', '1.el9', 'x86_64');
        INSERT INTO trans_item VALUES (1, 1, 1, 1, 1, 2, 1), (2, 2, 1, 2, 8, 2, 1);
    """)
    rows = parse_package_database(db, source_path="var/lib/dnf/history.sqlite", passwd_content=PASSWD)
    install, remove = rows
    assert (install["action"], install["package"], install["version"], install["package_repository"]) == ("install", "nmap", "3:7.92-1.el9", "baseos")
    assert (install["uid"], install["username"], install["command"], install["package_reason"]) == (1000, "alice", "install nmap", "user")
    assert install["timestamp"] == "2026-10-23T18:14:13+00:00" and install["transaction_id"] == 1
    assert remove["action"] == "remove" and remove.get("uid") is None  # -1: no audit login UID recorded


def test_dnf5_history_uses_the_lookup_tables(tmp_path):
    db = _database(tmp_path / "transaction_history.sqlite", """
        CREATE TABLE trans_state (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE trans (id INTEGER PRIMARY KEY, dt_begin INTEGER NOT NULL, dt_end INTEGER, rpmdb_version_begin TEXT, rpmdb_version_end TEXT,
            releasever TEXT NOT NULL, user_id INTEGER NOT NULL, description TEXT, comment TEXT, state_id INTEGER);
        CREATE TABLE repo (id INTEGER PRIMARY KEY, repoid TEXT NOT NULL);
        CREATE TABLE pkg_name (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE arch (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE trans_item_action (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE trans_item_reason (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE trans_item_state (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER, item_id INTEGER, repo_id INTEGER, action_id INTEGER NOT NULL, reason_id INTEGER NOT NULL, state_id INTEGER NOT NULL);
        CREATE TABLE rpm (item_id INTEGER NOT NULL UNIQUE, name_id INTEGER NOT NULL, epoch INTEGER NOT NULL, version TEXT NOT NULL, release TEXT NOT NULL, arch_id INTEGER NOT NULL);
        INSERT INTO trans_state VALUES (1, 'Started'), (2, 'Ok'), (3, 'Error');
        INSERT INTO trans_item_action VALUES (1, 'Install'), (5, 'Remove'), (7, 'Reason Change');
        INSERT INTO trans_item_reason VALUES (1, 'Dependency'), (2, 'User');
        INSERT INTO trans_item_state VALUES (1, 'Started'), (2, 'Ok'), (3, 'Error');
        INSERT INTO trans VALUES (3, 1792779254, 1792779254, 'a', 'b', '44', 0, 'dnf -y install nano', '', 2);
        INSERT INTO repo VALUES (1, 'updates');
        INSERT INTO pkg_name VALUES (1, 'nano');
        INSERT INTO arch VALUES (1, 'aarch64');
        INSERT INTO rpm VALUES (1, 1, 0, '8.7.1', '2.fc44', 1);
        INSERT INTO trans_item VALUES (1, 3, 1, 1, 1, 2, 1);
    """)
    row = parse_package_database(db, source_path="usr/lib/sysimage/libdnf5/transaction_history.sqlite", passwd_content=PASSWD)[0]
    assert (row["action"], row["package"], row["version"], row["package_arch"]) == ("install", "nano", "8.7.1-2.fc44", "aarch64")
    assert (row["username"], row["command"], row["package_status"], row["package_reason"]) == ("root", "dnf -y install nano", "ok", "user")


def test_yum_history_states_and_unset_login_uid(tmp_path):
    db = _database(tmp_path / "history-2026-10-23.sqlite", """
        CREATE TABLE trans_beg (tid INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, rpmdb_version TEXT NOT NULL, loginuid INTEGER);
        CREATE TABLE trans_end (tid INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, rpmdb_version TEXT NOT NULL, return_code INTEGER NOT NULL);
        CREATE TABLE trans_data_pkgs (tid INTEGER NOT NULL, pkgtupid INTEGER NOT NULL, done BOOL NOT NULL DEFAULT FALSE, state TEXT NOT NULL);
        CREATE TABLE pkgtups (pkgtupid INTEGER PRIMARY KEY, name TEXT NOT NULL, arch TEXT NOT NULL, epoch TEXT NOT NULL, version TEXT NOT NULL, release TEXT NOT NULL, checksum TEXT);
        CREATE TABLE trans_cmdline (tid INTEGER NOT NULL, cmdline TEXT NOT NULL);
        INSERT INTO trans_beg VALUES (1, 1792779248, 'x', 4294967295), (2, 1792779300, 'y', 1000);
        INSERT INTO trans_end VALUES (1, 1792779248, 'y', 0), (2, 1792779301, 'z', 1);
        INSERT INTO pkgtups VALUES (1, 'nano', 'aarch64', '0', '2.9.8', '2.amzn2.0.2', NULL), (2, 'ncat', 'x86_64', '2', '6.40', '7.el7', NULL);
        INSERT INTO trans_data_pkgs VALUES (1, 1, 'TRUE', 'Install'), (2, 2, 'TRUE', 'Dep-Install');
        INSERT INTO trans_cmdline VALUES (1, '-y install nano'), (2, 'install ncat');
    """)
    first, second = parse_package_database(db, source_path="var/lib/yum/history/history-2026-10-23.sqlite", passwd_content=PASSWD)
    assert (first["action"], first["command"], first["package_status"]) == ("install", "-y install nano", "done") and first.get("uid") is None
    assert (second["package"], second["version"], second["package_reason"], second["username"], second["package_status"]) == (
        "ncat", "2:6.40-7.el7", "dependency", "alice", "error",
    )


def _rpm_header(tags):
    """An rpmdb header blob: entry count, data size, 16-byte index entries, then the data store."""
    entries, data = b"", b""
    for tag, value in tags.items():
        if isinstance(value, int):
            while len(data) % 4:
                data += b"\x00"
            entries += struct.pack(">IIII", tag, 4, len(data), 1)
            data += struct.pack(">I", value)
        else:
            entries += struct.pack(">IIII", tag, 6, len(data), 1)
            data += value.encode() + b"\x00"
    return struct.pack(">II", len(tags), len(data)) + entries + data


def test_rpmdb_install_times_from_header_blobs(tmp_path):
    blob = _rpm_header({1000: "less", 1001: "590", 1002: "2.el9_2", 1022: "aarch64", 1008: 1700432743, 1011: "Rocky Enterprise Software Foundation"})
    assert parse_rpm_header(blob)[1008] == 1700432743
    db = tmp_path / "rpmdb.sqlite"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    connection.execute("INSERT INTO Packages (blob) VALUES (?)", (blob,))
    connection.execute("INSERT INTO Packages (blob) VALUES (?)", (b"\x00\x00",))  # damaged: skipped
    connection.commit()
    connection.close()
    before = db.read_bytes()
    rows = parse_package_database(db, source_path="var/lib/rpm/rpmdb.sqlite")
    assert [(row["package"], row["version"], row["timestamp"]) for row in rows] == [("less", "590-2.el9_2", "2023-11-19T22:25:43+00:00")]
    assert rows[0]["package_vendor"] == "Rocky Enterprise Software Foundation"
    assert db.read_bytes() == before  # read from a private copy


def test_package_database_dispatch_reads_the_write_ahead_log(tmp_path):
    root = tmp_path / "evidence"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(PASSWD)
    db = root / "var" / "lib" / "rpm" / "rpmdb.sqlite"
    db.parent.mkdir(parents=True)
    writer = sqlite3.connect(db)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    writer.execute("INSERT INTO Packages (blob) VALUES (?)", (_rpm_header({1000: "nmap", 1001: "7.92", 1002: "1", 1008: 1700432743}),))
    writer.commit()
    assert (db.parent / "rpmdb.sqlite-wal").stat().st_size > 0
    rows = parse_linux_artifact_file(db, parser="linux_packages_raw", artifact_type="linux_packages", source_path="var/lib/rpm/rpmdb.sqlite")
    writer.close()
    assert [row["package"] for row in rows] == ["nmap"]


def test_an_unknown_schema_yields_no_rows(tmp_path):
    db = _database(tmp_path / "history.sqlite", "CREATE TABLE something (id INTEGER);")
    assert parse_package_database(db, source_path="var/lib/dnf/history.sqlite") == []


def test_zypper_history_is_not_taken_for_a_browser_history(tmp_path):
    """Chrome's ``History`` is SQLite; zypper's text ``history`` must reach the package parser."""
    from app.ingest.detector import classify_artifact

    zypper = tmp_path / "var" / "log" / "zypp" / "history"
    zypper.parent.mkdir(parents=True)
    zypper.write_text("2026-10-23 18:14:40|install|nano|7.2-bp156.3.3.1|aarch64|root@h|repo-oss|abc|\n")
    chrome = tmp_path / "home" / "a" / ".config" / "google-chrome" / "Default" / "History"
    chrome.parent.mkdir(parents=True)
    connection = sqlite3.connect(chrome)
    connection.execute("CREATE TABLE urls (id INTEGER)")
    connection.commit()
    connection.close()
    assert classify_artifact(zypper)["parser"] == "linux_packages_raw"
    assert classify_artifact(chrome)["parser"] == "browser_chromium_history"


@pytest.mark.parametrize("source_path", ["var/log/zypp/history", "history", "/staging/gone/var/log/zypp/history"])
def test_a_linux_package_row_is_never_normalized_as_a_browser_record(source_path):
    from app.ingest.normalizer import normalize_row

    row = parse_packages(
        "2026-10-23 18:14:40|install|nano|7.2-bp156.3.3.1|aarch64|root@h|repo-oss|abc|\n", source_path="var/log/zypp/history",
    )[0]
    meta = {"artifact_type": "linux_packages", "artifact_family": "linux_packages", "parser": "linux_packages_raw", "source_path": source_path, "name": "history"}
    doc = normalize_row("case-1", "ev-1", "art-1", row, meta)
    assert doc["linux"]["artifact_family"] == "linux_packages" and doc["linux"]["package"] == "nano"
    assert doc["event"]["category"] != "web"
