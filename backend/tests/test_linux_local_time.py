"""Zone-less and year-less Linux log times become real UTC times. All data is synthetic."""
from __future__ import annotations

import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.ingest.linux import local_time
from app.ingest.linux.auth import parse_wtmp_btmp
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.local_time import HostClock, resolve_local_times

_UTMP = struct.Struct("hi32s4s32s256shhiii4i20s")


def _utmp(kind: int, user: str, when: datetime, *, line: str = "~", host: str = "", addr: tuple[int, int, int, int] = (0, 0, 0, 0)) -> bytes:
    return _UTMP.pack(kind, 1, line.encode(), b"~~", user.encode(), host.encode(), 0, 0, 0, int(when.timestamp()), 0, *addr, b"")


def _utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=timezone.utc)


def _ipv4_word(address: str) -> int:
    return struct.unpack("=i", bytes(int(octet) for octet in address.split(".")))[0]


@pytest.fixture()
def host(tmp_path: Path) -> Path:
    """A collected filesystem: Brussels time, booted in April 2016 and again in October 2019."""
    local_time._host_clock_for_root.cache_clear()
    (tmp_path / "etc").mkdir()
    (tmp_path / "var" / "log").mkdir(parents=True)
    (tmp_path / "etc" / "timezone").write_text("Europe/Brussels\n")
    (tmp_path / "var" / "log" / "wtmp").write_bytes(
        _utmp(2, "reboot", _utc(2016, 4, 3, 16, 15, 16), host="3.13.0-24-generic")
        + _utmp(7, "admin", _utc(2016, 4, 3, 16, 20, 0), line="pts/0", addr=(_ipv4_word("198.51.100.20"), 0, 0, 0))
        + _utmp(1, "shutdown", _utc(2016, 4, 3, 17, 9, 31))
        + _utmp(2, "reboot", _utc(2019, 10, 5, 9, 41, 55), host="3.13.0-24-generic")
    )
    (tmp_path / "var" / "log" / "btmp").write_bytes(_utmp(6, "root", _utc(2019, 10, 5, 11, 20, 59), line="ssh:notty", addr=(_ipv4_word("203.0.113.9"), 0, 0, 0)))
    (tmp_path / "var" / "log" / "syslog").write_text(
        "Apr  3 18:15:13 web kernel: [    0.000000] Linux version 3.13.0-24-generic\n"
        "Apr  3 18:30:00 web cron[100]: (root) CMD (run-parts /etc/cron.hourly)\n"
        "Oct  5 11:42:10 web kernel: [    0.000000] Linux version 3.13.0-24-generic\n"
        "Oct  5 13:24:04 web sshd[2000]: Failed password for root from 203.0.113.9 port 4000 ssh2\n"
    )
    return tmp_path


def _syslog(host: Path) -> list[dict]:
    return parse_linux_artifact_file(host / "var" / "log" / "syslog", parser="linux_syslog_raw", artifact_type=None, source_path="var/log/syslog")


def test_each_line_gets_the_year_the_machine_was_running_and_true_utc(host):
    rows = _syslog(host)
    assert [row["timestamp"] for row in rows] == [
        "2016-04-03T16:15:13+00:00",   # 18:15:13 Brussels summer time; wtmp says the boot was 16:15:16 UTC
        "2016-04-03T16:30:00+00:00",
        "2019-10-05T09:42:10+00:00",
        "2019-10-05T11:24:04+00:00",
    ]
    assert {row["timestamp_status"] for row in rows} == {"inferred_year_host_timezone"}


def test_winter_time_uses_the_winter_offset(host):
    (host / "var" / "log" / "wtmp").write_bytes(_utmp(2, "reboot", _utc(2016, 1, 10, 8, 0, 0)) + _utmp(1, "shutdown", _utc(2016, 1, 10, 20, 0, 0)))
    (host / "var" / "log" / "btmp").unlink()
    local_time._host_clock_for_root.cache_clear()
    (host / "var" / "log" / "syslog").write_text("Jan 10 09:05:00 web cron[1]: hello\n")
    assert _syslog(host)[0]["timestamp"] == "2016-01-10T08:05:00+00:00"


def test_without_boot_records_the_year_comes_from_the_file_modification_time(tmp_path):
    local_time._host_clock_for_root.cache_clear()
    log = tmp_path / "syslog"
    log.write_text("Dec 30 23:00:00 web cron[1]: a\nJan  2 01:00:00 web cron[1]: b\n")
    stamp = _utc(2017, 1, 3, 12, 0, 0).timestamp()
    os.utime(log, (stamp, stamp))
    rows = parse_linux_artifact_file(log, parser="linux_syslog_raw", artifact_type=None, source_path="var/log/syslog")
    assert [row["timestamp"][:10] for row in rows] == ["2016-12-30", "2017-01-02"]
    assert {row["timestamp_status"] for row in rows} == {"inferred_year"}   # no zone known: still read as UTC


def test_the_zone_of_the_machine_running_kairon_is_never_used(tmp_path, monkeypatch):
    # A collection without /etc must not pick up the analysis machine's own /etc further up.
    local_time._host_clock_for_root.cache_clear()
    monkeypatch.setattr(local_time, "_is_outside_evidence", lambda candidate: candidate == tmp_path)
    (tmp_path / "etc").mkdir()
    (tmp_path / "var").mkdir()
    (tmp_path / "etc" / "timezone").write_text("Asia/Tokyo\n")
    log = tmp_path / "collection" / "var" / "log" / "syslog"
    log.parent.mkdir(parents=True)
    log.write_text("x")
    assert local_time.host_clock_for(log).zone is None


def test_a_few_lines_out_of_order_are_not_a_new_year():
    clock = HostClock()
    rows = [{"timestamp": "2026-03-10T10:00:05+00:00", "timestamp_status": "assumed_year_utc"},
            {"timestamp": "2026-03-10T10:00:00+00:00", "timestamp_status": "assumed_year_utc"}]
    resolve_local_times(rows, reference=_utc(2020, 6, 1, 0, 0, 0), clock=clock)
    assert [row["timestamp"][:4] for row in rows] == ["2020", "2020"]


def test_zone_less_logs_with_a_year_get_the_host_zone(host):
    (host / "var" / "log" / "mysql").mkdir()
    (host / "var" / "log" / "mysql" / "error.log").write_text("160403 19:02:55 [Note] Plugin 'FEDERATED' is disabled.\n160403 19:02:55 InnoDB: Completed init\nInnoDB: a continuation\n")
    rows = parse_linux_artifact_file(host / "var" / "log" / "mysql" / "error.log", parser="linux_database_raw", artifact_type=None, source_path="var/log/mysql/error.log")
    assert [(row["timestamp"], row["timestamp_status"]) for row in rows] == [
        ("2016-04-03T17:02:55+00:00", "host_timezone"), ("2016-04-03T17:02:55+00:00", "host_timezone"), (None, "missing")]
    assert rows[0]["db_level"] == "note" and rows[1]["message"] == "InnoDB: Completed init"


def test_without_a_known_zone_zone_less_times_stay_marked_utc(tmp_path):
    local_time._host_clock_for_root.cache_clear()
    rows = [{"timestamp": "2016-04-03T19:02:55+00:00", "timestamp_status": "assumed_utc"}]
    resolve_local_times(rows, reference=_utc(2016, 5, 1, 0, 0, 0), clock=HostClock())
    assert rows == [{"timestamp": "2016-04-03T19:02:55+00:00", "timestamp_status": "assumed_utc"}]


def test_the_zone_can_come_from_the_localtime_binary(tmp_path):
    local_time._host_clock_for_root.cache_clear()
    zoneinfo_file = Path("/usr/share/zoneinfo/Europe/Brussels")
    if not zoneinfo_file.exists():
        pytest.skip("no system zoneinfo to copy a TZif file from")
    (tmp_path / "etc").mkdir()
    (tmp_path / "var" / "log").mkdir(parents=True)
    (tmp_path / "etc" / "localtime").write_bytes(zoneinfo_file.read_bytes())
    clock = local_time.host_clock_for(tmp_path / "var" / "log" / "syslog")
    rows = [{"timestamp": "2016-07-01T12:00:00+00:00", "timestamp_status": "assumed_utc"}]
    resolve_local_times(rows, reference=_utc(2016, 8, 1, 0, 0, 0), clock=clock)
    assert rows[0]["timestamp"] == "2016-07-01T10:00:00+00:00"


# ------------------------------------------------------------------ login records

def test_wtmp_and_btmp_from_a_disk_image_are_read_as_binary(host):
    for name in ("wtmp", "btmp"):
        assert looks_like_linux_artifact(f"volume-1/linux/var/log/{name}")[1] == name
    # A disk image hands the coarse family as the artifact type; the file name decides.
    rows = parse_linux_artifact_file(host / "var" / "log" / "btmp", parser="linux_auth_raw", artifact_type="linux_auth", source_path="var/log/btmp")
    assert [(row["event_action"], row["username"], row["source_ip"]) for row in rows] == [("login_failure", "root", "203.0.113.9")]


def test_login_records_name_boots_shutdowns_and_logins(host):
    rows = parse_wtmp_btmp((host / "var" / "log" / "wtmp").read_bytes(), source_path="var/log/wtmp")
    assert [row["event_action"] for row in rows] == ["system_boot", "login_success", "system_shutdown", "system_boot"]
    assert rows[0]["message"] == "wtmp system boot (kernel 3.13.0-24-generic)"
    assert rows[1]["source_ip"] == "198.51.100.20"   # high bit set: negative as a signed int


def test_an_ipv6_source_is_formatted():
    words = struct.unpack("=4i", bytes.fromhex("20010db8000000000000000000000001"))
    record = _utmp(7, "admin", _utc(2020, 1, 1, 0, 0, 0), line="pts/1", addr=words)
    assert parse_wtmp_btmp(record, source_path="var/log/wtmp")[0]["source_ip"] == "2001:db8::1"


# ------------------------------------------------------------------ other fixes

def test_installer_syslog_lines_without_a_host_are_dated(tmp_path):
    local_time._host_clock_for_root.cache_clear()
    log = tmp_path / "syslog"
    log.write_text("Apr  3 16:07:14 in-target: Setting up linux-headers-generic (3.13.0.24.28) ...\n")
    row = parse_linux_artifact_file(log, parser="linux_syslog_raw", artifact_type=None, source_path="var/log/installer/syslog")[0]
    assert row["timestamp"] is not None and row["process"] == "in-target" and row["message"].startswith("Setting up")


def test_the_dpkg_backup_database_is_not_parsed_twice():
    assert looks_like_linux_artifact("volume-1/linux/var/lib/dpkg/status")[0] == "linux_packages"
    assert looks_like_linux_artifact("volume-1/linux/var/lib/dpkg/status-old") is None


def test_disk_image_extraction_keeps_the_file_times(tmp_path):
    from app.disk_images.service import _preserve_file_times

    target = tmp_path / "syslog"
    target.write_text("x")
    _preserve_file_times(target, SimpleNamespace(mtime=int(_utc(2016, 5, 4, 17, 0, 0).timestamp()), atime=0))
    assert datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc) == _utc(2016, 5, 4, 17, 0, 0)
    _preserve_file_times(target, SimpleNamespace(mtime=None, atime=None))   # no time known: left alone
