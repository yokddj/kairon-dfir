"""Generic Linux timezone discovery, parsing, TZif validation and
normalization -- the first Host Facts consumer.

Uses the real system zoneinfo database (present on both the CI runner and
local dev machines -- see zoneinfo.TZPATH) for TZif exact-match assertions,
so these tests exercise the real matching path rather than a mock.
"""
import struct
from pathlib import Path

import pytest

from app.ingest.linux.timezone import (
    match_tzif_to_zone_name,
    parse_timezone,
)


def _real_tzif(zone: str) -> bytes:
    import zoneinfo
    for candidate in zoneinfo.TZPATH:
        path = Path(candidate) / zone
        if path.is_file():
            return path.read_bytes()
    pytest.skip(f"system zoneinfo database does not have {zone}")


class TestEtcTimezone:
    def test_valid_iana_name(self):
        rows = parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        assert rows[0]["artifact_family"] == "linux_timezone"
        assert rows[0]["artifact_type"] == "etc_timezone"
        assert rows[0]["fact_type"] == "host.timezone"
        assert rows[0]["normalized_value"] == "Europe/Madrid"
        assert rows[0]["confidence"] == "high"
        assert rows[0]["parse_status"] == "valid"

    def test_bare_utc(self):
        rows = parse_timezone("UTC\n", source_path="etc/timezone")
        assert rows[0]["normalized_value"] == "UTC"
        assert rows[0]["parse_status"] == "valid"

    def test_unknown_zone_is_invalid_not_guessed(self):
        rows = parse_timezone("Not/AZone\n", source_path="etc/timezone")
        assert rows[0]["normalized_value"] is None
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["reason"] == "not_a_known_iana_zone"

    def test_empty_file(self):
        rows = parse_timezone("", source_path="etc/timezone")
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["reason"] == "empty_file"

    def test_whitespace_and_comments_ignored(self):
        rows = parse_timezone("# comment\n\n  Europe/Madrid  \n", source_path="etc/timezone")
        assert rows[0]["normalized_value"] == "Europe/Madrid"


class TestSysconfigAndConfD:
    def test_sysconfig_zone_assignment(self):
        rows = parse_timezone('ZONE="America/New_York"\n', source_path="etc/sysconfig/clock")
        assert rows[0]["artifact_type"] == "sysconfig_clock"
        assert rows[0]["normalized_value"] == "America/New_York"
        assert rows[0]["confidence"] == "medium"

    def test_conf_d_timezone_assignment(self):
        rows = parse_timezone('TIMEZONE="Etc/UTC"\n', source_path="etc/conf.d/clock")
        assert rows[0]["artifact_type"] == "conf_d_clock"
        assert rows[0]["normalized_value"] == "Etc/UTC"

    def test_unquoted_assignment(self):
        rows = parse_timezone("ZONE=Europe/Madrid\n", source_path="etc/sysconfig/clock")
        assert rows[0]["normalized_value"] == "Europe/Madrid"

    def test_never_executes_shell_syntax(self):
        # A file containing shell metacharacters must never be evaluated --
        # only regex-matched. This must not raise or execute anything.
        content = '$(rm -rf /)\nZONE="Europe/Madrid"\nexport FOO=`whoami`\n'
        rows = parse_timezone(content, source_path="etc/sysconfig/clock")
        assert rows[0]["normalized_value"] == "Europe/Madrid"

    def test_no_assignment_found(self):
        rows = parse_timezone("# nothing useful here\n", source_path="etc/sysconfig/clock")
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["reason"] == "no_zone_assignment_found"


class TestTimedatectlAndHostnamectl:
    def test_timedatectl_extracts_zone_only(self):
        content = (
            "               Local time: Tue 2026-07-28 10:00:00 CEST\n"
            "           Universal time: Tue 2026-07-28 08:00:00 UTC\n"
            "                Time zone: Europe/Madrid (CEST, +0200)\n"
        )
        rows = parse_timezone(content, source_path="timedatectl.txt")
        assert rows[0]["artifact_type"] == "timedatectl"
        assert rows[0]["normalized_value"] == "Europe/Madrid"
        # The parenthetical abbreviation/offset must never leak into the value.
        assert "CEST" not in rows[0]["normalized_value"]
        assert "+0200" not in rows[0]["normalized_value"]

    def test_timedatectl_missing_line_is_invalid(self):
        rows = parse_timezone("Local time: n/a\n", source_path="timedatectl.txt")
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["reason"] == "no_time_zone_line_found"

    def test_hostnamectl_is_not_handled_here(self):
        # hostnamectl output is host-identity command output first --
        # dispatch and parsing moved to app.ingest.linux.os_info in the
        # Host Facts: Identity & Operating System sprint (see
        # test_linux_host_identity.py), which reuses this module's own
        # validate_iana_zone/TIME_ZONE_LINE_RE for the timezone line it
        # also carries rather than this function handling it directly.
        content = "Static hostname: db01\nTime zone: America/New_York (EDT, -0400)\n"
        assert parse_timezone(content, source_path="hostnamectl.txt") == []

    def test_timedatectl_binary_under_bin_is_not_dispatched(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("usr/bin/timedatectl") is None
        assert looks_like_linux_artifact("usr/bin/hostnamectl") is None

    def test_shell_completion_script_is_not_dispatched(self):
        # Confirmed against real disk-image evidence: systemd ships a file
        # named exactly "timedatectl" under bash-completion/completions/ --
        # a shell-completion script, not captured command output.
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("usr/share/bash-completion/completions/timedatectl") is None
        assert looks_like_linux_artifact("usr/share/bash-completion/completions/hostnamectl") is None


class TestEtcLocaltimeTzif:
    def test_known_zone_matches_exactly(self):
        content = _real_tzif("Europe/Madrid")
        assert match_tzif_to_zone_name(content) == "Europe/Madrid"
        rows = parse_timezone(content, source_path="etc/localtime")
        assert rows[0]["artifact_type"] == "etc_localtime_tzif"
        assert rows[0]["normalized_value"] == "Europe/Madrid"
        assert rows[0]["parse_status"] == "valid"
        assert rows[0]["tzif_meta"]["version"] in {"1", "2", "3", "4"}

    def test_another_known_zone(self):
        content = _real_tzif("America/New_York")
        rows = parse_timezone(content, source_path="etc/localtime")
        assert rows[0]["normalized_value"] == "America/New_York"

    def test_utc_zone(self):
        content = _real_tzif("Etc/UTC")
        rows = parse_timezone(content, source_path="etc/localtime")
        assert rows[0]["normalized_value"] == "Etc/UTC"

    def test_structurally_valid_but_unmatched_tzif_is_not_guessed(self):
        header = struct.pack(">4sc15xllllll", b"TZif", b"2", 0, 0, 0, 0, 1, 4)
        body = b"\x00" * 4 + b"\x00" + b"\xff\xff\xff\xff" + b"FAKE\x00"
        fake = header + body
        rows = parse_timezone(fake, source_path="etc/localtime")
        assert rows[0]["normalized_value"] is None
        assert rows[0]["parse_status"] == "unknown_zone"
        assert rows[0]["confidence"] == "low"
        assert rows[0]["reason"] == "tzif_valid_no_exact_zone_match"

    def test_malformed_binary_is_rejected(self):
        garbage = b"\x00\x01\x02not a timezone file at all\xff\xfe\x00\x00"
        assert parse_timezone(garbage, source_path="etc/localtime") == []

    def test_truncated_tzif_header_is_rejected(self):
        assert parse_timezone(b"TZif2", source_path="etc/localtime") == []


class TestEtcLocaltimeSymlinkText:
    def test_symlink_target_as_text(self):
        rows = parse_timezone("/usr/share/zoneinfo/Europe/Madrid", source_path="etc/localtime")
        assert rows[0]["artifact_type"] == "etc_localtime_symlink"
        assert rows[0]["normalized_value"] == "Europe/Madrid"

    def test_relative_symlink_target(self):
        rows = parse_timezone("../usr/share/zoneinfo/Etc/UTC", source_path="etc/localtime")
        assert rows[0]["normalized_value"] == "Etc/UTC"

    def test_unrelated_text_is_rejected(self):
        assert parse_timezone("this is not a path at all", source_path="etc/localtime") == []


class TestUnrelatedFilesRejected:
    def test_unrelated_file_at_unrelated_path(self):
        assert parse_timezone("hello world", source_path="etc/motd") == []

    def test_documentation_mentioning_timezone_is_not_matched(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("usr/share/doc/tzdata/README.timezone") is None

    def test_source_code_is_not_matched(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("usr/lib/python3/dist-packages/tz_helpers.py") is None


class TestDiscoveryIntegration:
    def test_all_timezone_sources_detected(self, tmp_path: Path):
        from app.ingest.linux.discovery import build_linux_inventory

        (tmp_path / "etc/sysconfig").mkdir(parents=True)
        (tmp_path / "etc/conf.d").mkdir(parents=True)
        (tmp_path / "etc/timezone").write_text("Europe/Madrid\n", encoding="utf-8")
        (tmp_path / "etc/localtime").write_bytes(_real_tzif("Europe/Madrid"))
        (tmp_path / "etc/sysconfig/clock").write_text('ZONE="Europe/Madrid"\n', encoding="utf-8")
        (tmp_path / "etc/conf.d/clock").write_text('TIMEZONE="Europe/Madrid"\n', encoding="utf-8")
        (tmp_path / "timedatectl.txt").write_text("Time zone: Europe/Madrid (CEST, +0200)\n", encoding="utf-8")

        files = [str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file()]
        inventory = build_linux_inventory(tmp_path, files)

        assert inventory is not None
        timezone_item = next(item for item in inventory["detected_artifacts"] if item["key"] == "timezone")
        assert timezone_item["family"] == "linux_timezone"
        assert timezone_item["parser"] == "linux_timezone_raw"
        assert set(timezone_item["paths"]) == {
            "etc/timezone", "etc/localtime", "etc/sysconfig/clock", "etc/conf.d/clock", "timedatectl.txt",
        }

    def test_registry_entry_present(self):
        from app.services.parser_registry import get_parser_registry_entry
        entry = get_parser_registry_entry(artifact_type="linux_timezone")
        assert entry["parser_name"] == "linux_timezone_raw"


class TestDispatchIntegration:
    def test_etc_localtime_dispatched_as_bytes(self, tmp_path: Path):
        from app.ingest.linux.dispatch import parse_linux_artifact_file

        localtime_path = tmp_path / "etc/localtime"
        localtime_path.parent.mkdir(parents=True)
        localtime_path.write_bytes(_real_tzif("Europe/Madrid"))

        rows = parse_linux_artifact_file(
            localtime_path, parser="linux_timezone_raw", artifact_type="etc_localtime", source_path="etc/localtime",
        )
        assert rows[0]["normalized_value"] == "Europe/Madrid"

    def test_etc_localtime_dispatched_as_bytes_with_coarse_artifact_type(self, tmp_path: Path):
        """Regression guard: app.ingest.detector.classify_artifact() reports
        the coarse family ("linux_timezone") as artifact_type for
        disk-image-sourced candidates, not the fine-grained source_kind --
        confirmed against real evidence, where this silently text-decoded a
        real TZif binary and produced zero records. Dispatch must still
        route /etc/localtime as bytes by filename in that case.
        """
        from app.ingest.linux.dispatch import parse_linux_artifact_file

        localtime_path = tmp_path / "etc/localtime"
        localtime_path.parent.mkdir(parents=True)
        localtime_path.write_bytes(_real_tzif("Europe/Madrid"))

        rows = parse_linux_artifact_file(
            localtime_path, parser="linux_timezone_raw", artifact_type="linux_timezone", source_path="etc/localtime",
        )
        assert rows != []
        assert rows[0]["normalized_value"] == "Europe/Madrid"

    def test_etc_timezone_dispatched_as_text(self, tmp_path: Path):
        from app.ingest.linux.dispatch import parse_linux_artifact_file

        tz_path = tmp_path / "etc/timezone"
        tz_path.parent.mkdir(parents=True)
        tz_path.write_text("Europe/Madrid\n", encoding="utf-8")

        rows = parse_linux_artifact_file(
            tz_path, parser="linux_timezone_raw", artifact_type="etc_timezone", source_path="etc/timezone",
        )
        assert rows[0]["normalized_value"] == "Europe/Madrid"


class TestNormalization:
    def test_normalizes_config_event_semantics(self):
        from app.ingest.normalizer import normalize_row

        rows = parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_timezone",
            "artifact_type": "etc_timezone",
            "parser": "linux_timezone_raw",
            "name": "timezone",
            "source_path": "etc/timezone",
        })
        assert doc["event"]["category"] == "config"
        assert doc["event"]["type"] == "timezone"
        assert doc["event"]["action"] == "timezone_detected"
        assert doc["event"]["outcome"] == "success"
        assert doc["event"]["severity"] == "info"
        assert doc["artifact"]["type"] == "linux_timezone"
        assert doc["linux"]["timezone_name"] == "Europe/Madrid"
        assert doc["linux"]["timezone_confidence"] == "high"
        assert doc["linux"]["timezone_parse_status"] == "valid"
        assert doc["linux"]["fact_type"] == "host.timezone"

    def test_invalid_observation_has_failure_outcome(self):
        from app.ingest.normalizer import normalize_row

        rows = parse_timezone("Not/AZone\n", source_path="etc/timezone")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_timezone",
            "artifact_type": "etc_timezone",
            "parser": "linux_timezone_raw",
            "name": "timezone",
            "source_path": "etc/timezone",
        })
        assert doc["event"]["outcome"] == "failure"
        assert doc["linux"]["timezone_name"] == ""

    def test_search_text_contains_zone_and_family(self):
        from app.ingest.normalizer import normalize_row

        rows = parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_timezone",
            "artifact_type": "etc_timezone",
            "parser": "linux_timezone_raw",
            "name": "timezone",
            "source_path": "etc/timezone",
        })
        assert "Madrid" in doc["search_text"]
        assert "timezone" in doc["search_text"]

    def test_does_not_overwrite_record_timestamp_timezone_field(self):
        """doc['timezone'] describes the record's own @timestamp precision,
        never the host's configured timezone -- that lives only under
        linux.timezone_name. Regression guard against the two being confused.
        """
        from app.ingest.normalizer import normalize_row

        rows = parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_timezone",
            "artifact_type": "etc_timezone",
            "parser": "linux_timezone_raw",
            "name": "timezone",
            "source_path": "etc/timezone",
        })
        assert doc["timezone"] is None  # no @timestamp on a config record
        assert doc["linux"]["timezone_name"] == "Europe/Madrid"
