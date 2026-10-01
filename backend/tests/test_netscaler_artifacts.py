"""Unit coverage for Citrix NetScaler/ADC ns.conf detection and parsing.

Diagnosed against a real NetScaler VPX disk image whose /nsconfig/ns.conf
(current config) and dozens of ns.conf.<build> backups were previously
invisible to Kairon end to end: never materialized out of the volume
(no entry in app.disk_images.service._should_materialize), never classified
(no entry in app.ingest.detector.classify_artifact), and so never parsed or
indexed -- 0 OpenSearch events for a disk image that, as it turns out,
holds the appliance's entire account/certificate/feature history.
"""
from __future__ import annotations

from app.ingest.netscaler.config import parse_ns_conf
from app.ingest.netscaler.helpers import looks_like_netscaler_artifact


def test_looks_like_netscaler_artifact_matches_current_and_backup_conf() -> None:
    assert looks_like_netscaler_artifact("nsconfig/ns.conf") == ("netscaler_config", "ns_conf", "netscaler_config_raw")
    assert looks_like_netscaler_artifact("nsconfig/ns.conf.bak")[1] == "ns_conf_backup"
    assert looks_like_netscaler_artifact("nsconfig/ns.conf.0")[1] == "ns_conf_backup"
    assert looks_like_netscaler_artifact("nsconfig/ns.conf.NS14.1-73.37")[1] == "ns_conf_backup"
    assert looks_like_netscaler_artifact("nsconfig/unified.conf") is not None
    assert looks_like_netscaler_artifact("nsconfig/deprecated_ns.conf") is not None


def test_looks_like_netscaler_artifact_does_not_match_unrelated_conf() -> None:
    assert looks_like_netscaler_artifact("etc/snmpd.conf") is None
    assert looks_like_netscaler_artifact("etc/rc.conf") is None


def test_parse_ns_conf_header_captures_version_and_build() -> None:
    content = "#NS14.1 Build 73.37\n# Last modified by `save config`, Mon Jan 01 00:00:00 2026\n"
    rows = parse_ns_conf(content, source_path="nsconfig/ns.conf")

    assert rows[0]["artifact_type"] == "ns_conf_header"
    assert rows[0]["ns_version"] == "14.1"
    assert rows[0]["ns_build"] == "73.37"
    assert rows[1]["artifact_type"] == "ns_conf_header"
    assert rows[1]["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_parse_ns_conf_extracts_hostname_and_user_commands() -> None:
    content = (
        '#NS14.1 Build 73.37\n'
        '# Last modified by `save config`, Mon Jan 01 00:00:00 2026\n'
        'set ns hostName HOST-REDACTED\n'
        'add system user svc-account-example 0000000000000000 -encrypted -timeout 900\n'
        'add system group ExampleAdminGroup -promptString "%u@%h-%T" -timeout 9000\n'
        'add vlan 305 -aliasName "Internal Segment"\n'
    )
    rows = parse_ns_conf(content, source_path="nsconfig/ns.conf")
    by_line = {row["line_number"]: row for row in rows}

    hostname_row = by_line[3]
    assert hostname_row["command_verb"] == "set"
    assert hostname_row["object_type"] == "ns"
    assert hostname_row["object_subtype"] == "hostName"
    assert hostname_row["object_name"] == "HOST-REDACTED"
    assert hostname_row["is_backup_config"] is False

    user_row = by_line[4]
    assert user_row["command_verb"] == "add"
    assert user_row["object_type"] == "system"
    assert user_row["object_subtype"] == "user"
    assert user_row["object_name"] == "svc-account-example"

    group_row = by_line[5]
    assert group_row["object_subtype"] == "group"
    assert group_row["object_name"] == "ExampleAdminGroup"

    # "305" is a bare vlan id, not an alphabetic subtype -- the heuristic
    # correctly leaves object_subtype unset rather than misreading a digit
    # string as a noun.
    vlan_row = by_line[6]
    assert vlan_row["object_type"] == "vlan"
    assert vlan_row["object_subtype"] is None
    assert vlan_row["object_name"] == "305"


def test_parse_ns_conf_flags_backup_files() -> None:
    content = "set ns hostName HOST-REDACTED\n"
    rows = parse_ns_conf(content, source_path="nsconfig/ns.conf.NS13.0-82.45")
    assert rows[0]["is_backup_config"] is True
    assert rows[0]["artifact_type"] == "ns_conf_backup"


def test_parse_ns_conf_skips_blank_lines_and_plain_comments() -> None:
    content = "\n# just a comment, not the version/saved header\n   \nset ns hostName X\n"
    rows = parse_ns_conf(content, source_path="nsconfig/ns.conf")
    assert len(rows) == 1
    assert rows[0]["object_name"] == "X"


def test_normalize_file_indexes_ns_conf_as_netscaler_events(tmp_path) -> None:
    from app.ingest.normalizer import normalize_file

    path = tmp_path / "ns.conf"
    path.write_text(
        '#NS14.1 Build 73.37\n'
        '# Last modified by `save config`, Mon Jan 01 00:00:00 2026\n'
        'set ns hostName HOST-REDACTED\n'
        'add system user svc-account-example 0000000000000000 -encrypted -timeout 900\n',
        encoding="utf-8",
    )
    artifact_meta = {
        "artifact_family": "netscaler_config",
        "artifact_type": "ns_conf",
        "parser": "netscaler_config_raw",
        "name": "ns.conf",
        "source_path": "nsconfig/ns.conf",
    }

    docs = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)

    assert len(docs) == 4
    header_doc = docs[0]
    assert header_doc["case_id"] == "case-1"
    assert header_doc["evidence_id"] == "ev-1"
    assert header_doc["artifact"]["type"] == "netscaler_config"
    assert header_doc["artifact"]["parser"] == "netscaler_config_raw"
    assert header_doc["os"]["type"] == "bsd"

    saved_doc = docs[1]
    assert saved_doc["@timestamp"] == "2026-01-01T00:00:00+00:00"

    hostname_doc = docs[2]
    assert hostname_doc["netscaler"]["command_verb"] == "set"
    assert hostname_doc["netscaler"]["object_name"] == "HOST-REDACTED"
    assert hostname_doc["host"]["hostname"] == "HOST-REDACTED"

    user_doc = docs[3]
    assert user_doc["netscaler"]["object_type"] == "system"
    assert user_doc["netscaler"]["object_subtype"] == "user"
    assert user_doc["netscaler"]["object_name"] == "svc-account-example"
    assert user_doc["event"]["message"] == "add system user: svc-account-example"
    assert artifact_meta["ingest_audit"]["parser_status"] == "parsed"
    assert artifact_meta["ingest_audit"]["records_indexed"] == 4
