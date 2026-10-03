"""OpenVPN and strongSwan logs. Users, hosts and addresses are synthetic."""
from __future__ import annotations

import gzip
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.vpn_logs import parse_vpn_log, vpn_kind
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax

OVPN_PATH = "var/log/openvpn/openvpn.log"


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


@pytest.mark.parametrize(
    "path, kind",
    [
        ("var/log/openvpn/openvpn.log", "openvpn"), ("var/log/openvpn/server.log.1", "openvpn"), ("var/log/openvpn.log", "openvpn"), ("var/log/openvpn/openvpn.log.2.gz", "openvpn"),
        ("var/log/openvpn/openvpn-status.log", "openvpn_status"), ("var/log/openvpn-status.log", "openvpn_status"), ("var/log/openvpn/status.log", "openvpn_status"),
        ("etc/openvpn/server/openvpn-status.log", "openvpn_status"),
        ("var/log/charon.log", "strongswan"), ("var/log/strongswan/charon.log", "strongswan"), ("var/log/charon.log.1.gz", "strongswan"), ("evidence/gw/var/log/charon.log", "strongswan"),
    ],
)
def test_vpn_paths_are_detected(path, kind):
    assert vpn_kind(path) == kind
    assert looks_like_linux_artifact(path) == ("linux_vpn", "vpn_log", "linux_vpn_raw")


@pytest.mark.parametrize("path", ["var/log/syslog", "var/log/status.log", "var/log/mail-status.log", "var/log/auth.log", "home/u/openvpn.log"])
def test_other_paths_are_not_vpn_logs(path):
    assert vpn_kind(path) is None
    found = looks_like_linux_artifact(path)
    assert found is None or found[0] != "linux_vpn"


OVPN = (
    "Fri Mar  1 10:20:30 2024 203.0.113.9:51234 TLS: Initial packet from [AF_INET]203.0.113.9:51234, sid=ab\n"
    "Fri Mar  1 10:20:31 2024 203.0.113.9:51234 VERIFY OK: depth=0, CN=alice\n"
    "Fri Mar  1 10:20:32 2024 alice/203.0.113.9:51234 MULTI: Learn: 10.8.0.6 -> alice/203.0.113.9:51234\n"
    "Fri Mar  1 10:20:33 2024 203.0.113.9:51234 [alice] Peer Connection Initiated with [AF_INET]203.0.113.9:51234\n"
    "Fri Mar  1 10:20:34 2024 198.51.100.7:4000 TLS Auth Error: Auth Username/Password verification failed for peer\n"
    "Fri Mar  1 10:20:35 2024 alice/203.0.113.9:51234 SIGTERM[soft,remote-exit] received, client-instance exiting\n"
)


def test_an_openvpn_session_from_first_packet_to_exit():
    rows = parse_vpn_log(OVPN, source_path=OVPN_PATH)
    assert [r["event_action"] for r in rows] == ["vpn_connection_received", "vpn_cert_verified", "vpn_address_assigned", "vpn_connect", "vpn_auth_failed", "vpn_disconnect"]
    assert rows[1]["username"] == "alice" and rows[2]["vpn_assigned_ip"] == "10.8.0.6"
    assert (rows[3]["username"], rows[3]["source_ip"], rows[3]["source_port"], rows[3]["vpn_status"]) == ("alice", "203.0.113.9", 51234, "success")
    assert (rows[4]["source_ip"], rows[4]["vpn_status"], rows[4]["artifact_type"]) == ("198.51.100.7", "failed", "openvpn_log")


def test_openvpn_times_have_no_zone_and_are_read_as_utc():
    row = parse_vpn_log(OVPN, source_path=OVPN_PATH)[0]
    assert (row["timestamp"], row["timestamp_status"]) == ("2024-03-01T10:20:30+00:00", "assumed_utc")


def test_the_iso_prefix_is_read_too():
    row = parse_vpn_log("2024-03-01 10:20:30 alice/203.0.113.9:51234 MULTI: Learn: 10.8.0.6 -> alice/203.0.113.9:51234\n2024-03-01T10:20:31+02:00 x\n", source_path=OVPN_PATH)
    assert row[0]["timestamp"] == "2024-03-01T10:20:30+00:00" and row[0]["vpn_assigned_ip"] == "10.8.0.6"
    assert (row[1]["timestamp"], row[1]["timestamp_status"]) == ("2024-03-01T08:20:31+00:00", "ok")


def test_unmatched_lines_are_kept_undated():
    rows = parse_vpn_log("OpenVPN 2.6.8 x86_64-pc-linux-gnu\n" + OVPN.splitlines()[0] + "\n", source_path=OVPN_PATH)
    assert rows[0]["timestamp"] is None and rows[0]["message"].startswith("OpenVPN 2.6.8") and rows[1]["timestamp"]


def test_repeated_failures_from_one_address_are_flagged():
    line = "Fri Mar  1 10:20:3{n} 2024 198.51.100.7:4000 TLS Auth Error: Auth Username/Password verification failed for peer\n"
    rows = parse_vpn_log("".join(line.format(n=n) for n in range(5)) + line.format(n=5).replace("198.51.100.7", "192.0.2.50"), source_path=OVPN_PATH)
    assert [r["suspicious_indicators"] for r in rows] == [["repeated_auth_failures"]] * 5 + [[]]


STATUS_V1 = (
    "OpenVPN CLIENT LIST\nUpdated,Fri Mar  1 10:30:00 2024\nCommon Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
    "alice,203.0.113.9:51234,1234,5678,Fri Mar  1 10:00:00 2024\nROUTING TABLE\nVirtual Address,Common Name,Real Address,Last Ref\n"
    "10.8.0.6,alice,203.0.113.9:51234,Fri Mar  1 10:20:00 2024\nGLOBAL STATS\nMax bcast/mcast queue length,0\nEND\n"
)
STATUS_V3 = (
    "TITLE\tOpenVPN 2.6.8\nTIME\tFri Mar  1 10:30:00 2024\t1709289000\nHEADER\tCLIENT_LIST\tCommon Name\tReal Address\n"
    "CLIENT_LIST\tbob\t198.51.100.7:5000\t10.8.0.7\t\t10\t20\tFri Mar  1 10:00:00 2024\t1709287200\tUNDEF\t1\t0\tAES-256-GCM\nEND\n"
)


def test_status_file_v1_lists_the_open_sessions_only_once():
    rows = parse_vpn_log(STATUS_V1, source_path="var/log/openvpn/openvpn-status.log")
    assert len(rows) == 1
    row = rows[0]
    assert (row["event_action"], row["username"], row["source_ip"], row["source_port"], row["vpn_bytes_received"], row["vpn_bytes_sent"]) == ("vpn_session", "alice", "203.0.113.9", 51234, 1234, 5678)
    assert row["timestamp"] == "2024-03-01T10:00:00+00:00" and row["vpn_status_updated"] == "2024-03-01T10:30:00+00:00"


def test_status_file_v3_uses_the_epoch_and_the_tunnel_address():
    row = parse_vpn_log(STATUS_V3, source_path="var/log/openvpn/openvpn-status.log")[0]
    assert (row["username"], row["vpn_assigned_ip"], row["source_ip"]) == ("bob", "10.8.0.7", "198.51.100.7")
    assert (row["timestamp"], row["timestamp_status"]) == ("2024-03-01T10:00:00+00:00", "ok")


SS = (
    "Mar  1 10:20:30 12[IKE] 203.0.113.9 is initiating an IKE_SA\n"
    "Mar  1 10:20:31 12[IKE] EAP method EAP_MSCHAPV2 failed for peer alice\n"
    "Mar  1 10:20:32 12[IKE] authentication of 'alice' with EAP successful\n"
    "Mar  1 10:20:33 12[IKE] assigning virtual IP 10.9.0.2 to peer 'alice'\n"
    "Mar  1 10:20:34 12[IKE] IKE_SA vpn[3] established between 192.0.2.1[gw]...203.0.113.9[alice]\n"
    "Mar  1 10:20:35 12[CHD] CHILD_SA vpn{2} established with SPIs c1_i c2_o and TS 10.0.0.0/24 === 10.9.0.2/32\n"
    "Mar  1 10:20:36 12[IKE] deleting IKE_SA vpn[3] between 192.0.2.1[gw]...203.0.113.9[alice]\n"
    "2024-03-01 10:20:37 13[IKE] no proposal chosen\n"
)


def test_a_strongswan_negotiation():
    rows = parse_vpn_log(SS, source_path="var/log/charon.log")
    assert [r["event_action"] for r in rows] == ["vpn_connection_received", "vpn_auth_failed", "vpn_auth_ok", "vpn_address_assigned", "vpn_connect", "vpn_tunnel_established", "vpn_disconnect", "vpn_auth_failed"]
    assert (rows[0]["source_ip"], rows[1]["username"], rows[3]["vpn_assigned_ip"]) == ("203.0.113.9", "alice", "10.9.0.2")
    assert (rows[4]["username"], rows[4]["source_ip"], rows[4]["vpn_connection"], rows[4]["vpn_local_ip"]) == ("alice", "203.0.113.9", "vpn", "192.0.2.1")
    assert rows[5]["vpn_traffic_selectors"] == "10.0.0.0/24 === 10.9.0.2/32" and rows[0]["vpn_component"] == "IKE"


def test_strongswan_syslog_times_have_no_year_and_the_iso_prefix_does():
    rows = parse_vpn_log(SS, source_path="var/log/charon.log")
    assert rows[0]["timestamp_status"] == "assumed_year_utc" and rows[0]["timestamp"].endswith("-03-01T10:20:30+00:00")
    assert (rows[-1]["timestamp"], rows[-1]["timestamp_status"]) == ("2024-03-01T10:20:37+00:00", "assumed_utc")


def test_a_strongswan_line_with_the_daemon_prefix_still_parses():
    row = parse_vpn_log("Mar  1 10:20:32 gw charon: 12[IKE] authentication of 'alice' with EAP successful\n", source_path="var/log/charon.log")[0]
    assert row["event_action"] == "vpn_auth_ok" and row["username"] == "alice"


def test_garbage_does_not_raise():
    for path in (OVPN_PATH, "var/log/openvpn/openvpn-status.log", "var/log/charon.log"):
        parse_vpn_log("\x00\x01 ???\n,,,\nCLIENT_LIST\t\nOpenVPN CLIENT LIST\nx,y\n" + "A" * 100000 + "\n", source_path=path)


def test_dispatch_reads_a_compressed_log_and_marks_truncation(tmp_path):
    path = tmp_path / "openvpn.log.1.gz"
    path.write_bytes(gzip.compress(OVPN.encode()))
    rows = parse_linux_artifact_file(path, parser="linux_vpn_raw", artifact_type="vpn_log", source_path="var/log/openvpn/openvpn.log.1.gz")
    assert len(rows) == 6 and rows[4]["event_action"] == "vpn_auth_failed"
    blob = gzip.compress((OVPN * 500).encode())
    cut = tmp_path / "cut.log.gz"
    cut.write_bytes(blob[: len(blob) // 2])
    rows = parse_linux_artifact_file(cut, parser="linux_vpn_raw", artifact_type="vpn_log", source_path="var/log/openvpn/openvpn.log.2.gz")
    assert rows and "truncated" in rows[-1]["message"]


def test_a_failed_login_normalizes_with_outcome_severity_and_source():
    doc = _doc(parse_vpn_log(OVPN, source_path=OVPN_PATH)[4])
    assert doc["event"]["type"] == "openvpn_log" and doc["event"]["action"] == "vpn_auth_failed" and doc["event"]["outcome"] == "failure"
    assert doc["event"]["severity"] == "medium" and doc["network"]["source_ip"] == "198.51.100.7"
    assert doc["title"] == "openvpn auth failed from 198.51.100.7"
    assert doc["linux"]["vpn_software"] == "openvpn" and doc["linux"]["vpn_status"] == "failed"


def test_a_connection_names_the_user_and_the_tunnel_address():
    doc = _doc(parse_vpn_log(SS, source_path="var/log/charon.log")[3])
    assert doc["event"]["outcome"] == "success" and doc["event"]["severity"] == "info" and doc["user"]["name"] == "alice"
    assert doc["title"] == "strongswan address assigned: alice -> 10.9.0.2"


def test_an_unclassified_line_keeps_its_text_as_the_title():
    doc = _doc(parse_vpn_log("Fri Mar  1 10:20:30 2024 Initialization Sequence Completed\n", source_path=OVPN_PATH)[0])
    assert doc["title"] == "openvpn: Initialization Sequence Completed" and doc["event"]["severity"] == "info"


@pytest.mark.parametrize(
    "query, field",
    [("vpn:openvpn", "linux.vpn_software"), ("vpnstatus:failed", "linux.vpn_status"), ("vpnip:10.8.0.6", "linux.vpn_assigned_ip"), ("vpnconn:office", "linux.vpn_connection")],
)
def test_vpn_shortcuts_are_searchable(query, field):
    assert field in str(analyze_query_syntax(query, lambda t: {"simple_query_string": {"query": t}})["query"])


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_vpn_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"vpn_software", "vpn_status", "vpn_assigned_ip", "vpn_connection", "vpn_bytes_sent"} <= set(properties)
