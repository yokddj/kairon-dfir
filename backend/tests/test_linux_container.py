"""Docker / CRI container logs and Docker container configuration. All synthetic."""
from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.container_logs import HIGH_SEVERITY_FLAGS, container_kind, parse_container_artifact
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax

CID = "a1b2c3d4" * 8
DOCKER_LOG = f"var/lib/docker/containers/{CID}/{CID}-json.log"
DOCKER_CONFIG = f"var/lib/docker/containers/{CID}/config.v2.json"
DOCKER_HOSTCONFIG = f"var/lib/docker/containers/{CID}/hostconfig.json"
CRI_POD = "var/log/pods/shop_web-7d9_9f1c2e/nginx/0.log"
CRI_LINK = f"var/log/containers/web-7d9_shop_nginx-{CID}.log"


def _entry(log: str, stream: str = "stdout", time: str = "2024-03-01T10:20:30.123456789Z") -> str:
    return json.dumps({"log": log, "stream": stream, "time": time})


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


# --------------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path, kind",
    [
        (DOCKER_LOG, "container_log"),
        (DOCKER_LOG + ".1", "container_log"),
        (DOCKER_LOG + ".2.gz", "container_log"),
        (DOCKER_CONFIG, "container_config"),
        (DOCKER_HOSTCONFIG, "container_hostconfig"),
        (CRI_POD, "container_log"),
        ("var/log/pods/shop_web-7d9_9f1c2e/nginx/3.log.20240301-102030", "container_log"),
        (CRI_LINK, "container_log"),
        ("evidence/node1/" + DOCKER_LOG, "container_log"),
    ],
)
def test_container_paths_are_detected(path, kind):
    assert container_kind(path) == kind
    assert looks_like_linux_artifact(path) == ("linux_container", kind, "linux_container_raw")


@pytest.mark.parametrize("path", ["var/lib/docker/containers/xyz/y.txt", "var/lib/docker/image/overlay2/repositories.json", "var/log/pods/notapod/x.log", "var/lib/docker/containers/short/config.v2.json"])
def test_other_paths_are_not_container_artifacts(path):
    assert container_kind(path) is None


# ---------------------------------------------------------------------- Docker logs

def test_a_docker_line_carries_its_container_stream_and_exact_time():
    row = parse_container_artifact(_entry("GET / 200 from 203.0.113.9\n"), source_path=DOCKER_LOG)[0]
    assert row["message"] == "GET / 200 from 203.0.113.9"
    assert (row["container_id"], row["container_stream"]) == (CID, "stdout")
    assert row["timestamp"] == "2024-03-01T10:20:30.123456+00:00" and row["timestamp_status"] == "ok"
    assert row["source_ip"] == "203.0.113.9"


def test_partial_lines_are_reassembled_under_the_first_piece_time():
    content = "\n".join([_entry("first part, ", time="2024-03-01T10:20:31Z"), _entry("middle, ", time="2024-03-01T10:20:32Z"), _entry("end\n", time="2024-03-01T10:20:33Z"), _entry("next line\n", time="2024-03-01T10:20:34Z")])
    rows = parse_container_artifact(content, source_path=DOCKER_LOG)
    assert [r["message"] for r in rows] == ["first part, middle, end", "next line"]
    assert rows[0]["timestamp"] == "2024-03-01T10:20:31+00:00" and rows[0]["line_number"] == 1


def test_a_trailing_fragment_is_still_emitted():
    rows = parse_container_artifact(_entry("never finished"), source_path=DOCKER_LOG)
    assert [r["message"] for r in rows] == ["never finished"]


def test_an_application_that_logs_json_has_its_message_and_level_lifted_out():
    inner = json.dumps({"level": "error", "msg": "db connection refused", "user": "svc-app"})
    row = parse_container_artifact(_entry(inner + "\n", stream="stderr"), source_path=DOCKER_LOG)[0]
    assert row["message"] == "db connection refused" and row["severity"] == "error" and row["container_stream"] == "stderr"
    assert row["username"] == "svc-app"


def test_a_level_word_in_plain_text_sets_the_severity():
    assert parse_container_artifact(_entry("2024-03-01 WARN cache cold\n"), source_path=DOCKER_LOG)[0]["severity"] == "warning"
    assert parse_container_artifact(_entry("all good\n"), source_path=DOCKER_LOG)[0]["severity"] is None


def test_unparsable_lines_are_kept_undated():
    rows = parse_container_artifact("not json\n" + _entry("ok\n"), source_path=DOCKER_LOG)
    assert rows[0]["message"] == "not json" and rows[0]["timestamp"] is None and rows[0]["timestamp_status"] == "missing"
    assert rows[1]["message"] == "ok"


# ------------------------------------------------------------------------ CRI logs

CRI = (
    "2024-03-01T10:20:30.123456789Z stdout F hello world\n"
    "2024-03-01T10:20:31Z stderr P a long line that was split \n"
    "2024-03-01T10:20:31.5Z stderr F and finished ERROR boom\n"
)


def test_cri_lines_carry_the_pod_namespace_and_container_from_the_path():
    rows = parse_container_artifact(CRI, source_path=CRI_POD)
    assert rows[0]["message"] == "hello world" and rows[0]["container_stream"] == "stdout"
    assert (rows[0]["k8s_namespace"], rows[0]["k8s_pod"], rows[0]["container_name"], rows[0]["process"]) == ("shop", "web-7d9", "nginx", "nginx")
    assert rows[0]["timestamp"] == "2024-03-01T10:20:30.123456+00:00"


def test_cri_partial_lines_are_joined_until_the_full_tag():
    rows = parse_container_artifact(CRI, source_path=CRI_POD)
    assert len(rows) == 2 and rows[1]["message"] == "a long line that was split and finished ERROR boom"
    assert rows[1]["severity"] == "error" and rows[1]["container_stream"] == "stderr"


def test_the_container_link_path_gives_the_id_as_well():
    row = parse_container_artifact(CRI, source_path=CRI_LINK)[0]
    assert (row["k8s_pod"], row["k8s_namespace"], row["container_name"], row["container_id"]) == ("web-7d9", "shop", "nginx", CID)


def test_unmatched_cri_text_is_not_dropped():
    rows = parse_container_artifact(CRI + "garbage\n", source_path=CRI_POD)
    assert rows[-1]["message"] == "garbage" and rows[-1]["timestamp"] is None


# -------------------------------------------------------------------- configuration

CONFIG = {
    "ID": CID, "Created": "2024-03-01T09:00:00.123456789Z", "Path": "/bin/sh", "Args": ["-c", "sleep 3600"],
    "State": {"Running": True, "ExitCode": 0, "Pid": 4242}, "Name": "/web",
    "Config": {"Image": "nginx:1.25", "User": "", "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2-not-a-real-secret", "API_TOKEN=abc123xyz", "LD_PRELOAD=/lib/x.so"]},
    "MountPoints": {"/h": {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/h"}, "/d": {"Type": "volume", "Source": "data", "Destination": "/d"}},
}
HOSTCONFIG = {
    "Privileged": True, "NetworkMode": "host", "PidMode": "host", "IpcMode": "host", "CapAdd": ["CAP_SYS_ADMIN"],
    "Binds": ["/:/host", "/etc:/e:ro", "named-volume:/data", "/srv/app:/app"], "SecurityOpt": ["seccomp=unconfined"], "Devices": [{"PathOnHost": "/dev/sda"}],
}


def _config(document: dict, path: str = DOCKER_CONFIG) -> dict:
    return parse_container_artifact(json.dumps(document), source_path=path)[0]


def test_config_describes_the_container():
    row = _config(CONFIG)
    assert (row["container_name"], row["container_image"], row["container_state"], row["container_exit_code"]) == ("web", "nginx:1.25", "running", 0)
    assert row["container_command"] == "/bin/sh -c sleep 3600" and row["container_id"] == CID
    assert row["timestamp"] == "2024-03-01T09:00:00.123456+00:00"
    assert row["message"].startswith("Container web (nginx:1.25) running: /bin/sh -c sleep 3600")


def test_environment_values_are_never_stored_only_names():
    row = _config(CONFIG)
    assert row["container_env_names"] == ["PATH", "DB_PASSWORD", "API_TOKEN", "LD_PRELOAD"]
    blob = json.dumps(row)
    assert "hunter2" not in blob and "abc123xyz" not in blob and "/lib/x.so" not in blob


def test_config_flags_from_mounts_and_environment():
    flags = set(_config(CONFIG)["suspicious_indicators"])
    assert {"docker_socket_mount", "host_path_mount", "sensitive_host_mount", "secret_in_environment", "ld_preload_env"} <= flags
    assert "host_root_mount" not in flags and "privileged_container" not in flags


def test_hostconfig_flags():
    row = _config(HOSTCONFIG, DOCKER_HOSTCONFIG)
    assert row["artifact_type"] == "container_hostconfig" and row["container_privileged"] is True
    assert {"privileged_container", "host_network", "host_pid", "host_ipc", "dangerous_capability", "unconfined_security", "host_device", "host_root_mount", "host_path_mount", "sensitive_host_mount"} <= set(row["suspicious_indicators"])
    assert (row["network_mode"], row["pid_mode"], row["container_cap_add"]) == ("host", "host", ["CAP_SYS_ADMIN"])
    assert row["container_mounts"][0] == "/:/host"


def test_a_plain_container_is_not_flagged():
    row = _config({"ID": CID, "Name": "/db", "Config": {"Image": "postgres:16", "Env": ["POSTGRES_DB=app"]}, "State": {"Running": False, "ExitCode": 1}, "MountPoints": {"/d": {"Type": "volume", "Source": "pgdata"}}})
    assert row["suspicious_indicators"] == [] and row["container_state"] == "exited" and row["container_exit_code"] == 1


def test_named_volumes_are_not_host_paths_and_dangerous_caps_need_to_be_dangerous():
    row = _config({"Binds": ["data:/data"], "CapAdd": ["NET_BIND_SERVICE"], "NetworkMode": "bridge"}, DOCKER_HOSTCONFIG)
    assert row["suspicious_indicators"] == []


def test_malformed_and_oversized_config_do_not_raise():
    assert parse_container_artifact("{not json", source_path=DOCKER_CONFIG) == []
    assert parse_container_artifact("[1, 2]", source_path=DOCKER_CONFIG) == []
    odd = {"Config": "x", "State": [], "MountPoints": {"/x": 5}, "Args": "notalist", "Name": 7}
    assert _config(odd)["artifact_type"] == "container_config"
    big = parse_container_artifact(" " * (5 * 1024 * 1024 + 1), source_path=DOCKER_CONFIG)[0]
    assert "not parsed" in big["message"]


# ----------------------------------------------------------------- dispatch/normalize

def test_dispatch_reads_a_compressed_rotated_log(tmp_path):
    path = tmp_path / f"{CID}-json.log.1.gz"
    path.write_bytes(gzip.compress((_entry("hello\n") + "\n").encode()))
    rows = parse_linux_artifact_file(path, parser="linux_container_raw", artifact_type="container_log", source_path=DOCKER_LOG + ".1.gz")
    assert [r["message"] for r in rows] == ["hello"]


def test_dispatch_marks_a_truncated_log(tmp_path):
    blob = gzip.compress(("\n".join(_entry(f"line {i}\n") for i in range(2000))).encode())
    path = tmp_path / "cut.log.gz"
    path.write_bytes(blob[: len(blob) // 2])
    rows = parse_linux_artifact_file(path, parser="linux_container_raw", artifact_type="container_log", source_path=DOCKER_LOG + ".1.gz")
    assert rows and "truncated" in rows[-1]["message"]


def test_a_log_line_normalizes_with_its_level_as_severity():
    doc = _doc(parse_container_artifact(_entry(json.dumps({"level": "error", "msg": "boom"}) + "\n", stream="stderr"), source_path=DOCKER_LOG)[0])
    assert doc["event"]["type"] == "container_log" and doc["event"]["action"] == "container_stderr" and doc["event"]["severity"] == "medium"
    assert doc["linux"]["container_id"] == CID and doc["linux"]["container_stream"] == "stderr" and doc["title"] == "boom"


def test_a_cri_line_normalizes_with_pod_fields():
    linux = _doc(parse_container_artifact(CRI, source_path=CRI_POD)[0])["linux"]
    assert (linux["k8s_pod"], linux["k8s_namespace"], linux["container_name"]) == ("web-7d9", "shop", "nginx")


def test_config_severity_follows_the_flags():
    privileged = _doc(_config(HOSTCONFIG, DOCKER_HOSTCONFIG))
    mild = _doc(_config({"Config": {"Env": ["API_TOKEN=x"]}, "Name": "/x"}))
    plain = _doc(_config({"Config": {"Image": "alpine"}, "Name": "/x"}))
    assert (privileged["event"]["severity"], mild["event"]["severity"], plain["event"]["severity"]) == ("high", "medium", "info")
    assert {"privileged_container", "docker_socket_mount", "host_root_mount"} == HIGH_SEVERITY_FLAGS
    assert privileged["event"]["type"] == "container_hostconfig" and privileged["linux"]["container_privileged"] is True


def test_the_secret_never_reaches_the_indexed_document():
    assert "hunter2" not in json.dumps(_doc(_config(CONFIG)), default=str)


# ------------------------------------------------------------------ search/mapping

@pytest.mark.parametrize(
    "query, field",
    [("container:web", "linux.container_name"), ("container:web", "linux.container_id"), ("image:nginx*", "linux.container_image"), ("pod:web-7d9", "linux.k8s_pod"),
     ("stream:stderr", "linux.container_stream"), ("namespace:shop", "linux.k8s_namespace"), ("indicator:privileged_container", "linux.suspicious_indicators")],
)
def test_container_shortcuts_are_searchable(query, field):
    assert field in str(analyze_query_syntax(query, lambda t: {"simple_query_string": {"query": t}})["query"])


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_container_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"container_id", "container_name", "container_image", "container_privileged", "container_stream", "container_mounts", "k8s_pod", "network_mode"} <= set(properties)
