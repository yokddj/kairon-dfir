"""Kubernetes API-server audit log parser. Users, clusters and addresses are synthetic."""
from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.audit import parse_audit
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.k8s_audit import HIGH_SEVERITY_FLAGS, MAX_LINE_CHARS, looks_like_k8s_audit, parse_k8s_audit
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax


def _event(**fields) -> str:
    base = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "stage": "ResponseComplete", "auditID": "a-1",
        "requestReceivedTimestamp": "2024-03-01T10:20:30.123456Z", "sourceIPs": ["203.0.113.9"], "userAgent": "kubectl/v1.29",
        "user": {"username": "alice", "groups": ["system:authenticated"]}, "responseStatus": {"code": 200}, "verb": "get",
    }
    return json.dumps({**base, **fields})


def _one(**fields) -> dict:
    return parse_k8s_audit(_event(**fields), source_path="var/log/kubernetes/audit.log")[0]


def _flags(**fields) -> list[str]:
    return _one(**fields)["suspicious_indicators"]


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


# ------------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path",
    [
        "var/log/kubernetes/audit.log",
        "var/log/kubernetes/audit/audit.log",
        "var/log/kubernetes/audit-2024-03-01T10-20-30.123.log",
        "var/log/kube-apiserver/audit.log.1",
        "var/log/kube-apiserver/audit.log.2.gz",
        "var/log/audit/kube-apiserver-audit.log",
        "evidence/cp1/var/log/k8s/apiserver/audit.log",
    ],
)
def test_kubernetes_audit_paths_are_detected(path):
    assert looks_like_linux_artifact(path) == ("linux_k8s_audit", "k8s_audit", "linux_k8s_audit_raw")


@pytest.mark.parametrize("path", ["var/log/audit/audit.log", "var/log/audit/audit.log.1", "var/log/audit.log", "var/log/auth.log"])
def test_auditd_paths_still_mean_auditd(path):
    assert looks_like_linux_artifact(path)[0] != "linux_k8s_audit"


def test_content_sniff():
    assert looks_like_k8s_audit(_event())
    assert looks_like_k8s_audit("\n\n" + _event())
    assert not looks_like_k8s_audit("type=SYSCALL msg=audit(1709288430.1:1): arch=c000003e")
    assert not looks_like_k8s_audit('{"some": "other json"}')
    assert not looks_like_k8s_audit("")


def test_an_audit_log_named_like_auditds_is_still_read_as_kubernetes_by_content():
    rows = parse_audit(_event(requestURI="/api/v1/pods", objectRef={"resource": "pods"}) + "\n", source_path="var/log/audit/audit.log")
    assert rows and rows[0]["artifact_family"] == "linux_k8s_audit"


def test_a_real_auditd_log_is_unaffected():
    rows = parse_audit('type=SYSCALL msg=audit(1709288430.123:456): arch=c000003e syscall=59 success=yes comm="wget" exe="/usr/bin/wget"\n', source_path="var/log/audit/audit.log")
    assert rows[0]["artifact_family"] == "linux_audit"


# ------------------------------------------------------------------- extraction

def test_a_request_is_summarised_with_who_what_where_and_the_decision():
    row = _one(
        requestURI="/api/v1/namespaces/default/pods/web", verb="delete",
        objectRef={"resource": "pods", "namespace": "default", "name": "web", "apiVersion": "v1"},
        annotations={"authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": "RBAC: allowed"},
    )
    assert row["message"] == "alice delete pods/web (namespace default) -> 200 [allow]"
    assert (row["username"], row["source_ip"], row["http_status"], row["http_user_agent"]) == ("alice", "203.0.113.9", 200, "kubectl/v1.29")
    assert (row["k8s_verb"], row["k8s_resource"], row["k8s_namespace"], row["k8s_object"], row["k8s_decision"]) == ("delete", "pods", "default", "web", "allow")
    assert row["k8s_groups"] == ["system:authenticated"] and row["k8s_audit_id"] == "a-1" and row["k8s_stage"] == "ResponseComplete"
    assert row["url_path"] == "/api/v1/namespaces/default/pods/web"


def test_the_time_is_the_exact_request_time():
    row = _one(objectRef={"resource": "pods"})
    assert row["timestamp"] == "2024-03-01T10:20:30.123456+00:00" and row["timestamp_status"] == "ok"


def test_the_stage_time_is_the_fallback():
    event = json.loads(_event(objectRef={"resource": "pods"}, stageTimestamp="2024-03-01T10:20:31Z"))
    del event["requestReceivedTimestamp"]
    assert parse_k8s_audit(json.dumps(event))[0]["timestamp"] == "2024-03-01T10:20:31+00:00"


def test_the_first_valid_source_address_is_used():
    assert _one(sourceIPs=["not-an-ip", "198.51.100.7", "203.0.113.9"], objectRef={"resource": "pods"})["source_ip"] == "198.51.100.7"
    assert _one(sourceIPs=[], objectRef={"resource": "pods"})["source_ip"] == ""


def test_impersonation_is_recorded():
    row = _one(impersonatedUser={"username": "system:admin"}, objectRef={"resource": "pods"})
    assert row["k8s_impersonated"] == "system:admin" and "impersonation" in row["suspicious_indicators"]


def test_garbage_and_foreign_json_lines_are_kept_undated():
    rows = parse_k8s_audit('not json\n{"hello": "world"}\n[1, 2]\n', source_path="x")
    assert len(rows) == 3 and all(r["timestamp"] is None and r["timestamp_status"] == "missing" for r in rows)
    assert rows[0]["message"] == "not json"


def test_an_oversized_event_is_reported_not_parsed():
    huge = _event(verb="create", requestObject={"data": "A" * (MAX_LINE_CHARS + 10)})
    row = parse_k8s_audit(huge)[0]
    assert "not parsed" in row["message"] and row["timestamp"] is None and not row.get("k8s_verb")


def test_missing_fields_do_not_fail():
    row = parse_k8s_audit('{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get"}')[0]
    assert row["k8s_verb"] == "get" and row["username"] is None and row["http_status"] is None


# ------------------------------------------------------------------- indicators

def test_exec_attach_and_portforward_into_a_pod():
    for sub in ("exec", "attach", "portforward"):
        assert f"pod_{sub}" in _flags(verb="create", objectRef={"resource": "pods", "subresource": sub})


def test_secrets_reads_and_writes_differ():
    assert "secret_access" in _flags(verb="list", objectRef={"resource": "secrets"})
    assert "secret_change" in _flags(verb="update", objectRef={"resource": "secrets"})
    assert _flags(verb="get", objectRef={"resource": "configmaps"}) == []


def test_rbac_changes_and_cluster_admin_bindings():
    assert _flags(verb="create", objectRef={"resource": "rolebindings"}) == ["rbac_change"]
    assert _flags(verb="get", objectRef={"resource": "clusterrolebindings"}) == []
    flags = _flags(verb="create", objectRef={"resource": "clusterrolebindings"}, requestObject={"roleRef": {"name": "cluster-admin"}})
    assert set(flags) == {"rbac_change", "cluster_admin_binding"}


def test_a_service_account_token_request():
    assert "token_request" in _flags(verb="create", objectRef={"resource": "serviceaccounts", "subresource": "token"})


def test_anonymous_callers_and_whether_they_succeeded():
    ok = _flags(user={"username": "system:anonymous", "groups": ["system:unauthenticated"]}, objectRef={"resource": "pods"})
    denied = _flags(user={"username": "system:anonymous"}, responseStatus={"code": 403}, objectRef={"resource": "pods"})
    assert {"anonymous_request", "anonymous_success"} <= set(ok)
    assert denied == ["anonymous_request"]


def test_workload_hardening_flags_in_a_pod():
    spec = {
        "hostNetwork": True, "hostPID": True,
        "containers": [{"securityContext": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}}],
        "volumes": [{"hostPath": {"path": "/"}}, {"hostPath": {"path": "/var/run/docker.sock"}}],
    }
    flags = set(_flags(verb="create", objectRef={"resource": "pods"}, requestObject={"spec": spec}))
    assert {"host_network", "host_pid", "privileged_container", "dangerous_capability", "host_path_mount", "host_root_mount", "docker_socket_mount"} <= flags


def test_the_same_inspection_applies_to_deployments_and_cronjobs():
    template = {"template": {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}}
    assert "privileged_container" in _flags(verb="create", objectRef={"resource": "deployments"}, requestObject={"spec": template})
    cron = {"spec": {"jobTemplate": {"spec": template}}}
    assert "privileged_container" in _flags(verb="create", objectRef={"resource": "cronjobs"}, requestObject=cron)


def test_a_plain_workload_is_not_flagged_and_reads_are_not_inspected():
    plain = {"spec": {"containers": [{"image": "nginx", "securityContext": {"privileged": False}}]}}
    assert _flags(verb="create", objectRef={"resource": "pods"}, requestObject=plain) == []
    assert _flags(verb="get", objectRef={"resource": "pods"}, requestObject={"spec": {"hostNetwork": True}}) == []


def test_malformed_bodies_do_not_break_the_parser():
    for body in ("a string", [1, 2], {"spec": "x"}, {"spec": {"containers": "x", "volumes": [None, 3]}}, {"spec": {"template": 5}}):
        assert _one(verb="create", objectRef={"resource": "pods"}, requestObject=body)["k8s_verb"] == "create"


# ------------------------------------------------------------------- normalizing

def test_a_flagged_request_normalizes_to_standard_fields_and_severity():
    doc = _doc(_one(verb="create", requestURI="/api/v1/namespaces/default/pods/web/exec", objectRef={"resource": "pods", "subresource": "exec", "namespace": "default", "name": "web"}, responseStatus={"code": 101}))
    assert doc["event"]["type"] == "k8s_audit" and doc["event"]["action"] == "k8s_create" and doc["event"]["outcome"] == "success"
    assert doc["network"]["source_ip"] == "203.0.113.9" and doc["user"]["name"] == "alice"
    assert doc["url"]["path"] == "/api/v1/namespaces/default/pods/web/exec" and doc["http"]["response"]["status_code"] == 101
    assert doc["event"]["severity"] == "medium" and doc["linux"]["suspicious_indicators"] == ["pod_exec"]
    assert doc["title"].startswith("alice create pods/web/exec")


def test_severity_scale():
    plain = _doc(_one(objectRef={"resource": "pods"}))
    privileged = _doc(_one(verb="create", objectRef={"resource": "pods"}, requestObject={"spec": {"containers": [{"securityContext": {"privileged": True}}]}}))
    assert (plain["event"]["severity"], privileged["event"]["severity"]) == ("info", "high")
    assert "privileged_container" in HIGH_SEVERITY_FLAGS


def test_a_denied_request_is_a_failure():
    assert _doc(_one(responseStatus={"code": 403}, objectRef={"resource": "pods"}))["event"]["outcome"] == "failure"


def test_linux_fields_for_search_and_the_dispatcher(tmp_path):
    path = tmp_path / "audit.log.1.gz"
    path.write_bytes(gzip.compress((_event(verb="list", objectRef={"resource": "secrets", "namespace": "kube-system"}) + "\n").encode()))
    rows = parse_linux_artifact_file(path, parser="linux_k8s_audit_raw", artifact_type="k8s_audit", source_path="var/log/kubernetes/audit.log.1.gz")
    doc = _doc(rows[0])
    assert doc["linux"]["k8s_verb"] == "list" and doc["linux"]["k8s_resource"] == "secrets" and doc["linux"]["k8s_namespace"] == "kube-system"


# --------------------------------------------------------------------- search

@pytest.mark.parametrize(
    "query, field",
    [("verb:create", "linux.k8s_verb"), ("resource:secrets", "linux.k8s_resource"), ("namespace:kube-system", "linux.k8s_namespace"), ("decision:allow", "linux.k8s_decision"), ("sysmon:1", "linux.sysmon_event_id"), ("indicator:pod_exec", "linux.suspicious_indicators")],
)
def test_kubernetes_shortcuts_are_searchable(query, field):
    built = analyze_query_syntax(query, lambda text: {"simple_query_string": {"query": text}})["query"]
    assert field in str(built)


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_kubernetes_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"k8s_verb", "k8s_resource", "k8s_namespace", "k8s_object", "k8s_decision", "k8s_groups", "k8s_audit_id"} <= set(properties)
