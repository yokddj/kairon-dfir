"""Lateral movement view: remote authentications on any platform, grouped by
target, source, account and method; sources resolved through observed
host addresses without guessing; routine traffic flagged, not dropped."""

from __future__ import annotations

import pytest

from app.services import lateral_movement as lm


def _bucket(target, source_ip, user, event_type, count, first, last, *, logon_type=None, service=None, auth_method=None, workstations=()):
    return {
        "key": {"target": target, "source_ip": source_ip, "user": user, "domain": None, "logon_type": logon_type,
                "auth_method": auth_method, "service": service, "event_type": event_type},
        "doc_count": count,
        "first_seen": {"value_as_string": first},
        "last_seen": {"value_as_string": last},
        "workstation": {"buckets": [{"key": name, "doc_count": 1} for name in workstations]},
    }


class _Client:
    def __init__(self, buckets):
        self.buckets = buckets
        self.bodies = []

    def search(self, *, index, body, params=None):
        self.bodies.append(body)
        return {"aggregations": {"edges": {"buckets": self.buckets if len(self.bodies) == 1 else [], "after_key": None}}}


@pytest.fixture
def run(monkeypatch):
    def _run(buckets, inventory=None, names=None):
        client = _Client(buckets)
        monkeypatch.setattr(lm, "get_opensearch_client", lambda: client)
        monkeypatch.setattr(lm, "get_events_index", lambda case_id: "events")
        monkeypatch.setattr(lm, "index_exists", lambda *_a: True)
        monkeypatch.setattr(lm, "is_index_queryable", lambda *_a: True)
        monkeypatch.setattr(lm, "resolve_aggregatable_field", lambda _c, _i, field: field)
        monkeypatch.setattr(lm, "_host_inventory", lambda db, case_id: (inventory or {}, names or {}))
        return lm.get_lateral_movement(None, "case-1"), client
    return _run


def test_helpers() -> None:
    assert lm.routine_reason("WS01$") == "machine account"
    assert lm.routine_reason("ANONYMOUS LOGON") == "built-in or anonymous account"
    assert lm.routine_reason(None) == "built-in or anonymous account"
    assert lm.routine_reason("alice") is None
    assert lm.method_label("10", None, None).startswith("Remote Desktop")
    assert lm.method_label(None, "sshd", "publickey") == "sshd (publickey)"
    assert not lm._is_remote_address("127.0.0.1") and not lm._is_remote_address("-") and not lm._is_remote_address("::1")
    assert lm._is_remote_address("10.1.2.3") and lm._is_remote_address("jumpbox.example")


def test_edges_merge_outcomes_resolve_sources_and_flag_routine(run) -> None:
    result, client = run(
        [
            _bucket("SRV-A", "10.0.0.5", "alice", "logon_success", 4, "2026-01-01T10:00:00.000Z", "2026-01-01T10:05:00.000Z", logon_type="3", workstations=["WKS-B"]),
            _bucket("SRV-A", "10.0.0.5", "alice", "logon_failed", 2, "2026-01-01T09:58:00.000Z", "2026-01-01T09:59:00.000Z", logon_type="3"),
            _bucket("SRV-A", "10.0.0.5", "alice", "logon_success", 1, "2026-01-01T10:06:00.000Z", "2026-01-01T10:06:00.000Z", logon_type="10", workstations=["SRV-A"]),
            _bucket("SRV-A", "10.0.0.5", "WKS-B$", "logon_success", 50, "2026-01-01T08:00:00.000Z", "2026-01-01T12:00:00.000Z", logon_type="3"),
            _bucket("linux-web", "203.0.113.9", "root", "login_failure", 30, "2026-01-01T07:00:00.000Z", "2026-01-01T07:10:00.000Z", service="sshd", auth_method="password"),
            _bucket("SRV-A", "10.0.0.7", "bob", "logon_success", 1, "2026-01-01T11:00:00.000Z", "2026-01-01T11:00:00.000Z", logon_type="3"),
            _bucket("SRV-A", "127.0.0.1", "alice", "logon_success", 9, "2026-01-01T11:00:00.000Z", "2026-01-01T11:00:00.000Z", logon_type="3"),
        ],
        inventory={"10.0.0.5": ["WKS-A"], "10.0.0.7": ["SRV-A"]},
        names={"WKS-A": "WKS-A", "WKS-B": "WKS-B", "SRV-A": "SRV-A", "LINUX-WEB": "linux-web"},
    )
    query = client.bodies[0]["query"]["bool"]["filter"]
    assert {"terms": {"windows.logon_type": ["3", "8", "10"]}} in query[3]["bool"]["should"]
    edges = result["edges"]
    # Loopback and the host's own address are not movement.
    assert all(edge["source_ip"] not in {"127.0.0.1", "10.0.0.7"} for edge in edges)
    ssh = edges[0]
    assert (ssh["target_host"], ssh["method"], ssh["failures"], ssh["source_hosts"]) == ("linux-web", "sshd (password)", 30, [])
    machine = edges[1]
    assert machine["routine_reason"] == "machine account" and machine["successes"] == 50
    network = edges[2]
    assert (network["successes"], network["failures"]) == (4, 2)
    assert network["first_seen"] == "2026-01-01T09:58:00.000Z" and network["last_seen"] == "2026-01-01T10:05:00.000Z"
    assert network["source_hosts"] == ["WKS-A"] and network["source_workstations"] == ["WKS-B"]
    # The logon names another case host than the one holding the address.
    assert network["workstation_mismatch"] is True
    rdp = edges[3]
    assert rdp["method"].startswith("Remote Desktop")
    # Remote Desktop records the target's own name: not a mismatch.
    assert rdp["source_workstations"] == [] and rdp["workstation_mismatch"] is False


def test_address_on_several_hosts_is_ambiguous_not_resolved(run) -> None:
    result, _ = run(
        [_bucket("SRV-A", "10.0.0.9", "carol", "logon_success", 1, "2026-01-01T10:00:00.000Z", "2026-01-01T10:00:00.000Z", logon_type="3")],
        inventory={"10.0.0.9": ["WKS-A", "WKS-B"]},
    )
    edge = result["edges"][0]
    assert edge["source_hosts"] == ["WKS-A", "WKS-B"] and edge["source_ambiguous"] is True
    assert result["addresses"] == [{"ip": "10.0.0.9", "hosts": ["WKS-A", "WKS-B"], "ambiguous": True}]
