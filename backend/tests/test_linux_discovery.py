from pathlib import Path

from app.ingest.csv_json import list_generic_artifacts
from app.ingest.linux.discovery import build_linux_inventory
from app.ingest.linux.journal import parse_journal
from app.services.parser_registry import get_parser_registry_entry


def test_linux_inventory_detects_identity_distribution_hostname_kernel_and_coverage(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "var/log/audit").mkdir(parents=True)
    (tmp_path / "home/alice").mkdir(parents=True)
    (tmp_path / "proc").mkdir()
    (tmp_path / "etc/os-release").write_text('PRETTY_NAME="Ubuntu 24.04 LTS"\n', encoding="utf-8")
    (tmp_path / "etc/hostname").write_text("web01\n", encoding="utf-8")
    (tmp_path / "proc/version").write_text("Linux version 6.8.0-31-generic (buildd@ubuntu)\n", encoding="utf-8")
    (tmp_path / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n", encoding="utf-8")
    (tmp_path / "var/log/auth.log").write_text("Accepted password for alice from 10.0.0.5\n", encoding="utf-8")
    (tmp_path / "var/log/audit/audit.log").write_text("type=SYSCALL msg=audit(1710000000.1:7): arch=c000003e\n", encoding="utf-8")
    (tmp_path / "home/alice/.bash_history").write_text("id\n", encoding="utf-8")
    (tmp_path / "etc/selinux").mkdir()
    (tmp_path / "etc/selinux/config").write_text("SELINUX=enforcing\n", encoding="utf-8")

    files = [str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file()]
    inventory = build_linux_inventory(tmp_path, files)

    assert inventory is not None
    assert inventory["distribution"] == "Ubuntu 24.04 LTS"
    assert inventory["hostname"] == "web01"
    assert inventory["kernel"] == "6.8.0-31-generic"
    assert inventory["users"] == ["root", "alice"]
    detected = {item["key"] for item in inventory["detected_artifacts"]}
    assert {"auth_log", "audit_log", "shell_history", "identity", "os_info"} <= detected
    assert inventory["coverage"]["detected"] == inventory["coverage"]["supported"] + inventory["coverage"]["unsupported"]
    assert inventory["coverage"]["coverage_percent"] == round((inventory["coverage"]["supported"] / inventory["coverage"]["detected"]) * 100)
    assert any(item["label"] == "SELinux database" for item in inventory["unsupported"])


def test_linux_inventory_falls_back_to_hostnamectl_when_etc_hostname_is_missing(tmp_path: Path) -> None:
    (tmp_path / "commands").mkdir()
    (tmp_path / "commands/hostnamectl.txt").write_text(
        "Static hostname: web02\nOperating System: Ubuntu 26.04 LTS\nKernel: Linux 6.9.0-test\n",
        encoding="utf-8",
    )

    inventory = build_linux_inventory(tmp_path, ["commands/hostnamectl.txt"])

    assert inventory is not None
    assert inventory["hostname"] == "web02"
    assert inventory["distribution"] == "Ubuntu 26.04 LTS"
    assert inventory["kernel"] == "6.9.0-test"


def test_generic_artifact_listing_includes_linux_files_without_extensions(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    (tmp_path / "etc/sudoers").write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    (tmp_path / "etc/cron.d").mkdir(parents=True)
    (tmp_path / "etc/cron.d/kairon").write_text("* * * * * root /usr/local/bin/check.sh\n", encoding="utf-8")

    artifacts = list_generic_artifacts(tmp_path)

    by_name = {artifact["name"]: artifact for artifact in artifacts}
    assert by_name["passwd"]["artifact_type"] == "linux_identity"
    assert by_name["passwd"]["artifact_family"] == "linux_identity"
    assert by_name["sudoers"]["artifact_type"] == "linux_sudoers"
    assert by_name["kairon"]["artifact_type"] == "linux_cron"


def test_linux_inventory_and_generic_listing_include_journal_exports(tmp_path: Path) -> None:
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs/journal.export").write_text("__REALTIME_TIMESTAMP=1710000000000000\n_HOSTNAME=web01\nSYSLOG_IDENTIFIER=sshd\nMESSAGE=Accepted publickey for alice\n\n", encoding="utf-8")
    (tmp_path / "logs/journal.json").write_text('{"__REALTIME_TIMESTAMP":"1710000000000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Started nginx.service"}\n', encoding="utf-8")

    inventory = build_linux_inventory(tmp_path, ["logs/journal.export", "logs/journal.json"])
    artifacts = list_generic_artifacts(tmp_path)
    registry_entry = get_parser_registry_entry(artifact_type="linux_journal")

    assert inventory is not None
    assert any(item["family"] == "linux_journal" for item in inventory["detected_artifacts"])
    assert any(item["artifact_type"] == "linux_journal" for item in artifacts)
    assert registry_entry["parser_name"] == "linux_journal_raw"


def test_journal_parser_handles_json_and_export() -> None:
    json_rows = parse_journal('{"__REALTIME_TIMESTAMP":"1710000000000000","_HOSTNAME":"db01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for root"}\n', source_path="journal.json")
    export_rows = parse_journal("__REALTIME_TIMESTAMP=1710000000000000\n_HOSTNAME=db01\nSYSLOG_IDENTIFIER=sudo\nMESSAGE=session opened\n\n", source_path="journal.export")

    assert json_rows[0]["artifact_type"] == "linux_journal"
    assert json_rows[0]["hostname"] == "db01"
    assert export_rows[0]["process"] == "sudo"
    assert export_rows[0]["source_path"] == "journal.export"
