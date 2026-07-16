from app.ingest.normalizer import normalize_row


def _linux_meta(**overrides):
    return {
        "name": "syslog",
        "artifact_type": "linux_syslog",
        "artifact_family": "linux_syslog",
        "parser": "linux_syslog_raw",
        "source_path": "volume-3/linux/var/log/syslog",
        "original_source_path": "/var/log/syslog",
        "disk_image_id": "disk-1",
        "disk_volume_id": "vol-1",
        "os_installation_id": "os-1",
        "logical_source_path": "volume-3/linux/var/log/syslog",
        "acquisition_method": "pytsk3_readonly_materialization",
        **overrides,
    }


def test_linux_syslog_normalization_preserves_source_identity_with_defender_like_headers() -> None:
    row = {
        "artifact_family": "linux_syslog",
        "artifact_type": "syslog",
        "source_file": "volume-3/linux/var/log/syslog",
        "timestamp": "2026-07-16T20:00:00+00:00",
        "host": "vm-101",
        "severity": "info",
        "message": "system message",
    }

    document = normalize_row("case-1", "ev-1", "artifact-1", row, _linux_meta())

    assert document["artifact"]["type"] == "linux_syslog"
    assert document["artifact"]["family"] == "linux_syslog"
    assert document["artifact"]["parser"] == "linux_syslog_raw"
    assert document["event"]["category"] == "linux_syslog"
    assert document["linux"]["artifact_family"] == "linux_syslog"


def test_linux_syslog_index_document_keeps_provenance_fields() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "artifact-1",
        {"artifact_family": "linux_syslog", "artifact_type": "syslog", "source_file": "volume-3/linux/var/log/syslog", "message": "message"},
        _linux_meta(),
    )

    assert document["evidence_source"] == {
        "disk_image_id": "disk-1",
        "disk_volume_id": "vol-1",
        "os_installation_id": "os-1",
        "original_path": "/var/log/syslog",
        "logical_source_path": "volume-3/linux/var/log/syslog",
        "acquisition_method": "pytsk3_readonly_materialization",
    }


def test_linux_auth_identity_does_not_regress() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "artifact-1",
        {"artifact_family": "linux_auth", "artifact_type": "auth_log", "source_file": "volume-3/linux/var/log/auth.log", "message": "sudo session opened"},
        _linux_meta(name="auth.log", artifact_type="linux_auth", artifact_family="linux_auth", parser="linux_auth_raw", source_path="volume-3/linux/var/log/auth.log", original_source_path="/var/log/auth.log"),
    )

    assert document["artifact"]["type"] == "linux_auth"
    assert document["event"]["category"] == "linux_auth"


def test_generic_detection_document_without_source_family_still_uses_detection_identity() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "artifact-1",
        {"ThreatName": "EICAR-Test-File", "Severity": "High", "Action": "Detected", "Path": "C:\\Temp\\eicar.com"},
        {"name": "DetectionHistory", "artifact_type": "detection", "parser": "defender_csv", "source_path": "DetectionHistory.csv"},
    )

    assert document["artifact"]["type"] == "detection"
    assert document["event"]["category"] == "detection"
    assert document["detection"]["threat_name"] == "EICAR-Test-File"
