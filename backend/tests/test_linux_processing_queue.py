from types import SimpleNamespace

from app.services.processing_queue import _linux_processing_rows


def test_linux_processing_rows_expose_detected_parsed_unsupported_and_not_found() -> None:
    evidence = SimpleNamespace(
        metadata_json={
            "linux_inventory": {
                "processing": [
                    {"name": "auth.log", "family": "linux_auth", "status": "Detected", "paths": ["var/log/auth.log"]},
                    {"name": "SELinux database", "family": "selinux_database", "status": "Unsupported", "paths": ["etc/selinux/config"]},
                    {"name": "journal export", "family": "journal_export", "status": "Not found", "paths": []},
                ]
            }
        }
    )
    artifacts = [SimpleNamespace(artifact_type="linux_auth", status="completed", record_count=7)]

    rows = _linux_processing_rows(evidence, artifacts)  # type: ignore[arg-type]

    assert rows[0]["name"] == "auth.log"
    assert rows[0]["status"] == "Parsed"
    assert rows[0]["records"] == 7
    assert rows[1]["status"] == "Unsupported"
    assert rows[2]["status"] == "Not Found"
