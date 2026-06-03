from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    env_root = os.environ.get("DFIR_REPO_ROOT")
    candidates = [
        Path(env_root) if env_root else None,
        Path(__file__).resolve().parents[2],
        Path(__file__).resolve().parents[1],
        Path("/app"),
    ]
    for candidate in candidates:
        if candidate and (candidate / "docs").exists():
            return candidate
    return Path(__file__).resolve().parents[2]


REPO_ROOT = _repo_root()


def test_beta_deployment_docs_exist_and_cover_operational_basics() -> None:
    docs = {
        "beta-deployment.md": ("private network", "dfir-healthcheck.sh", "Do not expose"),
        "backup-restore.md": ("PostgreSQL logical dump", "Restore Order", "OpenSearch Snapshot"),
        "update-rollback.md": ("Pre-Update", "Rollback", "Smoke"),
        "troubleshooting.md": ("tooling_missing", "disk", "OpenSearch"),
    }

    for filename, expected_terms in docs.items():
        content = (REPO_ROOT / "docs" / "deployment" / filename).read_text(encoding="utf-8")
        for term in expected_terms:
            assert term in content


def test_release_docs_and_license_exist() -> None:
    expected = {
        "README.md": ("private-beta", "Do not expose", ".env.example"),
        "CHANGELOG.md": ("Private Beta Candidate", "Known Limitations"),
        "LICENSE": ("Private Beta Evaluation", "Third-party dependencies"),
        "docs/SECURITY.md": ("Do not expose", "Never commit `.env`"),
        "docs/KNOWN_LIMITATIONS.md": ("SRUM", "Shellbags", "Outlook"),
        "docs/BETA_NOTES.md": ("What To Test", "Reporting Feedback"),
    }

    for relative_path, terms in expected.items():
        content = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        for term in terms:
            assert term in content


def test_gitignore_and_dockerignore_exclude_sensitive_runtime_data() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    for content in (gitignore, dockerignore):
        for term in (
            ".env",
            "data/",
            "uploads/",
            "backups/",
            "logs/",
            "*.7z",
            "*.E01",
            "*.raw",
            "*.ost",
            "*.pst",
        ):
            assert term in content
    assert "!.env.example" in gitignore
    assert "!.env.example" in dockerignore


def test_env_example_uses_placeholders_and_no_default_beta_secrets() -> None:
    content = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

    assert "CHANGE_ME_POSTGRES_PASSWORD" in content
    assert "CHANGE_ME_OPENSEARCH_PASSWORD" in content
    assert "POSTGRES_PASSWORD=dfir" not in content
    assert "OPENSEARCH_PASSWORD=admin" not in content
    assert "DFIR_ALLOW_HOST_PATH_IMPORT=false" in content
    assert "MAX_PARALLEL_ARTIFACTS=1" in content


def test_healthcheck_script_checks_components_without_printing_secrets() -> None:
    content = (REPO_ROOT / "scripts" / "dfir-healthcheck.sh").read_text(encoding="utf-8")

    for term in (
        "/api/system/status",
        "/api/system/task-health",
        "frontend",
        "opensearch",
        "queues",
        "worker",
        "disk",
        "parser_tools",
    ):
        assert term in content
    assert "POSTGRES_PASSWORD" not in content
    assert "OPENSEARCH_PASSWORD" not in content


def test_backup_dry_run_is_safe_and_redacts_database_details() -> None:
    script = REPO_ROOT / "scripts" / "dfir-backup.sh"
    result = subprocess.run(
        ["sh", str(script), "--dry-run"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "POSTGRES_USER": "secret_user", "POSTGRES_DB": "secret_db"},
    )

    assert "Would create:" in result.stdout
    assert "pg_dump -U <redacted> -d <redacted>" in result.stdout
    assert "secret_user" not in result.stdout
    assert "secret_db" not in result.stdout
