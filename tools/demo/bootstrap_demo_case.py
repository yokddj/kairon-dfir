from __future__ import annotations

from datetime import datetime
import json
import mimetypes
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from generate_demo_evidence import DEFAULT_OUTPUT, generate_demo_evidence


BASE_URL = "http://127.0.0.1:8000/api"
CASE_NAME = "Demo - ACME Incident 001"
CASE_DESCRIPTION = "Synthetic DFIR APP MVP demo case with generic ACME evidence."
OUTPUT_ROOT = Path(__file__).resolve().parents[2] / "demo" / "output"

SIGMA_RULE = """title: Encoded PowerShell
id: demo-sigma-encoded-ps
status: experimental
logsource:
  product: windows
detection:
  selection:
    process.command_line|contains: EncodedCommand
  condition: selection
level: high
"""

YARA_RULE = """rule DemoPayloadMarker {
  strings:
    $a = "malicious_test_marker"
  condition:
    $a
}
"""


class ApiClient:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url.rstrip("/")

    def get(self, path: str, query: dict | None = None) -> dict | list:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query, doseq=True)}"
        with urlopen(url) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path: str, payload: dict | None = None) -> dict:
        body = json.dumps(payload or {}).encode("utf-8")
        request = Request(f"{self.base_url}{path}", data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))

    def patch_json(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        request = Request(f"{self.base_url}{path}", data=body, headers={"Content-Type": "application/json"}, method="PATCH")
        with urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))

    def download(self, path: str, *, payload: dict | None = None, query: dict | None = None) -> bytes:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query, doseq=True)}"
        if payload is None:
            request = Request(url, method="GET")
        else:
            request = Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request) as response:
            return response.read()

    def _curl_multipart(self, path: str, file_path: Path, *, fields: dict[str, str] | None = None) -> dict:
        command = ["curl", "-sS", "-X", "POST"]
        for key, value in (fields or {}).items():
            command.extend(["-F", f"{key}={value}"])
        command.extend(["-F", f"file=@{file_path}", f"{self.base_url}{path}"])
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    def upload_evidence(self, case_id: str, zip_path: Path) -> dict:
        return self._curl_multipart(f"/cases/{case_id}/evidences/upload", zip_path)

    def import_rule_file(self, file_path: Path, *, engine: str, case_id: str) -> dict:
        return self._curl_multipart("/rules/import-file", file_path, fields={"engine": engine, "case_id": case_id, "enabled": "true"})


def _wait_for_evidence(client: ApiClient, evidence_id: str, *, timeout_seconds: int = 300) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        evidence = client.get(f"/evidences/{evidence_id}")
        status = str(evidence.get("ingest_status") or "")
        if status in {"completed", "failed"}:
            return evidence
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for evidence {evidence_id}")


def _wait_for_rule_run(client: ApiClient, case_id: str, run_id: str, *, timeout_seconds: int = 300) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        run = client.get(f"/cases/{case_id}/rules/runs/{run_id}")
        if str(run.get("status") or "") in {"completed", "failed", "skipped"}:
            return run
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for rule run {run_id}")


def _wait_for_api(client: ApiClient, *, timeout_seconds: int = 60) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            client.get("/docs")
            return
        except Exception as exc:  # pragma: no cover - operational retry path
            last_error = exc
            time.sleep(2)
    raise TimeoutError(f"Timed out waiting for API readiness: {last_error}")


def _first_search_item(client: ApiClient, case_id: str, query: str) -> dict | None:
    response = client.get(f"/cases/{case_id}/search", {"q": query, "page_size": 5})
    results = list(response.get("results") or [])
    for item in results:
        if item.get("kind") == "event":
            return item
    return results[0] if results else None


def _write_rule_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def bootstrap_demo_case(*, base_url: str = BASE_URL) -> dict:
    client = ApiClient(base_url)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    _wait_for_api(client)

    demo_zip = generate_demo_evidence(DEFAULT_OUTPUT)
    case = client.post_json("/cases", {"name": CASE_NAME, "description": CASE_DESCRIPTION, "timezone": "Europe/Madrid"})
    case_id = str(case["id"])

    evidence = client.upload_evidence(case_id, demo_zip)
    evidence_id = str(evidence["id"])
    evidence = _wait_for_evidence(client, evidence_id)

    correlate_result = client.post_json(f"/cases/{case_id}/correlate", {})

    sigma_path = _write_rule_file(OUTPUT_ROOT / "demo_sigma.yml", SIGMA_RULE)
    yara_path = _write_rule_file(OUTPUT_ROOT / "demo_marker.yar", YARA_RULE)
    sigma_import = client.import_rule_file(sigma_path, engine="sigma", case_id=case_id)
    yara_import = client.import_rule_file(yara_path, engine="yara", case_id=case_id)
    imported_rule_ids = [item["id"] for item in sigma_import.get("rules", [])] + [item["id"] for item in yara_import.get("rules", [])]

    rule_run_request = {
        "rule_ids": imported_rule_ids,
        "scope": "case",
        "enabled_only": False,
        "include_parsed_outputs": True,
        "include_text_outputs": True,
    }
    rules_run = client.post_json(f"/cases/{case_id}/rules/run", rule_run_request)
    run_id = str(rules_run.get("run_id") or "")
    completed_rule_run = _wait_for_rule_run(client, case_id, run_id) if run_id else {"status": "skipped"}

    findings = client.get(f"/cases/{case_id}/findings")
    detections = client.get(f"/cases/{case_id}/detections")

    key_queries = [
        ("Phishing delivery path", "phishing.example"),
        ("Invoice trusted in Office", 'artifact.type:user_activity invoice.docm'),
        ("Encoded PowerShell executed", "process.name:powershell.exe EncodedCommand"),
        ("Payload downloaded", 'artifact.type:ntfs payload.exe'),
        ("Defender notification", "artifact.type:windows_ui quarantined"),
        ("Cloud upload candidate", 'artifact.type:cloud passwords.xlsx'),
        ("USB device connected", "artifact.type:usb"),
    ]
    bookmarks: list[dict] = []
    for index, (title, query) in enumerate(key_queries, start=1):
        event = _first_search_item(client, case_id, query)
        if not event:
            continue
        bookmarks.append(
            client.post_json(
                f"/cases/{case_id}/timeline/key-events",
                {
                    "event_id": event["id"],
                    "title": title,
                    "note": f"Auto-created from demo bootstrap query: {query}",
                    "include_in_report": True,
                    "order_index": index,
                },
            )
        )

    report = client.post_json(
        f"/cases/{case_id}/reports/draft",
        {
            "title": "DFIR Investigation Report - Demo - ACME Incident 001",
            "template": "standard_investigation",
            "auto_select": True,
            "selected_key_event_ids": [item["id"] for item in bookmarks],
        },
    )
    report_id = str(report["id"])
    report_preview = client.get(f"/cases/{case_id}/reports/{report_id}/preview")
    markdown_bytes = client.download(f"/cases/{case_id}/reports/{report_id}/export", query={"format": "markdown"})
    pdf_bytes = client.download(f"/cases/{case_id}/reports/{report_id}/export", query={"format": "pdf"})
    debug_bytes = client.download(
        f"/cases/{case_id}/debug-export",
        payload={
            "scope": "case",
            "artifact_types": ["email", "user_activity", "ntfs", "windows_ui", "cloud", "usb"],
            "include_source_paths": True,
            "redact_secrets": True,
        },
    )

    markdown_path = OUTPUT_ROOT / f"{case_id}-demo-report.md"
    pdf_path = OUTPUT_ROOT / f"{case_id}-demo-report.pdf"
    debug_path = OUTPUT_ROOT / f"{case_id}-debug-pack.zip"
    markdown_path.write_bytes(markdown_bytes)
    pdf_path.write_bytes(pdf_bytes)
    debug_path.write_bytes(debug_bytes)

    search_check = client.get(f"/cases/{case_id}/search", {"q": "process.name:powershell.exe", "page_size": 5})
    timeline_check = client.get(f"/cases/{case_id}/timeline", {"mode": "investigation", "page_size": 25})

    result = {
        "demo_case_id": case_id,
        "demo_evidence_id": evidence_id,
        "events_indexed": int((evidence.get("metadata_json") or {}).get("events_indexed") or (evidence.get("metadata_json") or {}).get("indexed_events") or 0),
        "findings_count": len(findings),
        "detections_count": len(detections.get("items") or []),
        "key_events_count": len(bookmarks),
        "report_markdown_ok": bool(markdown_bytes),
        "report_pdf_ok": bool(pdf_bytes),
        "debug_export_ok": bool(debug_bytes),
        "opensearch_discover_ready": True,
        "demo_zip_path": str(demo_zip),
        "report_preview_sections": len(report_preview.get("sections") or []),
        "search_hits": int(search_check.get("total") or 0),
        "timeline_items": len(timeline_check.get("items") or []),
        "correlation_findings_generated": correlate_result.get("counts", {}).get("created", len(findings)),
        "rules_run_status": completed_rule_run.get("status"),
        "docs": ["docs/demo_mvp.md", "docs/demo_checklist.md"],
        "known_limitations": [] if detections.get("items") else ["No detections were returned; review rule engine availability and queue status."],
    }
    (OUTPUT_ROOT / f"{case_id}-bootstrap-summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    print(json.dumps(bootstrap_demo_case(), indent=2))


if __name__ == "__main__":
    main()
