from __future__ import annotations

import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "email_artifacts.py"
_SPEC = importlib.util.spec_from_file_location("email_artifacts_under_test", _MODULE_PATH)
assert _SPEC and _SPEC.loader
email_artifacts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(email_artifacts)


def test_detect_outlook_ost_and_account_hint() -> None:
    path = r"C:\Users\usera\AppData\Local\Microsoft\Outlook\user.a@outlook.es.ost"

    assert email_artifacts.classify_email_artifact(path) == "store"
    assert email_artifacts.classify_email_client(path) == "outlook"
    assert email_artifacts.extract_account_hint(file_path=path) == "user.a@outlook.es"


def test_classify_message_files_and_attachment_cache() -> None:
    assert email_artifacts.classify_email_artifact(r"C:\Users\alice\Downloads\invoice.eml") == "message_file"
    assert email_artifacts.classify_email_artifact(r"C:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABC\invoice.iso") == "attachment_cache"


def test_classify_webmail_activity() -> None:
    assert email_artifacts.classify_email_artifact("https://outlook.office.com/mail/inbox") == "webmail_activity"
    assert email_artifacts.classify_email_artifact("https://outlook.office.com/mail/inbox", "browser") == "webmail_activity"
    assert email_artifacts.classify_email_artifact("Sysmon DNS query: outlook.office.com", "dns") == "webmail_activity"
    assert email_artifacts.classify_email_artifact("MFT entry observed: outlook.office.com.txt", "mft") is None
    assert email_artifacts.classify_email_client("", "https://outlook.office.com/mail/inbox") == "outlook"


def test_zone_identifier_path_alone_is_not_email() -> None:
    path = r"C:\Users\Administrator.EXAMPLECORP\Downloads\loupe-mono-dark.heic:Zone.Identifier"

    assert email_artifacts.classify_email_artifact(path, "motw") is None
    assert email_artifacts.classify_email_artifact(r".\share\Software\vlc.msi:Zone.Identifier", "motw") is None


def test_windows_mail_package_presence_is_grouped_and_technical_traces_hidden() -> None:
    package_dll = r"C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.14326.21854.0_x64__8wekyb3d8bbwe\HxAccounts.exe"
    package_etl = r"C:\Users\alice\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxCommAlwaysOnLog_Old.etl"

    assert email_artifacts.classify_email_artifact(package_dll, "mft") == "app_presence"
    assert email_artifacts.classify_email_artifact(package_etl, "mft") == "technical_trace"

    rows = [
        email_artifacts._normalize_row("case-1", "mft", {"id": "wm-1", "host": {"name": "HOSTA"}, "file": {"path": package_dll, "name": "HxAccounts.exe"}}),
        email_artifacts._normalize_row("case-1", "mft", {"id": "wm-2", "host": {"name": "HOSTA"}, "file": {"path": package_dll.replace("HxAccounts.exe", "HxCalendar.dll"), "name": "HxCalendar.dll"}}),
        email_artifacts._normalize_row("case-1", "mft", {"id": "wm-3", "host": {"name": "HOSTA"}, "file": {"path": package_etl, "name": "HxCommAlwaysOnLog_Old.etl"}}),
    ]
    grouped = email_artifacts._group_windows_mail_presence([item for item in rows if item])

    visible = [item for item in grouped if item["email_artifact_type"] != "technical_trace"]
    technical = [item for item in grouped if item["email_artifact_type"] == "technical_trace"]
    assert len(visible) == 1
    assert visible[0]["email_artifact_type"] == "app_presence"
    assert visible[0]["file_name"] == "microsoft.windowscommunicationsapps"
    assert visible[0]["risk_score"] == 5
    assert visible[0]["grouped_source_count"] == 2
    assert len(technical) == 1


def test_motw_with_mail_host_url_is_related_email_download() -> None:
    item = email_artifacts._normalize_row(
        "case-1",
        "motw",
        {
            "id": "motw-mail",
            "host": {"name": "HOSTA"},
            "file": {"path": r"C:\Users\usera\Downloads\invoice.pdf:Zone.Identifier", "name": "invoice.pdf:Zone.Identifier"},
            "ntfs": {"host_url": "https://outlook.office.com/mail/attachment/invoice.pdf"},
        },
    )

    assert item
    assert item["email_artifact_type"] == "related_email_download"
    assert item["relation_reason"]
    assert item["confidence"] == "high"


def test_ost_scoring_does_not_claim_message_content() -> None:
    score, reasons = email_artifacts.score_email_item("store", "outlook", "user.a@outlook.es.ost")

    assert score >= 20
    assert "mail_store_detected" in reasons


def test_list_email_artifacts_correlates_downloads_and_motw(monkeypatch) -> None:
    def fake_search(case_id, params, db=None):  # noqa: ANN001
        artifact_types = set(params.get("artifact_type") or [])
        if "mft" in artifact_types:
            return 2, [
                {
                    "id": "mft-ost",
                    "case_id": case_id,
                    "evidence_id": "ev-1",
                    "host": {"name": "HOSTA"},
                    "artifact": {"type": "mft"},
                    "file": {
                        "path": r"C:\Users\usera\AppData\Local\Microsoft\Outlook\user.a@outlook.es.ost",
                        "name": "user.a@outlook.es.ost",
                        "size": 123,
                    },
                },
                {
                    "id": "mft-msg",
                    "case_id": case_id,
                    "evidence_id": "ev-1",
                    "host": {"name": "HOSTA"},
                    "artifact": {"type": "mft"},
                    "file": {"path": r"C:\Users\usera\Downloads\note.eml", "name": "note.eml"},
                },
            ], [], {}
        if "browser" in artifact_types:
            return 1, [
                {
                    "id": "browser-outlook",
                    "case_id": case_id,
                    "evidence_id": "ev-1",
                    "host": {"name": "HOSTA"},
                    "artifact": {"type": "browser"},
                    "browser": {"url": "https://outlook.office.com/mail/inbox", "domain": "outlook.office.com"},
                    "event": {"message": "Outlook webmail visit"},
                }
            ], [], {}
        if "motw" in artifact_types:
            return 2, [
                {
                    "id": "motw-generic",
                    "case_id": case_id,
                    "evidence_id": "ev-1",
                    "host": {"name": "HOSTA"},
                    "artifact": {"type": "motw"},
                    "file": {"path": r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier", "name": "sample.iso:Zone.Identifier"},
                },
                {
                    "id": "motw-mail",
                    "case_id": case_id,
                    "evidence_id": "ev-1",
                    "host": {"name": "HOSTA"},
                    "artifact": {"type": "motw"},
                    "file": {"path": r"C:\Users\usera\Downloads\invoice.pdf:Zone.Identifier", "name": "invoice.pdf:Zone.Identifier"},
                    "ntfs": {"host_url": "https://outlook.office.com/mail/attachment/invoice.pdf"},
                },
            ], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(email_artifacts, "search_events_v2", fake_search)
    result = email_artifacts.list_email_artifacts(None, "case-1", {"page_size": 25})
    by_type = result["summary"]["by_type"]
    store = next(item for item in result["items"] if item["email_artifact_type"] == "store")

    assert by_type["store"] == 1
    assert by_type["message_file"] == 1
    assert result["summary"]["webmail_activity"] == 1
    assert result["summary"]["related_email_downloads"] == 1
    assert not any("sample.iso:Zone.Identifier" in str(item.get("file_path") or "") for item in result["items"])
    assert store["account_hint"] == "user.a@outlook.es"
    assert store["content_parsed"] is False
    assert store["related_downloads"]
    assert store["related_motw"]
    assert store["related_motw"][0]["relation_reason"]
    assert "Mail stores are detected" in result["limitations"][0]


def test_email_report_markdown_includes_content_caveat() -> None:
    markdown = email_artifacts.render_email_artifacts_markdown(
        [
            {
                "host": "HOSTA",
                "email_artifact_type": "store",
                "client": "outlook",
                "account_hint": "user.a@outlook.es",
                "file_path": r"C:\Users\usera\AppData\Local\Microsoft\Outlook\user.a@outlook.es.ost",
                "content_parsed": False,
                "related_downloads": [{"id": "d1"}],
                "related_motw": [{"id": "m1"}],
                "related_user_activity": [],
            }
        ]
    )

    assert "Mail store presence does not prove malicious email content" in markdown
    assert "user.a@outlook.es" in markdown
    assert "| HOSTA | store | outlook |" in markdown
