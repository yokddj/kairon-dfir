from __future__ import annotations

import mailbox
import mimetypes
import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlparse

from app.ingest.email.helpers import (
    basename_windows,
    clean_value,
    extract_ipv4s,
    extract_urls,
    is_outlook_temp_attachment_path,
    is_thunderbird_profile_path,
    is_windows_mail_inventory_path,
    normalize_windows_path,
    parse_email_domain,
    redact_secret_like_text,
    suffix_windows,
)
from app.ingest.identity_extraction import extract_user_from_path


EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".msi", ".dll", ".hta", ".jar", ".lnk"}
SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1xml"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".cab"}
SUSPICIOUS_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}[^\s\"'<>()]*", re.IGNORECASE)
MBOX_MAX_MESSAGES = 500


def _parse_address_list(value: object | None) -> list[dict[str, str | None]]:
    entries: list[dict[str, str | None]] = []
    for display_name, address in getaddresses([str(value or "")]):
        if not address:
            continue
        entries.append(
            {
                "address": address.strip(),
                "display_name": display_name.strip() or None,
            }
        )
    return entries


def _extract_body_preview(message: Message, *, max_len: int = 1200) -> str | None:
    candidates: list[str] = []
    if isinstance(message, EmailMessage):
        text_body = message.get_body(preferencelist=("plain",))
        if text_body is not None:
            try:
                candidates.append(text_body.get_content())
            except Exception:  # noqa: BLE001
                pass
        html_body = message.get_body(preferencelist=("html",))
        if html_body is not None:
            try:
                html_text = re.sub(r"<[^>]+>", " ", html_body.get_content())
                candidates.append(html_text)
            except Exception:  # noqa: BLE001
                pass
    if not candidates:
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = str(part.get_content_type() or "").lower()
            filename = part.get_filename()
            if filename:
                continue
            if content_type.startswith("text/"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        payload_text = part.get_payload()
                    else:
                        charset = part.get_content_charset() or "utf-8"
                        payload_text = payload.decode(charset, errors="ignore")
                    candidates.append(payload_text)
                except Exception:  # noqa: BLE001
                    continue
    preview = next((text for text in candidates if str(text).strip()), None)
    if not preview:
        return None
    preview = re.sub(r"\s+", " ", str(preview)).strip()
    return redact_secret_like_text(preview, max_len=max_len)


def _attachment_risk(file_name: str | None) -> tuple[bool, list[str], int]:
    lower_name = str(file_name or "").lower()
    ext = Path(lower_name).suffix.lower()
    reasons: list[str] = []
    risk = 5
    if ext in EXECUTABLE_EXTENSIONS:
        reasons.append("Executable attachment")
        risk = max(risk, 90)
    if ext in SCRIPT_EXTENSIONS:
        reasons.append("Script attachment")
        risk = max(risk, 90)
    if ext in MACRO_EXTENSIONS:
        reasons.append("Macro-enabled Office attachment")
        risk = max(risk, 80)
    if ext in ARCHIVE_EXTENSIONS:
        reasons.append("Archive attachment")
        risk = max(risk, 60)
    if lower_name.count(".") >= 2:
        parts = lower_name.split(".")
        if f".{parts[-1]}" in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS and f".{parts[-2]}" in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}:
            reasons.append("Double extension attachment")
            risk = max(risk, 90)
    return bool(reasons), reasons, risk


def _parse_auth_results(authentication_results: str | None, received_spf: str | None) -> tuple[str, str, str]:
    blob = f"{authentication_results or ''} {received_spf or ''}".lower()
    def _extract(name: str) -> str:
        match = re.search(rf"{name}\s*=\s*([a-z_]+)", blob)
        return str(match.group(1)) if match else "unknown"
    return _extract("spf"), _extract("dmarc"), _extract("dkim")


def _message_to_row(message: Message, *, source_file: str, parser_name: str, source_kind: str, mailbox_name: str | None = None, message_index: int | None = None) -> dict:
    from_entries = _parse_address_list(message.get("From"))
    to_entries = _parse_address_list(message.get("To"))
    cc_entries = _parse_address_list(message.get("Cc"))
    bcc_entries = _parse_address_list(message.get("Bcc"))
    reply_to_entries = _parse_address_list(message.get("Reply-To"))
    message_id = clean_value(message.get("Message-ID"))
    subject = clean_value(message.get("Subject"))
    auth_results = clean_value(message.get("Authentication-Results"))
    received_spf = clean_value(message.get("Received-SPF"))
    spf_result, dmarc_result, dkim_result = _parse_auth_results(auth_results, received_spf)
    dkim_present = bool(message.get("DKIM-Signature"))
    body_preview = _extract_body_preview(message)
    urls = extract_urls(body_preview)
    ips = extract_ipv4s(body_preview)
    suspicious_url_present = any(SUSPICIOUS_URL_RE.search(url) for url in urls)

    attachments: list[dict] = []
    suspicious_attachment_count = 0
    attachment_risk = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        content_type = str(part.get_content_type() or mimetypes.guess_type(filename)[0] or "application/octet-stream")
        size = len(payload) if payload is not None else None
        is_suspicious, reasons, risk = _attachment_risk(filename)
        if is_suspicious:
            suspicious_attachment_count += 1
            attachment_risk = max(attachment_risk, risk)
        attachments.append(
            {
                "file_name": filename,
                "content_type": content_type,
                "size": size,
                "extension": Path(filename).suffix.lower() or None,
                "is_suspicious": is_suspicious,
                "risk_reasons": reasons,
            }
        )

    from_address = from_entries[0]["address"] if from_entries else None
    reply_to_address = reply_to_entries[0]["address"] if reply_to_entries else None
    from_domain = parse_email_domain(from_address)
    reply_to_domain = parse_email_domain(reply_to_address)
    url_domains = [urlparse(url).hostname.lower() for url in urls if urlparse(url).hostname]
    all_domains = {
        item
        for item in [
            from_domain,
            reply_to_domain,
            *[parse_email_domain(entry["address"]) for entry in to_entries],
            *[parse_email_domain(entry["address"]) for entry in cc_entries],
            *[parse_email_domain(entry["address"]) for entry in bcc_entries],
            *url_domains,
        ]
        if item
    }

    suspicious_reasons: list[str] = []
    tags: list[str] = []
    risk_score = 15
    auth_failure = False
    if suspicious_attachment_count:
        suspicious_reasons.append("Suspicious email attachment observed")
        tags.append("suspicious_attachment")
        risk_score = max(risk_score, attachment_risk)
    if spf_result in {"fail", "softfail"}:
        suspicious_reasons.append(f"SPF {spf_result}")
        tags.append("email_auth_warning")
        risk_score = max(risk_score, 60)
        auth_failure = True
    if dkim_result == "fail":
        suspicious_reasons.append("DKIM fail")
        tags.append("email_auth_warning")
        risk_score = max(risk_score, 65)
        auth_failure = True
    if dmarc_result == "fail":
        suspicious_reasons.append("DMARC fail")
        tags.append("email_auth_warning")
        risk_score = max(risk_score, 70)
        auth_failure = True
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        suspicious_reasons.append("Reply-To domain mismatch")
        tags.append("email_reply_to_mismatch")
        risk_score = max(risk_score, 55)
    originating_ip = clean_value(message.get("X-Originating-IP"))
    if originating_ip:
        ips.extend(extract_ipv4s(originating_ip))
        suspicious_reasons.append("X-Originating-IP present")
        tags.append("email_originating_ip")
        risk_score = max(risk_score, 35)
    if suspicious_url_present:
        suspicious_reasons.append("Suspicious URL in email body preview")
        tags.append("suspicious_url")
        risk_score = max(risk_score, 65)
    if not message_id:
        suspicious_reasons.append("Missing Message-ID")
        risk_score = max(risk_score, 25)

    raw_size = len(message.as_bytes(policy=policy.default))
    return {
        "EventType": "email_message",
        "Date": clean_value(message.get("Date")),
        "ClientSubmitTime": clean_value(message.get("X-MS-Exchange-Organization-DateReceived")),
        "MessageID": message_id,
        "Subject": subject,
        "FromAddress": from_address,
        "FromDisplayName": from_entries[0]["display_name"] if from_entries else None,
        "ToAddresses": [entry["address"] for entry in to_entries],
        "CcAddresses": [entry["address"] for entry in cc_entries],
        "BccAddresses": [entry["address"] for entry in bcc_entries],
        "ReplyTo": reply_to_address,
        "ReturnPath": clean_value(message.get("Return-Path")),
        "XMailer": clean_value(message.get("X-Mailer")),
        "UserAgent": clean_value(message.get("User-Agent")),
        "AuthenticationResults": auth_results,
        "ReceivedSPF": received_spf,
        "SPFResult": spf_result,
        "DMARCResult": dmarc_result,
        "DKIMResult": dkim_result,
        "DKIMPresent": dkim_present,
        "XOriginatingIP": originating_ip,
        "Attachments": attachments,
        "SuspiciousAttachmentCount": suspicious_attachment_count,
        "BodyPreview": body_preview,
        "Urls": urls,
        "Domains": sorted(all_domains),
        "IPs": sorted({ip for ip in ips if ip}),
        "RiskScore": risk_score,
        "SuspiciousReasons": suspicious_reasons,
        "Tags": sorted(set(tags)),
        "AuthFailure": auth_failure,
        "MessageSize": raw_size,
        "SourceFile": source_file,
        "SourceKind": source_kind,
        "MailboxName": mailbox_name,
        "MessageIndex": message_index,
        "ParserStatus": "parsed",
        "FilePath": source_file,
        "FileSize": raw_size,
        "FileSHA256": None,
    }


def parse_eml_file(path: Path, *, source_path: str | None = None) -> tuple[list[dict], dict]:
    source = normalize_windows_path(source_path or str(path)) or str(path)
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    row = _message_to_row(message, source_file=source, parser_name="email_eml", source_kind="eml_file")
    audit = {
        "records_read": 1,
        "records_parsed": 1,
        "records_indexed": 1,
        "message_count": 1,
        "attachment_count": len(row.get("Attachments") or []),
        "suspicious_attachment_count": int(row.get("SuspiciousAttachmentCount") or 0),
        "auth_failure_count": 1 if row.get("AuthFailure") else 0,
        "warnings": [],
        "parser_errors": [],
    }
    return [row], audit


def parse_mbox_file(path: Path, *, source_path: str | None = None, max_messages: int = MBOX_MAX_MESSAGES) -> tuple[list[dict], dict]:
    source = normalize_windows_path(source_path or str(path)) or str(path)
    mailbox_name = path.name
    rows: list[dict] = []
    warnings: list[str] = []
    records_failed = 0
    mbox = mailbox.mbox(str(path), create=False)
    try:
        for index, message in enumerate(mbox):
            if index >= max_messages:
                warnings.append("mbox_message_limit_reached")
                break
            try:
                rows.append(_message_to_row(message, source_file=source, parser_name="email_mbox", source_kind="mbox_file", mailbox_name=mailbox_name, message_index=index + 1))
            except Exception:  # noqa: BLE001
                records_failed += 1
    finally:
        mbox.close()
    audit = {
        "records_read": len(rows) + records_failed,
        "records_parsed": len(rows),
        "records_indexed": len(rows),
        "records_failed": records_failed,
        "message_count": len(rows),
        "attachment_count": sum(len(row.get("Attachments") or []) for row in rows),
        "suspicious_attachment_count": sum(int(row.get("SuspiciousAttachmentCount") or 0) for row in rows),
        "auth_failure_count": sum(1 for row in rows if row.get("AuthFailure")),
        "warnings": warnings,
        "parser_errors": [],
    }
    return rows, audit


def parse_mailbox_inventory(path: Path, *, source_path: str | None = None, mailbox_type: str) -> tuple[list[dict], dict]:
    source = normalize_windows_path(source_path or str(path)) or str(path)
    row = {
        "EventType": "email_mailbox_observed",
        "FilePath": source,
        "FileSize": path.stat().st_size if path.exists() else None,
        "MailboxType": mailbox_type,
        "SourceFile": source,
        "SourceKind": mailbox_type,
        "UnsupportedReason": "unsupported_pst_ost_parsing_not_enabled",
        "ParserStatus": "unsupported_inventory",
        "RiskScore": 5,
        "SuspiciousReasons": [],
        "Tags": ["email_mailbox_inventory"],
        "User": extract_user_from_path(source),
    }
    audit = {
        "records_read": 1,
        "records_parsed": 1,
        "records_indexed": 1,
        "mailbox_inventory_count": 1,
        "unsupported_counts": {mailbox_type: 1},
        "warnings": ["unsupported_pst_ost_parsing_not_enabled"],
        "parser_errors": [],
    }
    return [row], audit


def parse_outlook_temp_attachment(path: Path, *, source_path: str | None = None) -> tuple[list[dict], dict]:
    source = normalize_windows_path(source_path or str(path)) or str(path)
    file_name = basename_windows(source)
    ext = suffix_windows(source)
    suspicious, reasons, risk = _attachment_risk(file_name)
    row = {
        "EventType": "email_temp_attachment_observed",
        "Date": None,
        "FilePath": source,
        "FileSize": path.stat().st_size if path.exists() else None,
        "SourceFile": source,
        "SourceKind": "outlook_temp_attachment",
        "RiskScore": risk if suspicious else 20,
        "SuspiciousReasons": reasons,
        "Tags": ["outlook_temp_attachment", *(["suspicious_attachment"] if suspicious else [])],
        "Attachments": [
            {
                "file_name": file_name,
                "content_type": mimetypes.guess_type(file_name or "")[0] or "application/octet-stream",
                "size": path.stat().st_size if path.exists() else None,
                "extension": ext,
                "is_suspicious": suspicious,
                "risk_reasons": reasons,
            }
        ],
        "SuspiciousAttachmentCount": 1 if suspicious else 0,
        "User": extract_user_from_path(source),
    }
    audit = {
        "records_read": 1,
        "records_parsed": 1,
        "records_indexed": 1,
        "temp_attachment_count": 1,
        "suspicious_attachment_count": 1 if suspicious else 0,
        "warnings": [],
        "parser_errors": [],
    }
    return [row], audit


def parse_windows_mail_inventory(path: Path, *, source_path: str | None = None) -> tuple[list[dict], dict]:
    source = normalize_windows_path(source_path or str(path)) or str(path)
    row = {
        "EventType": "email_client_artifact_observed",
        "FilePath": source,
        "FileSize": path.stat().st_size if path.exists() else None,
        "SourceFile": source,
        "SourceKind": "windows_mail_inventory",
        "ParserStatus": "inventory_only",
        "UnsupportedReason": "windows_mail_inventory_only_v1",
        "RiskScore": 5,
        "SuspiciousReasons": [],
        "Tags": ["windows_mail_inventory"],
        "User": extract_user_from_path(source),
    }
    audit = {
        "records_read": 1,
        "records_parsed": 1,
        "records_indexed": 1,
        "mailbox_inventory_count": 1,
        "unsupported_counts": {"windows_mail_inventory": 1},
        "warnings": ["windows_mail_inventory_only_v1"],
        "parser_errors": [],
    }
    return [row], audit


def parse_email_artifact_file(path: Path, artifact_meta: dict) -> tuple[list[dict], dict]:
    parser_name = str(artifact_meta.get("parser") or "").lower()
    source_path = str(artifact_meta.get("source_path") or path)
    if parser_name == "email_eml":
        return parse_eml_file(path, source_path=source_path)
    if parser_name == "email_mbox":
        return parse_mbox_file(path, source_path=source_path)
    if parser_name == "email_pst_inventory":
        return parse_mailbox_inventory(path, source_path=source_path, mailbox_type="pst")
    if parser_name == "email_ost_inventory":
        return parse_mailbox_inventory(path, source_path=source_path, mailbox_type="ost")
    if parser_name == "email_outlook_temp_attachment":
        return parse_outlook_temp_attachment(path, source_path=source_path)
    if parser_name == "email_windows_mail_inventory":
        return parse_windows_mail_inventory(path, source_path=source_path)

    normalized = normalize_windows_path(source_path) or str(source_path).replace("/", "\\")
    if is_outlook_temp_attachment_path(normalized):
        return parse_outlook_temp_attachment(path, source_path=source_path)
    if is_windows_mail_inventory_path(normalized):
        return parse_windows_mail_inventory(path, source_path=source_path)
    if parser_name == "email_generic_raw" and (path.suffix.lower() == ".mbox" or is_thunderbird_profile_path(normalized) and path.suffix.lower() not in {".msf", ".sqlite"}):
        return parse_mbox_file(path, source_path=source_path)
    return parse_eml_file(path, source_path=source_path)
