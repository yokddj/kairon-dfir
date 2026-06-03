from __future__ import annotations

from app.ingest.email.helpers import (
    basename_windows,
    clean_value,
    first_nonempty,
    normalize_windows_path,
    parse_email_domain,
    suffix_windows,
)
from app.ingest.windows_event_mapping import risk_score_to_severity


def _coerce_list(value: object | None) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value)
    if "|" in text:
        return [item.strip() for item in text.split("|") if item.strip()]
    return [text.strip()] if text.strip() else []


def normalize_email_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    source_file = normalize_windows_path(str(artifact_meta.get("source_path") or artifact_meta.get("name") or ""))
    parser_name = str(artifact_meta.get("parser") or "email_generic_raw").lower()
    event_type = str(first_nonempty(row, "EventType") or "email_message")
    subject = clean_value(first_nonempty(row, "Subject"))
    message_id = clean_value(first_nonempty(row, "MessageID", "Message-Id"))
    from_address = clean_value(first_nonempty(row, "FromAddress", "From"))
    from_display_name = clean_value(first_nonempty(row, "FromDisplayName"))
    to_addresses = _coerce_list(row.get("ToAddresses") or first_nonempty(row, "To"))
    cc_addresses = _coerce_list(row.get("CcAddresses") or first_nonempty(row, "Cc"))
    bcc_addresses = _coerce_list(row.get("BccAddresses") or first_nonempty(row, "Bcc"))
    reply_to = clean_value(first_nonempty(row, "ReplyTo"))
    return_path = clean_value(first_nonempty(row, "ReturnPath"))
    authentication_results = clean_value(first_nonempty(row, "AuthenticationResults"))
    received_spf = clean_value(first_nonempty(row, "ReceivedSPF"))
    x_mailer = clean_value(first_nonempty(row, "XMailer"))
    user_agent = clean_value(first_nonempty(row, "UserAgent"))
    x_originating_ip = clean_value(first_nonempty(row, "XOriginatingIP"))
    body_preview = clean_value(first_nonempty(row, "BodyPreview"))
    urls = _coerce_list(row.get("Urls"))
    domains = _coerce_list(row.get("Domains"))
    ips = _coerce_list(row.get("IPs"))
    attachments = row.get("Attachments") if isinstance(row.get("Attachments"), list) else []
    mailbox_name = clean_value(first_nonempty(row, "MailboxName"))
    mailbox_type = clean_value(first_nonempty(row, "MailboxType"))
    unsupported_reason = clean_value(first_nonempty(row, "UnsupportedReason"))
    parser_status = clean_value(first_nonempty(row, "ParserStatus")) or ("unsupported_inventory" if unsupported_reason else "parsed")
    risk_score = int(row.get("RiskScore") or 0)
    suspicious_reasons = _coerce_list(row.get("SuspiciousReasons"))
    tags = _coerce_list(row.get("Tags"))
    auth_failure = bool(row.get("AuthFailure"))
    suspicious_attachment_count = int(row.get("SuspiciousAttachmentCount") or 0)
    source_kind = clean_value(first_nonempty(row, "SourceKind"))
    source_user = clean_value(first_nonempty(row, "User"))
    source_host = clean_value(first_nonempty(row, "Computer"))

    document["artifact"]["type"] = "email"
    document["artifact"]["parser"] = parser_name
    document["artifact"]["name"] = f"Email - {subject or basename_windows(source_file) or event_type}"
    document["event"]["category"] = "email"
    document["event"]["type"] = event_type
    document["event"]["action"] = event_type
    document["event"]["severity"] = risk_score_to_severity(risk_score)
    document["risk_score"] = risk_score
    document["_preserve_risk_score"] = True
    document["suspicious_reasons"] = suspicious_reasons
    document["tags"] = tags

    if event_type == "email_message":
        document["event"]["message"] = f"Email message observed: {subject or message_id or from_address or '-'}"
    elif event_type == "email_temp_attachment_observed":
        document["event"]["message"] = f"Outlook temporary attachment observed: {basename_windows(source_file) or source_file or '-'}"
    elif event_type == "email_mailbox_observed":
        document["event"]["message"] = f"Email mailbox observed: {basename_windows(source_file) or source_file or '-'}"
    else:
        document["event"]["message"] = f"Email client artifact observed: {basename_windows(source_file) or source_file or '-'}"

    document["email"] = {
        "message_id": message_id,
        "subject": subject,
        "from": {"address": from_address, "display_name": from_display_name},
        "to": to_addresses,
        "cc": cc_addresses,
        "bcc": bcc_addresses,
        "date": clean_value(first_nonempty(row, "Date")),
        "client_submit_time": clean_value(first_nonempty(row, "ClientSubmitTime")),
        "conversation_index": clean_value(first_nonempty(row, "ConversationIndex")),
        "headers": {
            "return_path": return_path,
            "reply_to": reply_to,
            "x_mailer": x_mailer,
            "user_agent": user_agent,
            "authentication_results": authentication_results,
            "received_spf": received_spf,
            "x_originating_ip": x_originating_ip,
            "dkim_present": bool(row.get("DKIMPresent")),
            "spf_result": clean_value(first_nonempty(row, "SPFResult")) or "unknown",
            "dmarc_result": clean_value(first_nonempty(row, "DMARCResult")) or "unknown",
            "dkim_result": clean_value(first_nonempty(row, "DKIMResult")) or "unknown",
        },
        "attachments": attachments,
        "body_preview": body_preview,
        "mailbox_name": mailbox_name,
        "mailbox_type": mailbox_type,
        "message_index": row.get("MessageIndex"),
        "source_kind": source_kind,
        "unsupported_reason": unsupported_reason,
        "parser_status": parser_status,
        "auth_failure": auth_failure,
        "suspicious_attachment_count": suspicious_attachment_count,
    }

    primary_file_path = normalize_windows_path(first_nonempty(row, "FilePath", "SourceFile")) or source_file
    if primary_file_path:
        document["file"].update(
            {
                "path": primary_file_path,
                "name": basename_windows(primary_file_path),
                "extension": suffix_windows(primary_file_path),
                "size": row.get("FileSize") or row.get("MessageSize"),
                "sha256": clean_value(first_nonempty(row, "FileSHA256")),
                "source_path": source_file,
            }
        )

    document["user"]["name"] = document["user"].get("name") or source_user
    if source_host:
        document["host"]["name"] = source_host
        document["host"]["hostname"] = source_host

    attachment_names = [str(item.get("file_name") or "").strip() for item in attachments if isinstance(item, dict) and str(item.get("file_name") or "").strip()]
    primary_url = urls[0] if urls else None
    primary_domain = domains[0] if domains else parse_email_domain(from_address)
    primary_ip = ips[0] if ips else x_originating_ip

    document["url"].update(
        {
            "full": primary_url,
            "domain": primary_domain,
        }
    )
    document["network"].update(
        {
            "source_ip": primary_ip,
            "domain": primary_domain,
            "application": "email",
        }
    )

    if message_id and not document.get("@timestamp"):
        document["timestamp_precision"] = "email_header_date"
    if not document.get("@timestamp"):
        document["event"]["timeline_include"] = False

    quality = set(document.get("data_quality") or [])
    if event_type == "email_message" and not body_preview:
        quality.add("missing_email_body_preview")
    if event_type == "email_message" and not message_id:
        quality.add("missing_email_message_id")
    if event_type == "email_message" and not from_address:
        quality.add("missing_email_from")
    if event_type == "email_message" and not to_addresses:
        quality.add("missing_email_to")
    if event_type in {"email_mailbox_observed", "email_client_artifact_observed"} and unsupported_reason:
        quality.add("email_inventory_only")
    document["data_quality"] = sorted(quality)

    document["related_iocs"] = {
        "emails": sorted({item for item in [from_address, *to_addresses, *cc_addresses, *bcc_addresses] if item}),
        "domains": sorted({item for item in domains if item}),
        "urls": sorted({item for item in urls if item}),
        "ips": sorted({item for item in ips if item}),
        "files": sorted({item for item in attachment_names if item}),
    }
    return document
