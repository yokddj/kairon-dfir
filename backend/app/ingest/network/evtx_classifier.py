from __future__ import annotations

from app.ingest.network.helpers import first_nonempty, normalize_dns_record_type, normalize_dns_status


def classify_wlan_autoconfig_event(row: dict) -> dict:
    event_id = str(first_nonempty(row, "EventId", "Id") or "")
    if event_id in {"8001", "11000", "11001"}:
        event_type = "wlan_connected"
    elif event_id in {"8002"}:
        event_type = "wlan_connection_failed"
    elif event_id in {"8003", "11004"}:
        event_type = "wlan_disconnected"
    elif event_id in {"11005", "11006"}:
        event_type = "wlan_profile"
    else:
        reason = str(first_nonempty(row, "Reason", "FailureReason") or "").lower()
        if "fail" in reason or "error" in reason:
            event_type = "wlan_connection_failed"
        elif first_nonempty(row, "ConnectionEnd"):
            event_type = "wlan_disconnected"
        elif first_nonempty(row, "SSID", "ProfileName"):
            event_type = "wlan_connected"
        else:
            event_type = "wlan_profile"
    return {
        "ArtifactType": "wlan_evtx",
        "NetworkEventType": event_type,
        "SSID": first_nonempty(row, "SSID"),
        "SsidHex": first_nonempty(row, "SsidHex", "SSIDHex"),
        "BSSID": first_nonempty(row, "BSSID"),
        "InterfaceGuid": first_nonempty(row, "InterfaceGuid"),
        "InterfaceDescription": first_nonempty(row, "InterfaceDescription"),
        "ConnectionMode": first_nonempty(row, "ConnectionMode"),
        "Authentication": first_nonempty(row, "Authentication"),
        "Encryption": first_nonempty(row, "Encryption"),
        "Reason": first_nonempty(row, "Reason", "FailureReason"),
        "ProfileName": first_nonempty(row, "ProfileName"),
        "TimeCreated": first_nonempty(row, "TimeCreated", "Timestamp", "Time"),
        "ConnectionStart": first_nonempty(row, "ConnectionStart"),
        "ConnectionEnd": first_nonempty(row, "ConnectionEnd"),
        "EventID": first_nonempty(row, "EventID", "EventId", "Id"),
        "Provider": first_nonempty(row, "Provider"),
        "Channel": first_nonempty(row, "Channel"),
        "Computer": first_nonempty(row, "Computer"),
        "RecordId": first_nonempty(row, "RecordId", "RecordNumber"),
    }


def classify_dns_client_event(row: dict) -> dict:
    status = normalize_dns_status(first_nonempty(row, "Status", "QueryStatus", "Result"))
    event_type = "dns_query_failed" if status in {"failed", "nxdomain", "timeout", "refused"} else "dns_query"
    return {
        "ArtifactType": "dns_evtx",
        "NetworkEventType": event_type,
        "QueryName": first_nonempty(row, "QueryName", "Name", "RecordName", "Domain"),
        "RecordType": normalize_dns_record_type(first_nonempty(row, "RecordType", "Type")),
        "Data": first_nonempty(row, "Data", "Address", "IP", "CNAME"),
        "Status": status,
        "Server": first_nonempty(row, "Server", "DnsServer"),
        "InterfaceGuid": first_nonempty(row, "InterfaceGuid"),
        "Interface": first_nonempty(row, "Interface", "InterfaceDescription"),
        "TimeCreated": first_nonempty(row, "TimeCreated", "Timestamp", "Time"),
        "EventID": first_nonempty(row, "EventID", "EventId", "Id"),
        "Provider": first_nonempty(row, "Provider"),
        "Channel": first_nonempty(row, "Channel"),
        "Computer": first_nonempty(row, "Computer"),
        "RecordId": first_nonempty(row, "RecordId", "RecordNumber"),
        "ProcessId": first_nonempty(row, "ProcessId", "PID"),
        "ProcessName": first_nonempty(row, "ProcessName", "Application"),
        "User": first_nonempty(row, "User", "UserName"),
        "UserSid": first_nonempty(row, "UserSid", "SID"),
    }
