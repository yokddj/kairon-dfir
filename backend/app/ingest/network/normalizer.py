from __future__ import annotations

from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.host_detection import normalize_hostname
from app.ingest.network.helpers import (
    basename_windows,
    clean_value,
    classify_dns_query,
    classify_dns_servers,
    classify_hosts_entry,
    classify_netstat_entry,
    classify_wlan_profile,
    first_nonempty,
    is_ip_literal,
    normalize_dns_record_type,
    normalize_dns_status,
    normalize_windows_path,
    parse_boolish,
    parse_domain,
    suffix_windows,
)
from app.ingest.windows_event_mapping import risk_score_to_severity


def _split_multi(value: str | None) -> list[str]:
    cleaned = clean_value(value)
    if not cleaned:
        return []
    parts = []
    for item in cleaned.replace(";", "|").replace(",", "|").split("|"):
        normalized = item.strip()
        if normalized:
            parts.append(normalized)
    return parts


def normalize_network_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    artifact_parser = str(artifact_meta.get("parser") or "")
    artifact_type = clean_value(first_nonempty(row, "ArtifactType")) or str(artifact_meta.get("network_artifact_type") or artifact_parser or "network_generic")
    network_event_type = clean_value(first_nonempty(row, "NetworkEventType"))
    is_wlan = str(artifact_meta.get("artifact_type") or "").lower() == "wlan" or "wlan" in str(artifact_type or "").lower() or "wlan" in str(artifact_parser or "").lower()
    is_dns = str(artifact_meta.get("artifact_type") or "").lower() == "dns" or "dns" in str(artifact_type or "").lower() or str(artifact_parser or "").lower() in {"dns_csv", "dns_json", "dns_jsonl", "dns_evtx", "dns_raw"}

    if not network_event_type:
        network_event_type = (
            "wlan_profile" if artifact_type == "wlan_profile_xml"
            else "wlan_connected" if artifact_type in {"wlan_autoconfig_evtx", "wlan_evtx"}
            else "hosts_entry" if artifact_type == "hosts_file"
            else "dns_query_failed" if is_dns and normalize_dns_status(first_nonempty(row, "Status", "QueryStatus", "Result")) in {"failed", "nxdomain", "timeout", "refused"}
            else "dns_query" if is_dns
            else "dns_cache_entry" if artifact_type == "dns_cache_output"
            else "dns_config" if artifact_type in {"dns_config_output", "ipconfig_output", "netipconfiguration_output"}
            else "network_profile" if artifact_type == "networklist_registry"
            else "interface_config" if artifact_type == "tcpip_interfaces_registry"
            else "netstat_connection" if artifact_type == "netstat_output"
            else "arp_entry" if artifact_type == "arp_output"
            else "route_entry" if artifact_type == "route_table_output"
            else "wlan_profile" if artifact_parser in {"wlan_profile_xml", "netsh_txt", "wlan_xml", "wlan_csv", "wlan_json", "wlan_jsonl", "wlan_raw"}
            else "dns_cache_entry" if artifact_parser == "dns_csv"
            else "network_observed"
        )

    ssid = clean_value(first_nonempty(row, "SSID", "ProfileName"))
    profile_name = clean_value(first_nonempty(row, "ProfileName"))
    interface_name = clean_value(first_nonempty(row, "InterfaceName"))
    interface_guid = clean_value(first_nonempty(row, "InterfaceGuid"))
    interface_description = clean_value(first_nonempty(row, "InterfaceDescription", "Description"))
    computer = clean_value(first_nonempty(row, "Computer"))
    ipv4 = clean_value(first_nonempty(row, "IPv4Address", "IPAddress"))
    ipv6 = clean_value(first_nonempty(row, "IPv6Address"))
    gateway = clean_value(first_nonempty(row, "DefaultGateway", "Gateway"))
    dns_servers = _split_multi(first_nonempty(row, "DNSServers", "NameServer", "DhcpNameServer", "Server"))
    local_path = normalize_windows_path(first_nonempty(row, "SourceFile"))
    dns_name = clean_value(first_nonempty(row, "QueryName", "Name", "RecordName", "Domain", "HostName"))
    host_name = clean_value(first_nonempty(row, "HostName", "Name", "RecordName", "Domain", "QueryName"))
    dns_value = clean_value(first_nonempty(row, "Data", "IPAddress", "Address", "IP", "CNAME"))
    dns_ip = dns_value if is_ip_literal(dns_value) else (clean_value(first_nonempty(row, "IPAddress", "Address", "IP")) if is_ip_literal(first_nonempty(row, "IPAddress", "Address", "IP")) else None)
    remote_address = clean_value(first_nonempty(row, "RemoteAddress", "ForeignAddress", "DestinationIP"))
    source_address = clean_value(first_nonempty(row, "LocalAddress", "SourceIP"))
    profile_user = artifact_meta.get("user") or extract_user_from_path(artifact_meta.get("velociraptor_normalized_windows_path")) or extract_user_from_path(local_path)

    if is_wlan and document.get("raw"):
        raw = dict(document["raw"])
        for key in list(raw.keys()):
            if str(key).lower() == "keymaterial" and raw[key] not in (None, ""):
                raw[key] = "[REDACTED]"
        document["raw"] = raw

    document["artifact"]["type"] = "wlan" if is_wlan else "dns" if is_dns else "network"
    parser_name = str(artifact_meta.get("parser") or "network_csv")
    if is_wlan and parser_name == "evtx":
        parser_name = "wlan_evtx"
    elif is_wlan and parser_name == "netsh_txt":
        parser_name = "wlan_raw"
    elif is_wlan and parser_name == "network_csv":
        parser_name = "wlan_csv"
    elif is_wlan and parser_name == "network_json":
        parser_name = "wlan_json"
    if is_dns and parser_name == "network_json":
        parser_name = "dns_json"
    elif is_dns and parser_name == "network_csv":
        parser_name = "dns_csv"
    elif is_dns and parser_name == "evtx":
        parser_name = "dns_evtx"
    document["artifact"]["parser"] = parser_name
    document["event"]["category"] = "network"
    document["event"]["type"] = network_event_type
    document["event"]["action"] = {
        "wlan_profile": "wlan_profile_observed",
        "wlan_connected": "wlan_connected",
        "wlan_disconnected": "wlan_disconnected",
        "wlan_connection_failed": "wlan_connection_failed",
        "dns_query": "dns_query_observed",
        "dns_query_failed": "dns_query_failed",
        "dns_cache_entry": "dns_entry_observed",
        "dns_config": "dns_config_observed",
        "hosts_entry": "hosts_entry_observed",
        "network_profile": "network_profile_observed",
        "interface_config": "interface_config_observed",
        "route_entry": "route_entry_observed",
        "netstat_connection": "netstat_connection_observed",
        "arp_entry": "arp_entry_observed",
    }.get(network_event_type, "network_observed")
    document["event"]["severity"] = "info"
    document["event"]["message"] = (
        f"WLAN profile observed: {ssid or profile_name or 'unknown'}" if network_event_type == "wlan_profile"
        else f"Hosts entry observed: {host_name or 'unknown'}" if network_event_type == "hosts_entry"
        else f"DNS query observed: {parse_domain(dns_name) or 'unknown'} -> {dns_value or '-'}" if network_event_type == "dns_query"
        else f"DNS query failed: {parse_domain(dns_name) or 'unknown'} status={normalize_dns_status(first_nonempty(row, 'Status', 'QueryStatus', 'Result'))}" if network_event_type == "dns_query_failed"
        else f"DNS entry observed: {host_name or dns_ip or 'unknown'}" if network_event_type == "dns_cache_entry"
        else f"WLAN connected: {ssid or profile_name or 'unknown'} BSSID={clean_value(first_nonempty(row, 'BSSID')) or '-'}" if network_event_type == "wlan_connected"
        else f"WLAN disconnected: {ssid or profile_name or 'unknown'} reason={clean_value(first_nonempty(row, 'Reason', 'FailureReason')) or '-'}" if network_event_type == "wlan_disconnected"
        else f"WLAN connection failed: {ssid or profile_name or 'unknown'} reason={clean_value(first_nonempty(row, 'Reason', 'FailureReason')) or '-'}" if network_event_type == "wlan_connection_failed"
        else f"Network profile observed: {profile_name or 'unknown'}" if network_event_type == "network_profile"
        else f"Network artifact observed: {artifact_type}"
    )

    document["network"].update(
        {
            "artifact_type": artifact_type,
            "interface_name": interface_name,
            "interface_guid": interface_guid,
            "interface_alias": clean_value(first_nonempty(row, "InterfaceAlias")),
            "interface_description": interface_description,
            "mac_address": clean_value(first_nonempty(row, "MACAddress", "PhysicalAddress")),
            "ip_address": ipv4 or ipv6,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "subnet": clean_value(first_nonempty(row, "SubnetMask", "Subnet")),
            "gateway": gateway,
            "dns_servers": dns_servers,
            "dhcp_enabled": parse_boolish(first_nonempty(row, "DHCPEnabled")),
            "dhcp_server": clean_value(first_nonempty(row, "DHCPServer")),
            "profile_name": profile_name or ssid,
            "profile_guid": clean_value(first_nonempty(row, "ProfileGuid")),
            "network_category": clean_value(first_nonempty(row, "NetworkCategory", "Category")),
            "domain": parse_domain(first_nonempty(row, "Domain", "HostName", "Name", "RecordName", "QueryName")),
            "url": clean_value(first_nonempty(row, "URL")),
            "destination_ip": remote_address,
            "destination_port": clean_value(first_nonempty(row, "RemotePort", "DestinationPort")),
            "source_ip": source_address,
            "source_port": clean_value(first_nonempty(row, "LocalPort", "SourcePort")),
            "protocol": clean_value(first_nonempty(row, "Protocol", "Proto")),
            "state": clean_value(first_nonempty(row, "State", "Status")),
            "process_id": clean_value(first_nonempty(row, "PID", "ProcessId")),
            "process_name": clean_value(first_nonempty(row, "ProcessName")),
            "application": clean_value(first_nonempty(row, "Application", "Provider")),
            "bytes_sent": clean_value(first_nonempty(row, "BytesSent")),
            "bytes_received": clean_value(first_nonempty(row, "BytesReceived")),
            "bytes_total": clean_value(first_nonempty(row, "BytesTotal")),
            "first_seen": clean_value(first_nonempty(row, "FirstSeen", "Created")),
            "last_seen": clean_value(first_nonempty(row, "LastSeen", "Modified", "LastConnected")),
            "source_file": str(artifact_meta.get("source_path") or ""),
            "parser_status": "ready",
        }
    )
    document["wlan"].update(
        {
            "ssid": ssid,
            "ssid_hex": clean_value(first_nonempty(row, "SSIDHex")),
            "profile_name": profile_name or ssid,
            "profile_type": clean_value(first_nonempty(row, "ConnectionType", "ProfileType")),
            "connection_mode": clean_value(first_nonempty(row, "ConnectionMode")),
            "authentication": clean_value(first_nonempty(row, "Authentication")),
            "encryption": clean_value(first_nonempty(row, "Encryption")),
            "key_type": clean_value(first_nonempty(row, "KeyType")),
            "key_protected": parse_boolish(first_nonempty(row, "KeyProtected")),
            "key_material_present": parse_boolish(first_nonempty(row, "KeyMaterialPresent")) or bool(first_nonempty(row, "KeyMaterial")),
            "auto_switch": parse_boolish(first_nonempty(row, "AutoSwitch")),
            "mac_randomization": clean_value(first_nonempty(row, "MacRandomization")),
            "interface_guid": interface_guid,
            "interface_description": interface_description,
            "bssid": clean_value(first_nonempty(row, "BSSID")),
            "signal_quality": clean_value(first_nonempty(row, "SignalQuality")),
            "connection_start": clean_value(first_nonempty(row, "ConnectionStart", "Time")),
            "connection_end": clean_value(first_nonempty(row, "ConnectionEnd")),
            "reason": clean_value(first_nonempty(row, "Reason")),
            "source_file": str(artifact_meta.get("source_path") or ""),
        }
    )
    if is_wlan:
        document["network"].update(
            {
                "artifact_type": "wlan",
                "profile_name": profile_name or ssid,
                "profile": profile_name or ssid,
                "interface_guid": interface_guid,
                "interface_description": interface_description,
                "first_seen": clean_value(first_nonempty(row, "ConnectionStart", "TimeCreated", "Timestamp")),
                "last_seen": clean_value(first_nonempty(row, "ConnectionEnd", "TimeCreated", "Timestamp")),
                "direction": None,
                "domain": None,
                "url": None,
            }
        )
    document["dns"].update(
        {
            "name": parse_domain(dns_name),
            "domain": parse_domain(dns_name),
            "record_type": normalize_dns_record_type(first_nonempty(row, "RecordType", "Type")),
            "data": dns_value,
            "ip": dns_ip,
            "ttl": clean_value(first_nonempty(row, "TTL")),
            "status": normalize_dns_status(first_nonempty(row, "Status", "QueryStatus", "Result")),
            "source": clean_value(first_nonempty(row, "Source")) or ("evtx" if parser_name == "dns_evtx" else "cache"),
            "server": clean_value(first_nonempty(row, "Server", "DnsServer")),
            "interface": clean_value(first_nonempty(row, "Interface")) or interface_name,
            "timestamp": clean_value(first_nonempty(row, "TimeCreated", "Timestamp", "Time")),
            "source_file": str(artifact_meta.get("source_path") or ""),
        }
    )
    document["registry"].update(
        {
            "hive": clean_value(first_nonempty(row, "RegistryHive")),
            "key_path": clean_value(first_nonempty(row, "RegistryKeyPath")),
            "value_name": clean_value(first_nonempty(row, "RegistryValueName")),
            "value_data": clean_value(first_nonempty(row, "RegistryValueData")),
            "last_write": clean_value(first_nonempty(row, "LastWriteTime")),
        }
    )
    if network_event_type == "hosts_entry":
        document["file"]["path"] = normalize_windows_path(str(artifact_meta.get("velociraptor_normalized_windows_path") or artifact_meta.get("source_path") or ""))
        document["file"]["name"] = basename_windows(document["file"]["path"])
        document["file"]["extension"] = suffix_windows(document["file"]["path"])
    elif local_path:
        document["file"]["path"] = local_path
        document["file"]["name"] = basename_windows(local_path)
        document["file"]["extension"] = suffix_windows(local_path)
    document["url"]["full"] = clean_value(first_nonempty(row, "URL"))
    document["url"]["domain"] = parse_domain(first_nonempty(row, "URL", "Domain", "HostName", "Name", "QueryName", "RecordName"))
    document["process"]["pid"] = document["process"].get("pid") or document["network"]["process_id"]
    document["process"]["name"] = document["process"].get("name") or document["network"]["process_name"]
    if is_dns:
        document["process"]["application"] = document["process"]["name"]
        document["user"]["sid"] = document["user"].get("sid") or clean_value(first_nonempty(row, "UserSid"))
        explicit_user = clean_value(first_nonempty(row, "User"))
        if explicit_user:
            document["user"]["name"] = explicit_user
        document["network"].update(
            {
                "artifact_type": "dns",
                "domain": document["dns"].get("domain"),
                "destination_ip": document["dns"].get("ip"),
                "dns_servers": [document["dns"].get("server")] if document["dns"].get("server") else [],
                "interface_guid": interface_guid,
                "interface": document["dns"].get("interface"),
                "state": document["dns"].get("status"),
            }
        )
    document["user"]["name"] = document["user"].get("name") or profile_user
    if is_wlan:
        document["host"]["name"] = normalize_hostname(computer) if computer else None
    elif is_dns:
        document["host"]["name"] = normalize_hostname(computer) if computer else None

    document["velociraptor"]["original_path"] = artifact_meta.get("velociraptor_original_path")
    document["velociraptor"]["normalized_windows_path"] = artifact_meta.get("velociraptor_normalized_windows_path")
    document["velociraptor"]["artifact_category"] = artifact_meta.get("velociraptor_category")
    document["velociraptor"]["parser_status"] = artifact_meta.get("velociraptor_parser_status")

    tags = set(document.get("tags", []))
    reasons = set(document.get("suspicious_reasons", []))
    risk = int(document.get("risk_score") or 0)
    tags.update({"network"})

    if network_event_type in {"wlan_profile", "wlan_connected", "wlan_disconnected", "wlan_connection_failed"}:
        wlan_tags, wlan_reasons, wlan_risk = classify_wlan_profile(document["wlan"]["authentication"], document["wlan"]["encryption"], document["wlan"]["ssid"])
        tags.update(wlan_tags)
        reasons.update(wlan_reasons)
        risk = max(risk, wlan_risk)
    if is_dns and network_event_type in {"dns_query", "dns_query_failed"}:
        dns_tags, dns_reasons, dns_risk = classify_dns_query(document["dns"]["domain"], document["dns"]["record_type"], document["dns"]["status"], document["process"]["name"])
        tags.update(dns_tags)
        reasons.update(dns_reasons)
        risk = max(risk, dns_risk)
        if document["dns"].get("status") in {"failed", "nxdomain", "timeout", "refused"}:
            document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"dns_failed_query"})
    if is_wlan and document["wlan"].get("key_material_present"):
        tags.add("wlan_key_material_present")
        reasons.add("WLAN key material present and redacted")
    if is_wlan and document["wlan"].get("key_material_present"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"wlan_key_material_redacted"})
    if is_wlan and str(document["wlan"].get("mac_randomization") or "").strip().lower() in {"false", "disabled", "0", "no"}:
        reasons.add("WLAN MAC randomization disabled")
        risk = max(risk, 15)
    if is_wlan and network_event_type == "wlan_connection_failed":
        reasons.add("WLAN connection failed")
        risk = max(risk, 30)
    if is_wlan and not document["wlan"].get("ssid"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_ssid"})
    if is_wlan and not (interface_guid or interface_description):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_interface"})
    if is_wlan and not document["host"].get("name"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_host"})
    if is_dns and not document["dns"].get("domain"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_domain"})
    if is_dns and document["dns"].get("record_type") == "UNKNOWN":
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"dns_unknown_record_type", "missing_record_type"})
    if is_dns and not document["dns"].get("data"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_data"})
    if is_dns and not document["host"].get("name"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_host"})
    if is_dns and document["dns"].get("status") in {"failed", "nxdomain", "timeout", "refused"}:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"dns_failed_query"})
    if is_dns and not document["dns"].get("timestamp"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"dns_cache_without_timestamp"})
    if network_event_type == "hosts_entry":
        host_tags, host_reasons, host_risk = classify_hosts_entry(document["dns"]["ip"], document["dns"]["name"])
        tags.update(host_tags)
        reasons.update(host_reasons)
        risk = max(risk, host_risk)
    if network_event_type in {"dns_config", "interface_config"} and dns_servers:
        dns_tags, dns_reasons, dns_risk = classify_dns_servers(dns_servers, gateway=gateway)
        tags.update(dns_tags)
        reasons.update(dns_reasons)
        risk = max(risk, dns_risk)
    if network_event_type == "netstat_connection":
        netstat_tags, netstat_reasons, netstat_risk = classify_netstat_entry(document["network"]["process_name"], document["network"]["destination_ip"], document["network"]["destination_port"])
        tags.update(netstat_tags)
        reasons.update(netstat_reasons)
        risk = max(risk, netstat_risk)
    timestamp_map = [
        ("wlan_connection_start", document["wlan"].get("connection_start")),
        ("wlan_connection_end", document["wlan"].get("connection_end")),
        ("dns_timestamp", document["dns"].get("timestamp")),
        ("event_time", clean_value(first_nonempty(row, "TimeCreated", "Time"))),
        ("registry_last_write", document["registry"].get("last_write")),
        ("dns_cache_time", document["dns"].get("timestamp")),
        ("source_file_mtime", artifact_meta.get("mtime")),
    ]
    for precision, value in timestamp_map:
        if value:
            document["@timestamp"] = value
            document["timestamp_precision"] = precision
            break
    if not document.get("@timestamp"):
        document["timestamp_precision"] = "unknown"
        document["event"]["timeline_include"] = False
    if is_wlan and document["timestamp_precision"] == "source_file_mtime":
        document["network"]["timestamp_interpretation"] = "WLAN profile file modification time; not necessarily first connection time"
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"timestamp_source_file_only"})
    if is_wlan:
        document["execution"].update(
            {
                "source": "wlan",
                "is_execution_confirmed": False,
                "confidence": "low",
                "interpretation": "WLAN artifacts indicate wireless profile or connectivity activity, not program execution",
            }
        )
    if is_dns:
        document["execution"].update(
            {
                "source": "dns",
                "is_execution_confirmed": False,
                "confidence": "low",
                "interpretation": "DNS artifacts indicate name resolution activity, not process execution by itself",
            }
        )
    if is_wlan and parser_name == "wlan_evtx":
        document["windows"].update(
            {
                "event_id": clean_value(first_nonempty(row, "EventID", "EventId", "Id")),
                "channel": clean_value(first_nonempty(row, "Channel")),
                "provider": clean_value(first_nonempty(row, "Provider")),
                "computer": computer,
                "record_id": clean_value(first_nonempty(row, "RecordId", "RecordNumber")),
                "event_data": row,
            }
        )
    if is_dns and parser_name == "dns_evtx":
        document["windows"].update(
            {
                "event_id": clean_value(first_nonempty(row, "EventID", "EventId", "Id")),
                "channel": clean_value(first_nonempty(row, "Channel")),
                "provider": clean_value(first_nonempty(row, "Provider")),
                "computer": computer,
                "record_id": clean_value(first_nonempty(row, "RecordId", "RecordNumber")),
                "process_id": clean_value(first_nonempty(row, "ProcessId", "PID")),
                "event_data": {key: value for key, value in row.items() if value not in (None, "")},
            }
        )
    document["raw_summary"] = (
        f"Type={network_event_type} | SSID={document['wlan'].get('ssid') or '-'} | Domain={document['dns'].get('name') or document['network'].get('domain') or '-'} | Source={artifact_meta.get('source_path') or ''}"
    )[:1024]
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["risk_score"] = risk
    document["event"]["severity"] = risk_score_to_severity(risk)
    document["_preserve_risk_score"] = True
    return document
