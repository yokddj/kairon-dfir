from __future__ import annotations

from app.ingest.network.helpers import first_nonempty


def classify_network_registry_row(row: dict) -> dict:
    key_path = first_nonempty(row, "KeyPath", "Path", "RegistryPath") or ""
    value_name = first_nonempty(row, "ValueName", "Value") or ""
    value_data = first_nonempty(row, "ValueData", "Data", "ValueData0") or ""
    lower_key = key_path.lower()
    if "networklist\\profiles" in lower_key or "networklist\\signatures" in lower_key:
        return {
            "ArtifactType": "networklist_registry",
            "NetworkEventType": "network_profile",
            "ProfileName": first_nonempty(row, "ProfileName", "Description", "Name") or value_data,
            "ProfileGuid": first_nonempty(row, "ProfileGuid", "Guid"),
            "NetworkCategory": first_nonempty(row, "Category", "NetworkCategory"),
            "RegistryHive": first_nonempty(row, "Hive"),
            "RegistryKeyPath": key_path,
            "RegistryValueName": value_name,
            "RegistryValueData": value_data,
            "LastWriteTime": first_nonempty(row, "LastWriteTime"),
        }
    if "services\\tcpip\\parameters\\interfaces" in lower_key:
        return {
            "ArtifactType": "tcpip_interfaces_registry",
            "NetworkEventType": "interface_config",
            "InterfaceGuid": key_path.split("\\")[-1] if key_path else None,
            "NameServer": first_nonempty(row, "NameServer") or (value_data if value_name == "NameServer" else None),
            "DhcpNameServer": first_nonempty(row, "DhcpNameServer") or (value_data if value_name == "DhcpNameServer" else None),
            "IPAddress": first_nonempty(row, "IPAddress", "DhcpIPAddress") or (value_data if value_name in {"IPAddress", "DhcpIPAddress"} else None),
            "DefaultGateway": first_nonempty(row, "DefaultGateway", "DhcpDefaultGateway") or (value_data if value_name in {"DefaultGateway", "DhcpDefaultGateway"} else None),
            "Domain": first_nonempty(row, "Domain", "DhcpDomain") or (value_data if value_name in {"Domain", "DhcpDomain"} else None),
            "DHCPEnabled": first_nonempty(row, "EnableDHCP"),
            "RegistryHive": first_nonempty(row, "Hive"),
            "RegistryKeyPath": key_path,
            "RegistryValueName": value_name,
            "RegistryValueData": value_data,
            "LastWriteTime": first_nonempty(row, "LastWriteTime"),
        }
    return dict(row)
