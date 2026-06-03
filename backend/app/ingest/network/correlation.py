from __future__ import annotations

from app.models.forensic_activity import ForensicActivity


def correlate_network_activity(activities: list[ForensicActivity]) -> list[ForensicActivity]:
    browser = [item for item in activities if item.activity_type in {"browser_history", "file_download"}]
    bits = [item for item in activities if item.activity_type in {"background_download"}]
    powershell = [item for item in activities if item.activity_type in {"powershell_download", "powershell_execution"}]
    cloud = [item for item in activities if item.activity_type in {"cloud_sync_root_observed", "cloud_file_activity"}]

    indicators: dict[str, list[ForensicActivity]] = {}
    for item in activities:
        if item.activity_type not in {"network_indicator_seen", "suspicious_hosts_override", "wlan_connection_observed", "dns_config_observed", "wlan_profile_observed"}:
            continue
        key = str(item.key_fields.get("domain") or item.key_fields.get("hostname") or item.key_fields.get("ssid") or "").lower()
        if key:
            indicators.setdefault(key, []).append(item)

    for item in browser + bits + powershell + cloud:
        fields = item.key_fields or {}
        for key in [str(fields.get("domain") or "").lower(), str(fields.get("provider_domain") or "").lower()]:
            if not key or key not in indicators:
                continue
            for indicator in indicators[key]:
                indicator.tags = sorted(set(indicator.tags) | {"network_correlation"})
                indicator.suspicious_reasons = sorted(set(indicator.suspicious_reasons) | {f"Network indicator correlates with suspicious {item.activity_type.replace('_', ' ')} activity"})
                indicator.confidence = max(indicator.confidence, 0.82)
    return activities
