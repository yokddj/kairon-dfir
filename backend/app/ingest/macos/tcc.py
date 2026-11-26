"""TCC.db: the privacy permissions (Transparency, Consent and Control) granted or denied to apps.

The system database (``/Library/Application Support/com.apple.TCC/TCC.db``) holds machine-wide
grants such as Full Disk Access and Accessibility; each user's own database holds per-user grants
(camera, microphone, Desktop and Documents folders...). One row per entry, timed by its
``last_modified`` column (Unix seconds), which is when the decision was last changed.

Since macOS 11 the decision is ``auth_value`` (0 denied, 2 allowed, 3 limited); older releases
had a boolean ``allowed``. Both are read.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ingest.macos.common import open_sqlite_copy, original_path, table_columns, unix_to_iso, user_from_path

ARTIFACT_FAMILY = "macos_tcc"
SERVICE_LABELS = {
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic input (keystrokes and clicks)",
    "kTCCServiceAppleEvents": "Automation (Apple Events)",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
    "kTCCServiceSystemPolicySysAdminFiles": "Administration files",
    "kTCCServiceDeveloperTool": "Developer tool",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security client",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendars",
    "kTCCServiceReminders": "Reminders",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceLocation": "Location",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceFileProviderDomain": "File provider",
    "kTCCServiceMediaLibrary": "Media library",
    "kTCCServiceRemoteDesktop": "Remote desktop",
}
# Grants that give an app reach over the whole machine or the user's input: leads for review when
# allowed, never detections (many legitimate tools need them).
SENSITIVE_SERVICES = {
    "kTCCServiceAccessibility", "kTCCServiceSystemPolicyAllFiles", "kTCCServiceScreenCapture",
    "kTCCServiceListenEvent", "kTCCServicePostEvent", "kTCCServiceEndpointSecurityClient", "kTCCServiceRemoteDesktop",
}
_AUTH_VALUES = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited"}
_AUTH_REASONS = {
    1: "error", 2: "user consent", 3: "user set", 4: "system set", 5: "service policy", 6: "MDM policy",
    7: "override policy", 8: "missing usage string", 9: "prompt timeout", 10: "preflight unknown",
    11: "entitled", 12: "app type policy",
}
_CLIENT_TYPES = {0: "bundle id", 1: "absolute path"}


def parse_tcc(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    original = original_path(source_path)
    scope = "user" if original.lower().startswith("/users/") else "system"
    username = user_from_path(source_path) if scope == "user" else ""
    rows: list[dict[str, Any]] = []
    with open_sqlite_copy(path) as connection:
        columns = table_columns(connection, "access")
        if not {"service", "client"} <= columns:
            return []
        optional = [column for column in ("client_type", "auth_value", "allowed", "auth_reason", "prompt_count", "indirect_object_identifier", "last_modified") if column in columns]
        select = ", ".join(["service", "client", *optional])
        for index, record in enumerate(connection.execute(f"SELECT {select} FROM access"), start=1):
            data = dict(record)
            service = str(data.get("service") or "")
            if "auth_value" in data and data["auth_value"] is not None:
                decision = _AUTH_VALUES.get(int(data["auth_value"]), str(data["auth_value"]))
            elif "allowed" in data and data["allowed"] is not None:
                decision = "allowed" if int(data["allowed"]) else "denied"
            else:
                decision = "unknown"
            label = SERVICE_LABELS.get(service, service.removeprefix("kTCCService") or service)
            target = str(data.get("indirect_object_identifier") or "")
            if target in {"UNUSED", "0"}:
                target = ""
            client = str(data.get("client") or "")
            sensitive = service in SENSITIVE_SERVICES and decision in {"allowed", "limited"}
            rows.append({
                "artifact_family": ARTIFACT_FAMILY,
                "artifact_type": "tcc_permission",
                "source_file": source_path,
                "line_number": index,
                "timestamp": unix_to_iso(data.get("last_modified")),
                "event_action": f"tcc_{decision}",
                "username": username,
                "tcc_scope": scope,
                "tcc_service": service,
                "tcc_service_label": label,
                "tcc_client": client,
                "tcc_client_type": _CLIENT_TYPES.get(data.get("client_type"), str(data.get("client_type") or "")),
                "tcc_decision": decision,
                "tcc_reason": _AUTH_REASONS.get(data.get("auth_reason"), str(data.get("auth_reason") or "")),
                "tcc_target": target,
                "sensitive_permission": sensitive,
                "message": f"{label} {decision} for {client}" + (f" (target {target})" if target else "") + (f" [{scope} database]" if scope == "system" else ""),
            })
    return rows
