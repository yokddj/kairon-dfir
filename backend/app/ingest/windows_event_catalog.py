from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EventSourceRule:
    provider_contains: tuple[str, ...] = ()
    channel_equals: tuple[str, ...] = ()
    channel_contains: tuple[str, ...] = ()


@dataclass(frozen=True)
class EventDefinition:
    key: str
    event_id: int
    category: str
    event_type: str
    action: str
    severity: str = "info"
    tags: tuple[str, ...] = ()
    valid_sources: tuple[EventSourceRule, ...] = ()


@dataclass(frozen=True)
class CatalogMatch:
    event_id: int | None
    category: str
    event_type: str
    action: str
    severity: str
    tags: list[str] = field(default_factory=list)
    source_match: bool = True
    matched_definition: str | None = None
    source_family: str = "generic"


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _rule(
    *,
    provider_contains: str | tuple[str, ...] | None = None,
    channel_equals: str | tuple[str, ...] | None = None,
    channel_contains: str | tuple[str, ...] | None = None,
) -> EventSourceRule:
    def _tuple(value: str | tuple[str, ...] | None) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, tuple):
            return tuple(_normalize(item) for item in value)
        return (_normalize(value),)

    return EventSourceRule(
        provider_contains=_tuple(provider_contains),
        channel_equals=_tuple(channel_equals),
        channel_contains=_tuple(channel_contains),
    )


SECURITY_AUDITING = _rule(
    provider_contains="microsoft-windows-security-auditing",
    channel_equals="security",
)
EVENTLOG_SECURITY = _rule(
    provider_contains=("microsoft-windows-eventlog", "eventlog"),
    channel_equals="security",
)
SYSTEM_SCM = _rule(
    provider_contains="service control manager",
    channel_equals="system",
)
TASK_SCHEDULER = _rule(
    provider_contains="microsoft-windows-taskscheduler",
    channel_contains="microsoft-windows-taskscheduler/operational",
)
POWERSHELL = _rule(
    provider_contains=("microsoft-windows-powershell", "powershell"),
    channel_contains=("microsoft-windows-powershell/operational", "windows powershell", "powershellcore/operational"),
)
BITS_CLIENT = _rule(
    provider_contains="bits-client",
    channel_contains="bits-client",
)
WLAN_AUTOCONFIG = _rule(
    provider_contains="wlan-autoconfig",
    channel_contains="wlan-autoconfig",
)
TASK_SCHEDULER_ALT = _rule(
    provider_contains="taskscheduler",
    channel_contains="taskscheduler",
)
TS_LOCAL = _rule(
    provider_contains="localsessionmanager",
    channel_contains="microsoft-windows-terminalservices-localsessionmanager/operational",
)
TS_REMOTE = _rule(
    provider_contains="remoteconnectionmanager",
    channel_contains="microsoft-windows-terminalservices-remoteconnectionmanager/operational",
)
TS_GENERIC = _rule(
    provider_contains="terminalservices",
    channel_contains="terminalservices",
)
DEFENDER = _rule(
    provider_contains="microsoft-windows-windows defender",
    channel_contains="microsoft-windows-windows defender/operational",
)
WMI_ACTIVITY = _rule(
    provider_contains="microsoft-windows-wmi-activity",
    channel_contains="microsoft-windows-wmi-activity/operational",
)
WINRM = _rule(
    provider_contains="microsoft-windows-winrm",
    channel_contains="microsoft-windows-winrm/operational",
)
SYSMON = _rule(
    provider_contains="microsoft-windows-sysmon",
    channel_contains="microsoft-windows-sysmon/operational",
)


EVENT_DEFINITIONS: tuple[EventDefinition, ...] = (
    EventDefinition("security_4624", 4624, "authentication", "logon_success", "logon_success", tags=("authentication", "logon"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4625", 4625, "authentication", "logon_failed", "logon_failed", severity="medium", tags=("authentication", "logon", "failed"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4634", 4634, "authentication", "logoff", "logoff", tags=("authentication", "logoff"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4647", 4647, "authentication", "user_logoff", "user_logoff", tags=("authentication", "logoff"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4648", 4648, "authentication", "explicit_credentials_logon", "explicit_credentials_logon", severity="medium", tags=("authentication", "credentials"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4672", 4672, "authentication", "special_privileges_assigned", "special_privileges_assigned", tags=("privilege", "authentication"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4688", 4688, "process", "process_creation", "process_creation", tags=("execution", "process"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4689", 4689, "process", "process_termination", "process_termination", tags=("execution", "process"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4697", 4697, "persistence", "service_created", "service_created", severity="medium", tags=("service", "persistence"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4698", 4698, "persistence", "scheduled_task_created", "scheduled_task_created", severity="medium", tags=("scheduled_task", "persistence"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4702", 4702, "persistence", "scheduled_task_updated", "scheduled_task_updated", severity="medium", tags=("scheduled_task", "persistence"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4720", 4720, "account_management", "user_created", "user_created", severity="medium", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4722", 4722, "account_management", "user_enabled", "user_enabled", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4723", 4723, "account_management", "password_change_attempt", "password_change_attempt", severity="medium", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4724", 4724, "account_management", "password_reset_attempt", "password_reset_attempt", severity="medium", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4725", 4725, "account_management", "user_disabled", "user_disabled", severity="medium", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4726", 4726, "account_management", "user_deleted", "user_deleted", severity="medium", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4728", 4728, "account_management", "user_added_to_group", "user_added_to_group", severity="medium", tags=("account_management", "privilege"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4732", 4732, "account_management", "user_added_to_group", "user_added_to_group", severity="medium", tags=("account_management", "privilege"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4735", 4735, "account_management", "group_changed", "group_changed", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4737", 4737, "account_management", "group_changed", "group_changed", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4738", 4738, "account_management", "user_modified", "user_modified", tags=("account_management",), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4740", 4740, "account_management", "account_locked_out", "account_locked_out", severity="medium", tags=("account_management", "authentication"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4768", 4768, "authentication", "kerberos_tgt_requested", "kerberos_tgt_requested", tags=("authentication", "kerberos"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4769", 4769, "authentication", "kerberos_service_ticket_requested", "kerberos_service_ticket_requested", tags=("authentication", "kerberos"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4771", 4771, "authentication", "kerberos_preauth_failed", "kerberos_preauth_failed", severity="medium", tags=("authentication", "kerberos", "failed"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4776", 4776, "authentication", "ntlm_authentication", "ntlm_authentication", tags=("authentication", "ntlm"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4778", 4778, "remote_access", "rdp_session_reconnected", "rdp_session_reconnected", severity="medium", tags=("rdp", "remote_access"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_4779", 4779, "remote_access", "rdp_session_disconnected", "rdp_session_disconnected", tags=("rdp", "remote_access"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_5140", 5140, "network", "network_share_access", "network_share_access", severity="medium", tags=("smb", "share"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_5145", 5145, "network", "network_share_object_access", "network_share_object_access", severity="medium", tags=("smb", "share", "file_access"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("security_5156", 5156, "network", "network_connection_allowed", "network_connection_allowed", tags=("network", "firewall"), valid_sources=(SECURITY_AUDITING,)),
    EventDefinition("eventlog_1102", 1102, "anti_forensics", "audit_log_cleared", "audit_log_cleared", severity="high", tags=("anti_forensics", "log_cleared", "security"), valid_sources=(EVENTLOG_SECURITY,)),
    EventDefinition("system_7036", 7036, "service", "service_state_changed", "service_state_changed", tags=("service",), valid_sources=(SYSTEM_SCM,)),
    EventDefinition("system_7040", 7040, "service", "service_start_type_changed", "service_start_type_changed", severity="medium", tags=("service", "persistence"), valid_sources=(SYSTEM_SCM,)),
    EventDefinition("system_7045", 7045, "persistence", "service_created", "service_created", severity="high", tags=("service", "persistence"), valid_sources=(SYSTEM_SCM,)),
    EventDefinition("task_106", 106, "persistence", "scheduled_task_registered", "scheduled_task_registered", severity="medium", tags=("scheduled_task", "persistence"), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_140", 140, "persistence", "scheduled_task_updated", "scheduled_task_updated", severity="medium", tags=("scheduled_task",), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_141", 141, "persistence", "scheduled_task_deleted", "scheduled_task_deleted", severity="medium", tags=("scheduled_task",), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_200", 200, "execution", "scheduled_task_action_started", "scheduled_task_action_started", tags=("scheduled_task",), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_201", 201, "execution", "scheduled_task_action_completed", "scheduled_task_action_completed", tags=("scheduled_task",), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_102", 102, "execution", "scheduled_task_completed", "scheduled_task_completed", tags=("scheduled_task",), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("task_129", 129, "execution", "scheduled_task_launch_failed", "scheduled_task_launch_failed", severity="medium", tags=("scheduled_task", "failed"), valid_sources=(TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
    EventDefinition("powershell_400", 400, "powershell", "powershell_engine_start", "powershell_engine_start", tags=("powershell",), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_403", 403, "powershell", "powershell_engine_stop", "powershell_engine_stop", tags=("powershell",), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_600", 600, "powershell", "powershell_provider_lifecycle", "powershell_provider_lifecycle", tags=("powershell",), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_800", 800, "powershell", "powershell_pipeline_execution", "powershell_pipeline_execution", tags=("powershell", "script"), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_4103", 4103, "powershell", "powershell_module_logging", "powershell_module_logging", severity="medium", tags=("powershell", "script"), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_4104", 4104, "powershell", "powershell_script_block", "powershell_script_block", severity="medium", tags=("powershell", "script"), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_4105", 4105, "powershell", "powershell_script_block_start", "powershell_script_block_start", tags=("powershell", "script"), valid_sources=(POWERSHELL,)),
    EventDefinition("powershell_4106", 4106, "powershell", "powershell_script_block_stop", "powershell_script_block_stop", tags=("powershell", "script"), valid_sources=(POWERSHELL,)),
    EventDefinition("rdp_local_21", 21, "remote_access", "rdp_session_logon", "rdp_session_logon", severity="medium", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_22", 22, "remote_access", "rdp_shell_start", "rdp_shell_start", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_23", 23, "remote_access", "rdp_session_logoff", "rdp_session_logoff", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_24", 24, "remote_access", "rdp_session_disconnected", "rdp_session_disconnected", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_25", 25, "remote_access", "rdp_session_reconnected", "rdp_session_reconnected", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_39", 39, "remote_access", "rdp_session_disconnected_by_session", "rdp_session_disconnected_by_session", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_local_40", 40, "remote_access", "rdp_session_reconnection_or_disconnect_reason", "rdp_session_reconnection_or_disconnect_reason", tags=("rdp", "remote_access"), valid_sources=(TS_LOCAL, TS_GENERIC)),
    EventDefinition("rdp_remote_1149", 1149, "remote_access", "rdp_authentication_success", "rdp_authentication_success", severity="medium", tags=("rdp", "remote_access", "authentication"), valid_sources=(TS_REMOTE, TS_GENERIC)),
    EventDefinition("bits_3", 3, "network", "bits_job_created", "bits_job_created", tags=("bits", "network"), valid_sources=(BITS_CLIENT,)),
    EventDefinition("bits_4", 4, "network", "bits_job_modified", "bits_job_modified", tags=("bits", "network"), valid_sources=(BITS_CLIENT,)),
    EventDefinition("bits_59", 59, "network", "bits_job_transferred", "bits_job_transferred", tags=("bits", "network"), valid_sources=(BITS_CLIENT,)),
    EventDefinition("bits_60", 60, "network", "bits_job_error", "bits_job_error", severity="medium", tags=("bits", "network", "failed"), valid_sources=(BITS_CLIENT,)),
    EventDefinition("wlan_8000", 8000, "network", "wlan_connection_started", "wlan_connection_started", tags=("wlan", "network"), valid_sources=(WLAN_AUTOCONFIG,)),
    EventDefinition("wlan_8001", 8001, "network", "wlan_connection", "wlan_connection", tags=("wlan", "network"), valid_sources=(WLAN_AUTOCONFIG,)),
    EventDefinition("wlan_8002", 8002, "network", "wlan_connection_failed", "wlan_connection_failed", severity="medium", tags=("wlan", "network", "failed"), valid_sources=(WLAN_AUTOCONFIG,)),
    EventDefinition("wlan_8003", 8003, "network", "wlan_disconnection", "wlan_disconnection", tags=("wlan", "network"), valid_sources=(WLAN_AUTOCONFIG,)),
    EventDefinition("defender_1116", 1116, "detection", "defender_malware_detected", "defender_malware_detected", severity="high", tags=("defender", "malware", "detection"), valid_sources=(DEFENDER,)),
    EventDefinition("defender_1117", 1117, "detection", "defender_action_taken", "defender_action_taken", severity="medium", tags=("defender",), valid_sources=(DEFENDER,)),
    EventDefinition("defender_1118", 1118, "detection", "defender_action_failed", "defender_action_failed", severity="medium", tags=("defender",), valid_sources=(DEFENDER,)),
    EventDefinition("defender_1119", 1119, "detection", "defender_remediation_critical", "defender_remediation_critical", severity="high", tags=("defender",), valid_sources=(DEFENDER,)),
    EventDefinition("defender_5007", 5007, "detection", "defender_configuration_changed", "defender_configuration_changed", severity="medium", tags=("defender", "configuration"), valid_sources=(DEFENDER,)),
    EventDefinition("defender_5013", 5013, "detection", "defender_tamper_or_config_issue", "defender_tamper_or_config_issue", severity="high", tags=("defender",), valid_sources=(DEFENDER,)),
    EventDefinition("wmi_5857", 5857, "wmi", "wmi_provider_started", "wmi_provider_started", tags=("wmi",), valid_sources=(WMI_ACTIVITY,)),
    EventDefinition("wmi_5858", 5858, "wmi", "wmi_error", "wmi_error", severity="medium", tags=("wmi",), valid_sources=(WMI_ACTIVITY,)),
    EventDefinition("wmi_5859", 5859, "persistence", "wmi_persistence_or_filter", "wmi_persistence_or_filter", severity="high", tags=("wmi", "persistence"), valid_sources=(WMI_ACTIVITY,)),
    EventDefinition("wmi_5860", 5860, "persistence", "wmi_persistence_or_consumer", "wmi_persistence_or_consumer", severity="high", tags=("wmi", "persistence"), valid_sources=(WMI_ACTIVITY,)),
    EventDefinition("wmi_5861", 5861, "persistence", "wmi_persistence_or_binding", "wmi_persistence_or_binding", severity="high", tags=("wmi", "persistence"), valid_sources=(WMI_ACTIVITY,)),
    EventDefinition("winrm_generic", -1, "remote_access", "winrm_activity", "winrm_activity", severity="medium", tags=("winrm", "remote_access"), valid_sources=(WINRM,)),
    EventDefinition("sysmon_1", 1, "process", "sysmon_process_creation", "sysmon_process_creation", tags=("sysmon", "process", "execution"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_3", 3, "network", "sysmon_network_connection", "sysmon_network_connection", tags=("sysmon", "network"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_7", 7, "process", "sysmon_image_loaded", "sysmon_image_loaded", tags=("sysmon",), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_10", 10, "process", "sysmon_process_access", "sysmon_process_access", severity="medium", tags=("sysmon",), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_11", 11, "file", "sysmon_file_created", "sysmon_file_created", tags=("sysmon", "file"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_12", 12, "registry", "sysmon_registry_object_created_deleted", "sysmon_registry_object_created_deleted", tags=("sysmon", "registry"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_13", 13, "registry", "sysmon_registry_value_set", "sysmon_registry_value_set", tags=("sysmon", "registry"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_14", 14, "registry", "sysmon_registry_key_value_renamed", "sysmon_registry_key_value_renamed", tags=("sysmon", "registry"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_15", 15, "file", "sysmon_file_create_stream_hash", "sysmon_file_create_stream_hash", tags=("sysmon", "file"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_22", 22, "network", "sysmon_dns_query", "sysmon_dns_query", tags=("sysmon", "dns"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_23", 23, "file", "sysmon_file_deleted", "sysmon_file_deleted", tags=("sysmon", "file"), valid_sources=(SYSMON,)),
    EventDefinition("sysmon_26", 26, "file", "sysmon_file_delete_detected", "sysmon_file_delete_detected", tags=("sysmon", "file"), valid_sources=(SYSMON,)),
)


def _source_matches(rule: EventSourceRule, provider: str, channel: str) -> bool:
    if rule.provider_contains and not any(token in provider for token in rule.provider_contains):
        return False
    if rule.channel_equals and channel not in rule.channel_equals:
        return False
    if rule.channel_contains and not any(token in channel for token in rule.channel_contains):
        return False
    return True


def _generic_match(event_id: int | None, provider: str, channel: str) -> CatalogMatch:
    event_type = f"event_id_{event_id}" if event_id is not None else "windows_event"
    return CatalogMatch(
        event_id=event_id,
        category="windows_event",
        event_type=event_type,
        action="windows_event_observed",
        severity="info",
        tags=["windows_event"],
        source_match=True,
        source_family=infer_event_source_family(provider, channel),
    )


def infer_event_source_family(provider: str | None, channel: str | None) -> str:
    provider_normalized = _normalize(provider)
    channel_normalized = _normalize(channel)
    families: tuple[tuple[str, tuple[EventSourceRule, ...]], ...] = (
        ("security", (SECURITY_AUDITING, EVENTLOG_SECURITY)),
        ("powershell", (POWERSHELL,)),
        ("system_service", (SYSTEM_SCM,)),
        ("wmi", (WMI_ACTIVITY,)),
        ("bits", (BITS_CLIENT,)),
        ("wlan", (WLAN_AUTOCONFIG,)),
        ("task_scheduler", (TASK_SCHEDULER, TASK_SCHEDULER_ALT)),
        ("terminal_services", (TS_LOCAL, TS_REMOTE, TS_GENERIC)),
        ("defender", (DEFENDER,)),
        ("winrm", (WINRM,)),
        ("sysmon", (SYSMON,)),
    )
    for family, rules in families:
        if any(_source_matches(rule, provider_normalized, channel_normalized) for rule in rules):
            return family
    return "generic"


def classify_evtx_event(event_id: int | None, channel: str | None, provider: str | None, payload: dict | None = None) -> CatalogMatch:
    provider_normalized = _normalize(provider)
    channel_normalized = _normalize(channel)
    matched_by_id = False
    source_family = infer_event_source_family(provider_normalized, channel_normalized)

    for definition in EVENT_DEFINITIONS:
        if definition.event_id >= 0 and definition.event_id != event_id:
            continue
        if definition.event_id == -1 and not (
            any(_source_matches(rule, provider_normalized, channel_normalized) for rule in definition.valid_sources)
        ):
            continue
        if definition.event_id != -1:
            matched_by_id = True
        if not definition.valid_sources or any(_source_matches(rule, provider_normalized, channel_normalized) for rule in definition.valid_sources):
            return CatalogMatch(
                event_id=event_id,
                category=definition.category,
                event_type=definition.event_type,
                action=definition.action,
                severity=definition.severity,
                tags=list(definition.tags),
                source_match=True,
                matched_definition=definition.key,
                source_family=source_family,
            )

    if matched_by_id:
        return CatalogMatch(
            event_id=event_id,
            category="windows_event",
            event_type=f"event_id_{event_id}" if event_id is not None else "windows_event",
            action="windows_event_observed",
            severity="info",
            tags=["windows_event", "source_mismatch"],
            source_match=False,
            source_family=source_family,
        )

    return _generic_match(event_id, provider_normalized, channel_normalized)


def classify_windows_event(event_id: int | None, provider: str | None, channel: str | None) -> CatalogMatch:
    return classify_evtx_event(event_id, channel, provider)
