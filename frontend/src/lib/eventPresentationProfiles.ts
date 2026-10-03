export type PresentationColumn = {
  key: string;
  label: string;
  paths: string[];
  defaultVisible?: boolean;
  /** When set, the column is shown by default only if this returns true for the rows on screen. */
  visibleWhen?: (items: Record<string, unknown>[]) => boolean;
  format?: (value: unknown, item: Record<string, unknown>) => string;
};

export type DetailField = {
  label: string;
  paths: string[];
  format?: (value: unknown, item: Record<string, unknown>) => string;
};

export type DetailSection = {
  title: string;
  fields: DetailField[];
};

export type PresentationProfile = {
  id: string;
  label: string;
  columns: PresentationColumn[];
  details: DetailSection[];
};

function valueAt(item: Record<string, unknown>, path: string): unknown {
  return path.split(".").reduce<unknown>((current, part) => {
    if (current && typeof current === "object") return (current as Record<string, unknown>)[part];
    return undefined;
  }, item);
}

export function isPresent(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  const text = String(value).trim();
  return text !== "" && text !== "-" && text !== "null" && text !== "undefined";
}

export function firstPresent(item: Record<string, unknown>, paths: string[]): unknown {
  for (const path of paths) {
    const value = valueAt(item, path);
    if (isPresent(value)) return value;
  }
  return undefined;
}

export function renderPresentationValue(item: Record<string, unknown>, field: { paths: string[]; format?: (value: unknown, item: Record<string, unknown>) => string }): string {
  const value = firstPresent(item, field.paths);
  if (!isPresent(value)) return "-";
  if (field.format) return field.format(value, item);
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

const eventSection: DetailSection = {
  title: "Event",
  fields: [
    { label: "Summary", paths: ["title", "event.message", "message"] },
    { label: "Timestamp", paths: ["@timestamp"] },
    { label: "Type", paths: ["event.type"] },
    { label: "Action", paths: ["event.action"] },
    { label: "Outcome", paths: ["event.outcome"] },
    { label: "Severity", paths: ["event.severity"] },
    { label: "Host", paths: ["host.name", "host.hostname", "linux.hostname"] },
  ],
};

const networkSection: DetailSection = {
  title: "Network",
  fields: [
    { label: "Source IP", paths: ["network.source_ip", "linux.remote_ip", "linux.source_ip"] },
    { label: "Source Port", paths: ["network.source_port", "linux.source_port"] },
    { label: "Destination IP", paths: ["network.destination_ip", "destination.ip", "linux.local_ip", "linux.destination_ip"] },
    { label: "Destination Port", paths: ["network.destination_port", "destination.port", "linux.destination_port"] },
  ],
};

const provenanceSection: DetailSection = {
  title: "Provenance",
  fields: [
    { label: "Case", paths: ["case_id"] },
    { label: "Evidence", paths: ["evidence_id"] },
    { label: "Artifact ID", paths: ["artifact_id"] },
    { label: "Artifact family", paths: ["artifact.family", "artifact.type"] },
    { label: "Parser", paths: ["artifact.parser", "source_tool"] },
    { label: "Source file", paths: ["source_file", "artifact.source_path"] },
    { label: "Original source file", paths: ["artifact.original_source_path", "evidence_source.original_path"] },
    { label: "Source event ID", paths: ["event_id", "source_event_id"] },
    { label: "Line number", paths: ["linux.line_number"] },
  ],
};

const rawSection: DetailSection = {
  title: "Raw",
  fields: [
    { label: "Raw excerpt", paths: ["raw_excerpt", "linux.raw_excerpt"] },
    { label: "Message", paths: ["message", "event.message"] },
  ],
};

const apacheAccessProfile: PresentationProfile = {
  id: "linux_apache_access",
  label: "Apache access logs",
  columns: [
    { key: "timestamp", label: "Timestamp", paths: ["@timestamp"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    { key: "host", label: "Host", paths: ["host.name", "host.hostname", "linux.hostname"] },
    { key: "http_method", label: "Method", paths: ["http.request.method", "linux.http_method"] },
    { key: "request", label: "Request", paths: ["url.path", "url.full", "linux.url_path"] },
    { key: "http_status", label: "HTTP Status", paths: ["http.response.status_code", "linux.http_status"] },
    { key: "user_agent", label: "User Agent", paths: ["user_agent.original", "linux.http_user_agent"] },
    { key: "source_port", label: "Source Port", paths: ["network.source_port", "linux.source_port"], defaultVisible: false },
    { key: "destination_ip", label: "Destination IP", paths: ["network.destination_ip", "destination.ip"], defaultVisible: false },
    { key: "destination_port", label: "Destination Port", paths: ["network.destination_port", "destination.port"], defaultVisible: false },
    { key: "severity", label: "Severity", paths: ["event.severity"], defaultVisible: false },
    { key: "outcome", label: "Outcome", paths: ["event.outcome"], defaultVisible: false },
    { key: "bytes", label: "Bytes", paths: ["network.bytes_sent", "linux.bytes_sent"], defaultVisible: false },
    { key: "type", label: "Event Type", paths: ["event.type"], format: (value) => value === "apache_access" ? "Access" : String(value), defaultVisible: false },
    { key: "source_file", label: "Source File", paths: ["source_file", "artifact.source_path"], defaultVisible: false },
    { key: "line_number", label: "Line Number", paths: ["linux.line_number"], defaultVisible: false },
  ],
  details: [
    eventSection,
    networkSection,
    {
      title: "HTTP",
      fields: [
        { label: "Method", paths: ["http.request.method", "linux.http_method"] },
        { label: "URL / Request", paths: ["url.path", "url.full", "linux.url_path"] },
        { label: "HTTP Status", paths: ["http.response.status_code", "linux.http_status"] },
        { label: "User Agent", paths: ["user_agent.original", "linux.http_user_agent"] },
        { label: "Bytes", paths: ["network.bytes_sent", "linux.bytes_sent"] },
      ],
    },
    provenanceSection,
    rawSection,
  ],
};

const apacheErrorProfile: PresentationProfile = {
  id: "linux_apache_error",
  label: "Apache error logs",
  columns: [
    { key: "timestamp", label: "Timestamp", paths: ["@timestamp"] },
    { key: "severity", label: "Severity", paths: ["event.severity", "linux.http_severity"] },
    { key: "host", label: "Host", paths: ["host.name", "host.hostname", "linux.hostname"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    { key: "type", label: "Event Type", paths: ["event.type"], format: (value) => value === "apache_error" ? "Error" : String(value) },
    { key: "summary", label: "Message", paths: ["title", "event.message", "message"] },
    { key: "source_file", label: "Source File", paths: ["source_file", "artifact.source_path"], defaultVisible: false },
    { key: "line_number", label: "Line Number", paths: ["linux.line_number"], defaultVisible: false },
  ],
  details: [eventSection, networkSection, provenanceSection, rawSection],
};

const eximProfile: PresentationProfile = {
  id: "linux_exim",
  label: "Exim logs",
  columns: [
    { key: "timestamp", label: "Timestamp", paths: ["@timestamp"] },
    { key: "source_ip", label: "Remote IP", paths: ["network.source_ip", "linux.remote_ip", "linux.source_ip"] },
    { key: "host", label: "Host", paths: ["host.name", "host.hostname", "linux.hostname"] },
    { key: "action", label: "Action", paths: ["event.action", "linux.event_action"] },
    { key: "sender", label: "Sender", paths: ["email.from.address", "linux.sender"] },
    { key: "recipient", label: "Recipient", paths: ["email.to", "linux.recipient"] },
    { key: "smtp_outcome", label: "Outcome / SMTP", paths: ["linux.smtp_status", "event.outcome"] },
    { key: "queue_id", label: "Queue ID", paths: ["linux.queue_id"] },
    { key: "summary", label: "Summary", paths: ["title", "event.message", "message"] },
    { key: "source_port", label: "Remote Port", paths: ["network.source_port", "linux.source_port"], defaultVisible: false },
    { key: "destination_ip", label: "Local IP", paths: ["destination.ip", "linux.local_ip", "network.destination_ip"], defaultVisible: false },
    { key: "destination_port", label: "Local Port", paths: ["destination.port", "linux.destination_port", "network.destination_port"], defaultVisible: false },
    { key: "message_id", label: "Message ID", paths: ["email.message_id", "linux.message_id"], defaultVisible: false },
    { key: "helo", label: "HELO/EHLO", paths: ["linux.helo"], defaultVisible: false },
    { key: "authentication", label: "Authentication", paths: ["linux.authentication"], defaultVisible: false },
    { key: "severity", label: "Severity", paths: ["event.severity"], defaultVisible: false },
    { key: "source_file", label: "Source File", paths: ["source_file", "artifact.source_path"], defaultVisible: false },
    { key: "line_number", label: "Line Number", paths: ["linux.line_number"], defaultVisible: false },
  ],
  details: [
    eventSection,
    networkSection,
    {
      title: "Email / SMTP",
      fields: [
        { label: "Sender", paths: ["email.from.address", "linux.sender"] },
        { label: "Recipient", paths: ["email.to", "linux.recipient"] },
        { label: "Queue ID", paths: ["linux.queue_id"] },
        { label: "Message ID", paths: ["email.message_id", "linux.message_id"] },
        { label: "SMTP Status", paths: ["linux.smtp_status"] },
        { label: "HELO/EHLO", paths: ["linux.helo"] },
        { label: "Authentication", paths: ["linux.authentication"] },
      ],
    },
    provenanceSection,
    rawSection,
  ],
};


// ---------------------------------------------------------------------------------------------
// Linux log families
//
// Every profile below carries a Message column built from the log's own text, so the content
// that matters is always on screen even when no parser extracted a dedicated field for it
// (a generic text log is the extreme case: the message *is* the event).
// ---------------------------------------------------------------------------------------------

const MESSAGE_PATHS = ["message", "event.message", "raw_excerpt", "linux.message", "title"];

const messageColumn: PresentationColumn = { key: "message", label: "Message", paths: MESSAGE_PATHS };

const sourceFileColumns: PresentationColumn[] = [
  { key: "source_file", label: "Source File", paths: ["source_file", "artifact.source_path", "linux.source_file"], defaultVisible: false },
  { key: "line_number", label: "Line Number", paths: ["linux.line_number"], defaultVisible: false },
];

const TIME_QUALITY_LABELS: Record<string, string> = {
  ok: "Exact",
  assumed_utc: "Assumed UTC (log has no timezone)",
  assumed_year_utc: "Assumed year and UTC (syslog has neither)",
  missing: "No time in the log",
};

function timeQualityLabel(value: unknown): string {
  const key = String(value);
  return TIME_QUALITY_LABELS[key] ?? key;
}

/** Shown by default only when some row on screen has a time that is not exact. */
const timeQualityColumn: PresentationColumn = {
  key: "time_quality",
  label: "Time Quality",
  paths: ["linux.timestamp_status"],
  format: (value) => timeQualityLabel(value),
  visibleWhen: (items) => items.some((item) => {
    const status = firstPresent(item, ["linux.timestamp_status"]);
    return isPresent(status) && String(status) !== "ok";
  }),
};

const hostColumn: PresentationColumn = { key: "host", label: "Host", paths: ["host.name", "host.hostname", "linux.hostname"] };
const severityColumn: PresentationColumn = { key: "severity", label: "Severity", paths: ["event.severity"] };
const timestampColumn: PresentationColumn = { key: "timestamp", label: "Timestamp", paths: ["@timestamp"] };

const pidColumn: PresentationColumn = { key: "pid", label: "PID", paths: ["linux.pid", "process.pid"], defaultVisible: false };

const timeDetail: DetailSection = {
  title: "Time",
  fields: [
    { label: "Timestamp", paths: ["@timestamp"] },
    { label: "Time quality", paths: ["linux.timestamp_status"], format: (value) => timeQualityLabel(value) },
  ],
};

const FIREWALL_PROFILE_SHARE = 0.3;

const linuxSyslogProfile: PresentationProfile = {
  id: "linux_syslog",
  label: "Syslog",
  columns: [
    timestampColumn,
    hostColumn,
    { key: "process", label: "Process", paths: ["linux.process", "process.name"] },
    severityColumn,
    messageColumn,
    timeQualityColumn,
    pidColumn,
    { key: "user", label: "User", paths: ["user.name", "linux.username"], defaultVisible: false },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"], defaultVisible: false },
    { key: "destination_ip", label: "Destination IP", paths: ["network.destination_ip", "linux.destination_ip"], defaultVisible: false },
    { key: "verdict", label: "Firewall Verdict", paths: ["linux.firewall_action"], defaultVisible: false },
    { key: "type", label: "Event Type", paths: ["event.type"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [eventSection, timeDetail, networkSection, provenanceSection, rawSection],
};

const firewallDetail: DetailSection = {
  title: "Firewall packet",
  fields: [
    { label: "Verdict", paths: ["linux.firewall_action"] },
    { label: "Log prefix", paths: ["linux.firewall_prefix"] },
    { label: "Protocol", paths: ["linux.network_protocol", "network.protocol"] },
    { label: "Interface in", paths: ["linux.interface_in"] },
    { label: "Interface out", paths: ["linux.interface_out"] },
    { label: "TCP flags", paths: ["linux.tcp_flags"] },
  ],
};

const linuxFirewallProfile: PresentationProfile = {
  id: "linux_syslog_firewall",
  label: "Firewall (netfilter) log",
  columns: [
    timestampColumn,
    { key: "verdict", label: "Verdict", paths: ["linux.firewall_action"] },
    { key: "protocol", label: "Proto", paths: ["linux.network_protocol", "network.protocol"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    { key: "source_port", label: "Src Port", paths: ["network.source_port"], defaultVisible: false },
    { key: "destination_ip", label: "Destination IP", paths: ["network.destination_ip", "linux.destination_ip"] },
    { key: "destination_port", label: "Dst Port", paths: ["network.destination_port"] },
    { key: "interface_in", label: "In", paths: ["linux.interface_in"] },
    hostColumn,
    severityColumn,
    messageColumn,
    timeQualityColumn,
    { key: "interface_out", label: "Out", paths: ["linux.interface_out"], defaultVisible: false },
    { key: "tcp_flags", label: "TCP Flags", paths: ["linux.tcp_flags"], defaultVisible: false },
    { key: "prefix", label: "Log Prefix", paths: ["linux.firewall_prefix"], defaultVisible: false },
    { key: "process", label: "Process", paths: ["linux.process", "process.name"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [eventSection, firewallDetail, networkSection, timeDetail, provenanceSection, rawSection],
};

const SYSMON_EVENT_LABELS: Record<string, string> = {
  sysmon_process_created: "Process created",
  sysmon_network_connection: "Network connection",
  sysmon_process_terminated: "Process terminated",
  sysmon_file_created: "File created",
  sysmon_file_deleted: "File deleted",
  sysmon_raw_access_read: "Raw disk read",
  sysmon_config_changed: "Sysmon config changed",
  sysmon_state_changed: "Sysmon state changed",
};

const sysmonDetail: DetailSection = {
  title: "Sysmon event",
  fields: [
    { label: "Event", paths: ["event.type"], format: (value) => SYSMON_EVENT_LABELS[String(value)] ?? String(value) },
    { label: "Event ID", paths: ["event.code", "linux.sysmon_event_id"] },
    { label: "Image", paths: ["process.path", "linux.exe"] },
    { label: "Command line", paths: ["process.command_line"] },
    { label: "Working directory", paths: ["process.current_directory"] },
    { label: "User", paths: ["user.name"] },
    { label: "PID", paths: ["process.pid"] },
    { label: "SHA-256", paths: ["process.hashes.sha256"] },
    { label: "Parent image", paths: ["process.parent_path"] },
    { label: "Parent command line", paths: ["process.parent_command_line"] },
    { label: "Parent PID", paths: ["process.ppid"] },
    { label: "Target file", paths: ["file.path"] },
  ],
};

/** Sysmon for Linux events found inside syslog: structured process / network / file activity. */
const linuxSysmonProfile: PresentationProfile = {
  id: "linux_syslog_sysmon",
  label: "Sysmon for Linux",
  columns: [
    timestampColumn,
    { key: "sysmon_event", label: "Event", paths: ["event.type"], format: (value) => SYSMON_EVENT_LABELS[String(value)] ?? String(value) },
    { key: "user", label: "User", paths: ["user.name", "linux.username"] },
    { key: "exe", label: "Image", paths: ["process.path", "linux.exe"] },
    { key: "command", label: "Command Line", paths: ["process.command_line"] },
    { key: "parent_image", label: "Parent Image", paths: ["process.parent_path"] },
    { key: "destination_ip", label: "Destination IP", paths: ["network.destination_ip", "destination.ip"] },
    { key: "destination_port", label: "Dst Port", paths: ["network.destination_port", "destination.port"] },
    { key: "file", label: "Target File", paths: ["file.path"] },
    hostColumn,
    messageColumn,
    { key: "process", label: "Process", paths: ["process.name", "linux.process"], defaultVisible: false },
    pidColumn,
    { key: "parent_command", label: "Parent Command Line", paths: ["process.parent_command_line"], defaultVisible: false },
    { key: "sha256", label: "SHA-256", paths: ["process.hashes.sha256"], defaultVisible: false },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip"], defaultVisible: false },
    severityColumn,
    ...sourceFileColumns,
  ],
  details: [eventSection, sysmonDetail, networkSection, timeDetail, provenanceSection, rawSection],
};

const linuxJournalProfile: PresentationProfile = {
  id: "linux_journal",
  label: "systemd journal",
  columns: [
    timestampColumn,
    hostColumn,
    { key: "unit", label: "Unit", paths: ["linux.unit", "event.action"] },
    { key: "process", label: "Process", paths: ["linux.process", "process.name"] },
    severityColumn,
    { key: "user", label: "User", paths: ["user.name", "user.id"] },
    messageColumn,
    timeQualityColumn,
    pidColumn,
    { key: "exe", label: "Executable", paths: ["linux.exe"], defaultVisible: false },
    { key: "transport", label: "Transport", paths: ["linux.transport"], defaultVisible: false },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"], defaultVisible: false },
    { key: "boot_id", label: "Boot ID", paths: ["linux.boot_id"], defaultVisible: false },
    { key: "seqnum", label: "Sequence", paths: ["linux.seqnum"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    timeDetail,
    {
      title: "Journal",
      fields: [
        { label: "Unit", paths: ["linux.unit", "event.action"] },
        { label: "Process", paths: ["linux.process"] },
        { label: "PID", paths: ["linux.pid"] },
        { label: "Executable", paths: ["linux.exe"] },
        { label: "Transport", paths: ["linux.transport"] },
        { label: "User ID", paths: ["user.id", "linux.uid"] },
        { label: "Boot ID", paths: ["linux.boot_id"] },
        { label: "Sequence number", paths: ["linux.seqnum"] },
      ],
    },
    networkSection,
    provenanceSection,
    rawSection,
  ],
};

const linuxAuthProfile: PresentationProfile = {
  id: "linux_auth",
  label: "Authentication log",
  columns: [
    timestampColumn,
    hostColumn,
    { key: "user", label: "User", paths: ["user.name", "linux.username", "linux.attempted_username"] },
    { key: "event", label: "Event", paths: ["title", "event.type"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    { key: "method", label: "Method", paths: ["linux.auth_method"] },
    { key: "outcome", label: "Result", paths: ["linux.authentication_result", "event.outcome"] },
    { key: "process", label: "Process", paths: ["linux.process", "process.name"] },
    severityColumn,
    messageColumn,
    timeQualityColumn,
    pidColumn,
    { key: "source_port", label: "Source Port", paths: ["network.source_port", "linux.source_port"], defaultVisible: false },
    { key: "terminal", label: "Terminal", paths: ["linux.terminal"], defaultVisible: false },
    { key: "service", label: "Service", paths: ["linux.service"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    timeDetail,
    {
      title: "Authentication",
      fields: [
        { label: "Event", paths: ["linux.auth_event_type", "event.type"] },
        { label: "Method", paths: ["linux.auth_method"] },
        { label: "Result", paths: ["linux.authentication_result", "event.outcome"] },
        { label: "User", paths: ["user.name", "linux.username"] },
        { label: "Attempted user", paths: ["linux.attempted_username"] },
        { label: "Terminal", paths: ["linux.terminal"] },
        { label: "Service", paths: ["linux.service"] },
      ],
    },
    networkSection,
    provenanceSection,
    rawSection,
  ],
};

const linuxAuditProfile: PresentationProfile = {
  id: "linux_audit",
  label: "auditd",
  columns: [
    timestampColumn,
    hostColumn,
    { key: "audit_type", label: "Record", paths: ["linux.audit_type"] },
    { key: "exe", label: "Executable", paths: ["linux.exe", "process.path"] },
    { key: "command", label: "Command", paths: ["process.command_line", "linux.command"] },
    { key: "user", label: "User", paths: ["user.name", "linux.username", "linux.uid"] },
    { key: "audit_key", label: "Key", paths: ["linux.audit_key"] },
    severityColumn,
    messageColumn,
    { key: "cwd", label: "Working Dir", paths: ["linux.cwd", "process.working_directory"], defaultVisible: false },
    { key: "syscall", label: "Syscall", paths: ["linux.syscall"], defaultVisible: false },
    { key: "file", label: "Path", paths: ["linux.audit_name"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    {
      title: "Audit record",
      fields: [
        { label: "Record type", paths: ["linux.audit_type"] },
        { label: "Executable", paths: ["linux.exe", "process.path"] },
        { label: "Command", paths: ["process.command_line", "linux.command"] },
        { label: "Working directory", paths: ["linux.cwd", "process.working_directory"] },
        { label: "Key", paths: ["linux.audit_key"] },
        { label: "Syscall", paths: ["linux.syscall"] },
        { label: "Path", paths: ["linux.audit_name"] },
        { label: "UID / EUID", paths: ["linux.uid", "linux.euid"] },
      ],
    },
    provenanceSection,
    rawSection,
  ],
};

const FAIL2BAN_ACTIONS: Record<string, string> = {
  found: "Found (failed attempt)",
  ban: "Ban",
  unban: "Unban",
  restore_ban: "Restore ban",
  already_banned: "Already banned",
  ignore: "Ignore",
  jail_started: "Jail started",
  jail_stopped: "Jail stopped",
  jail_configured: "Jail configured",
};

const linuxFail2banProfile: PresentationProfile = {
  id: "linux_fail2ban",
  label: "fail2ban",
  columns: [
    timestampColumn,
    { key: "jail", label: "Jail", paths: ["linux.jail"] },
    { key: "fail2ban_action", label: "Action", paths: ["linux.event_action"], format: (value) => FAIL2BAN_ACTIONS[String(value)] ?? String(value) },
    { key: "source_ip", label: "Address", paths: ["network.source_ip", "linux.source_ip"] },
    severityColumn,
    messageColumn,
    timeQualityColumn,
    hostColumn,
    { key: "component", label: "Component", paths: ["linux.component"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    timeDetail,
    { title: "fail2ban", fields: [{ label: "Jail", paths: ["linux.jail"] }, { label: "Action", paths: ["linux.event_action"], format: (value) => FAIL2BAN_ACTIONS[String(value)] ?? String(value) }, { label: "Address", paths: ["network.source_ip", "linux.source_ip"] }, { label: "Component", paths: ["linux.component"] }] },
    provenanceSection,
    rawSection,
  ],
};

/** The generic text parser's output: the message is the event, so it leads. */
const linuxGenericLogProfile: PresentationProfile = {
  id: "linux_generic_log",
  label: "Text log",
  columns: [
    timestampColumn,
    timeQualityColumn,
    hostColumn,
    { key: "process", label: "Process", paths: ["linux.process", "process.name"] },
    severityColumn,
    { key: "user", label: "User", paths: ["user.name", "linux.username"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    messageColumn,
    pidColumn,
    { key: "log_format", label: "Format", paths: ["linux.log_format"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    timeDetail,
    { title: "Parsed from text", fields: [{ label: "Detected format", paths: ["linux.log_format"] }, { label: "Process", paths: ["linux.process"] }, { label: "PID", paths: ["linux.pid"] }, { label: "User", paths: ["linux.username"] }, { label: "Address", paths: ["linux.source_ip"] }] },
    provenanceSection,
    rawSection,
  ],
};

/** Kubernetes API-server audit events: who did what to which object, from where, and whether it was allowed. */
const linuxK8sAuditProfile: PresentationProfile = {
  id: "linux_k8s_audit",
  label: "Kubernetes audit",
  columns: [
    timestampColumn,
    { key: "user", label: "User", paths: ["user.name", "linux.username"] },
    { key: "verb", label: "Verb", paths: ["linux.k8s_verb"] },
    { key: "resource", label: "Resource", paths: ["linux.k8s_resource"] },
    { key: "subresource", label: "Subresource", paths: ["linux.k8s_subresource"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.k8s_subresource"]))) },
    { key: "namespace", label: "Namespace", paths: ["linux.k8s_namespace"] },
    { key: "object", label: "Name", paths: ["linux.k8s_object"] },
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"] },
    { key: "http_status", label: "Status", paths: ["http.response.status_code", "linux.http_status"] },
    { key: "decision", label: "Decision", paths: ["linux.k8s_decision"] },
    { key: "indicators", label: "Flags", paths: ["linux.suspicious_indicators"] },
    severityColumn,
    messageColumn,
    { key: "groups", label: "Groups", paths: ["linux.k8s_groups"], defaultVisible: false },
    { key: "user_agent", label: "User Agent", paths: ["user_agent.original", "linux.http_user_agent"], defaultVisible: false },
    { key: "impersonated", label: "Impersonated User", paths: ["linux.k8s_impersonated"], defaultVisible: false },
    { key: "request_uri", label: "Request URI", paths: ["url.path", "linux.url_path"], defaultVisible: false },
    { key: "stage", label: "Stage", paths: ["linux.k8s_stage"], defaultVisible: false },
    { key: "audit_id", label: "Audit ID", paths: ["linux.k8s_audit_id"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    {
      title: "Kubernetes request",
      fields: [
        { label: "User", paths: ["user.name", "linux.username"] },
        { label: "Groups", paths: ["linux.k8s_groups"] },
        { label: "Impersonated user", paths: ["linux.k8s_impersonated"] },
        { label: "Verb", paths: ["linux.k8s_verb"] },
        { label: "Resource", paths: ["linux.k8s_resource"] },
        { label: "Subresource", paths: ["linux.k8s_subresource"] },
        { label: "Namespace", paths: ["linux.k8s_namespace"] },
        { label: "Object name", paths: ["linux.k8s_object"] },
        { label: "Request URI", paths: ["url.path", "linux.url_path"] },
        { label: "Status", paths: ["http.response.status_code", "linux.http_status"] },
        { label: "Authorization decision", paths: ["linux.k8s_decision"] },
        { label: "User agent", paths: ["user_agent.original", "linux.http_user_agent"] },
        { label: "Audit ID", paths: ["linux.k8s_audit_id"] },
        { label: "Stage / level", paths: ["linux.k8s_stage", "linux.k8s_level"] },
        { label: "Flags for review", paths: ["linux.suspicious_indicators"] },
      ],
    },
    networkSection,
    provenanceSection,
    rawSection,
  ],
};

/** Container output (Docker and CRI logs). */
const linuxContainerLogProfile: PresentationProfile = {
  id: "linux_container_log",
  label: "Container logs",
  columns: [
    timestampColumn,
    { key: "container", label: "Container", paths: ["linux.container_name", "linux.container_id"] },
    { key: "pod", label: "Pod", paths: ["linux.k8s_pod"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.k8s_pod"]))) },
    { key: "namespace", label: "Namespace", paths: ["linux.k8s_namespace"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.k8s_namespace"]))) },
    { key: "stream", label: "Stream", paths: ["linux.container_stream"] },
    severityColumn,
    messageColumn,
    timeQualityColumn,
    { key: "source_ip", label: "Source IP", paths: ["network.source_ip", "linux.source_ip"], defaultVisible: false },
    { key: "user", label: "User", paths: ["user.name", "linux.username"], defaultVisible: false },
    { key: "container_id", label: "Container ID", paths: ["linux.container_id"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    timeDetail,
    { title: "Container", fields: [{ label: "Container", paths: ["linux.container_name"] }, { label: "Container ID", paths: ["linux.container_id"] }, { label: "Pod", paths: ["linux.k8s_pod"] }, { label: "Namespace", paths: ["linux.k8s_namespace"] }, { label: "Stream", paths: ["linux.container_stream"] }] },
    provenanceSection,
    rawSection,
  ],
};

const CONTAINER_KINDS: Record<string, string> = {
  container_config: "Container",
  container_hostconfig: "Host configuration",
};

/** Container configuration (config.v2.json, hostconfig.json): what a container is and may do. */
const linuxContainerConfigProfile: PresentationProfile = {
  id: "linux_container_config",
  label: "Container configuration",
  columns: [
    { key: "timestamp", label: "Created", paths: ["@timestamp"] },
    { key: "kind", label: "Kind", paths: ["event.type"], format: (value) => CONTAINER_KINDS[String(value)] ?? String(value) },
    { key: "container", label: "Name", paths: ["linux.container_name", "linux.container_id"] },
    { key: "image", label: "Image", paths: ["linux.container_image"] },
    { key: "state", label: "State", paths: ["linux.container_state"] },
    { key: "command", label: "Command", paths: ["linux.container_command"] },
    { key: "indicators", label: "Flags", paths: ["linux.suspicious_indicators"] },
    { key: "privileged", label: "Privileged", paths: ["linux.container_privileged"], format: (value) => (value === true || value === "true" ? "yes" : "no") },
    { key: "network_mode", label: "Network", paths: ["linux.network_mode"] },
    severityColumn,
    messageColumn,
    { key: "mounts", label: "Mounts", paths: ["linux.container_mounts"], defaultVisible: false },
    { key: "env", label: "Environment (names only)", paths: ["linux.container_env_names"], defaultVisible: false },
    { key: "exit_code", label: "Exit Code", paths: ["linux.container_exit_code"], defaultVisible: false },
    { key: "pid_mode", label: "PID Mode", paths: ["linux.pid_mode"], defaultVisible: false },
    { key: "caps", label: "Added Capabilities", paths: ["linux.container_cap_add"], defaultVisible: false },
    { key: "user", label: "Runs As", paths: ["user.name", "linux.username"], defaultVisible: false },
    ...sourceFileColumns,
  ],
  details: [
    eventSection,
    {
      title: "Container configuration",
      fields: [
        { label: "Name", paths: ["linux.container_name"] },
        { label: "Container ID", paths: ["linux.container_id"] },
        { label: "Image", paths: ["linux.container_image"] },
        { label: "State", paths: ["linux.container_state"] },
        { label: "Exit code", paths: ["linux.container_exit_code"] },
        { label: "Command", paths: ["linux.container_command"] },
        { label: "Runs as", paths: ["linux.username", "user.name"] },
        { label: "Privileged", paths: ["linux.container_privileged"], format: (value) => (value === true || value === "true" ? "yes" : "no") },
        { label: "Network mode", paths: ["linux.network_mode"] },
        { label: "PID mode", paths: ["linux.pid_mode"] },
        { label: "Added capabilities", paths: ["linux.container_cap_add"] },
        { label: "Mounts", paths: ["linux.container_mounts"] },
        { label: "Environment variable names (values are never stored)", paths: ["linux.container_env_names"] },
        { label: "Flags for review", paths: ["linux.suspicious_indicators"] },
      ],
    },
    provenanceSection,
    rawSection,
  ],
};

const PERSISTENCE_KINDS: Record<string, string> = {
  ld_so_preload: "Preloaded library",
  ld_so_conf: "Library search path",
  rc_local: "rc.local (boot)",
  pam_config: "PAM rule",
  at_job: "at job",
  shell_init: "Shell start-up",
};

const linuxPersistenceProfile: PresentationProfile = {
  id: "linux_persistence",
  label: "Persistence configuration",
  columns: [
    { key: "kind", label: "Kind", paths: ["event.type", "linux.artifact_type"], format: (value) => PERSISTENCE_KINDS[String(value)] ?? String(value) },
    severityColumn,
    { key: "user", label: "Owner", paths: ["user.name", "linux.username"] },
    { key: "item", label: "Entry / Command", paths: ["linux.library_path", "message", "event.message", "linux.command"] },
    { key: "pam", label: "PAM", paths: ["linux.pam_module"], format: (value, item) => [firstPresent(item, ["linux.pam_type"]), firstPresent(item, ["linux.pam_control"]), value].filter(isPresent).map(String).join(" ") },
    { key: "indicators", label: "Flags", paths: ["linux.suspicious_indicators"] },
    { key: "source_file", label: "Source File", paths: ["source_file", "artifact.source_path", "linux.source_file"] },
    { key: "line_number", label: "Line", paths: ["linux.line_number"] },
    hostColumn,
    { key: "timestamp", label: "Timestamp", paths: ["@timestamp"], defaultVisible: false },
  ],
  details: [
    eventSection,
    {
      title: "Persistence entry",
      fields: [
        { label: "Kind", paths: ["event.type", "linux.artifact_type"], format: (value) => PERSISTENCE_KINDS[String(value)] ?? String(value) },
        { label: "Owner", paths: ["user.name", "linux.username"] },
        { label: "Library", paths: ["linux.library_path"] },
        { label: "Command / line", paths: ["linux.command", "message"] },
        { label: "PAM type", paths: ["linux.pam_type"] },
        { label: "PAM control", paths: ["linux.pam_control"] },
        { label: "PAM module", paths: ["linux.pam_module"] },
        { label: "PAM arguments", paths: ["linux.pam_args"] },
        { label: "Flags for review", paths: ["linux.suspicious_indicators"] },
      ],
    },
    provenanceSection,
    rawSection,
  ],
};

/** The Apache access profile extended in place for what nginx and proxies add. */
const webAccessExtras: PresentationColumn[] = [
  { key: "web_server", label: "Web Server", paths: ["linux.web_server"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.web_server"]))) },
  { key: "xff", label: "Real Client (X-Forwarded-For)", paths: ["linux.x_forwarded_for"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.x_forwarded_for"]))) },
  { key: "http_host", label: "Host Header", paths: ["linux.http_host"], defaultVisible: false },
  { key: "referrer", label: "Referrer", paths: ["http.referrer", "linux.http_referrer"], defaultVisible: false },
];

const webErrorExtras: PresentationColumn[] = [
  { key: "web_server", label: "Web Server", paths: ["linux.web_server"], visibleWhen: (items) => items.some((item) => isPresent(firstPresent(item, ["linux.web_server"]))) },
  { key: "server_name", label: "Server", paths: ["linux.server_name"] },
  { key: "request", label: "Request", paths: ["url.path", "linux.url_path"] },
  { key: "upstream", label: "Upstream", paths: ["linux.upstream"], defaultVisible: false },
  timeQualityColumn,
];

const webDetail: DetailSection = {
  title: "Web server",
  fields: [
    { label: "Server", paths: ["linux.web_server"] },
    { label: "Real client (X-Forwarded-For)", paths: ["linux.x_forwarded_for"] },
    { label: "Host header", paths: ["linux.http_host"] },
    { label: "Server name", paths: ["linux.server_name"] },
    { label: "Upstream", paths: ["linux.upstream"] },
    { label: "Suspicious request markers", paths: ["linux.suspicious_url_indicators"] },
  ],
};

function extendProfile(base: PresentationProfile, extraColumns: PresentationColumn[], extraDetail: DetailSection[], id: string, label: string): PresentationProfile {
  // Extra columns go before the "hidden by default" tail, after the primary ones.
  const firstHidden = base.columns.findIndex((column) => column.defaultVisible === false);
  const at = firstHidden === -1 ? base.columns.length : firstHidden;
  const columns = [...base.columns.slice(0, at), ...extraColumns, ...base.columns.slice(at)];
  const details = [...base.details.slice(0, base.details.length - 2), ...extraDetail, ...base.details.slice(base.details.length - 2)];
  return { id, label, columns, details };
}

const webAccessProfile = extendProfile(apacheAccessProfile, webAccessExtras, [webDetail], "linux_web_access", "Web server access logs");
const webErrorProfile = extendProfile(apacheErrorProfile, webErrorExtras, [webDetail], "linux_web_error", "Web server error logs");

/** Applies each column's data-driven default visibility to the rows on screen. */
function withVisibility(profile: PresentationProfile, items: Record<string, unknown>[]): PresentationProfile {
  if (!profile.columns.some((column) => column.visibleWhen)) return profile;
  return {
    ...profile,
    columns: profile.columns.map((column) => (column.visibleWhen ? { ...column, defaultVisible: column.visibleWhen(items) } : column)),
  };
}

/** Guarantees a message column: whatever else a profile shows, the log's own text stays visible. */
function withMessageColumn(profile: PresentationProfile, visibleByDefault = true): PresentationProfile {
  const hasMessage = profile.columns.some((column) => column.key === "message" || column.key === "summary" || column.paths.some((path) => path === "message" || path === "event.message"));
  if (hasMessage) return profile;
  const firstHidden = profile.columns.findIndex((column) => column.defaultVisible === false);
  const at = firstHidden === -1 ? profile.columns.length : firstHidden;
  const column = visibleByDefault ? messageColumn : { ...messageColumn, defaultVisible: false };
  return { ...profile, columns: [...profile.columns.slice(0, at), column, ...profile.columns.slice(at)] };
}

function isSysmonRow(item: Record<string, unknown>): boolean {
  return isPresent(firstPresent(item, ["linux.sysmon_event_id"]));
}

function isFirewallRow(item: Record<string, unknown>): boolean {
  return isPresent(firstPresent(item, ["linux.firewall_action"]));
}

export function presentationProfileForItems(items: Record<string, unknown>[]): PresentationProfile | null {
  const artifactTypes = new Set(items.map((item) => String(((item.artifact as Record<string, unknown>) ?? {}).type ?? "")).filter(Boolean));
  if (artifactTypes.size !== 1) return null;
  const artifactType = [...artifactTypes][0];
  const eventTypes = new Set(items.map((item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "")).filter(Boolean));
  let profile: PresentationProfile | null = null;
  switch (artifactType) {
    case "linux_exim":
      profile = eximProfile;
      break;
    case "linux_apache":
      profile = eventTypes.size === 1 && eventTypes.has("apache_error") ? webErrorProfile : webAccessProfile;
      break;
    case "linux_syslog": {
      const threshold = Math.max(1, items.length * FIREWALL_PROFILE_SHARE);
      const firewall = items.filter(isFirewallRow).length;
      const sysmon = items.filter(isSysmonRow).length;
      // Packet logs or Sysmon events, whichever dominates once it is a meaningful share of the rows.
      if (sysmon >= threshold && sysmon >= firewall) profile = linuxSysmonProfile;
      else if (firewall >= threshold) profile = linuxFirewallProfile;
      else profile = linuxSyslogProfile;
      break;
    }
    case "linux_journal":
      profile = linuxJournalProfile;
      break;
    case "linux_auth":
      profile = linuxAuthProfile;
      break;
    case "linux_audit":
      profile = linuxAuditProfile;
      break;
    case "linux_fail2ban":
      profile = linuxFail2banProfile;
      break;
    case "linux_generic_log":
      profile = linuxGenericLogProfile;
      break;
    case "linux_persistence":
      profile = linuxPersistenceProfile;
      break;
    case "linux_k8s_audit":
      profile = linuxK8sAuditProfile;
      break;
    case "linux_container":
      // Configuration rows and log lines are different shapes; the logs take over once any are present.
      profile = [...eventTypes].length > 0 && [...eventTypes].every((type) => type in CONTAINER_KINDS) ? linuxContainerConfigProfile : linuxContainerLogProfile;
      break;
    default:
      return null;
  }
  // A web access line's content already sits in the method, request and status columns, so the
  // message is offered but not shown by default there.
  return withVisibility(withMessageColumn(profile, profile.id !== "linux_web_access"), items);
}
