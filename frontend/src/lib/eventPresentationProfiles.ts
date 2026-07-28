export type PresentationColumn = {
  key: string;
  label: string;
  paths: string[];
  defaultVisible?: boolean;
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

export function presentationProfileForItems(items: Record<string, unknown>[]): PresentationProfile | null {
  const artifactTypes = new Set(items.map((item) => String(((item.artifact as Record<string, unknown>) ?? {}).type ?? "")).filter(Boolean));
  if (artifactTypes.size !== 1) return null;
  const artifactType = [...artifactTypes][0];
  if (artifactType === "linux_exim") return eximProfile;
  if (artifactType === "linux_apache") {
    const eventTypes = new Set(items.map((item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "")).filter(Boolean));
    if (eventTypes.size === 1 && eventTypes.has("apache_error")) return apacheErrorProfile;
    return apacheAccessProfile;
  }
  return null;
}
