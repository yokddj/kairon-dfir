import type { CaseContextHostSummary, Finding, FindingSeverity, FindingStatus } from "../api/client";
import { artifactLabel as registryArtifactLabel } from "./artifactRegistry";
import { resolveHost } from "../hooks/useHostContext";

export type FindingPrefill = Partial<Finding> & {
  title: string;
  body?: string | null;
  severity: FindingSeverity;
  status: FindingStatus;
  tags?: string[];
};

type PrefillContext = {
  caseId?: string;
  evidenceId?: string | null;
  hostId?: string | null;
  hosts?: CaseContextHostSummary[];
  sourceView: string;
  sourceRoute?: string;
  artifactFamily?: string | null;
  artifactType?: string | null;
  label?: string;
};

const SECRET_KEYS = /token|secret|password|credential|authorization|cookie|apikey|api_key/i;
const ALLOWED_FIELD_KEYS = ["url", "path", "command_line", "command", "process", "process_name", "pid", "user", "host", "domain", "ip", "file_name", "hash", "registry_key", "registry_path", "event_id", "source_file", "address", "range", "plugin"];
const MAX_STRING = 500;

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function asString(value: unknown): string {
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function pickPath(row: Record<string, unknown>, path: string): unknown {
  return path.split(".").reduce<unknown>((current, part) => asRecord(current)[part], row);
}

function firstString(row: Record<string, unknown>, paths: string[]): string {
  for (const path of paths) {
    const value = asString(pickPath(row, path));
    if (value) return value;
  }
  return "";
}

function cleanString(value: unknown): string | undefined {
  const text = asString(value).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (!text) return undefined;
  return text.length > MAX_STRING ? `${text.slice(0, MAX_STRING)}...` : text;
}

function artifactLabel(family?: string | null, type?: string | null): string {
  return registryArtifactLabel(type || family || "source item");
}

function inferTitle(row: Record<string, unknown>, family: string, type: string, summary: string): string {
  const command = firstString(row, ["process.command_line", "powershell.command", "display_command"]);
  const url = firstString(row, ["url.full", "browser.url", "download.url", "url"]);
  const process = firstString(row, ["process.name", "process_name", "name"]);
  const registry = firstString(row, ["registry.path", "registry.key"]);
  if (/powershell/i.test(command || process || type)) return "Suspicious PowerShell command";
  if (/download|browser|url|motw/i.test(family || type) && url) return "Potential malware download";
  if (/registry|runmru|autorun|startup|persistence|service|scheduled/i.test(family || type || registry)) return "Interesting registry modification";
  if (process || /process|prefetch|amcache|shimcache/i.test(family || type)) return "Suspicious process execution";
  if (/network|dns|socket|wlan/i.test(family || type)) return "Network indicator observed";
  return summary ? `Finding from ${artifactLabel(family, type)}` : "Finding from source item";
}

function buildFields(row: Record<string, unknown>): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const key of ALLOWED_FIELD_KEYS) {
    const candidates = [key, key.replace("_", "."), `process.${key}`, `file.${key}`, `url.${key}`, `registry.${key}`, `network.${key}`, `dns.${key}`, `browser.${key}`, `memory.${key}`];
    const value = firstString(row, candidates);
    if (value && !SECRET_KEYS.test(key)) fields[key] = cleanString(value) || value.slice(0, MAX_STRING);
  }
  return fields;
}

export function buildFindingPrefillFromArtifact(rowInput: unknown, context: PrefillContext): FindingPrefill {
  const row = asRecord(rowInput);
  const artifact = asRecord(row.artifact);
  const host = asRecord(row.host);
  const family = asString(context.artifactFamily || artifact.family || artifact.type || row.artifact_family || row.family);
  const type = asString(context.artifactType || artifact.type || row.artifact_type || row.type);
  const timestamp = firstString(row, ["@timestamp", "timestamp", "time", "created_at", "create_time", "first_seen"]);
  const evidenceId = asString(context.evidenceId || row.evidence_id || asRecord(row.evidence).id);
  const eventId = firstString(row, ["event_id", "source_event_id", "search_doc_id", "id"]);
  const artifactId = firstString(row, ["artifact_id", "document_id"]);
  const hostName = firstString(row, ["host.name", "host.hostname", "hostname", "detected_host"]);
  // context.hostId only reflects a filter the analyst happens to have active
  // right now (e.g. Artifact Explorer scoped to "all hosts") -- when it's
  // missing, resolve the item's own host name against the case's host list
  // so the finding still links to the right host instead of silently
  // dropping the association and becoming unfindable by host filter later.
  const hostId = asString(context.hostId || row.host_id || host.id) || (context.hosts ? resolveHost(context.hosts, null, hostName)?.id ?? "" : "");
  const evidenceName = firstString(row, ["evidence.filename", "evidence_name", "source_file"]);
  const summary = firstString(row, ["summary", "display_summary", "message", "event.message", "title", "command_or_target", "path", "process.command_line", "url.full", "browser.url"]);
  const title = inferTitle(row, family, type, summary);
  const tags = Array.from(new Set([context.sourceView, family, type, /powershell/i.test(summary) ? "powershell" : "", /download|url/i.test(summary) ? "download" : ""].filter(Boolean).map((item) => item.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, ""))));
  const fields = buildFields(row);
  const snapshot = {
    timestamp: timestamp || undefined,
    family: family || undefined,
    type: type || undefined,
    host: hostName || undefined,
    evidence: evidenceName || evidenceId || undefined,
    summary: cleanString(summary || title),
    fields,
  };
  return {
    title,
    body: summary ? `Created from ${context.label || artifactLabel(family, type)}.\n\n${summary}` : `Created from ${context.label || artifactLabel(family, type)}. Review the preserved source snapshot for context.`,
    severity: "medium",
    status: "draft",
    tags,
    related_hosts: hostName ? [hostName] : [],
    linked_evidence_id: evidenceId || null,
    linked_host_id: hostId || null,
    linked_artifact_id: artifactId || null,
    linked_artifact_family: family || null,
    linked_artifact_type: type || null,
    linked_event_id: eventId || null,
    event_ids: eventId ? [eventId] : [],
    source_view: context.sourceView,
    source_route: context.sourceRoute || window.location.pathname + window.location.search,
    source_timestamp: timestamp || null,
    source_label: context.label || artifactLabel(family, type),
    source_summary: cleanString(summary || title) || title,
    source_snapshot_json: snapshot,
  };
}
