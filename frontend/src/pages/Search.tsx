import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type EventContextResponse, type EventMarking, type EventMarkingStatus, type SearchQuickFilter, type SearchV2Response, type SearchV2Result } from "../api/client";
import ResponsiveDetailPanel, { useMinWidthQuery } from "../components/ResponsiveDetailPanel";
import SearchBar from "../components/SearchBar";
import { useActiveCase } from "../context/ActiveCaseContext";
import { copyToClipboard, formatTimestamp } from "../lib/time";

type Scope = "events" | "findings" | "all";
type SortValue = "timestamp_desc" | "timestamp_asc" | "risk_desc" | "risk_asc" | "relevance";
type SourceCategory = "" | "Memory" | "Disk" | "Event Log" | "Registry" | "Browser" | "Other";
type SearchTab = "results" | "timeline" | "findings" | "artifact_views";
type ArtifactViewMode = "auto" | "process" | "dns" | "downloads" | "defender" | "persistence" | "files" | "cloud_usb" | "generic";
type TableDensity = "compact" | "comfortable" | "expanded";
type FilterOperator = "is" | "is not" | "contains" | "does not contain" | "exists" | "does not exist" | "starts with";
type BuilderCondition = {
  field: string;
  operator: FilterOperator;
  value: string;
  negate?: boolean;
};
type EntitySummary = {
  keyEntity: string;
  primaryPath: string;
  primaryDomain: string;
  primaryIp: string;
  primaryProcess: string;
  primaryUser: string;
  primaryHost: string;
  compactMessage: string;
};

type RowAction = {
  label: string;
  onClick: () => void;
  ariaLabel?: string;
  disabled?: boolean;
  value?: string;
};
type PivotConfig = {
  label: string;
  field: string;
  value: unknown;
  operator?: FilterOperator;
  display?: ReactNode;
  className?: string;
};
type PivotRenderer = (config: PivotConfig) => ReactNode;

const scopeOptions: Scope[] = ["all", "events", "findings"];
const sortOptions: SortValue[] = ["timestamp_desc", "timestamp_asc", "risk_desc", "risk_asc", "relevance"];
const severityOptions = ["critical", "high", "medium", "low", "info"];
const findingStatusOptions = ["new", "reviewed", "confirmed", "dismissed"];
const eventMarkingStatusOptions: EventMarkingStatus[] = ["suspicious", "important", "reviewed", "false_positive"];
const SEARCH_UI_MAX_PAGE_SIZE = 500;
const pageSizeOptions = [50, 100, 250, 500];
const sourceCategoryOptions: Array<{ value: SourceCategory; label: string }> = [
  { value: "", label: "All sources" },
  { value: "Memory", label: "Memory" },
  { value: "Disk", label: "Disk" },
  { value: "Event Log", label: "Event Log" },
  { value: "Registry", label: "Registry" },
  { value: "Browser", label: "Browser" },
  { value: "Other", label: "Other" },
];
const riskPresets = [
  { label: "Low", min: "0", max: "29" },
  { label: "Medium", min: "30", max: "49" },
  { label: "High", min: "50", max: "74" },
  { label: "Critical", min: "75", max: "100" },
];
const filterFieldOptions: Array<{ value: string; label: string }> = [
  { value: "artifact.type", label: "Artifact type" },
  { value: "artifact.parser", label: "Parser" },
  { value: "source_file", label: "Source file" },
  { value: "host.name", label: "Host" },
  { value: "user.name", label: "User" },
  { value: "message", label: "Message / text" },
  { value: "event.type", label: "Event type" },
  { value: "event.action", label: "Event action" },
  { value: "event.id", label: "Event ID" },
  { value: "windows.event_id", label: "Windows event ID" },
  { value: "process.name", label: "Process name" },
  { value: "process.pid", label: "Process PID" },
  { value: "process.entity_id", label: "Process entity ID" },
  { value: "process.command_line", label: "Command line" },
  { value: "parent.process.name", label: "Parent process" },
  { value: "parent.process.pid", label: "Parent process PID" },
  { value: "parent.process.command_line", label: "Parent command line" },
  { value: "event.provider", label: "Event provider" },
  { value: "event.channel", label: "Event channel" },
  { value: "source.ip", label: "Source IP" },
  { value: "destination.ip", label: "Destination IP" },
  { value: "object.name", label: "Object name" },
  { value: "object.path", label: "Object path" },
  { value: "file.path", label: "File path" },
  { value: "dns.question.name", label: "DNS query" },
  { value: "registry.key", label: "Registry key" },
  { value: "registry.path", label: "Registry path" },
  { value: "url.full", label: "URL" },
  { value: "url.domain", label: "Domain" },
];
const filterOperators: FilterOperator[] = ["is", "is not", "contains", "does not contain", "exists", "does not exist", "starts with"];
const noValueOperators = new Set<FilterOperator>(["exists", "does not exist"]);
const searchTabs: Array<{ id: SearchTab; label: string }> = [
  { id: "results", label: "Results" },
  { id: "timeline", label: "Search Timeline" },
  { id: "findings", label: "Findings" },
  { id: "artifact_views", label: "Artifact Views" },
];

function useDebouncedValue<T>(value: T, delayMs: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(handle);
  }, [delayMs, value]);
  return debounced;
}

function splitParam(value: string | null) {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinParam(values: string[]) {
  return values.filter(Boolean).join(",");
}

function parseBuilderFilters(value: string | null): BuilderCondition[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item) => {
        const record = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
        return {
          field: String(record.field ?? ""),
          operator: (String(record.operator ?? "is") as FilterOperator),
          value: String(record.value ?? ""),
          negate: Boolean(record.negate),
        };
      })
      .filter((item) => filterFieldOptions.some((field) => field.value === item.field) && filterOperators.includes(item.operator));
  } catch {
    return [];
  }
}

function serializeBuilderFilters(filters: BuilderCondition[]) {
  const cleaned = filters
    .map((item) => ({
      field: item.field,
      operator: item.operator,
      value: noValueOperators.has(item.operator) ? "" : item.value.trim(),
      negate: Boolean(item.negate),
    }))
    .filter((item) => item.field && item.operator && (noValueOperators.has(item.operator) || item.value));
  return cleaned.length ? JSON.stringify(cleaned) : "";
}

function filterFieldLabel(field: string) {
  return filterFieldOptions.find((item) => item.value === field)?.label ?? field;
}

function filterConditionLabel(condition: BuilderCondition) {
  const negated = condition.negate || condition.operator === "is not" || condition.operator === "does not contain" || condition.operator === "does not exist";
  const operator = condition.operator.replace("is not", "is").replace("does not contain", "contains").replace("does not exist", "exists");
  const value = noValueOperators.has(condition.operator) ? "" : ` ${condition.value}`;
  return `${negated ? "NOT " : ""}${filterFieldLabel(condition.field)} ${operator}${value}`;
}

function buildState(searchParams: URLSearchParams) {
  const rawPageSize = Number(searchParams.get("page_size") ?? "50") || 50;
  const clampedPageSize = Math.min(rawPageSize, SEARCH_UI_MAX_PAGE_SIZE);
  const rawSort = searchParams.get("sort");
  const order = searchParams.get("order");
  const sort =
    rawSort === "@timestamp" || rawSort === "timestamp"
      ? order === "asc"
        ? "timestamp_asc"
        : "timestamp_desc"
      : ((rawSort as SortValue | null) ?? "timestamp_desc");
  return {
    q: searchParams.get("q") ?? "",
    exclude_q: searchParams.get("exclude_q") ?? "",
    filters: parseBuilderFilters(searchParams.get("filters")),
    scope: (searchParams.get("scope") as Scope | null) ?? "all",
    tab: ((searchParams.get("view") ?? searchParams.get("tab")) as SearchTab | null) ?? "results",
    sort,
    order: order ?? "",
    page: Number(searchParams.get("page") ?? "1") || 1,
    page_size: clampedPageSize,
    page_size_requested: rawPageSize,
    selected: searchParams.get("selected") ?? "",
    artifact_type: splitParam(searchParams.get("artifact_type")),
    parser: splitParam(searchParams.get("parser")),
    backend_variant: splitParam(searchParams.get("backend_variant")),
    parser_backend: splitParam(searchParams.get("parser_backend")),
    exclude_artifact_type: splitParam(searchParams.get("exclude_artifact_type")),
    exclude_parser: splitParam(searchParams.get("exclude_parser")),
    event_type: splitParam(searchParams.get("event_type")),
    event_category: splitParam(searchParams.get("event_category")),
    severity: splitParam(searchParams.get("severity")),
    status: splitParam(searchParams.get("status")),
    confidence: splitParam(searchParams.get("confidence")),
    host: searchParams.get("host") ?? "",
    user: searchParams.get("user") ?? "",
    exclude_host: searchParams.get("exclude_host") ?? "",
    exclude_user: searchParams.get("exclude_user") ?? "",
    process_name: searchParams.get("process_name") ?? "",
    source_file: searchParams.get("source_file") ?? "",
    exclude_source_file: searchParams.get("exclude_source_file") ?? "",
    file_name: searchParams.get("file_name") ?? "",
    file_path: searchParams.get("file_path") ?? "",
    domain: searchParams.get("domain") ?? "",
    ip: searchParams.get("ip") ?? "",
    hash: searchParams.get("hash") ?? "",
    url: searchParams.get("url") ?? "",
    risk_min: searchParams.get("risk_min") ?? "",
    risk_max: searchParams.get("risk_max") ?? "",
    marked_only: searchParams.get("marked_only") ?? "",
    marking_status: searchParams.get("marking_status") ?? "",
    marked_has_note: searchParams.get("marked_has_note") ?? "",
    marked_in_finding: searchParams.get("marked_in_finding") ?? "",
    include_filesystem_timeline: searchParams.get("include_filesystem_timeline") ?? "",
    evidence_id: searchParams.get("evidence_id") ?? "",
    source_category: (searchParams.get("source_category") ?? searchParams.get("source") ?? "") as SourceCategory,
    time_from: searchParams.get("time_from") ?? "",
    time_to: searchParams.get("time_to") ?? "",
  };
}

function ResultBadge({ children, tone = "default" }: { children: string; tone?: "default" | "critical" | "high" | "medium" | "muted" | "success" }) {
  const classes =
    tone === "critical"
      ? "border-danger/60 bg-danger/15 text-danger"
      : tone === "high"
        ? "border-warning/60 bg-warning/15 text-warning"
        : tone === "medium"
          ? "border-amber-400/50 bg-amber-400/10 text-amber-200"
          : tone === "muted"
            ? "border-line bg-white/5 text-muted"
            : tone === "success"
              ? "border-emerald-400/50 bg-emerald-400/10 text-emerald-200"
              : "border-accent/40 bg-accent/10 text-accent";
  return <span className={`rounded-full border px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${classes}`}>{children}</span>;
}

function resultSourceCategory(result: SearchV2Result): string {
  const raw = asRecord(result.raw);
  return asString(result.source_category) || asString(raw.source_category) || (result.kind === "finding" ? "Other" : "Disk");
}

function resultSourceProducer(result: SearchV2Result): string {
  const raw = asRecord(result.raw);
  return asString(result.source_plugin_or_parser) || asString(raw.source_plugin_or_parser) || asString(result.parser) || asString(asRecord(raw.artifact).parser) || "unknown";
}

function SourceBadge({ result }: { result: SearchV2Result }) {
  const category = resultSourceCategory(result);
  const producer = resultSourceProducer(result);
  return <ResultBadge tone={category === "Memory" ? "success" : "muted"}>{producer && producer !== "unknown" ? `${category}: ${producer}` : category}</ResultBadge>;
}

function InfoCard({ label, value, children }: { label: string; value?: string; children?: ReactNode }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <div className="mt-2 break-words text-white">{children ?? value}</div>
    </div>
  );
}

function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
        <option value="">Any</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function formatFacetOption(option: string, counts: Record<string, number> | undefined) {
  const count = counts?.[option];
  return typeof count === "number" ? `${option} (${count})` : option;
}

function TextField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
    </label>
  );
}

function NumberField({ label, value, onChange, min = 0, max = 100 }: { label: string; value: string; onChange: (value: string) => void; min?: number; max?: number }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input aria-label={label} type="number" min={min} max={max} value={value} onChange={(event) => onChange(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
    </label>
  );
}

function toDateTimeLocalValue(value: string) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const local = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function fromDateTimeLocalValue(value: string) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toISOString();
}

function TimeField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input
        aria-label={label}
        type="datetime-local"
        value={toDateTimeLocalValue(value)}
        onChange={(event) => onChange(fromDateTimeLocalValue(event.target.value))}
        className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
      />
    </label>
  );
}

function severityTone(value: string | null | undefined) {
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  return "muted";
}

function riskTone(score: number | null | undefined) {
  if ((score ?? 0) >= 90) return "critical";
  if ((score ?? 0) >= 70) return "high";
  if ((score ?? 0) >= 40) return "medium";
  return "muted";
}

function markingTone(status: string | null | undefined): "default" | "critical" | "high" | "medium" | "muted" | "success" {
  if (status === "suspicious") return "high";
  if (status === "important") return "medium";
  if (status === "false_positive") return "muted";
  if (status === "reviewed") return "success";
  return "default";
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asString(value: unknown) {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function looksPreTruncated(value: string) {
  return value.includes("...") || value.includes("…");
}

function messageLabel(value: string, fallback: string) {
  const [prefix] = value.split(":");
  return prefix && prefix.length < value.length ? prefix.trim() : fallback;
}

function getResultMarking(result: SearchV2Result): EventMarking | null {
  const rawMarking = asRecord(asRecord(result.raw).marking);
  const marking = result.marking ?? (rawMarking.status ? (rawMarking as EventMarking) : null);
  return marking?.status ? marking : null;
}

function markingLabel(status: string | null | undefined) {
  if (!status) return "";
  if (status === "false_positive") return "False positive";
  return humanizeToken(status);
}

function MarkingBadge({ marking }: { marking: EventMarking | null }) {
  if (!marking?.status) return null;
  return <ResultBadge tone={markingTone(marking.status)}>{markingLabel(marking.status)}</ResultBadge>;
}

function summarizeResult(result: SearchV2Result): EntitySummary {
  const raw = asRecord(result.raw);
  const file = asRecord(raw.file);
  const process = asRecord(raw.process);
  const dns = asRecord(raw.dns);
  const url = asRecord(raw.url);
  const download = asRecord(raw.download);
  const cloud = asRecord(raw.cloud);
  const object = asRecord(raw.object);
  const host = asRecord(raw.host);
  const user = asRecord(raw.user);
  const event = asRecord(raw.event);
  const filePath = asString(file.path || download.target_path || cloud.local_path || object.path || object.name);
  const domain = asString(dns.domain || dns.query || asRecord(dns.question).name || url.domain || url.full || download.url);
  const ip = asString(dns.ip || asRecord(raw.network).destination_ip || asRecord(raw.network).source_ip);
  const processName = asString(process.name || process.path);
  const processCommandLine = asString(process.command_line);
  const registryPath = asString(asRecord(raw.registry).path);
  const dnsQuery = asString(dns.query || asRecord(dns.question).name);
  const fullEntity = filePath || registryPath || processCommandLine || dnsQuery || domain || ip || processName || asString(result.host) || asString(result.user);
  const keyEntity = fullEntity;
  const rawCompactMessage = asString(result.summary || event.message || result.title);
  const label = messageLabel(rawCompactMessage, humanizeToken(asString(result.event_type || asRecord(raw.event).action || asRecord(raw.event).type || result.title || "Event")));
  const compactMessage = looksPreTruncated(rawCompactMessage) && fullEntity ? `${label}: ${fullEntity}` : rawCompactMessage;
  return {
    keyEntity,
    primaryPath: filePath,
    primaryDomain: domain,
    primaryIp: ip,
    primaryProcess: processName,
    primaryUser: asString(result.user || user.name),
    primaryHost: asString(result.host || host.name),
    compactMessage,
  };
}

function topCounts(values: string[], limit = 4) {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = value.trim() || "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

function buildGroupedSearchSummary(results: SearchV2Result[], query: string, total: number | undefined) {
  const normalized = query.trim().toLowerCase();
  const broadTerms = ["admin-user", "filezilla", "validation-sample"];
  const shouldGroup = Boolean(normalized && (broadTerms.some((term) => normalized.includes(term)) || (total ?? 0) >= 100));
  if (!shouldGroup || !results.length) return null;
  return {
    hosts: topCounts(results.map((item) => {
      const host = asRecord(asRecord(item.raw).host);
      return asString(item.host || host.name || host.hostname);
    })),
    artifacts: topCounts(results.map((item) => asString(item.artifact_type || asRecord(asRecord(item.raw).artifact).type))),
    sourceFiles: topCounts(results.map((item) => fullSourceFile(item)).filter((item) => item && item !== "-"), 3),
  };
}

function deduceArtifactView(results: SearchV2Result[], preferredArtifactTypes: string[]): ArtifactViewMode {
  const artifactHint = preferredArtifactTypes[0]?.toLowerCase() ?? "";
  if (artifactHint.includes("dns")) return "dns";
  if (artifactHint.includes("process") || artifactHint.includes("powershell")) return "process";
  if (artifactHint.includes("browser") || artifactHint.includes("bits")) return "downloads";
  if (artifactHint.includes("defender") || artifactHint.includes("detection")) return "defender";
  if (artifactHint.includes("autorun") || artifactHint.includes("scheduled_task") || artifactHint.includes("service") || artifactHint.includes("wmi")) return "persistence";
  if (artifactHint.includes("mft") || artifactHint.includes("recycle") || artifactHint.includes("filesystem")) return "files";
  if (artifactHint.includes("cloud") || artifactHint.includes("usb")) return "cloud_usb";

  const sample = results.find((item) => item.kind === "event");
  const raw = asRecord(sample?.raw);
  if (raw.dns) return "dns";
  if (raw.process) return "process";
  if (raw.download || raw.bits || raw.browser) return "downloads";
  if (raw.defender) return "defender";
  if (raw.autoruns || raw.persistence || raw.scheduled_task || raw.service || raw.wmi) return "persistence";
  if (raw.file || raw.mft || raw.recycle) return "files";
  if (raw.cloud || raw.usb) return "cloud_usb";
  return "generic";
}

function applyCellFallbacks(...values: unknown[]) {
  for (const value of values) {
    const text = asString(value).trim();
    if (text) return text;
  }
  return "-";
}

function fullSourceFile(result: SearchV2Result) {
  const raw = asRecord(result.raw);
  const artifact = asRecord(raw.artifact);
  const source = asRecord(raw.source);
  return applyCellFallbacks(
    !looksPreTruncated(asString(result.source_file)) ? result.source_file : "",
    raw.source_file,
    artifact.source_file,
    artifact.source_path,
    source.file,
    source.path,
    result.source_file,
  );
}

function humanizeToken(value: string | null | undefined) {
  const text = asString(value).trim();
  if (!text) return "-";
  return text
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
}

function artifactLabel(value: string | null | undefined) {
  const normalized = asString(value).trim().toLowerCase();
  if (!normalized) return "-";
  if (normalized === "user_activity") return "User Activity";
  if (normalized === "email") return "Email";
  if (normalized === "ntfs") return "NTFS";
  if (normalized === "windows_ui") return "Windows UI";
  if (normalized === "cloud_sync") return "Cloud Sync";
  if (normalized === "recycle_bin") return "Recycle Bin";
  return humanizeToken(normalized);
}

function renderActions(actions: RowAction[]) {
  return (
    <div className="flex flex-wrap gap-2">
      {actions.map((action) => (
        <button key={action.label} type="button" aria-label={action.ariaLabel ?? action.label} disabled={action.disabled} onClick={action.onClick} className="rounded-xl border border-line px-3 py-2 text-xs text-muted disabled:cursor-not-allowed disabled:opacity-45">
          {action.label}
        </button>
      ))}
    </div>
  );
}

function parseSearchError(error: unknown): { message: string; examples: string[]; inline: boolean } | null {
  if (!(error instanceof Error) || !error.message) return null;
  try {
    const parsed = JSON.parse(error.message) as { error?: string; message?: string; examples?: string[] };
    return {
      message: parsed.message || parsed.error || error.message,
      examples: Array.isArray(parsed.examples) ? parsed.examples : [],
      inline: true,
    };
  } catch {
    return {
      message: error.message,
      examples: [],
      inline: false,
    };
  }
}

function ActionMenu({ actions, resultId }: { actions: RowAction[]; resultId: string }) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function handleClickOutside() {
      setOpen(false);
    }
    if (!open) return;
    window.addEventListener("click", handleClickOutside);
    return () => window.removeEventListener("click", handleClickOutside);
  }, [open]);

  return (
    <div className="relative" data-testid={`search-actions-menu-${resultId}`}>
      <button
        type="button"
        aria-label="Actions"
        onClick={(event) => {
          event.stopPropagation();
          setOpen((current) => !current);
        }}
        className="rounded-xl border border-line px-3 py-2 text-xs text-muted"
      >
        Actions
      </button>
      {open ? (
        <div className="absolute right-0 z-20 mt-2 min-w-52 rounded-2xl border border-line bg-abyss/95 p-2 shadow-2xl" onClick={(event) => event.stopPropagation()}>
          <div className="space-y-1">
            {actions.map((action) => (
              <button
                key={action.label}
                type="button"
                aria-label={action.ariaLabel ?? action.label}
                disabled={action.disabled}
                onClick={() => {
                  if (action.disabled) return;
                  setOpen(false);
                  action.onClick();
                }}
                className="block w-full rounded-xl px-3 py-2 text-left text-xs text-muted hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-45"
              >
                {action.label}
              </button>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function PivotValue({
  label,
  field,
  value,
  operator = "is",
  display,
  className = "",
  onApply,
}: PivotConfig & { onApply: (condition: BuilderCondition) => void }) {
  const [open, setOpen] = useState(false);
  const text = asString(value).trim();
  const isUsable = Boolean(text && text !== "-");

  useEffect(() => {
    function handleClickOutside() {
      setOpen(false);
    }
    if (!open) return;
    window.addEventListener("click", handleClickOutside);
    return () => window.removeEventListener("click", handleClickOutside);
  }, [open]);

  if (!isUsable) {
    return <span className={className}>{display ?? "-"}</span>;
  }

  return (
    <span className="relative block min-w-0 align-top" onClick={(event) => event.stopPropagation()}>
      <button
        type="button"
        aria-label={`Pivot ${label}`}
        title={text}
        onClick={(event) => {
          event.stopPropagation();
          setOpen((current) => !current);
        }}
        className={`min-w-0 text-left text-slate-100 underline decoration-accent/30 decoration-dotted underline-offset-4 hover:text-accent ${className}`}
      >
        {display ?? text}
      </button>
      {open ? (
        <span className="absolute left-0 z-30 mt-2 block min-w-56 rounded-2xl border border-line bg-abyss/95 p-2 text-xs shadow-2xl" onClick={(event) => event.stopPropagation()}>
          <button
            type="button"
            aria-label={`Filter by ${label}`}
            onClick={() => {
              setOpen(false);
              onApply({ field, operator, value: text, negate: false });
            }}
            className="block w-full rounded-xl px-3 py-2 text-left text-muted hover:bg-white/5"
          >
            Filter by this
          </button>
          <button
            type="button"
            aria-label={`Exclude ${label}`}
            onClick={() => {
              setOpen(false);
              onApply({ field, operator, value: text, negate: true });
            }}
            className="block w-full rounded-xl px-3 py-2 text-left text-warning hover:bg-warning/10"
          >
            Exclude this
          </button>
          <button
            type="button"
            aria-label={`Copy ${label}`}
            onClick={() => {
              setOpen(false);
              void copyToClipboard(text);
            }}
            className="block w-full rounded-xl px-3 py-2 text-left text-muted hover:bg-white/5"
          >
            Copy value
          </button>
        </span>
      ) : null}
    </span>
  );
}

type ColumnDef = {
  key: string;
  label: string;
  render: (result: SearchV2Result, summary: EntitySummary, pivot: PivotRenderer, density: TableDensity) => ReactNode;
  defaultWidth?: number;
  minWidth?: number;
};

function cellTextClass(density: TableDensity) {
  if (density === "expanded") return "block w-full max-w-none whitespace-pre-wrap break-words";
  if (density === "comfortable") return "block w-full max-w-none overflow-hidden whitespace-normal break-words [display:-webkit-box] [-webkit-box-orient:vertical] [-webkit-line-clamp:2]";
  return "block w-full max-w-none overflow-hidden text-ellipsis whitespace-nowrap";
}

function TruncatedCell({ value, density }: { value: unknown; density: TableDensity }) {
  const display = applyCellFallbacks(value);
  return (
    <span className={cellTextClass(density)} title={display === "-" ? "" : display}>
      {display}
    </span>
  );
}

function genericColumns(): ColumnDef[] {
  return [
    { key: "timestamp", label: "Timestamp", defaultWidth: 180, minWidth: 140, render: (result, _summary, _pivot, density) => <TruncatedCell value={formatTimestamp(result.timestamp, "UTC")} density={density} /> },
    { key: "artifact", label: "Artifact", defaultWidth: 135, minWidth: 110, render: (result, _summary, pivot, density) => pivot({ label: "artifact type", field: "artifact.type", value: result.artifact_type, display: artifactLabel(result.artifact_type), className: cellTextClass(density) }) },
    { key: "source", label: "Source", defaultWidth: 190, minWidth: 130, render: (result) => <SourceBadge result={result} /> },
    { key: "parser", label: "Parser", defaultWidth: 170, minWidth: 120, render: (result, _summary, pivot, density) => pivot({ label: "parser", field: "artifact.parser", value: applyCellFallbacks(result.parser, asString(asRecord(result.raw).artifact && asRecord(asRecord(result.raw).artifact).parser)), className: cellTextClass(density) }) },
    { key: "source_file", label: "Source file", defaultWidth: 260, minWidth: 150, render: (result, _summary, pivot, density) => pivot({ label: "source file", field: "source_file", value: fullSourceFile(result), operator: "contains", className: cellTextClass(density) }) },
    { key: "type", label: "Event Type / Finding Type", defaultWidth: 180, minWidth: 130, render: (result, _summary, pivot, density) => pivot({ label: "event type", field: "event.type", value: result.event_type, display: applyCellFallbacks(result.event_type), className: cellTextClass(density) }) },
    { key: "host", label: "Host", defaultWidth: 145, minWidth: 110, render: (_result, summary, pivot, density) => pivot({ label: "host", field: "host.name", value: summary.primaryHost, className: cellTextClass(density) }) },
    { key: "user", label: "User", defaultWidth: 150, minWidth: 110, render: (_result, summary, pivot, density) => pivot({ label: "user", field: "user.name", value: summary.primaryUser, className: cellTextClass(density) }) },
    { key: "entity", label: "Key Entity", defaultWidth: 250, minWidth: 150, render: (_result, summary, pivot, density) => pivot({ label: "key entity", field: "message", value: summary.keyEntity, operator: "contains", className: cellTextClass(density) }) },
    { key: "message", label: "Snippet", defaultWidth: 320, minWidth: 180, render: (_result, summary, _pivot, density) => <span data-testid="search-snippet-cell" className={cellTextClass(density)} title={summary.compactMessage}>{applyCellFallbacks(summary.compactMessage)}</span> },
    { key: "risk", label: "Risk", defaultWidth: 95, minWidth: 80, render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
    { key: "review", label: "Review", defaultWidth: 130, minWidth: 100, render: (result) => <MarkingBadge marking={getResultMarking(result)} /> },
  ];
}

function specializedColumns(view: ArtifactViewMode): ColumnDef[] {
  const timestamp = { key: "timestamp", label: "Timestamp", render: (result: SearchV2Result, _summary: EntitySummary, _pivot: PivotRenderer, density: TableDensity) => <TruncatedCell value={formatTimestamp(result.timestamp, "UTC")} density={density} /> };
  switch (view) {
    case "process":
      return [
        timestamp,
        { key: "parent", label: "Parent", render: (result, _summary, _pivot, density) => <TruncatedCell value={applyCellFallbacks(asRecord(asRecord(result.raw).process).parent_name, asRecord(asRecord(result.raw).process).parent_command_line)} density={density} /> },
        { key: "process", label: "Process", render: (result, _summary, _pivot, density) => <TruncatedCell value={applyCellFallbacks(asRecord(asRecord(result.raw).process).name, asRecord(asRecord(result.raw).process).path)} density={density} /> },
        { key: "command_line", label: "Command Line", render: (result, _summary, _pivot, density) => <span className={cellTextClass(density)} title={asString(asRecord(asRecord(result.raw).process).command_line)}>{applyCellFallbacks(asRecord(asRecord(result.raw).process).command_line)}</span> },
        { key: "user", label: "User", render: (_result, summary, _pivot, density) => <TruncatedCell value={summary.primaryUser} density={density} /> },
        { key: "host", label: "Host", render: (_result, summary, _pivot, density) => <TruncatedCell value={summary.primaryHost} density={density} /> },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "dns":
      return [
        timestamp,
        { key: "domain", label: "Domain", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).dns).domain) },
        { key: "record_type", label: "Record Type", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).dns).record_type) },
        { key: "data", label: "IP / Data", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).dns).ip, asRecord(asRecord(result.raw).dns).answer) },
        { key: "status", label: "Status", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).dns).status, result.severity) },
        { key: "process", label: "Process", render: (_result, summary) => applyCellFallbacks(summary.primaryProcess) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "downloads":
      return [
        timestamp,
        { key: "source", label: "Source", render: (result) => artifactLabel(result.artifact_type) },
        { key: "url", label: "URL", render: (result, _summary, _pivot, density) => <span className={cellTextClass(density)} title={asString(asRecord(asRecord(result.raw).download).url || asRecord(asRecord(result.raw).browser).url || asRecord(asRecord(result.raw).bits).remote_url)}>{applyCellFallbacks(asRecord(asRecord(result.raw).download).url, asRecord(asRecord(result.raw).browser).url, asRecord(asRecord(result.raw).bits).remote_url)}</span> },
        { key: "file", label: "File", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).download).file_name, asRecord(asRecord(result.raw).file).name) },
        { key: "target_path", label: "Target Path", render: (_result, summary, _pivot, density) => <span className={cellTextClass(density)} title={summary.primaryPath}>{applyCellFallbacks(summary.primaryPath)}</span> },
        { key: "state", label: "State", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).bits).state, result.event_type) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "defender":
      return [
        timestamp,
        { key: "threat", label: "Threat", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).defender).threat_name, result.title) },
        { key: "action", label: "Action", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).defender).action) },
        { key: "path", label: "Path", render: (_result, summary, _pivot, density) => <span className={cellTextClass(density)} title={summary.primaryPath}>{applyCellFallbacks(summary.primaryPath)}</span> },
        { key: "severity", label: "Severity", render: (result) => <ResultBadge tone={severityTone(result.severity)}>{applyCellFallbacks(result.severity)}</ResultBadge> },
        { key: "status", label: "Status", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).defender).status) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "persistence":
      return [
        timestamp,
        { key: "mechanism", label: "Mechanism", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).persistence).mechanism) },
        { key: "name", label: "Name", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).persistence).name, asRecord(asRecord(result.raw).autoruns).entry) },
        { key: "command", label: "Command", render: (result, _summary, _pivot, density) => <span className={cellTextClass(density)} title={asString(asRecord(asRecord(result.raw).process).command_line || asRecord(asRecord(result.raw).persistence).command || asRecord(asRecord(result.raw).autoruns).command_line)}>{applyCellFallbacks(asRecord(asRecord(result.raw).persistence).command, asRecord(asRecord(result.raw).autoruns).command_line, asRecord(asRecord(result.raw).process).command_line)}</span> },
        { key: "path", label: "Path", render: (_result, summary, _pivot, density) => <span className={cellTextClass(density)} title={summary.primaryPath}>{applyCellFallbacks(summary.primaryPath)}</span> },
        { key: "scope", label: "User / Scope", render: (result, summary) => applyCellFallbacks(summary.primaryUser, asRecord(asRecord(result.raw).persistence).scope) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "files":
      return [
        timestamp,
        { key: "action", label: "Action", render: (result) => applyCellFallbacks(result.event_type) },
        { key: "path", label: "Path", render: (_result, summary, _pivot, density) => <span className={cellTextClass(density)} title={summary.primaryPath}>{applyCellFallbacks(summary.primaryPath)}</span> },
        { key: "extension", label: "Extension", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).file).extension) },
        { key: "deleted", label: "Deleted", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).file).deleted, asRecord(asRecord(result.raw).mft).is_deleted) },
        { key: "size", label: "Size", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).file).size) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    case "cloud_usb":
      return [
        timestamp,
        { key: "type", label: "Type", render: (result) => applyCellFallbacks(artifactLabel(result.artifact_type), humanizeToken(result.event_type)) },
        { key: "entity", label: "Entity", render: (_result, summary) => applyCellFallbacks(summary.keyEntity) },
        { key: "direction", label: "Direction / Device", render: (result) => applyCellFallbacks(asRecord(asRecord(result.raw).cloud).direction, asRecord(asRecord(result.raw).usb).device_type) },
        { key: "path", label: "Path", render: (_result, summary, _pivot, density) => <span className={cellTextClass(density)} title={summary.primaryPath}>{applyCellFallbacks(summary.primaryPath)}</span> },
        { key: "user", label: "User", render: (_result, summary) => applyCellFallbacks(summary.primaryUser) },
        { key: "risk", label: "Risk", render: (result) => <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge> },
      ];
    default:
      return genericColumns();
  }
}

function SearchTable({
  results,
  columns,
  selectedId,
  onSelect,
  actionBuilder,
  pivotRenderer,
  testId,
  density,
  sort,
  onSortChange,
}: {
  results: SearchV2Result[];
  columns: ColumnDef[];
  selectedId: string;
  onSelect: (result: SearchV2Result) => void;
  actionBuilder: (result: SearchV2Result) => RowAction[];
  pivotRenderer: PivotRenderer;
  testId: string;
  density: TableDensity;
  sort: SortValue;
  onSortChange: (sort: SortValue) => void;
}) {
  const storageKey = `dfir.search.columnWidths.${testId}`;
  const defaultWidths = useMemo(() => Object.fromEntries(columns.map((column) => [column.key, column.defaultWidth ?? 160])), [columns]);
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(() => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      return raw ? { ...defaultWidths, ...(JSON.parse(raw) as Record<string, number>) } : defaultWidths;
    } catch {
      return defaultWidths;
    }
  });
  useEffect(() => {
    setColumnWidths((current) => ({ ...defaultWidths, ...current }));
  }, [defaultWidths]);
  useEffect(() => {
    window.localStorage.setItem(storageKey, JSON.stringify(columnWidths));
  }, [columnWidths, storageKey]);
  const cellClass = density === "compact" ? "min-w-0 px-3 py-2.5 align-top" : density === "comfortable" ? "min-w-0 px-4 py-3.5 align-top" : "min-w-0 px-4 py-4 align-top";
  const headClass = density === "compact" ? "relative px-3 py-2.5 text-left" : "relative px-4 py-3 text-left";

  function handleSort(key: string) {
    if (key === "timestamp") {
      onSortChange(sort === "timestamp_asc" ? "timestamp_desc" : "timestamp_asc");
      return;
    }
    if (key === "risk") {
      onSortChange(sort === "risk_asc" ? "risk_desc" : "risk_asc");
    }
  }

  function sortIndicator(key: string) {
    if (key === "timestamp" && sort.startsWith("timestamp_")) return sort === "timestamp_asc" ? "↑" : "↓";
    if (key === "risk" && sort.startsWith("risk_")) return sort === "risk_asc" ? "↑" : "↓";
    return null;
  }

  function startResize(column: ColumnDef, clientX: number) {
    const startWidth = columnWidths[column.key] ?? column.defaultWidth ?? 160;
    const minWidth = column.minWidth ?? 90;
    const handleMove = (event: MouseEvent) => {
      const nextWidth = Math.max(minWidth, Math.round(startWidth + event.clientX - clientX));
      setColumnWidths((current) => ({ ...current, [column.key]: nextWidth }));
    };
    const handleUp = () => {
      window.removeEventListener("mousemove", handleMove);
      window.removeEventListener("mouseup", handleUp);
    };
    window.addEventListener("mousemove", handleMove);
    window.addEventListener("mouseup", handleUp);
  }

  function resetColumnWidths() {
    window.localStorage.removeItem(storageKey);
    setColumnWidths(defaultWidths);
  }

  const actionWidth = 120;
  const totalTableWidth = columns.reduce((total, column) => total + (columnWidths[column.key] ?? column.defaultWidth ?? 160), actionWidth);

  return (
    <div data-testid={testId} className="min-w-0 overflow-hidden rounded-[28px] border border-line bg-panel/70 shadow-panel">
      <div className="flex items-center justify-end border-b border-line/60 px-4 py-2">
        <button type="button" onClick={resetColumnWidths} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted hover:bg-white/5">
          Reset columns
        </button>
      </div>
      <div className="max-h-[68vh] overflow-auto">
        <table className="table-fixed text-sm" style={{ minWidth: `${Math.max(totalTableWidth, 1180)}px`, width: `${Math.max(totalTableWidth, 1180)}px` }}>
          <colgroup>
            {columns.map((column) => (
              <col key={column.key} style={{ width: `${columnWidths[column.key] ?? column.defaultWidth ?? 160}px` }} />
            ))}
            <col style={{ width: `${actionWidth}px` }} />
          </colgroup>
          <thead className="sticky top-0 z-10 border-b border-line bg-abyss/95 backdrop-blur">
            <tr className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
              {columns.map((column) => (
                <th key={column.key} className={headClass}>
                  <button type="button" onClick={() => handleSort(column.key)} className="inline-flex items-center gap-2">
                    <span>{column.label}</span>
                    {sortIndicator(column.key) ? <span>{sortIndicator(column.key)}</span> : null}
                  </button>
                  <button
                    type="button"
                    aria-label={`Resize ${column.label} column`}
                    onMouseDown={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      startResize(column, event.clientX);
                    }}
                    className="absolute right-0 top-0 h-full w-2 cursor-col-resize border-r border-line/70 hover:border-accent"
                  />
                </th>
              ))}
              <th className={headClass}>Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {results.map((result) => {
              const summary = summarizeResult(result);
              const selected = selectedId === result.id;
              const isDismissed = result.kind === "finding" && asString(asRecord(result.raw).status) === "dismissed";
              const rowClass =
                (result.severity === "critical" ? "bg-danger/6 " : result.severity === "high" || (result.risk_score ?? 0) >= 70 ? "bg-warning/6 " : "") +
                (selected ? "ring-1 ring-accent/50 " : "") +
                (isDismissed ? "opacity-55 " : "");
              return (
                <tr
                  key={`${result.kind}-${result.id}`}
                  data-testid={`search-row-${result.kind}-${result.id}`}
                  className={`cursor-pointer hover:bg-white/5 ${rowClass}`}
                  onClick={() => onSelect(result)}
                >
                  {columns.map((column) => (
                    <td key={`${result.id}-${column.key}`} className={cellClass}>
                      <div role="button" tabIndex={0} onClick={() => onSelect(result)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onSelect(result); }} className="block w-full text-left">
                        {column.render(result, summary, pivotRenderer, density)}
                      </div>
                    </td>
                  ))}
                  <td className={cellClass} onClick={(event) => event.stopPropagation()}>
                    <ActionMenu actions={actionBuilder(result)} resultId={result.id} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DetailPanel({
  result,
  onClose,
  actions,
  relatedActions,
  pivotRenderer,
  eventContext,
  eventContextLoading = false,
  mode = "drawer",
  showCloseButton = true,
}: {
  result: SearchV2Result | null;
  onClose: () => void;
  actions: RowAction[];
  relatedActions: RowAction[];
  pivotRenderer: PivotRenderer;
  eventContext?: EventContextResponse | null;
  eventContextLoading?: boolean;
  mode?: "drawer";
  showCloseButton?: boolean;
}) {
  if (!result) {
    return null;
  }

  const raw = asRecord(result.raw);
  const marking = getResultMarking(result);
  const event = asRecord(raw.event);
  const windows = asRecord(raw.windows);
  const artifact = asRecord(raw.artifact);
  const process = asRecord(raw.process);
  const parentProcess = asRecord(process.parent);
  const file = asRecord(raw.file);
  const registry = asRecord(raw.registry);
  const object = asRecord(raw.object);
  const access = asRecord(raw.access);
  const url = asRecord(raw.url);
  const browser = asRecord(raw.browser);
  const download = asRecord(raw.download);
  const timestampStatus = asString(raw.timestamp_status);
  const timestampWarning = asString(raw.timestamp_warning);
  const originalTimestamp = applyCellFallbacks(raw.timestamp_original, raw.raw_timestamp, raw.original_timestamp);
  const hasTimestampWarning = timestampStatus === "suspicious" || timestampStatus === "invalid" || Boolean(timestampWarning);
  const hasValidTimestamp = !hasTimestampWarning && Boolean(result.timestamp || raw["@timestamp"]);
  const observedHost = asString(asRecord(raw.observed_host).name || asRecord(raw.observed_host).hostname);
  const summary = summarizeResult(result);
  const timeline = Array.isArray(raw.timeline) ? (raw.timeline as Array<Record<string, unknown>>) : [];
  const highlights = result.highlights ?? {};
  const relatedProcessNodes = Array.isArray(raw.related_process_node_ids) ? (raw.related_process_node_ids as string[]) : [];
  const investigationActions = actions.filter((action) => ["Open execution story", "Open Command History"].includes(action.label));
  const advancedInvestigationActions = actions.filter((action) => action.label === "Open advanced process graph");
  const reviewActions = actions.filter((action) => ["Mark suspicious", "Mark important", "Mark reviewed", "False positive", "Add note", "Edit labels", "Add to finding", "Clear marking"].includes(action.label));
  const copyExportActions = actions.filter((action) => ["Copy event ID", "Copy raw JSON"].includes(action.label));
  const otherActions = actions.filter((action) => ![...investigationActions, ...advancedInvestigationActions, ...reviewActions, ...copyExportActions].includes(action));
  const entities: Array<[string, string[]]> = [
    ["Files", Array.isArray(raw.related_files) ? (raw.related_files as string[]) : summary.primaryPath ? [summary.primaryPath] : []],
    ["Domains", Array.isArray(raw.related_domains) ? (raw.related_domains as string[]) : summary.primaryDomain ? [summary.primaryDomain] : []],
    ["IPs", Array.isArray(raw.related_ips) ? (raw.related_ips as string[]) : summary.primaryIp ? [summary.primaryIp] : []],
    ["Users", Array.isArray(raw.related_users) ? (raw.related_users as string[]) : summary.primaryUser ? [summary.primaryUser] : []],
    ["Hosts", Array.isArray(raw.related_hosts) ? (raw.related_hosts as string[]) : summary.primaryHost ? [summary.primaryHost] : []],
  ];

  const containerClass = "h-full max-w-none overflow-visible bg-transparent p-0 shadow-none";

  return (
    <aside data-testid="search-detail-panel" className={containerClass}>
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Search detail</p>
            <h3 className="mt-2 break-words text-2xl font-semibold">{result.title}</h3>
            <p className="mt-3 break-words text-sm text-muted">{result.summary || "No summary available."}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <ResultBadge tone={result.kind === "finding" ? "success" : "default"}>{result.kind}</ResultBadge>
              {result.severity ? <ResultBadge tone={severityTone(result.severity)}>{result.severity}</ResultBadge> : null}
              {result.risk_score !== undefined && result.risk_score !== null ? <ResultBadge tone={riskTone(result.risk_score)}>{`risk ${result.risk_score}`}</ResultBadge> : null}
              {result.artifact_type ? <ResultBadge tone="muted">{artifactLabel(result.artifact_type)}</ResultBadge> : null}
              {result.event_type ? <ResultBadge tone="muted">{humanizeToken(result.event_type)}</ResultBadge> : null}
              <MarkingBadge marking={marking} />
              {result.kind === "finding" && asString(raw.confidence) ? <ResultBadge tone="muted">{`confidence ${asString(raw.confidence)}`}</ResultBadge> : null}
            </div>
          </div>
          <div className="min-w-0 w-full space-y-2 md:w-[280px]">
            <InfoCard label="Timestamp" value={formatTimestamp(result.timestamp, "UTC")} />
            <InfoCard label="Host / User">
              <div className="flex min-w-0 flex-wrap gap-1">
                {pivotRenderer({ label: "host", field: "host.name", value: summary.primaryHost, className: cellTextClass("expanded") })}
                <span className="text-muted">·</span>
                {pivotRenderer({ label: "user", field: "user.name", value: summary.primaryUser, className: cellTextClass("expanded") })}
              </div>
            </InfoCard>
            <InfoCard label="Key entity">
              {pivotRenderer({ label: "key entity", field: "message", value: summary.keyEntity, operator: "contains", className: cellTextClass("expanded") })}
            </InfoCard>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <InfoCard label="Artifact">{pivotRenderer({ label: "artifact type", field: "artifact.type", value: result.artifact_type || artifact.type, display: artifactLabel(result.artifact_type || asString(artifact.type)), className: cellTextClass("expanded") })}</InfoCard>
          <InfoCard label="Parser">{pivotRenderer({ label: "parser", field: "artifact.parser", value: applyCellFallbacks(result.parser, artifact.parser), className: cellTextClass("expanded") })}</InfoCard>
          <InfoCard label="Source file">{pivotRenderer({ label: "source file", field: "source_file", value: fullSourceFile(result), operator: "contains", className: cellTextClass("expanded") })}</InfoCard>
        </div>

        {hasTimestampWarning ? (
          <div className="rounded-2xl border border-amber-400/40 bg-amber-400/10 p-4 text-sm text-amber-100">
            Suspicious timestamp preserved but not used for timeline.
            <span className="mt-1 block text-xs text-amber-100/80">
              Status: {timestampStatus || "suspicious"} · Warning: {timestampWarning || "timestamp_out_of_range"} · Original: {originalTimestamp}
            </span>
          </div>
        ) : null}

        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Process investigation</p>
              <p className="mt-1 text-xs text-muted">Open the exact execution story for this event, or use raw graph controls from Advanced.</p>
            </div>
            {showCloseButton ? (
              <button type="button" aria-label="Close detail panel" onClick={onClose} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                Close
              </button>
            ) : null}
          </div>
          <div className="mt-3 space-y-3">
            {investigationActions.length ? <div>{renderActions(investigationActions)}</div> : null}
            {advancedInvestigationActions.length ? (
              <details className="rounded-2xl border border-line bg-panel/30 p-3">
                <summary className="cursor-pointer text-xs text-muted">Advanced graph</summary>
                <div className="mt-3">{renderActions(advancedInvestigationActions)}</div>
              </details>
            ) : null}
            {otherActions.length ? <div>{renderActions(otherActions)}</div> : null}
            {reviewActions.length ? (
              <div>
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Analyst marking</p>
                {renderActions(reviewActions)}
              </div>
            ) : null}
            {copyExportActions.length ? (
              <div>
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Copy / export</p>
                {renderActions(copyExportActions)}
              </div>
            ) : null}
          </div>
        </div>

        {result.kind === "event" ? (
          <div data-testid="event-marking-panel" className="rounded-2xl border border-line bg-abyss/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Analyst review</p>
                <p className="mt-1 text-sm text-muted">Persistent marking for this event. Original indexed event data stays unchanged.</p>
              </div>
              <MarkingBadge marking={marking} />
            </div>
            <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
              <div>Status: <span className="text-slate-100">{markingLabel(marking?.status) || "Unmarked"}</span></div>
              <div>Finding: <span className="text-slate-100">{applyCellFallbacks(marking?.finding_id)}</span></div>
              <div className="md:col-span-2">Labels: <span className="text-slate-100">{marking?.labels?.length ? marking.labels.join(", ") : "-"}</span></div>
              <div className="md:col-span-2">Note: <span className="text-slate-100">{applyCellFallbacks(marking?.note)}</span></div>
            </div>
          </div>
        ) : null}

        {result.kind === "event" ? (
          <div data-testid="related-activity-section" className="rounded-2xl border border-line bg-abyss/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Related activity</p>
                <p className="mt-1 text-sm text-muted">Pivot from this event without manually rebuilding filters.</p>
              </div>
              {eventContextLoading ? <span className="rounded-full border border-line px-3 py-1 text-xs text-muted">Loading linked detections…</span> : null}
            </div>
            {!hasValidTimestamp ? (
              <p className="mt-3 rounded-2xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-100">This event has no valid forensic timestamp.</p>
            ) : null}
            {relatedActions.length ? (
              <div className="mt-4 grid gap-2 md:grid-cols-2">
                {relatedActions.map((action) => (
                  <button
                    key={action.label}
                    type="button"
                    aria-label={action.ariaLabel ?? action.label}
                    disabled={action.disabled}
                    title={action.value || action.label}
                    onClick={action.onClick}
                    className="min-w-0 rounded-2xl border border-line bg-panel/40 px-3 py-2 text-left text-xs text-muted hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    <span className="block font-medium text-slate-100">{action.label}</span>
                    {action.value ? <span className="mt-1 block truncate">{action.value}</span> : null}
                  </button>
                ))}
              </div>
            ) : null}
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-black/10 p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-muted">Linked detections</p>
                <p className="mt-2 text-sm text-slate-100">{eventContext?.counts.related_detections ?? 0} linked</p>
                {eventContext?.related_detections?.length ? (
                  <div className="mt-2 space-y-1 text-xs text-muted">
                    {eventContext.related_detections.slice(0, 3).map((item) => (
                      <button key={item.id} type="button" onClick={() => { window.location.href = `/cases/${eventContext.case_id}/detections?detection_id=${encodeURIComponent(item.id)}`; }} className="block w-full truncate text-left hover:text-slate-100" title={item.rule_title || item.rule_name}>
                        {item.rule_title || item.rule_name}
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-muted">No linked detections.</p>
                )}
              </div>
              <div className="rounded-2xl border border-line bg-black/10 p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-muted">Linked findings</p>
                <p className="mt-2 text-sm text-slate-100">{eventContext?.counts.related_findings ?? 0} linked</p>
                {eventContext?.related_findings?.length ? (
                  <div className="mt-2 space-y-1 text-xs text-muted">
                    {eventContext.related_findings.slice(0, 3).map((item) => (
                      <button key={item.id} type="button" onClick={() => { window.location.href = `/cases/${eventContext.case_id}/findings?finding_id=${encodeURIComponent(item.id)}`; }} className="block w-full truncate text-left hover:text-slate-100" title={item.title}>
                        {item.title}
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-muted">No linked findings.</p>
                )}
              </div>
            </div>
          </div>
        ) : null}

        <div className="grid gap-4 xl:grid-cols-2">
          <div className="rounded-2xl border border-line bg-abyss/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Key fields</p>
            <div className="mt-3 grid gap-2 text-sm text-muted">
              <div className="break-words">Timestamp: <span className="text-white">{formatTimestamp(result.timestamp, "UTC")}</span></div>
              <div className="break-words">Host: <span className="text-white">{applyCellFallbacks(summary.primaryHost)}</span></div>
              {observedHost && observedHost !== summary.primaryHost ? (
                <div className="break-words">Observed as: <span className="text-white">{observedHost}</span></div>
              ) : null}
              <div className="break-words">User: <span className="text-white">{pivotRenderer({ label: "user", field: "user.name", value: summary.primaryUser })}</span></div>
              <div className="break-words">Process: <span className="text-white">{pivotRenderer({ label: "process", field: "process.name", value: summary.primaryProcess })}</span></div>
              <div className="break-words">Path: <span className="text-white">{pivotRenderer({ label: "file path", field: "file.path", value: summary.primaryPath, operator: "contains" })}</span></div>
              <div className="break-words">Domain / IP: <span className="text-white">{pivotRenderer({ label: "domain", field: "url.domain", value: summary.primaryDomain || summary.primaryIp, operator: "contains" })}</span></div>
            </div>
          </div>

          {Object.keys(highlights).length ? (
            <div className="rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Highlights</p>
              <div className="mt-3 space-y-3 text-xs text-muted">
                {Object.entries(highlights).map(([field, values]) => (
                  <div key={field}>
                    <div className="font-medium text-slate-200">{field}</div>
                    {values.map((value, index) => (
                      <div key={`${field}-${index}`} className="mt-1 break-words">
                        {value}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {timeline.length ? (
          <div className="rounded-2xl border border-line bg-abyss/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search Timeline</p>
            <div className="mt-3 space-y-3">
              {timeline.slice(0, 8).map((item, index) => (
                <div key={`${asString(item.event_id)}-${index}`} className="border-l border-line pl-3 text-xs text-muted">
                  <div className="font-medium text-slate-200">{formatTimestamp(asString(item.timestamp), "UTC")}</div>
                  <div>{applyCellFallbacks(item.artifact_type, item.event_type)}</div>
                  <div className="mt-1">{applyCellFallbacks(item.summary)}</div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Entities</p>
          <div className="mt-3 space-y-3">
            {entities.map(([label, values]) =>
              values.length ? (
                <div key={label}>
                  <div className="text-xs uppercase tracking-[0.14em] text-muted">{label}</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {values.slice(0, 8).map((value) => (
                      <button key={`${label}-${value}`} type="button" onClick={() => void copyToClipboard(value)} className="max-w-full break-all rounded-full border border-line px-3 py-1 text-left text-xs text-muted">
                        {value}
                      </button>
                    ))}
                  </div>
                </div>
              ) : null,
            )}
            {relatedProcessNodes.length ? (
              <div>
                <div className="text-xs uppercase tracking-[0.14em] text-muted">Process nodes</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {relatedProcessNodes.slice(0, 8).map((value) => (
                    <span key={value} className="rounded-full border border-line px-3 py-1 text-xs text-muted">
                      {value}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>

        {(raw.object || raw.access || raw.registry || raw.folder || raw.office || raw.execution || raw.process || raw.file || raw.ntfs || raw.url) ? (
          <div className="rounded-2xl border border-line bg-abyss/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Observed data</p>
            <div className="mt-3 grid gap-2 text-sm text-muted">
              <div className="break-words">Event type: <span className="text-white">{pivotRenderer({ label: "event type", field: "event.type", value: result.event_type || event.type, display: applyCellFallbacks(humanizeToken(result.event_type)) })}</span></div>
              <div className="break-words">Event ID: <span className="text-white">{pivotRenderer({ label: "Windows event ID", field: "windows.event_id", value: windows.event_id || event.id })}</span></div>
              <div className="break-words">Provider: <span className="text-white">{pivotRenderer({ label: "provider", field: "event.provider", value: event.provider || windows.provider })}</span></div>
              <div className="break-words">Channel: <span className="text-white">{pivotRenderer({ label: "channel", field: "event.channel", value: event.channel || windows.channel })}</span></div>
              <div className="break-words">Parent process: <span className="text-white">{pivotRenderer({ label: "parent process", field: "parent.process.name", value: process.parent_name || parentProcess.name })}</span></div>
              <div className="break-words">Parent command line: <span className="text-white">{pivotRenderer({ label: "parent command line", field: "parent.process.command_line", value: process.parent_command_line || parentProcess.command_line, operator: "contains" })}</span></div>
              <div className="break-words">Object name: <span className="text-white">{pivotRenderer({ label: "object name", field: "object.name", value: object.name || object.path, operator: "contains" })}</span></div>
              <div className="break-words">Object type: <span className="text-white">{applyCellFallbacks(object.type)}</span></div>
              <div className="break-words">Access mask: <span className="text-white">{pivotRenderer({ label: "access mask", field: "access.mask", value: access.mask })}</span></div>
              <div className="break-words">Accesses: <span className="text-white">{Array.isArray(access.list) ? access.list.join(", ") : applyCellFallbacks(access.accesses)}</span></div>
              <div className="break-words">Registry key: <span className="text-white">{pivotRenderer({ label: "registry key", field: "registry.key", value: registry.key_path || registry.key, operator: "contains" })}</span></div>
              <div className="break-words">Registry value: <span className="text-white">{applyCellFallbacks(registry.value_name, registry.value_data)}</span></div>
              <div className="break-words">Command line: <span className="text-white">{pivotRenderer({ label: "command line", field: "process.command_line", value: process.command_line, operator: "contains" })}</span></div>
              <div className="break-words">File path: <span className="text-white">{pivotRenderer({ label: "file path", field: "file.path", value: file.path, operator: "contains" })}</span></div>
              <div className="break-words">Folder: <span className="text-white">{applyCellFallbacks(asRecord(raw.folder).path)}</span></div>
              <div className="break-words">Office app: <span className="text-white">{applyCellFallbacks(asRecord(raw.office).app)}</span></div>
              <div className="break-words">Trusted document: <span className="text-white">{applyCellFallbacks(asRecord(raw.office).trusted_document)}</span></div>
              <div className="break-words">Execution confirmed: <span className="text-white">{applyCellFallbacks(asRecord(raw.execution).is_execution_confirmed)}</span></div>
              <div className="break-words">NTFS source: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).source)}</span></div>
              <div className="break-words">Reason: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).reason)}</span></div>
              <div className="break-words">Zone ID: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).zone_id)}</span></div>
              <div className="break-words">Host URL: <span className="text-white">{pivotRenderer({ label: "URL", field: "url.full", value: asRecord(raw.ntfs).host_url || url.full || browser.url || download.url, operator: "contains" })}</span></div>
              <div className="break-words">Referrer URL: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).referrer_url)}</span></div>
              <div className="break-words">Old / new name: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).old_name, asRecord(raw.ntfs).new_name)}</span></div>
              <div className="break-words">Snapshot time: <span className="text-white">{applyCellFallbacks(asRecord(raw.ntfs).snapshot_time)}</span></div>
            </div>
          </div>
        ) : null}

        <details className="rounded-2xl border border-line bg-abyss/60 p-4">
          <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw JSON</summary>
          <pre className="mt-3 max-h-[24rem] overflow-auto whitespace-pre-wrap break-all text-xs text-muted">{JSON.stringify(raw, null, 2)}</pre>
        </details>
      </div>
    </aside>
  );
}

export default function Search() {
  const navigate = useNavigate();
  const { caseId: routeCaseId } = useParams();
  const { activeCaseId, selectedEvidenceId, selectedHost, setActiveCaseId } = useActiveCase();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const state = useMemo(() => buildState(searchParams), [searchParams]);
  const pageSizeWasClamped = state.page_size_requested > SEARCH_UI_MAX_PAGE_SIZE;
  const [pageSizeClampNotice, setPageSizeClampNotice] = useState(pageSizeWasClamped);
  const [queryInput, setQueryInput] = useState(state.q);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [facetsOpen, setFacetsOpen] = useState(false);
  const [syntaxHelpOpen, setSyntaxHelpOpen] = useState(false);
  const [contextResponse, setContextResponse] = useState<SearchV2Response | null>(null);
  const [contextLabel, setContextLabel] = useState("");
  const [selectedId, setSelectedId] = useState(state.selected);
  const [density, setDensity] = useState<TableDensity>("compact");
  const [draftCondition, setDraftCondition] = useState<BuilderCondition>({ field: "artifact.type", operator: "is", value: "", negate: false });
  const [filterBuilderError, setFilterBuilderError] = useState("");
  const debouncedQuery = useDebouncedValue(queryInput, 300);
  const isUltraWideLayout = useMinWidthQuery(1600);
  const resolvedCaseId = routeCaseId || activeCaseId;

  useEffect(() => {
    if (routeCaseId) setActiveCaseId(routeCaseId);
  }, [routeCaseId, setActiveCaseId]);

  useEffect(() => {
    if (pageSizeWasClamped) {
      setPageSizeClampNotice(true);
    }
  }, [pageSizeWasClamped]);

  useEffect(() => {
    if (!pageSizeWasClamped) return;
    const next = new URLSearchParams(searchParams);
    next.set("page_size", String(SEARCH_UI_MAX_PAGE_SIZE));
    setSearchParams(next, { replace: true });
  }, [pageSizeWasClamped, searchParams, setSearchParams]);

  useEffect(() => {
    setQueryInput(state.q);
  }, [state.q]);

  useEffect(() => {
    setSelectedId(state.selected);
  }, [state.selected]);

  useEffect(() => {
    if (debouncedQuery === state.q) return;
    const next = new URLSearchParams(searchParams);
    if (debouncedQuery) next.set("q", debouncedQuery);
    else next.delete("q");
    next.set("page", "1");
    setSearchParams(next, { replace: true });
  }, [debouncedQuery, searchParams, setSearchParams, state.q]);

  const searchRequestState = useMemo(
    () => ({
      q: state.q,
      exclude_q: state.exclude_q,
      filters: state.filters,
      scope: state.scope,
      artifact_type: state.artifact_type,
      parser: state.parser,
      backend_variant: state.backend_variant,
      parser_backend: state.parser_backend,
      exclude_artifact_type: state.exclude_artifact_type,
      exclude_parser: state.exclude_parser,
      event_type: state.event_type,
      event_category: state.event_category,
      severity: state.severity,
      status: state.status,
      confidence: state.confidence,
      host: state.host || selectedHost,
      user: state.user,
      exclude_host: state.exclude_host,
      exclude_user: state.exclude_user,
      process_name: state.process_name,
      source_file: state.source_file,
      exclude_source_file: state.exclude_source_file,
      file_name: state.file_name,
      file_path: state.file_path,
      domain: state.domain,
      ip: state.ip,
      hash: state.hash,
      url: state.url,
      risk_min: state.risk_min,
      risk_max: state.risk_max,
      marked_only: state.marked_only,
      marking_status: state.marking_status,
      marked_has_note: state.marked_has_note,
      marked_in_finding: state.marked_in_finding,
      include_filesystem_timeline: state.include_filesystem_timeline,
      evidence_id: state.evidence_id || selectedEvidenceId,
      source_category: state.source_category,
      time_from: state.time_from,
      time_to: state.time_to,
      sort: state.sort,
      page: state.page,
      page_size: state.page_size,
      cursor: undefined,
    }),
    [selectedEvidenceId, selectedHost, state],
  );

  const searchQuery = useQuery({
    queryKey: ["search-v2-workspace", resolvedCaseId, searchRequestState, contextLabel],
    queryFn: () =>
      api.searchCase(resolvedCaseId, {
        q: searchRequestState.q,
        exclude_q: searchRequestState.exclude_q || undefined,
        filters: serializeBuilderFilters(searchRequestState.filters) || undefined,
        scope: searchRequestState.scope,
        evidence_id: searchRequestState.evidence_id || undefined,
        source_category: searchRequestState.source_category || undefined,
        artifact_type: searchRequestState.artifact_type,
        parser: searchRequestState.parser,
        backend_variant: searchRequestState.backend_variant,
        parser_backend: searchRequestState.parser_backend,
        exclude_artifact_type: searchRequestState.exclude_artifact_type,
        exclude_parser: searchRequestState.exclude_parser,
        event_type: searchRequestState.event_type,
        event_category: searchRequestState.event_category,
        severity: searchRequestState.severity,
        status: searchRequestState.status,
        confidence: searchRequestState.confidence,
        host: searchRequestState.host || undefined,
        user: searchRequestState.user || undefined,
        exclude_host: searchRequestState.exclude_host || undefined,
        exclude_user: searchRequestState.exclude_user || undefined,
        process_name: searchRequestState.process_name || undefined,
        source_file: searchRequestState.source_file || undefined,
        exclude_source_file: searchRequestState.exclude_source_file || undefined,
        file_name: searchRequestState.file_name || undefined,
        file_path: searchRequestState.file_path || undefined,
        domain: searchRequestState.domain || undefined,
        ip: searchRequestState.ip || undefined,
        hash: searchRequestState.hash || undefined,
        url: searchRequestState.url || undefined,
        risk_min: searchRequestState.risk_min ? Number(searchRequestState.risk_min) : undefined,
        risk_max: searchRequestState.risk_max ? Number(searchRequestState.risk_max) : undefined,
        marked_only: searchRequestState.marked_only === "true" || undefined,
        marking_status: searchRequestState.marking_status || undefined,
        marked_has_note: searchRequestState.marked_has_note === "true" || undefined,
        marked_in_finding: searchRequestState.marked_in_finding === "true" || undefined,
        include_filesystem_timeline: searchRequestState.include_filesystem_timeline === "true" || undefined,
        time_from: searchRequestState.time_from || undefined,
        time_to: searchRequestState.time_to || undefined,
        sort: searchRequestState.sort,
        page: searchRequestState.page,
        page_size: searchRequestState.page_size,
        cursor: searchRequestState.cursor,
        include_highlights: true,
        include_facets: true,
      }),
    enabled: Boolean(resolvedCaseId) && !contextResponse,
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });

  const quickFiltersQuery = useQuery({
    queryKey: ["search-v2-quick-filters", resolvedCaseId],
    queryFn: () => api.getSearchQuickFilters(resolvedCaseId),
    enabled: Boolean(resolvedCaseId),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const facetsQuery = useQuery({
    queryKey: ["search-v2-facets", resolvedCaseId, searchRequestState.evidence_id || ""],
    queryFn: () => api.searchFacets({ caseId: resolvedCaseId, evidenceId: searchRequestState.evidence_id || undefined }),
    enabled: Boolean(resolvedCaseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  const response = contextResponse ?? searchQuery.data;
  const globalFacets = facetsQuery.data ?? {};
  const facetPanelFacets = useMemo(() => {
    const source = (Object.keys(globalFacets).length ? globalFacets : (response?.facets ?? {})) as Record<string, Record<string, number>>;
    const result: Record<string, Record<string, number>> = {};
    for (const [label, aliases] of Object.entries({
      artifact_type: ["artifact_type", "artifact.type"],
      parser: ["parser", "artifact.parser"],
      source_file: ["source_file"],
      host: ["host", "host.name"],
      user: ["user", "user.name"],
      event_type: ["event_type", "event.type"],
      severity: ["severity", "event.severity"],
      status: ["status"],
    })) {
      const values = aliases.map((alias) => source[alias]).find((items) => items && Object.keys(items).length);
      if (values) result[label] = values;
    }
    return result;
  }, [globalFacets, response?.facets]);
  const parsedSearchError = useMemo(() => parseSearchError(searchQuery.error), [searchQuery.error]);
  const results = response?.results ?? [];
  const groupedSearchSummary = useMemo(
    () => buildGroupedSearchSummary(results, searchRequestState.q, response?.total),
    [results, response?.total, searchRequestState.q],
  );
  const findingResults = useMemo(() => results.filter((item) => item.kind === "finding"), [results]);
  const eventResults = useMemo(() => results.filter((item) => item.kind === "event"), [results]);
  const selectedResult = useMemo(() => results.find((item) => item.id === selectedId) ?? null, [results, selectedId]);
  const eventContextQuery = useQuery({
    queryKey: ["event-context", resolvedCaseId, selectedResult?.id, selectedResult?.kind],
    queryFn: () => api.getEventContext(resolvedCaseId || "", selectedResult?.id ?? ""),
    enabled: Boolean(resolvedCaseId && selectedResult?.kind === "event" && selectedResult?.id),
    staleTime: 30_000,
  });
  const markEventMutation = useMutation({
    mutationFn: ({ result, status, note, labels, findingId }: { result: SearchV2Result; status: EventMarkingStatus; note?: string | null; labels?: string[]; findingId?: string | null }) => {
      const raw = asRecord(result.raw);
      const host = asRecord(raw.host);
      const existing = getResultMarking(result);
      return api.markEvent(result.id, {
        case_id: resolvedCaseId,
        evidence_id: asString(raw.evidence_id) || undefined,
        search_doc_id: result.id,
        stable_event_id: asString(raw.stable_event_id) || undefined,
        artifact_type: asString(result.artifact_type || asRecord(raw.artifact).type) || undefined,
        timestamp: asString(result.timestamp || raw["@timestamp"]) || undefined,
        host: asString(host.canonical || host.name || result.host) || undefined,
        status,
        labels: labels ?? existing?.labels ?? [],
        note: note ?? existing?.note ?? undefined,
        finding_id: findingId ?? existing?.finding_id ?? undefined,
        created_by: "analyst",
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["search-v2-workspace"] });
      void queryClient.invalidateQueries({ queryKey: ["event-markings"] });
    },
  });
  const deleteMarkingMutation = useMutation({
    mutationFn: (markingId: string) => api.deleteEventMarking(markingId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["search-v2-workspace"] });
      void queryClient.invalidateQueries({ queryKey: ["event-markings"] });
    },
  });
  const activeView = useMemo(() => deduceArtifactView(eventResults, state.artifact_type), [eventResults, state.artifact_type]);
  const artifactColumns = useMemo(() => specializedColumns(activeView), [activeView]);
  const genericResultColumns = useMemo(() => genericColumns(), []);
  const activeFilterChips = useMemo(() => {
    const chips: Array<{ key: string; label: string; clear: Record<string, string | null> }> = [];
    if (state.q) chips.push({ key: "q", label: `query: ${state.q}`, clear: { q: null } });
    if (state.exclude_q) chips.push({ key: "exclude_q", label: `NOT text: ${state.exclude_q}`, clear: { exclude_q: null } });
    for (const [index, condition] of state.filters.entries()) {
      const nextFilters = state.filters.filter((_, itemIndex) => itemIndex !== index);
      chips.push({
        key: `filter-${index}-${condition.field}-${condition.operator}-${condition.value}`,
        label: filterConditionLabel(condition),
        clear: { filters: serializeBuilderFilters(nextFilters) || null },
      });
    }
    if (state.risk_min || state.risk_max) {
      chips.push({
        key: "risk_range",
        label: state.risk_min && state.risk_max ? `risk ${state.risk_min}-${state.risk_max}` : state.risk_min ? `risk >= ${state.risk_min}` : `risk <= ${state.risk_max}`,
        clear: { risk_min: null, risk_max: null },
      });
    }
    if (state.marked_only) chips.push({ key: "marked_only", label: "marked only", clear: { marked_only: null } });
    if (state.marking_status) chips.push({ key: "marking_status", label: `marking: ${state.marking_status}`, clear: { marking_status: null } });
    if (state.marked_has_note) chips.push({ key: "marked_has_note", label: "has analyst note", clear: { marked_has_note: null } });
    if (state.marked_in_finding) chips.push({ key: "marked_in_finding", label: "in finding", clear: { marked_in_finding: null } });
    if (searchRequestState.host) chips.push({ key: "host", label: `host: ${searchRequestState.host}`, clear: { host: null } });
    if (state.user) chips.push({ key: "user", label: `user: ${state.user}`, clear: { user: null } });
    if (state.parser.length) chips.push({ key: "parser", label: `parser: ${state.parser.join(", ")}`, clear: { parser: null } });
    if (state.backend_variant.length) chips.push({ key: "backend_variant", label: `backend: ${state.backend_variant.join(", ")}`, clear: { backend_variant: null } });
    if (state.parser_backend.length) chips.push({ key: "parser_backend", label: `parser backend: ${state.parser_backend.join(", ")}`, clear: { parser_backend: null } });
    if (state.exclude_parser.length) chips.push({ key: "exclude_parser", label: `NOT parser: ${state.exclude_parser.join(", ")}`, clear: { exclude_parser: null } });
    if (state.exclude_host) chips.push({ key: "exclude_host", label: `NOT host: ${state.exclude_host}`, clear: { exclude_host: null } });
    if (state.exclude_user) chips.push({ key: "exclude_user", label: `NOT user: ${state.exclude_user}`, clear: { exclude_user: null } });
    if (state.process_name) chips.push({ key: "process_name", label: `process: ${state.process_name}`, clear: { process_name: null } });
    if (state.source_file) chips.push({ key: "source_file", label: `source: ${state.source_file}`, clear: { source_file: null } });
    if (state.exclude_source_file) chips.push({ key: "exclude_source_file", label: `NOT source: ${state.exclude_source_file}`, clear: { exclude_source_file: null } });
    if (state.domain) chips.push({ key: "domain", label: `domain: ${state.domain}`, clear: { domain: null } });
    if (state.file_path) chips.push({ key: "file_path", label: `path: ${state.file_path}`, clear: { file_path: null } });
    if (state.file_name) chips.push({ key: "file_name", label: `file: ${state.file_name}`, clear: { file_name: null } });
    if (searchRequestState.evidence_id) chips.push({ key: "evidence_id", label: `evidence: ${searchRequestState.evidence_id.slice(0, 8)}`, clear: { evidence_id: null } });
    if (searchRequestState.source_category) chips.push({ key: "source_category", label: `source: ${searchRequestState.source_category}`, clear: { source_category: null, source: null } });
    if (state.artifact_type.length) chips.push({ key: "artifact_type", label: `artifact: ${state.artifact_type.join(", ")}`, clear: { artifact_type: null } });
    if (state.exclude_artifact_type.length) chips.push({ key: "exclude_artifact_type", label: `NOT artifact: ${state.exclude_artifact_type.join(", ")}`, clear: { exclude_artifact_type: null } });
    if (state.event_type.length) chips.push({ key: "event_type", label: `type: ${state.event_type.join(", ")}`, clear: { event_type: null } });
    if (state.severity.length) chips.push({ key: "severity", label: `severity: ${state.severity.join(", ")}`, clear: { severity: null } });
    if (state.status.length) chips.push({ key: "status", label: `status: ${state.status.join(", ")}`, clear: { status: null } });
    if (state.time_from || state.time_to) chips.push({ key: "time", label: `time: ${state.time_from || "…"} → ${state.time_to || "…"}`, clear: { time_from: null, time_to: null } });
    return chips;
  }, [searchRequestState.evidence_id, searchRequestState.host, searchRequestState.source_category, state]);
  const querySyntaxChips = useMemo(
    () =>
      (response?.query_syntax?.applied_filters ?? []).map((item, index) => ({
        id: `${item.field}-${item.operator}-${item.value}-${index}`,
        label: item.operator === "has" ? `has ${item.field}` : `${item.field} ${item.operator} ${item.value}`,
      })),
    [response?.query_syntax?.applied_filters],
  );
  const currentPage = Math.max(1, state.page);
  const pageStart = results.length ? (currentPage - 1) * state.page_size + 1 : 0;
  const pageEnd = results.length ? pageStart + results.length - 1 : 0;
  const hasNextPage = response?.has_next ?? currentPage * state.page_size < (response?.total ?? 0);
  const hasFalseEmptyPage = Boolean(response && !searchQuery.isLoading && !searchQuery.isError && !results.length && (response.total ?? 0) > 0);
  const paginationLocked = Boolean(contextResponse);
  const detailMode: "stacked" = "stacked";
  const detailDrawerWidth = "w-full max-w-6xl";
  const timeRangeInvalid =
    Boolean(state.time_from && state.time_to) &&
    !Number.isNaN(Date.parse(state.time_from)) &&
    !Number.isNaN(Date.parse(state.time_to)) &&
    Date.parse(state.time_from) > Date.parse(state.time_to);

  useEffect(() => {
    if (!selectedId) return;
    if (!response) return;
    if (!results.some((item) => item.id === selectedId)) {
      closeSelectedResult();
    }
  }, [response, results, searchParams, selectedId, setSearchParams]);

  function closeSelectedResult() {
    setSelectedId("");
    const next = new URLSearchParams(searchParams);
    next.delete("selected");
    setSearchParams(next, { replace: true });
  }

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(updates)) {
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
    }
    if (!("selected" in updates)) {
      next.delete("selected");
      setSelectedId("");
    }
    if (!("page" in updates)) next.set("page", "1");
    setSearchParams(next, { replace: true });
  }

  function updateBackendSort(nextSort: SortValue) {
    if (nextSort === "timestamp_asc" || nextSort === "timestamp_desc") {
      updateParams({ sort: "@timestamp", order: nextSort === "timestamp_asc" ? "asc" : "desc" });
      return;
    }
    updateParams({ sort: nextSort, order: null });
  }

  function handleSelect(result: SearchV2Result) {
    setSelectedId(result.id);
    const next = new URLSearchParams(searchParams);
    next.set("selected", result.id);
    next.set("tab", state.tab);
    setSearchParams(next, { replace: true });
  }

  function applyTimePreset(preset: "24h" | "7d" | "30d" | "clear") {
    if (preset === "clear") {
      updateParams({ time_from: null, time_to: null });
      return;
    }
    const now = new Date();
    const nextTo = now.toISOString();
    const deltaDays = preset === "24h" ? 1 : preset === "7d" ? 7 : 30;
    const from = new Date(now.getTime() - deltaDays * 24 * 60 * 60 * 1000).toISOString();
    updateParams({ time_from: from, time_to: nextTo });
  }

  function applyRiskPreset(min: string, max: string) {
    updateParams({ risk_min: min, risk_max: max });
  }

  function clearRisk() {
    updateParams({ risk_min: null, risk_max: null });
  }

  function resetFilters() {
    setContextResponse(null);
    setContextLabel("");
    setSelectedId("");
    setSearchParams(new URLSearchParams([["scope", "all"], ["tab", "results"], ["page_size", String(state.page_size)]]), { replace: true });
  }

  function applySearchNow() {
    updateParams({ q: queryInput });
  }

  function clearExclusions() {
    updateParams({
      exclude_q: null,
      exclude_artifact_type: null,
      exclude_parser: null,
      exclude_source_file: null,
      exclude_host: null,
      exclude_user: null,
      filters: serializeBuilderFilters(state.filters.filter((item) => !(item.negate || item.operator === "is not" || item.operator === "does not contain" || item.operator === "does not exist"))) || null,
    });
  }

  function addBuilderCondition(condition: BuilderCondition) {
    const normalized = {
      ...condition,
      value: noValueOperators.has(condition.operator) ? "" : condition.value.trim(),
    };
    if (!normalized.field || !filterFieldOptions.some((item) => item.value === normalized.field)) {
      setFilterBuilderError("Choose a supported field.");
      return;
    }
    if (!noValueOperators.has(normalized.operator) && !normalized.value) {
      setFilterBuilderError("Enter a value for this filter.");
      return;
    }
    setFilterBuilderError("");
    const nextFilters = [...state.filters, normalized];
    updateParams({ filters: serializeBuilderFilters(nextFilters), tab: state.tab });
  }

  function renderPivotValue(config: PivotConfig) {
    return <PivotValue {...config} onApply={addBuilderCondition} />;
  }

  function removeBuilderCondition(index: number) {
    const nextFilters = state.filters.filter((_, itemIndex) => itemIndex !== index);
    updateParams({ filters: serializeBuilderFilters(nextFilters) || null });
  }

  function applyQuickFilter(item: SearchQuickFilter) {
    const next = new URLSearchParams();
    next.set("tab", "results");
    next.set("scope", String(item.params.scope ?? "events"));
    next.set("page_size", String(state.page_size));
    if (searchRequestState.evidence_id) next.set("evidence_id", searchRequestState.evidence_id);
    if (searchRequestState.host) next.set("host", searchRequestState.host);
    if (item.params.risk_min !== undefined) next.set("risk_min", String(item.params.risk_min));
    if (Array.isArray(item.params.event_type)) next.set("event_type", joinParam(item.params.event_type as string[]));
    if (Array.isArray(item.params.event_category)) next.set("event_category", joinParam(item.params.event_category as string[]));
    if (Array.isArray(item.params.artifact_type)) next.set("artifact_type", joinParam(item.params.artifact_type as string[]));
    if (Array.isArray(item.params.severity)) next.set("severity", joinParam(item.params.severity as string[]));
    if (item.params.process_name) next.set("process_name", asString(item.params.process_name));
    setContextResponse(null);
    setContextLabel("");
    setSearchParams(next, { replace: true });
  }

  function handleFacetClick(field: string, value: string, mode: "include" | "exclude" = "include") {
    const mapping: Record<string, string> = {
      artifact_type: "artifact_type",
      "artifact.type": "artifact_type",
      parser: "parser",
      "artifact.parser": "parser",
      event_type: "event_type",
      severity: "severity",
      host: "host",
      "host.name": "host",
      user: "user",
      "user.name": "user",
      source_file: "source_file",
      status: "status",
    };
    const key = mapping[field];
    if (!key) return;
    const conditionField = key === "artifact_type" ? "artifact.type" : key === "parser" ? "artifact.parser" : key === "host" ? "host.name" : key === "user" ? "user.name" : key;
    if (["artifact.type", "artifact.parser", "host.name", "user.name", "source_file"].includes(conditionField)) {
      addBuilderCondition({ field: conditionField, operator: "is", value, negate: mode === "exclude" });
      return;
    }
    updateParams({ [key]: value, tab: field === "status" ? "findings" : state.tab });
  }

  function resultTimestampMs(result: SearchV2Result) {
    const raw = asRecord(result.raw);
    const timestampStatus = asString(raw.timestamp_status);
    if (timestampStatus === "suspicious" || timestampStatus === "invalid") return null;
    const timestamp = asString(result.timestamp || raw["@timestamp"]);
    const parsed = Date.parse(timestamp);
    return Number.isNaN(parsed) ? null : parsed;
  }

  async function handleAroundEvent(result: SearchV2Result, windowMs: number) {
    if (!resolvedCaseId) return;
    const raw = asRecord(result.raw);
    const evidenceId = asString(raw.evidence_id) || searchRequestState.evidence_id;
    const parsed = resultTimestampMs(result);
    const params = new URLSearchParams();
    params.set("scope", "all");
    params.set("tab", "results");
    params.set("sort", "@timestamp");
    params.set("order", "asc");
    params.set("page_size", String(state.page_size));
    params.set("selected", result.id);
    if (evidenceId) params.set("evidence_id", evidenceId);
    if (searchRequestState.filters.length) params.set("filters", serializeBuilderFilters(searchRequestState.filters));
    if (searchRequestState.exclude_q) params.set("exclude_q", searchRequestState.exclude_q);
    if (searchRequestState.artifact_type.length) params.set("artifact_type", joinParam(searchRequestState.artifact_type));
    if (searchRequestState.parser.length) params.set("parser", joinParam(searchRequestState.parser));
    if (searchRequestState.backend_variant.length) params.set("backend_variant", joinParam(searchRequestState.backend_variant));
    if (searchRequestState.parser_backend.length) params.set("parser_backend", joinParam(searchRequestState.parser_backend));
    if (searchRequestState.exclude_artifact_type.length) params.set("exclude_artifact_type", joinParam(searchRequestState.exclude_artifact_type));
    if (searchRequestState.exclude_parser.length) params.set("exclude_parser", joinParam(searchRequestState.exclude_parser));
    if (searchRequestState.host) params.set("host", searchRequestState.host);
    if (searchRequestState.user) params.set("user", searchRequestState.user);
    if (searchRequestState.exclude_host) params.set("exclude_host", searchRequestState.exclude_host);
    if (searchRequestState.exclude_user) params.set("exclude_user", searchRequestState.exclude_user);
    if (searchRequestState.exclude_source_file) params.set("exclude_source_file", searchRequestState.exclude_source_file);
    if (parsed !== null) {
      params.set("time_from", new Date(parsed - windowMs).toISOString());
      params.set("time_to", new Date(parsed + windowMs).toISOString());
    }
    navigate(`/cases/${resolvedCaseId}/search?${params.toString()}`);
  }

  async function handleRelatedFinding(result: SearchV2Result) {
    if (!resolvedCaseId) return;
    const data = await api.searchRelatedToFinding(resolvedCaseId, result.id, { page_size: 100 });
    setContextResponse(data);
    setContextLabel(`Events related to ${result.title}`);
  }

  function makeRelatedFilterAction(label: string, field: string, value: unknown, operator: FilterOperator = "is"): RowAction | null {
    const text = asString(value).trim();
    if (!text || text === "-") return null;
    return {
      label,
      value: text,
      ariaLabel: label,
      onClick: () => addBuilderCondition({ field, operator, value: text, negate: false }),
    };
  }

  function buildRelatedActivityActions(result: SearchV2Result): RowAction[] {
    if (result.kind !== "event") return [];
    const raw = asRecord(result.raw);
    const summary = summarizeResult(result);
    const event = asRecord(raw.event);
    const windows = asRecord(raw.windows);
    const artifact = asRecord(raw.artifact);
    const process = asRecord(raw.process);
    const parentProcess = asRecord(process.parent);
    const hasTimestamp = resultTimestampMs(result) !== null;
    const actions: Array<RowAction | null> = [
      { label: "Around this event · ±30s", onClick: () => void handleAroundEvent(result, 30 * 1000), disabled: !hasTimestamp, value: hasTimestamp ? formatTimestamp(result.timestamp, "UTC") : "No valid forensic timestamp" },
      { label: "Around this event · ±5m", onClick: () => void handleAroundEvent(result, 5 * 60 * 1000), disabled: !hasTimestamp, value: hasTimestamp ? formatTimestamp(result.timestamp, "UTC") : "No valid forensic timestamp" },
      { label: "Around this event · ±30m", onClick: () => void handleAroundEvent(result, 30 * 60 * 1000), disabled: !hasTimestamp, value: hasTimestamp ? formatTimestamp(result.timestamp, "UTC") : "No valid forensic timestamp" },
      makeRelatedFilterAction("Same host", "host.name", summary.primaryHost),
      makeRelatedFilterAction("Same user", "user.name", summary.primaryUser),
      makeRelatedFilterAction("Same process", "process.name", process.name || summary.primaryProcess),
      makeRelatedFilterAction("Same process PID", "process.pid", process.pid),
      makeRelatedFilterAction("Same process entity", "process.entity_id", process.entity_id || process.guid),
      makeRelatedFilterAction("Same command line", "process.command_line", process.command_line, "contains"),
      makeRelatedFilterAction("Same parent process", "parent.process.name", process.parent_name || parentProcess.name),
      makeRelatedFilterAction("Same parent PID", "parent.process.pid", process.parent_pid || parentProcess.pid),
      makeRelatedFilterAction("Same source file", "source_file", result.source_file || raw.source_file, "contains"),
      makeRelatedFilterAction("Same artifact type", "artifact.type", result.artifact_type || artifact.type),
      makeRelatedFilterAction("Same parser", "artifact.parser", result.parser || artifact.parser),
      makeRelatedFilterAction("Same Windows event ID", "windows.event_id", windows.event_id || event.id),
      makeRelatedFilterAction("Same event ID", "event.id", raw.event_id || event.id),
    ];
    return actions.filter((item): item is RowAction => Boolean(item));
  }

  function buildActions(result: SearchV2Result): RowAction[] {
    const raw = asRecord(result.raw);
    const summary = summarizeResult(result);
    const process = asRecord(raw.process);
    const marking = getResultMarking(result);
    const processNodeIds = Array.isArray(raw.related_process_node_ids) ? (raw.related_process_node_ids as string[]) : [];
    const evidenceId = asString(raw.evidence_id);
    const pid = asString(asRecord(raw.process).pid);
    const processGuid = asString(process.entity_id) || asString(process.guid) || processNodeIds[0] || "";
    const sourceEventId = asString(raw.search_doc_id) || asString(raw.id) || result.id;
    const timestamp = asString(raw["@timestamp"]) || asString(raw.timestamp) || result.timestamp || "";
    const processName = summary.primaryProcess;
    const host = asString(summary.primaryHost) || asString(result.host) || asString(asRecord(raw.host).name);
    const actions: RowAction[] = [];

    if (result.kind === "finding") {
      actions.push({ label: "Open finding", onClick: () => navigate(`/cases/${resolvedCaseId}/findings?finding_id=${result.id}`) });
      const findingTimelineParams = new URLSearchParams();
      findingTimelineParams.set("mode", "investigation");
      findingTimelineParams.set("finding_id", result.id);
      if (evidenceId || searchRequestState.evidence_id) findingTimelineParams.set("evidence_id", evidenceId || searchRequestState.evidence_id);
      actions.push({ label: "Open in Search Timeline", onClick: () => navigate(`/cases/${resolvedCaseId}/timeline?${findingTimelineParams.toString()}`) });
      actions.push({ label: "Search related", onClick: () => void handleRelatedFinding(result), ariaLabel: "Search related finding events" });
    } else {
      const hasTimestamp = resultTimestampMs(result) !== null;
      actions.push({ label: "Show ±30 sec", onClick: () => void handleAroundEvent(result, 30 * 1000), ariaLabel: "Show ±30 seconds around this event", disabled: !hasTimestamp });
      actions.push({ label: "Show ±5 min", onClick: () => void handleAroundEvent(result, 5 * 60 * 1000), ariaLabel: "Show ±5 minutes around this event", disabled: !hasTimestamp });
      actions.push({ label: "Show ±30 min", onClick: () => void handleAroundEvent(result, 30 * 60 * 1000), ariaLabel: "Show ±30 minutes around this event", disabled: !hasTimestamp });
      if (!hasTimestamp) actions.push({ label: "No valid forensic timestamp", onClick: () => undefined, disabled: true });
      actions.push({ label: "Open details", onClick: () => handleSelect(result), ariaLabel: "Open details" });
      actions.push({ label: "Mark suspicious", onClick: () => markEventMutation.mutate({ result, status: "suspicious" }), ariaLabel: "Mark suspicious" });
      actions.push({ label: "Mark important", onClick: () => markEventMutation.mutate({ result, status: "important" }), ariaLabel: "Mark important" });
      actions.push({ label: "Mark reviewed", onClick: () => markEventMutation.mutate({ result, status: "reviewed" }), ariaLabel: "Mark reviewed" });
      actions.push({ label: "False positive", onClick: () => markEventMutation.mutate({ result, status: "false_positive" }), ariaLabel: "Mark false positive" });
      actions.push({
        label: "Add note",
        onClick: () => {
          const note = window.prompt("Analyst note", marking?.note ?? "");
          if (note === null) return;
          markEventMutation.mutate({ result, status: marking?.status ?? "important", note });
        },
        ariaLabel: "Add analyst note",
      });
      actions.push({
        label: "Edit labels",
        onClick: () => {
          const labelText = window.prompt("Labels, comma separated", marking?.labels?.join(", ") ?? "");
          if (labelText === null) return;
          const labels = labelText.split(",").map((item) => item.trim()).filter(Boolean);
          markEventMutation.mutate({ result, status: marking?.status ?? "important", labels });
        },
        ariaLabel: "Edit event labels",
      });
      actions.push({
        label: "Add to finding",
        onClick: () => {
          const findingId = window.prompt("Finding ID to attach", marking?.finding_id ?? "");
          if (!findingId) return;
          markEventMutation.mutate({ result, status: marking?.status ?? "important", findingId });
        },
        ariaLabel: "Add to finding",
      });
      if (marking?.id) {
        actions.push({ label: "Clear marking", onClick: () => deleteMarkingMutation.mutate(marking.id), ariaLabel: "Clear event marking" });
      }
      actions.push({ label: "Copy event ID", onClick: () => void copyToClipboard(result.id), ariaLabel: "Copy event ID" });
      actions.push({ label: "Copy raw JSON", onClick: () => void copyToClipboard(JSON.stringify(raw, null, 2)), ariaLabel: "Copy raw JSON" });
    }
    if (processNodeIds.length || processName || pid || processGuid || sourceEventId) {
      const buildProcessParams = (modeValue: string) => {
        const params = new URLSearchParams();
        params.set("mode", modeValue);
        if (evidenceId) params.set("evidence_id", evidenceId);
        if (host && host !== "-") params.set("host", host);
        if (pid) params.set("pid", pid);
        if (processGuid) params.set("process_guid", processGuid);
        if (sourceEventId) {
          params.set("source_event_id", sourceEventId);
          params.set("story_event_id", sourceEventId);
          params.set("from_search_event_id", sourceEventId);
        }
        if (timestamp) params.set("timestamp", timestamp);
        if (processName) params.set("process_name", processName);
        if (result.kind === "finding") params.set("finding_id", result.id);
        for (const nodeId of processNodeIds) params.append("node_id", nodeId);
        return params;
      };
      const storyParams = buildProcessParams("execution_story");
      actions.push({
        label: "Open execution story",
        ariaLabel: "Open execution story for this exact event",
        onClick: () => navigate(`/cases/${resolvedCaseId}/process-graph?${storyParams.toString()}`),
      });
      const commandHistoryParams = new URLSearchParams();
      if (evidenceId) commandHistoryParams.set("evidence_id", evidenceId);
      if (host && host !== "-") commandHistoryParams.set("host", host);
      if (processGuid) commandHistoryParams.set("process_guid", processGuid);
      if (pid) commandHistoryParams.set("pid", pid);
      if (sourceEventId) commandHistoryParams.set("source_event_id", sourceEventId);
      if (processName) commandHistoryParams.set("q", processName);
      actions.push({
        label: "Open Command History",
        ariaLabel: "Open Command History for this process",
        onClick: () => navigate(`/cases/${resolvedCaseId}/command-history?${commandHistoryParams.toString()}`),
      });
      const graphParams = buildProcessParams(result.kind === "finding" ? "finding_focus" : "process_focus");
      actions.push({
        label: "Open advanced process graph",
        ariaLabel: "Open advanced process graph",
        onClick: () => navigate(`/cases/${resolvedCaseId}/process-graph?${graphParams.toString()}`),
      });
    }
    return actions;
  }

  function renderPaginationControls(position: "top" | "bottom") {
    return (
      <div
        data-testid={`search-pagination-${position}`}
        className={`${position === "bottom" ? "sticky bottom-0 z-10 bg-panel/90 backdrop-blur" : ""} flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line px-4 py-3`}
      >
        <p className="text-xs text-muted">
          {results.length ? `Showing ${pageStart}-${pageEnd} of ${response?.total ?? results.length} · Page ${currentPage}` : `Page ${currentPage}`}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {pageSizeClampNotice ? <span className="rounded-full border border-warning/40 bg-warning/10 px-3 py-1 text-[11px] text-warning">Requested page size exceeded the backend maximum. Using {SEARCH_UI_MAX_PAGE_SIZE}.</span> : null}
          <label className="text-xs text-muted">
            Page size
            <select
              aria-label={`Page size ${position}`}
              value={String(state.page_size)}
              onChange={(event) => {
                setPageSizeClampNotice(false);
                updateParams({ page_size: event.target.value });
              }}
              className="ml-2 rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs"
            >
              {pageSizeOptions.map((value) => (
                <option key={`${position}-${value}`} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            aria-label={`Previous page ${position}`}
            disabled={currentPage <= 1 || paginationLocked}
            onClick={() => {
              updateParams({ page: String(Math.max(1, currentPage - 1)) });
            }}
            className="rounded-xl border border-line px-3 py-2 text-xs text-muted disabled:opacity-40"
          >
            Previous
          </button>
          <button
            type="button"
            aria-label={`Next page ${position}`}
            disabled={!hasNextPage || paginationLocked}
            onClick={() => {
              updateParams({ page: String(currentPage + 1) });
            }}
            className="rounded-xl border border-line px-3 py-2 text-xs text-muted disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    );
  }

  if (!resolvedCaseId) {
    return (
      <section className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Search UI v2</p>
        <h2 className="mt-2 text-2xl font-semibold">Investigation Search</h2>
        <p className="mt-4 text-sm text-muted">Select an active case first. Search is case-scoped to avoid cross-case leakage.</p>
      </section>
    );
  }

  return (
    <div className="min-w-0 w-full max-w-none space-y-6 overflow-x-hidden">
      <section className="min-w-0 rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Search UI v2</p>
        <h2 className="mt-2 text-2xl font-semibold">Investigation Search</h2>
        <p className="mt-2 text-sm text-muted">Compact investigation workspace with tables, pivots and artifact-specific views.</p>

        <div className="mt-5 grid gap-3 lg:grid-cols-[1fr,180px,180px,auto,auto]">
          <div className="min-w-0">
            <SearchBar ariaLabel="Search query" value={queryInput} onChange={setQueryInput} placeholder="Search commands, paths, hashes, domains or text" />
            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted">
              <button type="button" onClick={() => setSyntaxHelpOpen((current) => !current)} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">
                {syntaxHelpOpen ? "Hide search syntax" : "Search syntax"}
              </button>
              <span>Flags like -ep and -nop are treated as text. Field syntax is optional.</span>
            </div>
            {parsedSearchError?.inline ? (
              <div data-testid="search-query-error" className="mt-3 rounded-2xl border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
                <p>{parsedSearchError.message}</p>
                {parsedSearchError.examples.length ? (
                  <div className="mt-2 space-y-1 text-xs">
                    <p className="font-mono uppercase tracking-[0.14em] text-danger/80">Examples</p>
                    {parsedSearchError.examples.map((example) => (
                      <p key={example} className="font-mono text-danger/90">
                        {example}
                      </p>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
            {syntaxHelpOpen ? (
              <div data-testid="search-syntax-help" className="mt-3 rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Supported syntax</p>
                <div className="mt-3 space-y-1 font-mono text-xs text-slate-200">
                  <p>artifact.type:ntfs risk_score&gt;=70</p>
                  <p>process.name:powershell.exe EncodedCommand</p>
                  <p>file.name:"invoice.docm"</p>
                  <p>host.name:"TEST-WIN10-01"</p>
                  <p>email.from.domain:suspicious.example</p>
                  <p>detection.source:sigma</p>
                  <p>stable_event_id:5e9c...</p>
                </div>
              </div>
            ) : null}
          </div>
          <SelectField label="Scope" value={state.scope} options={scopeOptions} onChange={(value) => updateParams({ scope: value })} />
          <SelectField label="Sort" value={state.sort} options={sortOptions} onChange={(value) => updateBackendSort(value as SortValue)} />
          <button type="button" onClick={applySearchNow} className="self-end rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent">
            Search
          </button>
          <button type="button" onClick={resetFilters} className="self-end rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted">
            Clear filters
          </button>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-6">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source</span>
            <select aria-label="Source category" value={state.source_category} onChange={(event) => updateParams({ source_category: event.target.value, source: null })} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" data-testid="search-source-category-filter">
              {sourceCategoryOptions.map((option) => (
                <option key={option.label} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact type</span>
            <select aria-label="Artifact type" value={state.artifact_type[0] ?? ""} onChange={(event) => updateParams({ artifact_type: event.target.value })} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
              <option value="">Any</option>
              {Object.keys(globalFacets.artifact_type ?? response?.facets?.artifact_type ?? {}).map((option) => (
                <option key={option} value={option}>
                  {formatFacetOption(option, globalFacets.artifact_type)}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Parser</span>
            <select aria-label="Parser" value={state.parser[0] ?? ""} onChange={(event) => updateParams({ parser: event.target.value })} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
              <option value="">Any</option>
              {Object.keys(globalFacets.parser ?? response?.facets?.parser ?? {}).map((option) => (
                <option key={option} value={option}>
                  {formatFacetOption(option, globalFacets.parser)}
                </option>
              ))}
            </select>
          </label>
          <TextField label="Source file" value={state.source_file} onChange={(value) => updateParams({ source_file: value })} placeholder="Security.evtx" />
          <TextField label="Host" value={state.host} onChange={(value) => updateParams({ host: value })} placeholder="TEST-WIN10-01" />
          <TextField label="User" value={state.user} onChange={(value) => updateParams({ user: value })} placeholder="user01" />
          <TextField label="Evidence" value={searchRequestState.evidence_id} onChange={(value) => updateParams({ evidence_id: value })} placeholder="evidence id" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <TimeField label="Time from" value={state.time_from} onChange={(value) => updateParams({ time_from: value })} />
          <TimeField label="Time to" value={state.time_to} onChange={(value) => updateParams({ time_to: value })} />
          <div className="xl:col-span-2">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Time presets</span>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => applyTimePreset("24h")} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">Last 24h</button>
              <button type="button" onClick={() => applyTimePreset("7d")} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">Last 7d</button>
              <button type="button" onClick={() => applyTimePreset("30d")} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">Last 30d</button>
              <button type="button" onClick={() => applyTimePreset("clear")} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">Clear time</button>
            </div>
            <details className="mt-3 text-xs text-muted">
              <summary className="cursor-pointer">Advanced ISO input</summary>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <TextField label="Time from ISO" value={state.time_from} onChange={(value) => updateParams({ time_from: value })} placeholder="2026-05-15T10:00:00Z" />
                <TextField label="Time to ISO" value={state.time_to} onChange={(value) => updateParams({ time_to: value })} placeholder="2026-05-15T12:00:00Z" />
              </div>
            </details>
          </div>
        </div>
        {(state.time_from || state.time_to) ? (
          <div className={`mt-4 rounded-2xl border px-4 py-3 text-sm ${timeRangeInvalid ? "border-danger/40 bg-danger/10 text-danger" : "border-line bg-abyss/60 text-muted"}`}>
            {timeRangeInvalid ? "Invalid time range: start time must be before end time." : "Some documents do not have a valid forensic timestamp and are excluded from time filters."}
          </div>
        ) : null}

        <div data-testid="risk-filter-panel" className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[180px] flex-1">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Risk range</span>
              <div className="flex flex-wrap gap-2">
                {riskPresets.map((preset) => (
                  <button key={preset.label} type="button" aria-label={`Risk preset ${preset.label}`} onClick={() => applyRiskPreset(preset.min, preset.max)} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:bg-white/5">
                    {preset.label} · {preset.min}-{preset.max}
                  </button>
                ))}
                <button type="button" onClick={clearRisk} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">
                  Clear risk
                </button>
              </div>
            </div>
            <div className="grid min-w-[220px] grid-cols-2 gap-3">
              <NumberField label="Risk min" value={state.risk_min} onChange={(value) => updateParams({ risk_min: value })} />
              <NumberField label="Risk max" value={state.risk_max} onChange={(value) => updateParams({ risk_max: value })} />
            </div>
          </div>
        </div>

        <div data-testid="event-marking-filter-panel" className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[220px] flex-1">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Analyst markings</span>
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => updateParams({ marked_only: state.marked_only === "true" ? null : "true" })} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:bg-white/5">
                  Marked only
                </button>
                <button type="button" onClick={() => updateParams({ marked_has_note: state.marked_has_note === "true" ? null : "true" })} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:bg-white/5">
                  Has note
                </button>
                <button type="button" onClick={() => updateParams({ marked_in_finding: state.marked_in_finding === "true" ? null : "true" })} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:bg-white/5">
                  In finding
                </button>
                <button type="button" onClick={() => updateParams({ marked_only: "true", tab: "timeline", sort: "@timestamp", order: "asc" })} className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent">
                  Marked timeline
                </button>
              </div>
            </div>
            <label className="min-w-[220px]">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Review status</span>
              <select aria-label="Marking status" value={state.marking_status} onChange={(event) => updateParams({ marking_status: event.target.value, marked_only: event.target.value ? "true" : state.marked_only || null })} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
                <option value="">Any marking</option>
                {eventMarkingStatusOptions.map((status) => (
                  <option key={status} value={status}>{markingLabel(status)}</option>
                ))}
              </select>
            </label>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" aria-label="Advanced filters" onClick={() => setAdvancedOpen((current) => !current)} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">
            {advancedOpen ? "Hide advanced filters" : "Advanced filters"}
          </button>
          <button type="button" onClick={() => setAdvancedOpen(true)} className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent">
            Add filter
          </button>
          <button type="button" aria-label="Toggle facets" onClick={() => setFacetsOpen((current) => !current)} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">
            {facetsOpen ? "Hide facets" : "Facets"}
          </button>
          {(state.exclude_q || state.exclude_artifact_type.length || state.exclude_parser.length || state.exclude_source_file || state.exclude_host || state.exclude_user) ? (
            <button type="button" onClick={clearExclusions} className="rounded-full border border-warning/40 bg-warning/10 px-3 py-1.5 text-xs text-warning">
              Clear exclusions
            </button>
          ) : null}
          {(quickFiltersQuery.data?.items ?? []).map((item) => (
            <button key={item.id} type="button" onClick={() => applyQuickFilter(item)} className="rounded-full border border-line px-3 py-1.5 text-xs text-muted">
              {item.label}
            </button>
          ))}
        </div>

        {pageSizeClampNotice ? (
          <div className="mt-4 rounded-2xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning">
            Requested page size exceeded the backend maximum. Using {SEARCH_UI_MAX_PAGE_SIZE}.
          </div>
        ) : null}

        {activeFilterChips.length ? (
          <div data-testid="active-filter-chips" className="mt-4 flex flex-wrap gap-2">
            {activeFilterChips.map((chip) => (
              <button key={chip.key} type="button" onClick={() => updateParams(chip.clear)} className="rounded-full border border-accent/30 bg-accent/8 px-3 py-1.5 text-xs text-slate-200">
                {chip.label} ×
              </button>
            ))}
          </div>
        ) : null}

        {querySyntaxChips.length ? (
          <div data-testid="query-syntax-chips" className="mt-4 flex flex-wrap gap-2">
            {querySyntaxChips.map((chip) => (
              <span key={chip.id} className="rounded-full border border-line bg-white/5 px-3 py-1.5 text-xs text-slate-200">
                {chip.label}
              </span>
            ))}
          </div>
        ) : null}

        {advancedOpen ? (
          <div data-testid="advanced-filters-panel" className="mt-5 space-y-5">
            <div className="rounded-2xl border border-line bg-abyss/60 p-4">
              <div className="flex flex-wrap items-end gap-3">
                <label className="min-w-[180px] flex-1">
                  <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Field</span>
                  <select aria-label="Filter field" value={draftCondition.field} onChange={(event) => setDraftCondition((current) => ({ ...current, field: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
                    {filterFieldOptions.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
                <label className="min-w-[170px]">
                  <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Operator</span>
                  <select
                    aria-label="Filter operator"
                    value={draftCondition.operator}
                    onChange={(event) => setDraftCondition((current) => ({ ...current, operator: event.target.value as FilterOperator, value: noValueOperators.has(event.target.value as FilterOperator) ? "" : current.value }))}
                    className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
                  >
                    {filterOperators.map((operator) => (
                      <option key={operator} value={operator}>{operator}</option>
                    ))}
                  </select>
                </label>
                {!noValueOperators.has(draftCondition.operator) ? (
                  <TextField label="Filter value" value={draftCondition.value} onChange={(value) => setDraftCondition((current) => ({ ...current, value }))} placeholder="powershell" />
                ) : null}
                <label className="flex items-center gap-2 rounded-2xl border border-line px-4 py-3 text-sm text-muted">
                  <input aria-label="Exclude condition" type="checkbox" checked={Boolean(draftCondition.negate)} onChange={(event) => setDraftCondition((current) => ({ ...current, negate: event.target.checked }))} />
                  Exclude
                </label>
                <button type="button" onClick={() => addBuilderCondition(draftCondition)} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent">
                  Add condition
                </button>
              </div>
              {filterBuilderError ? <p className="mt-3 text-sm text-danger">{filterBuilderError}</p> : null}
              {state.filters.length ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  {state.filters.map((condition, index) => (
                    <button key={`${condition.field}-${condition.operator}-${condition.value}-${index}`} type="button" onClick={() => removeBuilderCondition(index)} className="rounded-full border border-accent/30 bg-accent/8 px-3 py-1.5 text-xs text-slate-200">
                      {filterConditionLabel(condition)} ×
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <SelectField label="Severity" value={state.severity[0] ?? ""} options={severityOptions} onChange={(value) => updateParams({ severity: value })} />
              <SelectField label="Finding status" value={state.status[0] ?? ""} options={findingStatusOptions} onChange={(value) => updateParams({ status: value })} />
              <TextField label="Process" value={state.process_name} onChange={(value) => updateParams({ process_name: value })} placeholder="powershell.exe" />
              <TextField label="Domain" value={state.domain} onChange={(value) => updateParams({ domain: value })} placeholder="suspicious.example" />
              <TextField label="IP" value={state.ip} onChange={(value) => updateParams({ ip: value })} placeholder="198.51.100.10" />
              <TextField label="File path" value={state.file_path} onChange={(value) => updateParams({ file_path: value })} placeholder="C:\\Users\\user01\\Downloads\\payload.exe" />
              <TextField label="File name" value={state.file_name} onChange={(value) => updateParams({ file_name: value })} placeholder="payload.exe" />
              <TextField label="Hash" value={state.hash} onChange={(value) => updateParams({ hash: value })} placeholder="SHA256 / SHA1 / MD5" />
              <SelectField label="Backend variant" value={state.backend_variant[0] ?? ""} options={["default", "advanced", "all"]} onChange={(value) => updateParams({ backend_variant: value })} />
              <TextField label="Parser backend" value={state.parser_backend[0] ?? ""} onChange={(value) => updateParams({ parser_backend: value })} placeholder="amcacheparser_csv" />
            </div>
          </div>
        ) : null}
      </section>

      {contextLabel ? (
        <section className="min-w-0 rounded-2xl border border-accent/30 bg-accent/8 p-4 text-sm text-slate-100">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span>{contextLabel}</span>
            <button type="button" onClick={() => { setContextResponse(null); setContextLabel(""); }} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
              Back to search query
            </button>
          </div>
        </section>
      ) : null}

      <div
        className={
          isUltraWideLayout
            ? `grid min-w-0 items-start gap-6 ${facetsOpen ? "grid-cols-[220px,minmax(0,1fr)]" : "grid-cols-1"}`
            : "min-w-0 space-y-6"
        }
      >
        {facetsOpen ? (
        <aside data-testid="facets-panel" className="space-y-4 2xl:w-[220px]">
          <div className="rounded-[24px] border border-line bg-panel/70 p-4 shadow-panel">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Facets</p>
            <div className="mt-4 space-y-4">
              {Object.entries(facetPanelFacets).map(([field, values]) =>
                Object.keys(values).length ? (
                  <div key={field}>
                    <p className="text-xs uppercase tracking-[0.14em] text-muted">{field.replaceAll("_", " ")}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {Object.entries(values)
                        .slice(0, 8)
                        .map(([value, count]) => (
                          <span key={`${field}-${value}`} className="inline-flex overflow-hidden rounded-full border border-line text-xs text-muted">
                            <button type="button" aria-label={`Include ${field} ${value}`} onClick={() => handleFacetClick(field, value, "include")} className="px-2 py-1 hover:bg-white/5">
                              + {value} · {count}
                            </button>
                            {["artifact_type", "artifact.type", "parser", "artifact.parser", "source_file", "host", "host.name", "user", "user.name"].includes(field) ? (
                              <button type="button" aria-label={`Exclude ${field} ${value}`} onClick={() => handleFacetClick(field, value, "exclude")} className="border-l border-line px-2 py-1 text-warning hover:bg-warning/10">
                                -
                              </button>
                            ) : null}
                          </span>
                        ))}
                    </div>
                  </div>
                ) : null,
              )}
            </div>
          </div>

          {response?.warnings?.length ? (
            <div className="rounded-[24px] border border-warning/30 bg-warning/10 p-5 text-sm text-warning">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Warnings</p>
              <ul className="mt-3 space-y-1">
                {response.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </aside>
        ) : null}

        <section className="min-w-0 space-y-4">
          <div className="rounded-[24px] border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Workspace</p>
                <p className="mt-1 text-sm text-muted">
                  {searchQuery.isLoading && !contextResponse
                    ? "Searching…"
                    : results.length
                      ? `Showing ${pageStart}-${pageEnd} of ${response?.total ?? results.length} matches`
                      : `${response?.total ?? 0} matches`}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <label className="text-xs text-muted">
                  Density
                  <select aria-label="Density" value={density} onChange={(event) => setDensity(event.target.value as TableDensity)} className="ml-2 rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs">
                    <option value="compact">Compact</option>
                    <option value="comfortable">Comfortable</option>
                    <option value="expanded">Expanded</option>
                  </select>
                </label>
                <div className="flex gap-2">
                  {searchTabs.map((item) => (
                    <button key={item.id} type="button" onClick={() => updateParams({ tab: item.id })} className={`rounded-full px-3 py-1.5 text-xs ${state.tab === item.id ? "bg-accent text-abyss" : "border border-line text-muted"}`}>
                      {item.label}
                    </button>
                  ))}
                </div>
                {state.tab === "timeline" ? (
                  <label className="flex items-center gap-2 rounded-full border border-line px-3 py-1.5 text-xs text-muted">
                    <input
                      type="checkbox"
                      checked={state.include_filesystem_timeline === "true"}
                      onChange={(event) => updateParams({ include_filesystem_timeline: event.target.checked ? "true" : null, tab: "timeline" })}
                    />
                    Include filesystem/MFT events
                  </label>
                ) : null}
              </div>
            </div>
            <div className="mt-4">{renderPaginationControls("top")}</div>
          </div>

          {searchQuery.isLoading && !response ? <div className="rounded-[24px] border border-line bg-panel/70 p-6 text-sm text-muted shadow-panel">Loading investigation results…</div> : null}
          {searchQuery.isError && !parsedSearchError?.inline ? <div className="rounded-[24px] border border-danger/40 bg-danger/10 p-6 text-sm text-danger shadow-panel">{parsedSearchError?.message ?? (searchQuery.error as Error).message}</div> : null}
          {!searchQuery.isLoading && !searchQuery.isError && hasFalseEmptyPage ? (
            <div className="rounded-[24px] border border-warning/40 bg-warning/10 p-6 text-sm text-warning shadow-panel">
              <p className="font-medium text-warning">Pagination returned an empty page</p>
              <p className="mt-2">There are {response?.total ?? 0} matching results, but page {currentPage} returned none. Go back one page or narrow the query.</p>
            </div>
          ) : null}
          {!searchQuery.isLoading && !searchQuery.isError && !results.length && !hasFalseEmptyPage ? (
            <div className="rounded-[24px] border border-line bg-panel/70 p-6 text-sm text-muted shadow-panel">
              <p className="font-medium text-slate-100">No results yet</p>
              <p className="mt-2">Try a quick filter, a full path, domain, IOC or process name.</p>
            </div>
          ) : null}
          {groupedSearchSummary ? (
            <div className="rounded-[24px] border border-line bg-panel/70 p-5 text-sm shadow-panel" data-testid="search-grouped-summary">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Grouped summary</p>
                  <p className="mt-1 text-muted">{response?.total ?? results.length} results found. Use these groups to narrow broad terms without leaving Search.</p>
                </div>
                <button type="button" onClick={() => setFacetsOpen(true)} className="rounded-full border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">Open facets</button>
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-3">
                {[
                  ["Host", groupedSearchSummary.hosts],
                  ["Artifact", groupedSearchSummary.artifacts],
                  ["Source file", groupedSearchSummary.sourceFiles],
                ].map(([label, values]) => (
                  <div key={String(label)} className="rounded-2xl border border-line bg-abyss/60 p-3">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{String(label)}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {(values as Array<{ key: string; count: number }>).length ? (values as Array<{ key: string; count: number }>).map((item) => (
                        <span key={`${label}-${item.key}`} className="rounded-full border border-line bg-panel/50 px-2 py-1 text-xs text-muted">{item.key} · {item.count}</span>
                      )) : <span className="text-xs text-muted">No grouping value</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {!searchQuery.isError && results.length ? (
            <>
              {state.tab === "results" ? (
                <SearchTable results={results} columns={genericResultColumns} selectedId={selectedId} onSelect={handleSelect} actionBuilder={buildActions} pivotRenderer={renderPivotValue} testId="results-table" density={density} sort={state.sort} onSortChange={updateBackendSort} />
              ) : null}

              {state.tab === "findings" ? (
                <SearchTable results={findingResults} columns={genericResultColumns} selectedId={selectedId} onSelect={handleSelect} actionBuilder={buildActions} pivotRenderer={renderPivotValue} testId="findings-table" density={density} sort={state.sort} onSortChange={updateBackendSort} />
              ) : null}

              {state.tab === "artifact_views" ? (
                <div className="space-y-3">
                <div className="min-w-0 rounded-[24px] border border-line bg-panel/70 p-4 shadow-panel">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact view</p>
                    <p className="mt-2 text-sm text-muted">Using <span className="font-medium text-slate-200">{activeView}</span> columns for the current result set.</p>
                  </div>
                  <SearchTable results={eventResults} columns={artifactColumns} selectedId={selectedId} onSelect={handleSelect} actionBuilder={buildActions} pivotRenderer={renderPivotValue} testId="artifact-view-table" density={density} sort={state.sort} onSortChange={updateBackendSort} />
                </div>
              ) : null}

              {state.tab === "timeline" ? (
                <div data-testid="timeline-view" className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search Timeline</p>
                  <p className="mt-2 text-sm text-muted">Explore matching Search results over time. This is a filtered event view, not the curated Incident Timeline.</p>
                  <div className="mt-4 space-y-4">
                    {results
                      .slice()
                      .sort((left, right) => asString(left.timestamp).localeCompare(asString(right.timestamp)))
                      .map((result) => {
                        const summary = summarizeResult(result);
                        return (
                          <button key={`${result.kind}-${result.id}`} type="button" onClick={() => handleSelect(result)} className="flex w-full items-start gap-4 rounded-2xl border border-line bg-abyss/50 p-4 text-left hover:bg-white/5">
                            <div className="w-40 shrink-0 text-xs text-muted">{formatTimestamp(result.timestamp, "UTC")}</div>
                            <div className="mt-1 h-3 w-3 shrink-0 rounded-full bg-accent" />
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap gap-2">
                                <ResultBadge tone={riskTone(result.risk_score)}>{String(result.risk_score ?? 0)}</ResultBadge>
                                <ResultBadge tone={result.kind === "finding" ? "success" : "default"}>{result.kind}</ResultBadge>
                                <ResultBadge tone="muted">{applyCellFallbacks(result.artifact_type)}</ResultBadge>
                                <MarkingBadge marking={getResultMarking(result)} />
                              </div>
                              <div className="mt-2 font-medium text-slate-100">{result.title}</div>
                              <div className="mt-1 truncate text-sm text-muted" title={summary.compactMessage}>{summary.compactMessage}</div>
                            </div>
                          </button>
                        );
                      })}
                  </div>
                </div>
              ) : null}

              {renderPaginationControls("bottom")}
            </>
          ) : null}
        </section>

      </div>

      {selectedResult ? (
        <ResponsiveDetailPanel
          open
          mode={detailMode}
          widthClass={detailDrawerWidth}
          heading="Search detail"
          subheading="Investigation detail aligned with Findings, Timeline and Detections."
          onClose={closeSelectedResult}
        >
          <DetailPanel
            result={selectedResult}
            mode="drawer"
            showCloseButton={false}
            onClose={closeSelectedResult}
            actions={selectedResult ? buildActions(selectedResult) : []}
            relatedActions={selectedResult ? buildRelatedActivityActions(selectedResult) : []}
            pivotRenderer={renderPivotValue}
            eventContext={eventContextQuery.data ?? null}
            eventContextLoading={eventContextQuery.isLoading}
          />
        </ResponsiveDetailPanel>
      ) : null}
    </div>
  );
}
