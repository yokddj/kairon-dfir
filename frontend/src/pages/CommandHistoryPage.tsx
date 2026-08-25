import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type CommandHistoryItem } from "../api/client";
import { NumberField, SelectField, TextField } from "../components/FilterField";
import { InvestigationBreadcrumbs } from "../components/InvestigationContext";
import TimeField from "../components/TimeField";
import { useTimezonePreference } from "../context/TimezoneContext";
import { useHostContext } from "../hooks/useHostContext";
import { memoryEvidenceRoute, memoryWorkbenchRoute, windowsExecutionStoriesRoute } from "../lib/canonicalRoutes";
import { formatTimestamp } from "../lib/time";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

const PAGE_SIZE = 100;
const SOURCE_OPTIONS = ["Memory", "Disk", "Event Log", "Registry", "Browser", "Other"];

function valueOrDash(value: unknown): string {
  const text = String(value ?? "").trim();
  return text || "-";
}

function aroundEventWindow(item: CommandHistoryItem, windowMs: number): { time_from: string; time_to: string } | null {
  if (!item.timestamp) return null;
  const parsed = new Date(item.timestamp).getTime();
  if (Number.isNaN(parsed)) return null;
  return { time_from: new Date(parsed - windowMs).toISOString(), time_to: new Date(parsed + windowMs).toISOString() };
}

function riskLabel(score: number): string {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

function sourceLabel(item: CommandHistoryItem): string {
  const sources = item.supporting_events?.map((event) => event.source_type).filter(Boolean) ?? [];
  const unique = Array.from(new Set([item.source_category, item.source_plugin_or_parser, item.source_type, ...sources].filter(Boolean)));
  return unique.join(", ");
}

function SourceBadge({ item }: { item: CommandHistoryItem }) {
  const category = item.source_category || (item.source_type === "memory" ? "Memory" : "Disk");
  const producer = item.source_plugin_or_parser || item.source_type;
  return <span className="rounded-full border border-line bg-panel px-2 py-1 text-xs text-ink">{producer ? `${category}: ${producer}` : category}</span>;
}

function familyLabel(item: CommandHistoryItem): string {
  return valueOrDash(item.shell_family || item.shell);
}

function launcherLabel(item: CommandHistoryItem): string {
  return valueOrDash(item.launcher || item.process?.name || item.process?.executable);
}

function commandRowSourceEventId(item: CommandHistoryItem): string {
  return String(item.source_event_id || item.supporting_events?.[0]?.event_id || item.supporting_events?.[0]?.stable_event_id || "").trim();
}

function processGraphUrl(caseId: string, item: CommandHistoryItem): string {
  if (item.source_type === "linux_shell_history") return item.linked_search_url;
  if (item.source_category === "Memory" || item.source_type === "memory") {
    const params = new URLSearchParams();
    params.set("tab", "graph");
    if (item.run_id) params.set("run_id", item.run_id);
    if (item.process_entity_id || item.process?.guid) params.set("process_entity_id", item.process_entity_id || item.process?.guid || "");
    if (item.process?.pid !== undefined && item.process?.pid !== null) params.set("pid", String(item.process.pid));
    return item.evidence_id ? memoryEvidenceRoute(caseId, item.evidence_id, "overview", params) : memoryWorkbenchRoute(caseId, params);
  }
  const params = new URLSearchParams();
  const sourceEventId = commandRowSourceEventId(item);
  params.set("mode", "execution_story");
  params.set("origin", "command_history");
  params.set("command_history_row_id", item.id);
  if (item.evidence_id) params.set("evidence_id", item.evidence_id);
  if (item.host) params.set("host", item.host);
  if (item.process?.pid !== undefined && item.process?.pid !== null) params.set("pid", String(item.process.pid));
  if (item.process?.guid) params.set("process_guid", item.process.guid);
  if (item.process?.name || item.process?.executable) params.set("process_name", item.process.name || item.process.executable || "");
  if (sourceEventId) {
    params.set("source_event_id", sourceEventId);
    params.set("story_event_id", sourceEventId);
  }
  if (item.timestamp) params.set("timestamp", item.timestamp);
  return windowsExecutionStoriesRoute(caseId, params);
}

function buildParams(searchParams: URLSearchParams) {
  const sortOrder = searchParams.get("sort_order");
  const legacySort = searchParams.get("sort");
  const resolvedSort =
    legacySort === "timestamp_asc" || legacySort === "timestamp_desc"
      ? legacySort
      : sortOrder === "asc"
        ? "timestamp_asc"
        : "timestamp_desc";
  return {
    evidence_id: searchParams.get("evidence_id") || undefined,
    host: searchParams.get("host") || undefined,
    host_id: searchParams.get("host_id") || undefined,
    user: searchParams.get("user") || undefined,
    time_from: searchParams.get("time_from") || undefined,
    time_to: searchParams.get("time_to") || undefined,
    family: searchParams.get("family") || searchParams.get("shell") || undefined,
    launcher: searchParams.get("launcher") || undefined,
    source_type: searchParams.get("source_type") || undefined,
    source_category: searchParams.get("source_category") || searchParams.get("source") || undefined,
    pid: searchParams.get("pid") ? Number(searchParams.get("pid")) : undefined,
    process_name: searchParams.get("process_name") || undefined,
    q: searchParams.get("q") || undefined,
    risk_min: searchParams.get("risk_min") ? Number(searchParams.get("risk_min")) : undefined,
    risk_max: searchParams.get("risk_max") ? Number(searchParams.get("risk_max")) : undefined,
    only_suspicious: searchParams.get("only_suspicious") === "true" || undefined,
    has_supporting_sources: searchParams.get("has_supporting_sources") === "true" || undefined,
    page: searchParams.get("page") ? Number(searchParams.get("page")) : 1,
    page_size: searchParams.get("page_size") ? Number(searchParams.get("page_size")) : PAGE_SIZE,
    sort: resolvedSort as "timestamp_asc" | "timestamp_desc",
    sort_by: "timestamp" as const,
    sort_order: (resolvedSort === "timestamp_asc" ? "asc" : "desc") as "asc" | "desc",
  };
}

async function copyText(text: string) {
  const clipboard = window.navigator.clipboard;
  if (clipboard?.writeText) {
    await clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  if (typeof document.execCommand === "function") {
    document.execCommand("copy");
  }
  textarea.remove();
}

export default function CommandHistoryPage() {
  const { caseId = "" } = useParams();
  const breadcrumbs = useInvestigationBreadcrumbs();
  const { effectiveTimezone } = useTimezonePreference();
  const { activeHost, hasHostFilter, clearHostFilter } = useHostContext();
  const [searchParams, setSearchParams] = useSearchParams();
  const params = useMemo(() => buildParams(searchParams), [searchParams]);
  const [qDraft, setQDraft] = useState(params.q ?? "");
  const [data, setData] = useState<Awaited<ReturnType<typeof api.getCommandHistory>> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [marking, setMarking] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => setQDraft(params.q ?? ""), [params.q]);

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getCommandHistory(caseId, params)
      .then((response) => {
        if (!cancelled) setData(response);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [caseId, params]);

  function update(next: Record<string, string | number | boolean | undefined | null>) {
    const updated = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(next)) {
      if (value === undefined || value === null || value === "" || value === false) {
        updated.delete(key);
      } else {
        updated.set(key, String(value));
      }
    }
    if (!Object.prototype.hasOwnProperty.call(next, "page")) {
      updated.set("page", "1");
    }
    setSearchParams(updated);
  }

  async function markSuspicious(item: CommandHistoryItem) {
    const source = item.supporting_events?.[0];
    const eventId = String(source?.event_id || item.id);
    setMarking(item.id);
    try {
      await api.markEvent(eventId, {
        case_id: caseId,
        evidence_id: item.evidence_id ?? null,
        search_doc_id: eventId,
        artifact_type: source?.artifact_type ?? null,
        timestamp: item.timestamp ?? null,
        host: item.host ?? null,
        status: "suspicious",
        labels: ["command-history"],
        note: `Marked from Command History. Risk: ${item.risk_score}. ${item.risk_reasons.join("; ")}`,
      });
    } finally {
      setMarking(null);
    }
  }

  async function copyCommand(item: CommandHistoryItem) {
    await copyText(item.command);
    setCopiedId(item.id);
  }

  const items = data?.items ?? [];
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  const sortOrder = params.sort === "timestamp_asc" ? "asc" : "desc";
  const paginationControls = (
    <div className="flex flex-col gap-2 text-sm text-ink sm:flex-row sm:items-center sm:justify-between">
      <div>
        Page {data?.page ?? 1} of {totalPages} · {data?.total ?? 0} commands
      </div>
      <div className="flex gap-2">
        <button className="rounded border border-line px-3 py-2 disabled:opacity-40" disabled={(data?.page ?? 1) <= 1} onClick={() => update({ page: Math.max(1, (data?.page ?? 1) - 1) })}>
          Previous
        </button>
        <button className="rounded border border-line px-3 py-2 disabled:opacity-40" disabled={(data?.page ?? 1) >= totalPages} onClick={() => update({ page: (data?.page ?? 1) + 1 })}>
          Next
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-5">
      <InvestigationBreadcrumbs items={breadcrumbs} />
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">Case workspace</p>
          <h1 className="mt-1 text-2xl font-semibold text-ink">Command History</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted">
            Consolidated command execution from Sysmon, Security 4688, PowerShell logs, scheduled tasks, transcripts and console history when present.
          </p>
        </div>
        <Link to={`/cases/${caseId}/search`} className="rounded-2xl border border-line px-4 py-3 text-sm text-ink hover:bg-white/5">
          Open Search
        </Link>
      </div>

      <div className="grid gap-3 md:grid-cols-5">
        {[
          ["Commands", data?.summary.commands_total ?? 0],
          ["Suspicious", data?.summary.suspicious_total ?? 0],
          ["High confidence", data?.summary.high_confidence ?? 0],
          ["With sources", data?.summary.with_supporting_events ?? 0],
          ["With command line", data?.summary.with_command_line ?? 0],
        ].map(([label, value]) => (
          <div key={label} className="rounded-2xl border border-line bg-panel/70 p-4 shadow-panel">
            <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted">{label}</div>
            <div className="mt-1 text-xl font-semibold text-ink">{value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr_1fr_1fr_1fr_1fr_auto]">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search commands</span>
            <input
              aria-label="Search commands"
              className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
              value={qDraft}
              onChange={(event) => setQDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") update({ q: qDraft });
              }}
              placeholder="maintenance.ps1, powershell -ep bypass, remote-admin"
            />
          </label>
          <SelectField label="Family" value={params.family ?? ""} options={Object.keys(data?.facets.family ?? data?.facets.shell ?? {})} onChange={(value) => update({ family: value, shell: undefined })} />
          <SelectField label="Source category" value={params.source_category ?? ""} options={SOURCE_OPTIONS} emptyLabel="All sources" onChange={(value) => update({ source_category: value, source: undefined })} />
          <TextField label="Launcher" value={params.launcher ?? ""} onChange={(value) => update({ launcher: value })} placeholder="remote-admin.exe" />
          <SelectField label="Source" value={params.source_type ?? ""} options={Object.keys(data?.facets.source_type ?? {})} onChange={(value) => update({ source_type: value })} />
          <NumberField label="Risk min" value={String(params.risk_min ?? "")} onChange={(value) => update({ risk_min: value })} />
          <div className="flex items-end gap-2">
            <button className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent" onClick={() => update({ q: qDraft })}>
              Apply
            </button>
            <button className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted" onClick={() => setSearchParams(new URLSearchParams())}>
              Clear
            </button>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-muted">
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{activeHost ? `Host filter: ${activeHost}` : "Host filter: All hosts"}</span>
          {hasHostFilter ? (
            <button type="button" onClick={clearHostFilter} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-accent">
              Clear host filter
            </button>
          ) : (
            <span>Change the host filter from the top bar.</span>
          )}
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_1fr_auto]">
          <TimeField label="Time from" value={params.time_from ?? ""} onChange={(value) => update({ time_from: value })} />
          <TimeField label="Time to" value={params.time_to ?? ""} onChange={(value) => update({ time_to: value })} />
          {params.time_from || params.time_to ? (
            <div className="flex items-end">
              <button type="button" className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted" onClick={() => update({ time_from: undefined, time_to: undefined })}>
                Clear time filter
              </button>
            </div>
          ) : null}
        </div>
        <label className="mt-4 flex items-center gap-2 text-sm text-ink">
          <input type="checkbox" checked={Boolean(params.only_suspicious)} onChange={(event) => update({ only_suspicious: event.target.checked })} />
          Only suspicious commands
        </label>
      </div>

      {error ? <div className="rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">{error}</div> : null}

      {paginationControls}

      <div className="rounded-lg border border-line bg-panel/60">
        <table data-testid="command-history-table" className="w-full table-fixed text-left text-sm">
          <thead className="border-b border-line text-xs uppercase text-muted">
            <tr>
              <th className="w-[150px] px-3 py-2">
                <button
                  type="button"
                  className="text-left uppercase text-muted hover:text-ink"
                  onClick={() =>
                    update({
                      sort: sortOrder === "asc" ? "timestamp_desc" : "timestamp_asc",
                      sort_by: "timestamp",
                      sort_order: sortOrder === "asc" ? "desc" : "asc",
                    })
                  }
                  aria-label={`Sort timestamp ${sortOrder === "asc" ? "descending" : "ascending"}`}
                >
                  Timestamp {sortOrder === "asc" ? "↑" : "↓"}
                </button>
              </th>
              <th className="w-[96px] px-3 py-2">Family</th>
              <th className="w-[130px] px-3 py-2">Launcher</th>
              <th className="px-3 py-2">Command</th>
              <th className="w-[150px] px-3 py-2">User</th>
              <th className="w-[130px] px-3 py-2">Host</th>
              <th className="w-[170px] px-3 py-2">Source</th>
              <th className="w-[96px] px-3 py-2">Risk</th>
              <th className="w-[260px] px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {loading ? (
              <tr>
                <td className="px-3 py-5 text-muted" colSpan={9}>
                  Loading command history...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td className="px-3 py-5 text-muted" colSpan={9}>
                  No command executions matched the current filters.
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <Fragment key={item.id}>
                  <tr className="align-top hover:bg-abyss/50">
                    <td className="whitespace-normal px-3 py-3 text-ink" title={item.timestamp ?? ""}>
                      {formatTimestamp(item.timestamp, effectiveTimezone)}
                    </td>
                    <td className="px-3 py-3 text-ink" title={`Confidence: ${item.classification_confidence || item.confidence}`}>
                      <div className="truncate">{familyLabel(item)}</div>
                    </td>
                    <td className="px-3 py-3 text-ink" title={item.launcher_path || item.process?.executable || item.process?.name || ""}>
                      <div className="truncate">{launcherLabel(item)}</div>
                      {item.parent_shell ? <div className="truncate text-xs text-muted">parent: {item.parent_shell}</div> : null}
                    </td>
                    <td className="px-3 py-3">
                      <div
                        data-testid="command-cell"
                        className="overflow-hidden break-words font-mono text-xs leading-relaxed text-ink"
                        title={item.command}
                        style={{ display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical" }}
                      >
                        {item.command}
                      </div>
                      {item.registry_command ? (
                        <div className="mt-1 flex flex-wrap gap-1 text-[11px]">
                          <span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-accent">Registry command evidence</span>
                          <span className="rounded-full border border-line px-2 py-0.5 text-ink">{item.registry_command.operation || "unknown"}</span>
                          <span className={`rounded-full border px-2 py-0.5 ${item.registry_command.confirmed_by_registry_event ? "border-mint/40 text-mint" : "border-amber/40 text-amber"}`}>
                            {item.registry_command.confirmed_by_registry_event ? "confirmed by registry event" : "not confirmed by registry event"}
                          </span>
                        </div>
                      ) : null}
                      {item.risk_reasons.length ? <div className="mt-1 truncate text-xs text-amber">{item.risk_reasons.join(" · ")}</div> : null}
                    </td>
                    <td className="px-3 py-3 text-ink" title={item.user ?? ""}>
                      <div className="truncate">{valueOrDash(item.user)}</div>
                    </td>
                    <td className="px-3 py-3 text-ink" title={item.host ?? ""}>
                      <div className="truncate">{valueOrDash(item.host)}</div>
                    </td>
                    <td className="px-3 py-3 text-ink" title={sourceLabel(item)}>
                      <SourceBadge item={item} />
                    </td>
                    <td className="px-3 py-3">
                      <span className="rounded-full border border-line px-2 py-1 text-xs text-ink" title={item.risk_reasons.join("; ")}>
                        {riskLabel(item.risk_score)} {item.risk_score}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
                          {expandedId === item.id ? "Hide details" : "Details"}
                        </button>
                        <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => void copyCommand(item)}>
                          {copiedId === item.id ? "Copied" : "Copy"}
                        </button>
                        <Link
                          className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5"
                          to={processGraphUrl(caseId, item)}
                        >
                          Open process tree
                        </Link>
                        {item.timestamp ? (
                          <>
                            <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => update(aroundEventWindow(item, 30 * 1000) ?? {})}>
                              ±30s
                            </button>
                            <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => update(aroundEventWindow(item, 5 * 60 * 1000) ?? {})}>
                              ±5m
                            </button>
                            <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => update(aroundEventWindow(item, 30 * 60 * 1000) ?? {})}>
                              ±30m
                            </button>
                          </>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                  {expandedId === item.id ? (
                    <tr className="bg-abyss/90">
                      <td colSpan={9} className="px-3 pb-4">
                        <div className="grid gap-4 rounded-lg border border-line bg-abyss p-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.6fr)]">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <p className="text-xs uppercase tracking-wide text-muted">Full command</p>
                              <button className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" onClick={() => void copyCommand(item)}>
                                {copiedId === item.id ? "Copied" : "Copy command"}
                              </button>
                            </div>
                            <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-abyss/60 p-3 font-mono text-xs leading-relaxed text-ink">{item.command}</pre>
                            {item.raw_payload ? (
                              <>
                                <p className="mt-4 text-xs uppercase tracking-wide text-muted">Raw payload</p>
                                <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-abyss/60 p-3 font-mono text-xs leading-relaxed text-ink">{item.raw_payload}</pre>
                              </>
                            ) : null}
                          </div>
                          <div className="space-y-3 text-sm text-ink">
                            <div><span className="text-muted">Timestamp:</span> {formatTimestamp(item.timestamp, effectiveTimezone)}</div>
                            <div><span className="text-muted">User:</span> {valueOrDash(item.user)}</div>
                            <div><span className="text-muted">Host:</span> {valueOrDash(item.host)}</div>
                            <div><span className="text-muted">Source:</span> <SourceBadge item={item} /> <span className="ml-1">{sourceLabel(item)} · {item.supporting_events.length} event(s)</span></div>
                            <div><span className="text-muted">Artifact family:</span> {valueOrDash(item.artifact_type)}</div>
                            <div><span className="text-muted">Parser:</span> {valueOrDash(item.parser || item.supporting_events[0]?.parser)}</div>
                            <div><span className="text-muted">Artifact ID:</span> {valueOrDash(item.artifact_id)}</div>
                            <div><span className="text-muted">Source file:</span> <span className="break-words font-mono text-xs">{valueOrDash(item.source_file)}</span></div>
                            <div><span className="text-muted">Source event:</span> {valueOrDash(item.source_event_id)}</div>
                            <div><span className="text-muted">Parent:</span> {valueOrDash(item.parent_process?.name || item.parent_process?.executable)}</div>
                            <div><span className="text-muted">Parent command:</span> <span className="break-words font-mono text-xs">{valueOrDash(item.parent_process?.command_line)}</span></div>
                            <div><span className="text-muted">Risk reasons:</span> {item.risk_reasons.length ? item.risk_reasons.join(" · ") : "-"}</div>
                            {item.registry_command ? (
                              <div className="rounded-md border border-accent/30 bg-accent/10 p-3 text-xs">
                                <div><span className="text-muted">Registry operation:</span> {valueOrDash(item.registry_command.operation)}</div>
                                <div><span className="text-muted">Registry path:</span> <span className="break-words font-mono">{valueOrDash(item.registry_command.registry_path)}</span></div>
                                <div><span className="text-muted">Confidence:</span> command evidence</div>
                                <div><span className="text-muted">Confirmed by registry event:</span> {item.registry_command.confirmed_by_registry_event ? "yes" : "no"}</div>
                              </div>
                            ) : null}
                            <div className="flex flex-wrap gap-2 pt-2">
                              <Link className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" to={item.linked_search_url}>
                                Open search
                              </Link>
                              <Link className="rounded border border-line px-2 py-1 text-xs text-ink hover:bg-white/5" to={processGraphUrl(caseId, item)}>
                                Open process tree
                              </Link>
                              <button className="rounded border border-amber/40 px-2 py-1 text-xs text-amber hover:bg-amber/10" disabled={marking === item.id} onClick={() => markSuspicious(item)}>
                                Mark suspicious
                              </button>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>

      {paginationControls}
    </div>
  );
}
