import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type CommandHistoryItem } from "../api/client";

const PAGE_SIZE = 100;

function valueOrDash(value: unknown): string {
  const text = String(value ?? "").trim();
  return text || "-";
}

function formatTimestamp(value?: string | null): string {
  if (!value) return "No timestamp";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
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
  const unique = Array.from(new Set([item.source_type, ...sources].filter(Boolean)));
  return unique.join(", ");
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
  return `/cases/${caseId}/process-graph?${params.toString()}`;
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
    user: searchParams.get("user") || undefined,
    family: searchParams.get("family") || searchParams.get("shell") || undefined,
    launcher: searchParams.get("launcher") || undefined,
    source_type: searchParams.get("source_type") || undefined,
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
    <div className="flex flex-col gap-2 text-sm text-zinc-300 sm:flex-row sm:items-center sm:justify-between">
      <div>
        Page {data?.page ?? 1} of {totalPages} · {data?.total ?? 0} commands
      </div>
      <div className="flex gap-2">
        <button className="rounded border border-zinc-700 px-3 py-2 disabled:opacity-40" disabled={(data?.page ?? 1) <= 1} onClick={() => update({ page: Math.max(1, (data?.page ?? 1) - 1) })}>
          Previous
        </button>
        <button className="rounded border border-zinc-700 px-3 py-2 disabled:opacity-40" disabled={(data?.page ?? 1) >= totalPages} onClick={() => update({ page: (data?.page ?? 1) + 1 })}>
          Next
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-wide text-zinc-500">Case workspace</p>
          <h1 className="text-2xl font-semibold text-zinc-100">Command History</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-400">
            Consolidated command execution from Sysmon, Security 4688, PowerShell logs, scheduled tasks, transcripts and console history when present.
          </p>
        </div>
        <Link to={`/cases/${caseId}/search`} className="rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900">
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
          <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <div className="text-xs text-zinc-500">{label}</div>
            <div className="mt-1 text-xl font-semibold text-zinc-100">{value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-4">
        <div className="grid gap-3 lg:grid-cols-[2fr_1fr_1fr_1fr_1fr_1fr_auto]">
          <label className="text-xs text-zinc-400">
            Search commands
            <input
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
              value={qDraft}
              onChange={(event) => setQDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") update({ q: qDraft });
              }}
              placeholder="maintenance.ps1, powershell -ep bypass, remote-admin"
            />
          </label>
          <label className="text-xs text-zinc-400">
            Family
            <select className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100" value={params.family ?? ""} onChange={(event) => update({ family: event.target.value, shell: undefined })}>
              <option value="">Any</option>
              {Object.keys(data?.facets.family ?? data?.facets.shell ?? {}).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-zinc-400">
            Launcher
            <input className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100" value={params.launcher ?? ""} onChange={(event) => update({ launcher: event.target.value })} placeholder="remote-admin.exe" />
          </label>
          <label className="text-xs text-zinc-400">
            Source
            <select className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100" value={params.source_type ?? ""} onChange={(event) => update({ source_type: event.target.value })}>
              <option value="">Any</option>
              {Object.keys(data?.facets.source_type ?? {}).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-zinc-400">
            Host
            <input className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100" value={params.host ?? ""} onChange={(event) => update({ host: event.target.value })} placeholder="HOSTA" />
          </label>
          <label className="text-xs text-zinc-400">
            Risk min
            <input className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100" type="number" min={0} max={100} value={params.risk_min ?? ""} onChange={(event) => update({ risk_min: event.target.value })} />
          </label>
          <div className="flex items-end gap-2">
            <button className="rounded-md bg-cyan-500 px-3 py-2 text-sm font-medium text-zinc-950 hover:bg-cyan-400" onClick={() => update({ q: qDraft })}>
              Apply
            </button>
            <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900" onClick={() => setSearchParams(new URLSearchParams())}>
              Clear
            </button>
          </div>
        </div>
        <label className="mt-3 flex items-center gap-2 text-sm text-zinc-300">
          <input type="checkbox" checked={Boolean(params.only_suspicious)} onChange={(event) => update({ only_suspicious: event.target.checked })} />
          Only suspicious commands
        </label>
      </div>

      {error ? <div className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-200">{error}</div> : null}

      {paginationControls}

      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60">
        <table data-testid="command-history-table" className="w-full table-fixed text-left text-sm">
          <thead className="border-b border-zinc-800 text-xs uppercase text-zinc-500">
            <tr>
              <th className="w-[150px] px-3 py-2">
                <button
                  type="button"
                  className="text-left uppercase text-zinc-400 hover:text-zinc-100"
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
              <th className="w-[96px] px-3 py-2">Risk</th>
              <th className="w-[210px] px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-900">
            {loading ? (
              <tr>
                <td className="px-3 py-5 text-zinc-400" colSpan={8}>
                  Loading command history...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td className="px-3 py-5 text-zinc-400" colSpan={8}>
                  No command executions matched the current filters.
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <Fragment key={item.id}>
                  <tr className="align-top hover:bg-zinc-900/50">
                    <td className="whitespace-normal px-3 py-3 text-zinc-300" title={item.timestamp ?? ""}>
                      {formatTimestamp(item.timestamp)}
                    </td>
                    <td className="px-3 py-3 text-zinc-300" title={`Confidence: ${item.classification_confidence || item.confidence}`}>
                      <div className="truncate">{familyLabel(item)}</div>
                    </td>
                    <td className="px-3 py-3 text-zinc-300" title={item.launcher_path || item.process?.executable || item.process?.name || ""}>
                      <div className="truncate">{launcherLabel(item)}</div>
                      {item.parent_shell ? <div className="truncate text-xs text-zinc-500">parent: {item.parent_shell}</div> : null}
                    </td>
                    <td className="px-3 py-3">
                      <div
                        data-testid="command-cell"
                        className="overflow-hidden break-words font-mono text-xs leading-relaxed text-zinc-100"
                        title={item.command}
                        style={{ display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical" }}
                      >
                        {item.command}
                      </div>
                      {item.risk_reasons.length ? <div className="mt-1 truncate text-xs text-amber-300">{item.risk_reasons.join(" · ")}</div> : null}
                    </td>
                    <td className="px-3 py-3 text-zinc-300" title={item.user ?? ""}>
                      <div className="truncate">{valueOrDash(item.user)}</div>
                    </td>
                    <td className="px-3 py-3 text-zinc-300" title={item.host ?? ""}>
                      <div className="truncate">{valueOrDash(item.host)}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className="rounded-full border border-zinc-700 px-2 py-1 text-xs text-zinc-200" title={item.risk_reasons.join("; ")}>
                        {riskLabel(item.risk_score)} {item.risk_score}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
                          {expandedId === item.id ? "Hide details" : "Details"}
                        </button>
                        <button className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" onClick={() => void copyCommand(item)}>
                          {copiedId === item.id ? "Copied" : "Copy"}
                        </button>
                        <Link
                          className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                          to={processGraphUrl(caseId, item)}
                        >
                          Open process tree
                        </Link>
                      </div>
                    </td>
                  </tr>
                  {expandedId === item.id ? (
                    <tr className="bg-zinc-950/90">
                      <td colSpan={8} className="px-3 pb-4">
                        <div className="grid gap-4 rounded-lg border border-zinc-800 bg-zinc-950 p-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.6fr)]">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <p className="text-xs uppercase tracking-wide text-zinc-500">Full command</p>
                              <button className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" onClick={() => void copyCommand(item)}>
                                {copiedId === item.id ? "Copied" : "Copy command"}
                              </button>
                            </div>
                            <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border border-zinc-800 bg-zinc-900/60 p-3 font-mono text-xs leading-relaxed text-zinc-100">{item.command}</pre>
                            {item.raw_payload ? (
                              <>
                                <p className="mt-4 text-xs uppercase tracking-wide text-zinc-500">Raw payload</p>
                                <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md border border-zinc-800 bg-zinc-900/60 p-3 font-mono text-xs leading-relaxed text-zinc-300">{item.raw_payload}</pre>
                              </>
                            ) : null}
                          </div>
                          <div className="space-y-3 text-sm text-zinc-300">
                            <div><span className="text-zinc-500">User:</span> {valueOrDash(item.user)}</div>
                            <div><span className="text-zinc-500">Host:</span> {valueOrDash(item.host)}</div>
                            <div><span className="text-zinc-500">Source:</span> {sourceLabel(item)} · {item.supporting_events.length} event(s)</div>
                            <div><span className="text-zinc-500">Source event:</span> {valueOrDash(item.source_event_id)}</div>
                            <div><span className="text-zinc-500">Parent:</span> {valueOrDash(item.parent_process?.name || item.parent_process?.executable)}</div>
                            <div><span className="text-zinc-500">Parent command:</span> <span className="break-words font-mono text-xs">{valueOrDash(item.parent_process?.command_line)}</span></div>
                            <div><span className="text-zinc-500">Risk reasons:</span> {item.risk_reasons.length ? item.risk_reasons.join(" · ") : "-"}</div>
                            <div className="flex flex-wrap gap-2 pt-2">
                              <Link className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" to={item.linked_search_url}>
                                Open search
                              </Link>
                              <Link className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" to={processGraphUrl(caseId, item)}>
                                Open process tree
                              </Link>
                              <button className="rounded border border-amber-700 px-2 py-1 text-xs text-amber-200 hover:bg-amber-950" disabled={marking === item.id} onClick={() => markSuspicious(item)}>
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
