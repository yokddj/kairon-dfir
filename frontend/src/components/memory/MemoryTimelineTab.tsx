import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type MemoryTimelineCorrelation, type MemoryTimelineEvent, type MemoryTimelineParams } from "../../api/client";
import type { MemoryTab } from "../../lib/memoryWorkspaceState";

const PAGE_SIZES = [50, 100, 250, 500] as const;
const EVENT_KINDS = ["process_start", "process_exit", "command_line", "network_connection", "suspicious_memory", "event_log_process_creation", "powershell_execution", "prefetch_execution", "amcache_observation", "shimcache_observation", "service_execution", "scheduled_task_execution", "registry_persistence"];
const FAMILIES = ["processes", "raw_observations", "network", "modules", "handles", "suspicious", "vads", "drivers", "kernel", "event_logs", "powershell", "prefetch", "amcache", "shimcache", "services", "scheduled_tasks", "registry_persistence", "network_logs"];

type Props = {
  caseId: string;
  evidenceId?: string;
  selectedRunId: string | null;
  selectedEntityId: string | null;
  onSelectRunId: (runId: string | null) => void;
  onSelectEntityId: (entityId: string | null) => void;
  onJumpToTab: (tab: MemoryTab) => void;
};

function Pagination({ page, totalPages, total, pageSize, onPage }: { page: number; totalPages: number; total: number; pageSize: number; onPage: (page: number) => void }) {
  const start = total ? (page - 1) * pageSize + 1 : 0;
  const end = Math.min(total, page * pageSize);
  return <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted" data-testid="memory-timeline-pagination"><span>{start}-{end} of {total} · page {page} of {totalPages || 1}</span><div className="flex gap-2"><button type="button" className="rounded-lg border border-line px-2 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button><button type="button" className="rounded-lg border border-line px-2 py-1 disabled:opacity-40" disabled={!totalPages || page >= totalPages} onClick={() => onPage(page + 1)}>Next</button></div></div>;
}

function Confidence({ value }: { value: string }) {
  const tone = value === "exact" || value === "high" ? "bg-emerald-500/15 text-emerald-100" : value === "medium" ? "bg-amber-500/15 text-amber-100" : "bg-muted/20 text-muted";
  return <span className={`rounded-full px-2 py-0.5 text-[11px] ${tone}`} data-testid="memory-timeline-confidence">{value}</span>;
}

function CorrelationDetail({ correlation, onClose }: { correlation: MemoryTimelineCorrelation; onClose: () => void }) {
  return <div className="rounded-2xl border border-accent/40 bg-abyss p-4" data-testid="memory-correlation-detail"><div className="flex items-center justify-between gap-3"><div><div className="text-sm font-semibold text-ink">Correlation detail</div><div className="text-xs text-muted">{correlation.correlation_type}</div></div><button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={onClose}>Close</button></div><div className="mt-3 flex flex-wrap gap-2"><Confidence value={correlation.confidence} /><span className="text-xs text-muted">Rule {correlation.created_by_rule_version}</span>{correlation.time_delta_seconds !== null && correlation.time_delta_seconds !== undefined ? <span className="text-xs text-muted">Δ {correlation.time_delta_seconds.toFixed(1)}s</span> : null}</div><div className="mt-3 grid gap-3 md:grid-cols-2"><section><div className="text-xs uppercase tracking-[0.16em] text-muted">Matched fields</div>{correlation.matched_fields.map((field) => <div key={field} className="mt-1 rounded-lg bg-panel/70 px-2 py-1 text-xs" data-testid="memory-correlation-matched-field">{field}</div>)}</section><section><div className="text-xs uppercase tracking-[0.16em] text-muted">Contradictions</div>{correlation.contradictory_fields.length ? correlation.contradictory_fields.map((field) => <div key={field} className="mt-1 rounded-lg bg-rose-500/10 px-2 py-1 text-xs text-rose-100" data-testid="memory-correlation-contradiction">{field}</div>) : <div className="mt-1 text-xs text-muted" data-testid="memory-correlation-contradiction">None</div>}</section></div><div className="mt-3"><div className="text-xs uppercase tracking-[0.16em] text-muted">Reasons</div>{correlation.reasons.map((reason) => <div key={reason} className="mt-1 text-xs" data-testid="memory-correlation-reason">{reason}</div>)}</div></div>;
}

function EventRow({ event, onOpen, onCorrelation }: { event: MemoryTimelineEvent; onOpen: (event: MemoryTimelineEvent, mode: "process" | "graph" | "source" | "raw" | "search") => void; onCorrelation: (correlation: MemoryTimelineCorrelation) => void }) {
  const endpoint = event.local_endpoint || event.remote_endpoint ? `${event.local_endpoint?.address ?? "*"}:${event.local_endpoint?.port ?? "*"} -> ${event.remote_endpoint?.address ?? "*"}:${event.remote_endpoint?.port ?? "*"}` : null;
  return <article className="rounded-2xl border border-line bg-panel/70 p-4" data-testid={event.is_undated ? "memory-timeline-undated-event" : "memory-timeline-event"}><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="text-sm font-semibold text-ink">{event.title}</div><div className="mt-1 text-xs text-muted">{event.artifact_family} · {event.event_kind} · {event.source_plugin || event.source_parser || "unknown source"}</div></div><div className="text-right text-xs"><div>{event.occurred_at || "Undated"}</div><div className="text-muted" data-testid="memory-timeline-precision">{event.timestamp_precision}/{event.timestamp_confidence}</div></div></div><div className="mt-2 text-sm">{event.process_name || "Unknown process"}{event.pid !== null && event.pid !== undefined ? <span className="ml-2 font-mono text-xs text-muted">PID {event.pid}</span> : null}</div>{endpoint ? <div className="mt-1 font-mono text-xs text-muted" data-testid="memory-timeline-endpoints">{endpoint}</div> : null}{event.command_line_summary ? <div className="mt-1 truncate font-mono text-xs text-muted" title={event.command_line_summary}>{event.command_line_summary}</div> : null}{event.summary ? <div className="mt-2 text-xs text-muted">{event.summary}</div> : null}<div className="mt-3 flex flex-wrap gap-2"><button type="button" className="rounded-lg bg-accent px-2 py-1 text-xs text-abyss" onClick={() => onOpen(event, "source")}>Inspect</button>{event.process_entity_id ? <button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(event, "process")}>Open process</button> : null}{event.process_entity_id ? <button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(event, "graph")}>Focus graph</button> : null}<button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(event, "raw")}>Open raw</button><button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(event, "search")}>Open Search result</button>{event.correlations.map((correlation) => <button key={correlation.correlation_id} type="button" className="rounded-lg border border-accent/50 px-2 py-1 text-xs" onClick={() => onCorrelation(correlation)} data-testid="memory-timeline-correlation-badge">Correlation <Confidence value={correlation.confidence} /></button>)}</div></article>;
}

export function MemoryTimelineTab({ caseId, evidenceId, selectedRunId, selectedEntityId, onSelectRunId, onSelectEntityId, onJumpToTab }: Props) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(100);
  const [pid, setPid] = useState("");
  const [processName, setProcessName] = useState("");
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const [kind, setKind] = useState("");
  const [family, setFamily] = useState("");
  const [confidence, setConfidence] = useState("");
  const [correlatedOnly, setCorrelatedOnly] = useState(false);
  const [includeUndated, setIncludeUndated] = useState(false);
  const [detail, setDetail] = useState<MemoryTimelineCorrelation | null>(null);

  const params: MemoryTimelineParams = { evidence_id: evidenceId || "", page, page_size: pageSize, sort_order: "asc", include_undated: includeUndated };
  if (selectedRunId) params.memory_run_id = selectedRunId;
  if (selectedEntityId) params.process_entity_id = selectedEntityId;
  if (pid) params.pid = Number(pid);
  if (processName) params.process_name = processName;
  if (timeFrom) params.time_from = timeFrom;
  if (timeTo) params.time_to = timeTo;
  if (kind) params.event_kinds = [kind];
  if (family) params.artifact_families = [family];
  if (confidence) params.correlation_confidence = confidence;
  if (correlatedOnly) params.has_correlations = true;

  const query = useQuery({ queryKey: ["memory-timeline", caseId, params], queryFn: () => api.getMemoryTimeline(caseId, params), enabled: Boolean(caseId && evidenceId), refetchOnWindowFocus: false });
  const reset = (fn: () => void) => { fn(); setPage(1); };
  const clear = () => { setPid(""); setProcessName(""); setTimeFrom(""); setTimeTo(""); setKind(""); setFamily(""); setConfidence(""); setCorrelatedOnly(false); setIncludeUndated(false); setPage(1); };
  const onOpen = (event: MemoryTimelineEvent, mode: "process" | "graph" | "source" | "raw" | "search") => { const target = event.navigation_target as any; if (target.run_id) onSelectRunId(target.run_id); if (event.process_entity_id) onSelectEntityId(event.process_entity_id); if (mode === "graph") onJumpToTab("graph"); else if (mode === "process") onJumpToTab("processes"); else if (mode === "raw") onJumpToTab("raw"); else onJumpToTab((target.tab as MemoryTab) || "artifacts"); };

  if (!evidenceId) return <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">Select one memory Evidence to build a timeline.</section>;
  const data = query.data;
  const chronological = data?.items.filter((item) => !item.is_undated) ?? [];
  const undated = data?.items.filter((item) => item.is_undated) ?? [];

  return <section className="space-y-4" data-testid="memory-timeline-tab"><div className="rounded-2xl border border-line bg-panel/70 p-5"><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"><label className="text-xs text-muted">Time from<input value={timeFrom} onChange={(e) => reset(() => setTimeFrom(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink" /></label><label className="text-xs text-muted">Time to<input value={timeTo} onChange={(e) => reset(() => setTimeTo(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink" /></label><label className="text-xs text-muted">PID<input value={pid} onChange={(e) => reset(() => setPid(e.target.value.replace(/\D/g, "")))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink" /></label><label className="text-xs text-muted">Process<input value={processName} onChange={(e) => reset(() => setProcessName(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink" /></label><label className="text-xs text-muted">Event kind<select value={kind} onChange={(e) => reset(() => setKind(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink"><option value="">All</option>{EVENT_KINDS.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label className="text-xs text-muted">Family<select value={family} onChange={(e) => reset(() => setFamily(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink"><option value="">All</option>{FAMILIES.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label className="text-xs text-muted">Confidence<select value={confidence} onChange={(e) => reset(() => setConfidence(e.target.value))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink"><option value="">Default</option><option value="exact">Exact</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="text-xs text-muted">Page size<select value={pageSize} onChange={(e) => reset(() => setPageSize(Number(e.target.value)))} className="mt-1 w-full rounded-lg border border-line bg-abyss px-2 py-1 text-sm text-ink" data-testid="memory-timeline-page-size">{PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}</select></label></div><div className="mt-3 flex flex-wrap gap-3 text-xs"><label className="flex items-center gap-2 text-muted"><input type="checkbox" checked={correlatedOnly} onChange={(e) => reset(() => setCorrelatedOnly(e.target.checked))} /> Correlated only</label><label className="flex items-center gap-2 text-muted"><input type="checkbox" checked={includeUndated} onChange={(e) => reset(() => setIncludeUndated(e.target.checked))} /> Include undated</label><button type="button" className="rounded-lg border border-line px-2 py-1 text-muted" onClick={clear}>Reset</button></div></div>{query.isError ? <div className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100">{query.error instanceof Error ? query.error.message : "Timeline failed"}</div> : null}{data ? <div className="grid gap-4 xl:grid-cols-[260px_1fr]"><aside className="rounded-2xl border border-line bg-panel/60 p-4 text-xs text-muted"><div className="font-semibold text-ink">Timeline coverage</div><div className="mt-2" data-testid="memory-timeline-counts">Timestamped: {data.timestamp_quality_summary.timestamped ?? 0}</div><div>Undated: {data.undated_count}</div><div>Correlated events: {data.correlated_event_count}</div><div className="mt-3 font-semibold text-ink">Kinds</div>{Object.entries(data.event_kind_counts).slice(0, 8).map(([key, count]) => <div key={key} className="mt-1 flex justify-between"><span>{key}</span><span>{count}</span></div>)}</aside><div className="space-y-3"><Pagination page={data.page} totalPages={data.total_pages} total={data.total} pageSize={data.page_size} onPage={setPage} />{data.total === 0 ? <div className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted" data-testid="memory-timeline-empty">No timestamped timeline data matched this scope. Try including Undated evidence if artifacts lack occurrence timestamps.</div> : null}{chronological.map((event) => <EventRow key={event.event_id} event={event} onOpen={onOpen} onCorrelation={setDetail} />)}{undated.length ? <section className="rounded-2xl border border-dashed border-line bg-panel/40 p-4" data-testid="memory-timeline-undated"><div className="mb-3 text-sm font-semibold text-ink">Undated evidence</div><div className="space-y-3">{undated.map((event) => <EventRow key={event.event_id} event={event} onOpen={onOpen} onCorrelation={setDetail} />)}</div></section> : null}<Pagination page={data.page} totalPages={data.total_pages} total={data.total} pageSize={data.page_size} onPage={setPage} />{detail ? <CorrelationDetail correlation={detail} onClose={() => setDetail(null)} /> : null}</div></div> : query.isLoading ? <div className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">Loading timeline...</div> : null}</section>;
}
