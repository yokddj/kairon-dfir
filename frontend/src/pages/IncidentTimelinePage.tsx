import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, ExternalLink, FileText, Filter, GitBranch, RefreshCw, Search, ShieldAlert, X } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api, type IncidentTimelineItem } from "../api/client";
import IndicatorResolutionPanel from "../components/IndicatorResolutionPanel";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";
import { formatTimestamp } from "../lib/time";

const BASE_SOURCE_OPTIONS = [
  { id: "marked_events", label: "Marked events" },
  { id: "findings", label: "Findings" },
  { id: "command_history", label: "Command History" },
  { id: "defender", label: "Defender" },
];
const GROUND_TRUTH_SOURCE_OPTION = { id: "ground_truth", label: "Validation seeds" };

const TIMELINE_TABS = [
  { id: "official", label: "Official Timeline" },
  { id: "candidates", label: "Suggested Candidates" },
  { id: "sources", label: "Sources / Provenance" },
];

const PHASE_LABELS: Record<string, string> = {
  initial_access: "Initial access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege escalation",
  defense_evasion: "Defense evasion",
  credential_access: "Credential access",
  discovery: "Discovery",
  lateral_movement: "Lateral movement",
  collection: "Collection",
  exfiltration: "Exfiltration",
  impact: "Impact",
  cleanup: "Cleanup",
  unknown: "Unknown",
};

function sourceLabel(value: string | null | undefined) {
  const labels: Record<string, string> = {
    find_this_file: "Find this file",
    view_activity_around_time: "View activity around this time",
    open_artifact_evidence: "Open artifact evidence",
    search_exact_command_reference: "Search exact command/reference",
    execution_story: "Open Execution Story",
    validation_matrix: "Open Validation Matrix",
  };
  if (value && labels[value]) return labels[value];
  return (value || "source")
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function pivotTooltip(value: string) {
  const labels: Record<string, string> = {
    find_this_file: "Search for this filename/path across indexed evidence.",
    view_activity_around_time: "Show events on this host around the item timestamp.",
    open_artifact_evidence: "Open specialized artifact evidence linked to this item.",
    search_exact_command_reference: "Search the exact command or referenced string.",
    execution_story: "Open the exact process story when process identity is available.",
    validation_matrix: "Open the training/validation ground-truth item context.",
  };
  return labels[value] || sourceLabel(value);
}

function targetLabel(value: string | null | undefined) {
  const labels: Record<string, string> = {
    exact_process: "Exact process",
    candidate_process: "Candidate process",
    command: "Command",
    evidence_bundle: "Evidence bundle",
    lateral_movement: "Movement",
    file_artifact: "File",
    defender_detection: "Defender",
    validation_item: "Validation",
    search_context: "Search context",
    none: "No exact story",
  };
  return labels[value || ""] || sourceLabel(value || "evidence_bundle");
}

function primaryActionLabel(item: IncidentTimelineItem) {
  return item.story_primary_action || (item.story_target_type === "exact_process" ? "Open Execution Story" : `Open ${targetLabel(item.story_target_type)}`);
}

function renderRecordList(record: Record<string, unknown> | null | undefined) {
  if (!record) return null;
  return Object.entries(record)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([key, value]) => (
      <div key={key} className="rounded-lg border border-line/70 bg-abyss/50 px-3 py-2">
        <p className="text-[11px] uppercase tracking-[0.14em] text-muted">{sourceLabel(key)}</p>
        <p className="mt-1 break-words text-sm text-ink">{Array.isArray(value) ? value.join(", ") : String(value)}</p>
      </div>
    ));
}

function riskClass(score: number) {
  if (score >= 80) return "border-rose-400/40 bg-rose-500/10 text-rose-100";
  if (score >= 50) return "border-amber-400/40 bg-amber-500/10 text-amber-100";
  return "border-line bg-abyss/60 text-muted";
}

function groupItems(items: IncidentTimelineItem[], groupBy: string) {
  const groups = new Map<string, IncidentTimelineItem[]>();
  for (const item of items) {
    const key = groupBy === "host" ? item.host || "unknown" : groupBy === "none" ? "Timeline" : PHASE_LABELS[item.phase] || sourceLabel(item.phase);
    groups.set(key, [...(groups.get(key) || []), item]);
  }
  return Array.from(groups.entries());
}

export default function IncidentTimelinePage() {
  const { caseId: routeCaseId } = useParams();
  const { activeCaseId, selectedHost, setActiveCaseId, caseContext } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const caseId = routeCaseId || activeCaseId;
  const showValidationMatrix = Boolean(caseContext?.summary?.validation_matrix?.show_validation_matrix);
  const sourceOptions = useMemo(() => (showValidationMatrix ? [...BASE_SOURCE_OPTIONS, GROUND_TRUTH_SOURCE_OPTION] : BASE_SOURCE_OPTIONS), [showValidationMatrix]);
  const [sources, setSources] = useState<string[]>(BASE_SOURCE_OPTIONS.map((item) => item.id));
  const [hostFilter, setHostFilter] = useState<string[]>(selectedHost ? [selectedHost] : []);
  const [phaseFilter, setPhaseFilter] = useState<string[]>([]);
  const [groupBy, setGroupBy] = useState("phase");
  const [includeLowSignal, setIncludeLowSignal] = useState(false);
  const [removedIds, setRemovedIds] = useState<Set<string>>(new Set());
  const [phaseOverrides, setPhaseOverrides] = useState<Record<string, string>>({});
  const [statusOverrides, setStatusOverrides] = useState<Record<string, string>>({});
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState("official");
  const [exportStatus, setExportStatus] = useState("");
  const [regenerateStatus, setRegenerateStatus] = useState("");
  const [storyBundleItem, setStoryBundleItem] = useState<IncidentTimelineItem | null>(null);

  useEffect(() => {
    const allowedSources = new Set(sourceOptions.map((item) => item.id));
    setSources((current) => {
      const filtered = current.filter((item) => allowedSources.has(item));
      return filtered.length ? filtered : sourceOptions.map((item) => item.id);
    });
  }, [sourceOptions]);

  useEffect(() => {
    if (routeCaseId && routeCaseId !== activeCaseId) {
      setActiveCaseId(routeCaseId);
    }
  }, [activeCaseId, routeCaseId, setActiveCaseId]);

  const draftQuery = useQuery({
    queryKey: ["incident-timeline-draft", caseId, sources, hostFilter, phaseFilter, includeLowSignal],
    queryFn: () =>
      api.getIncidentTimelineDraft(caseId!, {
        sources,
        host: hostFilter,
        phase: phaseFilter,
        include_low_signal: includeLowSignal,
        max_items: 80,
      }),
    enabled: Boolean(caseId),
  });

  const storyBundleQuery = useQuery({
    queryKey: ["incident-timeline-story-bundle", caseId, storyBundleItem?.id],
    queryFn: () => api.getIncidentTimelineStoryBundle(caseId!, storyBundleItem!.id),
    enabled: Boolean(caseId && storyBundleItem?.id),
  });

  const items = useMemo(() => {
    return (draftQuery.data?.items || [])
      .filter((item) => !removedIds.has(item.id))
      .map((item) => ({
        ...item,
        phase: phaseOverrides[item.id] || item.phase,
        status: statusOverrides[item.id] || item.status || "candidate",
        notes: notes[item.id] ?? item.notes,
      }));
  }, [draftQuery.data?.items, notes, phaseOverrides, removedIds, statusOverrides]);

  const hostOptions = draftQuery.data?.hosts || [];
  const phaseOptions = draftQuery.data?.phase_options || Object.keys(PHASE_LABELS);
  const officialItems = items.filter((item) => (item.status || "candidate") === "accepted");
  const candidateItems = items.filter((item) => ["candidate", "needs_review"].includes(item.status || "candidate"));
  const dismissedItems = items.filter((item) => item.status === "dismissed");
  const visibleItems = activeTab === "candidates" ? candidateItems : officialItems;
  const grouped = groupItems(visibleItems, groupBy);
  const sourceSummary = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      const key = item.source_type || item.source || "unknown";
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    return Array.from(counts.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [items]);

  async function copyMarkdown() {
    if (!caseId) return;
    setExportStatus("Preparing Markdown...");
    try {
      const markdown = await api.exportIncidentTimelineMarkdown(caseId, {
        title: "Incident Timeline",
        group_by: groupBy,
        items: officialItems,
        include_candidates: false,
      });
      await navigator.clipboard.writeText(markdown);
      setExportStatus("Markdown copied to clipboard.");
    } catch (error) {
      setExportStatus(error instanceof Error ? error.message : "Markdown export failed.");
    }
  }

  async function regenerateDraft() {
    if (!caseId) return;
    setRegenerateStatus("Regenerating timeline...");
    try {
      await api.regenerateIncidentTimelineDraft(caseId, {
        sources,
        host: hostFilter,
        phase: phaseFilter,
        include_low_signal: includeLowSignal,
        max_items: 80,
      });
      await draftQuery.refetch();
      setRegenerateStatus("Timeline regenerated.");
    } catch (error) {
      setRegenerateStatus(error instanceof Error ? error.message : "Timeline regeneration failed.");
    }
  }

  async function updateItemStatus(item: IncidentTimelineItem, status: string) {
    setStatusOverrides((current) => ({ ...current, [item.id]: status }));
    const timelineId = draftQuery.data?.timeline_id || draftQuery.data?.cache?.timeline_id || draftQuery.data?.cache?.draft_id;
    if (!caseId || !timelineId) return;
    try {
      await api.updateIncidentTimelineItemStatus(caseId, timelineId, item.id, {
        status,
        note: notes[item.id] ?? item.notes ?? undefined,
      });
      await draftQuery.refetch();
    } catch (error) {
      setRegenerateStatus(error instanceof Error ? error.message : "Timeline item update failed.");
    }
  }

  return (
    <div className="space-y-6">
      <header className="rounded-2xl border border-line bg-panel/80 p-5 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Curated incident story</p>
            <h1 className="mt-2 text-2xl font-semibold text-ink">Incident Timeline</h1>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              Curated reportable story of the incident built from reviewed evidence, findings and marked events. Use Search Timeline for broad event exploration.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {caseContext?.summary?.validation_matrix?.show_validation_matrix ? (
                <span className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent">Ground truth seed</span>
              ) : (
                <span className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">Start from marked events, findings, or high-confidence suggestions.</span>
              )}
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">Raw MFT and broad EVTX excluded by default</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={regenerateDraft}
              className="inline-flex items-center gap-2 rounded-xl border border-line bg-abyss px-3 py-2 text-sm text-ink hover:border-accent/60"
            >
              <RefreshCw size={16} />
              Regenerate
            </button>
            <button
              type="button"
              onClick={copyMarkdown}
              className="inline-flex items-center gap-2 rounded-xl border border-accent/40 bg-accent/10 px-3 py-2 text-sm text-accent hover:bg-accent/15"
            >
              <Download size={16} />
              Copy Markdown
            </button>
          </div>
        </div>
      </header>

      <section className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <aside className="space-y-4 rounded-2xl border border-line bg-panel/70 p-4">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-ink">
              <Filter size={16} />
              Sources
            </div>
            <div className="mt-3 space-y-2">
              {sourceOptions.map((option) => (
                <label key={option.id} className="flex items-center gap-2 rounded-xl border border-line/70 bg-abyss/50 px-3 py-2 text-sm text-muted">
                  <input
                    type="checkbox"
                    checked={sources.includes(option.id)}
                    onChange={(event) => {
                      setSources((current) => (event.target.checked ? [...current, option.id] : current.filter((item) => item !== option.id)));
                    }}
                  />
                  {option.label}
                </label>
              ))}
            </div>
          </div>

          <div>
            <p className="text-sm font-semibold text-ink">Hosts</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {hostOptions.map((host) => {
                const active = hostFilter.includes(host);
                return (
                  <button
                    type="button"
                    key={host}
                    onClick={() => setHostFilter((current) => (active ? current.filter((item) => item !== host) : [...current, host]))}
                    className={`rounded-full border px-3 py-1 text-xs ${active ? "border-accent/50 bg-accent/10 text-accent" : "border-line bg-abyss text-muted"}`}
                  >
                    {host}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <p className="text-sm font-semibold text-ink">Phases</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {phaseOptions.map((phase) => {
                const active = phaseFilter.includes(phase);
                return (
                  <button
                    type="button"
                    key={phase}
                    onClick={() => setPhaseFilter((current) => (active ? current.filter((item) => item !== phase) : [...current, phase]))}
                    className={`rounded-full border px-3 py-1 text-xs ${active ? "border-accent/50 bg-accent/10 text-accent" : "border-line bg-abyss text-muted"}`}
                  >
                    {PHASE_LABELS[phase] || sourceLabel(phase)}
                  </button>
                );
              })}
            </div>
          </div>

          <label className="flex items-center justify-between rounded-xl border border-line bg-abyss/50 px-3 py-2 text-sm text-muted">
            Include low-signal gaps
            <input type="checkbox" checked={includeLowSignal} onChange={(event) => setIncludeLowSignal(event.target.checked)} />
          </label>

          <div>
            <p className="text-sm font-semibold text-ink">Group by</p>
            <select value={groupBy} onChange={(event) => setGroupBy(event.target.value)} className="mt-2 w-full rounded-xl border border-line bg-abyss px-3 py-2 text-sm text-ink">
              <option value="phase">Phase</option>
              <option value="host">Host</option>
              <option value="none">Time only</option>
            </select>
          </div>

          <details className="rounded-xl border border-line bg-abyss/40 p-3 text-sm text-muted">
            <summary className="cursor-pointer text-ink">Advanced details</summary>
            <div className="mt-2 space-y-1">
              <p>No raw MFT flood by default: {String(draftQuery.data?.no_mft_flood_default ?? true)}</p>
              <p>Draft items: {draftQuery.data?.total ?? 0}</p>
              <p>Official items: {officialItems.length}</p>
              <p>Suggested candidates: {candidateItems.length}</p>
              <p>Dismissed locally: {dismissedItems.length}</p>
              {(draftQuery.data?.warnings || []).slice(0, 5).map((warning) => (
                <p key={warning} className="text-amber-200">{warning}</p>
              ))}
            </div>
          </details>
        </aside>

        <main className="space-y-4">
          {draftQuery.isLoading ? (
            <div className="rounded-2xl border border-line bg-panel/70 p-6 text-sm text-muted">
              <p className="font-medium text-ink">Generating draft timeline...</p>
              <p className="mt-2">Collecting high-signal findings, marked events, command history, Defender detections and curated case seeds. Raw MFT and broad EVTX stay excluded.</p>
            </div>
          ) : draftQuery.isError ? (
            <div className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-6 text-sm text-rose-100">{draftQuery.error instanceof Error ? draftQuery.error.message : "Timeline builder failed."}</div>
          ) : (
            <>
              <div className="grid gap-3 md:grid-cols-4">
                <div className="rounded-2xl border border-line bg-panel/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted">Official</p>
                  <p className="mt-1 text-2xl font-semibold text-ink">{officialItems.length}</p>
                </div>
                <div className="rounded-2xl border border-line bg-panel/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted">Candidates</p>
                  <p className="mt-1 text-2xl font-semibold text-ink">{candidateItems.length}</p>
                </div>
                <div className="rounded-2xl border border-line bg-panel/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted">Needs review</p>
                  <p className="mt-1 text-2xl font-semibold text-ink">{items.filter((item) => item.status === "needs_review").length}</p>
                </div>
                <div className="rounded-2xl border border-line bg-panel/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted">Export</p>
                  <p className="mt-1 text-sm text-muted">{exportStatus || "Official timeline only"}</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 rounded-2xl border border-line bg-panel/70 p-2">
                {TIMELINE_TABS.map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`rounded-xl px-3 py-2 text-sm ${activeTab === tab.id ? "bg-accent/15 text-accent" : "text-muted hover:bg-abyss/70"}`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
              {draftQuery.data?.cache?.hit ? (
                <div className={`rounded-2xl border p-3 text-sm ${draftQuery.data.cache.status === "stale" || draftQuery.data.cache.stale ? "border-amber-400/30 bg-amber-500/10 text-amber-100" : "border-mint/25 bg-mint/10 text-mint"}`}>
                  {draftQuery.data.cache.status === "stale" || draftQuery.data.cache.stale ? (
                    <>
                      Timeline may be outdated. You can use this existing draft or select Regenerate.
                      {draftQuery.data.cache.reason ? <span className="ml-1 text-amber-100/80">{draftQuery.data.cache.reason}</span> : null}
                    </>
                  ) : (
                    <>
                      Using cached draft generated {draftQuery.data.cache.generated_at ? formatTimestamp(draftQuery.data.cache.generated_at, effectiveTimezone) : "recently"}.
                      {typeof draftQuery.data.cache.generation_seconds === "number" ? <span className="ml-1">Original build: {draftQuery.data.cache.generation_seconds.toFixed(1)}s.</span> : null}
                    </>
                  )}
                </div>
              ) : null}
              {regenerateStatus ? (
                <div className="rounded-2xl border border-line bg-panel/70 p-3 text-sm text-muted">{regenerateStatus}</div>
              ) : null}

              {activeTab === "sources" ? (
                <section className="rounded-2xl border border-line bg-panel/70 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <FileText size={16} className="text-accent" />
                    <h2 className="font-semibold text-ink">Sources / Provenance</h2>
                  </div>
                  {caseContext?.summary?.validation_matrix?.show_validation_matrix ? (
                    <p className="mb-4 rounded-xl border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-accent">
                      This validation/training case includes timeline items seeded from imported ground truth. They are labeled as Ground truth seed.
                    </p>
                  ) : (
                    <p className="mb-4 rounded-xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                      Normal investigations start with analyst-added items, findings, marked events, or accepted candidates.
                    </p>
                  )}
                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {sourceSummary.map(([source, count]) => (
                      <div key={source} className="rounded-xl border border-line bg-abyss/60 p-3">
                        <p className="font-medium text-ink">{sourceLabel(source)}</p>
                        <p className="mt-1 text-sm text-muted">{count} items</p>
                      </div>
                    ))}
                  </div>
                </section>
              ) : grouped.map(([group, groupItems]) => (
                <section key={group} className="rounded-2xl border border-line bg-panel/70 p-4">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <GitBranch size={16} className="text-accent" />
                      <h2 className="font-semibold text-ink">{group}</h2>
                    </div>
                    <span className="rounded-full border border-line bg-abyss px-2 py-1 text-xs text-muted">{groupItems.length} items</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="min-w-full text-left text-sm">
                      <thead className="text-xs uppercase tracking-[0.14em] text-muted">
                        <tr className="border-b border-line">
                          <th className="py-2 pr-4">Time</th>
                          <th className="py-2 pr-4">Host</th>
                          <th className="py-2 pr-4">Phase</th>
                          <th className="py-2 pr-4">Event</th>
                          <th className="py-2 pr-4">Source</th>
                          <th className="py-2 pr-4">Risk</th>
                          <th className="py-2 pr-4">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {groupItems.map((item) => (
                          <tr key={item.id} className="border-b border-line/60 align-top">
                            <td className="max-w-[160px] py-3 pr-4 text-muted">{item.timestamp ? formatTimestamp(item.timestamp, effectiveTimezone) : "Unknown"}</td>
                            <td className="py-3 pr-4 text-ink">
                              <p>{item.host || "unknown"}</p>
                              {item.host_alias ? <p className="mt-1 text-xs text-muted">Alias: {item.host_alias}</p> : null}
                            </td>
                            <td className="py-3 pr-4">
                              <select
                                value={item.phase}
                                onChange={(event) => setPhaseOverrides((current) => ({ ...current, [item.id]: event.target.value }))}
                                className="rounded-lg border border-line bg-abyss px-2 py-1 text-xs text-ink"
                              >
                                {phaseOptions.map((phase) => (
                                  <option key={phase} value={phase}>{PHASE_LABELS[phase] || sourceLabel(phase)}</option>
                                ))}
                              </select>
                            </td>
                            <td className="min-w-[280px] max-w-[460px] py-3 pr-4">
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="font-medium text-ink">{item.title}</p>
                                <span className="rounded-full border border-line bg-abyss/70 px-2 py-0.5 text-[11px] text-muted">{item.provenance_badge || sourceLabel(item.source_type || item.source)}</span>
                                <span className="rounded-full border border-line bg-abyss/70 px-2 py-0.5 text-[11px] text-muted">{sourceLabel(item.status)}</span>
                                <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent">{targetLabel(item.story_target_type)}</span>
                              </div>
                              <p className="mt-1 break-words text-xs text-muted">{item.summary || "No summary provided."}</p>
                              {item.story_target_type && item.story_target_type !== "exact_process" ? (
                                <p className="mt-1 text-xs text-muted">No exact process story: {item.story_target_reason || "use linked evidence context."}</p>
                              ) : null}
                              <input
                                value={notes[item.id] ?? item.notes ?? ""}
                                onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))}
                                placeholder="Add analyst note"
                                className="mt-2 w-full rounded-lg border border-line bg-abyss/70 px-2 py-1 text-xs text-ink placeholder:text-muted/60"
                              />
                            </td>
                            <td className="py-3 pr-4 text-muted">
                              <p>{sourceLabel(item.source_type || item.source)}</p>
                              {item.artifact_type ? <p className="text-xs">{sourceLabel(item.artifact_type)}</p> : null}
                              {item.confidence ? <p className="text-xs">Confidence: {sourceLabel(item.confidence)}</p> : null}
                            </td>
                            <td className="py-3 pr-4">
                              <span className={`rounded-full border px-2 py-1 text-xs ${riskClass(item.risk_score || 0)}`}>{item.risk_score || 0}</span>
                            </td>
                            <td className="py-3 pr-4">
                              <div className="flex flex-wrap gap-2">
                                {item.search_url ? (
                                  <Link to={item.search_url} className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-accent hover:border-accent/60">
                                    <Search size={13} />
                                    Search
                                  </Link>
                                ) : null}
                                {item.story_target_type === "exact_process" && item.execution_story_url ? (
                                  <Link to={item.execution_story_url} className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-accent hover:border-accent/60">
                                    <ExternalLink size={13} />
                                    Open Execution Story
                                  </Link>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => setStoryBundleItem(item)}
                                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-accent hover:border-accent/60"
                                  >
                                    <ExternalLink size={13} />
                                    {primaryActionLabel(item)}
                                  </button>
                                )}
                                {item.finding_id ? (
                                  <Link to={`/cases/${caseId}/findings`} className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-accent hover:border-accent/60">
                                    <ShieldAlert size={13} />
                                    Finding
                                  </Link>
                                ) : null}
                                {activeTab === "candidates" ? (
                                  <>
                                    <button type="button" onClick={() => void updateItemStatus(item, "accepted")} className="inline-flex items-center gap-1 rounded-lg border border-accent/40 px-2 py-1 text-xs text-accent hover:bg-accent/10">
                                      Add to timeline
                                    </button>
                                    <button type="button" onClick={() => void updateItemStatus(item, "needs_review")} className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-muted hover:border-amber-400/50 hover:text-amber-100">
                                      Needs review
                                    </button>
                                    <button type="button" onClick={() => void updateItemStatus(item, "dismissed")} className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-muted hover:border-rose-400/50 hover:text-rose-100">
                                      Dismiss
                                    </button>
                                  </>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => void updateItemStatus(item, "dismissed")}
                                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs text-muted hover:border-rose-400/50 hover:text-rose-100"
                                  >
                                    <X size={13} />
                                    Remove
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ))}

              {activeTab !== "sources" && !visibleItems.length ? (
                <div className="rounded-2xl border border-line bg-panel/70 p-6 text-sm text-muted">
                  {activeTab === "official"
                    ? "No official timeline yet. Add marked events, create findings, or review suggested candidates."
                    : "No suggested timeline candidates matched the selected sources and filters."}
                </div>
              ) : null}
            </>
          )}
        </main>
      </section>

      <footer className="rounded-2xl border border-line bg-panel/70 p-4 text-sm text-muted">
        <div className="flex items-start gap-2">
          <FileText size={16} className="mt-0.5 text-accent" />
          <p>
            Use this builder for a curated incident chronology. Open the raw Search Timeline when you need broad event context around a selected item.
          </p>
        </div>
      </footer>

      {storyBundleItem ? (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/55 p-4 sm:items-center">
          <section className="max-h-[86vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-line bg-panel p-5 shadow-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{targetLabel(storyBundleItem.story_target_type)}</p>
                <h2 className="mt-1 text-xl font-semibold text-ink">{storyBundleQuery.data?.target.primary_action || primaryActionLabel(storyBundleItem)}</h2>
                <p className="mt-2 text-sm text-muted">{storyBundleQuery.data?.target.reason || storyBundleItem.story_target_reason || "Evidence context for this timeline item."}</p>
              </div>
              <button type="button" onClick={() => setStoryBundleItem(null)} className="rounded-lg border border-line p-2 text-muted hover:text-ink" aria-label="Close evidence bundle">
                <X size={16} />
              </button>
            </div>

            {storyBundleQuery.isLoading ? (
              <div className="mt-4 rounded-xl border border-line bg-abyss/60 p-4 text-sm text-muted">Loading linked evidence...</div>
            ) : storyBundleQuery.isError ? (
              <div className="mt-4 rounded-xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100">
                {storyBundleQuery.error instanceof Error ? storyBundleQuery.error.message : "Evidence bundle failed."}
              </div>
            ) : (
              <div className="mt-5 space-y-4">
                <div className="rounded-xl border border-line bg-abyss/60 p-4">
                  <p className="font-medium text-ink">{storyBundleQuery.data?.item.title || storyBundleItem.title}</p>
                  <p className="mt-1 text-sm text-muted">{storyBundleQuery.data?.item.summary || storyBundleItem.summary || "No summary provided."}</p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs">
                    <span className="rounded-full border border-line bg-panel/70 px-2 py-1 text-muted">{storyBundleItem.host || "unknown host"}</span>
                    <span className="rounded-full border border-line bg-panel/70 px-2 py-1 text-muted">{PHASE_LABELS[storyBundleItem.phase] || sourceLabel(storyBundleItem.phase)}</span>
                    <span className="rounded-full border border-line bg-panel/70 px-2 py-1 text-muted">{storyBundleItem.timestamp ? formatTimestamp(storyBundleItem.timestamp, effectiveTimezone) : "unknown time"}</span>
                  </div>
                </div>

                {storyBundleQuery.data?.movement ? (
                  <div>
                    <h3 className="mb-2 font-semibold text-ink">Movement Story</h3>
                    <div className="grid gap-2 sm:grid-cols-2">{renderRecordList(storyBundleQuery.data.movement)}</div>
                  </div>
                ) : null}

                {storyBundleQuery.data?.file_story ? (
                  <div>
                    <h3 className="mb-2 font-semibold text-ink">File Story</h3>
                    <div className="grid gap-2 sm:grid-cols-2">{renderRecordList(storyBundleQuery.data.file_story)}</div>
                  </div>
                ) : null}

                <IndicatorResolutionPanel data={storyBundleQuery.data?.indicator_resolution ?? null} />

                <div>
                  <h3 className="mb-2 font-semibold text-ink">Linked Evidence</h3>
                  <div className="grid gap-2 sm:grid-cols-2">{renderRecordList(storyBundleQuery.data?.linked_evidence)}</div>
                </div>

                <div>
                  <h3 className="mb-2 font-semibold text-ink">Pivots</h3>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(storyBundleQuery.data?.pivots || {})
                      .filter(([, value]) => Boolean(value))
                      .map(([key, value]) => (
                        <Link key={key} to={String(value)} title={pivotTooltip(key)} className="inline-flex items-center gap-2 rounded-xl border border-line px-3 py-2 text-sm text-accent hover:border-accent/60">
                          <ExternalLink size={14} />
                          {sourceLabel(key)}
                        </Link>
                      ))}
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      ) : null}
    </div>
  );
}
