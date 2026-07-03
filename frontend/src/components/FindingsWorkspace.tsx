import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, type CorrelationRunResult, type Finding, type FindingStatus, type SearchResponse } from "../api/client";
import ResponsiveDetailPanel from "./ResponsiveDetailPanel";
import { useNotifications } from "../context/NotificationsContext";
import { useTimezonePreference } from "../context/TimezoneContext";
import { formatTimestamp } from "../lib/time";
import EventTable from "./EventTable";
import IndicatorResolutionPanel from "./IndicatorResolutionPanel";
import PaginationControls from "./PaginationControls";

type Props = {
  caseId: string;
  evidenceId?: string;
  host?: string;
  embedded?: boolean;
  showHeader?: boolean;
};

type Filters = {
  severity: string;
  confidence: string;
  status: string;
  findingType: string;
  source: string;
  evidenceId: string;
  process: string;
  pid: string;
  search: string;
};

function severityTone(severity: string) {
  if (severity === "critical") return "border-danger/60 bg-danger/15 text-danger";
  if (severity === "high") return "border-warning/60 bg-warning/15 text-warning";
  if (severity === "medium") return "border-amber-400/50 bg-amber-400/10 text-amber-200";
  if (severity === "low") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200";
  return "border-line bg-white/5 text-muted";
}

function confidenceTone(confidence: string | null | undefined) {
  if (confidence === "exact") return "border-accent/50 bg-accent/10 text-accent";
  if (confidence === "high") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200";
  if (confidence === "medium") return "border-amber-400/40 bg-amber-400/10 text-amber-200";
  return "border-line bg-white/5 text-muted";
}

function statusTone(status: string) {
  if (status === "dismissed" || status === "false_positive" || status === "closed") return "border-line bg-white/5 text-muted";
  if (status === "confirmed") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200";
  if (status === "reviewed") return "border-accent/40 bg-accent/10 text-accent";
  return "border-warning/40 bg-warning/10 text-warning";
}

function normalizeStatus(status: string | null | undefined): "new" | "reviewed" | "confirmed" | "dismissed" {
  if (status === "confirmed") return "confirmed";
  if (status === "reviewed" || status === "triaged" || status === "investigating" || status === "accepted_risk") return "reviewed";
  if (status === "dismissed" || status === "false_positive" || status === "closed" || status === "resolved" || status === "suppressed") return "dismissed";
  return "new";
}

function sourceLabel(finding: Finding) {
  const categories = finding.source_categories?.length ? finding.source_categories : finding.source ? finding.source.split(",") : [];
  const category = categories.filter(Boolean).join(", ") || "Other";
  const producer = finding.source_plugin_or_parser || finding.rule_id || finding.finding_type || "hunting";
  return `${category}: ${producer}`;
}

function uniqueSorted(values: Array<string | null | undefined>) {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value && value.trim())).map((value) => value.trim()))).sort((a, b) => a.localeCompare(b));
}

function sortFindings(items: Finding[]) {
  return [...items].sort((left, right) => {
    const leftDismissed = normalizeStatus(left.status) === "dismissed" ? 1 : 0;
    const rightDismissed = normalizeStatus(right.status) === "dismissed" ? 1 : 0;
    if (leftDismissed !== rightDismissed) return leftDismissed - rightDismissed;
    const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const;
    const leftSeverity = severityRank[left.severity] ?? 0;
    const rightSeverity = severityRank[right.severity] ?? 0;
    if (leftSeverity !== rightSeverity) return rightSeverity - leftSeverity;
    const leftRisk = left.risk_score ?? 0;
    const rightRisk = right.risk_score ?? 0;
    if (leftRisk !== rightRisk) return rightRisk - leftRisk;
    const confidenceRank = { high: 3, medium: 2, low: 1 } as const;
    const leftConfidence = confidenceRank[(left.confidence ?? "low") as keyof typeof confidenceRank] ?? 0;
    const rightConfidence = confidenceRank[(right.confidence ?? "low") as keyof typeof confidenceRank] ?? 0;
    if (leftConfidence !== rightConfidence) return rightConfidence - leftConfidence;
    return String(right.time_start ?? right.created_at ?? "").localeCompare(String(left.time_start ?? left.created_at ?? ""));
  });
}

function matchesFinding(finding: Finding, token: string) {
  if (!token) return true;
  const haystack = [
    finding.title,
    finding.summary,
    ...(finding.related_files ?? []),
    ...(finding.related_domains ?? []),
    ...(finding.related_users ?? []),
    ...(finding.related_hosts ?? []),
    ...(finding.reasons ?? []),
    ...(finding.tags ?? []),
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
  return haystack.includes(token);
}

function Chip({ children, tone = "default" }: { children: string; tone?: "default" | "warning" }) {
  return (
    <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" : "border-line bg-white/5 text-muted"}`}>
      {children}
    </span>
  );
}

function FieldList({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {values.length ? values.map((value) => <Chip key={`${label}-${value}`}>{value}</Chip>) : <span className="text-sm text-muted">None</span>}
      </div>
    </div>
  );
}

function BreakdownList({ title, values }: { title: string; values?: Record<string, number> }) {
  const entries = Object.entries(values ?? {}).filter(([, count]) => count > 0).slice(0, 8);
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{title}</p>
      <div className="mt-3 space-y-1 text-sm">
        {entries.length ? entries.map(([key, count]) => (
          <div key={`${title}-${key}`} className="flex items-center justify-between gap-3">
            <span className="truncate text-muted">{key}</span>
            <span className="font-mono text-ink">{count}</span>
          </div>
        )) : <span className="text-muted">None</span>}
      </div>
    </div>
  );
}

export default function FindingsWorkspace({ caseId, evidenceId = "", host = "", embedded = false, showHeader = true }: Props) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { notify } = useNotifications();
  const { effectiveTimezone } = useTimezonePreference();
  const apiCompat = api as typeof api & {
    listFindingsPage?: typeof api.listFindingsPage;
    updateFindingStatus?: typeof api.updateFindingStatus;
    suppressFinding?: typeof api.suppressFinding;
  };
  const [filters, setFilters] = useState<Filters>({
    severity: "",
    confidence: "",
    status: "",
    findingType: "",
    source: "",
    evidenceId,
    process: "",
    pid: "",
    search: "",
  });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [correlationReport, setCorrelationReport] = useState<CorrelationRunResult | null>(null);

  const findingsQuery = useQuery({
    queryKey: ["findings", caseId, filters, host || "all-hosts", page, pageSize],
    queryFn: async () => {
      if (typeof apiCompat.listFindingsPage !== "function") {
        const legacy = await api.listFindings(caseId, { evidence_id: filters.evidenceId || undefined, host: host || undefined });
        return { items: legacy, results: legacy, total: legacy.length, page: 1, page_size: legacy.length || pageSize, total_pages: legacy.length ? 1 : 0 };
      }
      const response = await apiCompat.listFindingsPage(caseId, {
        severity: filters.severity || undefined,
        confidence: filters.confidence || undefined,
        status: filters.status || undefined,
        rule: filters.findingType || undefined,
        source_category: filters.source || undefined,
        evidence_id: filters.evidenceId || undefined,
        process_entity_id: filters.process || undefined,
        pid: filters.pid || undefined,
        page,
        page_size: pageSize,
      });
      return response;
    },
    enabled: Boolean(caseId),
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });

  const runCorrelationMutation = useMutation({
    mutationFn: ({ page = 1 }: { page?: number } = {}) => api.runCorrelation(caseId, { evidence_id: filters.evidenceId || undefined, host: host || undefined, force: true, page, page_size: 25 }),
    onSuccess: ({ report }) => {
      setCorrelationReport(report);
      notify({
        title: "Correlation completed",
        description: `${report.counts?.matched ?? report.findings_generated} matched · ${report.counts?.deduplicated ?? report.findings_deduplicated} deduplicated`,
        tone: "success",
      });
      void queryClient.invalidateQueries({ queryKey: ["findings", caseId] });
    },
    onError: (error: Error) => {
      notify({ title: "Correlation failed", description: error.message, tone: "error" });
    },
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) => (typeof apiCompat.updateFindingStatus === "function" ? apiCompat.updateFindingStatus(caseId, findingId, { status }) : api.updateFinding(caseId, findingId, { status })),
    onSuccess: (updated) => {
      notify({ title: "Finding updated", description: `${updated.title} -> ${updated.status}`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["findings", caseId] });
    },
    onError: (error: Error) => {
      notify({ title: "Status update failed", description: error.message, tone: "error" });
    },
  });

  const suppressMutation = useMutation({
    mutationFn: ({ findingId, reason }: { findingId: string; reason?: string }) => (typeof apiCompat.suppressFinding === "function" ? apiCompat.suppressFinding(caseId, findingId, { reason }) : api.updateFinding(caseId, findingId, { status: "dismissed" as FindingStatus, data_quality: [reason || "suppressed"] })),
    onSuccess: () => {
      notify({ title: "Finding suppressed", description: "Suppression history was preserved.", tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["findings", caseId] });
    },
    onError: (error: Error) => notify({ title: "Suppression failed", description: error.message, tone: "error" }),
  });

  useEffect(() => {
    setPage(1);
  }, [filters, pageSize]);

  const serverFindings = findingsQuery.data?.items ?? [];
  const sortedFindings = useMemo(() => sortFindings(serverFindings), [serverFindings]);
  const evidenceOptions = useMemo(() => uniqueSorted(sortedFindings.map((finding) => finding.evidence_id ?? null)), [sortedFindings]);
  const findingTypeOptions = useMemo(() => uniqueSorted(sortedFindings.map((finding) => finding.finding_type ?? null)), [sortedFindings]);

  const filteredFindings = useMemo(() => {
    const token = filters.search.trim().toLowerCase();
    return sortedFindings.filter((finding) => {
      if (filters.severity && finding.severity !== filters.severity) return false;
      if (filters.confidence && (finding.confidence ?? "") !== filters.confidence) return false;
      if (filters.status && normalizeStatus(finding.status) !== filters.status) return false;
      if (filters.findingType && (finding.finding_type ?? "") !== filters.findingType) return false;
      if (filters.source && !(finding.source_categories ?? finding.source?.split(",") ?? []).includes(filters.source)) return false;
      if (filters.evidenceId && (finding.evidence_id ?? "") !== filters.evidenceId) return false;
      if (filters.process && (finding.process_entity_id ?? finding.related_process_node_ids?.[0] ?? "") !== filters.process) return false;
      if (filters.pid && String(finding.pid ?? "") !== filters.pid) return false;
      if (host && !(finding.related_hosts ?? []).some((item) => item === host)) return false;
      return matchesFinding(finding, token);
    });
  }, [filters, host, sortedFindings]);

  const correlationMatched = correlationReport?.counts?.matched ?? correlationReport?.findings_generated ?? 0;
  const correlationPage = correlationReport?.limits?.page ?? 1;
  const correlationPageSize = correlationReport?.limits?.page_size ?? 25;
  const correlationVisible = correlationReport ? Math.min(correlationMatched, correlationPage * correlationPageSize) : 0;
  const correlationHasMore = Boolean(correlationReport?.counts?.has_more || correlationReport?.pagination?.has_more);
  const effectiveScope = correlationReport?.effective_scope || correlationReport?.scope;
  const effectiveScopeLabel = effectiveScope?.all_hosts
    ? "all hosts"
    : [effectiveScope?.canonical_host || effectiveScope?.host, effectiveScope?.evidence_id ? `evidence ${String(effectiveScope.evidence_id).slice(0, 8)}` : ""].filter(Boolean).join(" / ") || correlationReport?.scope?.scope_type || "case";
  const requestedHost = host || "";
  const effectiveHost = String(effectiveScope?.canonical_host || effectiveScope?.host || "");
  const scopeMismatch = Boolean(
    requestedHost &&
      (
        effectiveScope?.all_hosts ||
        !effectiveHost ||
        (requestedHost.toLowerCase() !== effectiveHost.toLowerCase() && !effectiveHost.toLowerCase().startsWith(requestedHost.toLowerCase().split(".", 1)[0]))
      ),
  );

  const selectedFinding = useMemo(
    () => {
      if (selectedFindingId) return filteredFindings.find((finding) => finding.id === selectedFindingId) ?? null;
      return null;
    },
    [filteredFindings, selectedFindingId],
  );

  useEffect(() => {
    if (!filteredFindings.length) {
      if (selectedFindingId !== null) setSelectedFindingId(null);
      return;
    }
    if (!selectedFindingId) return;
    if (!filteredFindings.some((finding) => finding.id === selectedFindingId)) {
      setSelectedFindingId(null);
    }
  }, [filteredFindings, selectedFindingId]);

  const relatedEventsQuery = useQuery({
    queryKey: ["finding-related-events", caseId, selectedFinding?.id],
    queryFn: async () => {
      const eventIds = selectedFinding?.related_event_ids ?? [];
      if (!eventIds.length) {
        return {
          total: 0,
          total_relation: "eq",
          has_more: false,
          page: 1,
          page_size: 25,
          total_pages: 1,
          total_pages_visible: 1,
          deep_pagination_supported: false,
          result_window_limit: 0,
          has_more_beyond_window: false,
          result_profile: {
            is_homogeneous: true,
            artifact_types: [],
            event_categories: [],
            recommended_view: "auto",
          },
          items: [],
        } satisfies SearchResponse;
      }
      return api.search({
        case_id: caseId,
        query: "*",
        filters: {
          event_id: eventIds,
          evidence_id: selectedFinding?.evidence_id ? [selectedFinding.evidence_id] : [],
        },
        page: 1,
        page_size: Math.max(eventIds.length, 25),
      });
    },
    enabled: Boolean(caseId && selectedFinding?.related_event_ids?.length),
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });

  const findingIndicatorsQuery = useQuery({
    queryKey: ["finding-indicator-resolution", caseId, selectedFinding?.id],
    queryFn: () =>
      api.extractAndResolveIndicators(caseId, {
        source: {
          title: selectedFinding?.title,
          summary: selectedFinding?.summary,
          description: selectedFinding?.description,
          related_files: selectedFinding?.related_files,
          related_domains: selectedFinding?.related_domains,
          related_ips: selectedFinding?.related_ips,
          related_users: selectedFinding?.related_users,
          reasons: selectedFinding?.reasons,
          tags: selectedFinding?.tags,
        },
        context: {
          evidence_id: selectedFinding?.evidence_id,
          host: selectedFinding?.related_hosts?.[0],
          timestamp: selectedFinding?.time_start ?? selectedFinding?.created_at,
        },
      }),
    enabled: Boolean(caseId && selectedFinding?.id),
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });

  const overview = useMemo(() => {
    const counts = { total: filteredFindings.length, critical: 0, high: 0, medium: 0, new: 0, reviewed: 0, confirmed: 0, dismissed: 0 };
    for (const finding of filteredFindings) {
      if (finding.severity === "critical") counts.critical += 1;
      if (finding.severity === "high") counts.high += 1;
      if (finding.severity === "medium") counts.medium += 1;
      counts[normalizeStatus(finding.status)] += 1;
    }
    return counts;
  }, [filteredFindings]);

  const relatedEventsById = useMemo(() => {
    const entries = (relatedEventsQuery.data?.items ?? []).map((item) => [String(item.id ?? ""), item] as const);
    return new Map(entries.filter(([id]) => Boolean(id)));
  }, [relatedEventsQuery.data?.items]);

  const findingDetailContent = selectedFinding ? (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Finding detail</p>
          <h3 className="mt-2 break-words text-2xl font-semibold">{selectedFinding.title}</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${severityTone(selectedFinding.severity)}`}>{selectedFinding.severity}</span>
            <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${confidenceTone(selectedFinding.confidence)}`}>{selectedFinding.confidence ?? "low"}</span>
            <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${statusTone(normalizeStatus(selectedFinding.status))}`}>{normalizeStatus(selectedFinding.status)}</span>
            {selectedFinding.finding_type ? <Chip>{selectedFinding.finding_type}</Chip> : null}
          </div>
        </div>
        <div className="min-w-0 w-full space-y-2 md:w-[260px]">
          <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
            <p>Risk score: <span className="font-semibold text-white">{selectedFinding.risk_score ?? 0}</span></p>
            <p className="break-words">Time range: <span className="text-white">{formatTimestamp(selectedFinding.time_start ?? selectedFinding.created_at, effectiveTimezone)}</span> → <span className="text-white">{formatTimestamp(selectedFinding.time_end ?? selectedFinding.updated_at, effectiveTimezone)}</span></p>
            <p className="break-words">Source: <span className="text-white">{sourceLabel(selectedFinding)}</span></p>
            <p className="break-words">Rule/version: <span className="text-white">{selectedFinding.rule_id || selectedFinding.finding_type || "manual"} {selectedFinding.rule_version || selectedFinding.correlation_version || ""}</span></p>
            <p className="break-words">Process: <span className="text-white">{selectedFinding.process_entity_id || selectedFinding.related_process_node_ids?.[0] || "n/a"}{selectedFinding.pid ? ` / PID ${selectedFinding.pid}` : ""}</span></p>
          </div>
          <select
            aria-label="Finding status"
            value={normalizeStatus(selectedFinding.status)}
            onChange={(event) => updateStatusMutation.mutate({ findingId: selectedFinding.id, status: event.target.value as FindingStatus })}
            className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"
          >
            {["new", "reviewed", "confirmed", "dismissed", "false_positive", "accepted_risk", "resolved", "suppressed"].map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <button type="button" onClick={() => suppressMutation.mutate({ findingId: selectedFinding.id, reason: "Suppressed from finding detail" })} className="w-full rounded-2xl border border-warning/40 bg-warning/10 px-4 py-2 text-sm text-warning">
            Suppress finding
          </button>
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <p className="break-words text-sm text-muted">{selectedFinding.summary || selectedFinding.description || "No summary available."}</p>
      </div>

      <IndicatorResolutionPanel
        data={findingIndicatorsQuery.data}
        loading={findingIndicatorsQuery.isPending}
        error={findingIndicatorsQuery.error instanceof Error ? findingIndicatorsQuery.error : null}
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Reasons</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {(selectedFinding.reasons ?? []).length ? (selectedFinding.reasons ?? []).map((reason) => <Chip key={`${selectedFinding.id}-${reason}`} tone="warning">{reason}</Chip>) : <span className="text-sm text-muted">No explicit reasons</span>}
          </div>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Matched fields</p>
          <div className="mt-3 space-y-2 text-sm text-muted">
            {Object.entries(selectedFinding.matched_values ?? selectedFinding.matched_fields ?? {}).length ? Object.entries(selectedFinding.matched_values ?? selectedFinding.matched_fields ?? {}).map(([field, values]) => (
              <p key={`${selectedFinding.id}-${field}`} className="break-words"><span className="font-mono text-accent">{field}</span>: {(values ?? []).join(" · ")}</p>
            )) : <span>No matched field details</span>}
          </div>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Contradictions and uncertainty</p>
          <div className="mt-3 space-y-2 text-sm text-muted">
            {Object.entries(selectedFinding.contradictory_fields ?? {}).map(([field, values]) => <p key={`${selectedFinding.id}-contradiction-${field}`} className="break-words"><span className="font-mono text-warning">{field}</span>: {values.join(" · ")}</p>)}
            {(selectedFinding.missing_prerequisites ?? []).map((value) => <p key={`${selectedFinding.id}-missing-${value}`} className="break-words">Missing prerequisite: {value}</p>)}
            {!Object.keys(selectedFinding.contradictory_fields ?? {}).length && !(selectedFinding.missing_prerequisites ?? []).length ? <span>No contradictions or missing prerequisites reported.</span> : null}
          </div>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Recommended triage</p>
          <div className="mt-3 space-y-2">
            {(selectedFinding.recommended_triage ?? []).length ? (selectedFinding.recommended_triage ?? []).map((step) => <p key={`${selectedFinding.id}-${step}`} className="break-words rounded-xl border border-line/70 bg-panel/40 px-3 py-2 text-sm text-muted">{step}</p>) : <span className="text-sm text-muted">No triage guidance</span>}
          </div>
        </div>
      </div>

      {(selectedFinding.data_quality ?? []).length ? (
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Data quality</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {(selectedFinding.data_quality ?? []).map((item) => <Chip key={`${selectedFinding.id}-${item}`}>{item}</Chip>)}
          </div>
        </div>
      ) : null}

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Investigation actions</p>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={openFindingSearch} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
              Open Search
            </button>
            <button type="button" onClick={openFindingTimeline} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
              Open Incident Timeline
            </button>
            <button type="button" onClick={openFindingCommandHistory} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
              Open Command History
            </button>
            {selectedFinding.related_process_node_ids?.length ? (
              <button type="button" aria-label="Open in Process Graph" onClick={openProcessGraph} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                Focus Graph
              </button>
            ) : null}
            <button type="button" onClick={openFindingNetwork} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
              Open Network
            </button>
          </div>
        </div>
        <div className="mt-3 space-y-3">
          {(selectedFinding.timeline ?? [])
            .slice()
            .sort((left, right) => String(left.timestamp ?? "").localeCompare(String(right.timestamp ?? "")))
            .map((item, index) => {
              const eventId = typeof item.event_id === "string" ? item.event_id : null;
              const relatedEvent = eventId ? relatedEventsById.get(eventId) : null;
              return (
                <div key={`${selectedFinding.id}-timeline-${index}`} className="rounded-2xl border border-line/70 bg-panel/40 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted">
                    <span>{formatTimestamp(item.timestamp ?? null, effectiveTimezone)}</span>
                    <span className="break-words">{item.artifact_type ?? "-"}</span>
                    <span className="break-words">{item.event_type ?? "-"}</span>
                  </div>
                  <p className="mt-2 break-words text-sm">{item.summary ?? "No event summary."}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {eventId ? (
                      <button type="button" onClick={() => openFindingEvent(eventId)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                        Open source event
                      </button>
                    ) : null}
                    {relatedEvent ? (
                      <button type="button" onClick={() => openFindingProcessTree(relatedEvent as Record<string, unknown>)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                        View process tree
                      </button>
                    ) : null}
                  </div>
                </div>
              );
            })}
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Related events</p>
        <div className="mt-3">
          {relatedEventsQuery.isPending ? <p className="text-sm text-muted">Resolving related events…</p> : null}
          {relatedEventsQuery.error instanceof Error ? <p className="text-sm text-danger">{relatedEventsQuery.error.message}</p> : null}
          {relatedEventsQuery.data?.items?.length ? (
            <EventTable items={relatedEventsQuery.data.items} view="auto" onViewProcessTree={openFindingProcessTree} />
          ) : !relatedEventsQuery.isPending ? (
            <div className="space-y-2">
              {(selectedFinding.related_event_ids ?? []).map((eventId) => (
                <div key={`${selectedFinding.id}-${eventId}`} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line/70 bg-panel/40 px-3 py-2 text-sm">
                  <span className="break-all font-mono text-xs text-muted">{eventId}</span>
                  <button type="button" onClick={() => openFindingEvent(eventId)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">
                    Open
                  </button>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <FieldList label="Files" values={selectedFinding.related_files ?? []} />
        <FieldList label="Domains" values={selectedFinding.related_domains ?? []} />
        <FieldList label="IPs" values={selectedFinding.related_ips ?? []} />
        <FieldList label="Users" values={selectedFinding.related_users ?? []} />
        <FieldList label="Hosts" values={selectedFinding.related_hosts ?? []} />
        <FieldList label="Process nodes" values={selectedFinding.related_process_node_ids ?? []} />
      </div>
    </div>
  ) : (
    <p className="text-sm text-muted">Select a finding to inspect its story.</p>
  );

  function openFindingEvent(eventId: string | null | undefined) {
    if (!eventId) return;
    const params = new URLSearchParams({ tab: "search", event_id: eventId });
    if (selectedFinding?.evidence_id) params.set("evidence_id", selectedFinding.evidence_id);
    navigate(`/cases/${caseId}?${params.toString()}`);
  }

  function appendFindingScope(params: URLSearchParams) {
    if (!selectedFinding) return;
    if (selectedFinding.evidence_id) params.set("evidence_id", selectedFinding.evidence_id);
    const processEntityId = selectedFinding.process_entity_id || selectedFinding.related_process_node_ids?.[0];
    if (processEntityId) params.set("process_entity_id", processEntityId);
    if (selectedFinding.pid) params.set("pid", String(selectedFinding.pid));
    const source = selectedFinding.source_categories?.[0] || selectedFinding.source?.split(",")?.[0];
    if (source) params.set("source_category", source);
    params.set("finding_id", selectedFinding.id);
  }

  function openFindingSearch() {
    const params = new URLSearchParams();
    appendFindingScope(params);
    navigate(`/cases/${caseId}/search?${params.toString()}`);
  }

  function openFindingCommandHistory() {
    const params = new URLSearchParams();
    appendFindingScope(params);
    navigate(`/cases/${caseId}/command-history?${params.toString()}`);
  }

  function openFindingNetwork() {
    const params = new URLSearchParams({ tab: "network" });
    appendFindingScope(params);
    navigate(`/cases/${caseId}/memory${selectedFinding?.evidence_id ? `/${selectedFinding.evidence_id}` : ""}?${params.toString()}`);
  }

  function openFindingProcessTree(item: Record<string, unknown>) {
    const process = (item.process as Record<string, unknown>) ?? {};
    const params = new URLSearchParams({ mode: "process_focus" });
    const eventEvidenceId = String(item.evidence_id ?? selectedFinding?.evidence_id ?? "").trim();
    const relatedProcessNodeIds = Array.isArray(item.related_process_node_ids)
      ? (item.related_process_node_ids as unknown[]).map((value) => String(value ?? "").trim()).filter(Boolean)
      : [];
    const processEntityId = String(process.entity_id ?? "").trim();
    if (eventEvidenceId) params.set("evidence_id", eventEvidenceId);
    if (relatedProcessNodeIds.length) {
      for (const nodeId of relatedProcessNodeIds) params.append("process_node_id", nodeId);
    } else if (processEntityId) {
      params.set("process_node_id", processEntityId);
    } else {
      if (process.pid !== undefined && process.pid !== null && String(process.pid).trim()) params.set("pid", String(process.pid));
      if (process.name !== undefined && process.name !== null && String(process.name).trim()) params.set("process_name", String(process.name));
    }
    navigate(`/cases/${caseId}/process-graph?${params.toString()}`);
  }

  function openProcessGraph() {
    if (!selectedFinding?.related_process_node_ids?.length) return;
    const params = new URLSearchParams({ mode: "finding_focus" });
    if (selectedFinding.evidence_id) params.set("evidence_id", selectedFinding.evidence_id);
    params.set("finding_id", selectedFinding.id);
    for (const nodeId of selectedFinding.related_process_node_ids) params.append("node_id", nodeId);
    navigate(`/cases/${caseId}/process-graph?${params.toString()}`);
  }

  function openFindingTimeline() {
    if (!selectedFinding) return;
    const params = new URLSearchParams();
    params.set("mode", "investigation");
    appendFindingScope(params);
    navigate(`/cases/${caseId}/timeline?${params.toString()}`);
  }

  return (
    <section className="space-y-4">
      {showHeader ? (
        <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Findings</p>
              <h3 className="mt-2 text-2xl font-semibold">Investigation workspace</h3>
              <p className="mt-2 max-w-3xl text-sm text-muted">Prioriza hallazgos correlados, abre la historia completa y salta al proceso o evento original sin volver a buscarlo a mano.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => runCorrelationMutation.mutate({ page: 1 })}
                disabled={runCorrelationMutation.isPending || !caseId}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {runCorrelationMutation.isPending ? "Running correlation…" : "Run correlation"}
              </button>
              <button
                type="button"
                onClick={() => void findingsQuery.refetch()}
                className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
              >
                Refresh findings
              </button>
            </div>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-4 xl:grid-cols-8">
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Total</p><p className="mt-2 text-lg font-semibold">{overview.total}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Critical</p><p className="mt-2 text-lg font-semibold">{overview.critical}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">High</p><p className="mt-2 text-lg font-semibold">{overview.high}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Medium</p><p className="mt-2 text-lg font-semibold">{overview.medium}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">New</p><p className="mt-2 text-lg font-semibold">{overview.new}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Reviewed</p><p className="mt-2 text-lg font-semibold">{overview.reviewed}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Confirmed</p><p className="mt-2 text-lg font-semibold">{overview.confirmed}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Dismissed</p><p className="mt-2 text-lg font-semibold">{overview.dismissed}</p></div>
          </div>
          {correlationReport ? (
            <div className="mt-4 rounded-3xl border border-line bg-abyss/60 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Correlation scope</p>
                  <p className="mt-1 text-sm text-ink">
                    Showing {correlationVisible} of {correlationMatched} correlated items
                    {correlationHasMore ? " · more results available" : " · exhaustive for this run"}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    Scope: {effectiveScopeLabel} · candidates scanned: {correlationReport.counts?.candidates_scanned ?? 0}
                    {correlationReport.limits?.reason && correlationReport.limits.reason !== "none" ? ` · limit: ${correlationReport.limits.reason}` : ""}
                    {correlationReport.counts?.hidden_by_limit ? ` · hidden by current page: ${correlationReport.counts.hidden_by_limit}` : ""}
                  </p>
                  {scopeMismatch ? <p className="mt-2 rounded-2xl border border-amber-400/40 bg-amber-400/10 px-3 py-2 text-xs text-amber-200">Backend effective scope differs from the selected UI host filter. Review returned hosts before using these findings.</p> : null}
                  {correlationReport.cache_key ? <p className="mt-1 font-mono text-[10px] text-muted">Run {correlationReport.correlation_run_id || "n/a"} · cache {correlationReport.cache_key}</p> : null}
                </div>
                {correlationHasMore ? (
                  <button
                    type="button"
                    disabled={runCorrelationMutation.isPending}
                    onClick={() => runCorrelationMutation.mutate({ page: correlationPage + 1 })}
                    className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-50"
                  >
                    Load more
                  </button>
                ) : null}
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <BreakdownList title="Sources scanned" values={correlationReport.source_breakdown} />
                <BreakdownList title="Hosts scanned" values={correlationReport.host_breakdown} />
                <BreakdownList title="Finding types" values={correlationReport.result_source_breakdown || correlationReport.by_type} />
                <BreakdownList title="Finding hosts" values={correlationReport.result_host_breakdown} />
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Severity</span>
            <select value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {["critical", "high", "medium", "low", "info"].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Confidence</span>
            <select value={filters.confidence} onChange={(event) => setFilters((current) => ({ ...current, confidence: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {["high", "medium", "low"].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Status</span>
            <select value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {["new", "reviewed", "confirmed", "dismissed"].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Finding type</span>
            <select value={filters.findingType} onChange={(event) => setFilters((current) => ({ ...current, findingType: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {findingTypeOptions.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source</span>
            <select value={filters.source} onChange={(event) => setFilters((current) => ({ ...current, source: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {["Memory", "Disk", "Event Log", "Registry", "Network Log", "Other"].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence</span>
            <select value={filters.evidenceId} onChange={(event) => setFilters((current) => ({ ...current, evidenceId: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="">All</option>
              {evidenceOptions.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Process</span>
            <input value={filters.process} onChange={(event) => setFilters((current) => ({ ...current, process: event.target.value }))} placeholder="canonical entity id" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">PID</span>
            <input value={filters.pid} onChange={(event) => setFilters((current) => ({ ...current, pid: event.target.value }))} placeholder="6996" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search</span>
            <input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="title, path, domain, host, user…" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
        </div>
      </div>

      <PaginationControls page={page} totalPages={findingsQuery.data?.total_pages ?? 0} total={findingsQuery.data?.total ?? filteredFindings.length} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={setPageSize} />

      {findingsQuery.isPending ? <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">Loading findings…</div> : null}
      {findingsQuery.error instanceof Error ? <div className="rounded-3xl border border-danger/40 bg-danger/10 p-6 text-sm text-danger">{findingsQuery.error.message}</div> : null}

      {!findingsQuery.isPending && !filteredFindings.length ? (
        <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">
          <p className="text-base font-semibold text-white">No findings yet</p>
          <p className="mt-2">No findings were generated by the evaluated rules for the available artifacts.</p>
          <p className="mt-2">If rules have not been evaluated yet, run hunting evaluation from Rules. Current filters may also hide existing findings.</p>
          <button
            type="button"
            onClick={() => runCorrelationMutation.mutate({ page: 1 })}
            className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss"
          >
            Run correlation
          </button>
        </div>
      ) : null}

      {filteredFindings.length ? (
        <div className="grid grid-cols-1 gap-4">
          <div className="space-y-3">
            {filteredFindings.map((finding) => {
              const isSelected = selectedFinding?.id === finding.id;
              const normalizedStatus = normalizeStatus(finding.status);
              return (
                <button
                  key={finding.id}
                  type="button"
                  data-testid={`finding-card-${finding.id}`}
                  onClick={() => setSelectedFindingId(finding.id)}
                  className={`w-full rounded-3xl border p-5 text-left shadow-panel transition ${isSelected ? "border-accent bg-accent/10" : normalizedStatus === "dismissed" ? "border-line bg-panel/30 opacity-70" : "border-line bg-panel/70 hover:bg-panel/80"}`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="break-words text-base font-semibold">{finding.title}</span>
                        <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${severityTone(finding.severity)}`}>{finding.severity}</span>
                        <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${confidenceTone(finding.confidence)}`}>{finding.confidence ?? "low"}</span>
                        <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${statusTone(normalizedStatus)}`}>{normalizedStatus}</span>
                        <Chip>{sourceLabel(finding)}</Chip>
                      </div>
                      <p className="mt-3 line-clamp-2 text-sm text-muted">{finding.summary || finding.description || "No summary."}</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {(finding.reasons ?? []).slice(0, 3).map((reason) => <Chip key={`${finding.id}-${reason}`} tone="warning">{reason}</Chip>)}
                        {(finding.tags ?? []).slice(0, 3).map((tag) => <Chip key={`${finding.id}-${tag}`}>{tag}</Chip>)}
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted">
                      <p>risk {finding.risk_score ?? 0}</p>
                      <p>{formatTimestamp(finding.first_seen ?? finding.time_start ?? finding.created_at, effectiveTimezone)}</p>
                      <p>{finding.grouped_artifact_count ?? finding.related_artifact_ids?.length ?? 0} artifacts</p>
                      {finding.pid ? <p>PID {finding.pid}</p> : null}
                      {finding.evidence_id ? <p className="font-mono">{finding.evidence_id.slice(0, 8)}</p> : null}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      ) : null}

      {filteredFindings.length ? <PaginationControls page={page} totalPages={findingsQuery.data?.total_pages ?? 0} total={findingsQuery.data?.total ?? filteredFindings.length} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={setPageSize} /> : null}

      {filteredFindings.length && selectedFinding ? (
        <ResponsiveDetailPanel open mode="drawer" widthClass="h-full w-full sm:w-[88vw] xl:w-[82vw] 2xl:w-[78vw]" heading="Finding detail" subheading="Wide investigation detail aligned with Search, Timeline and Detections." onClose={() => setSelectedFindingId(null)}>
          {findingDetailContent}
        </ResponsiveDetailPanel>
      ) : null}
    </section>
  );
}
