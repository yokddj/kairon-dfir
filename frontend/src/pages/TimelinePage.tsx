import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Bookmark, Clock3, ExternalLink, FileSearch, Filter, Network, RefreshCw, Search, ShieldAlert, UploadCloud, X } from "lucide-react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { api, type SearchQuickFilter, type TimelineBookmark, type TimelineItem, type TimelineMode } from "../api/client";
import PaginationControls from "../components/PaginationControls";
import ResponsiveDetailPanel from "../components/ResponsiveDetailPanel";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";
import { compareValues, nextSortDirection, type SortDirection } from "../lib/sorting";
import { formatTimestamp } from "../lib/time";


function riskTone(score: number) {
  if (score >= 90) return "border-rose-400/40 bg-rose-500/10 text-rose-200";
  if (score >= 70) return "border-amber-400/40 bg-amber-500/10 text-amber-100";
  if (score >= 40) return "border-cyan-400/40 bg-cyan-500/10 text-cyan-100";
  return "border-line bg-abyss/60 text-muted";
}

function compact(value: string | null | undefined, fallback = "—") {
  return value && value.trim() ? value.trim() : fallback;
}

function humanizeToken(value: string | null | undefined, fallback = "—") {
  if (!value || !value.trim()) return fallback;
  return value
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
}

function artifactLabel(value: string | null | undefined) {
  const normalized = (value || "").trim().toLowerCase();
  if (!normalized) return "—";
  if (normalized === "user_activity") return "User Activity";
  if (normalized === "email") return "Email";
  if (normalized === "ntfs") return "NTFS";
  if (normalized === "windows_ui") return "Windows UI";
  if (normalized === "cloud_sync") return "Cloud Sync";
  if (normalized === "recycle_bin") return "Recycle Bin";
  return humanizeToken(normalized);
}

function paramValues(params: URLSearchParams, key: string) {
  const values = params.getAll(key).map((value) => value.trim()).filter(Boolean);
  if (values.length) return values;
  const single = params.get(key);
  if (!single) return undefined;
  const split = single.split(",").map((value) => value.trim()).filter(Boolean);
  return split.length ? split : undefined;
}

function itemTimestamp(item: TimelineItem, timezone: string) {
  return item.timestamp ? formatTimestamp(item.timestamp, timezone) : "Undated";
}

function timelineSortValue(item: TimelineItem, key: string) {
  switch (key) {
    case "timestamp":
      return item.timestamp;
    case "risk":
      return item.risk_score ?? 0;
    case "kind":
      return item.kind;
    case "artifact":
      return item.artifact_type;
    case "type":
      return item.event_type;
    case "host":
      return item.host;
    case "summary":
      return item.summary || item.title;
    default:
      return item.summary || item.title;
  }
}

function TimelinePage() {
  const { caseId: routeCaseId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const {
    activeCaseId,
    selectedHost,
    selectedEvidenceId,
    setActiveCaseId,
  } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const caseId = routeCaseId || activeCaseId;
  const requestedEvidenceId = searchParams.get("evidence_id") ?? "";
  const resolvedEvidenceId = requestedEvidenceId || selectedEvidenceId || "";
  const mode = (searchParams.get("mode") as TimelineMode | null) ?? "investigation";
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const [sort, setSort] = useState(searchParams.get("sort") ?? "timestamp_desc");
  const [timeFrom, setTimeFrom] = useState(searchParams.get("time_from") ?? "");
  const [timeTo, setTimeTo] = useState(searchParams.get("time_to") ?? "");
  const [riskMin, setRiskMin] = useState(searchParams.get("risk_min") ?? (mode === "investigation" ? "40" : ""));
  const [groupBy, setGroupBy] = useState(searchParams.get("group_by") ?? "hour");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get("selected"));
  const [tableSortKey, setTableSortKey] = useState("timestamp");
  const [tableSortDirection, setTableSortDirection] = useState<SortDirection>("desc");
  const [bookmarkDraft, setBookmarkDraft] = useState<{ open: boolean; item: TimelineItem | null; note: string; category: TimelineBookmark["category"]; importance: TimelineBookmark["importance"] }>({
    open: false,
    item: null,
    note: "",
    category: "other",
    importance: "medium",
  });
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const focusedContextRef = useRef<string>("");

  useEffect(() => {
    if (routeCaseId) {
      setActiveCaseId(routeCaseId);
    }
  }, [routeCaseId, setActiveCaseId]);

  useEffect(() => {
    setRiskMin((current) => {
      if (mode !== "investigation") return current === "40" ? "" : current;
      return current || "40";
    });
  }, [mode]);

  const timelineParams = useMemo(
    () => ({
      host: selectedHost || undefined,
      evidence_id: resolvedEvidenceId || undefined,
      mode,
      q: query || undefined,
      artifact_type: paramValues(searchParams, "artifact_type"),
      event_type: paramValues(searchParams, "event_type"),
      event_category: paramValues(searchParams, "event_category"),
      kind: searchParams.get("kind") || undefined,
      risk_min: riskMin ? Number(riskMin) : undefined,
      time_from: timeFrom || undefined,
      time_to: timeTo || undefined,
      sort: sort as "timestamp_desc" | "timestamp_asc" | "risk_desc" | "risk_asc",
      page_size: 100,
      cursor: cursorStack.length ? cursorStack[cursorStack.length - 1] : undefined,
      include_findings: searchParams.get("include_findings") !== "false",
      include_bookmarks: searchParams.get("include_bookmarks") !== "false",
      include_facets: false,
      lightweight: true,
      group_by: groupBy as "none" | "hour" | "day",
      finding_id: searchParams.get("finding_id") || undefined,
      key_events_only: searchParams.get("key_events_only") === "true" || undefined,
    }),
    [selectedHost, resolvedEvidenceId, mode, query, riskMin, timeFrom, timeTo, sort, cursorStack, groupBy, searchParams],
  );

  const timelineQuery = useQuery({
    queryKey: ["case-timeline-v2", caseId, timelineParams],
    queryFn: () => api.getTimeline(caseId!, timelineParams),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });
  const quickFiltersQuery = useQuery({
    queryKey: ["timeline-quick-filters", caseId],
    queryFn: () => api.getTimelineQuickFilters(caseId!),
    enabled: Boolean(caseId),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const keyEventsQuery = useQuery({
    queryKey: ["timeline-key-events", caseId],
    queryFn: () => api.listTimelineKeyEvents(caseId!),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const selectedItem = useMemo(
    () => timelineQuery.data?.items.find((item) => item.id === selectedId) ?? null,
    [timelineQuery.data?.items, selectedId],
  );
  const selectedObservedHost = useMemo(() => {
    const raw = (selectedItem?.raw ?? {}) as Record<string, unknown>;
    const observed = ((raw.observed_host ?? {}) as Record<string, unknown>).name;
    return typeof observed === "string" ? observed : "";
  }, [selectedItem]);
  const selectedTimelineDetail = selectedItem ? (
    <div className="space-y-4">
      <div className="min-w-0">
        <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">{selectedItem.kind}</p>
        <h3 className="mt-2 break-words text-lg font-semibold">{selectedItem.title}</h3>
        <p className="mt-2 break-words text-sm text-muted">{selectedItem.summary || "No summary available."}</p>
      </div>

      <div className="grid gap-2 text-sm text-muted">
        <div>Timestamp: <span className="text-ink">{itemTimestamp(selectedItem, effectiveTimezone)}</span></div>
        <div>Risk: <span className="text-ink">{selectedItem.risk_score || 0}</span></div>
        <div>Artifact: <span className="text-ink break-words">{artifactLabel(selectedItem.artifact_type)}</span></div>
        <div>Type: <span className="text-ink break-words">{humanizeToken(selectedItem.event_type)}</span></div>
        <div>Host: <span className="text-ink break-words">{compact(selectedItem.host)}</span></div>
        {selectedObservedHost && selectedObservedHost !== selectedItem.host ? <div>Observed as: <span className="text-ink break-words">{selectedObservedHost}</span></div> : null}
        <div>User: <span className="text-ink break-words">{compact(selectedItem.user)}</span></div>
        <div>Entity: <span className="text-ink break-all">{compact(selectedItem.key_entity)}</span></div>
      </div>

      <div className="flex flex-wrap gap-2">
        {selectedItem.kind === "event" || selectedItem.kind === "bookmark" ? (
          <button
            type="button"
            onClick={() => setBookmarkDraft({ open: true, item: selectedItem, note: selectedItem.bookmark?.note || "", category: selectedItem.bookmark?.category || "other", importance: selectedItem.bookmark?.importance || "medium" })}
            className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
          >
            <Bookmark className="mr-2 inline h-3.5 w-3.5" />
            Mark key
          </button>
        ) : null}
        {selectedItem.id && (selectedItem.kind === "event" || selectedItem.kind === "bookmark") ? (
          <button type="button" onClick={() => openAroundEvent(selectedItem)} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
            <Clock3 className="mr-2 inline h-3.5 w-3.5" />
            Show ±30 min
          </button>
        ) : null}
        {selectedItem.related_finding_ids?.[0] ? (
          <button type="button" onClick={() => openAroundFinding(selectedItem.related_finding_ids![0]!)} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
            <ShieldAlert className="mr-2 inline h-3.5 w-3.5" />
            Open finding in timeline
          </button>
        ) : null}
        {selectedItem.key_entity ? (
          <button type="button" onClick={() => searchEntity("file_path", selectedItem.key_entity)} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
            <FileSearch className="mr-2 inline h-3.5 w-3.5" />
            Search this entity
          </button>
        ) : null}
        {selectedItem.raw?.process && selectedItem.related_process_node_ids?.length ? (() => {
          const params = new URLSearchParams({ mode: selectedItem.related_finding_ids?.[0] ? "finding_focus" : "process_focus" });
          for (const nodeId of selectedItem.related_process_node_ids ?? []) {
            if (nodeId) params.append("node_id", nodeId);
          }
          if (selectedItem.evidence_id) params.set("evidence_id", selectedItem.evidence_id);
          if (selectedItem.related_finding_ids?.[0]) params.set("finding_id", selectedItem.related_finding_ids[0]!);
          return (
            <Link to={`/cases/${caseId}/process-graph?${params.toString()}`} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
              <ExternalLink className="mr-2 inline h-3.5 w-3.5" />
              Open in Process Graph
            </Link>
          );
        })() : null}
      </div>

      <details className="rounded-2xl border border-line bg-abyss/60 p-3">
        <summary className="cursor-pointer font-mono text-xs uppercase tracking-[0.16em] text-muted">Raw JSON</summary>
        <pre className="mt-3 max-h-[22rem] overflow-auto whitespace-pre-wrap break-all text-xs text-muted">
          {JSON.stringify(selectedItem.raw ?? {}, null, 2)}
        </pre>
      </details>

      <div className="rounded-2xl border border-line bg-abyss/60 p-3">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected timeline</p>
        <div className="mt-3 space-y-2">
          {(keyEventsQuery.data ?? []).slice(0, 8).map((bookmark) => (
            <div key={bookmark.id} className="rounded-2xl border border-line/70 bg-panel/40 p-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="break-words text-ink">{bookmark.title}</p>
                  <p className="break-words text-xs text-muted">{bookmark.note || bookmark.summary || "No note"}</p>
                </div>
                <span className={`rounded-full border px-2 py-0.5 text-xs ${riskTone(bookmark.importance === "critical" ? 95 : bookmark.importance === "high" ? 75 : bookmark.importance === "medium" ? 45 : 10)}`}>
                  {bookmark.importance}
                </span>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex gap-2">
          <button type="button" onClick={() => api.exportTimelineKeyEventsMarkdown(caseId, { host: selectedHost || undefined, evidence_id: selectedEvidenceId || undefined }).then((content) => navigator.clipboard.writeText(content))} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
            <UploadCloud className="mr-2 inline h-3.5 w-3.5" />
            Copy Markdown export
          </button>
        </div>
      </div>
    </div>
  ) : (
    <div className="flex h-full min-h-[22rem] items-center justify-center rounded-[24px] border border-dashed border-line bg-abyss/40 p-6 text-center text-sm text-muted">
      Select a timeline item to inspect details, pivot to Search, open a related finding or mark it as a key event.
    </div>
  );
  const sortedTimelineItems = useMemo(() => {
    const items = timelineQuery.data?.items ?? [];
    return [...items].sort((left, right) => compareValues(timelineSortValue(left, tableSortKey), timelineSortValue(right, tableSortKey), tableSortDirection));
  }, [tableSortDirection, tableSortKey, timelineQuery.data?.items]);

  function handleTableSort(key: string) {
    setTableSortDirection((current) => nextSortDirection(tableSortKey, current, key));
    setTableSortKey(key);
  }

  const aroundEventId = searchParams.get("around_event") ?? "";
  const focusedFindingId = searchParams.get("finding_id") ?? "";
  const timelineFocusChips = useMemo(() => {
    const chips: string[] = [];
    chips.push(mode === "full" ? "Full timeline" : "Investigation timeline");
    if (aroundEventId) chips.push("Around event");
    if (focusedFindingId) chips.push("Around finding");
    if (selectedHost) chips.push(`Host: ${selectedHost}`);
    if (resolvedEvidenceId) chips.push(`Evidence: ${resolvedEvidenceId}`);
    return chips;
  }, [aroundEventId, focusedFindingId, mode, selectedEvidenceId, selectedHost]);

  useEffect(() => {
    const params = new URLSearchParams(searchParams);
    if (query) params.set("q", query); else params.delete("q");
    params.set("mode", mode);
    params.set("sort", sort);
    if (timeFrom) params.set("time_from", timeFrom); else params.delete("time_from");
    if (timeTo) params.set("time_to", timeTo); else params.delete("time_to");
    if (riskMin) params.set("risk_min", riskMin); else params.delete("risk_min");
    if (groupBy) params.set("group_by", groupBy); else params.delete("group_by");
    if (selectedId) params.set("selected", selectedId); else params.delete("selected");
    setSearchParams(params, { replace: true });
  }, [groupBy, mode, query, riskMin, searchParams, selectedId, setSearchParams, sort, timeFrom, timeTo]);

  useEffect(() => {
    if (selectedId && !(timelineQuery.data?.items ?? []).some((item) => item.id === selectedId)) {
      setSelectedId(null);
    }
  }, [selectedId, timelineQuery.data?.items]);

  useEffect(() => {
    if (!caseId) return;
    const focusKey = aroundEventId ? `event:${aroundEventId}` : focusedFindingId ? `finding:${focusedFindingId}` : "";
    if (!focusKey || focusedContextRef.current === focusKey) return;
    focusedContextRef.current = focusKey;

    if (aroundEventId) {
      void api.getTimelineAroundEvent(caseId, aroundEventId, { window: "30m", page_size: 100 }).then((response) => {
        queryClient.setQueryData(["case-timeline-v2", caseId, timelineParams], response);
        setSelectedId(aroundEventId);
      });
      return;
    }

    if (focusedFindingId) {
      void api.getTimelineAroundFinding(caseId, focusedFindingId, { window: "30m", page_size: 100 }).then((response) => {
        queryClient.setQueryData(["case-timeline-v2", caseId, timelineParams], response);
        setSelectedId(focusedFindingId);
      });
    }
  }, [aroundEventId, caseId, focusedFindingId, queryClient, timelineParams]);

  const createBookmark = useMutation({
    mutationFn: (payload: { event_id: string; note?: string; category?: TimelineBookmark["category"]; importance?: TimelineBookmark["importance"] }) =>
      api.createTimelineKeyEvent(caseId!, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case-timeline-v2", caseId] });
      queryClient.invalidateQueries({ queryKey: ["timeline-key-events", caseId] });
      setBookmarkDraft({ open: false, item: null, note: "", category: "other", importance: "medium" });
    },
  });

  if (!caseId) {
    return (
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case Timeline</p>
        <h2 className="mt-2 text-2xl font-semibold">No active case selected</h2>
        <p className="mt-2 text-sm text-muted">Select a case first to reconstruct the investigation timeline.</p>
      </section>
    );
  }

  const applyQuickFilter = (filter: SearchQuickFilter) => {
    const params = new URLSearchParams(searchParams);
    const risk = filter.params.risk_min;
    const findingId = filter.params.finding_id;
    const setArrayParam = (key: string, value: unknown) => {
      params.delete(key);
      if (!Array.isArray(value)) return;
      for (const item of value) {
        if (item !== undefined && item !== null && String(item).trim()) {
          params.append(key, String(item));
        }
      }
    };

    params.delete("artifact_type");
    params.delete("event_type");
    params.delete("event_category");
    params.delete("kind");
    params.delete("include_findings");
    params.delete("include_bookmarks");
    params.delete("key_events_only");
    if (risk !== undefined) {
      params.set("risk_min", String(risk));
      setRiskMin(String(risk));
    } else {
      params.delete("risk_min");
      if (filter.id !== "key_events") setRiskMin("");
    }
    if (findingId) {
      params.set("finding_id", String(findingId));
    } else {
      params.delete("finding_id");
    }
    setArrayParam("artifact_type", filter.params.artifact_type);
    setArrayParam("event_type", filter.params.event_type);
    setArrayParam("event_category", filter.params.event_category);
    if (String(filter.params.kind || "") === "finding" || filter.id === "findings_only") {
      params.set("kind", "finding");
      params.set("include_findings", "true");
      params.set("include_bookmarks", "false");
    } else if (filter.id === "key_events") {
      params.set("key_events_only", "true");
      params.set("include_findings", "false");
      params.set("include_bookmarks", "true");
    } else {
      params.delete("key_events_only");
      params.set("kind", "event");
      params.set("include_findings", "false");
      params.set("include_bookmarks", "false");
    }
    setCursorStack([]);
    setSearchParams(params);
  };

  const openAroundEvent = (item: TimelineItem) => {
    if (!item.id) return;
    const params = new URLSearchParams(searchParams);
    params.delete("finding_id");
    params.set("around_event", item.id);
    params.set("selected", item.id);
    setSearchParams(params);
    api.getTimelineAroundEvent(caseId, item.id, { window: "30m", page_size: 100 }).then((response) => {
      queryClient.setQueryData(["case-timeline-v2", caseId, timelineParams], response);
    });
  };

  const openAroundFinding = (findingId: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("finding_id", findingId);
    params.set("mode", "investigation");
    params.delete("around_event");
    setCursorStack([]);
    setSearchParams(params);
    api.getTimelineAroundFinding(caseId, findingId, { window: "30m", page_size: 100 }).then((response) => {
      queryClient.setQueryData(["case-timeline-v2", caseId, timelineParams], response);
    });
  };

  const searchEntity = (type: "file_path" | "process_name" | "domain", value: string | null | undefined) => {
    if (!value) return;
    const params = new URLSearchParams();
    params.set("q", value);
    if (type === "file_path") params.set("file_path", value);
    if (type === "process_name") params.set("process_name", value);
    if (type === "domain") params.set("domain", value);
    navigate(`/cases/${caseId}/search?${params.toString()}`);
  };

  return (
    <div className="space-y-5">
      <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case Timeline</p>
            <h2 className="mt-2 text-2xl font-semibold">Reconstruct the story of the case.</h2>
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedHost ? `Host: ${selectedHost}` : "Host: all hosts"}</span>
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{resolvedEvidenceId ? `Evidence: ${resolvedEvidenceId.slice(0, 8)}` : "Evidence: all evidence"}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => setModeInUrl("full", searchParams, setSearchParams, setCursorStack)} className={`rounded-full px-4 py-2 text-sm ${mode === "full" ? "bg-accent text-abyss" : "border border-line bg-abyss/70 text-muted"}`}>Full Timeline</button>
            <button type="button" onClick={() => setModeInUrl("investigation", searchParams, setSearchParams, setCursorStack)} className={`rounded-full px-4 py-2 text-sm ${mode === "investigation" ? "bg-accent text-abyss" : "border border-line bg-abyss/70 text-muted"}`}>Investigation Timeline</button>
          </div>
        </div>

        <div className="mt-5 grid gap-3 xl:grid-cols-[minmax(0,1fr)_auto_auto_auto]">
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search</span>
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-muted" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="payload.exe, powershell.exe, duckdns.org..." className="w-full bg-transparent outline-none" />
            </div>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Time from</span>
            <input type="datetime-local" step="1" value={timeFrom} onChange={(event) => setTimeFrom(event.target.value)} className="w-full bg-transparent outline-none" />
          </label>
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Time to</span>
            <input type="datetime-local" step="1" value={timeTo} onChange={(event) => setTimeTo(event.target.value)} className="w-full bg-transparent outline-none" />
          </label>
          <div className="flex flex-wrap gap-2">
            <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Risk min</span>
              <input value={riskMin} onChange={(event) => setRiskMin(event.target.value)} className="w-20 bg-transparent outline-none" />
            </label>
            <button type="button" onClick={() => setShowAdvanced((current) => !current)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
              <Filter className="mr-2 inline h-4 w-4" />
              Advanced
            </button>
            <button type="button" onClick={() => timelineQuery.refetch()} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
              <RefreshCw className="mr-2 inline h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>

        {showAdvanced ? (
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Sort</span>
              <select value={sort} onChange={(event) => setSort(event.target.value)} className="w-full bg-transparent outline-none">
                <option value="timestamp_desc">Newest first</option>
                <option value="timestamp_asc">Oldest first</option>
                <option value="risk_desc">Risk descending</option>
                <option value="risk_asc">Risk ascending</option>
              </select>
            </label>
            <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Group by</span>
              <select value={groupBy} onChange={(event) => setGroupBy(event.target.value)} className="w-full bg-transparent outline-none">
                <option value="hour">Hour</option>
                <option value="day">Day</option>
                <option value="none">None</option>
              </select>
            </label>
          </div>
        ) : null}

        <div className="mt-4 flex flex-wrap gap-2">
          <div data-testid="timeline-focus-chips" className="contents">
            {timelineFocusChips.map((chip) => (
              <span key={chip} className="rounded-full border border-accent/30 bg-accent/8 px-3 py-1.5 text-xs text-slate-100">
                {chip}
              </span>
            ))}
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {(quickFiltersQuery.data?.items ?? []).map((item) => (
            <button key={item.id} type="button" onClick={() => applyQuickFilter(item)} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted hover:border-accent/40 hover:text-ink">
              {item.label}
            </button>
          ))}
        </div>
      </section>

      {timelineQuery.data?.warnings?.length ? (
        <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          {timelineQuery.data.warnings.join(" · ")}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-5">
        <section className="min-w-0 space-y-3 rounded-[28px] border border-line bg-panel/70 p-4 shadow-panel">
          <div className="flex flex-wrap gap-3 text-xs text-muted">
            {timelineQuery.data?.groups?.map((group) => (
              <span key={group.key} className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">
                {group.label} · {group.count} items · {group.high_risk_count} high
              </span>
            ))}
          </div>

          <div className="overflow-hidden rounded-[24px] border border-line">
            <div className="grid grid-cols-[170px_70px_90px_110px_120px_110px_minmax(160px,1fr)_72px] gap-3 border-b border-line bg-abyss/70 px-4 py-3 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
              <button type="button" onClick={() => handleTableSort("timestamp")} className="text-left">Timestamp {tableSortKey === "timestamp" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("risk")} className="text-left">Risk {tableSortKey === "risk" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("kind")} className="text-left">Kind {tableSortKey === "kind" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("artifact")} className="text-left">Artifact {tableSortKey === "artifact" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("type")} className="text-left">Type {tableSortKey === "type" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("host")} className="text-left">Host {tableSortKey === "host" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <button type="button" onClick={() => handleTableSort("summary")} className="text-left">Summary {tableSortKey === "summary" ? (tableSortDirection === "asc" ? "↑" : "↓") : ""}</button>
              <span>Action</span>
            </div>
            <div className="divide-y divide-line/60">
              {timelineQuery.isLoading ? (
                <div className="px-4 py-6 text-sm text-muted">Loading timeline…</div>
              ) : timelineQuery.isError ? (
                <div className="px-4 py-6 text-sm text-rose-200">{String((timelineQuery.error as Error)?.message || "Timeline failed")}</div>
              ) : sortedTimelineItems.length ? (
                sortedTimelineItems.map((item) => (
                  <div
                    key={`${item.kind}-${item.id}`}
                    className={`grid grid-cols-[170px_70px_90px_110px_120px_110px_minmax(160px,1fr)_72px] gap-3 px-4 py-3 text-sm ${selectedId === item.id ? "bg-accent/8" : "bg-transparent"} cursor-pointer hover:bg-white/5`}
                    onClick={() => setSelectedId(item.id)}
                  >
                    <span className="truncate text-muted">{itemTimestamp(item, effectiveTimezone)}</span>
                    <span className={`w-fit rounded-full border px-2 py-0.5 text-xs ${riskTone(Number(item.risk_score || 0))}`}>{item.risk_score || 0}</span>
                    <span className="truncate text-muted">{item.kind}</span>
                    <span className="truncate text-muted">{artifactLabel(item.artifact_type)}</span>
                    <span className="truncate text-muted">{compact(item.event_type)}</span>
                    <span className="truncate text-muted">{compact(item.host)}</span>
                    <span className="truncate text-ink" title={item.summary || item.title}>{item.summary || item.title}</span>
                    <button type="button" className="rounded-full border border-line bg-abyss/70 px-2 py-1 text-xs text-muted" onClick={(event) => { event.stopPropagation(); setSelectedId(item.id); }}>
                      Open
                    </button>
                  </div>
                ))
              ) : (
                <div className="px-4 py-6 text-sm text-muted">No timeline items match the current filters.</div>
              )}
            </div>
          </div>

          <PaginationControls
            page={cursorStack.length + 1}
            totalPages={timelineQuery.data?.next_cursor ? cursorStack.length + 2 : cursorStack.length + 1}
            total={timelineQuery.data?.total ?? 0}
            totalRelation="eq"
            pageSize={timelineQuery.data?.page_size ?? 100}
            onPageChange={(nextPage) => {
              if (nextPage <= 1) {
                setCursorStack([]);
                return;
              }
              if (nextPage === cursorStack.length + 2 && timelineQuery.data?.next_cursor) {
                setCursorStack((current) => [...current, timelineQuery.data?.next_cursor || ""]);
                return;
              }
              setCursorStack((current) => current.slice(0, Math.max(0, nextPage - 1)));
            }}
            onPageSizeChange={() => undefined}
          />
        </section>
      </div>

      {selectedItem ? (
        <ResponsiveDetailPanel open mode="drawer" widthClass="h-full w-full sm:w-[88vw] xl:w-[82vw] 2xl:w-[78vw]" heading="Timeline detail" subheading="Wide investigation detail aligned with Search, Findings and Detections." onClose={() => setSelectedId(null)}>
          {selectedTimelineDetail}
        </ResponsiveDetailPanel>
      ) : null}

      {bookmarkDraft.open && bookmarkDraft.item ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-abyss/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-[28px] border border-line bg-panel p-5 shadow-panel">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">Key event</p>
                <h3 className="mt-2 text-lg font-semibold">{bookmarkDraft.item.title}</h3>
              </div>
              <button type="button" onClick={() => setBookmarkDraft({ open: false, item: null, note: "", category: "other", importance: "medium" })} className="rounded-full border border-line bg-abyss/70 p-2 text-muted">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Category</span>
                <select value={bookmarkDraft.category} onChange={(event) => setBookmarkDraft((current) => ({ ...current, category: event.target.value as TimelineBookmark["category"] }))} className="w-full bg-transparent outline-none">
                  {["execution", "download", "detection", "persistence", "network", "cleanup", "other"].map((value) => (
                    <option key={value} value={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Importance</span>
                <select value={bookmarkDraft.importance} onChange={(event) => setBookmarkDraft((current) => ({ ...current, importance: event.target.value as TimelineBookmark["importance"] }))} className="w-full bg-transparent outline-none">
                  {["low", "medium", "high", "critical"].map((value) => (
                    <option key={value} value={value}>{value}</option>
                  ))}
                </select>
              </label>
            </div>
            <label className="mt-3 block rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Note</span>
              <textarea value={bookmarkDraft.note} onChange={(event) => setBookmarkDraft((current) => ({ ...current, note: event.target.value }))} rows={4} className="w-full resize-none bg-transparent outline-none" />
            </label>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setBookmarkDraft({ open: false, item: null, note: "", category: "other", importance: "medium" })} className="rounded-full border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">Cancel</button>
              <button
                type="button"
                onClick={() => createBookmark.mutate({ event_id: bookmarkDraft.item!.kind === "bookmark" ? bookmarkDraft.item!.bookmark?.event_id || bookmarkDraft.item!.id : bookmarkDraft.item!.id, note: bookmarkDraft.note, category: bookmarkDraft.category, importance: bookmarkDraft.importance })}
                className="rounded-full bg-accent px-4 py-2 text-sm text-abyss"
              >
                Save key event
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function setModeInUrl(mode: TimelineMode, searchParams: URLSearchParams, setSearchParams: ReturnType<typeof useSearchParams>[1], setCursorStack: (updater: (current: string[]) => string[]) => void) {
  const params = new URLSearchParams(searchParams);
  params.set("mode", mode);
  params.delete("cursor");
  setCursorStack(() => []);
  setSearchParams(params);
}

export default TimelinePage;
