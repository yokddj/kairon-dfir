import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Navigate, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type DfirCase, type ResumableUploadSessionRead } from "../api/client";
import ArtifactBadge from "../components/ArtifactBadge";
import CreateFindingDialog from "../components/CreateFindingDialog";
import DebugExportDialog from "../components/DebugExportDialog";
import EvidenceIngestionWizard from "../components/EvidenceIngestionWizard";
import EventTable from "../components/EventTable";
import FindingsWorkspace from "../components/FindingsWorkspace";
import InvestigationContext from "../components/InvestigationContext";
import ProcessTreePanel from "../components/ProcessTreePanel";
import Timeline from "../components/Timeline";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useHostContext } from "../hooks/useHostContext";
import DeleteCaseDialog from "../components/DeleteCaseDialog";
import { memoryEvidenceRoute } from "../lib/canonicalRoutes";

const tabs = ["overview", "evidences", "processing", "artifacts", "artifact_explorer", "search", "process_tree", "investigation_timeline", "detections", "findings", "activity"] as const;
// This page's remaining, non-duplicated responsibility -- everything else in
// `tabs` above now has its own dedicated Investigation page (see
// redirectTargetForTab) and only stays in `tabs`/`tabLabels` so that legacy
// ?tab= links still resolve to a value before being redirected away.
const PRIMARY_TABS = ["evidences", "processing"] as const;
type ExpectedEvidenceKind = "disk_image" | "memory_dump" | "collection" | "archive" | "unknown";

// Most of this page's original tabs have since grown into dedicated
// Investigation pages (Overview, Search, Timeline, Detections, Findings,
// Artifact Views) -- redirecting here keeps old bookmarks/links working
// without this page rendering a second, stale copy of that UI.
function redirectTargetForTab(tab: string, caseId: string): string | null {
  switch (tab) {
    case "overview":
      return `/cases/${caseId}/overview`;
    case "artifacts":
    case "artifact_explorer":
      return `/cases/${caseId}/artifacts`;
    case "search":
      return `/cases/${caseId}/search`;
    case "process_tree":
      return `/cases/${caseId}/w/execution/stories`;
    case "investigation_timeline":
      return `/cases/${caseId}/incident-timeline`;
    case "detections":
      return `/cases/${caseId}/detections`;
    case "findings":
      return `/cases/${caseId}/findings`;
    case "activity":
      return "/activity";
    default:
      return null;
  }
}

function expectedEvidenceKind(value: string | null): ExpectedEvidenceKind | null {
  if (value === "disk_image" || value === "memory_dump" || value === "collection" || value === "archive" || value === "unknown") return value;
  return null;
}

const tabLabels: Record<(typeof tabs)[number], string> = {
  overview: "Overview",
  evidences: "Evidence & Ingest",
  processing: "Processing",
  artifacts: "Artifact Inventory",
  artifact_explorer: "Artifact Search",
  search: "Search",
  process_tree: "Process Graph",
  investigation_timeline: "Timeline",
  detections: "Detections",
  findings: "Findings",
  activity: "Jobs & Activity",
};

export default function CaseDetail() {
  const { caseId = "" } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { activeCaseId, setActiveCase, caseContext } = useActiveCase();
  const { activeHost, activeHostId, hasHostFilter, clearHostFilter } = useHostContext();
  const initialTab = searchParams.get("tab");
  const expectedKind = expectedEvidenceKind(searchParams.get("expected_kind"));
  // "evidences" (Evidence & Ingest) is this page's own remaining
  // responsibility and the correct default when no ?tab= is present --
  // "overview" duplicates the dedicated /overview page and only exists here
  // so an explicit ?tab=overview link still resolves to something before
  // redirectTargetForTab redirects it away.
  const [tab, setTab] = useState<(typeof tabs)[number]>(tabs.includes(initialTab as (typeof tabs)[number]) ? (initialTab as (typeof tabs)[number]) : "evidences");
  const [caseTimezone, setCaseTimezone] = useState("");
  const [query, setQuery] = useState(searchParams.get("query") ?? "");
  const [searchEventId, setSearchEventId] = useState(searchParams.get("event_id") ?? "");
  const [searchEvidenceId, setSearchEvidenceId] = useState(searchParams.get("evidence_id") ?? "");
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [selectedProcessingId, setSelectedProcessingId] = useState<string>("");
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const [metadataEditorOpen, setMetadataEditorOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [ingestionWizardOpen, setIngestionWizardOpen] = useState(false);
  const [resumeCandidate, setResumeCandidate] = useState<ResumableUploadSessionRead | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editPriority, setEditPriority] = useState("medium");
  const [editStatus, setEditStatus] = useState("active");
  const [editTags, setEditTags] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const caseQuery = useQuery({ queryKey: ["case", caseId], queryFn: () => api.getCase(caseId), enabled: Boolean(caseId), staleTime: 15_000, refetchOnWindowFocus: false });
  const evidencesQuery = useQuery({ queryKey: ["evidences", caseId, activeHostId, activeHost], queryFn: () => api.listEvidences(caseId, { host_id: activeHostId || undefined, host: activeHost || undefined }), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  // Surfaces interrupted/active uploads directly on the Evidence page, not
  // only inside the Wizard, so a session started here is still discoverable
  // after a browser close/reload without needing a resume_session URL param.
  const resumableUploadsQuery = useQuery({ queryKey: ["resumable-evidence-uploads", caseId], queryFn: () => api.listResumableEvidenceUploads(caseId), enabled: Boolean(caseId), staleTime: 5_000, refetchInterval: 20_000 });
  // A session that reached 100% is neither interrupted nor still
  // transferring -- it's done or finalizing, and listing it here just pushes
  // the Add Evidence card down for no reason (mirrors the same fix in
  // EvidenceIngestionWizard's own discovery panel).
  const resumableUploads = (resumableUploadsQuery.data?.sessions ?? []).filter((candidate) => candidate.progress_percent === null || candidate.progress_percent < 100);
  const artifactsQuery = useQuery({ queryKey: ["artifacts", caseId], queryFn: () => api.listArtifacts(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const findingsQuery = useQuery({ queryKey: ["findings", caseId], queryFn: () => api.listFindings(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const detectionsQuery = useQuery({ queryKey: ["detections", caseId], queryFn: () => api.listDetections(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const summaryQuery = useQuery({ queryKey: ["investigation-summary", caseId], queryFn: () => api.getInvestigationSummary(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const activityQuery = useQuery({ queryKey: ["case-activity", caseId], queryFn: () => api.listCaseActivity(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const processingQuery = useQuery({ queryKey: ["case-processing", caseId, activeHostId, activeHost], queryFn: () => api.getCaseProcessing(caseId, { host_id: activeHostId || undefined, host: activeHost || undefined }), enabled: Boolean(caseId), staleTime: 5_000, refetchInterval: tab === "processing" ? 5000 : false, refetchOnWindowFocus: false });
  const hostNameById = useMemo(() => new Map((caseContext?.hosts ?? []).map((host) => [host.id, host.display_name || host.canonical_name])), [caseContext?.hosts]);
  const siemLinksQuery = useQuery({ queryKey: ["siem-external-links", "case", caseId], queryFn: () => api.siemExternalLinks({ case_id: caseId }), enabled: Boolean(caseId), staleTime: 30_000, refetchOnWindowFocus: false });
  const searchQuery = useQuery({
    queryKey: ["case-search", caseId, query, searchEventId, searchEvidenceId, activeHostId, activeHost],
    queryFn: () =>
      api.search({
        case_id: caseId,
        query: query || "*",
        filters: {
          event_id: searchEventId ? [searchEventId] : [],
          evidence_id: searchEvidenceId ? [searchEvidenceId] : [],
          host: activeHost ? [activeHost] : [],
          host_id: activeHostId ? [activeHostId] : [],
        },
        page: 1,
        page_size: 50,
      }),
    enabled: Boolean(caseId) && tab === "search",
    refetchOnWindowFocus: false,
  });
  const timelineQuery = useQuery({
    queryKey: ["case-timeline", caseId],
    queryFn: () => api.timeline({ case_id: caseId, query: "*", filters: {}, page: 1, page_size: 100 }),
    enabled: Boolean(caseId) && tab === "investigation_timeline",
    refetchOnWindowFocus: false,
  });
  const updateCaseMutation = useMutation({
    mutationFn: (timezone: string) => api.updateCase(caseId, { timezone: timezone || null }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  const updateCaseMetadataMutation = useMutation({
    mutationFn: () => api.updateCase(caseId, { name: editName, description: editDescription, priority: editPriority as DfirCase["priority"], status: editStatus as DfirCase["status"], tags: editTags.split(",").map((tag) => tag.trim()).filter(Boolean), case_notes: editNotes }),
    onSuccess: (updated) => {
      setMetadataEditorOpen(false);
      setActiveCase(updated);
      void queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  const caseStatusMutation = useMutation({
    mutationFn: (action: "archive" | "unarchive" | "close" | "reopen") => {
      if (action === "archive") return api.archiveCase(caseId);
      if (action === "unarchive") return api.unarchiveCase(caseId);
      if (action === "close") return api.closeCase(caseId);
      return api.reopenCase(caseId);
    },
    onSuccess: (updated) => {
      setActiveCase(updated);
      void queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  useEffect(() => {
    if (caseQuery.data && caseQuery.data.id !== activeCaseId) {
      setActiveCase(caseQuery.data);
    }
  }, [activeCaseId, caseQuery.data, setActiveCase]);

  useEffect(() => {
    if (!caseQuery.data || !metadataEditorOpen) return;
    setEditName(caseQuery.data.name || "");
    setEditDescription(caseQuery.data.description || "");
    setEditPriority(caseQuery.data.priority || "medium");
    setEditStatus(caseQuery.data.status === "open" ? "active" : caseQuery.data.status || "active");
    setEditTags((caseQuery.data.tags || []).join(", "));
    setEditNotes(caseQuery.data.case_notes || "");
  }, [caseQuery.data, metadataEditorOpen]);

  useEffect(() => {
    const requestedTab = searchParams.get("tab");
    if (requestedTab && tabs.includes(requestedTab as (typeof tabs)[number]) && requestedTab !== tab) {
      setTab(requestedTab as (typeof tabs)[number]);
    }
  }, [searchParams, tab]);

  useEffect(() => {
    if (searchParams.get("resume_session") || searchParams.get("add_evidence")) {
      setIngestionWizardOpen(true);
      setTab("evidences");
    }
  }, [searchParams]);

  useEffect(() => {
    const requestedQuery = searchParams.get("query") ?? "";
    if (requestedQuery !== query) {
      setQuery(requestedQuery);
    }
  }, [query, searchParams]);

  useEffect(() => {
    const requestedEvidenceId = searchParams.get("evidence_id") ?? "";
    if (tab === "processing" && requestedEvidenceId && requestedEvidenceId !== selectedProcessingId) {
      setSelectedProcessingId(requestedEvidenceId);
    }
  }, [selectedProcessingId, searchParams, tab]);

  useEffect(() => {
    const requestedEventId = searchParams.get("event_id") ?? "";
    const requestedEvidenceId = searchParams.get("evidence_id") ?? "";
    if (requestedEventId !== searchEventId) {
      setSearchEventId(requestedEventId);
    }
    if (requestedEvidenceId !== searchEvidenceId) {
      setSearchEvidenceId(requestedEvidenceId);
    }
  }, [searchEvidenceId, searchEventId, searchParams]);

  const overviewStats = useMemo(
    () => [
      ["Evidences", evidencesQuery.data?.length ?? 0],
      ["Hosts", caseQuery.data?.host_count ?? caseContext?.hosts?.length ?? 0],
      ["Artifact Inventory", artifactsQuery.data?.length ?? 0],
      ["Detections", summaryQuery.data?.counts.detections ?? caseQuery.data?.detections_count ?? 0],
      ["Findings", summaryQuery.data?.counts.findings ?? caseQuery.data?.findings_count ?? 0],
      ["Status", caseQuery.data?.status === "open" ? "active" : caseQuery.data?.status ?? "-"],
      ["Priority", caseQuery.data?.priority ?? "medium"],
      ["Evidence processing", processingSummaryLabel(processingQuery.data?.summary)],
    ],
    [artifactsQuery.data?.length, caseContext?.hosts?.length, caseQuery.data?.detections_count, caseQuery.data?.findings_count, caseQuery.data?.host_count, caseQuery.data?.priority, caseQuery.data?.status, evidencesQuery.data?.length, processingQuery.data?.summary, summaryQuery.data?.counts.detections, summaryQuery.data?.counts.findings],
  );
  const selectedProcessing = processingQuery.data?.items.find((item) => item.evidence_id === selectedProcessingId) ?? processingQuery.data?.items[0] ?? null;
  const normalizedCaseStatus = caseQuery.data?.status === "open" ? "active" : caseQuery.data?.status;
  const renderGuidedIngestionPanel = () => (
    <div className="space-y-4">
      {resumableUploads.length ? (
        <div className="rounded-3xl border border-amber-400/30 bg-amber-400/5 p-5 shadow-panel" data-testid="case-resumable-uploads-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber-300">Interrupted or active uploads</p>
          <div className="mt-3 space-y-2">
            {resumableUploads.map((candidate) => (
              <div key={candidate.id} className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-abyss/60 p-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-ink">{candidate.original_filename}</p>
                  <p className="mt-0.5 text-xs text-muted">
                    {candidate.category ?? "evidence"} &middot; {candidate.status}
                    {candidate.progress_percent !== null ? ` · ${candidate.progress_percent.toFixed(0)}%` : ""}
                  </p>
                </div>
                {candidate.status === "promoted" && candidate.promoted_evidence_id ? (
                  <Link to={candidate.category === "memory_dump" ? memoryEvidenceRoute(caseId, candidate.promoted_evidence_id) : `/evidences/${candidate.promoted_evidence_id}`} className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss">
                    Open evidence
                  </Link>
                ) : candidate.resumable || candidate.status === "staged" ? (
                  <button
                    type="button"
                    onClick={() => { setResumeCandidate(candidate); setIngestionWizardOpen(true); }}
                    className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss"
                  >
                    Resume
                  </button>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}
      <div className="rounded-3xl border border-accent/30 bg-accent/5 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Add evidence</p>
        <p className="mt-2 text-sm text-muted">A guided wizard classifies your evidence and previews exactly what Kairon is about to do before anything is processed.</p>
        <button type="button" onClick={() => { setResumeCandidate(null); setIngestionWizardOpen(true); }} className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
          Add Evidence
        </button>
      </div>
      <div className="rounded-3xl border border-line bg-panel/50 p-4 text-sm text-muted">
        Specialized disk, memory, archive, collection, EVTX, folder, and server-path intake now starts from the same Add Evidence wizard. Select the evidence first; Kairon detects the route before asking for confirmation.
      </div>
    </div>
  );

  const redirectTarget = redirectTargetForTab(initialTab || "", caseId);
  if (redirectTarget) {
    const preservedParams = new URLSearchParams(searchParams);
    preservedParams.delete("tab");
    const query = preservedParams.toString();
    return <Navigate to={query ? `${redirectTarget}?${query}` : redirectTarget} replace />;
  }

  return (
    <div className="space-y-8">
      {caseQuery.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{caseQuery.error.message}</div> : null}
      <InvestigationContext
        caseId={caseId}
        caseName={caseQuery.data?.name}
        hostId={activeHostId}
        host={activeHost}
        current={tabLabels[tab]}
        breadcrumbs={[{ label: "Cases", to: "/cases" }, { label: caseQuery.data?.name || "Case", to: `/cases/${caseId}` }, { label: tabLabels[tab] }]}
      />
      {normalizedCaseStatus === "archived" ? (
        <div className="rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">This case is archived. It is hidden from the default case list but evidence is preserved.</div>
      ) : null}
      {normalizedCaseStatus === "closed" ? (
        <div className="rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted">This case is closed. Reopen it to continue active investigation.</div>
      ) : null}
      <section className="rounded-[28px] border border-line bg-panel/60 p-6 shadow-panel">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case</p>
            <h2 className="mt-2 text-3xl font-semibold">{caseQuery.data?.name}</h2>
            <p className="mt-3 max-w-3xl text-sm text-muted">{caseQuery.data?.description}</p>
          </div>
          <div className="grid gap-3 md:grid-cols-6">
            {overviewStats.map(([label, value]) => (
              <div key={String(label)} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
                <p className="mt-2 text-lg font-semibold">{value}</p>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-6 grid gap-3 rounded-3xl border border-line bg-abyss/60 p-4 md:grid-cols-4" data-testid="case-management-metadata">
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Status</p><p className="mt-1 text-sm font-semibold text-ink">{normalizedCaseStatus || "active"}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Priority</p><p className="mt-1 text-sm font-semibold text-ink">{caseQuery.data?.priority || "medium"}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Tags</p><p className="mt-1 text-sm font-semibold text-ink">{(caseQuery.data?.tags || []).length ? caseQuery.data?.tags.join(", ") : "No tags"}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Updated</p><p className="mt-1 text-sm font-semibold text-ink">{caseQuery.data?.updated_at ? new Date(caseQuery.data.updated_at).toLocaleString() : "-"}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Created</p><p className="mt-1 text-sm font-semibold text-ink">{caseQuery.data?.created_at ? new Date(caseQuery.data.created_at).toLocaleString() : "-"}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence count</p><p className="mt-1 text-sm font-semibold text-ink">{caseQuery.data?.evidence_count ?? evidencesQuery.data?.length ?? 0}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host count</p><p className="mt-1 text-sm font-semibold text-ink">{caseQuery.data?.host_count ?? caseContext?.hosts?.length ?? 0}</p></div>
          <div><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Processing summary</p><p className="mt-1 text-sm font-semibold text-ink">{processingSummaryLabel(processingQuery.data?.summary)}</p></div>
          <div className="md:col-span-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Notes</p><p className="mt-1 whitespace-pre-wrap text-sm text-muted">{caseQuery.data?.case_notes || "No case notes yet."}</p></div>
        </div>
        <div className="mt-6 flex flex-wrap gap-2">
          {PRIMARY_TABS.map((item) => (
            <button
              key={item}
              onClick={() => {
                setTab(item);
                const next = new URLSearchParams(searchParams);
                next.set("tab", item);
                setSearchParams(next, { replace: true });
              }}
              className={`rounded-full px-4 py-2 text-sm ${tab === item ? "bg-accent text-abyss" : "border border-line bg-white/5 text-muted"}`}
            >
              {tabLabels[item]}
            </button>
          ))}
          <button onClick={() => setMetadataEditorOpen(true)} className="rounded-full border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent">Edit case</button>
          {normalizedCaseStatus === "archived" ? <button onClick={() => caseStatusMutation.mutate("unarchive")} className="rounded-full border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent">Unarchive case</button> : <button onClick={() => window.confirm("Archive this case? Evidence and indexes are preserved.") && caseStatusMutation.mutate("archive")} className="rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted">Archive case</button>}
          {normalizedCaseStatus === "closed" ? <button onClick={() => caseStatusMutation.mutate("reopen")} className="rounded-full border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent">Reopen case</button> : <button onClick={() => window.confirm("Close this case? You can reopen it later.") && caseStatusMutation.mutate("close")} className="rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted">Close case</button>}
          <button onClick={() => setDebugExportOpen(true)} className="rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted">
            Export full case validation pack
          </button>
          <button onClick={() => setDeleteDialogOpen(true)} className="rounded-full border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">
            Delete case
          </button>
        </div>
        {caseStatusMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{caseStatusMutation.error.message}</p> : null}
        {updateCaseMetadataMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{updateCaseMetadataMutation.error.message}</p> : null}
      </section>

      {tab === "overview" ? (
        <section className="grid gap-6 lg:grid-cols-[1.1fr_1.9fr]">
          {renderGuidedIngestionPanel()}
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">What happened?</p>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Successful logons: {summaryQuery.data?.successful_logons ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Failed logons: {summaryQuery.data?.failed_logons ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Persistence events: {summaryQuery.data?.scheduled_task_events ?? 0} tasks, {summaryQuery.data?.service_install_events ?? 0} services</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Deleted files: {summaryQuery.data?.deleted_files ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Detections: {summaryQuery.data?.counts.detections ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Findings: {summaryQuery.data?.counts.findings ?? 0}</div>
            </div>
            <div className="mt-5 flex flex-wrap gap-2">
              <Link to={`/cases/${caseId}/search`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Search</Link>
              <Link to={`/cases/${caseId}/timeline`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Timeline</Link>
              <Link to={`/cases/${caseId}/artifacts`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Artifact Search</Link>
              <Link to={`/cases/${caseId}/findings`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Run correlation in Findings</Link>
              <Link to={`/cases/${caseId}/debug-export`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Debug Export</Link>
              {siemLinksQuery.data?.discover_url ? (
                <a href={siemLinksQuery.data.discover_url} target="_blank" rel="noreferrer" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                  Open in OpenSearch
                </a>
              ) : null}
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3 rounded-2xl border border-line bg-abyss/70 p-4">
              <input
                value={caseTimezone || caseQuery.data?.timezone || ""}
                onChange={(event) => setCaseTimezone(event.target.value)}
                placeholder="Case timezone, e.g. Europe/Madrid"
                className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm"
              />
              <button onClick={() => updateCaseMutation.mutate(caseTimezone || caseQuery.data?.timezone || "")} className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted">
                Save case timezone
              </button>
              <span className="text-xs text-muted">Current case timezone: {caseQuery.data?.timezone || "not set"}</span>
            </div>
            <div className="mt-6 grid gap-4 xl:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/70 p-4">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Top hosts and users</p>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="text-xs uppercase tracking-[0.14em] text-muted">Hosts</p>
                    <ul className="mt-2 space-y-2 text-sm text-muted">
                      {(summaryQuery.data?.top_hosts ?? []).slice(0, 5).map((item) => (
                        <li key={`host-${item.key}`} className="flex justify-between gap-3">
                          <span className="truncate">{item.key}</span>
                          <span>{item.count}</span>
                        </li>
                      ))}
                      {!summaryQuery.data?.top_hosts?.length ? <li>No host pivots yet.</li> : null}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.14em] text-muted">Users</p>
                    <ul className="mt-2 space-y-2 text-sm text-muted">
                      {(summaryQuery.data?.top_users ?? []).slice(0, 5).map((item) => (
                        <li key={`user-${item.key}`} className="flex justify-between gap-3">
                          <span className="truncate">{item.key}</span>
                          <span>{item.count}</span>
                        </li>
                      ))}
                      {!summaryQuery.data?.top_users?.length ? <li>No user pivots yet.</li> : null}
                    </ul>
                  </div>
                </div>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Execution and network leads</p>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="text-xs uppercase tracking-[0.14em] text-muted">Processes</p>
                    <ul className="mt-2 space-y-2 text-sm text-muted">
                      {(summaryQuery.data?.top_processes ?? []).slice(0, 5).map((item) => (
                        <li key={`process-${item.key}`} className="flex justify-between gap-3">
                          <span className="truncate">{item.key}</span>
                          <span>{item.count}</span>
                        </li>
                      ))}
                      {!summaryQuery.data?.top_processes?.length ? <li>No process pivots yet.</li> : null}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.14em] text-muted">Domains</p>
                    <ul className="mt-2 space-y-2 text-sm text-muted">
                      {(summaryQuery.data?.top_domains ?? []).slice(0, 5).map((item) => (
                        <li key={`domain-${item.key}`} className="flex justify-between gap-3">
                          <span className="truncate">{item.key}</span>
                          <span>{item.count}</span>
                        </li>
                      ))}
                      {!summaryQuery.data?.top_domains?.length ? <li>No domain pivots yet.</li> : null}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Suspicious recent events</p>
              <div className="mt-3 space-y-3">
                {(summaryQuery.data?.recent_high_severity_events ?? []).slice(0, 4).map((item, index) => {
                  const eventMeta = (item.event as Record<string, unknown>) ?? {};
                  const host = (item.host as Record<string, unknown>) ?? {};
                  return (
                    <div key={`recent-${index}`} className="rounded-2xl border border-line bg-panel/40 px-4 py-3">
                      <p className="text-sm">{String(eventMeta.message ?? "High-severity event")}</p>
                      <p className="mt-1 text-xs text-muted">
                        {String(item["@timestamp"] ?? "No timestamp")} · {String(host.name ?? "-")} · {String(eventMeta.type ?? "-")}
                      </p>
                    </div>
                  );
                })}
                {!summaryQuery.data?.recent_high_severity_events?.length ? <p className="text-sm text-muted">No recent high-severity events surfaced yet.</p> : null}
              </div>
            </div>
            <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Findings overview</p>
                  <p className="mt-2 text-sm text-muted">Resumen rápido de hallazgos correlados para priorizar el triage.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const next = new URLSearchParams(searchParams);
                      next.set("tab", "findings");
                      setSearchParams(next, { replace: false });
                      setTab("findings");
                    }}
                    className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted"
                  >
                    View findings
                  </button>
                </div>
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-4">
                <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">Total: {findingsQuery.data?.length ?? 0}</div>
                <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">Critical/High: {(findingsQuery.data ?? []).filter((finding) => finding.severity === "critical" || finding.severity === "high").length}</div>
                <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">New: {(findingsQuery.data ?? []).filter((finding) => finding.status === "new").length}</div>
                <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">Dismissed: {(findingsQuery.data ?? []).filter((finding) => finding.status === "dismissed").length}</div>
              </div>
              <div className="mt-4 space-y-2">
                {(findingsQuery.data ?? []).slice(0, 3).map((finding) => (
                  <div key={finding.id} className="rounded-2xl border border-line bg-panel/40 px-4 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <p className="text-sm font-semibold">{finding.title}</p>
                      <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{finding.severity}</span>
                    </div>
                    <p className="mt-2 text-sm text-muted">{finding.summary || finding.description || "No summary available."}</p>
                  </div>
                ))}
                {!(findingsQuery.data ?? []).length ? <p className="text-sm text-muted">No findings generated yet.</p> : null}
              </div>
            </div>
            <p className="mt-6 font-mono text-xs uppercase tracking-[0.18em] text-accent">Recent evidences</p>
            <div className="mt-4 space-y-3">
              {(evidencesQuery.data ?? []).slice(0, 6).map((item) => (
                <Link key={item.id} to={`/evidences/${item.id}`} className="flex items-center justify-between rounded-2xl border border-line bg-abyss/70 px-4 py-3">
                  <div>
                    <p className="text-sm">{item.original_filename}</p>
                    <p className="mt-1 font-mono text-xs text-muted">{item.evidence_type}</p>
                  </div>
                  <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{item.ingest_status}</span>
                </Link>
              ))}
              {!evidencesQuery.data?.length ? <p className="text-sm text-muted">{hasHostFilter ? `No recent evidence for ${activeHost}. Clear the host filter to see all evidence.` : "No evidences uploaded yet. Use the upload panel to add a raw evidence collection, KAPE/EZ outputs, or loose CSV/JSON files."}</p> : null}
            </div>
          </div>
        </section>
      ) : null}

      {tab === "evidences" ? (
        <section className="space-y-4">
          {renderGuidedIngestionPanel()}
          {!evidencesQuery.data?.length ? (
            <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">
              {hasHostFilter ? <>No evidence associated with {activeHost}. <button type="button" onClick={clearHostFilter} className="text-accent underline underline-offset-4">Clear host filter</button> to see all evidence, including unassigned evidence.</> : "This is the evidence workspace for the case. Use Add Evidence for guided ingestion, including specialized Velociraptor, EVTX, folder discovery, and server-path flows."}
            </div>
          ) : null}
          {(evidencesQuery.data ?? []).map((item) => {
            const assignedHostName = item.host_id ? hostNameById.get(item.host_id) || item.host_id.slice(0, 8) : "Unassigned";
            const detectedHost = item.detected_host || item.provided_host || "-";
            const mismatch = Boolean(item.host_id && detectedHost !== "-" && assignedHostName !== detectedHost);
            return (
            <Link key={item.id} to={`/evidences/${item.id}`} className="flex items-center justify-between gap-4 rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <div className="min-w-0">
                <p className="text-base font-semibold">{item.original_filename}</p>
                <p className="mt-1 font-mono text-xs text-muted">{item.sha256}</p>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                  <span className="rounded-full border border-line bg-abyss/70 px-2 py-1 text-muted">Detected: {detectedHost}</span>
                  <span className={`rounded-full border px-2 py-1 ${item.host_id ? "border-mint/30 bg-mint/10 text-mint" : "border-line bg-abyss/70 text-muted"}`}>Assigned: {assignedHostName}</span>
                  {mismatch ? <span className="rounded-full border border-amber/30 bg-amber/10 px-2 py-1 text-amber">Mismatch</span> : null}
                </div>
              </div>
              <div className="text-right">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{item.evidence_type}</p>
                <p className="mt-2 text-sm text-muted">{item.ingest_status}</p>
              </div>
            </Link>
            );
          })}
        </section>
      ) : null}

      {tab === "processing" ? (
        <section className="space-y-5" data-testid="processing-queue-view">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Evidence Processing Queue</p>
                <h3 className="mt-2 text-2xl font-semibold">Processing status by evidence</h3>
                <p className="mt-2 max-w-3xl text-sm text-muted">Track queued, running, completed and failed evidence processing without hiding parser errors. Partial results remain navigable when individual parsers fail.</p>
              </div>
              <div className="grid min-w-[320px] grid-cols-4 gap-2 text-center text-sm">
                {processingStatusCards(processingQuery.data?.summary).map((item) => (
                  <div key={item.label} className="rounded-2xl border border-line bg-abyss/70 px-3 py-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{item.label}</p>
                    <p className="mt-1 text-lg font-semibold text-ink">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
          {processingQuery.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{processingQuery.error.message}</div> : null}
          {!processingQuery.isLoading && !(processingQuery.data?.items ?? []).length ? (
            <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">
              {hasHostFilter ? <>No processing entries for {activeHost}. <button type="button" onClick={clearHostFilter} className="text-accent underline underline-offset-4">Clear host filter</button> to see all evidence.</> : "No processing runs yet. Upload evidence to see pending, queued, running and completed parser activity."}
            </div>
          ) : null}
          {(processingQuery.data?.items ?? []).length ? (
            <div className="grid gap-5 xl:grid-cols-[1.35fr_0.9fr]">
              <div className="overflow-hidden rounded-3xl border border-line bg-panel/70 shadow-panel">
                <div className="overflow-x-auto">
                  <table className="min-w-full text-left text-sm">
                    <thead className="border-b border-line bg-abyss/70 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                      <tr>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Evidence filename</th>
                        <th className="px-4 py-3">Host</th>
                        <th className="px-4 py-3">Type</th>
                        <th className="px-4 py-3">Last processed</th>
                        <th className="px-4 py-3">Duration</th>
                        <th className="px-4 py-3">Parsers OK</th>
                        <th className="px-4 py-3">Failed</th>
                        <th className="px-4 py-3">Artifacts</th>
                        <th className="px-4 py-3">Last error</th>
                        <th className="px-4 py-3">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/70">
                      {(processingQuery.data?.items ?? []).map((item) => (
                        <tr key={item.evidence_id} className={selectedProcessing?.evidence_id === item.evidence_id ? "bg-accent/10" : "bg-panel/40"}>
                          <td className="px-4 py-3"><span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.12em] ${processingStatusClass(item.processing_status)}`}>{item.processing_status.replaceAll("_", " ")}</span></td>
                          <td className="max-w-[240px] truncate px-4 py-3 font-semibold text-ink" title={item.filename}>{item.filename}</td>
                          <td className="max-w-[160px] truncate px-4 py-3 text-muted" title={item.host || "-"}>{item.host || "-"}</td>
                          <td className="px-4 py-3 font-mono text-xs text-muted">{item.evidence_type}</td>
                          <td className="px-4 py-3 text-muted">{formatDateTime(item.last_run_finished_at || item.last_run_started_at)}</td>
                          <td className="px-4 py-3 text-muted">{formatDuration(item.duration)}</td>
                          <td className="px-4 py-3 text-mint">{item.successful_parser_count}</td>
                          <td className="px-4 py-3 text-danger">{item.failed_parser_count}</td>
                          <td className="px-4 py-3 text-muted">{item.artifact_count}</td>
                          <td className="max-w-[260px] truncate px-4 py-3 text-muted" title={item.last_error || ""}>{item.last_error || "-"}</td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-2">
                              <button type="button" onClick={() => setSelectedProcessingId(item.evidence_id)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">View details</button>
                              <Link to={`/evidences/${item.evidence_id}`} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">Open evidence</Link>
                              <Link to={`/cases/${caseId}/artifacts?evidence_id=${item.evidence_id}`} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">Open artifacts</Link>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {selectedProcessing ? (
                <aside className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel" data-testid="processing-detail-panel">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Processing Detail</p>
                      <h3 className="mt-2 text-xl font-semibold">{selectedProcessing.filename}</h3>
                      <p className="mt-1 text-sm text-muted">{selectedProcessing.host || "Host unknown"} · {selectedProcessing.evidence_type}</p>
                    </div>
                    <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.12em] ${processingStatusClass(selectedProcessing.processing_status)}`}>{selectedProcessing.processing_status.replaceAll("_", " ")}</span>
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Uploaded</p><p className="mt-1 text-sm text-ink">{formatDateTime(selectedProcessing.uploaded_at)}</p></div>
                    <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Artifacts generated</p><p className="mt-1 text-sm text-ink">{selectedProcessing.artifact_count}</p></div>
                    <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Parsers OK</p><p className="mt-1 text-sm text-mint">{selectedProcessing.successful_parser_count}</p></div>
                    <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Parsers failed</p><p className="mt-1 text-sm text-danger">{selectedProcessing.failed_parser_count}</p></div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <Link to={`/evidences/${selectedProcessing.evidence_id}`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Evidence detail</Link>
                    <Link to={`/cases/${caseId}/search?evidence_id=${selectedProcessing.evidence_id}`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Search results</Link>
                    <Link to={`/cases/${caseId}/artifacts?evidence_id=${selectedProcessing.evidence_id}`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Artifact Explorer</Link>
                    {selectedProcessing.links.memory ? <Link to={selectedProcessing.links.memory} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Memory views</Link> : null}
                  </div>
                  <div className="mt-5">
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Timeline of processing runs</p>
                    {selectedProcessing.runs.length ? (
                      <ol className="mt-3 space-y-2">
                        {selectedProcessing.runs.map((run) => (
                          <li key={run.run_id} className="rounded-2xl border border-line bg-abyss/60 p-3">
                            <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-[11px] uppercase tracking-[0.14em] text-accent">{run.triggered_by} · {run.status.replaceAll("_", " ")}</span><span className="text-xs text-muted">{formatDateTime(run.started_at)} - {formatDateTime(run.finished_at)}</span></div>
                            <p className="mt-1 text-sm text-muted">{run.message || run.error_summary || "Run recorded."}</p>
                          </li>
                        ))}
                      </ol>
                    ) : <p className="mt-3 rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">No processing runs yet. This evidence has been uploaded but processing has not started.</p>}
                  </div>
                  {selectedProcessing.linux_artifacts?.length ? (
                    <div className="mt-5" data-testid="linux-processing-artifacts">
                      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Detected Linux artifacts</p>
                      <div className="mt-3 overflow-x-auto rounded-2xl border border-line">
                        <table className="min-w-full text-left text-xs">
                          <thead className="bg-abyss/70 font-mono uppercase tracking-[0.12em] text-muted"><tr><th className="px-3 py-2">Artifact</th><th className="px-3 py-2">Family</th><th className="px-3 py-2">Status</th><th className="px-3 py-2">Sources found</th><th className="px-3 py-2">Events parsed</th></tr></thead>
                          <tbody className="divide-y divide-line/70">
                            {selectedProcessing.linux_artifacts.map((artifact) => (
                              <tr key={`${artifact.family}-${artifact.name}`}><td className="px-3 py-2 text-ink">{artifact.name}</td><td className="px-3 py-2 text-muted">{artifact.family}</td><td className="px-3 py-2 text-muted">{artifact.status}</td><td className="px-3 py-2 text-muted">{artifact.source_count ?? artifact.paths?.length ?? 0}</td><td className="px-3 py-2 text-muted">{artifact.records ?? 0}</td></tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : null}
                  <div className="mt-5">
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Parser-level status</p>
                    {selectedProcessing.parser_runs.length ? (
                      <div className="mt-3 overflow-x-auto rounded-2xl border border-line">
                        <table className="min-w-full text-left text-xs">
                          <thead className="bg-abyss/70 font-mono uppercase tracking-[0.12em] text-muted"><tr><th className="px-3 py-2">Parser</th><th className="px-3 py-2">Family</th><th className="px-3 py-2">Status</th><th className="px-3 py-2">Artifacts</th><th className="px-3 py-2">Error</th></tr></thead>
                          <tbody className="divide-y divide-line/70">
                            {selectedProcessing.parser_runs.map((parser) => (
                              <tr key={`${parser.family}-${parser.parser}`}><td className="px-3 py-2 text-ink">{parser.parser}</td><td className="px-3 py-2 text-muted">{parser.family}</td><td className="px-3 py-2 text-muted">{parser.status}</td><td className="px-3 py-2 text-muted">{parser.artifacts}</td><td className="px-3 py-2 text-danger">{parser.error || "-"}</td></tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : <p className="mt-3 rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">No parser-level records yet. No artifacts were generated for this parser; this can be normal depending on evidence type and parser support. <Link to="/parser-coverage" className="text-accent underline underline-offset-4">Why no artifacts?</Link></p>}
                  </div>
                  <div className="mt-5">
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Errors and warnings</p>
                    {selectedProcessing.errors.length ? <div className="mt-3 space-y-2">{selectedProcessing.errors.map((error, index) => <div key={`${error.parser}-${index}`} className="rounded-2xl border border-danger/30 bg-danger/10 p-3 text-sm text-danger"><span className="font-mono text-xs uppercase tracking-[0.12em]">{error.parser}</span><p className="mt-1">{error.summary || "Processing failed."}</p></div>)}</div> : <p className="mt-3 rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">No parser errors recorded for this evidence.</p>}
                    {selectedProcessing.processing_status === "completed_with_warnings" ? <p className="mt-3 text-sm text-amber">Processing completed with warnings. Some parsers failed, but partial results are available.</p> : null}
                  </div>
                </aside>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : null}

      {tab === "artifacts" ? (
        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(artifactsQuery.data ?? []).map((artifact) => (
            <div key={artifact.id} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex items-center justify-between gap-4">
                <p className="text-sm font-semibold">{artifact.name}</p>
                <ArtifactBadge type={artifact.artifact_type} />
              </div>
              <p className="mt-3 font-mono text-xs text-muted">{artifact.source_path}</p>
              <div className="mt-4 flex items-center justify-between text-sm text-muted">
                <span>{artifact.parser}</span>
                <span>{artifact.record_count} events</span>
              </div>
            </div>
          ))}
        </section>
      ) : null}

      {tab === "search" ? (
        <section className="space-y-4">
          {searchEventId ? (
            <div className="rounded-2xl border border-line bg-panel/50 px-4 py-3 text-sm text-muted">
              Filtering Search to source event <span className="font-mono text-white/90">{searchEventId}</span>
              <button
                type="button"
                onClick={() => {
                  const next = new URLSearchParams(searchParams);
                  next.delete("event_id");
                  next.delete("evidence_id");
                  setSearchParams(next, { replace: true });
                  setSearchEventId("");
                  setSearchEvidenceId("");
                }}
                className="ml-3 rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs text-muted"
              >
                Clear source-event filter
              </button>
            </div>
          ) : null}
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search this case"
            className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
          />
          <EventTable
            items={searchQuery.data?.items ?? []}
            view="auto"
            onViewProcessTree={(item) => {
              const process = (item.process as Record<string, unknown>) ?? {};
              const next = new URLSearchParams(searchParams);
              next.set("tab", "process_tree");
              if (item.evidence_id) next.set("evidence_id", String(item.evidence_id));
              if (process.pid !== undefined && process.pid !== null && String(process.pid).trim()) next.set("pid", String(process.pid));
              if (process.name !== undefined && process.name !== null && String(process.name).trim()) next.set("process_name", String(process.name));
              setSearchParams(next, { replace: false });
              setTab("process_tree");
            }}
          />
        </section>
      ) : null}

      {tab === "process_tree" ? (
        <ProcessTreePanel
          caseId={caseId}
          evidences={evidencesQuery.data ?? []}
          initialEvidenceId={searchParams.get("evidence_id") ?? ""}
          initialPid={searchParams.get("pid") ?? ""}
          initialProcessName={searchParams.get("process_name") ?? ""}
          initialHighlightedNodeIds={searchParams.getAll("node_id")}
        />
      ) : null}

      {tab === "artifact_explorer" ? (
        <section className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">
          Use the dedicated artifact-focused workflow to pivot by artifact type, artifact name and evidence without starting from free-text search.
          <div className="mt-4">
            <Link to={`/cases/${caseId}/artifacts`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Artifact Search</Link>
          </div>
        </section>
      ) : null}

      {tab === "investigation_timeline" ? (
        <section>
          <div className="mb-4 rounded-3xl border border-line bg-panel/40 p-4 text-sm text-muted">
            Chronological reconstruction of indexed forensic events for the selected case or host.
          </div>
          <button
            type="button"
            disabled={!selectedEventIds.length}
            onClick={() => setFindingDialogOpen(true)}
            className="mb-4 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-50"
          >
            Create Finding from selected events
          </button>
          <Timeline
            items={timelineQuery.data?.items ?? []}
            selectedIds={selectedEventIds}
            onToggleSelect={(eventId) =>
              setSelectedEventIds((current) => (current.includes(eventId) ? current.filter((item) => item !== eventId) : [...current, eventId]))
            }
          />
        </section>
      ) : null}
      <CreateFindingDialog
        open={findingDialogOpen}
        onClose={() => setFindingDialogOpen(false)}
        caseId={caseId}
        eventIds={selectedEventIds}
        defaultTitle="Case timeline investigative lead"
        defaultDescription="Created from selected events inside the case timeline tab."
        defaultSeverity="medium"
        query={query || null}
        onCreated={() => setSelectedEventIds([])}
      />

      {tab === "findings" ? (
        <FindingsWorkspace caseId={caseId} embedded showHeader={false} />
      ) : null}

      {tab === "detections" ? (
        <section className="space-y-4">
          {(detectionsQuery.data?.items ?? []).length ? (
            detectionsQuery.data?.items.map((detection) => (
              <div key={detection.id} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-semibold">{detection.rule_name}</h3>
                  <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{detection.engine}</span>
                </div>
                <p className="mt-3 text-sm text-muted">{detection.message ?? "No detection message."}</p>
              </div>
            ))
          ) : (
            <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">No detections for this case yet.</div>
          )}
        </section>
      ) : null}

      {tab === "activity" ? (
        <section className="space-y-4">
          <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">Operational activity generated by this Kairon DFIR workbench: uploads, parsing jobs, rule runs and processing errors.</div>
          {(activityQuery.data ?? []).map((activity) => (
            <div key={activity.id} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-semibold">{activity.title}</h3>
                  <p className="mt-2 text-sm text-muted">{activity.message}</p>
                </div>
                <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{activity.severity}</span>
              </div>
            </div>
          ))}
        </section>
      ) : null}
      {metadataEditorOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Edit case">
          <div className="w-full max-w-2xl rounded-3xl border border-line bg-panel p-6 shadow-panel">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Edit case</p>
                <h2 className="mt-1 text-xl font-semibold">Case metadata</h2>
              </div>
              <button onClick={() => setMetadataEditorOpen(false)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Cancel</button>
            </div>
            <div className="mt-4 grid gap-3">
              <label className="text-xs text-muted">Name<input value={editName} onChange={(event) => setEditName(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <label className="text-xs text-muted">Description<textarea value={editDescription} onChange={(event) => setEditDescription(event.target.value)} className="mt-1 h-24 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="text-xs text-muted">Priority<select value={editPriority} onChange={(event) => setEditPriority(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink"><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></label>
                <label className="text-xs text-muted">Status<select value={editStatus} onChange={(event) => setEditStatus(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink"><option value="active">active</option><option value="closed">closed</option><option value="archived">archived</option><option value="on_hold">on_hold</option></select></label>
              </div>
              <label className="text-xs text-muted">Tags<input value={editTags} onChange={(event) => setEditTags(event.target.value)} placeholder="ctf, memory, windows" className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <label className="text-xs text-muted">Notes<textarea value={editNotes} onChange={(event) => setEditNotes(event.target.value)} className="mt-1 h-24 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
            </div>
            <button onClick={() => updateCaseMetadataMutation.mutate()} disabled={updateCaseMetadataMutation.isPending || !editName.trim()} className="mt-5 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
              {updateCaseMetadataMutation.isPending ? "Saving..." : "Save case"}
            </button>
          </div>
        </div>
      ) : null}
      <DebugExportDialog
        open={debugExportOpen}
        onClose={() => setDebugExportOpen(false)}
        caseId={caseId}
        title="Export full case validation pack"
        defaultRequest={{
          scope: "case",
          include_raw_samples: false,
          include_raw_xml: false,
          include_source_paths: true,
          include_full_raw: false,
          max_events_per_type: 25,
          max_field_length: 2000,
          redact_secrets: true,
          ui_context: {
            page: "CaseDetail",
            tab,
            selected_case: caseId,
            selected_event_ids: selectedEventIds,
            query,
          },
        }}
      />
      <DeleteCaseDialog
        open={deleteDialogOpen}
        caseItem={caseQuery.data ?? null}
        onClose={() => setDeleteDialogOpen(false)}
        onDeleted={() => navigate("/cases")}
      />
      <EvidenceIngestionWizard
        open={ingestionWizardOpen}
        caseId={caseId}
        resumeSessionId={searchParams.get("resume_session") ?? undefined}
        resumeCandidate={resumeCandidate}
        expectedKind={expectedKind}
        onClose={() => {
          setIngestionWizardOpen(false);
          setResumeCandidate(null);
          if (searchParams.get("resume_session") || searchParams.get("add_evidence") || searchParams.get("expected_kind")) {
            const next = new URLSearchParams(searchParams);
            next.delete("resume_session");
            next.delete("add_evidence");
            next.delete("expected_kind");
            setSearchParams(next, { replace: true });
          }
        }}
      />
    </div>
  );
}

function processingSummaryLabel(summary: Record<string, number> | undefined) {
  if (!summary) return "-";
  const completed = Number(summary.completed ?? 0) + Number(summary.completed_with_warnings ?? 0);
  const running = Number(summary.running ?? 0) + Number(summary.queued ?? 0);
  const failed = Number(summary.failed ?? 0);
  return `${completed} completed · ${running} running · ${failed} failed`;
}

function processingStatusCards(summary: Record<string, number> | undefined) {
  return [
    { label: "Completed", value: Number(summary?.completed ?? 0) + Number(summary?.completed_with_warnings ?? 0) },
    { label: "Running", value: Number(summary?.running ?? 0) },
    { label: "Queued", value: Number(summary?.queued ?? 0) + Number(summary?.pending ?? 0) },
    { label: "Failed", value: Number(summary?.failed ?? 0) },
  ];
}

function processingStatusClass(status: string) {
  if (status === "completed") return "border-mint/30 bg-mint/10 text-mint";
  if (status === "completed_with_warnings") return "border-amber/30 bg-amber/10 text-amber";
  if (status === "failed") return "border-danger/30 bg-danger/10 text-danger";
  if (status === "running" || status === "queued") return "border-accent/30 bg-accent/10 text-accent";
  return "border-line bg-abyss/60 text-muted";
}

function formatDateTime(value: string | null | undefined) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatDuration(value: number | null | undefined) {
  if (value === null || value === undefined) return "-";
  if (value < 1) return `${Math.round(value * 1000)} ms`;
  if (value < 60) return `${value.toFixed(1)} s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  return `${minutes}m ${seconds}s`;
}
