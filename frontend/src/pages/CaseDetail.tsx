import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import ArtifactBadge from "../components/ArtifactBadge";
import CreateFindingDialog from "../components/CreateFindingDialog";
import DebugExportDialog from "../components/DebugExportDialog";
import EvidenceUpload from "../components/EvidenceUpload";
import EventTable from "../components/EventTable";
import FindingsWorkspace from "../components/FindingsWorkspace";
import ProcessTreePanel from "../components/ProcessTreePanel";
import Timeline from "../components/Timeline";
import { useActiveCase } from "../context/ActiveCaseContext";

const tabs = ["overview", "evidences", "artifacts", "artifact_explorer", "search", "process_tree", "investigation_timeline", "detections", "findings", "activity"] as const;
const tabLabels: Record<(typeof tabs)[number], string> = {
  overview: "Overview",
  evidences: "Evidence & Ingest",
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
  const { activeCaseId, clearActiveCase, setActiveCase } = useActiveCase();
  const initialTab = searchParams.get("tab");
  const [tab, setTab] = useState<(typeof tabs)[number]>(tabs.includes(initialTab as (typeof tabs)[number]) ? (initialTab as (typeof tabs)[number]) : "overview");
  const [caseTimezone, setCaseTimezone] = useState("");
  const [query, setQuery] = useState(searchParams.get("query") ?? "");
  const [searchEventId, setSearchEventId] = useState(searchParams.get("event_id") ?? "");
  const [searchEvidenceId, setSearchEvidenceId] = useState(searchParams.get("evidence_id") ?? "");
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const caseQuery = useQuery({ queryKey: ["case", caseId], queryFn: () => api.getCase(caseId), enabled: Boolean(caseId), staleTime: 15_000, refetchOnWindowFocus: false });
  const evidencesQuery = useQuery({ queryKey: ["evidences", caseId], queryFn: () => api.listEvidences(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const artifactsQuery = useQuery({ queryKey: ["artifacts", caseId], queryFn: () => api.listArtifacts(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const findingsQuery = useQuery({ queryKey: ["findings", caseId], queryFn: () => api.listFindings(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const detectionsQuery = useQuery({ queryKey: ["detections", caseId], queryFn: () => api.listDetections(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const summaryQuery = useQuery({ queryKey: ["investigation-summary", caseId], queryFn: () => api.getInvestigationSummary(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const activityQuery = useQuery({ queryKey: ["case-activity", caseId], queryFn: () => api.listCaseActivity(caseId), enabled: Boolean(caseId), staleTime: 10_000, refetchOnWindowFocus: false });
  const siemLinksQuery = useQuery({ queryKey: ["siem-external-links", "case", caseId], queryFn: () => api.siemExternalLinks({ case_id: caseId }), enabled: Boolean(caseId), staleTime: 30_000, refetchOnWindowFocus: false });
  const searchQuery = useQuery({
    queryKey: ["case-search", caseId, query, searchEventId, searchEvidenceId],
    queryFn: () =>
      api.search({
        case_id: caseId,
        query: query || "*",
        filters: {
          event_id: searchEventId ? [searchEventId] : [],
          evidence_id: searchEvidenceId ? [searchEvidenceId] : [],
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
  const deleteCaseMutation = useMutation({
    mutationFn: () => api.deleteCase(caseId),
    onSuccess: () => {
      if (activeCaseId === caseId) {
        clearActiveCase();
      }
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void navigate("/cases");
    },
  });

  useEffect(() => {
    if (caseQuery.data && caseQuery.data.id !== activeCaseId) {
      setActiveCase(caseQuery.data);
    }
  }, [activeCaseId, caseQuery.data, setActiveCase]);

  useEffect(() => {
    const requestedTab = searchParams.get("tab");
    if (requestedTab && tabs.includes(requestedTab as (typeof tabs)[number]) && requestedTab !== tab) {
      setTab(requestedTab as (typeof tabs)[number]);
    }
  }, [searchParams, tab]);

  useEffect(() => {
    const requestedQuery = searchParams.get("query") ?? "";
    if (requestedQuery !== query) {
      setQuery(requestedQuery);
    }
  }, [query, searchParams]);

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
      ["Artifact Inventory", artifactsQuery.data?.length ?? 0],
      ["Detections", summaryQuery.data?.counts.detections ?? caseQuery.data?.detections_count ?? 0],
      ["Findings", summaryQuery.data?.counts.findings ?? caseQuery.data?.findings_count ?? 0],
      ["Status", caseQuery.data?.status ?? "-"],
    ],
    [artifactsQuery.data?.length, caseQuery.data?.detections_count, caseQuery.data?.findings_count, caseQuery.data?.status, evidencesQuery.data?.length, summaryQuery.data?.counts.detections, summaryQuery.data?.counts.findings],
  );

  return (
    <div className="space-y-8">
      {caseQuery.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{caseQuery.error.message}</div> : null}
      <section className="rounded-[28px] border border-line bg-panel/60 p-6 shadow-panel">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case</p>
            <h2 className="mt-2 text-3xl font-semibold">{caseQuery.data?.name}</h2>
            <p className="mt-3 max-w-3xl text-sm text-muted">{caseQuery.data?.description}</p>
          </div>
          <div className="grid gap-3 md:grid-cols-5">
            {overviewStats.map(([label, value]) => (
              <div key={String(label)} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
                <p className="mt-2 text-lg font-semibold">{value}</p>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-6 flex flex-wrap gap-2">
          {tabs.map((item) => (
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
          <button
            onClick={() => {
              if (deleteCaseMutation.isPending) return;
              if (!window.confirm("Delete this case and all its evidences, artifacts and indexed events? This action cannot be undone.")) return;
              deleteCaseMutation.mutate();
            }}
            className="rounded-full border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger"
          >
            {deleteCaseMutation.isPending ? "Deleting..." : "Delete case"}
          </button>
          <button onClick={() => setDebugExportOpen(true)} className="rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted">
            Export full case validation pack
          </button>
        </div>
        {deleteCaseMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{deleteCaseMutation.error.message}</p> : null}
      </section>

      {tab === "overview" ? (
        <section className="grid gap-6 lg:grid-cols-[1.1fr_1.9fr]">
          <EvidenceUpload
            caseId={caseId}
            onUploaded={() => {
              void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
              void queryClient.invalidateQueries({ queryKey: ["artifacts", caseId] });
            }}
          />
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
              <Link to={`/cases/${caseId}/timeline`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Search Timeline</Link>
              <Link to={`/cases/${caseId}/artifact-search`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Artifact Search</Link>
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
              {!evidencesQuery.data?.length ? <p className="text-sm text-muted">No evidences uploaded yet. Use the upload panel to add a raw evidence collection, KAPE/EZ outputs, or loose CSV/JSON files.</p> : null}
            </div>
          </div>
        </section>
      ) : null}

      {tab === "evidences" ? (
        <section className="space-y-4">
          <EvidenceUpload
            caseId={caseId}
            onUploaded={() => {
              void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
            }}
          />
          {!evidencesQuery.data?.length ? (
            <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">
              This is the evidence workspace for the case. Click the upload panel above to add a raw evidence collection, parsed KAPE/EZ Tools output, or loose CSV/JSON artifacts.
            </div>
          ) : null}
          {(evidencesQuery.data ?? []).map((item) => (
            <Link key={item.id} to={`/evidences/${item.id}`} className="flex items-center justify-between rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <div>
                <p className="text-base font-semibold">{item.original_filename}</p>
                <p className="mt-1 font-mono text-xs text-muted">{item.sha256}</p>
              </div>
              <div className="text-right">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{item.evidence_type}</p>
                <p className="mt-2 text-sm text-muted">{item.ingest_status}</p>
              </div>
            </Link>
          ))}
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
            <Link to={`/cases/${caseId}/artifact-search`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open Artifact Search</Link>
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
    </div>
  );
}
