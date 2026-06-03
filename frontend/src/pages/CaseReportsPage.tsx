import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { api, type CaseReport, type Finding, type TimelineBookmark } from "../api/client";
import DebugExportDialog from "../components/DebugExportDialog";
import { useActiveCase } from "../context/ActiveCaseContext";

const SECTION_LABELS: Record<string, string> = {
  executive_summary: "Executive Summary",
  scope: "Scope",
  evidence: "Evidence",
  hosts: "Hosts",
  findings: "Findings",
  timeline: "Timeline",
  incident_timeline: "Incident Timeline",
  ground_truth_coverage: "Ground Truth Coverage",
  process_chains: "Process Chains",
  command_history: "Command History",
  defender: "Defender",
  motw: "MOTW / Downloaded Files",
  srum: "SRUM",
  iocs: "IOCs",
  persistence: "Persistence",
  network_cloud_usb: "Network / Cloud / USB",
  recommendations: "Recommendations",
  appendix: "Appendix",
};

function downloadBlobFile(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export default function CaseReportsPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId, selectedHost, selectedEvidenceId, caseContext } = useActiveCase();
  const queryClient = useQueryClient();
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const [selectedReportId, setSelectedReportId] = useState("");
  const [executiveNote, setExecutiveNote] = useState("");
  const [recommendationsNote, setRecommendationsNote] = useState("");
  const [limitationsNote, setLimitationsNote] = useState("");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<"default" | "error">("default");
  const [advancedFiltersOpen, setAdvancedFiltersOpen] = useState(false);
  const showValidationCoverage = Boolean(caseContext?.summary?.validation_matrix?.show_validation_matrix);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const templatesQuery = useQuery({
    queryKey: ["report-templates", caseId],
    queryFn: () => api.listReportTemplates(caseId),
    enabled: Boolean(caseId),
    staleTime: 60_000,
  });
  const reportsQuery = useQuery({
    queryKey: ["case-reports", caseId],
    queryFn: () => api.listCaseReports(caseId),
    enabled: Boolean(caseId),
    staleTime: 15_000,
  });
  const findingsQuery = useQuery({
    queryKey: ["report-findings", caseId, selectedHost, selectedEvidenceId],
    queryFn: () => api.listFindings(caseId, { host: selectedHost || undefined, evidence_id: selectedEvidenceId || undefined }),
    enabled: Boolean(caseId),
    staleTime: 15_000,
  });
  const keyEventsQuery = useQuery({
    queryKey: ["report-key-events", caseId],
    queryFn: () => api.listTimelineKeyEvents(caseId),
    enabled: Boolean(caseId),
    staleTime: 15_000,
  });
  const reportQuery = useQuery({
    queryKey: ["case-report", caseId, selectedReportId],
    queryFn: () => api.getCaseReport(caseId, selectedReportId),
    enabled: Boolean(caseId && selectedReportId),
  });
  const previewQuery = useQuery({
    queryKey: ["case-report-preview", caseId, selectedReportId],
    queryFn: () => api.getCaseReportPreview(caseId, selectedReportId),
    enabled: Boolean(caseId && selectedReportId),
  });

  useEffect(() => {
    if (!selectedReportId && reportsQuery.data?.length) {
      setSelectedReportId(reportsQuery.data[0]!.id);
    }
  }, [reportsQuery.data, selectedReportId]);

  useEffect(() => {
    const notes = reportQuery.data?.analyst_notes ?? {};
    setExecutiveNote(notes.executive_summary ?? "");
    setRecommendationsNote(notes.recommendations ?? "");
    setLimitationsNote(notes.limitations ?? "");
  }, [reportQuery.data]);

  const createDraft = useMutation({
    mutationFn: () =>
      api.createCaseReportDraft(caseId, {
        template: templatesQuery.data?.items[0]?.id ?? "standard_investigation",
        filters: {
          host: selectedHost || null,
          evidence_id: selectedEvidenceId || null,
          include_statuses: ["confirmed", "reviewed", "new"],
          detection_statuses: ["new", "reviewed", "confirmed"],
          detection_severities: ["medium", "high", "critical"],
          marking_statuses: ["suspicious", "important"],
          min_severity: "medium",
          include_findings: true,
          include_detections: true,
          include_marked_events: true,
          include_timeline_events: true,
          include_command_history: true,
          command_only_suspicious: true,
          include_execution_stories: true,
          include_incident_timeline: true,
          include_ground_truth_coverage: showValidationCoverage,
          max_commands: 50,
          max_execution_stories: 10,
          max_incident_timeline_items: 60,
        },
        auto_select: true,
      }),
    onSuccess: (report) => {
      setSelectedReportId(report.id);
      setStatusTone("default");
      setStatusMessage("Report draft created.");
      void queryClient.invalidateQueries({ queryKey: ["case-reports", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["case-report-preview", caseId, report.id] });
    },
    onError: (error) => {
      setStatusTone("error");
      setStatusMessage(error instanceof Error ? error.message : "Could not create report draft.");
    },
  });

  const reportOptionItems = [
    ["include_findings", "Include findings"],
    ["include_detections", "Include detections"],
    ["include_marked_events", "Include marked events"],
    ["include_timeline_events", "Include timeline events"],
    ["include_command_history", "Include suspicious commands"],
    ["include_incident_timeline", "Include incident timeline"],
    ...(showValidationCoverage ? [["include_ground_truth_coverage", "Include ground truth coverage"]] : []),
  ];

  const patchReport = useMutation({
    mutationFn: (payload: Partial<CaseReport>) => api.updateCaseReport(caseId, selectedReportId, payload),
    onSuccess: () => {
      setStatusTone("default");
      setStatusMessage("Draft updated.");
      void queryClient.invalidateQueries({ queryKey: ["case-report", caseId, selectedReportId] });
      void queryClient.invalidateQueries({ queryKey: ["case-report-preview", caseId, selectedReportId] });
      void queryClient.invalidateQueries({ queryKey: ["case-reports", caseId] });
    },
    onError: (error) => {
      setStatusTone("error");
      setStatusMessage(error instanceof Error ? error.message : "Could not update report draft.");
    },
  });

  const exportMarkdown = useMutation({
    mutationFn: () => api.exportCaseReport(caseId, selectedReportId, "markdown"),
    onSuccess: async ({ blob, filename }) => {
      downloadBlobFile(filename, blob);
      setStatusTone("default");
      setStatusMessage("Markdown report exported.");
    },
    onError: (error) => {
      setStatusTone("error");
      setStatusMessage(error instanceof Error ? error.message : "Markdown export failed.");
    },
  });

  const exportPdf = useMutation({
    mutationFn: () => api.exportCaseReport(caseId, selectedReportId, "pdf"),
    onSuccess: ({ blob, filename }) => {
      downloadBlobFile(filename, blob);
      setStatusTone("default");
      setStatusMessage("PDF report exported.");
    },
    onError: (error) => {
      setStatusTone("error");
      setStatusMessage(error instanceof Error ? `PDF export failed: ${error.message}` : "PDF export failed.");
    },
  });

  const currentReport = reportQuery.data;
  const reportFilters = currentReport?.filters ?? {};
  const selectedFindingIds = new Set(currentReport?.selected_finding_ids ?? []);
  const selectedKeyEventIds = new Set(currentReport?.selected_key_event_ids ?? []);
  const chainCandidates = useMemo(
    () => (findingsQuery.data ?? []).filter((finding) => (finding.related_process_node_ids?.length ?? 0) > 0),
    [findingsQuery.data],
  );
  const previewCounts = previewQuery.data?.counts ?? previewQuery.data?.stats ?? {};
  const activeFilterChips = useMemo(() => {
    const chips: string[] = [];
    if (reportFilters.evidence_id) chips.push(`Evidence: ${String(reportFilters.evidence_id)}`);
    if (reportFilters.host) chips.push(`Host: ${String(reportFilters.host)}`);
    if (reportFilters.time_from || reportFilters.time_to) chips.push(`Time: ${String(reportFilters.time_from || "beginning")} -> ${String(reportFilters.time_to || "latest")}`);
    if (reportFilters.min_severity) chips.push(`Severity >= ${String(reportFilters.min_severity)}`);
    if (reportFilters.risk_min || reportFilters.risk_max) chips.push(`Risk ${String(reportFilters.risk_min || 0)}-${String(reportFilters.risk_max || 100)}`);
    if (reportFilters.include_marked_events) chips.push("Marked events");
    if (reportFilters.include_command_history) chips.push("Command History");
    if (reportFilters.command_only_suspicious) chips.push("Suspicious commands");
    if (reportFilters.include_execution_stories) chips.push("Execution stories");
    if (reportFilters.include_incident_timeline) chips.push("Incident timeline");
    if (reportFilters.command_query) chips.push(`Command: ${String(reportFilters.command_query)}`);
    if (reportFilters.include_detections) chips.push("Detections");
    if (reportFilters.include_findings) chips.push("Findings");
    return chips;
  }, [reportFilters]);

  function updateReportFilters(next: Record<string, unknown>) {
    if (!currentReport) return;
    patchReport.mutate({ filters: { ...currentReport.filters, ...next } });
  }

  function setListFilter(key: string, value: string, checked: boolean) {
    const current = new Set((Array.isArray(reportFilters[key]) ? reportFilters[key] : []).map(String));
    if (checked) current.add(value);
    else current.delete(value);
    updateReportFilters({ [key]: Array.from(current) });
  }

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case to access reports and debug exports.</div>;
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Reports / Export</p>
            <h2 className="mt-2 text-2xl font-semibold">Investigation narrative builder</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              Build a report from selected findings, key events and process chains. Markdown remains editable and PDF export uses the same structured report data with secret redaction applied.
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">Host filter: {selectedHost || "All hosts"}</span>
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">Evidence filter: {selectedEvidenceId || "All evidence"}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={() => createDraft.mutate()} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
              Create investigation report
            </button>
            <button type="button" onClick={() => setDebugExportOpen(true)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
              Export full case debug pack
            </button>
          </div>
        </div>
        {statusMessage ? (
          <div className={`mt-4 rounded-2xl border p-3 text-sm ${statusTone === "error" ? "border-danger/40 bg-danger/10 text-danger" : "border-line bg-abyss/60 text-muted"}`}>
            {statusMessage}
          </div>
        ) : null}
      </section>

      <section className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="space-y-4 rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Drafts</p>
            <div className="mt-3 space-y-2">
              {(reportsQuery.data ?? []).map((report) => (
                <button
                  key={report.id}
                  type="button"
                  onClick={() => setSelectedReportId(report.id)}
                  className={`w-full rounded-2xl border px-3 py-3 text-left text-sm ${selectedReportId === report.id ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}
                >
                  <p className="font-semibold">{report.title}</p>
                  <p className="mt-1 text-xs uppercase tracking-[0.14em]">{report.status}</p>
                </button>
              ))}
              {!reportsQuery.data?.length ? <p className="text-sm text-muted">No report drafts yet.</p> : null}
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Auto-selection inputs</p>
            <p className="mt-2">Findings available: {(findingsQuery.data ?? []).length}</p>
            <p>Key events available: {(keyEventsQuery.data ?? []).length}</p>
            <p>Hosts in case: {caseContext?.hosts.length ?? 0}</p>
          </div>
        </aside>

        <div className="space-y-6 min-w-0">
          {currentReport ? (
            <>
              <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
                <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Title</span>
                    <input
                      value={currentReport.title}
                      onChange={(event) => patchReport.mutate({ title: event.target.value })}
                      className="w-full bg-transparent outline-none"
                    />
                  </label>
                  <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Template</p>
                    <p className="mt-2">{currentReport.template}</p>
                  </div>
                </div>

                <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Report filters</p>
                      <p className="mt-1 text-sm text-muted">Choose the scope and content before generating or exporting.</p>
                    </div>
                    <button type="button" onClick={() => setAdvancedFiltersOpen((current) => !current)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                      {advancedFiltersOpen ? "Hide advanced filters" : "Advanced filters"}
                    </button>
                  </div>
                  {activeFilterChips.length ? (
                    <div className="mt-3 flex flex-wrap gap-2" data-testid="report-filter-chips">
                      {activeFilterChips.map((chip) => (
                        <span key={chip} className="rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs text-accent">{chip}</span>
                      ))}
                    </div>
                  ) : null}
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-4">
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Min severity</span>
                    <select
                      value={String(reportFilters.min_severity ?? "medium")}
                      onChange={(event) => updateReportFilters({ min_severity: event.target.value })}
                      className="w-full bg-transparent outline-none"
                    >
                      <option value="info">info</option>
                      <option value="low">low</option>
                      <option value="medium">medium</option>
                      <option value="high">high</option>
                      <option value="critical">critical</option>
                    </select>
                  </label>
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host filter</span>
                    <select value={String(reportFilters.host ?? "")} onChange={(event) => updateReportFilters({ host: event.target.value || null })} className="w-full bg-transparent outline-none">
                      <option value="">All hosts</option>
                      {(caseContext?.hosts ?? []).map((host) => <option key={host.id} value={host.canonical_name}>{host.canonical_name}</option>)}
                    </select>
                  </label>
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence filter</span>
                    <select value={String(reportFilters.evidence_id ?? "")} onChange={(event) => updateReportFilters({ evidence_id: event.target.value || null })} className="w-full bg-transparent outline-none">
                      <option value="">All evidence</option>
                      {(caseContext?.evidences ?? []).map((evidence) => <option key={evidence.id} value={evidence.id}>{evidence.name}</option>)}
                    </select>
                  </label>
                  <button type="button" onClick={() => updateReportFilters({ evidence_id: null, host: null, time_from: null, time_to: null, risk_min: null, risk_max: null, source_file: null, artifact_type: null, parser: null, rule_name: null })} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
                    Clear filters
                  </button>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-4">
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Time from</span>
                    <input type="datetime-local" value={String(reportFilters.time_from ?? "").slice(0, 16)} onChange={(event) => updateReportFilters({ time_from: event.target.value ? `${event.target.value}:00Z` : null })} className="w-full bg-transparent outline-none" />
                  </label>
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Time to</span>
                    <input type="datetime-local" value={String(reportFilters.time_to ?? "").slice(0, 16)} onChange={(event) => updateReportFilters({ time_to: event.target.value ? `${event.target.value}:00Z` : null })} className="w-full bg-transparent outline-none" />
                  </label>
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Risk min</span>
                    <input value={String(reportFilters.risk_min ?? "")} onChange={(event) => updateReportFilters({ risk_min: event.target.value || null })} placeholder="0" className="w-full bg-transparent outline-none" />
                  </label>
                  <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                    <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Risk max</span>
                    <input value={String(reportFilters.risk_max ?? "")} onChange={(event) => updateReportFilters({ risk_max: event.target.value || null })} placeholder="100" className="w-full bg-transparent outline-none" />
                  </label>
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  {reportOptionItems.map(([key, label]) => (
                    <label key={key} className="flex items-center gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                      <input type="checkbox" checked={Boolean(reportFilters[key] ?? true)} onChange={(event) => updateReportFilters({ [key]: event.target.checked })} />
                      {label}
                    </label>
                  ))}
                </div>

                <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Command History</p>
                      <p className="mt-1 text-sm text-muted">Include suspicious or analyst-marked command executions with optional Execution Story summaries.</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <label className="flex items-center gap-2 rounded-xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                        <input type="checkbox" checked={Boolean(reportFilters.include_command_history ?? true)} onChange={(event) => updateReportFilters({ include_command_history: event.target.checked })} />
                        Include suspicious commands
                      </label>
                      <label className="flex items-center gap-2 rounded-xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                        <input type="checkbox" checked={Boolean(reportFilters.command_only_suspicious ?? true)} onChange={(event) => updateReportFilters({ command_only_suspicious: event.target.checked })} />
                        Suspicious only
                      </label>
                      <label className="flex items-center gap-2 rounded-xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                        <input type="checkbox" checked={Boolean(reportFilters.include_execution_stories ?? true)} onChange={(event) => updateReportFilters({ include_execution_stories: event.target.checked })} />
                        Include execution stories
                      </label>
                    </div>
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Command query</span>
                      <input value={String(reportFilters.command_query ?? "")} onChange={(event) => updateReportFilters({ command_query: event.target.value || null })} placeholder="remote-admin, maintenance.ps1, -ep bypass" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Family</span>
                      <select value={String(reportFilters.command_family ?? reportFilters.command_shell ?? "")} onChange={(event) => updateReportFilters({ command_family: event.target.value || null, command_shell: null })} className="w-full bg-transparent outline-none">
                        <option value="">Any</option>
                        {["powershell", "cmd", "remote_exec", "lolbin", "script_host", "scheduled_task", "binary_execution", "system", "browser", "unknown"].map((value) => <option key={value} value={value}>{value}</option>)}
                      </select>
                    </label>
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Launcher</span>
                      <input value={String(reportFilters.command_launcher ?? "")} onChange={(event) => updateReportFilters({ command_launcher: event.target.value || null })} placeholder="remote-admin.exe" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Source</span>
                      <select value={String(reportFilters.command_source_type ?? "")} onChange={(event) => updateReportFilters({ command_source_type: event.target.value || null })} className="w-full bg-transparent outline-none">
                        <option value="">Any</option>
                        {["sysmon_1", "security_4688", "powershell_operational", "psreadline", "transcript", "scheduled_task", "prefetch"].map((value) => <option key={value} value={value}>{value}</option>)}
                      </select>
                    </label>
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Command risk min</span>
                      <input value={String(reportFilters.command_risk_min ?? "")} onChange={(event) => updateReportFilters({ command_risk_min: event.target.value || null })} placeholder="50" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Max commands</span>
                      <input value={String(reportFilters.max_commands ?? 50)} onChange={(event) => updateReportFilters({ max_commands: event.target.value || 50 })} className="w-full bg-transparent outline-none" />
                    </label>
                  </div>
                </div>

                {advancedFiltersOpen ? (
                  <div data-testid="advanced-report-filters" className="mt-4 grid gap-4 xl:grid-cols-3">
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Detection status</span>
                      <div className="flex flex-wrap gap-2">
                        {["new", "reviewed", "confirmed", "dismissed"].map((status) => (
                          <label key={status} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={(Array.isArray(reportFilters.detection_statuses) ? reportFilters.detection_statuses : []).map(String).includes(status)} onChange={(event) => setListFilter("detection_statuses", status, event.target.checked)} />{status}</label>
                        ))}
                      </div>
                    </label>
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Marked event status</span>
                      <div className="flex flex-wrap gap-2">
                        {["suspicious", "important", "reviewed", "false_positive"].map((status) => (
                          <label key={status} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={(Array.isArray(reportFilters.marking_statuses) ? reportFilters.marking_statuses : []).map(String).includes(status)} onChange={(event) => setListFilter("marking_statuses", status, event.target.checked)} />{status}</label>
                        ))}
                      </div>
                    </label>
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule name</span>
                      <input value={String(reportFilters.rule_name ?? "")} onChange={(event) => updateReportFilters({ rule_name: event.target.value || null })} placeholder="Sigma rule" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact type</span>
                      <input value={String(reportFilters.artifact_type ?? "")} onChange={(event) => updateReportFilters({ artifact_type: event.target.value || null })} placeholder="windows_event" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Parser</span>
                      <input value={String(reportFilters.parser ?? "")} onChange={(event) => updateReportFilters({ parser: event.target.value || null })} placeholder="evtxecmd_csv" className="w-full bg-transparent outline-none" />
                    </label>
                    <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source file</span>
                      <input value={String(reportFilters.source_file ?? "")} onChange={(event) => updateReportFilters({ source_file: event.target.value || null })} placeholder="Security.evtx" className="w-full bg-transparent outline-none" />
                    </label>
                  </div>
                ) : null}

                <div className="mt-4">
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Sections</p>
                  <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                    {Object.entries(currentReport.sections_enabled).map(([key, enabled]) => (
                      <label key={key} className="flex items-center gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                        <input
                          type="checkbox"
                          checked={enabled}
                          onChange={(event) =>
                            patchReport.mutate({ sections_enabled: { ...currentReport.sections_enabled, [key]: event.target.checked } })
                          }
                        />
                        {SECTION_LABELS[key] ?? key}
                      </label>
                    ))}
                  </div>
                </div>
              </section>

              <section className="grid gap-6 xl:grid-cols-[1fr_1fr]">
                <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Analyst notes</p>
                  <div className="mt-4 space-y-4">
                    <label className="block rounded-2xl border border-line bg-abyss/60 p-4 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Executive summary note</span>
                      <textarea value={executiveNote} onChange={(event) => setExecutiveNote(event.target.value)} rows={4} className="w-full resize-none bg-transparent outline-none" />
                    </label>
                    <label className="block rounded-2xl border border-line bg-abyss/60 p-4 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Recommendations note</span>
                      <textarea value={recommendationsNote} onChange={(event) => setRecommendationsNote(event.target.value)} rows={4} className="w-full resize-none bg-transparent outline-none" />
                    </label>
                    <label className="block rounded-2xl border border-line bg-abyss/60 p-4 text-sm">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Limitations</span>
                      <textarea value={limitationsNote} onChange={(event) => setLimitationsNote(event.target.value)} rows={3} className="w-full resize-none bg-transparent outline-none" />
                    </label>
                    <div className="flex flex-wrap gap-3">
                      <button
                        type="button"
                        onClick={() =>
                          patchReport.mutate({
                            analyst_notes: {
                              ...currentReport.analyst_notes,
                              executive_summary: executiveNote,
                              recommendations: recommendationsNote,
                              limitations: limitationsNote,
                            },
                          })
                        }
                        className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
                      >
                        Save draft
                      </button>
                      <button type="button" onClick={() => void previewQuery.refetch()} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                        Refresh preview
                      </button>
                    </div>
                  </div>
                </div>

                <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Selections</p>
                  <div className="mt-4 space-y-4">
                    <div>
                      <p className="text-sm font-semibold">Findings</p>
                      <div className="mt-2 max-h-52 space-y-2 overflow-y-auto pr-1">
                        {(findingsQuery.data ?? []).map((finding: Finding) => (
                          <label key={finding.id} className="flex items-start gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                            <input
                              type="checkbox"
                              checked={selectedFindingIds.has(finding.id)}
                              onChange={(event) => {
                                const next = new Set(currentReport.selected_finding_ids);
                                if (event.target.checked) next.add(finding.id);
                                else next.delete(finding.id);
                                patchReport.mutate({ selected_finding_ids: Array.from(next) });
                              }}
                            />
                            <span>
                              <span className="block text-ink">{finding.title}</span>
                              <span className="text-xs">{finding.severity} · {finding.status} · risk {finding.risk_score ?? 0}</span>
                            </span>
                          </label>
                        ))}
                        {!findingsQuery.data?.length ? <p className="text-sm text-muted">No findings available for this filter set.</p> : null}
                      </div>
                    </div>

                    <div>
                      <p className="text-sm font-semibold">Key events</p>
                      <div className="mt-2 max-h-52 space-y-2 overflow-y-auto pr-1">
                        {(keyEventsQuery.data ?? []).map((bookmark: TimelineBookmark) => (
                          <label key={bookmark.id} className="flex items-start gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                            <input
                              type="checkbox"
                              checked={selectedKeyEventIds.has(bookmark.id)}
                              onChange={(event) => {
                                const next = new Set(currentReport.selected_key_event_ids);
                                if (event.target.checked) next.add(bookmark.id);
                                else next.delete(bookmark.id);
                                patchReport.mutate({ selected_key_event_ids: Array.from(next) });
                              }}
                            />
                            <span>
                              <span className="block text-ink">{bookmark.title}</span>
                              <span className="text-xs">{bookmark.importance} · {bookmark.category}</span>
                            </span>
                          </label>
                        ))}
                        {!keyEventsQuery.data?.length ? <p className="text-sm text-muted">No key events available yet.</p> : null}
                      </div>
                    </div>

                    <div>
                      <p className="text-sm font-semibold">Process chains</p>
                      <div className="mt-2 max-h-44 space-y-2 overflow-y-auto pr-1">
                        {chainCandidates.map((finding) => (
                          <label key={finding.id} className="flex items-start gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2 text-sm text-muted">
                            <input
                              type="checkbox"
                              checked={(currentReport.selected_process_chain_ids ?? []).includes(finding.id)}
                              onChange={(event) => {
                                const next = new Set(currentReport.selected_process_chain_ids);
                                if (event.target.checked) next.add(finding.id);
                                else next.delete(finding.id);
                                patchReport.mutate({ selected_process_chain_ids: Array.from(next) });
                              }}
                            />
                            <span className="text-ink">{finding.title}</span>
                          </label>
                        ))}
                        {!chainCandidates.length ? <p className="text-sm text-muted">No process chain candidates available.</p> : null}
                      </div>
                    </div>
                  </div>
                </div>
              </section>

              <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Preview</p>
                    <p className="mt-2 text-sm text-muted">Safe Markdown preview generated from the current draft and selections.</p>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <button type="button" onClick={() => exportMarkdown.mutate()} disabled={!selectedReportId || exportMarkdown.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
                      {exportMarkdown.isPending ? "Generating Markdown..." : "Export Markdown"}
                    </button>
                    <button type="button" onClick={() => exportPdf.mutate()} disabled={!selectedReportId || exportPdf.isPending} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-50">
                      {exportPdf.isPending ? "Generating PDF..." : "Export PDF"}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        const content = (previewQuery.data?.sections ?? []).map((section) => `## ${section.title}\n\n${section.markdown}`).join("\n\n");
                        void navigator.clipboard.writeText(content);
                        setStatusTone("default");
                        setStatusMessage("Markdown copied to clipboard.");
                      }}
                      disabled={!previewQuery.data}
                      className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-50"
                    >
                      Copy Markdown
                    </button>
                  </div>
                </div>
                {previewQuery.data?.warnings?.length ? (
                  <div className="mt-4 rounded-2xl border border-amber-400/40 bg-amber-500/10 p-3 text-sm text-amber-100">
                    {previewQuery.data.warnings.join(" · ")}
                  </div>
                ) : null}
                <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="report-preview-counts">
                  {[
                    ["Findings", previewCounts.findings_matched ?? previewCounts.selected_findings ?? 0],
                    ["Detections", previewCounts.detections_matched ?? 0],
                    ["Marked events", previewCounts.marked_events_matched ?? 0],
                    ["Timeline events", previewCounts.timeline_events_matched ?? previewCounts.selected_key_events ?? 0],
                    ["Commands", previewCounts.command_history_matched ?? 0],
                    ["Suspicious commands", previewCounts.suspicious_commands_matched ?? 0],
                    ["Marked commands", previewCounts.marked_commands_matched ?? 0],
                    ["Execution stories", previewCounts.execution_stories_available ?? previewCounts.execution_stories_included ?? 0],
                    ["Incident timeline", previewCounts.incident_timeline_items ?? 0],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-2xl border border-line bg-abyss/60 px-4 py-3">
                      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
                      <p className="mt-2 text-2xl font-semibold text-ink">{String(value)}</p>
                    </div>
                  ))}
                </div>
                {previewQuery.data?.filters_applied && Object.keys(previewQuery.data.filters_applied).length ? (
                  <div data-testid="report-filters-applied" className="mt-3 rounded-2xl border border-line bg-abyss/50 p-3 text-xs text-muted">
                    Filters applied: {Object.entries(previewQuery.data.filters_applied).map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : String(value)}`).join(" · ")}
                  </div>
                ) : null}
                <div className="mt-4 space-y-4" data-testid="report-preview">
                  {previewQuery.data?.sections.map((section) => (
                    <article key={section.id} className="rounded-2xl border border-line bg-abyss/60 p-4">
                      <h3 className="text-lg font-semibold">{section.title}</h3>
                      {section.warnings.length ? <p className="mt-2 text-xs text-amber-200">{section.warnings.join(" · ")}</p> : null}
                      <pre className="mt-3 whitespace-pre-wrap break-words text-sm text-muted">{section.markdown}</pre>
                    </article>
                  ))}
                  {!previewQuery.data?.sections.length ? <p className="text-sm text-muted">Create a draft to generate the report preview.</p> : null}
                </div>
              </section>
            </>
          ) : (
            <section className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">
              Create a report draft to start building an investigation narrative for this case.
            </section>
          )}
        </div>
      </section>

      <DebugExportDialog
        open={debugExportOpen}
        onClose={() => setDebugExportOpen(false)}
        caseId={caseId}
        title="Export case debug pack"
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
            page: "CaseReportsPage",
            selected_case: caseId,
          },
        }}
      />
    </div>
  );
}
