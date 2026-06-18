import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type MemoryBackendStatus, type MemoryOverview, type MemoryProcess, type MemorySystemInfo } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

function modeLabel(mode: MemoryOverview["mode"]) {
  switch (mode) {
    case "disk_only":
      return "Disk only";
    case "memory_only":
      return "Memory only";
    case "hybrid":
      return "Disk and memory";
    default:
      return "Empty case";
  }
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function backendBadge(status: MemoryBackendStatus) {
  if (status.ready) return "Ready";
  switch (status.status) {
    case "disabled":
      return "Disabled";
    case "not_configured":
      return "Not configured";
    case "blocked":
      return status.available ? "Installed but blocked" : "Blocked";
    case "not_found":
      return "Not found";
    case "available":
      return "Available";
    case "check_failed":
      return "Check failed";
    default:
      return status.status;
  }
}

const ACTIVE_RUN_STATUSES = new Set(["pending", "queued", "running"]);

function reported(value: unknown) {
  if (value === null || value === undefined || value === "") return "Not reported";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function durationLabel(value: number | null | undefined) {
  if (!value) return "Not reported";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function SystemInformation({ item }: { item: MemorySystemInfo }) {
  const fields: Array<[string, unknown]> = [
    ["OS family", item.os.family],
    ["Kernel base", item.os.kernel_base],
    ["Kernel version", item.os.kernel_version],
    ["Architecture", item.os.machine_type],
    ["Memory layer", item.memory.layer_name],
    ["DTB", item.memory.dtb],
    ["Symbol table", item.memory.kernel_symbols],
    ["System time", item.memory.system_time],
  ];
  return (
    <article className="rounded-2xl border border-line bg-abyss/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h4 className="font-semibold">windows.info</h4>
          <p className="mt-1 text-xs text-muted">Backend: {item.backend}</p>
        </div>
        <span className="rounded-xl border border-line bg-panel/70 px-3 py-1 text-xs text-muted">memory_system_info</span>
      </div>
      <dl className="mt-4 grid gap-3 md:grid-cols-2 text-sm">
        {fields.map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs uppercase tracking-[0.14em] text-muted">{label}</dt>
            <dd className="mt-1 break-words text-ink">{reported(value)}</dd>
          </div>
        ))}
      </dl>
    </article>
  );
}

function sourceBadges(item: MemoryProcess) {
  return (item.plugins || []).map((plugin) => plugin.replace("windows.", ""));
}

function stateLabel(item: MemoryProcess) {
  if (item.state?.terminated_candidate) return "Exited time reported";
  if (item.visibility?.psscan && !item.visibility?.pslist) return "Not present in pslist result";
  return "Listed";
}

export default function MemoryAnalysisPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const queryClient = useQueryClient();
  const [processPage, setProcessPage] = useState(1);
  const [processName, setProcessName] = useState("");

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => (query.state.data?.runs.some((run) => ACTIVE_RUN_STATUSES.has(run.status)) ? 3000 : false),
  });

  const backendQuery = useQuery({
    queryKey: ["memory-backends"],
    queryFn: () => api.getMemoryBackendOverview(),
    refetchOnWindowFocus: false,
  });

  const systemInfoQuery = useQuery({
    queryKey: ["memory-system-info", caseId],
    queryFn: () => api.getCaseMemorySystemInfo(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    refetchInterval: overviewQuery.data?.runs.some((run) => ACTIVE_RUN_STATUSES.has(run.status)) ? 3000 : false,
  });

  const latestProcessRun = overviewQuery.data?.runs.find((run) => run.profile === "processes_extended" || run.profile === "processes_basic");

  const processQuery = useQuery({
    queryKey: ["memory-processes", caseId, latestProcessRun?.id, processPage, processName],
    queryFn: () => api.getCaseMemoryProcesses(caseId, { run_id: latestProcessRun?.id, page: processPage, page_size: 50, process_name: processName || undefined }),
    enabled: Boolean(caseId && latestProcessRun?.id),
    refetchOnWindowFocus: false,
  });

  const processTreeQuery = useQuery({
    queryKey: ["memory-process-tree", latestProcessRun?.id],
    queryFn: () => api.getMemoryProcessTree(latestProcessRun!.id),
    enabled: Boolean(latestProcessRun?.id),
    refetchOnWindowFocus: false,
  });

  const registerMutation = useMutation({
    mutationFn: ({ evidenceId, profile }: { evidenceId: string; profile: "metadata_only" | "processes_basic" | "processes_extended" }) => api.startMemoryScan(evidenceId, profile),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] }),
        queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId] }),
        queryClient.invalidateQueries({ queryKey: ["memory-system-info", caseId] }),
        queryClient.invalidateQueries({ queryKey: ["memory-processes", caseId] }),
        queryClient.invalidateQueries({ queryKey: ["memory-process-tree"] }),
      ]);
    },
  });

  const overview = overviewQuery.data;
  const volatilityBackend = backendQuery.data?.backends.find((backend) => backend.backend === "volatility3");
  const canRunMetadata = Boolean(overview?.memory_analysis_enabled && volatilityBackend?.ready);
  const canRunProcessProfiles = Boolean(canRunMetadata && overview?.memory_process_profile_enabled);

  function runAnalysis(evidenceId: string, profile: "metadata_only" | "processes_basic" | "processes_extended") {
    const copy =
      profile === "processes_basic"
        ? "This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info, windows.pslist, windows.pstree, and windows.cmdline plugins."
        : profile === "processes_extended"
          ? "This also runs windows.psscan, which may return additional process structures requiring analyst interpretation."
          : "This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info metadata plugin.";
    const confirmed = window.confirm(copy);
    if (confirmed) registerMutation.mutate({ evidenceId, profile });
  }

  function runMetadataAnalysis(evidenceId: string) {
    const confirmed = window.confirm("This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info metadata plugin.");
    if (confirmed) registerMutation.mutate({ evidenceId, profile: "metadata_only" });
  }

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory Analysis</p>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-3xl font-semibold">Authorized RAM evidence</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">Isolated analysis for authorized memory evidence. Process results remain only in Memory Analysis and never enter global disk views.</p>
          </div>
          <Link to={`/cases/${caseId}/evidence`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Evidence &amp; Ingest</Link>
        </div>
      </section>

      {overviewQuery.isLoading ? <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">Loading memory overview...</section> : null}
      {overviewQuery.error instanceof Error ? <section className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-5 text-sm text-rose-100">{overviewQuery.error.message}</section> : null}

      <section className="rounded-[28px] border border-line bg-panel/60 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold">Memory backends</h3>
            <p className="mt-1 text-sm text-muted">
              Backend readiness checks only confirm configured external tools. They do not analyze RAM evidence.
            </p>
          </div>
          {backendQuery.data ? (
            <span className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">
              Ready backends: {backendQuery.data.ready_backend_count}
            </span>
          ) : null}
        </div>
        {backendQuery.isLoading ? <p className="mt-4 text-sm text-muted">Loading backend readiness...</p> : null}
        {backendQuery.error instanceof Error ? <p className="mt-4 text-sm text-rose-200">{backendQuery.error.message}</p> : null}
        {backendQuery.data ? (
          <>
            <p className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">{backendQuery.data.message}</p>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              {backendQuery.data.backends.map((backend) => (
                <article key={backend.backend} className="rounded-2xl border border-line bg-abyss/60 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h4 className="font-semibold">{backend.display_name}</h4>
                      <p className="mt-1 text-xs text-muted">{backend.command_display ? `Command: ${backend.command_display}` : "Command: none"}</p>
                    </div>
                    <span className="rounded-xl border border-line bg-panel/70 px-3 py-1 text-xs text-muted">{backendBadge(backend)}</span>
                  </div>
                  <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <dt className="text-xs uppercase tracking-[0.14em] text-muted">Configured</dt>
                      <dd className="mt-1 text-ink">{backend.configured ? "Yes" : "No"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-[0.14em] text-muted">Executable detected</dt>
                      <dd className="mt-1 text-ink">{backend.executable_found ? "Yes" : "No"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-[0.14em] text-muted">Execution allowed</dt>
                      <dd className="mt-1 text-ink">{backend.execution_allowed ? "Yes" : "No"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-[0.14em] text-muted">Version</dt>
                      <dd className="mt-1 text-ink">{backend.version || "Unknown"}</dd>
                    </div>
                  </dl>
                  <p className="mt-4 text-sm text-muted">{backend.message}</p>
                </article>
              ))}
            </div>
          </>
        ) : null}
      </section>

      {overview ? (
        <>
          <section className="grid gap-3 md:grid-cols-4">
            <div className="rounded-2xl border border-line bg-panel/60 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-muted">Mode</p>
              <p className="mt-1 text-xl font-semibold">{modeLabel(overview.mode)}</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/60 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-muted">Memory evidence</p>
              <p className="mt-1 text-2xl font-semibold">{overview.evidences.length}</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/60 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-muted">Runs</p>
              <p className="mt-1 text-2xl font-semibold">{overview.runs.length}</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/60 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-muted">Disk events</p>
              <p className="mt-1 text-xl font-semibold">{overview.has_disk_events ? "Present" : "None"}</p>
            </div>
          </section>

          {!overview.memory_analysis_enabled ? (
            <section className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-5 text-sm text-amber-100">
              Memory Analysis is currently disabled. Kairon can still work with disk artifacts only. Enable memory analysis in backend configuration when you are ready to analyze authorized RAM evidence.
            </section>
          ) : null}

          <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">{overview.message}</section>

          {!overview.evidences.length ? (
            <section className="rounded-[28px] border border-line bg-panel/60 p-6">
              <h3 className="text-lg font-semibold">No memory evidence found for this case</h3>
              <p className="mt-2 text-sm text-muted">Kairon can work with disk artifacts only, memory artifacts only, or both.</p>
            </section>
          ) : (
            <section className="overflow-hidden rounded-[28px] border border-line bg-panel/60">
              <div className="border-b border-line px-5 py-4">
                <h3 className="text-lg font-semibold">Memory evidence</h3>
                <p className="mt-1 text-sm text-muted">Only authorized RAM evidence appears here. Metadata analysis remains isolated from global disk views.</p>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-line text-sm">
                  <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                    <tr>
                      <th className="px-4 py-3">Evidence</th>
                      <th className="px-4 py-3">Size</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Created</th>
                      <th className="px-4 py-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {overview.evidences.map((evidence) => (
                      <tr key={evidence.id}>
                        <td className="px-4 py-3 font-medium text-ink">{evidence.original_filename}</td>
                        <td className="px-4 py-3 text-muted">{formatBytes(evidence.size_bytes)}</td>
                        <td className="px-4 py-3 text-muted">{evidence.ingest_status}</td>
                        <td className="px-4 py-3 text-muted">{evidence.created_at}</td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            disabled={!canRunMetadata || registerMutation.isPending}
                            onClick={() => runMetadataAnalysis(evidence.id)}
                            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50"
                          >
                            Run metadata analysis
                          </button>
                          <div className="mt-2 flex flex-wrap gap-2">
                            <button type="button" disabled={!canRunProcessProfiles || registerMutation.isPending} onClick={() => runAnalysis(evidence.id, "processes_basic")} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Run basic process analysis</button>
                            <button type="button" disabled={!canRunProcessProfiles || registerMutation.isPending} onClick={() => runAnalysis(evidence.id, "processes_extended")} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Run extended process analysis</button>
                          </div>
                          {!canRunMetadata ? <p className="mt-2 max-w-48 text-xs text-muted">{volatilityBackend?.message || "Volatility 3 is not ready for memory metadata analysis."}</p> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {registerMutation.data ? <p className="border-t border-line px-5 py-3 text-sm text-muted">{registerMutation.data.message}</p> : null}
              {registerMutation.error instanceof Error ? <p className="border-t border-line px-5 py-3 text-sm text-rose-200">{registerMutation.error.message}</p> : null}
            </section>
          )}

          {overview.runs.length ? (
            <section className="overflow-hidden rounded-[28px] border border-line bg-panel/60">
              <div className="border-b border-line px-5 py-4">
                <h3 className="text-lg font-semibold">Memory runs</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-line text-sm">
                  <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                    <tr>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Backend</th>
                      <th className="px-4 py-3">Profile</th>
                      <th className="px-4 py-3">Created</th>
                      <th className="px-4 py-3">Duration</th>
                      <th className="px-4 py-3">Version</th>
                      <th className="px-4 py-3">Plugins</th>
                      <th className="px-4 py-3">Completed</th>
                      <th className="px-4 py-3">Failed</th>
                      <th className="px-4 py-3">Error</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {overview.runs.map((run) => (
                      <tr key={run.id}>
                        <td className="px-4 py-3 text-ink">{run.status}</td>
                        <td className="px-4 py-3 text-muted">{run.backend || "none"}</td>
                        <td className="px-4 py-3 text-muted">{run.profile}</td>
                        <td className="px-4 py-3 text-muted">{run.created_at}</td>
                        <td className="px-4 py-3 text-muted">{durationLabel(run.duration_ms)}</td>
                        <td className="px-4 py-3 text-muted">{run.backend_version || "Not reported"}</td>
                        <td className="px-4 py-3 text-muted">{run.plugin_count}</td>
                        <td className="px-4 py-3 text-muted">{run.plugins_completed}</td>
                        <td className="px-4 py-3 text-muted">{run.plugins_failed}</td>
                        <td className="px-4 py-3 text-muted">{typeof run.error_log?.message === "string" ? run.error_log.message : "None"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          <section className="rounded-[28px] border border-line bg-panel/60 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold">System information</h3>
                <p className="mt-1 text-sm text-muted">Normalized metadata from completed windows.info runs only.</p>
              </div>
              {systemInfoQuery.data ? <span className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">{systemInfoQuery.data.length} result{systemInfoQuery.data.length === 1 ? "" : "s"}</span> : null}
            </div>
            {systemInfoQuery.isLoading ? <p className="mt-4 text-sm text-muted">Loading system information...</p> : null}
            {systemInfoQuery.error instanceof Error ? <p className="mt-4 text-sm text-rose-200">{systemInfoQuery.error.message}</p> : null}
            {systemInfoQuery.data?.length ? (
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                {systemInfoQuery.data.map((item) => (
                  <SystemInformation key={item.memory_plugin_run_id} item={item} />
                ))}
              </div>
            ) : !systemInfoQuery.isLoading ? (
              <p className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No memory system information has been reported.</p>
            ) : null}
          </section>

          <section className="rounded-[28px] border border-line bg-panel/60 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold">Processes</h3>
                <p className="mt-1 text-sm text-muted">Isolated Volatility process results. Neutral labels require analyst interpretation.</p>
              </div>
              {processQuery.data ? <span className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">{processQuery.data.total} processes</span> : null}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <input value={processName} onChange={(event) => { setProcessName(event.target.value); setProcessPage(1); }} placeholder="Filter by name" className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm outline-none" />
            </div>
            {processQuery.error instanceof Error ? <p className="mt-4 text-sm text-rose-200">{processQuery.error.message}</p> : null}
            {processQuery.data?.items.length ? (
              <div className="mt-4 overflow-x-auto">
                <table className="min-w-full divide-y divide-line text-sm">
                  <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                    <tr><th className="px-4 py-3">PID</th><th className="px-4 py-3">PPID</th><th className="px-4 py-3">Name</th><th className="px-4 py-3">Command line</th><th className="px-4 py-3">Created</th><th className="px-4 py-3">Exited</th><th className="px-4 py-3">Sources</th><th className="px-4 py-3">State</th></tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {processQuery.data.items.map((item) => (
                      <tr key={item.document_id || `${item.memory_run_id}-${item.process.pid}`}>
                        <td className="px-4 py-3 text-ink">{reported(item.process.pid)}</td>
                        <td className="px-4 py-3 text-muted">{reported(item.process.ppid)}</td>
                        <td className="px-4 py-3 text-ink">{reported(item.process.name)}</td>
                        <td className="max-w-xl truncate px-4 py-3 text-muted" title={reported(item.process.command_line)}>{reported(item.process.command_line)}</td>
                        <td className="px-4 py-3 text-muted">{reported(item.process.create_time)}</td>
                        <td className="px-4 py-3 text-muted">{reported(item.process.exit_time)}</td>
                        <td className="px-4 py-3 text-muted">{sourceBadges(item).join(", ") || "Not reported"}</td>
                        <td className="px-4 py-3 text-muted">{stateLabel(item)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="flex justify-end gap-2 border-t border-line p-3">
                  <button disabled={processPage <= 1} onClick={() => setProcessPage((page) => Math.max(1, page - 1))} className="rounded-xl border border-line px-3 py-2 text-xs disabled:opacity-50">Previous</button>
                  <button disabled={processQuery.data.items.length < processQuery.data.page_size} onClick={() => setProcessPage((page) => page + 1)} className="rounded-xl border border-line px-3 py-2 text-xs disabled:opacity-50">Next</button>
                </div>
              </div>
            ) : (
              <p className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No memory process results have been reported.</p>
            )}
          </section>

          <section className="rounded-[28px] border border-line bg-panel/60 p-5">
            <h3 className="text-lg font-semibold">Process tree</h3>
            {processTreeQuery.data && processTreeQuery.data.total_process_count > 200 ? <p className="mt-3 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">This result is too large for full graph rendering; use the process table and filters.</p> : null}
            {processTreeQuery.data ? (
              <div className="mt-4 space-y-2 text-sm">
                <p className="text-muted">Roots: {processTreeQuery.data.root_count} · Orphans: {processTreeQuery.data.orphan_count} · Sources: {processTreeQuery.data.source_plugins.map((plugin) => plugin.replace("windows.", "")).join(", ") || "Not reported"}</p>
                {processTreeQuery.data.nodes.slice(0, 200).map((item) => (
                  <div key={item.document_id || `${item.memory_run_id}-${item.process.pid}`} className="rounded-xl border border-line bg-abyss/60 px-3 py-2">
                    <span className="font-mono text-xs text-muted">PID {reported(item.process.pid)} PPID {reported(item.process.ppid)}</span>
                    <span className="ml-3 text-ink">{reported(item.process.name)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No isolated memory process tree is available.</p>
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}
