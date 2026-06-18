import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type MemoryBackendStatus, type MemoryOverview } from "../api/client";
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

export default function MemoryAnalysisPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const backendQuery = useQuery({
    queryKey: ["memory-backends"],
    queryFn: () => api.getMemoryBackendOverview(),
    refetchOnWindowFocus: false,
  });

  const registerMutation = useMutation({
    mutationFn: (evidenceId: string) => api.startMemoryScan(evidenceId),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] }),
        queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId] }),
      ]);
    },
  });

  const overview = overviewQuery.data;

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
            <p className="mt-2 max-w-3xl text-sm text-muted">Isolated foundation for authorized memory evidence. This build does not execute external memory forensics tools or add RAM artifacts to global investigation sections.</p>
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
                <p className="mt-1 text-sm text-muted">Only authorized RAM evidence appears here. Registering analysis records metadata only in this build.</p>
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
                            disabled={!overview.memory_analysis_enabled || registerMutation.isPending}
                            onClick={() => registerMutation.mutate(evidence.id)}
                            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50"
                          >
                            Register memory analysis
                          </button>
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
                      <th className="px-4 py-3">Plugins</th>
                      <th className="px-4 py-3">Completed</th>
                      <th className="px-4 py-3">Failed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {overview.runs.map((run) => (
                      <tr key={run.id}>
                        <td className="px-4 py-3 text-ink">{run.status}</td>
                        <td className="px-4 py-3 text-muted">{run.backend || "none"}</td>
                        <td className="px-4 py-3 text-muted">{run.profile}</td>
                        <td className="px-4 py-3 text-muted">{run.created_at}</td>
                        <td className="px-4 py-3 text-muted">{run.plugin_count}</td>
                        <td className="px-4 py-3 text-muted">{run.plugins_completed}</td>
                        <td className="px-4 py-3 text-muted">{run.plugins_failed}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
