import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { type MemoryScanRun, api } from "../../api/client";

type Props = {
  caseId: string;
  evidenceId: string;
  family: string;
  onClose: () => void;
  onSelectRun: (runId: string) => void;
  onReturnToLatest: () => void;
  selectedRunId: string | null;
};

function statusLabel(status: string): string {
  switch (status) {
    case "completed":
      return "Completed";
    case "completed_with_errors":
      return "Completed with errors";
    case "failed":
      return "Failed";
    case "running":
      return "Running";
    case "queued":
      return "Queued";
    case "pending":
      return "Pending";
    case "disabled":
      return "Disabled";
    default:
      return status;
  }
}

function statusTone(status: string): string {
  switch (status) {
    case "completed":
      return "border-emerald-400/30 bg-emerald-500/10 text-emerald-100";
    case "completed_with_errors":
      return "border-amber-400/30 bg-amber-500/10 text-amber-100";
    case "failed":
      return "border-rose-400/30 bg-rose-500/10 text-rose-100";
    case "running":
    case "queued":
    case "pending":
      return "border-sky-400/30 bg-sky-500/10 text-sky-100";
    default:
      return "border-line bg-abyss/70 text-muted";
  }
}

export function MemoryHistoryPanel({
  caseId,
  evidenceId,
  family,
  onClose,
  onSelectRun,
  onReturnToLatest,
  selectedRunId,
}: Props) {
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const runsQuery = useQuery<MemoryScanRun[]>({
    queryKey: ["memory-history-runs", caseId, evidenceId, family],
    queryFn: () => api.listMemoryRuns(caseId, evidenceId),
    refetchOnWindowFocus: false,
  });

  const runs = (runsQuery.data || []).filter((run) => _profileMatchesFamily(run.profile, family));
  const total = runs.length;
  const start = (page - 1) * pageSize;
  const end = start + pageSize;
  const pageItems = runs.slice(start, end);

  return (
    <div
      className="fixed inset-0 z-30 flex items-center justify-center bg-abyss/70 p-4"
      data-testid="memory-history-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="memory-history-title"
    >
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Analysis history</p>
            <h2 id="memory-history-title" className="mt-1 text-2xl font-semibold">{_familyLabel(family)}</h2>
            <p className="mt-1 max-w-2xl text-xs text-muted">
              Showing every analysis run for this evidence + family. Selecting a row switches the current view to a historical
              result; the active result for other families is unchanged.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {selectedRunId ? (
              <button
                type="button"
                onClick={onReturnToLatest}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
                data-testid="memory-history-return-to-latest"
              >
                Return to Latest successful
              </button>
            ) : null}
            <Link
              to={`/cases/${caseId}/memory/${evidenceId}`}
              onClick={onClose}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
              data-testid="memory-history-close"
            >
              Close
            </Link>
          </div>
        </div>

        {runsQuery.isLoading ? (
          <p className="mt-4 text-xs text-muted">Loading analysis history...</p>
        ) : total === 0 ? (
          <p className="mt-4 text-xs text-muted" data-testid="memory-history-empty">No previous runs for this family.</p>
        ) : (
          <>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-muted">
                    <th className="py-1 pr-2">Started</th>
                    <th className="py-1 pr-2">Completed</th>
                    <th className="py-1 pr-2">Profile</th>
                    <th className="py-1 pr-2">Status</th>
                    <th className="py-1 pr-2">Plugins</th>
                    <th className="py-1 pr-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((run) => (
                    <tr key={run.id} className="border-t border-line">
                      <td className="py-1 pr-2 font-mono">{run.started_at?.slice(0, 19).replace("T", " ") || run.created_at.slice(0, 19).replace("T", " ")}</td>
                      <td className="py-1 pr-2 font-mono">{run.completed_at?.slice(0, 19).replace("T", " ") || "—"}</td>
                      <td className="py-1 pr-2">{run.profile}</td>
                      <td className="py-1 pr-2">
                        <span className={`rounded-md border px-2 py-0.5 text-[10px] ${statusTone(run.status)}`}>
                          {statusLabel(run.status)}
                        </span>
                      </td>
                      <td className="py-1 pr-2 font-mono">
                        {run.plugins_completed ?? 0}/{run.plugin_count ?? 0}
                      </td>
                      <td className="py-1 pr-2">
                        <button
                          type="button"
                          onClick={() => {
                            onSelectRun(run.id);
                          }}
                          className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
                          data-testid={`memory-history-select-${run.id}`}
                        >
                          View as historical
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[10px] text-muted">
              <span>{total} run{total === 1 ? "" : "s"} for this family</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={page === 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 disabled:opacity-50"
                  data-testid="memory-history-prev"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={end >= total}
                  onClick={() => setPage((p) => p + 1)}
                  className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 disabled:opacity-50"
                  data-testid="memory-history-next"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function _profileMatchesFamily(profile: string, family: string): boolean {
  if (family === "processes") return profile === "processes_basic" || profile === "processes_extended";
  if (family === "system_info") return profile === "metadata_only";
  if (family === "network") return profile === "network_basic";
  if (family === "modules") return profile === "modules_basic";
  if (family === "handles") return profile === "handles_basic";
  if (family === "kernel_modules" || family === "drivers") return profile === "kernel_basic";
  if (family === "suspicious_regions") return profile === "suspicious_memory";
  return false;
}

function _familyLabel(family: string): string {
  return {
    system_info: "System metadata history",
    processes: "Processes history",
    network: "Network connections history",
    modules: "Process modules history",
    handles: "Process handles history",
    kernel_modules: "Kernel modules history",
    drivers: "Drivers history",
    suspicious_regions: "Suspicious memory regions history",
  }[family] || `${family} history`;
}
