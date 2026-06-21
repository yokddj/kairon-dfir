import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  type MemoryAnalysisCatalogue,
  type MemoryAnalysisCatalogueItem,
  type MemoryBackendStatus,
  type MemoryStartScanResponse,
  api,
} from "../../api/client";
import { backendBadge } from "../MemoryWorkspace";

type Props = {
  caseId: string;
  evidenceId: string;
  catalogue: MemoryAnalysisCatalogue;
  volatilityBackend: MemoryBackendStatus | null;
  canRun: boolean;
  onClose: () => void;
};

function familyHref(caseId: string, evidenceId: string, profile: MemoryAnalysisCatalogueItem): string {
  if (profile.family === "processes") return `/cases/${caseId}/memory/${evidenceId}?tab=processes`;
  if (profile.family === "system_info") return `/cases/${caseId}/memory/${evidenceId}?tab=system`;
  if (profile.family === "raw_observations") return `/cases/${caseId}/memory/${evidenceId}?tab=raw`;
  return `/cases/${caseId}/memory/${evidenceId}?tab=artifacts&artifact=${profile.family}`;
}

function CostLabel({ label }: { label: string }) {
  return (
    <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">{label}</span>
  );
}

function StatusBadge({ status, available, availabilityReason }: { status: string | null; available: boolean; availabilityReason: string | null }) {
  if (!available) {
    return (
      <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100" data-testid="catalogue-unavailable">
        Unavailable
      </span>
    );
  }
  if (!status) {
    return <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">Not run</span>;
  }
  switch (status) {
    case "completed":
      return <span className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-100">Completed</span>;
    case "completed_with_errors":
      return <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100">Completed with errors</span>;
    case "failed":
      return <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100">Failed</span>;
    case "running":
    case "queued":
    case "pending":
      return <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-100">Running</span>;
    default:
      return <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">{status}</span>;
  }
}

export function MemoryAnalysisCatalogueModal({ caseId, evidenceId, catalogue, volatilityBackend, canRun, onClose }: Props) {
  const queryClient = useQueryClient();
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startMutation = useMutation<MemoryStartScanResponse, Error, { profile: string }>({
    mutationFn: (vars) => api.startMemoryScan(evidenceId, vars.profile as never, true),
    onSuccess: (result) => {
      setFeedback(result.message);
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId, evidenceId] });
      queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId, evidenceId] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setFeedback(null);
    },
  });

  function handleRun(item: MemoryAnalysisCatalogueItem) {
    if (!window.confirm(
      "I confirm that I own this memory image or am explicitly authorized to analyze it, and I understand that RAM may contain sensitive personal or authentication data.",
    )) {
      return;
    }
    setError(null);
    setFeedback(null);
    startMutation.mutate({ profile: item.profile });
  }

  return (
    <div
      className="fixed inset-0 z-30 flex items-center justify-center bg-abyss/70 p-4"
      data-testid="memory-catalogue-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="memory-catalogue-title"
    >
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Run analysis</p>
            <h2 id="memory-catalogue-title" className="mt-1 text-2xl font-semibold">Available analysis profiles</h2>
            <p className="mt-1 max-w-2xl text-xs text-muted">
              Each profile runs against the selected authorized memory image using the externally configured Volatility 3 backend.
              Network profiles are unavailable when the installed runtime does not ship compatible Windows network plugins.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
            data-testid="memory-catalogue-close"
          >
            Close
          </button>
        </div>

        {volatilityBackend ? (
          <p className="mt-3 text-[10px] text-muted">
            Volatility 3: <span className="text-ink">{backendBadge(volatilityBackend)}</span>
          </p>
        ) : null}

        <div className="mt-4 space-y-3" data-testid="memory-catalogue-list">
          {catalogue.items.map((item: MemoryAnalysisCatalogueItem) => (
            <div
              key={item.profile}
              className="rounded-2xl border border-line bg-abyss/40 p-4"
              data-testid={`memory-catalogue-item-${item.profile}`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-semibold">{item.title}</h3>
                    <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
                      {item.profile}
                    </span>
                    <CostLabel label={item.cost_label} />
                    <StatusBadge status={item.last_status} available={item.available} availabilityReason={item.availability_reason} />
                  </div>
                  <p className="mt-1 text-xs text-muted">{item.description}</p>
                  {!item.available && item.availability_reason ? (
                    <p className="mt-2 text-[11px] text-rose-100" data-testid="catalogue-unavailable-reason">
                      {item.availability_reason}
                    </p>
                  ) : null}
                  <p className="mt-2 text-[10px] text-muted">
                    Estimated duration: ~{item.est_duration_seconds}s
                    {item.last_run ? (
                      <>
                        {" "}· last run {item.last_run.completed_at?.slice(0, 10) || item.last_run.started_at?.slice(0, 10) || "unknown"} ({item.last_count} artifacts)
                      </>
                    ) : null}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {item.last_run && item.available ? (
                    <Link
                      to={familyHref(caseId, evidenceId, item)}
                      className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
                      data-testid={`memory-catalogue-view-${item.profile}`}
                    >
                      View results
                    </Link>
                  ) : null}
                  <button
                    type="button"
                    onClick={() => handleRun(item)}
                    disabled={!item.available || !canRun || startMutation.isPending}
                    className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
                    data-testid={`memory-catalogue-run-${item.profile}`}
                  >
                    {item.last_run ? "Run again" : "Run"}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {feedback ? (
          <p className="mt-3 text-xs text-emerald-200" data-testid="memory-catalogue-feedback">{feedback}</p>
        ) : null}
        {error ? (
          <p className="mt-3 text-xs text-rose-200" data-testid="memory-catalogue-error">{error}</p>
        ) : null}
        {!canRun ? (
          <p className="mt-3 text-xs text-rose-200">
            {volatilityBackend?.message || "Volatility 3 is not ready for memory analysis."}
          </p>
        ) : null}
      </div>
    </div>
  );
}
