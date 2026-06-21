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
import { MemoryRunAllModal } from "./MemoryRunAllModal";

type Props = {
  caseId: string;
  evidenceId: string;
  evidenceFilename: string;
  evidenceHost: string | null;
  evidenceSizeBytes: number;
  catalogue: MemoryAnalysisCatalogue;
  volatilityBackend: MemoryBackendStatus | null;
  canRun: boolean;
  onClose: () => void;
};

type Section = "quick" | "artifacts" | "unavailable";

const SECTION_LABELS: Record<Section, string> = {
  quick: "Quick analysis",
  artifacts: "Memory artifacts",
  unavailable: "Unavailable",
};

const PROFILE_SECTION: Record<string, Section> = {
  metadata_only: "quick",
  processes_basic: "quick",
  processes_extended: "quick",
  network_basic: "unavailable",
  modules_basic: "artifacts",
  handles_basic: "artifacts",
  kernel_basic: "artifacts",
  suspicious_memory: "artifacts",
};

function familyHref(caseId: string, evidenceId: string, item: MemoryAnalysisCatalogueItem): string {
  if (item.family === "processes") return `/cases/${caseId}/memory/${evidenceId}?tab=processes`;
  if (item.family === "system_info") return `/cases/${caseId}/memory/${evidenceId}?tab=system`;
  if (item.family === "raw_observations") return `/cases/${caseId}/memory/${evidenceId}?tab=raw`;
  return `/cases/${caseId}/memory/${evidenceId}?tab=artifacts&artifact=${item.family}`;
}

function StatusBadge({
  status,
  available,
}: {
  status: string | null;
  available: boolean;
}) {
  if (!available) {
    return (
      <span
        className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100"
        data-testid="catalogue-unavailable"
      >
        Unavailable
      </span>
    );
  }
  if (!status) {
    return (
      <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted" data-testid="catalogue-not-run">
        Not run
      </span>
    );
  }
  switch (status) {
    case "completed":
    case "completed_with_errors":
      return (
        <span
          className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-100"
          data-testid="catalogue-completed"
        >
          Completed
        </span>
      );
    case "failed":
      return (
        <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100">
          Failed
        </span>
      );
    case "running":
    case "queued":
    case "pending":
      return (
        <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-100">
          Running
        </span>
      );
    default:
      return (
        <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
          {status}
        </span>
      );
  }
}

function CostLabel({ label }: { label: string }) {
  return (
    <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
      {label}
    </span>
  );
}

function PluginsLine({ plugins }: { plugins: string[] }) {
  if (plugins.length === 0) return null;
  return (
    <p className="mt-1 text-[10px] text-muted">
      Plugins: <span className="font-mono">{plugins.join(", ")}</span>
    </p>
  );
}

function CatalogueCard({
  caseId,
  evidenceId,
  item,
  canRun,
  isStarting,
  onRun,
}: {
  caseId: string;
  evidenceId: string;
  item: MemoryAnalysisCatalogueItem;
  canRun: boolean;
  isStarting: boolean;
  onRun: (item: MemoryAnalysisCatalogueItem) => void;
}) {
  const disabled = !item.available || !canRun || isStarting;
  if (!item.available) {
    return (
      <div
        className="rounded-2xl border border-rose-400/30 bg-rose-500/5 p-4 opacity-90"
        data-testid={`memory-catalogue-item-${item.profile}`}
        data-available="false"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold">{item.title}</h3>
              <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
                {item.profile}
              </span>
              <StatusBadge status={item.last_status} available={item.available} />
            </div>
            <p className="mt-1 text-xs text-muted">{item.description}</p>
            <p className="mt-2 text-[11px] text-rose-100" data-testid="catalogue-unavailable-reason">
              {item.availability_reason ?? "No compatible runtime is available for this profile."}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <button
              type="button"
              disabled
              aria-disabled="true"
              data-testid={`memory-catalogue-run-${item.profile}`}
              className="cursor-not-allowed rounded-xl border border-line bg-abyss/40 px-3 py-2 text-xs text-muted opacity-50"
            >
              Run
            </button>
            <Link
              to={`/cases/${caseId}/memory/${evidenceId}?tab=artifacts&artifact=${item.family}`}
              className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-[10px] text-muted"
              data-testid={`memory-catalogue-view-requirements-${item.profile}`}
            >
              View requirements
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const lastRunAt = item.last_run?.completed_at ?? item.last_run?.started_at ?? null;
  return (
    <div
      className="rounded-2xl border border-line bg-abyss/40 p-4"
      data-testid={`memory-catalogue-item-${item.profile}`}
      data-available="true"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold">{item.title}</h3>
            <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
              {item.profile}
            </span>
            <CostLabel label={item.cost_label} />
            <StatusBadge status={item.last_status} available={item.available} />
          </div>
          <p className="mt-1 text-xs text-muted">{item.description}</p>
          <p className="mt-1 text-[10px] text-muted" data-testid={`catalogue-est-duration-${item.profile}`}>
            Estimated duration: ~{item.est_duration_seconds}s
            {item.last_run ? (
              <>
                {" "}· last run {lastRunAt ? lastRunAt.slice(0, 10) : "unknown"} ({item.last_count.toLocaleString("en-US")} artifacts)
              </>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {item.last_run ? (
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
            onClick={() => onRun(item)}
            disabled={disabled}
            data-testid={`memory-catalogue-run-${item.profile}`}
            className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
          >
            {item.last_run ? "Run again" : "Run"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function MemoryAnalysisCatalogueModal({
  caseId,
  evidenceId,
  evidenceFilename,
  evidenceHost,
  evidenceSizeBytes,
  catalogue,
  volatilityBackend,
  canRun,
  onClose,
}: Props) {
  const queryClient = useQueryClient();
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [runAllOpen, setRunAllOpen] = useState(false);

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

  const sections: Section[] = ["quick", "artifacts", "unavailable"];
  const itemsBySection = sections.map((s) => ({
    section: s,
    items: catalogue.items.filter((it) => PROFILE_SECTION[it.profile] === s),
  }));

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
            <h2 id="memory-catalogue-title" className="mt-1 text-2xl font-semibold">
              Available analysis profiles
            </h2>
            <p className="mt-1 max-w-2xl text-xs text-muted">
              {evidenceFilename}
              {evidenceHost ? <> · Host {evidenceHost}</> : null}
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

        <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
          <p className="text-[10px] text-muted">
            Each profile runs against the selected authorized memory image using the externally configured Volatility 3 backend.
          </p>
          <button
            type="button"
            onClick={() => setRunAllOpen(true)}
            data-testid="memory-catalogue-run-all"
            className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
            disabled={!canRun || startMutation.isPending}
          >
            Run all supported profiles
          </button>
        </div>

        <div className="mt-4 space-y-5" data-testid="memory-catalogue-list">
          {itemsBySection.map(({ section, items }) => (
            <div key={section} data-testid={`memory-catalogue-section-${section}`}>
              <h3 className="text-[10px] uppercase tracking-[0.18em] text-muted">
                {SECTION_LABELS[section]}
              </h3>
              <div className="mt-2 space-y-2">
                {items.length === 0 ? (
                  <p className="text-[10px] text-muted">No profiles in this section.</p>
                ) : (
                  items.map((item) => (
                    <CatalogueCard
                      key={item.profile}
                      caseId={caseId}
                      evidenceId={evidenceId}
                      item={item}
                      canRun={canRun}
                      isStarting={startMutation.isPending}
                      onRun={handleRun}
                    />
                  ))
                )}
              </div>
            </div>
          ))}
        </div>

        {feedback ? (
          <p className="mt-3 text-xs text-emerald-200" data-testid="memory-catalogue-feedback">
            {feedback}
          </p>
        ) : null}
        {error ? (
          <p className="mt-3 text-xs text-rose-200" data-testid="memory-catalogue-error">
            {error}
          </p>
        ) : null}
        {!canRun ? (
          <p className="mt-3 text-xs text-rose-200" data-testid="memory-catalogue-blocked-reason">
            {volatilityBackend?.message || "Volatility 3 is not ready for memory analysis."}
          </p>
        ) : null}
      </div>

      {runAllOpen ? (
        <MemoryRunAllModal
          caseId={caseId}
          evidenceId={evidenceId}
          evidenceFilename={evidenceFilename}
          evidenceHost={evidenceHost}
          evidenceSizeBytes={evidenceSizeBytes}
          catalogue={catalogue}
          volatilityBackend={volatilityBackend}
          canRun={canRun}
          onClose={() => setRunAllOpen(false)}
          onCompleted={() => {
            setRunAllOpen(false);
            setFeedback("Run-all batch started.");
            queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId, evidenceId] });
            queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
            queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
            queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId, evidenceId] });
          }}
        />
      ) : null}
    </div>
  );
}
