import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  type MemoryAnalysisBatch,
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
  readinessReady: boolean | null;
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
  gateType,
}: {
  status: string | null;
  available: boolean;
  gateType?: "available" | "blocked_symbol_probe_required" | "blocked_symbols_missing" | "blocked_acquisition_pending" | "unavailable";
}) {
  if (!available || gateType === "unavailable") {
    return (
      <span
        className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100"
        data-testid="catalogue-unavailable"
      >
        Unavailable
      </span>
    );
  }
  if (gateType && gateType.startsWith("blocked")) {
    const label = gateType === "blocked_symbol_probe_required"
      ? "Blocked — Probe required"
      : gateType === "blocked_symbols_missing"
        ? "Blocked — Symbols missing"
        : "Blocked — Acquisition pending";
    return (
      <span
        className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100"
        data-testid="catalogue-blocked"
        data-gate-type={gateType}
      >
        {label}
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
              <StatusBadge status={item.last_status} available={item.available} gateType={item.gate_type} />
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
            <StatusBadge status={item.last_status} available={item.available} gateType={item.gate_type} />
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

type AnalysisStage = "first" | "partial" | "completed" | "ready" | "default";

function detectAnalysisStage(catalogue: MemoryAnalysisCatalogue): AnalysisStage {
  const supported = catalogue.items.filter((it) => it.available);
  if (supported.length === 0) return "default";
  const completed = supported.filter((it) => it.last_status === "completed" || it.last_status === "completed_with_errors");
  if (completed.length === 0) return "first";
  if (completed.length === supported.length) return "completed";
  return "partial";
}

function FirstAnalysisView({
  caseId,
  evidenceId,
  catalogue,
  evidenceFilename,
  onClose,
  onStart,
  isStarting,
  error,
  canRun,
  readinessReady,
}: {
  caseId: string;
  evidenceId: string;
  catalogue: MemoryAnalysisCatalogue;
  evidenceFilename: string;
  onClose: () => void;
  onStart: () => void;
  isStarting: boolean;
  error: string | null;
  canRun: boolean;
  readinessReady: boolean;
}) {
  const supported = catalogue.items.filter((it) => it.available);
  const included = supported.filter((it) => it.profile !== "network_basic");
  const skipped = supported.filter((it) => it.profile === "network_basic");
  const disabled = !canRun || !readinessReady || isStarting;
  return (
    <div className="space-y-3" data-testid="memory-first-analysis">
      <p className="text-sm text-muted">
        This will queue the supported memory analysis profiles for this evidence.
      </p>
      <div className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs">
        <p className="font-mono uppercase tracking-[0.16em] text-mint">Included</p>
        <ul className="mt-1 list-disc pl-5 text-ink">
          {included.map((it) => (
            <li key={it.profile}>{it.title}</li>
          ))}
        </ul>
      </div>
      {skipped.length > 0 ? (
        <div className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs">
          <p className="font-mono uppercase tracking-[0.16em] text-muted">Skipped</p>
          <ul className="mt-1 list-disc pl-5 text-muted">
            {skipped.map((it) => (
              <li key={it.profile}>{it.title} — unavailable or not supported for this evidence</li>
            ))}
          </ul>
        </div>
      ) : null}
      <label className="mt-2 flex items-start gap-2 text-xs text-muted">
        <input
          type="checkbox"
          data-testid="memory-first-analysis-confirm"
          defaultChecked={false}
          className="mt-0.5 h-3.5 w-3.5"
        />
        <span>I confirm that I am authorized to analyze this memory evidence.</span>
      </label>
      {error ? <p className="text-xs text-rose-200" data-testid="memory-first-analysis-error">{error}</p> : null}
      <div className="mt-2 flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
          data-testid="memory-first-analysis-close"
        >
          Close
        </button>
        <button
          type="button"
          onClick={onStart}
          disabled={disabled}
          data-testid="memory-first-analysis-start"
          className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
        >
          {isStarting ? "Starting…" : "Start full memory analysis"}
        </button>
      </div>
    </div>
  );
}

function PartialAnalysisView({
  caseId,
  evidenceId,
  supported,
  completed,
  partialAvailable,
  hasActiveProfiles,
  feedback,
  error,
  canRun,
  readinessReady,
  isStarting,
  onClose,
  onStartMissing,
  onShowAdvanced,
  showAdvanced,
  itemsBySection,
  startMutation,
  onRunItem,
}: {
  caseId: string;
  evidenceId: string;
  catalogue?: MemoryAnalysisCatalogue;
  supported: MemoryAnalysisCatalogueItem[];
  completed: MemoryAnalysisCatalogueItem[];
  partialAvailable: MemoryAnalysisCatalogueItem[];
  hasActiveProfiles: boolean;
  feedback: string | null;
  error: string | null;
  canRun: boolean;
  readinessReady: boolean;
  isStarting: boolean;
  onClose: () => void;
  onStartMissing: () => void;
  onShowAdvanced: () => void;
  showAdvanced: boolean;
  itemsBySection: { section: Section; items: MemoryAnalysisCatalogueItem[] }[];
  startMutation: { isPending: boolean };
  onRunItem: (item: MemoryAnalysisCatalogueItem) => void;
}) {
  const disabled = !canRun || !readinessReady || isStarting || hasActiveProfiles || partialAvailable.length === 0;
  return (
    <div className="space-y-3" data-testid="memory-partial-analysis">
      <p className="text-sm text-muted">
        Runs only analyses that have never completed and are not already queued or running. Historical failed attempts are skipped unless you choose a re-run.
      </p>
      <div className="grid gap-2 md:grid-cols-3 text-xs">
        <Stat label="Completed" value={completed.length} />
        <Stat label="Pending" value={partialAvailable.length} />
        <Stat label="Total supported" value={supported.length} />
      </div>
      {feedback ? <p className="text-xs text-emerald-200" data-testid="memory-partial-feedback">{feedback}</p> : null}
      {partialAvailable.length === 0 && !hasActiveProfiles ? (
        <p className="text-xs text-mint" data-testid="memory-partial-noop">All available profiles have already been run.</p>
      ) : null}
      {hasActiveProfiles ? (
        <p className="text-xs text-amber-100" data-testid="memory-partial-active">A memory analysis profile is already queued or running.</p>
      ) : null}
      {error ? <p className="text-xs text-rose-200" data-testid="memory-partial-error">{error}</p> : null}
      <div className="mt-2 flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
          data-testid="memory-partial-close"
        >
          Close
        </button>
        <button
          type="button"
          onClick={onShowAdvanced}
          className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
          data-testid="memory-partial-advanced"
        >
          {showAdvanced ? "Hide advanced" : "Show advanced"}
        </button>
        <button
          type="button"
          onClick={onStartMissing}
          disabled={disabled}
          data-testid="memory-partial-start"
          className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
        >
          {isStarting ? "Starting…" : `Run ${partialAvailable.length} remaining profile${partialAvailable.length === 1 ? "" : "s"}`}
        </button>
      </div>
      {showAdvanced ? (
        <div className="mt-2 border-t border-line pt-3" data-testid="memory-partial-catalogue">
          <CatalogueListing
            caseId={caseId}
            evidenceId={evidenceId}
            itemsBySection={itemsBySection}
            canRun={canRun}
            isStarting={startMutation.isPending}
            onRunItem={onRunItem}
          />
        </div>
      ) : null}
    </div>
  );
}

function CompletedAnalysisView({
  caseId,
  evidenceId,
  supported,
  completed,
  feedback,
  error,
  canRun,
  readinessReady,
  isStarting,
  onClose,
  onRerun,
  showAdvanced,
  onShowAdvanced,
  itemsBySection,
  startMutation,
  onRunItem,
}: {
  caseId: string;
  evidenceId: string;
  catalogue?: MemoryAnalysisCatalogue;
  supported: MemoryAnalysisCatalogueItem[];
  completed: MemoryAnalysisCatalogueItem[];
  feedback: string | null;
  error: string | null;
  canRun: boolean;
  readinessReady: boolean;
  isStarting: boolean;
  onClose: () => void;
  onRerun: () => void;
  showAdvanced: boolean;
  onShowAdvanced: () => void;
  itemsBySection: { section: Section; items: MemoryAnalysisCatalogueItem[] }[];
  startMutation: { isPending: boolean };
  onRunItem: (item: MemoryAnalysisCatalogueItem) => void;
}) {
  return (
    <div className="space-y-3" data-testid="memory-completed-analysis">
      <p className="text-sm text-muted">
        All supported profiles for this evidence have completed.
      </p>
      <div className="grid gap-2 md:grid-cols-3 text-xs">
        <Stat label="Completed" value={completed.length} />
        <Stat label="Total supported" value={supported.length} />
      </div>
      {feedback ? <p className="text-xs text-emerald-200" data-testid="memory-completed-feedback">{feedback}</p> : null}
      {error ? <p className="text-xs text-rose-200" data-testid="memory-completed-error">{error}</p> : null}
      <div className="mt-2 flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
          data-testid="memory-completed-close"
        >
          Close
        </button>
        <button
          type="button"
          onClick={onShowAdvanced}
          className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
          data-testid="memory-completed-advanced"
        >
          {showAdvanced ? "Hide advanced" : "Show advanced"}
        </button>
        <button
          type="button"
          onClick={onRerun}
          disabled={!canRun || !readinessReady || isStarting}
          data-testid="memory-completed-rerun"
          className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
        >
          {isStarting ? "Starting…" : "Re-run analysis"}
        </button>
      </div>
      {showAdvanced ? (
        <div className="mt-2 border-t border-line pt-3" data-testid="memory-completed-catalogue">
          <CatalogueListing
            caseId={caseId}
            evidenceId={evidenceId}
            itemsBySection={itemsBySection}
            canRun={canRun}
            isStarting={startMutation.isPending}
            onRunItem={onRunItem}
          />
        </div>
      ) : null}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/60 px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink" data-testid={`memory-stat-${label.toLowerCase().replace(/\s+/g, "-")}`}>{value}</p>
    </div>
  );
}

function CatalogueListing({
  caseId,
  evidenceId,
  itemsBySection,
  canRun,
  isStarting,
  onRunItem,
}: {
  caseId: string;
  evidenceId: string;
  itemsBySection: { section: Section; items: MemoryAnalysisCatalogueItem[] }[];
  canRun: boolean;
  isStarting: boolean;
  onRunItem: (item: MemoryAnalysisCatalogueItem) => void;
}) {
  return (
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
                  isStarting={isStarting}
                  onRun={onRunItem}
                />
              ))
            )}
          </div>
        </div>
      ))}
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
  readinessReady,
}: Props) {
  const queryClient = useQueryClient();
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [runAllOpen, setRunAllOpen] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const startMutation = useMutation<MemoryStartScanResponse, Error, { profile: string }>({
    mutationFn: (vars) => api.startMemoryScan(caseId, evidenceId, vars.profile as never, true),
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

  const startAllMissing = useMutation<MemoryAnalysisBatch, Error, void>({
    mutationFn: () => api.startMemoryRunAll(caseId, evidenceId, {
      mode: "missing_or_failed",
      authorization_acknowledged: true,
      continue_on_failure: true,
    }),
    onSuccess: (batch) => {
      const queuedCount = batch.requested_profiles?.length ?? 0;
      setFeedback(queuedCount > 0 ? `Queued ${queuedCount} memory analysis profile${queuedCount === 1 ? "" : "s"}.` : batch.message || "All available profiles have already been run.");
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId, evidenceId] });
      queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId, evidenceId] });
      queryClient.invalidateQueries({ queryKey: ["memory-active-batch", caseId, evidenceId] });
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

  const stage = detectAnalysisStage(catalogue);
  const supported = catalogue.items.filter((it) => it.available);
  const completed = supported.filter(
    (it) => it.last_status === "completed" || it.last_status === "completed_with_errors",
  );
  const activeAvailable = supported.filter(
    (it) => it.last_status === "pending" || it.last_status === "queued" || it.last_status === "running",
  );
  const partialAvailable = supported.filter(
    (it) => !it.last_status,
  );

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
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">
              {stage === "first" ? "Analyze memory" : stage === "partial" ? "Complete analysis" : "Memory analysis"}
            </p>
            <h2 id="memory-catalogue-title" className="mt-1 text-2xl font-semibold">
              {stage === "first"
                ? "Analyze memory"
                : stage === "partial"
                  ? "Complete memory analysis"
                  : "Memory analysis catalogue"}
            </h2>
            <p className="mt-1 max-w-2xl text-xs text-muted">
              {evidenceFilename}
              {evidenceHost ? <> · Host {evidenceHost}</> : null}
            </p>
            {stage !== "first" ? (
              <p className="mt-1 text-[10px] text-muted" data-testid="memory-catalogue-progress">
                {completed.length} of {supported.length} supported profiles completed
                {partialAvailable.length > 0 ? ` · ${partialAvailable.length} remaining` : ""}
              </p>
            ) : null}
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

        {stage === "first" ? (
          <FirstAnalysisView
            caseId={caseId}
            evidenceId={evidenceId}
            catalogue={catalogue}
            evidenceFilename={evidenceFilename}
            onClose={onClose}
            onStart={() => startAllMissing.mutate()}
            isStarting={startAllMissing.isPending}
            error={error}
            canRun={canRun}
            readinessReady={readinessReady ?? true}
          />
        ) : stage === "partial" ? (
          <PartialAnalysisView
            caseId={caseId}
            evidenceId={evidenceId}
            catalogue={catalogue}
            supported={supported}
            completed={completed}
            partialAvailable={partialAvailable}
            hasActiveProfiles={activeAvailable.length > 0}
            feedback={feedback}
            error={error}
            canRun={canRun}
            readinessReady={readinessReady ?? true}
            isStarting={startAllMissing.isPending}
            onClose={onClose}
            onStartMissing={() => startAllMissing.mutate()}
            onShowAdvanced={() => setShowAdvanced(true)}
            showAdvanced={showAdvanced}
            itemsBySection={itemsBySection}
            startMutation={startMutation}
            onRunItem={handleRun}
          />
        ) : stage === "completed" ? (
          <CompletedAnalysisView
            caseId={caseId}
            evidenceId={evidenceId}
            catalogue={catalogue}
            supported={supported}
            completed={completed}
            feedback={feedback}
            error={error}
            canRun={canRun}
            readinessReady={readinessReady ?? true}
            isStarting={startAllMissing.isPending}
            onClose={onClose}
            onRerun={() => setRunAllOpen(true)}
            showAdvanced={showAdvanced}
            onShowAdvanced={() => setShowAdvanced(true)}
            itemsBySection={itemsBySection}
            startMutation={startMutation}
            onRunItem={handleRun}
          />
        ) : null}

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
    </div>
  );
}
