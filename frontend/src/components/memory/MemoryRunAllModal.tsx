import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type MemoryAnalysisBatch,
  type MemoryAnalysisCatalogue,
  type MemoryBackendStatus,
  type MemoryRunAllMode,
  type MemoryRunAllPlan,
  api,
} from "../../api/client";

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
  onCompleted: () => void;
};

const MODE_MISSING = "missing_or_failed" as const;
const MODE_RERUN = "rerun_all" as const;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KiB`;
  return `${bytes} B`;
}

const PROFILE_TITLE: Record<string, string> = {
  metadata_only: "System metadata",
  processes_extended: "Extended process analysis",
  modules_basic: "Modules and DLLs",
  handles_basic: "Handles",
  kernel_basic: "Kernel modules and drivers",
  suspicious_memory: "Suspicious memory regions",
};

const HIGH_VOLUME_PROFILES = new Set(["handles_basic"]);
const SLOW_PROFILES = new Set(["suspicious_memory"]);

export function MemoryRunAllModal({
  caseId,
  evidenceId,
  evidenceFilename,
  evidenceHost,
  evidenceSizeBytes,
  catalogue,
  volatilityBackend,
  canRun,
  onClose,
  onCompleted,
}: Props) {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<MemoryRunAllMode>(MODE_MISSING);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [started, setStarted] = useState(false);

  const planQuery = useQuery({
    queryKey: ["memory-run-all-plan", caseId, evidenceId, mode],
    queryFn: () => api.previewMemoryRunAll(caseId, evidenceId, mode),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const plan: MemoryRunAllPlan | undefined = planQuery.data;

  const startMutation = useMutation<MemoryAnalysisBatch, Error>({
    mutationFn: () =>
      api.startMemoryRunAll(caseId, evidenceId, {
        mode,
        authorization_acknowledged: true,
        continue_on_failure: true,
      }),
    onSuccess: () => {
      setStarted(true);
      queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId, evidenceId] });
      queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId, evidenceId] });
      onCompleted();
    },
    onError: (err: Error & { errorCode?: string; detail?: unknown }) => {
      // Surface the structured blocker when the backend refused
      // because the exact Windows symbol is not cached.  The detail
      // payload includes the symbol_status, required_identifier
      // and a "can_acquire" flag.
      const code = (err as Error & { errorCode?: string }).errorCode;
      if (code === "MEMORY_SYMBOLS_REQUIRED") {
        const detail = (err as Error & { detail?: Record<string, unknown> }).detail || {};
        setError(
          (detail["message"] as string | undefined) ||
            "Windows symbols required for this evidence are not cached.",
        );
      } else {
        setError(err.message);
      }
    },
  });

  const totalSeconds = useMemo(() => {
    if (!plan) return 0;
    return plan.selected_profiles.reduce((acc, profile) => {
      const item = catalogue.items.find((it) => it.profile === profile);
      return acc + (item?.est_duration_seconds ?? 0);
    }, 0);
  }, [plan, catalogue.items]);

  const runnable = Boolean(plan && plan.selected_profiles.length > 0);
  const blockedReason = !canRun
    ? volatilityBackend?.message ?? "Volatility 3 is not ready for memory analysis."
    : null;

  // Pre-populate the catalogue item titles for the plan.
  const planWithTitles = useMemo(() => {
    if (!plan) return null;
    return {
      ...plan,
      titled: plan.selected_profiles.map((p) => ({
        profile: p,
        title: PROFILE_TITLE[p] ?? p,
        highVolume: HIGH_VOLUME_PROFILES.has(p),
        slow: SLOW_PROFILES.has(p),
      })),
    };
  }, [plan]);

  // Disable the action button while the request is in flight (double
  // click protection).
  const actionDisabled = !acknowledged || startMutation.isPending || !runnable;

  useEffect(() => {
    if (blockedReason && error === null) {
      setError(blockedReason);
    }
  }, [blockedReason, error]);

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-abyss/80 p-4"
      data-testid="memory-run-all-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="memory-run-all-title"
    >
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">
              Run all supported profiles
            </p>
            <h2 id="memory-run-all-title" className="mt-1 text-2xl font-semibold">
              {mode === MODE_MISSING
                ? "Run missing or failed profiles only"
                : "Re-run all supported profiles"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
            data-testid="memory-run-all-close"
          >
            Close
          </button>
        </div>

        <section className="mt-4 space-y-1 rounded-2xl border border-line bg-abyss/40 p-4">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Evidence</p>
          <p className="text-sm" data-testid="memory-run-all-evidence-filename">
            {evidenceFilename}
          </p>
          <p className="text-xs text-muted" data-testid="memory-run-all-evidence-meta">
            {evidenceHost ? <>Host {evidenceHost} · </> : null}
            Size {formatBytes(evidenceSizeBytes)}
          </p>
        </section>

        <section className="mt-4 space-y-2 rounded-2xl border border-line bg-abyss/40 p-4">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Will run sequentially</p>
          {planWithTitles ? (
            <ol className="space-y-1 text-sm" data-testid="memory-run-all-order">
              {planWithTitles.titled.map((item, index) => (
                <li
                  key={item.profile}
                  className="flex flex-wrap items-center justify-between gap-2"
                  data-testid={`memory-run-all-order-${item.profile}`}
                >
                  <span>
                    {index + 1}. {item.title}{" "}
                    <span className="font-mono text-[10px] text-muted">{item.profile}</span>
                  </span>
                  <span className="flex flex-wrap gap-1">
                    {item.highVolume ? (
                      <span
                        className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100"
                        data-testid={`memory-run-all-warning-${item.profile}`}
                      >
                        High volume
                      </span>
                    ) : null}
                    {item.slow ? (
                      <span
                        className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100"
                        data-testid={`memory-run-all-warning-${item.profile}`}
                      >
                        Slow analysis
                      </span>
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-xs text-muted">Resolving the plan…</p>
          )}
          <p className="mt-2 text-[10px] text-muted" data-testid="memory-run-all-est-duration">
            Estimated total duration: ~{totalSeconds}s
          </p>
        </section>

        <section className="mt-4 space-y-2 rounded-2xl border border-line bg-abyss/40 p-4">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Skipped</p>
          {plan && plan.skipped_profiles.length + plan.excluded_profiles.length > 0 ? (
            <ul className="space-y-1 text-xs" data-testid="memory-run-all-skipped">
              {[...plan.skipped_profiles, ...plan.excluded_profiles].map((s) => (
                <li
                  key={s.profile}
                  className="flex flex-wrap items-center justify-between gap-2"
                  data-testid={`memory-run-all-skipped-${s.profile}`}
                >
                  <span className="font-mono text-[10px]">{s.profile}</span>
                  <span className="text-muted">{s.reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted">No profiles skipped.</p>
          )}
        </section>

        <section className="mt-4 space-y-2 rounded-2xl border border-line bg-abyss/40 p-4">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Mode</p>
          <div className="flex flex-col gap-2 text-sm" data-testid="memory-run-all-mode">
            <label className="flex items-start gap-2">
              <input
                type="radio"
                name="run-all-mode"
                value={MODE_MISSING}
                checked={mode === MODE_MISSING}
                onChange={() => setMode(MODE_MISSING)}
                data-testid="memory-run-all-mode-missing"
                className="mt-1"
              />
              <span>
                <span className="font-medium">Run missing or failed only</span>
                <span className="block text-[10px] text-muted">Default. Skips families that already completed successfully.</span>
              </span>
            </label>
            <label className="flex items-start gap-2">
              <input
                type="radio"
                name="run-all-mode"
                value={MODE_RERUN}
                checked={mode === MODE_RERUN}
                onChange={() => setMode(MODE_RERUN)}
                data-testid="memory-run-all-mode-rerun"
                className="mt-1"
              />
              <span>
                <span className="font-medium">Re-run all supported profiles</span>
                <span className="block text-[10px] text-amber-200" data-testid="memory-run-all-rerun-warning">
                  Creates new runs. Keeps previous results. Can take a long time. Does not replace active results until the new run finishes successfully.
                </span>
              </span>
            </label>
          </div>
        </section>

        <label className="mt-4 flex items-start gap-2 text-sm" data-testid="memory-run-all-ack">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            data-testid="memory-run-all-ack-checkbox"
            className="mt-1"
          />
          <span>
            I confirm that I am authorized to analyze this memory evidence.
          </span>
        </label>

        {error ? (
          <p className="mt-3 text-xs text-rose-200" data-testid="memory-run-all-error">
            {error}
          </p>
        ) : null}

        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
            data-testid="memory-run-all-cancel"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              setError(null);
              startMutation.mutate();
            }}
            disabled={actionDisabled}
            data-testid="memory-run-all-confirm"
            className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
          >
            {startMutation.isPending
              ? "Starting…"
              : started
                ? "Started"
                : "Run all supported profiles"}
          </button>
        </div>
      </div>
    </div>
  );
}
