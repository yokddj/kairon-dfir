import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type MemorySymbolPreparation } from "../../api/client";

type Tone = "good" | "warn" | "bad" | "neutral";

function toneForUIState(uiState: string): Tone {
  if (uiState === "ready") return "good";
  if (uiState === "preparing") return "warn";
  if (uiState === "blocked") return "bad";
  if (uiState === "failed") return "bad";
  return "neutral";
}

function cardCopy(prep: MemorySymbolPreparation) {
  // Sprint 6 (OS-agnostic preparation): use the effective
  // state (post-reconciliation) to drive the copy.  The
  // states ``dispatch_failed``, ``platform_not_identified``
  // and ``platform_not_supported`` are now distinct from
  // the legacy "failed" / "blocked" buckets.
  const state = prep.effective_state || prep.ui_state;
  if (state === "ready" || prep.ui_state === "ready") {
    return {
      title: "Memory analysis ready",
      subtitle: "Symbols and system metadata are available for this evidence.",
      tone: "good" as const,
    };
  }
  if (state === "dispatch_failed" || prep.error_code === "MEMORY_PREPARATION_DISPATCH_FAILED") {
    return {
      title: "Preparation could not be enqueued",
      subtitle:
        prep.sanitized_message ||
        "The worker queue is unreachable. Retry to dispatch a new task.",
      tone: "bad" as const,
    };
  }
  if (state === "stale" || prep.stale) {
    return {
      title: "Memory preparation was interrupted.",
      subtitle:
        prep.sanitized_message ||
        "The previous preparation did not finish. You can retry the preparation.",
      tone: "bad" as const,
    };
  }
  if (state === "failed" || (prep.ui_state === "failed" && state === "failed")) {
    return {
      title: "Memory preparation failed",
      subtitle:
        prep.sanitized_message ||
        "Kairon could not obtain the required symbols for this evidence.",
      tone: "bad" as const,
    };
  }
  if (state === "platform_not_supported") {
    return {
      title: "Platform not supported",
      subtitle:
        prep.sanitized_message ||
        "Kairon does not currently support this operating system.",
      tone: "bad" as const,
    };
  }
  if (state === "platform_not_identified") {
    return {
      title: "Platform not identified",
      subtitle:
        prep.sanitized_message ||
        "The image does not match a known operating-system family.",
      tone: "bad" as const,
    };
  }
  if (state === "blocked") {
    return {
      title: "Preparation blocked",
      subtitle:
        prep.sanitized_message ||
        "A required dependency is missing. You can retry the preparation.",
      tone: "bad" as const,
    };
  }
  if (state === "cancelled") {
    return {
      title: "Memory preparation cancelled",
      subtitle: prep.sanitized_message || "The preparation was cancelled.",
      tone: "neutral" as const,
    };
  }
  // "preparing" or any queued/probing/acquiring/verifying state.
  if (prep.ui_state === "preparing" || prep.task_alive) {
    return {
      title: "Preparing memory analysis",
      subtitle: prep.progress_label || "Preparing the memory pipeline for this evidence.",
      tone: "warn" as const,
    };
  }
  return {
    title: "Memory symbols unavailable",
    subtitle:
      prep.sanitized_message ||
      "Kairon could not obtain the required symbols for this evidence.",
    tone: "bad" as const,
  };
}

type Props = {
  caseId: string;
  evidenceId: string;
  preparation: MemorySymbolPreparation | null;
  onRetry?: () => void;
};

export function MemoryPreparationCard({
  caseId,
  evidenceId,
  preparation,
  onRetry,
}: Props) {
  const queryClient = useQueryClient();
  const [showDetails, setShowDetails] = useState(false);

  const retryMutation = useMutation({
    mutationFn: () => api.retryMemoryPreparation(caseId, evidenceId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["memory-symbol-preparation", caseId, evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      onRetry?.();
    },
  });

  const cancelIntentMutation = useMutation({
    mutationFn: () => api.cancelMemoryRunWhenReady(caseId, evidenceId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["memory-symbol-preparation", caseId, evidenceId] });
    },
  });

  if (!preparation) {
    return null;
  }
  const copy = cardCopy(preparation);
  const tone = copy.tone;

  return (
    <section
      className={
        "rounded-[28px] border bg-panel/70 p-5 shadow-panel " +
        (tone === "good"
          ? "border-emerald-400/30"
          : tone === "warn"
            ? "border-amber-400/30"
            : tone === "bad"
              ? "border-rose-400/30"
              : "border-line")
      }
      data-testid="memory-preparation-card"
      data-ui-state={preparation.effective_state || preparation.ui_state}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
            {preparation.ui_state === "ready" ? "Ready" : "Memory preparation"}
          </p>
          <p
            className="mt-1 text-sm font-semibold"
            data-testid="memory-preparation-title"
          >
            {copy.title}
          </p>
          <p
            className="mt-1 text-xs text-muted"
            data-testid="memory-preparation-subtitle"
          >
            {copy.subtitle}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {preparation.ui_state !== "ready" ? (
            <button
              type="button"
              onClick={() => retryMutation.mutate()}
              disabled={retryMutation.isPending}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted disabled:opacity-50"
              data-testid="memory-preparation-retry-button"
            >
              {retryMutation.isPending ? "Retrying…" : "Retry preparation"}
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setShowDetails((v) => !v)}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="memory-preparation-toggle-details"
          >
            {showDetails ? "Hide details" : "View details"}
          </button>
        </div>
      </div>

      {/*
        Show the progress bar ONLY when:
        * ui_state is "preparing" AND
        * the effective state is NOT ready (i.e. the row has not
          been reconciled) AND
        * the task is alive (otherwise the percentage is a stale
          fake value that the analyst should not see).

        Sprint 6: when ``progress_percent`` is 0 the bar uses an
        indeterminate animation rather than rendering a 0% bar
        (the previous "Queued 5%" placeholder is gone).
      */}
      {preparation.ui_state === "preparing" &&
      preparation.effective_state !== "ready" &&
      preparation.task_alive ? (
        <div className="mt-3" data-testid="memory-preparation-progress">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-abyss/60">
            {preparation.progress_percent > 0 ? (
              <div
                className="h-full rounded-full bg-accent"
                style={{ width: `${Math.min(100, Math.max(0, preparation.progress_percent))}%` }}
              />
            ) : (
              <div
                className="h-full w-1/3 rounded-full bg-accent/70"
                data-testid="memory-preparation-progress-indeterminate"
                style={{
                  animation: "memory-progress-indeterminate 1.2s ease-in-out infinite",
                }}
              />
            )}
          </div>
          <p className="mt-1 text-[10px] text-muted">
            {preparation.progress_label}
            {preparation.progress_percent > 0
              ? ` · ${preparation.progress_percent}%`
              : ""}
          </p>
        </div>
      ) : null}

      {preparation.pending_intent_kind ? (
        <div
          className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-abyss/40 p-2 text-xs"
          data-testid="memory-preparation-pending-intent"
        >
          <span>
            Run {preparation.pending_intent_kind === "run_all" ? "all" : "analysis"} will
            start automatically when preparation is ready.
          </span>
          <button
            type="button"
            onClick={() => cancelIntentMutation.mutate()}
            disabled={cancelIntentMutation.isPending}
            className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-[10px] text-muted disabled:opacity-50"
            data-testid="memory-preparation-cancel-intent"
          >
            Cancel
          </button>
        </div>
      ) : null}

      {showDetails ? (
        <div
          className="mt-3 rounded-xl border border-line bg-abyss/40 p-3 text-[10px] text-muted"
          data-testid="memory-preparation-details"
        >
          <p className="font-mono">
            <span>preparation_state: {preparation.preparation_state}</span>
            <span className="ml-2">cache_status: {preparation.cache_status}</span>
            {preparation.link_source ? (
              <span className="ml-2">link_source: {preparation.link_source}</span>
            ) : null}
            {preparation.content_reused_by_hash ? (
              <span className="ml-2">reused_by_hash: true</span>
            ) : null}
          </p>
          {preparation.requirement ? (
            <p className="mt-1 font-mono">
              <span>PDB: {preparation.requirement.pdb_name}</span>
              <span className="ml-2">GUID: {preparation.requirement.pdb_guid}</span>
              <span className="ml-2">Age: {preparation.requirement.pdb_age}</span>
              <span className="ml-2">Arch: {preparation.requirement.architecture}</span>
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
