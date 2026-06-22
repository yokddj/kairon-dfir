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
  if (prep.ui_state === "ready") {
    return {
      title: "Memory analysis ready",
      subtitle: "Windows symbols cached for this evidence.",
      tone: "good" as const,
    };
  }
  if (prep.ui_state === "preparing") {
    return {
      title: "Preparing memory analysis",
      subtitle: prep.progress_label || "Preparing Windows symbols for this evidence.",
      tone: "warn" as const,
    };
  }
  if (prep.ui_state === "failed") {
    return {
      title: "Memory preparation failed",
      subtitle:
        prep.sanitized_message ||
        "Kairon could not obtain the required Windows symbols.",
      tone: "bad" as const,
    };
  }
  return {
    title: "Memory symbols unavailable",
    subtitle:
      prep.sanitized_message ||
      "Kairon could not obtain the required Windows symbols for this evidence.",
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
    mutationFn: () => api.retryMemorySymbolPreparation(caseId, evidenceId),
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
      data-ui-state={preparation.ui_state}
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
              {retryMutation.isPending ? "Retrying…" : "Retry"}
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setShowDetails((v) => !v)}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="memory-preparation-toggle-details"
          >
            {showDetails ? "Hide details" : "View technical details"}
          </button>
        </div>
      </div>

      {preparation.ui_state === "preparing" ? (
        <div className="mt-3" data-testid="memory-preparation-progress">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-abyss/60">
            <div
              className="h-full rounded-full bg-accent"
              style={{ width: `${Math.min(100, Math.max(0, preparation.progress_percent))}%` }}
            />
          </div>
          <p className="mt-1 text-[10px] text-muted">
            {preparation.progress_label} · {preparation.progress_percent}%
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
