import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import { MemoryEvidenceHeader } from "../components/memory/MemoryEvidenceHeader";
import { MemoryAnalysisCatalogueModal } from "../components/memory/MemoryAnalysisCatalogueModal";
import { MemoryHistoryPanel } from "../components/memory/MemoryHistoryPanel";
import { MemoryTypeConfirmationModal } from "../components/memory/MemoryTypeConfirmationModal";
import { MemorySymbolResolutionPanel } from "../components/memory/MemorySymbolResolutionPanel";
import { MemoryPreparationCard } from "../components/memory/MemoryPreparationCard";
import { MEMORY_TABS, isMemoryTab, type MemoryTab } from "../lib/memoryWorkspaceState";

const ARTIFACT_FAMILY_FROM_TAB: Record<string, string> = {
  processes: "processes",
  system: "system_info",
  raw: "raw_observations",
  artifacts: "artifacts",
};

function familyForTab(tab: MemoryTab, artifact?: string | null): string {
  if (tab === "artifacts") {
    if (artifact === "network") return "network";
    if (artifact === "modules") return "modules";
    if (artifact === "handles") return "handles";
    if (artifact === "drivers") return "drivers";
    if (artifact === "kernel_modules" || artifact === "kernel-modules") return "kernel_modules";
    if (artifact === "suspicious_regions" || artifact === "suspicious-regions") return "suspicious_regions";
    return "modules";
  }
  return ARTIFACT_FAMILY_FROM_TAB[tab] || "processes";
}

export default function MemoryEvidencePage() {
  const { caseId = "", evidenceId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { setActiveCaseId } = useActiveCase();
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [confirmationError, setConfirmationError] = useState<string | null>(null);
  const [confirmationToast, setConfirmationToast] = useState<string | null>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const tab = useMemo<MemoryTab>(() => {
    const raw = searchParams.get("tab");
    return isMemoryTab(raw) ? raw : "overview";
  }, [searchParams]);

  const artifactParam = searchParams.get("artifact");
  const family = familyForTab(tab, artifactParam);

  const historicalRunId = searchParams.get("run_id") || null;

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const landingQuery = useQuery({
    queryKey: ["memory-landing", caseId],
    queryFn: () => api.getMemoryEvidenceLanding(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, family, historicalRunId],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId, family, historicalRunId || undefined),
    enabled: Boolean(caseId && evidenceId && family),
    refetchOnWindowFocus: false,
  });

  const catalogueQuery = useQuery({
    queryKey: ["memory-catalogue", caseId, evidenceId],
    queryFn: () => api.getMemoryAnalysisCatalogue(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const backendQuery = useQuery({
    queryKey: ["memory-backends"],
    queryFn: () => api.getMemoryBackendOverview(),
    refetchOnWindowFocus: false,
  });

  const overview = overviewQuery.data;
  const evidence = landingQuery.data?.items?.find((item) => item.evidence_id === evidenceId) || null;
  const volatilityBackend = backendQuery.data?.backends.find((b) => b.backend === "volatility3") || null;
  const canRun = Boolean(overview?.memory_analysis_enabled && volatilityBackend?.ready);

  const activeBatchQuery = useQuery({
    queryKey: ["memory-active-batch", caseId, evidenceId],
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: 5_000,
    retry: false,
    queryFn: async () => {
      try {
        return await api.getActiveMemoryAnalysisBatch(caseId, evidenceId);
      } catch (err) {
        // 404 means "no active batch" - this is the normal end state.
        return null;
      }
    },
  });
  const activeBatch = activeBatchQuery.data ?? null;

  const cancelBatchMutation = useMutation({
    mutationFn: async () => {
      if (!activeBatch) return null;
      return api.cancelMemoryAnalysisBatch(caseId, evidenceId, activeBatch.id);
    },
    onSuccess: () => {
      activeBatchQuery.refetch();
    },
  });

  const confirmMemoryTypeMutation = useMutation({
    mutationFn: async (reason: string) =>
      api.confirmMemoryType(caseId, evidenceId, reason),
    onSuccess: () => {
      setConfirmationOpen(false);
      setConfirmationError(null);
      setConfirmationToast("Memory evidence type confirmed. Analysis is now available.");
      // Invalidate every query that depends on the evidence status.
      void queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-readiness", caseId] });
      window.setTimeout(() => setConfirmationToast(null), 5000);
    },
    onError: (error: Error & { errorCode?: string }) => {
      setConfirmationError(error.message || "Confirmation failed. Please try again.");
    },
  });

  useEffect(() => {
    if (!overview) return;
    if (overview.evidences.length === 0) {
      // No memory evidence: let the parent route render the empty state.
    }
  }, [overview]);

  useEffect(() => {
    if (!evidenceId) return;
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      if (!params.get("tab")) params.set("tab", "overview");
      return params;
    }, { replace: true });
  }, [evidenceId, setSearchParams]);

  useEffect(() => {
    if (catalogueQuery.data) return;
    if (catalogueOpen) {
      void catalogueQuery.refetch();
    }
  }, [catalogueOpen, catalogueQuery]);

  const evidenceReadinessQueries = useQueries({
    queries: (overview?.evidences || []).map((evidence) => ({
      queryKey: ["memory-evidence-readiness", caseId, evidence.id],
      queryFn: () => api.getMemoryEvidenceReadiness(caseId, evidence.id),
      refetchOnWindowFocus: false,
    })),
  });
  const readinessByEvidence = new Map(
    (overview?.evidences || []).map((evidence, index) => [evidence.id, evidenceReadinessQueries[index]?.data]),
  );

  // Per-evidence symbol readiness: drives the symbol resolution
  // panel and gates the Run analysis / Run all buttons.
  const symbolReadinessQuery = useQuery({
    queryKey: ["memory-symbol-readiness", caseId, evidenceId],
    queryFn: () => api.getMemorySymbolReadiness(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const symbolReadiness = symbolReadinessQuery.data ?? null;

  // Automatic preparation pipeline.  This is the new state machine
  // the analyst sees in the "Memory preparation" card.  Polled
  // aggressively while preparation is in progress.
  const symbolPreparationQuery = useQuery({
    queryKey: ["memory-symbol-preparation", caseId, evidenceId],
    queryFn: () => api.getMemorySymbolPreparation(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const data = query.state.data as { ui_state?: string } | undefined;
      if (data?.ui_state && data.ui_state !== "ready" && data.ui_state !== "failed" && data.ui_state !== "blocked") {
        return 2_000;
      }
      return false;
    },
  });
  const symbolPreparation = symbolPreparationQuery.data ?? null;

  const handleReturnToLatest = useCallback(() => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      params.delete("run_id");
      return params;
    }, { replace: true });
  }, [setSearchParams]);

  if (overviewQuery.isLoading) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading evidence...</div>;
  }

  if (!evidence) {
    return (
      <div className="rounded-[28px] border border-rose-400/30 bg-rose-500/10 p-8 text-sm text-rose-100 shadow-panel">
        Memory evidence was not found for this case.
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="memory-evidence-workspace">
      <MemoryEvidenceHeader
        caseId={caseId}
        evidence={evidence}
        activeResult={activeResultQuery.data ?? null}
        family={family}
        historicalRunId={historicalRunId}
        onViewHistory={() => setHistoryOpen(true)}
        onReturnToLatest={handleReturnToLatest}
        onOpenCatalogue={() => {
          if (evidence.can_analyze === false) {
            setConfirmationOpen(true);
            return;
          }
          setCatalogueOpen(true);
        }}
        symbolReadiness={symbolReadiness}
      />

      {confirmationToast ? (
        <div
          className="rounded-xl border border-mint/30 bg-mint/10 p-3 text-xs text-ink"
          data-testid="memory-confirmation-toast"
          role="status"
        >
          {confirmationToast}
        </div>
      ) : null}

      {tab === "overview" && readinessByEvidence.get(evidenceId)?.sanitized_message ? (
        <div className="rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100">
          {readinessByEvidence.get(evidenceId)?.sanitized_message}
        </div>
      ) : null}

      {evidence && symbolReadiness ? (
        <MemorySymbolResolutionPanel
          caseId={caseId}
          evidenceId={evidenceId}
          readiness={symbolReadiness}
        />
      ) : null}

      {evidence && symbolPreparation ? (
        <MemoryPreparationCard
          caseId={caseId}
          evidenceId={evidenceId}
          preparation={symbolPreparation}
        />
      ) : null}

      {activeBatch ? (
        <section
          className="rounded-[28px] border border-line bg-panel/60 p-4 shadow-panel"
          data-testid="memory-batch-progress"
        >
          <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
            Running all supported profiles
          </p>
          <p className="mt-1 text-sm" data-testid="memory-batch-progress-summary">
            {activeBatch.completed_profiles.length} of {activeBatch.requested_profiles.length} completed
            {activeBatch.current_profile ? <> · Current: <span className="font-mono">{activeBatch.current_profile}</span></> : null}
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Link
              to={`/cases/${caseId}/memory/${evidenceId}?tab=runs`}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="memory-batch-progress-view"
            >
              View progress
            </Link>
            {activeBatch.cancellation_requested === false && (activeBatch.status === "queued" || activeBatch.status === "running") ? (
              <button
                type="button"
                onClick={() => cancelBatchMutation.mutate()}
                disabled={cancelBatchMutation.isPending}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted disabled:opacity-50"
                data-testid="memory-batch-cancel"
              >
                {cancelBatchMutation.isPending ? "Cancelling…" : "Cancel remaining profiles"}
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      <MemoryWorkspace caseId={caseId} evidenceId={evidenceId} />

      {catalogueOpen && catalogueQuery.data && evidence ? (
        <MemoryAnalysisCatalogueModal
          caseId={caseId}
          evidenceId={evidenceId}
          evidenceFilename={evidence.filename}
          evidenceHost={evidence.detected_host}
          evidenceSizeBytes={evidence.size_bytes}
          catalogue={catalogueQuery.data}
          volatilityBackend={volatilityBackend}
          canRun={canRun}
          onClose={() => setCatalogueOpen(false)}
        />
      ) : null}

      {historyOpen ? (
        <MemoryHistoryPanel
          caseId={caseId}
          evidenceId={evidenceId}
          family={family}
          onClose={() => setHistoryOpen(false)}
          onSelectRun={(runId) => {
            setSearchParams((current) => {
              const params = new URLSearchParams(current);
              params.set("run_id", runId);
              return params;
            }, { replace: true });
            setHistoryOpen(false);
          }}
          onReturnToLatest={handleReturnToLatest}
          selectedRunId={historicalRunId}
        />
      ) : null}

      <MemoryTypeConfirmationModal
        open={confirmationOpen && Boolean(evidence)}
        filename={evidence?.filename || ""}
        evidenceId={evidence?.evidence_id || ""}
        sizeBytes={evidence?.size_bytes || 0}
        host={evidence?.detected_host}
        detectionStatus={evidence?.detection_status || ""}
        detectionReason={evidence?.detection_reason}
        detectedFormat={evidence?.detected_format}
        detectionConfidence={evidence?.detection_confidence}
        busy={confirmMemoryTypeMutation.isPending}
        errorMessage={confirmationError}
        onCancel={() => {
          setConfirmationOpen(false);
          setConfirmationError(null);
        }}
        onConfirm={async (reason) => {
          setConfirmationError(null);
          await confirmMemoryTypeMutation.mutateAsync(reason);
        }}
      />
    </div>
  );
}

export type { MemoryTab };
export { MEMORY_TABS };
