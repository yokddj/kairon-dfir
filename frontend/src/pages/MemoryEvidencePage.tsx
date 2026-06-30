import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams, useNavigate } from "react-router-dom";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import { MemoryEvidenceHeader } from "../components/memory/MemoryEvidenceHeader";
import { MemoryEvidenceSelector } from "../components/memory/MemoryEvidenceSelector";
import { MemoryAnalysisCatalogueModal } from "../components/memory/MemoryAnalysisCatalogueModal";
import { MemoryHistoryPanel } from "../components/memory/MemoryHistoryPanel";
import { MemoryTypeConfirmationModal } from "../components/memory/MemoryTypeConfirmationModal";
import { MemorySymbolResolutionPanel } from "../components/memory/MemorySymbolResolutionPanel";
import { MemoryExperimentalResultsPanel } from "../components/memory/MemoryExperimentalResultsPanel";
import { MemoryPreparationCard } from "../components/memory/MemoryPreparationCard";
import { MEMORY_TABS, isMemoryTab, type MemoryTab } from "../lib/memoryWorkspaceState";
import { memoryQueryKeys } from "../lib/memoryQueryKeys";
import type { MemoryScanRun } from "../api/client";

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
  const navigate = useNavigate();
  const { setActiveCaseId } = useActiveCase();
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [confirmationError, setConfirmationError] = useState<string | null>(null);
  const [confirmationToast, setConfirmationToast] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const submittingRef = useRef(false);

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

  const evidenceRunsQuery = useQuery({
    queryKey: memoryQueryKeys.runs(caseId, evidenceId),
    queryFn: () => api.listMemoryRuns(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const runs = (query.state.data ?? []) as MemoryScanRun[];
      return runs.some((run) => ["pending", "queued", "running"].includes(run.status)) ? 3000 : false;
    },
  });
  const hasActiveRuns = useMemo(
    () => (evidenceRunsQuery.data ?? []).some(
      (run: MemoryScanRun) => ["pending", "queued", "running"].includes(run.status),
    ),
    [evidenceRunsQuery.data],
  );

  const landingQuery = useQuery({
    queryKey: memoryQueryKeys.landing(caseId),
    queryFn: () => api.getMemoryEvidenceLanding(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    refetchInterval: hasActiveRuns ? 3000 : false,
  });

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, family, historicalRunId],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId, family, historicalRunId || undefined),
    enabled: Boolean(caseId && evidenceId && family),
    refetchOnWindowFocus: false,
  });

  const catalogueQuery = useQuery({
    queryKey: memoryQueryKeys.catalogue(caseId, evidenceId),
    queryFn: () => api.getMemoryAnalysisCatalogue(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: hasActiveRuns ? 3000 : false,
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
      const keys = memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId);
      for (const key of keys) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
      void queryClient.invalidateQueries({ queryKey: ["memory-readiness", caseId, evidenceId] });
      window.setTimeout(() => setConfirmationToast(null), 5000);
    },
    onError: (error: Error & { errorCode?: string }) => {
      setConfirmationError(error.message || "Confirmation failed. Please try again.");
    },
  });

  const startScanMutation = useMutation({
    mutationFn: async () =>
      api.startMemoryScan(caseId, evidenceId, "metadata_only", true),
    onSuccess: () => {
      const keys = memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId);
      for (const key of keys) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
    },
    onError: (_error: Error & { errorCode?: string }) => {
    },
    onSettled: () => {
      submittingRef.current = false;
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

  // Per-evidence symbol readiness is diagnostic only.  Volatility
  // identifies layers and resolves symbols during the actual run.
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

  const prepEffectiveState = symbolPreparation?.effective_state || symbolPreparation?.ui_state;
  const isBlockedSymbols = prepEffectiveState === "blocked_symbols";
  const isReadyState = prepEffectiveState === "ready";
  const isNativeReady = isReadyState && symbolPreparation?.native_compatible === true;

  const nativeProbeQuery = useQuery({
    queryKey: ["native-probe", caseId, evidenceId],
    queryFn: () => api.getNativeProbeStatus(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId && symbolPreparation
      && (isBlockedSymbols || isNativeReady)),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const data = query.state.data as { status?: string } | undefined;
      const status = data?.status;
      if (status === "queued" || status === "running") {
        return 3_000;
      }
      return false;
    },
  });

  const showExperimentalPanel =
    Boolean(symbolPreparation) && isBlockedSymbols;

  const handleReturnToLatest = useCallback(() => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      params.delete("run_id");
      return params;
    }, { replace: true });
  }, [setSearchParams]);

  const landingItems = landingQuery.data?.items ?? [];

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
      {landingItems.length > 1 ? (
        <MemoryEvidenceSelector
          caseId={caseId}
          selectedEvidenceId={evidenceId}
          evidences={landingItems}
          onChange={(newEvidenceId) => {
            navigate(`/cases/${caseId}/memory/${newEvidenceId}`);
          }}
        />
      ) : null}

      <MemoryEvidenceHeader
        caseId={caseId}
        evidence={evidence}
        activeResult={activeResultQuery.data ?? null}
        family={family}
        historicalRunId={historicalRunId}
        onViewHistory={() => setHistoryOpen(true)}
        onReturnToLatest={handleReturnToLatest}
        catalogue={catalogueQuery.data ?? null}
        onOpenCatalogue={() => {
          const ds = evidence.detection_status || "";
          if (ds === "probable_disk" || (ds === "ambiguous_raw" && !evidence.operator_override)) {
            setConfirmationOpen(true);
            return;
          }
          setCatalogueOpen(true);
        }}
        onAnalyzeMemory={() => {
          if (submittingRef.current) return;
          if (!window.confirm(
            "I am authorized and responsible for analyzing this memory evidence. " +
            "I confirm this is a legitimate memory capture from an authorized source."
          )) return;
          submittingRef.current = true;
          startScanMutation.mutate();
        }}
        isAnalyzing={startScanMutation.isPending}
        symbolReadiness={symbolReadiness}
        symbolPreparation={symbolPreparation}
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

      {evidence && symbolReadiness && false ? (
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
          nativeProbeStatus={nativeProbeQuery.data ?? null}
        />
      ) : null}

      {showExperimentalPanel ? (
        <MemoryExperimentalResultsPanel caseId={caseId} evidenceId={evidenceId} />
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

      <MemoryWorkspace key={evidenceId} caseId={caseId} evidenceId={evidenceId} />

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
