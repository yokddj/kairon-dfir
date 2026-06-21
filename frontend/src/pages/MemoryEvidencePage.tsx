import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import { MemoryEvidenceHeader } from "../components/memory/MemoryEvidenceHeader";
import { MemoryAnalysisCatalogueModal } from "../components/memory/MemoryAnalysisCatalogueModal";
import { MemoryHistoryPanel } from "../components/memory/MemoryHistoryPanel";
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
        onOpenCatalogue={() => setCatalogueOpen(true)}
      />

      {tab === "overview" && readinessByEvidence.get(evidenceId)?.sanitized_message ? (
        <div className="rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100">
          {readinessByEvidence.get(evidenceId)?.sanitized_message}
        </div>
      ) : null}

      <MemoryWorkspace caseId={caseId} evidenceId={evidenceId} />

      {catalogueOpen && catalogueQuery.data ? (
        <MemoryAnalysisCatalogueModal
          caseId={caseId}
          evidenceId={evidenceId}
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
    </div>
  );
}

export type { MemoryTab };
export { MEMORY_TABS };
